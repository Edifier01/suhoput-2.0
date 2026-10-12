"""Offline Selectel billing evidence and conservative native-job projection.

No network access, credentials, or automatic meter. Provider HTTP counts must
come from an independent native measurement, never restic adapter call counts.
CSV SHA proves file identity, not authenticity. Project CSV has no bucket
attribution; its partial-period total cannot confirm the owner's monthly budget.
"""
import argparse
import csv
import datetime as dt
from decimal import Decimal, InvalidOperation
import hashlib
import io
import json
import pathlib
import re


class BudgetError(ValueError):
    """Fail closed without disclosing private input values or file paths."""


HEADERS = ('Аккаунт', 'Период', 'Идентификатор проекта', 'Наименование проекта',
           'Идентификатор ресурса', 'Наименование ресурса', 'Количество ресурса',
           'Единица измерения ресурса', 'Продукт', 'Стоимость')
OPTIONAL_HEADERS = {'Бакет': 'bucket', 'Пул': 'pool'}
GIB = 1024 ** 3
METADATA_BYTES = 4096
RATE_KEYS = {'storage': 'storage_rub_gib_month', 'egress': 'egress_rub_gib',
             'put': 'put_rub_1000', 'get': 'get_rub_1000', 'delete': 'delete_rub_1000'}
RATE_UNITS = {'storage': 'RUB/GiB month (730 hours)', 'egress': 'RUB/GiB',
              'put': 'RUB/1000 requests', 'get': 'RUB/1000 requests', 'delete': 'RUB/1000 requests'}
NATIVE_UNITS = {'storage': 'MB*H', 'egress': 'MB', 'put': 'item', 'get': 'item', 'delete': 'item'}
FACTORS = {'storage': Decimal(1024 * 730), 'egress': Decimal(1024),
           'put': Decimal(1000), 'get': Decimal(1000), 'delete': Decimal(1000)}
JOBS = ('binlog', 'hourly', 'full', 'pre_update', 'check', 'retention', 'restore')
FIXED_CADENCE = {'binlog': 43200, 'hourly': 720, 'full': 30}
SHA = re.compile('[0-9a-f]{64}')


def number_text(value):
    return format(value, 'f').rstrip('0').rstrip('.') if '.' in format(value, 'f') else format(value, 'f')


def local_decimal(value, *, money=False):
    """Unambiguous decimal/local grouping; reject floats, exponent, negatives."""
    if isinstance(value, Decimal):
        result = value
    elif type(value) is int:
        result = Decimal(value)
    elif isinstance(value, str):
        text = value.strip().replace('\u00a0', ' ').replace('\u202f', ' ')
        if money:
            text = re.sub(r'\s*(?:RUB|руб\.?|₽)$', '', text, flags=re.I).strip()
        if not re.fullmatch(r'(?:[0-9]+|[0-9]{1,3}(?: [0-9]{3})+)(?:[.,][0-9]+)?', text):
            raise BudgetError('Invalid decimal input')
        try:
            result = Decimal(text.replace(' ', '').replace(',', '.'))
        except InvalidOperation:
            raise BudgetError('Invalid decimal input') from None
    else:
        raise BudgetError('Exact decimal input required')
    if not result.is_finite() or result < 0 or result.adjusted() > 30:
        raise BudgetError('Finite nonnegative bounded decimal required')
    return result


def nonnegative_integer(value):
    if type(value) is not int or value < 0 or value > 10 ** 30:
        raise BudgetError('Bounded nonnegative integer required')
    return value


def scope_fingerprint(account, project, bucket='', pool=''):
    """Match native receipt scope to export without publishing identifiers."""
    return hashlib.sha256(json.dumps([account, project, bucket, pool], ensure_ascii=False,
                                     separators=(',', ':')).encode()).hexdigest()


def metric_spec(resource):
    """Closed whitelist of provider tariff metric IDs, not resource names."""
    key = re.sub(r'[-_.]', '.', resource.lower())
    storage_class = 'cold' if key.endswith('.cold') else 'standard'
    if storage_class == 'cold': key = key[:-5]
    names = {'space.mb': 'storage', 'traffic.mb': 'egress',
             'traffic.api.put': 'put', 'traffic.api.get': 'get', 'traffic.api.delete': 'delete',
             'traffic.req.put': 'put', 'traffic.req.get': 'get', 'traffic.req.delete': 'delete'}
    return (names[key], storage_class) if key in names else None


def fixed_timezone(value):
    if value is None: return None
    if value == 'UTC': return dt.timezone.utc
    if not isinstance(value, str) or not re.fullmatch(r'[+-][0-9]{2}:[0-9]{2}', value):
        raise BudgetError('Explicit UTC or numeric timezone required')
    hours, minutes = map(int, value[1:].split(':'))
    if hours > 14 or minutes > 59 or (hours == 14 and minutes):
        raise BudgetError('Invalid timezone offset')
    offset = dt.timedelta(hours=hours, minutes=minutes)
    return dt.timezone(offset if value[0] == '+' else -offset)


def import_billing_csv(data, *, timezone=None, now=None):
    """Import actual project/metric/hour CSV, returning only scope hashes.

Costs rounded to kopecks imply an interval, not an exact tariff. MB*H converts
to GiB-month at the provider's 1024 MB and 730 hours convention. Missing costs
and absent operations remain unknown. File name is never a period authority.
"""
    if not isinstance(data, bytes) or len(data) > 16 * 1024 * 1024:
        raise BudgetError('Bounded CSV bytes required')
    try:
        text = data.decode('utf-8-sig')
        reader = csv.reader(io.StringIO(text, newline=''), delimiter=';', strict=True)
        header = next(reader)
        rows = list(reader)
    except (UnicodeError, csv.Error, StopIteration):
        raise BudgetError('Invalid UTF-8 semicolon CSV') from None
    if header[:len(HEADERS)] != list(HEADERS) or len(set(header)) != len(header):
        raise BudgetError('Unsupported billing CSV schema')
    extras = header[len(HEADERS):]
    if any(name not in OPTIONAL_HEADERS for name in extras) or not rows:
        raise BudgetError('Unsupported or empty billing CSV schema')
    zone = fixed_timezone(timezone)
    if now is None: now = dt.datetime.now(dt.timezone.utc)
    if not isinstance(now, dt.datetime) or now.tzinfo is None:
        raise BudgetError('Explicit aware measurement clock required')
    scopes = {name: set() for name in ('account', 'project', 'resource', 'bucket', 'pool')}
    groups, periods, unknown_rows, total, cost_complete, unknown_cost = {}, set(), 0, Decimal(0), True, False
    seen = set()
    bucket_scopes = set()
    for fields in rows:
        if len(fields) != len(header): raise BudgetError('Inconsistent CSV row width')
        account, timestamp, project, _, resource, _, consumption, unit, product, cost_text = fields[:10]
        if not account or not project or not resource: raise BudgetError('Missing CSV scope')
        try: period = dt.datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
        except ValueError: raise BudgetError('Invalid billing hour') from None
        if period.minute or period.second: raise BudgetError('Hourly billing period required')
        if zone is not None:
            period = period.replace(tzinfo=zone).astimezone(dt.timezone.utc)
            if period + dt.timedelta(hours=1) > now:
                raise BudgetError('Future or incomplete billing hour')
        periods.add(period)
        quantity = local_decimal(consumption) if consumption.strip() else None
        cost = local_decimal(cost_text, money=True) if cost_text.strip() else None
        if cost is not None and cost.as_tuple().exponent < -2:
            raise BudgetError('Kopeck-rounded billing cost required')
        if cost is None: cost_complete = False
        else: total += cost
        scope_values = {'account': account, 'project': project, 'resource': resource, 'bucket': '', 'pool': ''}
        for name, field in zip(extras, fields[10:]): scope_values[OPTIONAL_HEADERS[name]] = field
        for name, value in scope_values.items():
            if value: scopes[name].add(value)
        scope = scope_fingerprint(account, project, scope_values['bucket'], scope_values['pool'])
        identity = (scope, resource, product, period)
        if identity in seen: raise BudgetError('Duplicate metric hour in same billing scope')
        seen.add(identity)
        if scope_values['bucket']: bucket_scopes.add(scope)
        spec = metric_spec(resource) if product == 'storage' else None
        if spec is None:
            unknown_rows += 1
            unknown_cost = True
            metric, storage_class = None, None
        else:
            metric, storage_class = spec
            if unit != NATIVE_UNITS[metric]: raise BudgetError('Metric unit does not match provider tariff')
        key = (scope, resource, metric, storage_class, unit)
        group = groups.setdefault(key, {'scope_sha256': scope, 'resource_sha256': hashlib.sha256(resource.encode()).hexdigest(),
                                        'metric': metric, 'storage_class': storage_class, 'unit': unit,
                                        'quantity': Decimal(0), 'cost': Decimal(0), 'rows': 0,
                                        'complete': True, 'rate_lower': None, 'rate_upper': None})
        group['rows'] += 1
        if quantity is None or cost is None:
            group['complete'] = False
            continue
        group['quantity'] += quantity
        group['cost'] += cost
        if metric is None: continue
        if not quantity:
            if cost: raise BudgetError('Positive charge with zero consumption')
            continue
        lower = max(Decimal(0), cost - Decimal('.005')) / quantity * FACTORS[metric]
        upper = (cost + Decimal('.005')) / quantity * FACTORS[metric]
        group['rate_lower'] = lower if group['rate_lower'] is None else max(lower, group['rate_lower'])
        group['rate_upper'] = upper if group['rate_upper'] is None else min(upper, group['rate_upper'])
    metrics, inconsistent = [], False
    for group in groups.values():
        complete = group.pop('complete')
        quantity, cost = group.pop('quantity'), group.pop('cost')
        lower, upper = group.pop('rate_lower'), group.pop('rate_upper')
        conflict = lower is not None and lower >= upper
        inconsistent |= conflict
        group.update(consumption=number_text(quantity) if complete else None,
                     cost_rub=number_text(cost) if complete else None,
                     rate_unit=RATE_UNITS.get(group['metric']),
                     observed_rate=number_text(cost / quantity * FACTORS[group['metric']]) if complete and quantity and group['metric'] else None,
                     rate_interval={'lower': number_text(lower), 'upper': number_text(upper)}
                     if complete and lower is not None and not conflict else None)
        metrics.append(group)
    missing = ['native_monthly_pattern_missing']
    if not scopes['bucket']: missing.append('bucket_attribution_missing')
    if not scopes['pool']: missing.append('pool_attribution_missing')
    if zone is None: missing.append('source_timezone_unknown')
    if not cost_complete: missing.append('cost_missing')
    if unknown_cost: missing.append('unknown_metric_rows')
    if inconsistent: missing.append('inconsistent_observed_tariff')
    first, last = min(periods), max(periods)
    render = lambda value: value.isoformat().replace('+00:00', 'Z') if zone is not None else value.isoformat()
    return {'parsed': True, 'provider_budget_verified': False, 'provider_billing_verified': False,
            'provenance': {'file_sha256': hashlib.sha256(data).hexdigest(), 'encoding': 'utf-8-sig',
                           'delimiter': ';', 'schema': header, 'rows': len(rows),
                           'source_authenticity_verified': False, 'timezone': timezone,
                           'rate_interval_assumption': 'nearest kopeck rounding; quantities exact; not confirmed by CSV',
                           'tax_basis': 'unknown', 'provider_region': 'not present in CSV'},
            'scope_counts': {key: len(values) for key, values in scopes.items()},
            'bucket_scopes': sorted(bucket_scopes),
            'period': {'first_utc' if zone else 'first_local': render(first),
                       'last_utc' if zone else 'last_local': render(last), 'observed_hours': len(periods),
                       'span_hours': int((last - first).total_seconds() / 3600) + 1,
                       'monthly_pattern_verified': False},
            'metrics': metrics, 'unknown_metric_rows': unknown_rows,
            'observed_operations': sorted({group['metric'] for group in metrics if group['metric'] in ('put', 'get', 'delete')}),
            'cost_rub': number_text(total) if cost_complete else None,
            'cost_scope': 'all exported rows; current period only; no monthly extrapolation',
            'reconciliation_status': 'incomplete', 'missing': missing}


def reconcile_billing(report, rates, source_scope):
    """Verify scope, dimensions and tariff compatibility, never rate authenticity."""
    missing = []
    if not isinstance(report, dict) or not report.get('parsed'):
        return {'compatible': False, 'missing': ['account_billing_not_reconciled']}
    for condition in report.get('missing', []):
        if condition != 'native_monthly_pattern_missing': missing.append(condition)
    if report.get('bucket_scopes') != [source_scope]: missing.append('account_bucket_scope_mismatch')
    for metric, key in RATE_KEYS.items():
        observed = [group for group in report['metrics'] if group['metric'] == metric
                    and group['storage_class'] == 'standard' and group['scope_sha256'] == source_scope]
        if not observed: missing.append('account_rate_unobserved:' + metric)
        for group in observed:
            interval = group['rate_interval']
            if interval is None: missing.append('account_rate_unknown:' + metric)
            elif key not in rates or not (local_decimal(interval['lower']) <= local_decimal(rates[key]) < local_decimal(interval['upper'])):
                missing.append('account_rate_mismatch:' + metric)
    return {'compatible': not missing, 'missing': sorted(set(missing)),
            'tariff_authenticity_verified': False}


def monthly_projection(samples, cadence, inventory, rates, *, account_report=None,
                       budget_rub='500', max_gib='10'):
    """30-day scenario forecast with 730-hour provider storage month pricing.

Every scenario requires a native receipt and provider HTTP meter. Retained
bytes and object deltas are conservative upper bounds with no assumed dedup
or prune savings. No manual test count is used as a scheduled monthly cadence.
"""
    if not all(isinstance(value, dict) for value in (samples, cadence, inventory, rates)):
        raise BudgetError('Measurement dictionaries required')
    budget, capacity = local_decimal(budget_rub), local_decimal(max_gib)
    if not budget or not capacity: raise BudgetError('Positive budget and capacity required')
    missing, counts, measured_rates = [], {}, {}
    for metric, key in RATE_KEYS.items():
        if rates.get(key) is None: missing.append('rate_missing:' + metric)
        else: measured_rates[key] = local_decimal(rates[key])
    scope = inventory.get('source_scope')
    if not isinstance(scope, str) or not SHA.fullmatch(scope): missing.append('inventory_scope_missing')
    if not isinstance(inventory.get('receipt_sha256'), str) or not SHA.fullmatch(inventory['receipt_sha256']):
        missing.append('inventory_receipt_missing')
    for key in ('storage_bytes', 'objects', 'buckets'):
        if inventory.get(key) is None: missing.append('inventory_missing:' + key)
        else: nonnegative_integer(inventory[key])
    for job in JOBS:
        count = FIXED_CADENCE.get(job, cadence.get(job))
        if count is None: missing.append('cadence_missing:' + job)
        else: counts[job] = nonnegative_integer(count)
        if job in FIXED_CADENCE and job in cadence and cadence[job] != count:
            raise BudgetError('Fixed required schedule cannot be overridden')
        sample = samples.get(job)
        if not isinstance(sample, dict):
            missing.append('native_sample_missing:' + job)
            continue
        if sample.get('measurement') != 'native': missing.append('native_sample_unverified:' + job)
        if sample.get('source_scope') != scope: missing.append('sample_scope_mismatch:' + job)
        if not isinstance(sample.get('receipt_sha256'), str) or not SHA.fullmatch(sample['receipt_sha256']):
            missing.append('native_receipt_missing:' + job)
        http = sample.get('provider_http')
        if not isinstance(http, dict): missing.append('provider_http_missing:' + job)
        else:
            for operation in ('put', 'get', 'delete'):
                if http.get(operation) is None: missing.append('provider_http_unknown:' + job + ':' + operation)
                else: nonnegative_integer(http[operation])
        for key in ('egress_bytes', 'retained_delta_bytes', 'new_objects'):
            if sample.get(key) is None: missing.append('native_measurement_missing:' + job + ':' + key)
            else: nonnegative_integer(sample[key])
    result = {'budget_gate': False, 'provider_billing_verified': False,
              'projected_rub': None, 'over_limit': None, 'monthly_jobs': counts,
              'projection_days': 30, 'billing_month_hours': 730, 'missing': missing}
    if missing: return result
    objects = inventory['objects'] + sum(samples[job]['new_objects'] * counts[job] for job in JOBS)
    stored = inventory['storage_bytes'] + sum(samples[job]['retained_delta_bytes'] * counts[job] for job in JOBS)
    stored += (objects + inventory['buckets']) * METADATA_BYTES
    usage = {'storage_gib': number_text(Decimal(stored) / GIB),
             'egress_gib': number_text(Decimal(sum(samples[job]['egress_bytes'] * counts[job] for job in JOBS)) / GIB)}
    for operation in ('put', 'get', 'delete'):
        usage[operation + '_requests'] = sum(samples[job]['provider_http'][operation] * counts[job] for job in JOBS)
    cost = local_decimal(usage['storage_gib']) * measured_rates['storage_rub_gib_month']
    cost += local_decimal(usage['egress_gib']) * measured_rates['egress_rub_gib']
    cost += sum(Decimal(usage[operation + '_requests']) * measured_rates[operation + '_rub_1000'] / 1000
                for operation in ('put', 'get', 'delete'))
    billing = reconcile_billing(account_report, rates, scope)
    # Compatibility is a numerical test. A user-supplied CSV with unconfirmed
    # cost/quantity rounding and tax basis does not authenticate the tariff.
    verification_missing = []
    if isinstance(account_report, dict):
        provenance = account_report.get('provenance', {})
        if not provenance.get('source_authenticity_verified'):
            verification_missing.append('account_export_authenticity_unverified')
        if provenance.get('tax_basis') == 'unknown': verification_missing.append('account_tax_basis_unknown')
        if provenance.get('rate_interval_assumption'):
            verification_missing.append('account_rounding_basis_unverified')
    over_limit = cost > budget or Decimal(stored) / GIB > capacity
    result.update(usage=usage, storage_upper_bound_bytes=stored, projected_rub=number_text(cost),
                  over_limit=over_limit, missing=billing['missing'] + verification_missing,
                  account_tariff_compatible=billing['compatible'],
                  budget_gate=billing['compatible'] and not verification_missing and not over_limit,
                  provenance={'native_receipts': {job: samples[job]['receipt_sha256'] for job in JOBS},
                              'inventory_receipt': inventory['receipt_sha256']})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('csv', type=pathlib.Path)
    parser.add_argument('--timezone', help='Known export timezone, UTC or +HH:MM; absent remains unknown')
    args = parser.parse_args()
    try:
        result = import_billing_csv(args.csv.read_bytes(), timezone=args.timezone)
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
        return 0
    except (BudgetError, OSError):
        print(json.dumps({'parsed': False, 'error': 'Billing input rejected or unreadable'}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
