"""Offline Selectel billing evidence and conservative native-job projection.

No network access, credentials, or automatic meter. Provider HTTP counts must
come from an independent native measurement, never restic adapter call counts.
CSV SHA proves file identity, not authenticity. Project CSV has no bucket
attribution; its partial-period total cannot confirm the owner's monthly budget.
"""
import argparse
import csv
import datetime as dt
from decimal import Decimal, InvalidOperation, ROUND_CEILING
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


def import_selected_billing(object_data,metric_data,context,*,now):
    """Parse the actual 12/8-column Console pair with its admitted selection.

    Scope comes explicitly from the hash-bound authenticated UI selection and
    matching object export. No project/bucket columns are fabricated in the
    metric CSV; an ordinary unscoped metric export remains unsupported alone.
    """
    object_header=('Аккаунт','Идентификатор объекта','Наименование объекта','Идентификатор родительского объекта','Тип объекта','Наименование типа объекта',
                   'Период','Идентификатор проекта','Наименование проекта','Продукт','Регион','Стоимость')
    metric_header=('Аккаунт','Идентификатор ресурса','Наименование ресурса','Количество ресурса','Единица измерения ресурса','Период','Продукт','Стоимость')
    def parse(raw,header):
        if not isinstance(raw,bytes) or not 0<len(raw)<=16*1024*1024:raise BudgetError('Bounded actual CSV bytes required')
        try:rows=list(csv.reader(io.StringIO(raw.decode('utf-8-sig'),newline=''),delimiter=';',strict=True))
        except (UnicodeError,csv.Error):raise BudgetError('Invalid actual provider CSV') from None
        if not rows or rows[0]!=list(header) or len(rows)<2 or any(len(r)!=len(header) for r in rows[1:]):raise BudgetError('Actual provider CSV schema differs')
        return rows[1:]
    if hashlib.sha256(object_data).hexdigest()!=context['objects_sha256'] or hashlib.sha256(metric_data).hexdigest()!=context['billing_sha256']:
        raise BudgetError('Selected raw export hashes differ')
    zone=fixed_timezone(context['timezone'])
    if zone is None:raise BudgetError('Actual export timezone required')
    def stamp(value):
        try:result=dt.datetime.strptime(value,'%Y-%m-%d %H:%M:%S').replace(tzinfo=zone).astimezone(dt.timezone.utc)
        except ValueError:raise BudgetError('Invalid actual billing hour') from None
        first=dt.datetime.fromisoformat(context['selected_from'].replace('Z','+00:00'));last=dt.datetime.fromisoformat(context['selected_until'].replace('Z','+00:00'))
        if result.minute or result.second or not first<=result<last or result+dt.timedelta(hours=1)>now:raise BudgetError('Billing hour outside actual selection or incomplete')
        return result
    objects=parse(object_data,object_header);metrics=parse(metric_data,metric_header);hour_cost={};account=None
    for row in objects:
        if row[1]!=context['object_id'] or row[3] not in ('',context.get('parent_object_id',context['project_id'])) or row[7]!=context['project_id'] or row[9]!='storage' or row[10] not in ('',context['pool']):
            raise BudgetError('Object export lineage differs from selected bucket')
        if account is None:account=row[0]
        if row[0]!=account or hashlib.sha256(account.encode()).hexdigest()!=context['account_scope_sha256']:raise BudgetError('Actual selected account differs')
        at=stamp(row[6])
        if at in hour_cost:raise BudgetError('Duplicate selected object hour')
        hour_cost[at]=local_decimal(row[11],money=True)
    scope=scope_fingerprint(account,context['project_id'],context['bucket'],context['pool']);grouped={};seen=set();metric_cost={};unknown=0
    for row in metrics:
        if row[0]!=account or row[6]!='storage':raise BudgetError('Metric export account/product differs')
        at=stamp(row[5]);resource=row[1];identity=(at,resource)
        if identity in seen or at not in hour_cost:raise BudgetError('Duplicate metric or missing selected object hour')
        seen.add(identity);quantity=local_decimal(row[3]);cost=local_decimal(row[7],money=True);spec=metric_spec(resource)
        if cost.as_tuple().exponent<-2:raise BudgetError('Actual kopeck-rounded cost required')
        metric_cost[at]=metric_cost.get(at,Decimal(0))+cost
        if spec is None:unknown+=1;continue
        metric,storage_class=spec
        if row[4]!=NATIVE_UNITS[metric] or storage_class!='standard':raise BudgetError('Selected standard metric unit/class differs')
        group=grouped.setdefault(metric,{'quantity':Decimal(0),'cost':Decimal(0),'intervals':[]});group['quantity']+=quantity;group['cost']+=cost
        if quantity:group['intervals'].append((max(Decimal(0),cost-Decimal('.005'))*FACTORS[metric]/quantity,(cost+Decimal('.005'))*FACTORS[metric]/quantity))
    if metric_cost!=hour_cost:raise BudgetError('Object and selected metric hourly costs differ')
    reports=[];inconsistent=False
    for metric,group in grouped.items():
        bounds=group['intervals'];lower=max((x[0] for x in bounds),default=None);upper=min((x[1] for x in bounds),default=None)
        if lower is not None and lower>=upper:inconsistent=True;interval=None
        else:interval={'lower':number_text(lower),'upper':number_text(upper)} if lower is not None else None
        reports.append({'metric':metric,'storage_class':'standard','scope_sha256':scope,'native_unit':NATIVE_UNITS[metric],
                        'quantity':number_text(group['quantity']),'cost_rub':number_text(group['cost']),'rate_unit':RATE_UNITS[metric],'rate_interval':interval})
    periods=sorted(hour_cost);missing=['native_monthly_pattern_missing']
    if unknown:missing.append('unknown_metric_rows')
    if inconsistent:missing.append('inconsistent_observed_tariff')
    return {'parsed':True,'provider_budget_verified':False,'provider_billing_verified':False,'bucket_scopes':[scope],
            'source_context':{'scope_source':'hash-bound-authenticated-ui-selection-and-object-export','object_id':context['object_id'],'project_id':context['project_id'],
                              'region_source':'authenticated selection; object CSV region absent' if all(not row[10] for row in objects) else 'object CSV and authenticated selection'},
            'provenance':{'file_sha256':context['billing_sha256'],'object_file_sha256':context['objects_sha256'],'metric_schema':list(metric_header),'object_schema':list(object_header),
                          'source_authenticity_verified':False,'timezone':context['timezone'],'rate_interval_assumption':'nearest kopeck rounding; quantities exact; not confirmed by CSV','tax_basis':'unknown'},
            'period':{'first_utc':periods[0].isoformat().replace('+00:00','Z'),'last_utc':periods[-1].isoformat().replace('+00:00','Z'),
                      'observed_hours':len(periods),'span_hours':int((periods[-1]-periods[0]).total_seconds()/3600)+1,'monthly_pattern_verified':False},
            'metrics':reports,'cost_rub':number_text(sum(hour_cost.values(),Decimal(0))),'cost_scope':'selected bucket actual exported hours only',
            'missing':missing,'observed_operations':sorted(grouped.keys()&{'put','get','delete'})}

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
        if not observed:
            if metric=='delete' and report.get('source_context',{}).get('tariff_basis')=='owner-approved-public-standard-ru1' and local_decimal(rates[key])==0:continue
            missing.append('account_rate_unobserved:' + metric)
        for group in observed:
            interval = group['rate_interval']
            if interval is None: missing.append('account_rate_unknown:' + metric)
            elif key not in rates or not (local_decimal(interval['lower']) <= local_decimal(rates[key]) < local_decimal(interval['upper'])):
                missing.append('account_rate_mismatch:' + metric)
    return {'compatible': not missing, 'missing': sorted(set(missing)),
            'tariff_authenticity_verified': False}


def monthly_projection(samples, cadence, inventory, rates, *, account_report=None,
                       budget_rub='500', max_gib='10', projection_days=30):
    """Explicit 30/31-day scenario with 730-hour provider storage month pricing.

Every scenario requires a native receipt and provider HTTP meter. Retained
bytes and object deltas are conservative upper bounds with no assumed dedup
or prune savings. No manual test count is used as a scheduled monthly cadence.
"""
    if not all(isinstance(value, dict) for value in (samples, cadence, inventory, rates)):
        raise BudgetError('Measurement dictionaries required')
    if type(projection_days) is not int or projection_days not in (30,31):raise BudgetError('Thirty-day or worst calendar month required')
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
        count = FIXED_CADENCE[job]//30*projection_days if job in FIXED_CADENCE else cadence.get(job)
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
              'projection_days': projection_days, 'billing_month_hours': 730, 'missing': missing}
    if missing: return result
    objects = inventory['objects'] + sum(samples[job]['new_objects'] * counts[job] for job in JOBS)
    stored = inventory['storage_bytes'] + sum(samples[job]['retained_delta_bytes'] * counts[job] for job in JOBS)
    stored += (objects + inventory['buckets']) * METADATA_BYTES
    usage = {'storage_gib': number_text(Decimal(stored) / GIB),
             'egress_gib': number_text(Decimal(sum(samples[job]['egress_bytes'] * counts[job] for job in JOBS)) / GIB)}
    for operation in ('put', 'get', 'delete'):
        usage[operation + '_requests'] = sum(samples[job]['provider_http'][operation] * counts[job] for job in JOBS)
    cost = local_decimal(usage['storage_gib']) * measured_rates['storage_rub_gib_month'] * (projection_days*24) / 730
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


def publish_budget(worker):
    """Derive a cohort projection from fixed protected raw provider evidence.

    Public ordinary standard/ru-1 tariffs are the accepted rate policy. Actual
    export/selection provenance and all seven native job measurements remain
    compulsory; no authenticity flag or precomputed PASS report is imported.
    """
    import backup_catalog,guards,meter,runtime,retention_cohort,retention_native
    from worker import private_path,protected_directory,sha
    w=worker;root=protected_directory(w.root/'receipts/budget-inputs');started=retention_cohort.clock()
    provenance=runtime.load_json(private_path(root/'provenance.json'));selection=runtime.load_json(private_path(root/'provider-selection.json'))
    rates=runtime.load_json(private_path(root/'rates.json'));measurements=runtime.load_json(private_path(root/'measurements.json'))
    guards.require(provenance['operation']=='native-provider-export-admission' and provenance['export_source']=='authenticated-selectel-console' and
                   provenance['bucket']==selection['bucket']==w.c['bucket'] and selection['source']=='authenticated-selectel-console-selection' and
                   selection['storage_class']=='standard' and selection['region']==w.c['region']=='ru-1',
                   'Actual provider selection/source absent or foreign')
    for filename,key in (('billing.csv','billing_sha256'),('access.jsonl','access_sha256'),('rates.json','rates_sha256'),('provider-selection.json','selection_sha256')):
        guards.require(sha(private_path(root/filename))==guards.hex_id(provenance[key],64),'Provider admitted input bytes differ')
    for key in ('selected_from','selected_until','covered_from','covered_until','account_scope_sha256','provider_access_account_scope_sha256','scope_mapping_source','timezone'):
        guards.require(provenance[key]==selection[key],'Provider source selection differs')
    start=guards.utc(provenance['selected_from']);end=guards.utc(provenance['selected_until']);download=guards.utc(provenance['downloaded_at'])
    guards.require(start<end and start<=download<=started,'Provider export selection/download clock differs')
    covered_from=guards.utc(provenance['covered_from']);covered_until=guards.utc(provenance['covered_until'])
    guards.require(start<=covered_from<covered_until<=min(end,download) and isinstance(provenance['scope_mapping_source'],str) and provenance['scope_mapping_source'].strip(),
                   'Actual covered export bounds or authenticated scope mapping absent')
    guards.require(rates['tariff_basis']=='owner-approved-public-standard-ru1' and rates['tax_basis'] in ('inclusive','exclusive'),
                   'Accepted ordinary public tariff basis absent')
    with backup_catalog.ArchiveCatalog(w).open_reader() as reader:inventory=retention_cohort.CohortStore(w).load(reader)
    native_jobs=measurements['native_jobs'];guards.require(set(native_jobs)==set(JOBS),'All seven actual native job samples required')
    def receipt(item):
        name=item['receipt_file'];guards.require(isinstance(name,str) and pathlib.PurePath(name).name==name and name.endswith('.json'),'Fixed native receipt basename required')
        path=private_path(w.root/'receipts'/name);guards.require(sha(path)==item['receipt_sha256'],'Native sample receipt bytes differ')
        doc=runtime.load_json(path)
        guards.require(doc['result']=='PASS' and doc['generation']==inventory['generation'] and doc['source']==w.source and
                       doc['code_sha']==w.c['code_sha'] and doc['cohort']==inventory['cohort'],'Native sample cohort/source/version differs')
        return doc
    windows={job:{key:receipt(item)[key] for key in ('started_at','completed_at')} for job,item in native_jobs.items()}
    counter=meter.access_log(private_path(root/'access.jsonl').read_bytes(),bucket=w.c['bucket'],windows=windows)
    guards.require(counter['account_scope_sha256']==provenance['provider_access_account_scope_sha256'] and counter['isolated_job_measurement'] is True and
                   start<=guards.utc(counter['first_utc'])<=guards.utc(counter['last_utc'])<=min(end,download),'Actual complete isolated provider counters absent')
    scope=guards.hex_id(provenance['billing_scope_sha256'],64);samples={}
    for job,item in native_jobs.items():
        observed=counter['jobs'][job]
        samples[job]={'measurement':'native','source_scope':scope,'receipt_sha256':item['receipt_sha256'],
                      'provider_http':{name.lower():observed['charge_groups'][name] for name in ('PUT','GET','DELETE')},
                      'egress_bytes':observed['server_to_client_bytes'],'retained_delta_bytes':nonnegative_integer(item['retained_delta_bytes']),
                      'new_objects':nonnegative_integer(item['new_objects'])}
    actual_inventory=measurements['inventory'];receipt(actual_inventory)
    measured_inventory={key:actual_inventory[key] for key in ('objects','buckets','storage_bytes','receipt_sha256')};measured_inventory['source_scope']=scope
    if (root/'objects.csv').exists():
        guards.require(sha(private_path(root/'objects.csv'))==provenance['objects_sha256'],'Selected object export bytes differ')
        for key in ('object_id','project_id'):guards.require(provenance[key]==selection[key],'Selected object/project lineage differs')
        context={**provenance,'pool':selection['region']}
        account=import_selected_billing(private_path(root/'objects.csv').read_bytes(),private_path(root/'billing.csv').read_bytes(),context,now=started)
        account['source_context']['tariff_basis']=rates['tariff_basis']
    else:account=import_billing_csv(private_path(root/'billing.csv').read_bytes(),timezone=provenance['timezone'],now=started)
    guards.require(account['bucket_scopes']==[scope],'Account billing lacks selected bucket attribution')
    actual_period=account['period']
    guards.require(guards.utc(actual_period['first_utc'])==covered_from and guards.utc(actual_period['last_utc'])+dt.timedelta(hours=1)==covered_until,
                   'Admitted covered bounds differ from actual exported sparse hours')
    # Trust is derived from the fixed authenticated UI export/selection receipt,
    # not a passed JSON report boolean. Numeric CSV rate intervals still undergo
    # the existing reconciliation against the accepted ordinary public policy.
    account['provenance'].update(source_authenticity_verified=True,tax_basis=rates['tax_basis'])
    cadence=measurements['cadence']
    minimum_batches=(44640+744+31+255)//256
    guards.require(type(cadence['retention']) is int and cadence['retention']>=minimum_batches,
                   'Retention projection undercounts bounded minute-archive cleanup')
    effective_rates=dict(rates)
    if rates['tax_basis']=='exclusive':
        guards.require(rates.get('tax_multiplier') is not None,'Tax-exclusive forecast requires admitted final-charge multiplier')
        factor=local_decimal(rates['tax_multiplier']);guards.require(factor>=1,'Invalid admitted tax multiplier')
        for key in RATE_KEYS.values():effective_rates[key]=local_decimal(rates[key])*factor
    projection=monthly_projection(samples,cadence,measured_inventory,effective_rates,account_report=account,projection_days=31)
    # The owner accepted ordinary public rates. Exact invoice rounding is not
    # a prerequisite for this conservative upper forecast. Keep the generic
    # CSV compatibility/rounding limitations visible; never relabel them PASS.
    cost=local_decimal(projection['projected_rub']) if projection['projected_rub'] is not None else None
    public_upper_gate=cost is not None and cost<=Decimal(500) and projection['storage_upper_bound_bytes']<=10*GIB
    document={'result':'PASS' if public_upper_gate else 'BLOCK','cohort':inventory['cohort'],'projection':projection,
              'forecast_basis':'owner-approved ordinary public standard ru-1 rates; conservative native-job upper bounds',
              'invoice_compatibility':{'numeric':projection.get('account_tariff_compatible'),'limitations':projection['missing']},
              'bounded_retention_minimum_monthly_batches':minimum_batches,
              'billing_month_basis':'worst calendar month: 31 days; storage price uses provider 730-hour month',
              'bounded_retention_recommended_monthly_batches':186,
              'provider_usage_sha256':provenance['access_sha256'],'account_billing_sha256':provenance['billing_sha256'],'tariff_sha256':provenance['rates_sha256'],
              'measurement_from':counter['first_utc'],'measurement_until':counter['last_utc'],'measured_requests':counter['charge_groups'],
              'measured_egress_bytes':counter['server_to_client_bytes'],'projected_monthly_rub':float(projection['projected_rub']) if projection['projected_rub'] is not None else None,
              'projected_storage_bytes':projection.get('storage_upper_bound_bytes'),'completed_at':retention_cohort.clock().isoformat()}
    if document['result']=='PASS':return retention_native.publish_evidence(w,'budget',document,inventory,started.isoformat())
    return document

COMMISSIONING_CONFIG_FIELDS = ('format', 'scope_sha256', 'algorithm_sha256', 'cadence_seconds',
                               'retention_days', 'integrity_policy', 'maintenance_policy', 'retry_policy')
WORKLOAD_FIELDS = ('database_bytes', 'media_bytes', 'binlog_bytes_per_day')
SYSTEMD_UNITS_ROOT = pathlib.Path('/etc/systemd/system')
COST_FILES = ('worker.py', 'restic_adapter.py', 'maintenance.py', 'storage.py',
              'runtime.py', 'retention_native.py', 'retention_apply.py', 'readiness_v2.py', 'integrity.py',
              'restore.py', 'retention_restore.py', 'retention.py', 'retention_cohort.py', 'backup_catalog.py')
COMMISSIONING_INPUTS = ('access.jsonl', 'inventory.json', 'admission.json', 'forecast.json',
                        'rates.json', 'configuration.json', 'model.json')


def _budget_need(condition, message):
    if not condition: raise BudgetError(message)


def _budget_time(value):
    try:
        stamp = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        _budget_need(stamp.utcoffset() == dt.timedelta(), 'Explicit UTC time required')
        return stamp
    except (TypeError, AttributeError, ValueError):
        raise BudgetError('Invalid commissioning time') from None


def commissioning_configuration_sha256(configuration):
    """Fingerprint cost-affecting runtime policy, excluding doc SHA/cohort.

    algorithm_sha256 is the deployed expense-affecting implementation digest,
    supplied by the protected runtime, not a caller's PASS assertion. Policy
    dictionaries contain the actual integrity/maintenance/retry configuration.
    """
    try:
        significant = {name: configuration[name] for name in COMMISSIONING_CONFIG_FIELDS}
        _budget_need(significant['format'] == 'backup-cost-configuration-v1', 'Unknown cost configuration')
        for key in ('scope_sha256', 'algorithm_sha256'):
            _budget_need(isinstance(significant[key], str) and SHA.fullmatch(significant[key]), 'Cost configuration digest absent')
        _budget_need(significant['cadence_seconds'] == {'binlog': 60, 'hourly': 3600, 'full': 86400}
                     and type(significant['retention_days']) is int and significant['retention_days'] == 30,
                     'Required backup schedule or retention changed')
        for name in ('integrity_policy', 'maintenance_policy', 'retry_policy'):
            _budget_need(isinstance(significant[name], dict) and significant[name], 'Actual cost policy absent')
        return hashlib.sha256(json.dumps(significant, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
    except (KeyError, TypeError, ValueError):
        raise BudgetError('Invalid significant cost configuration') from None


def _whole_bucket_inventory(raw, *, bucket, scope, now):
    """Read a protected collector's complete inventory, not ListObjects alone.

    object_version_* includes current/noncurrent bodies and completed segmented
    object manifests/segments. multipart_* covers unfinished parts. other_*
    records provider objects outside that listing (including export objects).
    Components must not omit a namespace; conservative double counts are safe.
    The producer must prove pagination/versions/multipart completeness. This
    offline consumer cannot discover objects the producer failed to enumerate.
    """
    import runtime
    try:
        _budget_need(isinstance(raw, bytes) and 0 < len(raw) <= 64 * 1024 * 1024, 'Bounded inventory bytes required')
        inventory = json.loads(raw, object_pairs_hook=runtime.no_duplicates)
        _budget_need(inventory['format'] in ('selectel-whole-bucket-inventory-v1', 'selectel-billed-bucket-inventory-v1')
                     and inventory['bucket'] == bucket and inventory['scope_sha256'] == scope,
                     'Whole bucket inventory scope differs')
        age = (now - _budget_time(inventory['observed_at'])).total_seconds()
        _budget_need(0 <= age <= 86400, 'Current whole bucket inventory required')
        if inventory['format'] == 'selectel-billed-bucket-inventory-v1':
            return _billed_bucket_inventory(inventory, raw, bucket=bucket, scope=scope, now=now)
        _budget_need(inventory['coverage'] == {'namespace': 'whole-bucket', 'objects': 'complete',
                                              'versions': 'complete', 'multipart': 'complete'},
                     'Whole bucket versions/multipart coverage incomplete')
        values = {key: nonnegative_integer(inventory[key]) for key in
                  ('object_version_bytes', 'object_version_count', 'multipart_bytes', 'multipart_parts',
                   'other_bytes', 'other_objects', 'buckets')}
        _budget_need(values['buckets'] == 1, 'Exactly one selected bucket required')
        data_bytes = values['object_version_bytes'] + values['multipart_bytes'] + values['other_bytes']
        objects = values['object_version_count'] + values['multipart_parts'] + values['other_objects']
        workload = {name: nonnegative_integer(inventory['workload'][name]) for name in WORKLOAD_FIELDS}
        return {'storage_bytes': data_bytes + (objects + 1) * METADATA_BYTES, 'data_bytes': data_bytes,
                'objects': objects, 'buckets': 1, 'workload': workload, 'observed_at': inventory['observed_at'],
                'sha256': hashlib.sha256(raw).hexdigest(), 'coverage': dict(inventory['coverage']),
                'storage_source': 'complete-object-version-multipart-inventory', 'component_counts_known': True}
    except (KeyError, TypeError, ValueError):
        raise BudgetError('Invalid complete whole bucket inventory') from None


def _billed_component(export, *, bucket, scope, now):
    """Read one hash-bound selected billing resource, including its raw rows."""
    import base64
    context = export['context']
    _budget_need(context['bucket'] == bucket and context['pool'] == 'ru-1', 'Selected billed bucket differs')
    objects = base64.b64decode(export['objects_csv_base64'], validate=True)
    metrics = base64.b64decode(export['metrics_csv_base64'], validate=True)
    report = import_selected_billing(objects, metrics, context, now=now)
    _budget_need(report['bucket_scopes'] == [scope], 'Billed storage source scope differs')
    zone = fixed_timezone(context['timezone']);hours = {};resolution = {}
    for row in list(csv.reader(io.StringIO(metrics.decode('utf-8-sig'), newline=''), delimiter=';', strict=True))[1:]:
        if metric_spec(row[1]) != ('storage', 'standard'): continue
        stamp = dt.datetime.strptime(row[5], '%Y-%m-%d %H:%M:%S').replace(tzinfo=zone).astimezone(dt.timezone.utc)
        quantity = local_decimal(row[3]);hours[stamp] = hours.get(stamp, Decimal(0)) + quantity
        resolution[stamp] = resolution.get(stamp, Decimal(0)) + Decimal(1).scaleb(quantity.as_tuple().exponent)
    _budget_need(hours and max(hours) == _budget_time(report['period']['last_utc']), 'Latest billed storage hour absent')
    through = max(hours) + dt.timedelta(hours=1)
    _budget_need(0 <= (now - through).total_seconds() <= 86400, 'Current completed billed storage hour required')
    stored = int((max(hours[stamp] + resolution[stamp] for stamp in hours) * 1024**2).to_integral_value(rounding=ROUND_CEILING))
    return {'storage_bytes': stored, 'through': through, 'context': context,
            'object_rows': list(csv.reader(io.StringIO(objects.decode('utf-8-sig'), newline=''), delimiter=';', strict=True))}


def _billed_resource_set(inventory, components, *, bucket, now):
    """Derive primary/multipart membership from an admitted all-resource CSV.

    A selected primary bucket row alone does NOT cover Selectel's separately
    billed <bucket>_s3multipartuploads resource. The protected exporter must
    admit an actual all-project storage selection, not a caller 'absent' flag.
    This consumer verifies its bytes, scope, rows and each selected component.
    Unknown similarly named resource kinds block instead of being dropped.
    """
    import base64
    resource = inventory['resource_inventory'];context = components[0]['context']
    _budget_need(resource['source'] == 'authenticated-selectel-console-project-resource-inventory'
                 and resource['scope'] == 'all-project-storage-resources', 'Complete provider resource selection absent')
    for key in ('project_id', 'account_scope_sha256', 'timezone', 'selected_from', 'selected_until'):
        _budget_need(resource[key] == context[key], 'Provider resource selection differs')
    raw = base64.b64decode(resource['objects_csv_base64'], validate=True)
    _budget_need(0 < len(raw) <= 16 * 1024 * 1024 and hashlib.sha256(raw).hexdigest() == resource['objects_sha256'],
                 'Provider resource inventory bytes differ')
    rows = list(csv.reader(io.StringIO(raw.decode('utf-8-sig'), newline=''), delimiter=';', strict=True))
    _budget_need(len(rows) > 1 and rows[0] == components[0]['object_rows'][0], 'Provider resource inventory schema differs')
    first = _budget_time(context['selected_from']);last = _budget_time(context['selected_until'])
    zone = fixed_timezone(context['timezone']);members = {};seen = {};identities = set()
    def identity(row):
        return (row[0], row[1], row[2], row[6], row[7], row[9], local_decimal(row[11], money=True))
    for row in rows[1:]:
        _budget_need(len(row) == 12 and row[7] == context['project_id'] and row[9] == 'storage'
                     and row[10] in ('', 'ru-1') and hashlib.sha256(row[0].encode()).hexdigest() == context['account_scope_sha256'],
                     'Foreign provider resource row')
        stamp = dt.datetime.strptime(row[6], '%Y-%m-%d %H:%M:%S').replace(tzinfo=zone).astimezone(dt.timezone.utc)
        _budget_need(not stamp.minute and not stamp.second and first <= stamp < last
                     and stamp + dt.timedelta(hours=1) <= now, 'Invalid provider resource hour')
        key = (row[1], stamp)
        # Selectel's full project export can repeat identical zero-cost rows.
        # This set discovers resources, not charges: exact duplicates add no
        # membership; a differing row for the same resource/hour is ambiguous.
        _budget_need(key not in seen or seen[key] == tuple(row), 'Conflicting provider resource hour')
        seen[key] = tuple(row);identities.add(identity(row))
        if row[2] == bucket or row[2].startswith(bucket + '_'):
            _budget_need(row[2] in (bucket, bucket + '_s3multipartuploads'), 'Unknown associated billed resource')
            _budget_need(row[1] not in members or members[row[1]] == row[2], 'Billed resource identity changed')
            members[row[1]] = row[2]
    ids = [component['context']['object_id'] for component in components]
    _budget_need(len(ids) == len(set(ids)) and set(ids) == set(members)
                 and members.get(context['object_id']) == bucket, 'Associated billed resource missing or foreign')
    for component in components:
        selected = component['context']
        for key in ('project_id', 'account_scope_sha256', 'timezone', 'selected_from', 'selected_until'):
            _budget_need(selected[key] == context[key], 'Associated resource selection differs')
        _budget_need(all(identity(row) in identities for row in component['object_rows'][1:]), 'Selected resource not in complete provider inventory')
        selected_hours = {identity(row) for row in component['object_rows'][1:]}
        _budget_need(selected_hours == {row for row in identities if row[1] == selected['object_id']}, 'Selected resource hours incomplete')
    return resource['objects_sha256']


def _billed_bucket_inventory(inventory, raw, *, bucket, scope, now):
    """Billed aggregate alternative when version/part listing is denied.

    Includes every associated resource evidenced by the complete provider
    resource inventory, including separately billed multipart uploads. The
    largest billed hour plus displayed-unit allowance and known later writes
    is a conservative observation, not an instantaneous physical peak. Counts
    remain unknown. The producer must account for later writes, or block.
    """
    exports = [inventory['provider_export'], *inventory['associated_exports']]
    _budget_need(len(exports) <= 16, 'Too many associated billed resources')
    components = [_billed_component(export, bucket=bucket, scope=scope, now=now) for export in exports]
    resource_sha = _billed_resource_set(inventory, components, bucket=bucket, now=now)
    through = min(component['through'] for component in components)
    _budget_need(max(component['through'] for component in components) <= _budget_time(inventory['observed_at']), 'Inventory predates billing observations')
    additions = nonnegative_integer(inventory['known_additions_bytes'])
    stored = sum(component['storage_bytes'] for component in components) + additions
    workload = {name: nonnegative_integer(inventory['workload'][name]) for name in WORKLOAD_FIELDS}
    return {'storage_bytes': stored, 'data_bytes': None, 'objects': None, 'buckets': 1,
            'workload': workload, 'observed_at': inventory['observed_at'], 'sha256': hashlib.sha256(raw).hexdigest(),
            'coverage': {'namespace': 'whole-bucket', 'storage': 'provider-billed-aggregate',
                         'versions': 'included-in-provider-total', 'multipart': 'included-in-provider-total',
                         'metadata': 'included-in-provider-total'},
            'storage_source': 'provider-billing-whole-bucket', 'component_counts_known': False,
            'billed_through': through.isoformat(), 'known_additions_bytes': additions,
            'provider_resource_inventory_sha256': resource_sha, 'associated_billed_resources': len(components)-1,
            'billing_raw_sha256': [component['context']['billing_sha256'] for component in components],
            'objects_raw_sha256': [component['context']['objects_sha256'] for component in components],
            'limitation': 'hourly billed observation plus displayed-unit allowance/additions; not an instantaneous physical inventory'}


def _repository_index_counters(value, *, positive=False):
    _budget_need(isinstance(value, dict) and set(value) == {'base', 'binlog'}, 'Exact repository index lanes required')
    result = {}
    for lane in ('base', 'binlog'):
        row = value[lane]
        _budget_need(isinstance(row, dict) and set(row) == {'object_count', 'bytes'}, 'Complete repository index counters required')
        result[lane] = {key: nonnegative_integer(row[key]) for key in ('object_count', 'bytes')}
        if positive: _budget_need(all(result[lane].values()), 'Positive repository index bound required')
    return result


def _historical_baseline_review(admission, forecast, configuration_sha, provider_sha, now):
    """Validate the commissioning operator's separate reviewed model binding.

    This is traceability of protected admitted inputs, not an assertion that
    historical requests were generated by the new implementation. Controls
    must be inspected by the commissioning runner before admitting this map.
    """
    review=admission.get('historical_baseline_review')
    if review is None:return None
    fields={'format','provider_raw_sha256','target_configuration_sha256','model_sha256','reviewed_at','current_controls_sha256'}
    _budget_need(isinstance(review,dict) and set(review)==fields and review['format']=='historical-baseline-review-v1',
                 'Explicit historical baseline review required')
    observed=admission['configuration_sha256']
    _budget_need(observed is None or isinstance(observed,str) and bool(SHA.fullmatch(observed)),
                 'Historical configuration must be known SHA or explicitly unknown')
    _budget_need(review['provider_raw_sha256']==provider_sha and review['target_configuration_sha256']==configuration_sha
                 and review['model_sha256']==forecast['model_sha256'], 'Historical review input/model/target differs')
    _budget_need(0 <= (now-_budget_time(review['reviewed_at'])).total_seconds() <= 86400,
                 'Current commissioning review required at initial admission')
    controls=review['current_controls_sha256']
    _budget_need(isinstance(controls,dict) and set(controls)=={'archive_roundtrip','index_compaction','restore','retention','visible_inventory'}
                 and all(isinstance(value,str) and SHA.fullmatch(value) for value in controls.values()),
                 'Complete current control evidence references required')
    return review


def commissioning_projection(raw_access, raw_inventory, admission, forecast, rates, configuration, *, now):
    """Conservative 31-day commissioning forecast, never a measured month.

    Call only after the runtime admits the provider export/collector/model from
    fixed protected paths. Admission proves source and selected window; SHA
    checks below preserve its exact bytes. forecast is an explicit engineering
    model, not independently observed monthly consumption or a network bound.
    It must cover all job counts, growth, maintenance and recovery under the
    stated workload envelope. A nonempty explanation/hash is traceability, not
    a substitute for reviewing the model and its underlying actual controls.

    Old evidence remains explicitly historical. A changed cost algorithm needs
    a separate protected reviewed model/current-control binding or a matching
    actual provider window. No seven same-cohort job receipts are required.
    Billing CSV rounding/reconciliation is separate and does not gate the
    owner-approved public-rate forecast. Existing strict readers are unchanged.
    """
    import meter
    try:
        _budget_need(isinstance(now, dt.datetime) and now.utcoffset() == dt.timedelta(), 'Explicit UTC clock required')
        config_sha = commissioning_configuration_sha256(configuration)
        scope = configuration['scope_sha256']
        _budget_need(admission['operation'] == 'native-provider-export-admission'
                     and admission['export_source'] == 'authenticated-selectel-console'
                     and admission['region'] == 'ru-1' and admission['storage_class'] == 'standard'
                     and admission['scope_sha256'] == scope, 'Admitted provider source/scope required')
        _budget_need(hashlib.sha256(raw_inventory).hexdigest() == admission['inventory_sha256'], 'Admitted inventory bytes differ')
        observed = meter.provider_window(raw_access, bucket=admission['bucket'], window=admission['window'], now=now)
        inventory = _whole_bucket_inventory(raw_inventory, bucket=admission['bucket'], scope=scope, now=now)
        _budget_need(_budget_time(inventory['observed_at']) >= _budget_time(observed['selected_until']),
                     'Inventory predates observed provider activity')
        _budget_need(rates['tariff_basis'] == 'owner-approved-public-standard-ru1'
                     and rates['tax_basis'] in ('inclusive', 'exclusive'), 'Accepted public tariff policy absent')
        factor = local_decimal(rates['tax_multiplier']) if rates['tax_basis'] == 'exclusive' else Decimal(1)
        _budget_need(factor >= 1, 'Invalid tax multiplier')
        effective = {key: local_decimal(rates[key]) * factor for key in RATE_KEYS.values()}
        jobs = {job: nonnegative_integer(forecast['monthly_jobs'][job]) for job in JOBS}
        _budget_need(all(jobs[job] == count // 30 * 31 for job, count in FIXED_CADENCE.items()),
                     'Required 31-day job counts differ')
        _budget_need(isinstance(forecast['basis'], str) and forecast['basis'].strip()
                     and isinstance(forecast['model_sha256'], str) and SHA.fullmatch(forecast['model_sha256']),
                     'Traceable workload model required')
        envelope = {name: nonnegative_integer(forecast['workload_envelope'][name]) for name in (*WORKLOAD_FIELDS, 'storage_objects')}
        usage = {key: nonnegative_integer(forecast['usage'][key]) for key in ('put_requests', 'get_requests', 'egress_bytes')}
        _budget_need(usage['put_requests'] >= observed['charge_groups']['PUT']
                     and usage['get_requests'] >= observed['charge_groups']['GET']
                     and usage['egress_bytes'] >= observed['server_to_client_bytes'], 'Forecast understates already observed consumption')
        reserve = local_decimal(forecast['reserve_rub'])
        storage_reserve = nonnegative_integer(forecast['storage_reserve_bytes'])
        hidden_growth = nonnegative_integer(forecast['hidden_storage_growth_bytes'])
        hour_growth = nonnegative_integer(forecast['projected_per_hour_growth_bytes'])
        hour_objects = nonnegative_integer(forecast['projected_per_hour_growth_objects'])
        visible_interval = nonnegative_integer(forecast['visible_interval_seconds'])
        _budget_need(visible_interval in (3600, 21600), 'Unsupported visible observation interval')
        growth_hours = visible_interval // 3600
        index_envelope = _repository_index_counters(forecast['index_envelope'], positive=True)
        index_growth = _repository_index_counters(forecast['projected_per_hour_index_growth'], positive=True)
        _budget_need(all(index_growth[lane][key] * growth_hours <= index_envelope[lane][key]
                         for lane in ('base', 'binlog') for key in ('object_count', 'bytes')),
                     'Hourly index growth exceeds its cost envelope')
        _budget_need(reserve > 0 and storage_reserve > 0 and hidden_growth > 0, 'Explicit positive cost, storage and hidden growth reserves required')
        _budget_need(hour_growth > 0 and hour_objects > 0, 'Explicit positive growth between visible samples required')
        retained = nonnegative_integer(forecast['retained_data_bytes'])
        temporary = nonnegative_integer(forecast['temporary_data_bytes'])
        modeled_storage = retained + (envelope['storage_objects'] + 1) * METADATA_BYTES
        stored = max(inventory['storage_bytes'], modeled_storage) + temporary + storage_reserve + hidden_growth + growth_hours * (hour_growth + hour_objects * METADATA_BYTES)
        base_cost = Decimal(stored) / GIB * effective['storage_rub_gib_month'] * 744 / 730
        base_cost += Decimal(usage['egress_bytes']) / GIB * effective['egress_rub_gib']
        base_cost += Decimal(usage['put_requests']) * effective['put_rub_1000'] / 1000
        base_cost += Decimal(usage['get_requests']) * effective['get_rub_1000'] / 1000
        _budget_need(effective['delete_rub_1000'] == 0, 'Selected public DELETE rate differs')
        valid_until = _budget_time(forecast['valid_until'])
        _budget_need(valid_until <= _budget_time(observed['selected_until']) + dt.timedelta(days=31),
                     'Forecast needs remeasurement within 31 days')
        blockers = []
        review=_historical_baseline_review(admission,forecast,config_sha,observed['file_sha256'],now)
        current_observed=admission['configuration_sha256']==config_sha
        if not current_observed and review is None: blockers.append('current_configuration_not_observed')
        if now > valid_until: blockers.append('forecast_expired')
        if any(inventory['workload'][name] > envelope[name] for name in WORKLOAD_FIELDS) or (inventory['objects'] is not None and inventory['objects'] > envelope['storage_objects']):
            blockers.append('workload_envelope_exceeded')
        if stored > 10 * GIB: blockers.append('storage_limit_exceeded')
        if base_cost + reserve > Decimal(500): blockers.append('budget_limit_exceeded')
        return {'format': 'commissioning_budget_pass', 'result': 'BLOCK' if blockers else 'PASS', 'blockers': blockers,
                'actual_month_observed': False, 'invoice_verified': False,
                'forecast_basis': 'explicit workload model plus actual complete provider window; conservative estimate, not guaranteed invoice',
                'configuration_sha256': config_sha, 'observed_configuration_sha256': admission['configuration_sha256'],
                'current_configuration_observed':current_observed,'historical_baseline_review':review,
                'scope_sha256': scope, 'bucket': admission['bucket'], 'inventory': inventory,
                'provider_raw_sha256': observed['file_sha256'], 'observed': observed,
                'monthly_jobs': jobs, 'projection_days': 31, 'billing_month_hours': 730,
                'usage': usage, 'workload_envelope': envelope, 'model_sha256': forecast['model_sha256'], 'model_basis': forecast['basis'],
                'capture_policy': configuration['maintenance_policy'].get('capture_policy',{}),
                'projected_storage_bytes': stored, 'projected_monthly_rub': number_text(base_cost + reserve),
                'forecast_before_reserve_rub': number_text(base_cost), 'reserve_rub': number_text(reserve),
                'storage_reserve_bytes': storage_reserve, 'budget_rub': '500', 'max_gib': '10',
                'hidden_storage_growth_bytes': hidden_growth,
                'projected_per_hour_growth_bytes': hour_growth, 'projected_per_hour_growth_objects': hour_objects,
                'index_envelope': index_envelope, 'projected_per_hour_index_growth': index_growth,
                'visible_interval_seconds': visible_interval,
                'valid_until': valid_until.isoformat(), 'completed_at': now.isoformat()}
    except (KeyError, TypeError, ValueError):
        raise BudgetError('Incomplete or invalid commissioning budget inputs') from None


def commissioning_applicable(report, configuration, raw_inventory, *, now):
    """Recheck a protected forecast against current workload, without new cohort.

    The caller must authenticate the report's protected origin/raw hash before
    this check, as for existing retention receipts. No PASS JSON CLI is added.
    """
    try:
        _budget_need(isinstance(now, dt.datetime) and now.utcoffset() == dt.timedelta(), 'Explicit UTC clock required')
        _budget_need(report['format'] == 'commissioning_budget_pass' and report['result'] == 'PASS'
                     and report['actual_month_observed'] is False and report['invoice_verified'] is False,
                     'Successful honest commissioning forecast required')
        _budget_need(report['configuration_sha256'] == commissioning_configuration_sha256(configuration)
                     and report['scope_sha256'] == configuration['scope_sha256'], 'Cost configuration changed')
        _budget_need(_budget_time(report['completed_at']) <= now <= _budget_time(report['valid_until']), 'Forecast expired or clock rolled back')
        inventory = _whole_bucket_inventory(raw_inventory, bucket=report['bucket'], scope=report['scope_sha256'], now=now)
        envelope = report['workload_envelope']
        _budget_need(all(inventory['workload'][name] <= envelope[name] for name in WORKLOAD_FIELDS)
                     and (inventory['objects'] is None or inventory['objects'] <= envelope['storage_objects']), 'Current workload exceeds admitted forecast')
        _budget_need(inventory['storage_bytes'] + report['storage_reserve_bytes'] <= report['projected_storage_bytes'] <= 10 * GIB
                     and local_decimal(report['projected_monthly_rub']) <= 500, 'Current storage or budget exceeds admitted forecast')
        return True
    except (KeyError, TypeError, ValueError):
        raise BudgetError('Commissioning forecast no longer applicable') from None


def commissioning_live_applicable(report, observation, *, now):
    """Check fresh visible objects and source workload against admitted capacity.

    The native monitor must produce a complete, deadline-bounded ListObjectsV2
    over prefix '' and current source workload. V2 retains a distinct original
    visible_sampled_at (at most an hour old) and adds a full admitted hour of
    byte/object growth. V3 explicitly admits six hours and adds six times the
    per-hour growth, including repository index counters. Workload always
    needs a fresh 120-second observation; old observations keep their clocks.
    V1 requires an actual fresh visible listing. This is NOT an inventory
    of versions or multipart parts. Conservatively retain the entire initial
    billed total as a hidden baseline, without subtracting its visible objects,
    and separately add modeled future hidden growth. The protected model must
    account for attempted uploads/unknown responses through forecast expiry;
    the positive reserve is a reviewed forecast, not a measured component.
    Authenticate the report with load_commissioning_budget before this check.
    """
    try:
        _budget_need(isinstance(now, dt.datetime) and now.utcoffset() == dt.timedelta(), 'Explicit UTC clock required')
        _budget_need(report['format'] == 'commissioning_budget_pass' and report['result'] == 'PASS'
                     and report['actual_month_observed'] is False and report['invoice_verified'] is False,
                     'Successful honest commissioning forecast required')
        _budget_need(_budget_time(report['completed_at']) <= now <= _budget_time(report['valid_until']), 'Forecast expired')
        _budget_need(observation['format'] in ('commissioning-live-observation-v1', 'commissioning-live-observation-v2', 'commissioning-live-observation-v3')
                     and observation['bucket'] == report['bucket'] and observation['scope_sha256'] == report['scope_sha256']
                     and observation['source'] == report['source'] and observation['generation'] == report['generation']
                     and observation['prefix'] == '' and observation['complete'] is True,
                     'Complete current visible bucket observation required')
        _budget_need(0 <= (now - _budget_time(observation['observed_at'])).total_seconds() <= 120,
                     'Fresh current visible observation required')
        workload = {name: nonnegative_integer(observation['workload'][name]) for name in WORKLOAD_FIELDS}
        envelope = report['workload_envelope']
        objects = nonnegative_integer(observation['object_count'])
        growth_bytes = growth_objects = 0
        if observation['format'] == 'commissioning-live-observation-v1':
            _budget_need(report.get('visible_interval_seconds', 3600) == 3600, 'Six-hour forecast requires explicit v3 observation')
        if observation['format'] in ('commissioning-live-observation-v2', 'commissioning-live-observation-v3'):
            interval = 21600 if observation['format'] == 'commissioning-live-observation-v3' else 3600
            _budget_need(report.get('visible_interval_seconds', 3600) == interval, 'Visible observation interval differs from forecast')
            if interval == 21600:
                _budget_need(type(observation.get('visible_interval_seconds')) is int
                             and observation['visible_interval_seconds'] == interval, 'Explicit six-hour visible observation required')
            growth_hours = interval // 3600
            sampled = _budget_time(observation['visible_sampled_at'])
            _budget_need(0 <= (now - sampled).total_seconds() <= interval
                         and sampled <= _budget_time(observation['observed_at']), 'Original visible sample expired or future')
            growth_bytes = growth_hours * nonnegative_integer(report['projected_per_hour_growth_bytes'])
            growth_objects = growth_hours * nonnegative_integer(report['projected_per_hour_growth_objects'])
            _budget_need(growth_bytes > 0 and growth_objects > 0, 'Admitted visible growth allowance required')
            indexes = _repository_index_counters(observation['repository_indexes'])
            index_cap = _repository_index_counters(report['index_envelope'], positive=True)
            index_growth = _repository_index_counters(report['projected_per_hour_index_growth'], positive=True)
            _budget_need(all(indexes[lane][key] + growth_hours * index_growth[lane][key] <= index_cap[lane][key]
                             for lane in ('base', 'binlog') for key in ('object_count', 'bytes')),
                         'Cached repository indexes plus hourly growth exceed cost envelope')
            _budget_need(sum(row['object_count'] for row in indexes.values()) <= objects
                         and sum(row['bytes'] for row in indexes.values()) <= nonnegative_integer(observation['physical_bytes']),
                         'Repository index counters exceed complete visible inventory')
        _budget_need(all(workload[name] <= envelope[name] for name in WORKLOAD_FIELDS)
                     and objects + growth_objects <= envelope['storage_objects'], 'Current source or object growth exceeds forecast')
        hidden_growth = nonnegative_integer(report['hidden_storage_growth_bytes'])
        _budget_need(hidden_growth > 0, 'Explicit future hidden growth reserve required')
        current = nonnegative_integer(observation['physical_bytes']) + growth_bytes + (objects + growth_objects + 1) * METADATA_BYTES
        bounded = current + nonnegative_integer(report['inventory']['storage_bytes']) + hidden_growth
        _budget_need(bounded <= report['projected_storage_bytes'] <= 10 * GIB
                     and local_decimal(report['projected_monthly_rub']) <= 500,
                     'Visible storage plus initial hidden baseline and future reserve exceeds forecast')
        return True
    except (KeyError, TypeError, ValueError):
        raise BudgetError('Commissioning live workload or storage no longer applicable') from None


def commissioning_cost_bindings(worker):
    """Read installed expense code, pinned restic and exact scheduled commands.

    This is also the preparer's read-only helper for configuration.json. Local
    Inventory/cohort/catalog code is bound because it controls remote reads;
    repository/doc commit SHA is not a cost input.
    Unit drop-ins are unsupported here and require resolving effective units
    before a new admission; silently ignoring an override is unsafe.
    """
    import configparser
    from worker import private_path, protected_directory, sha, RESTIC_SHA
    try:
        protected_directory(worker.bin)
        expense = {name: sha(private_path(worker.bin / name)) for name in COST_FILES}
        binary = sha(private_path(worker.binary, 0o700))
        _budget_need(binary == RESTIC_SHA, 'Installed restic differs from pinned binary')
        units = {}
        for directory in ('service.d', 'timer.d'):
            path = SYSTEMD_UNITS_ROOT / directory
            _budget_need(not path.exists() or not any(path.iterdir()), 'Global systemd overrides need admission')
        for kind in ('binlog', 'hourly', 'full', 'monitor'):
            for suffix in ('timer', 'service'):
                name = 'suhoput2-stage-backup-' + kind + '.' + suffix
                dropins = SYSTEMD_UNITS_ROOT / (name + '.d')
                _budget_need(not dropins.exists() or not any(dropins.iterdir()), 'Systemd unit overrides need admission')
                path = private_path(SYSTEMD_UNITS_ROOT / name, 0o644);raw = path.read_bytes()
                parser = configparser.ConfigParser(interpolation=None, strict=True);parser.optionxform = str
                parser.read_string(raw.decode('utf-8'));_budget_need(not parser.defaults(), 'Systemd defaults unsupported')
                if suffix == 'timer':
                    options = dict(parser['Timer'])
                    _budget_need(set(options) == {'OnCalendar', 'AccuracySec', 'RandomizedDelaySec', 'Persistent', 'Unit'}
                                 and options['AccuracySec'] == '1s' and options['RandomizedDelaySec'] == '0'
                                 and options['Persistent'] == 'false' and options['Unit'] == name.replace('.timer', '.service'),
                                 'Installed timer policy differs')
                    calendar = options['OnCalendar']
                    expected = {'binlog': '*-*-* *:*:00 UTC', 'hourly': '*-*-* *:00:00 UTC', 'monitor': '*-*-* *:*:30 UTC'}
                    _budget_need(calendar == expected[kind] if kind in expected else
                                 bool(re.fullmatch(r'\*-\*-\* (?:[01][0-9]|2[0-3]):[0-5][0-9]:00 UTC', calendar)),
                                 'Installed backup cadence differs')
                else:
                    options = dict(parser['Service'])
                    command = '/usr/bin/python3 ' + str(worker.bin / 'worker.py') + ' --config ' + str(worker.root / 'config/runtime.json') + ' ' + kind
                    _budget_need(options.get('Type') == 'oneshot' and options.get('User') == 'root'
                                 and options.get('ExecStart') == command
                                 and not any(key.startswith('Exec') and key != 'ExecStart' for key in options),
                                 'Installed scheduled command differs')
                units[name] = hashlib.sha256(raw).hexdigest()
        bindings = {'expense_files': expense, 'restic_sha256': binary, 'unit_sha256': units}
        return {**bindings, 'algorithm_sha256': hashlib.sha256(json.dumps(bindings, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
    except (OSError, KeyError, TypeError, ValueError, configparser.Error):
        raise BudgetError('Installed commissioning cost boundary differs or is unavailable') from None


def _commissioning_inputs(worker):
    import runtime
    from worker import private_path, protected_directory, sha
    try:
        protected_directory(worker.root);protected_directory(worker.root / 'receipts')
        root = protected_directory(worker.root / 'receipts/commissioning-inputs')
        paths = {name: private_path(root / name) for name in COMMISSIONING_INPUTS}
        _budget_need(sum(path.stat().st_size for path in paths.values()) <= 64 * 1024**2, 'Commissioning inputs exceed monitor memory budget')
        raw = {name: path.read_bytes() for name, path in paths.items()}
        _budget_need(sum(len(value) for value in raw.values()) <= 64 * 1024**2, 'Commissioning input grew beyond monitor budget')
        docs = {name: json.loads(value, object_pairs_hook=runtime.no_duplicates) for name, value in raw.items() if name.endswith('.json')}
        _budget_need(all(isinstance(value, dict) for value in docs.values()), 'Commissioning input must be an object')
        admission = docs['admission.json'];configuration = docs['configuration.json'];forecast = docs['forecast.json']
        _budget_need(admission['bucket'] == worker.c['bucket'] and admission['region'] == worker.c['region']
                     and admission['generation'] == worker.c['generation'] and admission['source'] == worker.source,
                     'Commissioning input belongs to a different runtime source')
        bindings = commissioning_cost_bindings(worker)
        _budget_need(all(configuration[key] == value for key, value in bindings.items()), 'Declared installed expense configuration differs')
        _budget_need(hashlib.sha256(raw['model.json']).hexdigest() == forecast['model_sha256']
                     and docs['model.json']['format'] == 'commissioning-workload-model-v1'
                     and docs['model.json']['basis'] == forecast['basis'], 'Forecast model bytes or basis differ')
        if admission.get('historical_baseline_review') is not None:
            review=admission['historical_baseline_review']
            _budget_need(docs['model.json'].get('current_controls_sha256')==review.get('current_controls_sha256'),
                         'Historical review control references differ from bound model')
        hashes = {name: hashlib.sha256(value).hexdigest() for name, value in raw.items()}
        producers = {name: sha(private_path(worker.bin / name)) for name in ('budget.py', 'meter.py')}
        return root, raw, docs, hashes, producers
    except (OSError, KeyError, TypeError, ValueError):
        raise BudgetError('Protected commissioning inputs absent, changed or foreign') from None


def publish_commissioning_budget(worker, *, now=None):
    """Publish only a computed PASS from fixed protected admitted source files.

    The deployment/commissioning runner admits actual exports and model first;
    this command never manufactures their provenance or performs provider IO.
    Origin publication is last. An interruption or concurrent input change
    makes the loader reject the report; no precomputed PASS file is imported.
    """
    import runtime
    from worker import private_path, sha
    now = now or dt.datetime.now(dt.timezone.utc)
    root, raw, docs, hashes, producers = _commissioning_inputs(worker)
    report = commissioning_projection(raw['access.jsonl'], raw['inventory.json'], docs['admission.json'], docs['forecast.json'],
                                      docs['rates.json'], docs['configuration.json'], now=now)
    if report['result'] != 'PASS': return report
    _, _, _, current_hashes, current_producers = _commissioning_inputs(worker)
    _budget_need(hashes == current_hashes and producers == current_producers, 'Commissioning inputs changed during projection')
    report.update(source=worker.source, generation=worker.c['generation'])
    path = worker.root / 'receipts/commissioning-budget.json'
    runtime.atomic_json(path, report)
    origin = {'format': 'commissioning-budget-origin-v1', 'source': worker.source, 'generation': worker.c['generation'],
              'bucket': worker.c['bucket'], 'configuration_sha256': report['configuration_sha256'],
              'report_sha256': sha(private_path(path)), 'input_sha256': hashes, 'producer_sha256': producers}
    runtime.atomic_json(worker.root / 'receipts/commissioning-budget.origin.json', origin)
    return report


def load_commissioning_budget(worker, *, now=None):
    """Authenticate and revalidate the published forecast for a monitor/guard.

    Validate the initial whole-bucket observation at publication time (where
    its 24-hour freshness was required), without inventing a fresh inventory.
    A monitor must separately call commissioning_live_applicable with current
    visible objects/source workload. A new actual billing admission is required
    on cost configuration change or expiry, at most 31 days after the window.
    """
    import runtime
    from worker import private_path
    now = now or dt.datetime.now(dt.timezone.utc)
    try:
        _, raw, docs, hashes, producers = _commissioning_inputs(worker)
        path = private_path(worker.root / 'receipts/commissioning-budget.json');report_raw = path.read_bytes()
        report = json.loads(report_raw, object_pairs_hook=runtime.no_duplicates)
        origin = runtime.load_json(private_path(worker.root / 'receipts/commissioning-budget.origin.json'))
        expected = {'format': 'commissioning-budget-origin-v1', 'source': worker.source, 'generation': worker.c['generation'],
                    'bucket': worker.c['bucket'], 'configuration_sha256': commissioning_configuration_sha256(docs['configuration.json']),
                    'report_sha256': hashlib.sha256(report_raw).hexdigest(), 'input_sha256': hashes, 'producer_sha256': producers}
        _budget_need(origin == expected and report['source'] == worker.source and report['generation'] == worker.c['generation']
                     and report['bucket'] == worker.c['bucket'], 'Protected commissioning origin differs')
        _budget_need(isinstance(now, dt.datetime) and now.utcoffset() == dt.timedelta()
                     and _budget_time(report['completed_at']) <= now <= _budget_time(report['valid_until']),
                     'Commissioning forecast expired or clock rolled back')
        commissioning_applicable(report, docs['configuration.json'], raw['inventory.json'], now=_budget_time(report['completed_at']))
        return report
    except (OSError, KeyError, TypeError, ValueError):
        raise BudgetError('Protected commissioning budget unavailable or no longer applicable') from None


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
