"""Offline synthetic billing and native measurement faults; no provider calls."""
import copy
import datetime as dt
import importlib.util
import pathlib
import sys
import unittest
from decimal import Decimal

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'infra/backup'))
NOW = dt.datetime(2026, 10, 12, 12, tzinfo=dt.timezone.utc)
HEADER = 'Аккаунт;Период;Идентификатор проекта;Наименование проекта;Идентификатор ресурса;Наименование ресурса;Количество ресурса;Единица измерения ресурса;Продукт;Стоимость'


def subject():
    unittest.TestCase().assertIsNotNone(importlib.util.find_spec('budget'), 'Budget evidence importer absent')
    import budget
    return budget


def csv_bytes(rows, header=HEADER):
    return ('\ufeff' + header + '\n' + '\n'.join(';'.join(row) for row in rows) + '\n').encode('utf-8')


def row(metric='space-mb', quantity='1024', unit='MB*H', cost='0,01', period='2026-10-12 11:00:00'):
    return ['private-account', period, 'private-project', 'Private name', metric, 'Billing metric', quantity, unit, 'storage', cost]


def inputs():
    jobs = ('binlog', 'hourly', 'full', 'pre_update', 'check', 'retention', 'restore')
    samples = {job: {'measurement': 'native', 'source_scope': 'a' * 64,
                     'receipt_sha256': 'b' * 64, 'provider_http': {'put': 1, 'get': 2, 'delete': 0},
                     'egress_bytes': 1024, 'retained_delta_bytes': 4096, 'new_objects': 1}
               for job in jobs}
    cadence = {'pre_update': 1, 'check': 4, 'retention': 30, 'restore': 1}
    inventory = {'source_scope': 'a' * 64, 'receipt_sha256': 'c' * 64,
                 'storage_bytes': 1073741824, 'objects': 100, 'buckets': 1}
    rates = {'storage_rub_gib_month': '2.57', 'egress_rub_gib': '1.38',
             'put_rub_1000': '0.71', 'get_rub_1000': '0.054', 'delete_rub_1000': '0'}
    return samples, cadence, inventory, rates


class BillingImportTests(unittest.TestCase):
    def test_duplicate_hour_scope_metric_cannot_double_charge_report(self):
        m = subject()
        with self.assertRaises(m.BudgetError):
            m.import_billing_csv(csv_bytes([row(), row()]), now=NOW)

    def test_disagreeing_rounded_prices_cannot_become_verified_tariff(self):
        m = subject()
        r = m.import_billing_csv(csv_bytes([
            row('traffic-req-put', '1000', 'item', '0.71'),
            row('traffic-req-put', '1000', 'item', '1.71', '2026-10-12 10:00:00')]), now=NOW)
        self.assertIsNone(r['metrics'][0]['rate_interval'])
        self.assertIn('inconsistent_observed_tariff', r['missing'])

    def test_provider_req_metrics_and_binary_storage_price_conversion(self):
        m = subject()
        r = m.import_billing_csv(csv_bytes([
            row('traffic-req-get', '1000', 'item', '0.05'),
            row('space-mb', '747520', 'MB*H', '2.57'),
            row('traffic-mb', '1024', 'MB', '1.38')]), now=NOW)
        by_metric = {group['metric']: group for group in r['metrics']}
        self.assertEqual(by_metric['storage']['rate_interval'], {'lower': '2.565', 'upper': '2.575'})
        self.assertEqual(by_metric['egress']['rate_interval'], {'lower': '1.375', 'upper': '1.385'})
        self.assertIn('get', r['observed_operations'])

    def test_unknown_metric_retains_hashed_scope_native_units_and_cost(self):
        m = subject()
        r = m.import_billing_csv(csv_bytes([row('unknown-resource', '5', 'custom_unit', '0.03')]), now=NOW)
        self.assertEqual(len(r['metrics']), 1)
        self.assertEqual(r['metrics'][0]['unit'], 'custom_unit')
        self.assertEqual(r['metrics'][0]['cost_rub'], '0.03')
        self.assertIsNone(r['metrics'][0]['metric'])
        self.assertIsNone(r['metrics'][0]['rate_interval'])

    def test_bucket_scope_and_tariff_disagreement_block_reconciliation(self):
        m = subject()
        r = m.import_billing_csv(csv_bytes([row()]), timezone='+03:00', now=NOW)
        rates = inputs()[3]
        r = m.reconcile_billing(r, rates, 'a' * 64)
        self.assertFalse(r['compatible'])
        self.assertIn('account_bucket_scope_mismatch', r['missing'])
        self.assertIn('account_rate_unobserved:put', r['missing'])

    def test_project_export_preserves_units_and_withholds_private_scope(self):
        m = subject()
        result = m.import_billing_csv(csv_bytes([row(), row('traffic-api-put', '1000', 'item', '0.71')]), now=NOW)
        self.assertTrue(result['parsed'])
        self.assertFalse(result['provider_budget_verified'])
        self.assertIn('bucket_attribution_missing', result['missing'])
        self.assertIn('source_timezone_unknown', result['missing'])
        self.assertEqual(result['metrics'][0]['unit'], 'MB*H')
        self.assertEqual(result['cost_rub'], '0.72')
        self.assertNotIn('private-account', str(result))
        self.assertNotIn('private-project', str(result))
        self.assertEqual(result['scope_counts'], {'account': 1, 'project': 1, 'resource': 2, 'bucket': 0, 'pool': 0})

    def test_decimal_local_format_and_rate_interval_use_grouped_native_unit(self):
        m = subject()
        r = m.import_billing_csv(csv_bytes([row('traffic-api-put', '1 000', 'item', '0,71 ₽')]), timezone='+03:00', now=NOW)
        metric = r['metrics'][0]
        self.assertEqual(metric['consumption'], '1000')
        self.assertEqual(metric['rate_unit'], 'RUB/1000 requests')
        self.assertEqual(metric['rate_interval'], {'lower': '0.705', 'upper': '0.715'})
        self.assertEqual(r['period']['first_utc'], '2026-10-12T08:00:00Z')

    def test_standard_and_cold_metrics_never_merge_tariff_or_scope(self):
        m = subject()
        r = m.import_billing_csv(csv_bytes([row(), row('space-mb-cold', cost='0.02')]), timezone='+03:00', now=NOW)
        self.assertEqual({x['storage_class'] for x in r['metrics']}, {'standard', 'cold'})
        self.assertEqual(len(r['metrics']), 2)

    def test_missing_cost_unknown_metric_and_absent_operation_remain_unknown(self):
        m = subject()
        r = m.import_billing_csv(csv_bytes([row(cost=''), row('unknown-resource', unit='MB', cost='0')]), now=NOW)
        self.assertIsNone(r['cost_rub'])
        self.assertIsNone(r['metrics'][0]['rate_interval'])
        self.assertEqual(r['unknown_metric_rows'], 1)
        self.assertNotIn('get', r['observed_operations'])

    def test_rejects_float_like_invalid_numeric_schema_and_unit_alias(self):
        m = subject()
        for change in ('number', 'unit', 'schema', 'future'):
            fixture = row()
            header = HEADER
            if change == 'number': fixture[6] = 'NaN'
            if change == 'unit': fixture[7] = 'GB'
            if change == 'schema': header += ';unexpected'
            if change == 'future': fixture[1] = '2026-10-13 01:00:00'
            with self.subTest(change=change), self.assertRaises(m.BudgetError):
                m.import_billing_csv(csv_bytes([fixture], header), timezone='+03:00', now=NOW)

    def test_explicit_hour_period_partial_history_never_becomes_month(self):
        m = subject()
        r = m.import_billing_csv(csv_bytes([row()]), timezone='+03:00', now=NOW)
        self.assertEqual(r['period']['observed_hours'], 1)
        self.assertFalse(r['period']['monthly_pattern_verified'])
        self.assertFalse(r['provider_budget_verified'])

    def test_money_thousands_and_currency_are_strict_and_decimal(self):
        m = subject()
        self.assertEqual(m.local_decimal('1\u202f234,56 RUB', money=True), Decimal('1234.56'))
        for invalid in ('1,234.56', '-1', '1e3', '1 23', True):
            with self.subTest(value=invalid), self.assertRaises(m.BudgetError): m.local_decimal(invalid)


class MonthlyProjectionTests(unittest.TestCase):
    def test_arithmetic_compatible_csv_without_source_confirmation_never_opens_gate(self):
        m = subject()
        samples, cadence, inventory, rates = inputs()
        scope = m.scope_fingerprint('private-account', 'private-project', 'private-bucket', 'private-pool')
        inventory['source_scope'] = scope
        for sample in samples.values(): sample['source_scope'] = scope
        rows = [row('space-mb', '747520', 'MB*H', '2.57'),
                row('traffic-mb', '1024', 'MB', '1.38'),
                row('traffic-req-put', '1000', 'item', '0.71'),
                row('traffic-req-get', '1000', 'item', '0.05'),
                row('traffic-req-delete', '1000', 'item', '0.00')]
        rows = [fields + ['private-bucket', 'private-pool'] for fields in rows]
        report = m.import_billing_csv(csv_bytes(rows, HEADER + ';Бакет;Пул'), timezone='+03:00', now=NOW)
        r = m.monthly_projection(samples, cadence, inventory, rates, account_report=report)
        self.assertFalse(r['budget_gate'])
        self.assertIn('account_export_authenticity_unverified', r['missing'])

    def test_fixed_schedule_scales_native_http_and_includes_metadata(self):
        m = subject()
        samples, cadence, inventory, rates = inputs()
        r = m.monthly_projection(samples, cadence, inventory, rates)
        self.assertEqual(r['monthly_jobs']['binlog'], 43200)
        self.assertEqual(r['monthly_jobs']['hourly'], 720)
        self.assertEqual(r['monthly_jobs']['full'], 30)
        self.assertEqual(r['usage']['put_requests'], 43986)
        self.assertEqual(r['usage']['get_requests'], 87972)
        # 43986 retained deltas plus current 1GiB; each new/current object and bucket adds 4KiB.
        self.assertEqual(r['storage_upper_bound_bytes'], 1434488832)
        self.assertFalse(r['budget_gate'])
        self.assertIn('account_billing_not_reconciled', r['missing'])
        self.assertFalse(r['provider_billing_verified'])

    def test_manual_observed_job_counts_cannot_replace_cadence(self):
        m = subject()
        samples, cadence, inventory, rates = inputs()
        del cadence['restore']
        r = m.monthly_projection(samples, cadence, inventory, rates)
        self.assertFalse(r['budget_gate'])
        self.assertIsNone(r['projected_rub'])
        self.assertIn('cadence_missing:restore', r['missing'])

    def test_adapter_call_counts_and_boolean_attestation_cannot_be_http_meter(self):
        m = subject()
        samples, cadence, inventory, rates = inputs()
        samples['binlog']['call_counts'] = samples['binlog'].pop('provider_http')
        r = m.monthly_projection(samples, cadence, inventory, rates)
        self.assertIsNone(r['projected_rub'])
        self.assertIn('provider_http_missing:binlog', r['missing'])
        samples, cadence, inventory, rates = inputs()
        samples['binlog']['measurement'] = 'synthetic'
        self.assertFalse(m.monthly_projection(samples, cadence, inventory, rates)['budget_gate'])

    def test_wrong_scope_missing_tariff_and_zero_unknown_never_pass(self):
        m = subject()
        for change in ('scope', 'rate', 'counter'):
            samples, cadence, inventory, rates = inputs()
            if change == 'scope': samples['full']['source_scope'] = 'd' * 64
            if change == 'rate': del rates['put_rub_1000']
            if change == 'counter': samples['binlog']['provider_http']['put'] = None
            r = m.monthly_projection(samples, cadence, inventory, rates)
            self.assertFalse(r['budget_gate'])
            self.assertIsNone(r['projected_rub'])

    def test_over_capacity_and_expensive_requests_fail_independently(self):
        m = subject()
        for change in ('storage', 'cost'):
            samples, cadence, inventory, rates = inputs()
            if change == 'storage': inventory['storage_bytes'] = 10 * 1073741824
            if change == 'cost': samples['binlog']['provider_http']['put'] = 100
            r = m.monthly_projection(samples, cadence, inventory, rates)
            self.assertTrue(r['over_limit'])
            self.assertFalse(r['budget_gate'])

    def test_projection_never_trusts_rate_floats_or_negative_counts(self):
        m = subject()
        samples, cadence, inventory, rates = inputs()
        rates['put_rub_1000'] = 0.71
        with self.assertRaises(m.BudgetError): m.monthly_projection(samples, cadence, inventory, rates)
        samples, cadence, inventory, rates = inputs()
        samples['binlog']['provider_http']['put'] = -1
        with self.assertRaises(m.BudgetError): m.monthly_projection(samples, cadence, inventory, rates)


if __name__ == '__main__':
    unittest.main()
