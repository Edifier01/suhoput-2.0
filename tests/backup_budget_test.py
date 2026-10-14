"""Offline synthetic billing and native measurement faults; no provider calls."""
import copy
import base64
import datetime as dt
import importlib.util
import hashlib
import json
import os
import pathlib
import sys
import tempfile
import types
import unittest
from decimal import Decimal
from unittest import mock

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
    def test_selected_object_and_metric_exports_preserve_actual_schema_timezone_and_scope(self):
        m=subject();self.assertTrue(callable(getattr(m,'import_selected_billing',None)),'Actual selected Console CSV pair unsupported')
        import hashlib
        objects=['account','object','StageB','project','storage','Storage','2026-10-12 11:00:00','project','Project','storage','ru-1','0.71']
        object_header='Аккаунт;Идентификатор объекта;Наименование объекта;Идентификатор родительского объекта;Тип объекта;Наименование типа объекта;Период;Идентификатор проекта;Наименование проекта;Продукт;Регион;Стоимость'
        metric_header='Аккаунт;Идентификатор ресурса;Наименование ресурса;Количество ресурса;Единица измерения ресурса;Период;Продукт;Стоимость'
        raw_objects=csv_bytes([objects],object_header);raw_metrics=csv_bytes([['account','traffic-req-put','PUT','1000','item','2026-10-12 11:00:00','storage','0.71']],metric_header)
        context={'object_id':'object','project_id':'project','bucket':'stage-b','pool':'ru-1','timezone':'+03:00','account_scope_sha256':hashlib.sha256(b'account').hexdigest(),
                 'selected_from':'2026-10-12T08:00:00Z','selected_until':'2026-10-12T09:00:00Z',
                 'billing_sha256':hashlib.sha256(raw_metrics).hexdigest(),'objects_sha256':hashlib.sha256(raw_objects).hexdigest()}
        report=m.import_selected_billing(raw_objects,raw_metrics,context,now=NOW)
        self.assertEqual(report['period']['first_utc'],'2026-10-12T08:00:00Z')
        self.assertEqual(report['cost_rub'],'0.71');self.assertEqual(report['bucket_scopes'],[m.scope_fingerprint('account','project','stage-b','ru-1')])
        self.assertEqual(report['provenance']['metric_schema'],metric_header.split(';'))
        empty_fields=list(objects);empty_fields[3]=empty_fields[10]='';actual_objects=csv_bytes([empty_fields],object_header)
        actual_context={**context,'objects_sha256':hashlib.sha256(actual_objects).hexdigest()}
        try:actual=m.import_selected_billing(actual_objects,raw_metrics,actual_context,now=NOW)
        except m.BudgetError as error:self.fail('Actual empty parent/region fields must use explicit authenticated selection: '+str(error))
        self.assertEqual(actual['source_context']['region_source'],'authenticated selection; object CSV region absent')
        for key,value in [('project_id','other'),('object_id','other'),('billing_sha256','0'*64),('account_scope_sha256','0'*64)]:
            bad=copy.deepcopy(context);bad[key]=value
            with self.subTest(key=key),self.assertRaises(m.BudgetError):m.import_selected_billing(raw_objects,raw_metrics,bad,now=NOW)
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
    def test_calendar_month_charges_all_744_storage_hours_at_730_hour_unit(self):
        m=subject();samples,cadence,inventory,rates=inputs();cadence['retention']=178
        inventory.update(objects=0,buckets=1,storage_bytes=9*m.GIB-m.METADATA_BYTES)
        rates.update(storage_rub_gib_month='2.57',put_rub_1000='0.71',get_rub_1000='0',delete_rub_1000='0',egress_rub_gib='0')
        for job,sample in samples.items():
            sample.update(retained_delta_bytes=0,new_objects=0,egress_bytes=0,provider_http={'put':{'binlog':15,'hourly':1,'full':32}.get(job,0),'get':0,'delete':0})
        projection=m.monthly_projection(samples,cadence,inventory,rates,projection_days=31)
        self.assertEqual(projection['storage_upper_bound_bytes'],9*m.GIB)
        self.assertGreater(Decimal(projection['projected_rub']),Decimal(500))
        self.assertTrue(projection['over_limit'])
        self.assertEqual(Decimal(projection['projected_rub']),Decimal('476.64856')+Decimal(9)*Decimal('2.57')*744/730)

    def test_calendar_month_bound_rejects_cost_that_only_fits_thirty_days(self):
        m=subject();samples,cadence,inventory,rates=inputs();rates['put_rub_1000']='11'
        thirty=m.monthly_projection(samples,cadence,inventory,rates)
        try:calendar=m.monthly_projection(samples,cadence,inventory,rates,projection_days=31)
        except TypeError:self.fail('Native calendar month projection still has only thirty-day counts')
        self.assertLessEqual(Decimal(thirty['projected_rub']),Decimal(500))
        self.assertGreater(Decimal(calendar['projected_rub']),Decimal(500))
        self.assertTrue(calendar['over_limit'])
        self.assertEqual(calendar['monthly_jobs']['binlog'],44640)
        self.assertEqual(calendar['monthly_jobs']['hourly'],744)
        self.assertEqual(calendar['monthly_jobs']['full'],31)

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


def commissioning_inputs():
    """Synthetic native-source shapes; never an actual provider acceptance."""
    gib=1024**3
    configuration={'format':'backup-cost-configuration-v1','scope_sha256':'a'*64,'algorithm_sha256':'b'*64,
                   'cadence_seconds':{'binlog':60,'hourly':3600,'full':86400},'retention_days':30,
                   'integrity_policy':{'full_read_days':7},'maintenance_policy':{'batch':256},'retry_policy':{'max_attempts':3}}
    digest=hashlib.sha256(json.dumps(configuration,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    raw_access=(json.dumps({'container_name':'synthetic-stage-b','timestamp':'2026-10-12T10:30:00Z',
                           'server_to_client_bytes':1000,'client_to_server_bytes':2000,'http_method':'PUT','status':200,
                           'path':'/synthetic-stage-b/config','account_uuid':'c'*32})+'\n').encode()
    inventory={'format':'selectel-whole-bucket-inventory-v1','bucket':'synthetic-stage-b','scope_sha256':'a'*64,
               'observed_at':'2026-10-12T11:30:00Z','coverage':{'namespace':'whole-bucket','objects':'complete','versions':'complete','multipart':'complete'},
               'object_version_bytes':gib,'object_version_count':10,'multipart_bytes':4096,'multipart_parts':2,
               'other_bytes':1024,'other_objects':1,'buckets':1,
               'workload':{'database_bytes':10*1024**2,'media_bytes':20*1024**2,'binlog_bytes_per_day':100*1024**2}}
    raw_inventory=json.dumps(inventory).encode()
    admission={'operation':'native-provider-export-admission','export_source':'authenticated-selectel-console','bucket':'synthetic-stage-b',
               'region':'ru-1','storage_class':'standard','scope_sha256':'a'*64,'configuration_sha256':digest,
               'inventory_sha256':hashlib.sha256(raw_inventory).hexdigest(),
               'window':{'status':'DONE','from':'2026-10-12T10:00:00Z','until':'2026-10-12T11:00:00Z',
                         'completed_at':'2026-10-12T11:10:00Z','sha256':hashlib.sha256(raw_access).hexdigest(),
                         'account_scope_sha256':hashlib.sha256(('c'*32).encode()).hexdigest()}}
    forecast={'monthly_jobs':{'binlog':44640,'hourly':744,'full':31,'pre_update':1,'check':5,'retention':186,'restore':1},
              'usage':{'put_requests':200000,'get_requests':1000000,'egress_bytes':100*gib},
              'retained_data_bytes':2*gib,'temporary_data_bytes':gib,'storage_reserve_bytes':gib,'hidden_storage_growth_bytes':128*1024**2,'reserve_rub':'100',
              'projected_per_hour_growth_bytes':64*1024**2,'projected_per_hour_growth_objects':600,
              'visible_interval_seconds':3600,
              'index_envelope':{'base':{'object_count':32,'bytes':16*1024**2},'binlog':{'object_count':2048,'bytes':64*1024**2}},
              'projected_per_hour_index_growth':{'base':{'object_count':2,'bytes':4*1024**2},'binlog':{'object_count':61,'bytes':4*1024**2}},
              'workload_envelope':{'database_bytes':100*1024**2,'media_bytes':200*1024**2,'binlog_bytes_per_day':1024**3,'storage_objects':10000},
              'basis':'Synthetic controlled workload model covers every monthly job, growth and recovery.',
              'model_sha256':'d'*64,'valid_until':'2026-10-19T10:00:00Z'}
    rates={**inputs()[3],'tariff_basis':'owner-approved-public-standard-ru1','tax_basis':'inclusive'}
    return raw_access,raw_inventory,admission,forecast,rates,configuration


class CommissioningBudgetTests(unittest.TestCase):
    def test_historical_baseline_requires_separate_exact_reviewed_model_and_current_controls(self):
        m=self.subject();args=list(commissioning_inputs());args[2]['configuration_sha256']=None
        review={'format':'historical-baseline-review-v1','provider_raw_sha256':hashlib.sha256(args[0]).hexdigest(),
                'target_configuration_sha256':m.commissioning_configuration_sha256(args[5]),
                'model_sha256':args[3]['model_sha256'],'reviewed_at':NOW.isoformat(),
                'current_controls_sha256':{name:'e'*64 for name in ('archive_roundtrip','index_compaction','restore','retention','visible_inventory')}}
        args[2]['historical_baseline_review']=review
        report=m.commissioning_projection(*args,now=NOW)
        self.assertEqual(report['result'],'PASS');self.assertFalse(report['current_configuration_observed'])
        self.assertIsNone(report['observed_configuration_sha256'])
        self.assertEqual(report['historical_baseline_review'],review)
        for kind in ('missing','provider','target','model','controls','stale','future'):
            bad=copy.deepcopy(args);binding=bad[2]['historical_baseline_review']
            if kind=='missing':bad[2].pop('historical_baseline_review')
            elif kind=='provider':binding['provider_raw_sha256']='f'*64
            elif kind=='target':binding['target_configuration_sha256']='f'*64
            elif kind=='model':binding['model_sha256']='f'*64
            elif kind=='controls':binding['current_controls_sha256'].pop('restore')
            elif kind=='stale':binding['reviewed_at']=(NOW-dt.timedelta(hours=25)).isoformat()
            else:binding['reviewed_at']=(NOW+dt.timedelta(seconds=1)).isoformat()
            with self.subTest(kind=kind):
                if kind=='missing':self.assertEqual(m.commissioning_projection(*bad,now=NOW)['result'],'BLOCK')
                else:
                    with self.assertRaises(m.BudgetError):m.commissioning_projection(*bad,now=NOW)

    def test_installed_integrity_producer_is_a_significant_cost_input(self):
        self.assertIn('integrity.py',subject().COST_FILES)

    def subject(self):
        m=subject();self.assertTrue(callable(getattr(m,'commissioning_projection',None)),'Commissioning budget contract absent');return m

    def test_actual_window_and_inventory_support_forecast_without_seven_native_jobs(self):
        m=self.subject();r=m.commissioning_projection(*commissioning_inputs(),now=NOW)
        self.assertEqual(r['result'],'PASS');self.assertEqual(r['format'],'commissioning_budget_pass')
        self.assertFalse(r['actual_month_observed']);self.assertFalse(r['invoice_verified'])
        self.assertEqual(r['observed']['http_requests'],1)
        self.assertEqual(r['inventory']['storage_bytes'],1073804288) # 1GiB+5120 bytes+14 metadata entries.
        self.assertEqual(r['projected_storage_bytes'],4539715584) # Prior bound + explicit one-hour bytes/object growth.
        self.assertEqual(r['monthly_jobs']['binlog'],44640)
        want=Decimal(4539715584)/Decimal(1024**3)*Decimal('2.57')*744/730+Decimal(138+142+54+100)
        self.assertEqual(Decimal(r['projected_monthly_rub']),want)

    def test_significant_config_change_blocks_old_data_but_document_or_cohort_change_does_not(self):
        m=self.subject();args=list(commissioning_inputs());args[5]['documentation_sha']='f'*40;args[5]['cohort']='new'
        self.assertEqual(m.commissioning_projection(*args,now=NOW)['result'],'PASS')
        args[5]['algorithm_sha256']='e'*64
        r=m.commissioning_projection(*args,now=NOW)
        self.assertEqual(r['result'],'BLOCK');self.assertIn('current_configuration_not_observed',r['blockers'])
        self.assertIsNotNone(r['projected_monthly_rub'])

    def test_corrupt_foreign_partial_or_unknown_inventory_cannot_become_zero(self):
        m=self.subject()
        for kind in ('hash','bucket','versions','multipart','missing_bytes','negative','future','stale'):
            args=list(commissioning_inputs());inv=json.loads(args[1])
            if kind=='hash':args[2]['inventory_sha256']='0'*64
            elif kind=='bucket':inv['bucket']='foreign'
            elif kind in ('versions','multipart'):inv['coverage'][kind]='unknown'
            elif kind=='missing_bytes':inv.pop('multipart_bytes')
            elif kind=='negative':inv['other_bytes']=-1
            elif kind=='future':inv['observed_at']='2026-10-13T12:00:00Z'
            elif kind=='stale':inv['observed_at']='2026-10-10T12:00:00Z'
            if kind!='hash':args[1]=json.dumps(inv).encode();args[2]['inventory_sha256']=hashlib.sha256(args[1]).hexdigest()
            with self.subTest(kind=kind),self.assertRaises(m.BudgetError):m.commissioning_projection(*args,now=NOW)

    def test_limits_reserve_growth_and_31_day_schedule_are_enforced_independently(self):
        m=self.subject()
        for kind in ('cost','space','envelope','schedule','missing_usage','missing_model','reserve','hidden_growth','hour_growth','expired'):
            args=list(commissioning_inputs());forecast=args[3]
            if kind=='cost':forecast['usage']['put_requests']=1000000
            elif kind=='space':forecast['retained_data_bytes']=10*1024**3
            elif kind=='envelope':forecast['workload_envelope']['database_bytes']=1
            elif kind=='schedule':forecast['monthly_jobs']['binlog']=43200
            elif kind=='missing_usage':forecast['usage'].pop('get_requests')
            elif kind=='missing_model':forecast.pop('model_sha256')
            elif kind=='reserve':forecast['reserve_rub']='0'
            elif kind=='hidden_growth':forecast.pop('hidden_storage_growth_bytes')
            elif kind=='hour_growth':forecast.pop('projected_per_hour_growth_bytes')
            elif kind=='expired':forecast['valid_until']='2026-10-12T11:59:00Z'
            with self.subTest(kind=kind):
                if kind in ('cost','space','envelope','expired'):
                    self.assertEqual(m.commissioning_projection(*args,now=NOW)['result'],'BLOCK')
                else:
                    with self.assertRaises(m.BudgetError):m.commissioning_projection(*args,now=NOW)

    def test_forecast_cannot_understate_already_observed_provider_consumption(self):
        m=self.subject();args=list(commissioning_inputs());args[3]['usage']['egress_bytes']=999
        with self.assertRaises(m.BudgetError):m.commissioning_projection(*args,now=NOW)

    def test_reuse_requires_current_scope_configuration_capacity_and_workload(self):
        m=self.subject();self.assertTrue(callable(getattr(m,'commissioning_applicable',None)),'Reusable budget validator absent')
        args=commissioning_inputs();report=m.commissioning_projection(*args,now=NOW)
        self.assertTrue(m.commissioning_applicable(report,args[5],args[1],now=NOW))
        for kind in ('configuration','inventory','expiry'):
            config=copy.deepcopy(args[5]);raw=args[1];at=NOW
            if kind=='configuration':config['retry_policy']['max_attempts']=4
            elif kind=='inventory':inv=json.loads(raw);inv['workload']['database_bytes']=1024**3;raw=json.dumps(inv).encode()
            else:at=NOW+dt.timedelta(days=8)
            with self.subTest(kind=kind),self.assertRaises(m.BudgetError):m.commissioning_applicable(report,config,raw,now=at)

    def test_live_visible_observation_uses_initial_hidden_baseline_and_explicit_future_reserve(self):
        m=self.subject();self.assertTrue(callable(getattr(m,'commissioning_live_applicable',None)),'Separate live visible gate absent')
        args=commissioning_inputs();report=m.commissioning_projection(*args,now=NOW)
        report.update(generation='1'*32,source={'root':'synthetic','generation':'1'*32})
        at=NOW+dt.timedelta(days=2)
        observation={'format':'commissioning-live-observation-v1','bucket':report['bucket'],'scope_sha256':report['scope_sha256'],
                     'generation':report['generation'],'source':report['source'],'observed_at':at.isoformat(),'prefix':'','complete':True,
                     'physical_bytes':1024**3,'object_count':10,'workload':json.loads(args[1])['workload']}
        self.assertTrue(m.commissioning_live_applicable(report,observation,now=at))
        for kind in ('stale','future','partial','prefix','scope','generation','source','size','workload','unknown','expiry','hidden_growth'):
            current=copy.deepcopy(observation);saved=copy.deepcopy(report);clock=at
            if kind=='stale':current['observed_at']=(at-dt.timedelta(seconds=121)).isoformat()
            elif kind=='future':current['observed_at']=(at+dt.timedelta(seconds=1)).isoformat()
            elif kind=='partial':current['complete']=False
            elif kind=='prefix':current['prefix']='repositories/'
            elif kind=='scope':current['scope_sha256']='e'*64
            elif kind=='generation':current['generation']='2'*32
            elif kind=='source':current['source']={'root':'foreign'}
            elif kind=='size':current['physical_bytes']=4*1024**3 # below 10GiB, but baseline+growth exceeds admitted forecast.
            elif kind=='workload':current['workload']['database_bytes']=1024**3
            elif kind=='unknown':current['workload']['binlog_bytes_per_day']=None
            elif kind=='expiry':clock=at+dt.timedelta(days=8);current['observed_at']=clock.isoformat()
            elif kind=='hidden_growth':saved['hidden_storage_growth_bytes']=0
            with self.subTest(kind=kind),self.assertRaises(m.BudgetError):m.commissioning_live_applicable(saved,current,now=clock)

    def test_cached_visible_sample_keeps_its_own_hourly_clock_and_growth_reserve(self):
        m=self.subject();report=m.commissioning_projection(*commissioning_inputs(),now=NOW)
        report.update(source={'root':'synthetic'},generation='1'*32)
        observation={'format':'commissioning-live-observation-v2','bucket':report['bucket'],'scope_sha256':report['scope_sha256'],
                     'source':report['source'],'generation':report['generation'],'observed_at':NOW.isoformat(),
                     'visible_sampled_at':(NOW-dt.timedelta(minutes=59)).isoformat(),'prefix':'','complete':True,
                     'repository_indexes':{'base':{'object_count':2,'bytes':4096},'binlog':{'object_count':3,'bytes':8192}},
                     'physical_bytes':1024**3,'object_count':10,'workload':json.loads(commissioning_inputs()[1])['workload']}
        self.assertTrue(m.commissioning_live_applicable(report,observation,now=NOW))
        for kind in ('stale_visible','future_visible','missing_clock','objects','bytes','unknown_growth'):
            current=copy.deepcopy(observation);saved=copy.deepcopy(report)
            if kind=='stale_visible':current['visible_sampled_at']=(NOW-dt.timedelta(seconds=3601)).isoformat()
            elif kind=='future_visible':current['visible_sampled_at']=(NOW+dt.timedelta(seconds=1)).isoformat()
            elif kind=='missing_clock':current.pop('visible_sampled_at')
            elif kind=='objects':current['object_count']=saved['workload_envelope']['storage_objects']
            elif kind=='bytes':current['physical_bytes']=saved['projected_storage_bytes']-saved['inventory']['storage_bytes']-saved['hidden_storage_growth_bytes']-45056
            else:saved['projected_per_hour_growth_bytes']=0
            with self.subTest(kind=kind),self.assertRaises(m.BudgetError):m.commissioning_live_applicable(saved,current,now=NOW)

    def test_cached_index_growth_must_remain_within_each_lane_cost_envelope(self):
        m=self.subject();args=commissioning_inputs();report=m.commissioning_projection(*args,now=NOW)
        report.update(source={'root':'synthetic'},generation='1'*32)
        observation={'format':'commissioning-live-observation-v2','bucket':report['bucket'],'scope_sha256':report['scope_sha256'],
                     'source':report['source'],'generation':report['generation'],'observed_at':NOW.isoformat(),
                     'visible_sampled_at':(NOW-dt.timedelta(minutes=59)).isoformat(),'prefix':'','complete':True,
                     'physical_bytes':1024**3,'object_count':3000,'workload':json.loads(args[1])['workload'],
                     'repository_indexes':{'base':{'object_count':2,'bytes':4096},'binlog':{'object_count':1987,'bytes':60*1024**2}}}
        self.assertTrue(m.commissioning_live_applicable(report,observation,now=NOW))
        self.assertEqual(report.get('index_envelope'),args[3]['index_envelope'])
        for kind in ('missing_indexes','missing_lane','unknown_count','count_growth','byte_growth','zero_growth','missing_envelope','foreign_lane'):
            current=copy.deepcopy(observation);saved=copy.deepcopy(report)
            if kind=='missing_indexes':current.pop('repository_indexes')
            elif kind=='missing_lane':current['repository_indexes'].pop('base')
            elif kind=='unknown_count':current['repository_indexes']['base']['object_count']=None
            elif kind=='count_growth':current['repository_indexes']['binlog']['object_count']=1988
            elif kind=='byte_growth':current['repository_indexes']['binlog']['bytes']+=1
            elif kind=='zero_growth':saved['projected_per_hour_index_growth']['base']['object_count']=0
            elif kind=='missing_envelope':saved.pop('index_envelope')
            else:current['repository_indexes']['foreign']={'object_count':1,'bytes':1}
            with self.subTest(kind=kind),self.assertRaises(m.BudgetError):m.commissioning_live_applicable(saved,current,now=NOW)

    def test_projection_requires_explicit_index_envelope_and_hourly_growth(self):
        m=self.subject()
        for kind in ('envelope','growth','zero','negative','growth_exceeds_cap'):
            args=list(commissioning_inputs());forecast=args[3]
            if kind=='envelope':forecast.pop('index_envelope')
            elif kind=='growth':forecast.pop('projected_per_hour_index_growth')
            elif kind=='zero':forecast['index_envelope']['base']['object_count']=0
            elif kind=='negative':forecast['projected_per_hour_index_growth']['binlog']['bytes']=-1
            else:forecast['projected_per_hour_index_growth']['base']['object_count']=33
            with self.subTest(kind=kind),self.assertRaises(m.BudgetError):m.commissioning_projection(*args,now=NOW)

    def test_six_hour_visible_v3_preserves_actual_clock_and_reserves_six_hours_of_growth(self):
        m=self.subject();args=list(commissioning_inputs());args[3]['visible_interval_seconds']=21600
        args[3]['index_envelope']['base']['bytes']=32*1024**2
        report=m.commissioning_projection(*args,now=NOW);report.update(source={'root':'synthetic'},generation='1'*32)
        self.assertEqual(report.get('visible_interval_seconds'),21600)
        self.assertEqual(report['projected_storage_bytes'],4539715584+5*(64*1024**2+600*4096))
        observation={'format':'commissioning-live-observation-v3','visible_interval_seconds':21600,
                     'bucket':report['bucket'],'scope_sha256':report['scope_sha256'],'source':report['source'],'generation':report['generation'],
                     'observed_at':NOW.isoformat(),'visible_sampled_at':(NOW-dt.timedelta(seconds=21600)).isoformat(),
                     'prefix':'','complete':True,'physical_bytes':1024**3,'object_count':10,'workload':json.loads(args[1])['workload'],
                     'repository_indexes':{'base':{'object_count':2,'bytes':4096},'binlog':{'object_count':3,'bytes':8192}}}
        self.assertTrue(m.commissioning_live_applicable(report,observation,now=NOW))
        for kind in ('stale','rollover','missing_interval','wrong_interval','v2','v1','index_six_hours','object_six_hours','byte_six_hours','zero_growth'):
            current=copy.deepcopy(observation);saved=copy.deepcopy(report)
            if kind=='stale':current['visible_sampled_at']=(NOW-dt.timedelta(seconds=21601)).isoformat()
            elif kind=='rollover':current['visible_sampled_at']=(NOW+dt.timedelta(seconds=1)).isoformat()
            elif kind=='missing_interval':current.pop('visible_interval_seconds')
            elif kind=='wrong_interval':saved['visible_interval_seconds']=3600
            elif kind=='v2':current['format']='commissioning-live-observation-v2'
            elif kind=='v1':current['format']='commissioning-live-observation-v1'
            elif kind=='index_six_hours':current['repository_indexes']['base']['object_count']=21;current['object_count']=24
            elif kind=='object_six_hours':current['object_count']=saved['workload_envelope']['storage_objects']-3599
            elif kind=='byte_six_hours':current['physical_bytes']=saved['projected_storage_bytes']-saved['inventory']['storage_bytes']-saved['hidden_storage_growth_bytes']-5*64*1024**2
            else:saved['projected_per_hour_index_growth']['base']['bytes']=0
            with self.subTest(kind=kind),self.assertRaises(m.BudgetError):m.commissioning_live_applicable(saved,current,now=NOW)
        for interval in (None,0,3601,43200,True):
            changed=copy.deepcopy(args);changed[3]['visible_interval_seconds']=interval
            with self.subTest(interval=interval),self.assertRaises(m.BudgetError):m.commissioning_projection(*changed,now=NOW)

    def provider_inventory_inputs(self):
        args=list(commissioning_inputs());m=subject()
        objects_header='Аккаунт;Идентификатор объекта;Наименование объекта;Идентификатор родительского объекта;Тип объекта;Наименование типа объекта;Период;Идентификатор проекта;Наименование проекта;Продукт;Регион;Стоимость'
        metric_header='Аккаунт;Идентификатор ресурса;Наименование ресурса;Количество ресурса;Единица измерения ресурса;Период;Продукт;Стоимость'
        objects=csv_bytes([['account','object','synthetic-stage-b','project','storage','Storage','2026-10-12 11:00:00','project','Project','storage','ru-1','0.01']],objects_header)
        metrics=csv_bytes([['account','space-mb','Storage','1024','MB*H','2026-10-12 11:00:00','storage','0.01']],metric_header)
        context={'object_id':'object','project_id':'project','bucket':'synthetic-stage-b','pool':'ru-1','timezone':'UTC',
                 'account_scope_sha256':hashlib.sha256(b'account').hexdigest(),'selected_from':'2026-10-12T11:00:00Z','selected_until':'2026-10-12T12:00:00Z',
                 'billing_sha256':hashlib.sha256(metrics).hexdigest(),'objects_sha256':hashlib.sha256(objects).hexdigest()}
        scope=m.scope_fingerprint('account','project','synthetic-stage-b','ru-1');args[2]['scope_sha256']=args[5]['scope_sha256']=scope
        args[2]['configuration_sha256']=m.commissioning_configuration_sha256(args[5])
        inv={'format':'selectel-billed-bucket-inventory-v1','bucket':'synthetic-stage-b','scope_sha256':scope,'observed_at':'2026-10-12T12:00:00Z',
             'workload':json.loads(args[1])['workload'],'known_additions_bytes':4096,
             'provider_export':{'context':context,'objects_csv_base64':base64.b64encode(objects).decode(),
                                'metrics_csv_base64':base64.b64encode(metrics).decode()},
             'resource_inventory':{'source':'authenticated-selectel-console-project-resource-inventory',
                                   'scope':'all-project-storage-resources','project_id':'project','account_scope_sha256':context['account_scope_sha256'],
                                   'timezone':'UTC','selected_from':context['selected_from'],'selected_until':context['selected_until'],
                                   'objects_sha256':hashlib.sha256(objects).hexdigest(),'objects_csv_base64':base64.b64encode(objects).decode()},
             'associated_exports':[]}
        args[1]=json.dumps(inv).encode();args[2]['inventory_sha256']=hashlib.sha256(args[1]).hexdigest();return args

    def test_provider_billed_aggregate_covers_unknown_versions_and_parts_without_zero_fabrication(self):
        m=self.subject();args=self.provider_inventory_inputs()
        try:r=m.commissioning_projection(*args,now=NOW)
        except m.BudgetError as error:self.fail('Admitted billed aggregate must support unavailable object APIs: '+str(error))
        self.assertEqual(r['result'],'PASS');self.assertIsNone(r['inventory']['objects'])
        self.assertFalse(r['inventory']['component_counts_known'])
        self.assertEqual(r['inventory']['storage_bytes'],1074794496) # (1024+1 displayed MB)*MiB+4096 known additions.
        self.assertEqual(r['inventory']['storage_source'],'provider-billing-whole-bucket')
        self.assertTrue(m.commissioning_applicable(r,args[5],args[1],now=NOW))

    def test_provider_aggregate_requires_actual_raw_pair_scope_storage_metric_and_additions(self):
        m=self.subject()
        for kind in ('raw_hash','scope','additions','missing_storage'):
            args=self.provider_inventory_inputs();inv=json.loads(args[1]);context=inv['provider_export']['context']
            if kind=='raw_hash':context['billing_sha256']='0'*64
            elif kind=='scope':context['bucket']='foreign'
            elif kind=='additions':inv.pop('known_additions_bytes')
            else:
                raw=base64.b64decode(inv['provider_export']['metrics_csv_base64']).replace(b'space-mb',b'traffic-mb').replace(b'MB*H',b'MB')
                inv['provider_export']['metrics_csv_base64']=base64.b64encode(raw).decode();context['billing_sha256']=hashlib.sha256(raw).hexdigest()
            args[1]=json.dumps(inv).encode();args[2]['inventory_sha256']=hashlib.sha256(args[1]).hexdigest()
            with self.subTest(kind=kind),self.assertRaises(m.BudgetError):m.commissioning_projection(*args,now=NOW)

    def test_billing_primary_never_assumes_absent_multipart_resource(self):
        m=self.subject()
        for kind in ('absent_inventory','selected_only','missing_sibling'):
            args=self.provider_inventory_inputs();inv=json.loads(args[1])
            if kind=='absent_inventory':inv.pop('resource_inventory')
            elif kind=='selected_only':inv['resource_inventory']['scope']='selected-bucket'
            else:
                resource=inv['resource_inventory'];raw=base64.b64decode(resource['objects_csv_base64'])
                sibling=raw.decode().splitlines()[1].replace(';object;', ';multipart;').replace(';synthetic-stage-b;', ';synthetic-stage-b_s3multipartuploads;')
                raw+= (sibling+'\n').encode();resource['objects_csv_base64']=base64.b64encode(raw).decode();resource['objects_sha256']=hashlib.sha256(raw).hexdigest()
            args[1]=json.dumps(inv).encode();args[2]['inventory_sha256']=hashlib.sha256(args[1]).hexdigest()
            with self.subTest(kind=kind),self.assertRaises(m.BudgetError):m.commissioning_projection(*args,now=NOW)

    def test_billed_multipart_sibling_is_summed_from_its_own_raw_selected_pair(self):
        m=self.subject();args=self.provider_inventory_inputs();inv=json.loads(args[1])
        sibling=copy.deepcopy(inv['provider_export']);objects=base64.b64decode(sibling['objects_csv_base64'])
        objects=objects.replace(b';object;',b';multipart;').replace(b';synthetic-stage-b;',b';synthetic-stage-b_s3multipartuploads;')
        metrics=base64.b64decode(sibling['metrics_csv_base64']).replace(b';1024;',b';8;')
        sibling['context'].update(object_id='multipart',objects_sha256=hashlib.sha256(objects).hexdigest(),billing_sha256=hashlib.sha256(metrics).hexdigest())
        sibling.update(objects_csv_base64=base64.b64encode(objects).decode(),metrics_csv_base64=base64.b64encode(metrics).decode())
        inv['associated_exports']=[sibling]
        resource=inv['resource_inventory'];raw=base64.b64decode(resource['objects_csv_base64'])+('\n'.join(objects.decode().splitlines()[1:])+'\n').encode()
        resource['objects_csv_base64']=base64.b64encode(raw).decode();resource['objects_sha256']=hashlib.sha256(raw).hexdigest()
        args[1]=json.dumps(inv).encode();args[2]['inventory_sha256']=hashlib.sha256(args[1]).hexdigest()
        r=m.commissioning_projection(*args,now=NOW)
        self.assertEqual(r['inventory']['storage_bytes'],1084231680)
        self.assertEqual(r['inventory']['associated_billed_resources'],1)

    def test_resource_membership_tolerates_exact_provider_duplicates_but_not_conflicting_hours(self):
        # Actual project export repeats an unrelated bucket's zero-cost row.
        # This inventory discovers membership; selected metric charges are not summed here.
        m=self.subject()
        for conflicting in (False,True):
            args=self.provider_inventory_inputs();inv=json.loads(args[1]);resource=inv['resource_inventory']
            raw=base64.b64decode(resource['objects_csv_base64'])
            foreign=raw.decode().splitlines()[1].replace(';object;',';unrelated;').replace(';synthetic-stage-b;',';another-bucket;')
            duplicate=foreign if not conflicting else foreign.rsplit(';',1)[0]+';0.02'
            raw+=(foreign+'\n'+duplicate+'\n').encode()
            resource.update(objects_csv_base64=base64.b64encode(raw).decode(),objects_sha256=hashlib.sha256(raw).hexdigest())
            args[1]=json.dumps(inv).encode();args[2]['inventory_sha256']=hashlib.sha256(args[1]).hexdigest()
            with self.subTest(conflicting=conflicting):
                if conflicting:
                    with self.assertRaises(m.BudgetError):m.commissioning_projection(*args,now=NOW)
                else:self.assertEqual(m.commissioning_projection(*args,now=NOW)['inventory']['associated_billed_resources'],0)


@unittest.skipIf(os.name == 'nt', 'Protected publisher tests require real POSIX ownership/modes')
class ProtectedCommissioningTests(unittest.TestCase):
    def fixture(self):
        m=subject();self.assertTrue(callable(getattr(m,'publish_commissioning_budget',None)),'Protected commissioning publisher absent')
        self.assertTrue(callable(getattr(m,'load_commissioning_budget',None)),'Protected commissioning reader absent')
        import worker,runtime
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);root=pathlib.Path(temporary.name);os.chmod(root,0o700)
        for name in ('bin','receipts','receipts/commissioning-inputs','units'):(root/name).mkdir(mode=0o700)
        expense={}
        for name in (*m.COST_FILES,'retention.py','retention_cohort.py','backup_catalog.py'):
            raw=('# synthetic '+name+'\n').encode();(root/'bin'/name).write_bytes(raw);os.chmod(root/'bin'/name,0o600)
            if name in m.COST_FILES:expense[name]=hashlib.sha256(raw).hexdigest()
        for name in ('budget.py','meter.py'):
            (root/'bin'/name).write_bytes((pathlib.Path(__file__).resolve().parents[1]/'infra/backup'/name).read_bytes());os.chmod(root/'bin'/name,0o600)
        binary=root/'bin/restic';binary.write_bytes(b'synthetic restic');os.chmod(binary,0o700);restic_sha=hashlib.sha256(binary.read_bytes()).hexdigest()
        patch=mock.patch.object(worker,'RESTIC_SHA',restic_sha);patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.object(m,'SYSTEMD_UNITS_ROOT',root/'units');patch.start();self.addCleanup(patch.stop)
        unit_shas={}
        for kind,calendar in [('binlog','*-*-* *:*:00 UTC'),('hourly','*-*-* *:00:00 UTC'),('full','*-*-* 03:30:00 UTC'),('monitor','*-*-* *:*:30 UTC')]:
            for suffix,text in [('timer','[Timer]\nOnCalendar='+calendar+'\nAccuracySec=1s\nRandomizedDelaySec=0\nPersistent=false\nUnit=suhoput2-stage-backup-'+kind+'.service\n'),
                                ('service','[Service]\nType=oneshot\nUser=root\nExecStart=/usr/bin/python3 '+str(root/'bin/worker.py')+' --config '+str(root/'config/runtime.json')+' '+kind+'\n')]:
                name='suhoput2-stage-backup-'+kind+'.'+suffix;raw=text.encode();(root/'units'/name).write_bytes(raw);os.chmod(root/'units'/name,0o644);unit_shas[name]=hashlib.sha256(raw).hexdigest()
        bindings={'expense_files':expense,'restic_sha256':restic_sha,'unit_sha256':unit_shas}
        bindings['algorithm_sha256']=hashlib.sha256(json.dumps(bindings,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        args=list(commissioning_inputs());args[5].update(bindings)
        args[2].update(configuration_sha256=m.commissioning_configuration_sha256(args[5]),source={'generation':'1'*32,'root':'synthetic'},generation='1'*32)
        model={'format':'commissioning-workload-model-v1','basis':args[3]['basis'],'fixture':True};raw_model=(json.dumps(model,sort_keys=True)+'\n').encode()
        args[3]['model_sha256']=hashlib.sha256(raw_model).hexdigest()
        inputs=root/'receipts/commissioning-inputs'
        for name,raw in [('access.jsonl',args[0]),('inventory.json',args[1]),('model.json',raw_model)]:
            (inputs/name).write_bytes(raw);os.chmod(inputs/name,0o600)
        for name,index in [('admission.json',2),('forecast.json',3),('rates.json',4),('configuration.json',5)]:runtime.atomic_json(inputs/name,args[index])
        w=types.SimpleNamespace(root=root,bin=root/'bin',binary=binary,c={'bucket':'synthetic-stage-b','region':'ru-1','generation':'1'*32,'code_sha':'f'*40},source=args[2]['source'])
        return m,w,inputs

    def test_real_protected_publication_and_reuse_do_not_require_cohort_or_document_commit(self):
        m,w,inputs=self.fixture();report=m.publish_commissioning_budget(w,now=NOW)
        self.assertEqual(report['result'],'PASS');self.assertEqual((w.root/'receipts/commissioning-budget.json').stat().st_mode&0o777,0o600)
        self.assertTrue((w.root/'receipts/commissioning-budget.origin.json').exists())
        w.c['code_sha']='e'*40
        self.assertEqual(m.load_commissioning_budget(w,now=NOW),report)
        self.assertEqual(m.load_commissioning_budget(w,now=NOW+dt.timedelta(days=2)),report)
        with self.assertRaises(ValueError):m.load_commissioning_budget(w,now=NOW+dt.timedelta(days=8))

    def test_historical_review_is_bound_to_model_controls_and_reused_without_redating(self):
        import runtime
        m,w,inputs=self.fixture();model=runtime.load_json(inputs/'model.json')
        controls={name:'e'*64 for name in ('archive_roundtrip','index_compaction','restore','retention','visible_inventory')}
        model['current_controls_sha256']=controls;runtime.atomic_json(inputs/'model.json',model)
        forecast=runtime.load_json(inputs/'forecast.json');forecast['model_sha256']=hashlib.sha256((inputs/'model.json').read_bytes()).hexdigest()
        runtime.atomic_json(inputs/'forecast.json',forecast)
        admission=runtime.load_json(inputs/'admission.json');target=admission['configuration_sha256'];admission['configuration_sha256']=None
        review={'format':'historical-baseline-review-v1','provider_raw_sha256':hashlib.sha256((inputs/'access.jsonl').read_bytes()).hexdigest(),
                'target_configuration_sha256':target,'model_sha256':forecast['model_sha256'],'reviewed_at':NOW.isoformat(),
                'current_controls_sha256':dict(controls)}
        admission['historical_baseline_review']=review;runtime.atomic_json(inputs/'admission.json',admission)
        report=m.publish_commissioning_budget(w,now=NOW);self.assertEqual(report['result'],'PASS')
        self.assertFalse(report['current_configuration_observed'])
        self.assertEqual(m.load_commissioning_budget(w,now=NOW+dt.timedelta(days=2)),report)
        review['current_controls_sha256']['restore']='f'*64;runtime.atomic_json(inputs/'admission.json',admission)
        with self.assertRaisesRegex(m.BudgetError,'Protected commissioning inputs'):m.publish_commissioning_budget(w,now=NOW)
        with self.assertRaises(m.BudgetError):m.load_commissioning_budget(w,now=NOW)

    def test_reader_rejects_changed_report_model_expense_binary_schedule_producer_or_source(self):
        for kind in ('report','model','expense','runtime','retention_native','retention_apply','retention_inventory','cohort','catalog','readiness','binary','schedule','producer','source','mode'):
            m,w,inputs=self.fixture();m.publish_commissioning_budget(w,now=NOW)
            if kind=='source':w.source={'generation':'2'*32}
            elif kind=='mode':os.chmod(inputs/'model.json',0o644)
            else:
                path={'report':w.root/'receipts/commissioning-budget.json','model':inputs/'model.json','expense':w.bin/'worker.py',
                      'runtime':w.bin/'runtime.py','retention_native':w.bin/'retention_native.py',
                      'retention_inventory':w.bin/'retention.py','cohort':w.bin/'retention_cohort.py','catalog':w.bin/'backup_catalog.py',
                      'retention_apply':w.bin/'retention_apply.py','readiness':w.bin/'readiness_v2.py','integrity':w.bin/'integrity.py',
                      'binary':w.binary,'schedule':w.root/'units/suhoput2-stage-backup-binlog.timer','producer':w.bin/'meter.py'}[kind]
                path.write_bytes(path.read_bytes()+b' ')
            with self.subTest(kind=kind),self.assertRaises(ValueError):m.load_commissioning_budget(w,now=NOW)

    def test_publisher_rejects_wrong_source_or_model_and_never_publishes_block_as_pass(self):
        import runtime
        for kind in ('source','model','over_budget'):
            m,w,inputs=self.fixture()
            if kind=='source':doc=runtime.load_json(inputs/'admission.json');doc['generation']='2'*32;runtime.atomic_json(inputs/'admission.json',doc)
            elif kind=='model':(inputs/'model.json').write_bytes(b'{}')
            else:doc=runtime.load_json(inputs/'forecast.json');doc['usage']['put_requests']=1000000;runtime.atomic_json(inputs/'forecast.json',doc)
            if kind=='over_budget':self.assertEqual(m.publish_commissioning_budget(w,now=NOW)['result'],'BLOCK')
            else:
                with self.subTest(kind=kind),self.assertRaises(ValueError):m.publish_commissioning_budget(w,now=NOW)
            self.assertFalse((w.root/'receipts/commissioning-budget.json').exists())

    def test_oversized_source_is_rejected_before_reading_it_into_monitor_memory(self):
        m,w,inputs=self.fixture()
        with open(inputs/'access.jsonl','r+b') as output:output.truncate(65*1024**2)
        original=pathlib.Path.read_bytes
        def bounded_read(path):
            if path.stat().st_size>64*1024**2:self.fail('Oversized source read before size guard')
            return original(path)
        with mock.patch.object(pathlib.Path,'read_bytes',bounded_read),self.assertRaises(ValueError):m.publish_commissioning_budget(w,now=NOW)


if __name__ == '__main__':
    unittest.main()
