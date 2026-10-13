"""Synthetic provider log scopes, counters and charge groups."""
import datetime as dt,hashlib,importlib.util,json,pathlib,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'infra/backup'))
import guards
def subject():
    unittest.TestCase().assertIsNotNone(importlib.util.find_spec('meter'),'Provider access-log counter reader absent')
    import meter
    return meter
def row(method='GET',status=200,**kw):
    return {'container_name':'synthetic-stage-b','timestamp':'2026-10-12T12:00:00Z',
            'server_to_client_bytes':120,'client_to_server_bytes':80,'http_method':method,
            'status':status,'path':'/synthetic-stage-b/suhoput2/stage-b/repositories/base/config',**kw}
def data(rows):return b'\n'.join(json.dumps(r).encode() for r in rows)+b'\n'
class MeterTests(unittest.TestCase):
    def test_completed_provider_window_covers_quiet_edges_and_counts_each_retry_once(self):
        m=subject();self.assertTrue(callable(getattr(m,'provider_window',None)),'Completed provider-window reader absent')
        raw=data([row(account_uuid='a'*32),row(account_uuid='a'*32)])
        window={'status':'DONE','from':'2026-10-12T11:00:00Z','until':'2026-10-12T13:00:00Z',
                'completed_at':'2026-10-12T13:01:00Z','sha256':hashlib.sha256(raw).hexdigest(),
                'account_scope_sha256':hashlib.sha256(('a'*32).encode()).hexdigest()}
        report=m.provider_window(raw,bucket='synthetic-stage-b',window=window,now=dt.datetime(2026,10,12,14,tzinfo=dt.timezone.utc))
        self.assertEqual(report['http_requests'],2);self.assertEqual(report['server_to_client_bytes'],240)
        self.assertEqual(report['window_seconds'],7200);self.assertTrue(report['complete_provider_window'])
        self.assertFalse(report['monthly_projection_verified'])

    def test_window_requires_completed_export_hash_scope_and_all_rows_inside_interval(self):
        m=subject();self.assertTrue(callable(getattr(m,'provider_window',None)),'Completed provider-window reader absent')
        raw=data([row(account_uuid='a'*32)])
        original={'status':'DONE','from':'2026-10-12T11:00:00Z','until':'2026-10-12T13:00:00Z',
                  'completed_at':'2026-10-12T13:01:00Z','sha256':hashlib.sha256(raw).hexdigest(),
                  'account_scope_sha256':hashlib.sha256(('a'*32).encode()).hexdigest()}
        for key,value in [('status','IN PROGRESS'),('sha256','0'*64),('account_scope_sha256','0'*64),
                          ('from','2026-10-12T12:00:01Z'),('until','2026-10-12T12:00:00Z'),
                          ('completed_at','2026-10-12T12:59:00Z')]:
            with self.subTest(key=key),self.assertRaises(guards.GuardError):
                m.provider_window(raw,bucket='synthetic-stage-b',window={**original,key:value},now=dt.datetime(2026,10,12,14,tzinfo=dt.timezone.utc))

    def test_provider_mandatory_account_uuid_and_absolute_https_path_are_bound(self):
        r=row(account_uuid='a'*32,path='https://api.ru-1.storage.selcloud.ru/v2/panel/containers')
        report=subject().access_log(data([r]),bucket='synthetic-stage-b')
        self.assertEqual(report['http_requests'],1)
        self.assertEqual(report['account_scope_sha256'],__import__('hashlib').sha256(('a'*32).encode()).hexdigest())
        bad=row(account_uuid='b'*32)
        with self.assertRaises(guards.GuardError):subject().access_log(data([r,bad]),bucket='synthetic-stage-b')
    def test_physical_request_lines_retry_status_and_native_bytes_are_preserved(self):
        rows=[row('HEAD'),row('GET'),row('PUT'),row('POST'),row('COPY'),row('DELETE'),row('GET',503),row('GET',403)]
        report=subject().access_log(data(rows),bucket='synthetic-stage-b')
        self.assertEqual(report['http_requests'],8);self.assertEqual(report['server_to_client_bytes'],960)
        self.assertEqual(report['charge_groups'],{'GET':2,'PUT':3,'DELETE':0})
        self.assertEqual(report['methods']['GET'],3);self.assertEqual(report['status_exempt_requests'],2)
        self.assertFalse(report['monthly_projection_verified'])
    def test_foreign_bucket_unknown_fields_duplicate_json_naive_time_bool_or_missing_bytes_rejected(self):
        for kwargs in ({'container_name':'other'},{'secret':'injected'},{'timestamp':'2026-10-12T12:00:00'},
                       {'server_to_client_bytes':True},{'server_to_client_bytes':-1},{'http_method':'PATCH'}):
            with self.subTest(kwargs=kwargs),self.assertRaises(guards.GuardError):subject().access_log(data([row(**kwargs)]),bucket='synthetic-stage-b')
        raw=data([row()]).replace(b'"status": 200',b'"status":200,"status":200')
        with self.assertRaises(guards.GuardError):subject().access_log(raw,bucket='synthetic-stage-b')
        missing=row();missing.pop('client_to_server_bytes')
        with self.assertRaises(guards.GuardError):subject().access_log(data([missing]),bucket='synthetic-stage-b')
    def test_job_window_uses_utc_receipt_range_and_reports_overlap(self):
        rows=[row(timestamp='2026-10-12T12:00:00Z'),row(timestamp='2026-10-12T12:00:01Z'),row(timestamp='2026-10-12T12:00:02Z')]
        windows={'binlog':{'started_at':'2026-10-12T12:00:00Z','completed_at':'2026-10-12T12:00:02Z'},
                 'restore':{'started_at':'2026-10-12T12:00:01Z','completed_at':'2026-10-12T12:00:03Z'}}
        report=subject().access_log(data(rows),bucket='synthetic-stage-b',windows=windows)
        self.assertEqual(report['jobs']['binlog']['http_requests'],3)
        self.assertEqual(report['overlapping_request_lines'],2)
        self.assertFalse(report['isolated_job_measurement'])
if __name__=='__main__':unittest.main()
