"""Read-only storage accounting: failures cannot turn into empty inventory."""
import pathlib, sys, unittest, os, tempfile, time
from types import SimpleNamespace
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'infra/backup'))
import guards, runtime

PREFIX='suhoput2/stage-b/repositories/binlog/'

def page(rows, *, truncated='false', token=None, prefix=PREFIX, bucket='stage-b'):
    objects=''.join('<Contents><Key>'+key+'</Key><Size>'+str(size)+'</Size></Contents>' for key,size in rows)
    return ('<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>'+bucket+'</Name><Prefix>'+prefix+'</Prefix><IsTruncated>'+truncated+'</IsTruncated>'+objects+('' if token is None else '<NextContinuationToken>'+token+'</NextContinuationToken>')+'</ListBucketResult>').encode()

class StorageTests(unittest.TestCase):
    def test_exact_index_counts_from_all_pages_do_not_count_packs_or_other_buckets(self):
        m=self.subject();base=m.PREFIX+'base/'
        pages=[page([(PREFIX+'index/'+'a'*64,19),(base+'index/'+'b'*64,7)],prefix='',truncated='true',token='next'),
               page([(PREFIX+'index/'+'c'*64,5),(PREFIX+'data/index',100),('exports/index/file',22)],prefix='')]
        result=m.list_objects(lambda q:pages.pop(0),'stage-b','',whole_bucket=True)
        self.assertEqual(result['repository_indexes'],{'base':{'object_count':1,'bytes':7},'binlog':{'object_count':2,'bytes':24}})
        self.assertEqual(m.list_objects(lambda q:page([]),'stage-b',PREFIX)['repository_indexes'],{'binlog':{'object_count':0,'bytes':0}})
        with self.assertRaises(guards.GuardError):m.list_objects(lambda q:page([(PREFIX+'index/unknown',3)]),'stage-b',PREFIX)
    def subject(self):
        import storage
        return storage
    def test_complete_pages_count_only_requested_namespace(self):
        m=self.subject();responses=[page([(PREFIX+'data/a',12)],truncated='true',token='next'),page([(PREFIX+'config',5)])];calls=[]
        def read(query):calls.append(query);return responses.pop(0)
        r=m.list_objects(read,'stage-b',PREFIX)
        self.assertEqual(r['physical_bytes'],17);self.assertEqual(r['object_count'],2)
        self.assertEqual(calls[1]['continuation-token'],'next');self.assertEqual(r['list_requests'],2)
        self.assertFalse(r['whole_bucket_billed_storage_verified'])
    def test_explicit_whole_bucket_listing_counts_exports_without_claiming_billing(self):
        m=self.subject();raw=page([('exports/log.jsonl',8),(PREFIX+'config',5)],prefix='')
        result=m.list_objects(lambda q:raw,'stage-b','',whole_bucket=True)
        self.assertEqual(result['physical_bytes'],13);self.assertEqual(result['object_count'],2)
        self.assertFalse(result['whole_bucket_billed_storage_verified'])
        with self.assertRaises(guards.GuardError):m.list_objects(lambda q:raw,'stage-b','other/',whole_bucket=True)
    def test_live_workload_reads_current_source_sizes_and_recent_binlogs(self):
        m=self.subject()
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);uploads=root/'wordpress/wp-content/uploads';uploads.mkdir(parents=True)
            (uploads/'image.bin').write_bytes(b'12345');db=root/'db';db.mkdir()
            recent=db/'suhoput2-binlog.000002';recent.write_bytes(b'1234')
            old=db/'suhoput2-binlog.000001';old.write_bytes(b'old');os.utime(old,(1,1))
            w=SimpleNamespace(wp_volume=root/'wordpress',db_volume=db,sql=lambda query:b'8192\n')
            self.assertEqual(m.live_workload(w),{'database_bytes':8192,'media_bytes':5,'binlog_bytes_per_day':4})
            w.sql=lambda query:b'unknown\n'
            with self.assertRaises(guards.GuardError):m.live_workload(w)
    def test_invalid_partial_foreign_or_duplicate_response_blocks(self):
        m=self.subject()
        for raw in (b'<Error/>',b'<bad',page([],truncated='true'),page([],truncated='maybe'),page([],bucket='foreign'),page([],prefix='else/'),page([(PREFIX+'a',-1)]),page([('foreign/a',1)]),page([(PREFIX+'a',1),(PREFIX+'a',1)])):
            with self.subTest(raw=raw),self.assertRaises(guards.GuardError):m.list_objects(lambda q:raw,'stage-b',PREFIX)
    def test_repeated_token_and_cross_page_duplicate_block(self):
        m=self.subject()
        for second in (page([],truncated='true',token='next'),page([(PREFIX+'a',1)])):
            data=[page([(PREFIX+'a',1)],truncated='true',token='next'),second]
            with self.assertRaises(guards.GuardError):m.list_objects(lambda q:data.pop(0),'stage-b',PREFIX)
    def test_transport_error_is_not_zero(self):
        m=self.subject()
        def fail(query):raise TimeoutError()
        with self.assertRaises(TimeoutError):m.list_objects(fail,'stage-b',PREFIX)
    @unittest.skipIf(os.name!='posix','Protected Linux receipt ownership')
    def test_live_receipt_is_bound_to_original_forecast_and_installed_producer(self):
        m=self.subject()
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);os.chmod(root,0o700)
            for name in ('receipts','bin'):(root/name).mkdir(mode=0o700)
            producer=root/'bin/storage.py';producer.write_bytes(b'synthetic producer');os.chmod(producer,0o600)
            w=SimpleNamespace(root=root,bin=root/'bin');forecast={'configuration_sha256':'f'*64}
            observation={'physical_bytes':100}
            m.publish_live_observation(w,forecast,observation)
            self.assertEqual(m.load_live_observation(w,forecast),observation)
            with self.assertRaises(guards.GuardError):m.load_live_observation(w,{'configuration_sha256':'a'*64})
            receipt=root/'receipts/commissioning-live.json';doc=runtime.load_json(receipt)
            doc['observation']['physical_bytes']=1;runtime.atomic_json(receipt,doc)
            with self.assertRaises(guards.GuardError):m.load_live_observation(w,forecast)
    @unittest.skipIf(os.name!='posix','Protected Linux inventory cache')
    def test_six_hour_native_observation_is_accepted_by_real_budget_consumer(self):
        from unittest.mock import patch
        import datetime as dt, json, budget, backup_budget_test as fixture
        m=self.subject();args=list(fixture.commissioning_inputs());args[3]['visible_interval_seconds']=21600
        args[3]['index_envelope']['base']['bytes']=32*1024**2
        forecast=budget.commissioning_projection(*args,now=fixture.NOW)
        forecast.update(source={'test':'source'},generation='1'*32)
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);os.chmod(root,0o700)
            for name in ('receipts','bin'):(root/name).mkdir(mode=0o700)
            producer=root/'bin/storage.py';producer.write_bytes(b'synthetic producer');producer.chmod(0o600)
            w=SimpleNamespace(root=root,bin=root/'bin',c={'bucket':forecast['bucket'],'generation':forecast['generation']},source=forecast['source'])
            measured=m.list_objects(lambda q:page([(m.PREFIX+'base/index/'+'a'*64,4096),
                (PREFIX+'index/'+'b'*64,8192)],prefix='',bucket=forecast['bucket']),forecast['bucket'],'',whole_bucket=True)
            clock=SimpleNamespace(datetime=SimpleNamespace(now=lambda tz:fixture.NOW),timezone=dt.timezone)
            with patch.object(m,'dt',clock),patch.object(m,'run_inventory',return_value=measured),patch.object(m,'live_workload',return_value=json.loads(args[1])['workload']):
                observation=m.live_observation(w,forecast)
            self.assertTrue(budget.commissioning_live_applicable(forecast,observation,now=fixture.NOW))
    @unittest.skipIf(os.name!='posix','Protected Linux inventory cache')
    def test_monitor_reuses_visible_listing_without_refreshing_its_observed_time(self):
        from unittest.mock import patch
        import datetime as dt
        m=self.subject()
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);os.chmod(root,0o700)
            for name in ('receipts','bin'):(root/name).mkdir(mode=0o700)
            producer=root/'bin/storage.py';producer.write_bytes(b'synthetic producer');os.chmod(producer,0o600)
            w=SimpleNamespace(root=root,bin=root/'bin',c={'bucket':'stage-b','generation':'1'*32},source={'test':'source'})
            forecast={'scope_sha256':'f'*64,'configuration_sha256':'e'*64}
            measured={'physical_bytes':100,'object_count':2,'page_sha256':['a'*64],'list_requests':1}
            with patch.object(m,'run_inventory',return_value=measured) as remote,patch.object(m,'live_workload',return_value={'measured':'workload'}):
                first=m.live_observation(w,forecast);second=m.live_observation(w,forecast)
                self.assertEqual(remote.call_count,1)
                self.assertEqual(first['visible_sampled_at'],second['visible_sampled_at'])
                self.assertEqual(second['format'],'commissioning-live-observation-v2')
                self.assertEqual(second['physical_bytes'],100)
                cache=root/'receipts/commissioning-visible.json';doc=runtime.load_json(cache)
                doc['sampled_at']=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(hours=2)).isoformat()
                doc['sha256']=m.document_digest({k:v for k,v in doc.items() if k!='sha256'});runtime.atomic_json(cache,doc)
                m.live_observation(w,forecast);self.assertEqual(remote.call_count,2)
                forecast={**forecast,'visible_interval_seconds':21600}
                third=m.live_observation(w,forecast);self.assertEqual(remote.call_count,3)
                self.assertEqual(third['format'],'commissioning-live-observation-v3')
                doc=runtime.load_json(cache);stamp=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(hours=3)).isoformat()
                doc['sampled_at']=stamp;doc['sha256']=m.document_digest({k:v for k,v in doc.items() if k!='sha256'});runtime.atomic_json(cache,doc)
                cached=m.live_observation(w,forecast);self.assertEqual(remote.call_count,3)
                self.assertEqual(cached['visible_sampled_at'],stamp)
                doc['sampled_at']=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(hours=6)).isoformat()
                doc['sha256']=m.document_digest({k:v for k,v in doc.items() if k!='sha256'});runtime.atomic_json(cache,doc)
                m.live_observation(w,forecast);self.assertEqual(remote.call_count,4)
    def test_entity_expansion_and_unbounded_namespace_are_rejected(self):
        m=self.subject()
        raw=b'<!DOCTYPE a [<!ENTITY x "boom">]><ListBucketResult>&x;</ListBucketResult>'
        with self.assertRaises(guards.GuardError):m.list_objects(lambda q:raw,'stage-b',PREFIX)
        with self.assertRaises(guards.GuardError):m.list_objects(lambda q:page([]),'stage-b','')
    @unittest.skipIf(os.name!='posix','Native Linux process termination')
    def test_slow_reader_is_killed_within_overall_deadline(self):
        from worker import NativeRunner, NativeError
        m=self.subject()
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);os.chmod(root,0o700)
            (root/'storage.py').write_text('import time; time.sleep(5); print("{}")')
            w=SimpleNamespace(root=root,bin=root,native=NativeRunner(root));started=time.monotonic()
            with self.assertRaises(NativeError):m.run_inventory(w,'binlog',0.2)
            self.assertLess(time.monotonic()-started,2)

if __name__=='__main__':unittest.main()
