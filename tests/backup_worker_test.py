"""Synthetic fail-closed capture/native policy checks. No external credentials."""
import importlib.util,sys,pathlib,unittest,tempfile,json,hashlib,os,stat
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'infra'/'backup'))
import guards
GEN='a'*32;CODE='b'*40;DB_IMAGE='mariadb:10.11@sha256:7db29378d4fdab73f8123bbc2b48905c90d1a4b00cf848b028f1e81e623257f2';WP_IMAGE='wordpress:7.1.3-php8.3-apache@sha256:8ecd8d8e374167ea22235acf30f80d1165b82f07ffa5bcef90c1cad8f7be251f'
def module(name,features=()):
    case=unittest.TestCase();case.assertIsNotNone(importlib.util.find_spec(name),'Missing protected native '+name);result=__import__(name);[case.assertTrue((hasattr(result,f) or (hasattr(result,'Worker') and hasattr(result.Worker,f))),'Missing native function '+f) for f in features];return result
def config():return {'format':1,'root':'/srv/suhoput2-stage-20261011','schema':'suhoput2_stage','generation':GEN,'code_sha':CODE,'stage_app_sha':'c'*40,'endpoint':'https://s3.invalid','bucket':'stage-only','region':'ru-1','db_id':'d'*64,'wordpress_id':'e'*64,'db_environment_sha256':'f'*64,'wordpress_environment_sha256':'1'*64}
def dump(*extra):
    tables=[]
    for table,columns in [('wp_posts',['ID','post_type','post_content']),('wp_postmeta',['meta_id','post_id','meta_key','meta_value']),('wp_options',['option_id','option_name','option_value'])]:
        tables.append('CREATE TABLE `'+table+'` (\n'+',\n'.join('  `'+c+'` longtext' for c in columns)+'\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;')
    return ('-- CHANGE MASTER TO MASTER_LOG_FILE=\'suhoput2-binlog.000001\', MASTER_LOG_POS=512;\n'+'\n'.join(tables)+'\n'+"INSERT INTO `wp_posts` (`ID`, `post_type`, `post_content`) VALUES (1,'attachment','');\n"+"INSERT INTO `wp_postmeta` (`meta_id`, `post_id`, `meta_key`, `meta_value`) VALUES (1,1,'_wp_attached_file','a.jpg');\n"+'\n'.join(extra)).encode()
class DumpCaptureTests(unittest.TestCase):
    def test_snapshot_records_come_from_all_dump_tables(self):
        m=module('dump_records');r=m.records(dump("INSERT INTO `wp_options` (`option_id`, `option_name`, `option_value`) VALUES (1,'custom','wp-content/uploads/custom.pdf');"));self.assertEqual(r['posts'],[{'ID':'1','post_type':'attachment'}]);self.assertIn('wp-content/uploads/custom.pdf',r['texts']);self.assertEqual(r['tables'],3)
    def test_native_sql_escaping_quotes_backslashes_hex_utf8(self):
        m=module('dump_records');self.assertEqual(m.values(br"'a\'b','a\\b','line\nrow',0x6869,NULL,1.2,-9"),[b"a'b",b'a\\b',b'line\nrow',b'hi',None,b'1.2',b'-9'])
    def test_missing_column_unknown_row_or_engine_rejected(self):
        m=module('dump_records')
        for bad in [dump().replace(b'ENGINE=InnoDB',b'ENGINE=MyISAM'),dump("INSERT INTO `wp_posts` (`ID`) VALUES (2);"),dump("INSERT INTO `other` (`ID`) VALUES (1);"),dump("REPLACE INTO `wp_posts` VALUES (1,'attachment','');")]:
            with self.subTest(bad=bad[-50:]),self.assertRaises(guards.GuardError):m.records(bad)
    def test_unknown_sql_value_and_truncated_string_fail(self):
        m=module('dump_records')
        for bad in [b"'unterminated",b"CONCAT('a','b')",br"'unknown\q'",b'0x123',b"'x',"]:
            with self.assertRaises(guards.GuardError):m.values(bad)
    def test_duplicate_tables_and_columns_fail(self):
        m=module('dump_records')
        with self.assertRaises(guards.GuardError):m.records(dump()+dump())
        with self.assertRaises(guards.GuardError):m.records(dump().replace(b'`meta_key`, `meta_value`',b'`meta_key`, `meta_key`'))
class NativeWorkerPolicyTests(unittest.TestCase):
    def test_config_is_fixed_stage_and_canonical_repositories(self):
        m=module('worker');c=m.validate_config(config());self.assertEqual(c['source']['db_volume'],'suhoput2-stage-20261011_db');self.assertTrue(c['repositories']['binlog'].endswith('/suhoput2/stage-b/repositories/binlog'))
    def test_wrong_source_endpoint_identity_and_code_rejected(self):
        m=module('worker')
        for field,value in [('root','/srv/suhoput'),('schema','production'),('endpoint','http://s3.invalid'),('generation','other'),('db_id','bad'),('code_sha','unknown')]:
            with self.subTest(field=field),self.assertRaises(guards.GuardError):m.validate_config({**config(),field:value})
    def test_binlog_coordinates_require_single_native_record(self):
        m=module('worker');self.assertEqual(m.coordinates(dump()),{'file':'suhoput2-binlog.000001','position':512})
        for bad in [dump()+dump(),dump().replace(b'POS=512',b'POS=2'),dump().replace(b'suhoput2-binlog',b'old-prod-binlog')]:
            with self.assertRaises(guards.GuardError):m.coordinates(bad)
    def test_env_is_data_not_shell_and_cannot_inherit_other_credentials(self):
        m=module('worker');e=m.parse_credentials('AWS_ACCESS_KEY_ID=fake\nAWS_SECRET_ACCESS_KEY=synthetic\nAWS_DEFAULT_REGION=ru-1\n');self.assertEqual(set(e),{'AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_DEFAULT_REGION'})
        for bad in ['AWS_ACCESS_KEY_ID=fake\nAWS_ACCESS_KEY_ID=again\n','source /etc/old\n','AWS_SESSION_TOKEN=other\n','AWS_SECRET_ACCESS_KEY=$(cat /old)\n']:
            with self.assertRaises(guards.GuardError):m.parse_credentials(bad)
    def test_tree_captures_hashes_and_rejects_links(self):
        m=module('worker')
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);(root/'a').write_bytes(b'actual');r=m.tree_inventory(root);self.assertEqual(r,[{'path':'a','bytes':6,'sha256':hashlib.sha256(b'actual').hexdigest()}])
            if os.name!='nt':
                (root/'link').symlink_to('/etc/passwd')
                with self.assertRaises(guards.GuardError):m.tree_inventory(root)
    def test_native_failure_does_not_include_secret_diagnostic(self):
        m=module('worker');error=m.NativeError('failed','Authorization secret synthetic');self.assertNotIn('Authorization',str(error));self.assertNotIn('secret',str(error))
class CaptureRuntimeTests(unittest.TestCase):
    def test_container_identity_rejects_wrong_volume_image_environment_ports(self):
        m=module('worker',('verify_container',));c=m.validate_config(config());label={'com.docker.compose.project':c['source']['project'],'com.docker.compose.service':'db'}
        row={'Id':c['db_id'],'Config':{'Image':DB_IMAGE,'Labels':label,'Env':['SYNTHETIC=yes']},'Mounts':[{'Type':'volume','Name':c['source']['db_volume'],'Destination':'/var/lib/mysql','Source':'/var/lib/docker/volumes/'+c['source']['db_volume']+'/_data','RW':True}],'NetworkSettings':{'Ports':{'3306/tcp':None}}};c['db_environment_sha256']=hashlib.sha256('\0'.join(sorted(row['Config']['Env'])).encode()).hexdigest();m.verify_container(c,'db',row)
        import copy
        for mutation in ('image','volume','env','ports','id'):
            bad=copy.deepcopy(row)
            if mutation=='image':bad['Config']['Image']='old-db'
            if mutation=='volume':bad['Mounts'][0]['Name']='production'
            if mutation=='env':bad['Config']['Env']=['OTHER=credential']
            if mutation=='ports':bad['NetworkSettings']['Ports']={'3306/tcp':[{'HostPort':'3306'}]}
            if mutation=='id':bad['Id']='f'*64
            with self.assertRaises(guards.GuardError):m.verify_container(c,'db',bad)
    def test_disk_budget_reserves_space_and_never_shrinks_retention(self):
        m=module('worker',('disk_gate',));m.disk_gate(8*1024**3,500*1024**2)
        for free,spool in [(4*1024**3,0),(8*1024**3,2*1024**3)]:
            with self.assertRaises(guards.GuardError):m.disk_gate(free,spool)
    def test_payload_files_are_verified_before_accepting_remote_manifest(self):
        m=module('worker',('verify_payload',))
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d);(p/'db.sql').write_bytes(b'captured SQL');manifest={'files':m.tree_inventory(p)};m.verify_payload(p,manifest);(p/'db.sql').write_bytes(b'changed SQL')
            with self.assertRaises(guards.GuardError):m.verify_payload(p,manifest)
    def test_stale_minute_confirmation_is_an_error_not_new_watermark(self):
        m=module('worker',('binlog_watermark',));import datetime as dt
        with self.assertRaises(guards.GuardError):m.binlog_watermark('2026-10-12T10:00:00Z',dt.datetime(2026,10,12,10,1,1,tzinfo=dt.timezone.utc))
class SnapshotCoherenceTests(unittest.TestCase):
    def fake(self,directory,mutate=False):
        m=module('worker');w=m.Worker.__new__(m.Worker);w.stage=pathlib.Path(directory);w.root=w.stage/'backup';w.c=m.validate_config(config());w.source=w.c['source'];w.wp_volume=w.stage/'wp';w.wp_mounts=[]
        for name in ['backup/spool','backup/receipts','wp/wp-content/uploads','infra/staging']:(w.stage/name).mkdir(parents=True,exist_ok=True)
        (w.wp_volume/'wp-content/uploads/a.jpg').write_bytes(b'before snapshot')
        for name in ['.env','infra/staging/compose.yaml','infra/staging/backup.override.yaml','infra/staging/safety.php','infra/staging/proxy.conf']:(w.stage/name).write_text('synthetic')
        w.source_check=lambda:None;w.gate=lambda:None;w.schema_catalog=lambda:module('dump_records').records(dump())['catalog']
        def capture(path,**kwargs):
            path.write_bytes(dump())
            if mutate:(w.wp_volume/'wp-content/uploads/a.jpg').write_bytes(b'after snapshot')
        w.dump=capture;w.media=lambda *args:[]
        def upload(lane,payload):
            import runtime
            manifest=runtime.load_json(payload/'manifest.json');runtime.atomic_json(w.root/'receipts'/lane/'state.json',{'generation':GEN,'confirmed':[{'id':'a'*64,'manifest_sha256':m.sha(payload/'manifest.json'),'captured_at':manifest['captured_at'],'confirmed_at':manifest['captured_at'],'token':'b'*32}]});return 'a'*64
        w.upload=upload;return w
    def test_media_changes_during_sql_snapshot_fail_before_upload(self):
        with tempfile.TemporaryDirectory() as d:
            w=self.fake(d,True);calls=[];w.upload=lambda *args:calls.append(args) or 'a'*64
            with self.assertRaises(guards.GuardError):w.base('full')
            self.assertEqual(calls,[])
    def test_full_rejects_wrong_captured_app_even_when_source_returns_to_baseline(self):
        from unittest.mock import patch
        import shutil
        with tempfile.TemporaryDirectory() as d:
            w=self.fake(d);real=shutil.copyfile;calls=[];w.upload=lambda *args:calls.append(args) or 'a'*64
            def altered_copy(source,target,*args,**kwargs):
                result=real(source,target,*args,**kwargs)
                if pathlib.Path(target).name=='.env':pathlib.Path(target).write_bytes(b'copied concurrent version')
                return result
            with patch('worker.shutil.copyfile',side_effect=altered_copy),self.assertRaises(guards.GuardError):w.base('full')
            self.assertEqual(calls,[])
    def test_unchanged_file_and_similarly_named_directory_have_same_hash(self):
        with tempfile.TemporaryDirectory() as d:
            w=self.fake(d);(w.wp_volume/'blocks').mkdir();(w.wp_volume/'blocks/a.php').write_bytes(b'directory');(w.wp_volume/'blocks.php').write_bytes(b'file');w.base('full')
    def test_snapshot_watermark_precedes_dump_not_its_completion(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as d:
            w=self.fake(d);m=module('worker');original=w.dump
            def timed_dump(path,**kw):original(path,**kw);m.now()
            w.dump=timed_dump
            with patch('worker.now',side_effect=['2026-10-12T10:00:00Z','2026-10-12T10:00:20Z','2026-10-12T10:00:30Z','2026-10-12T10:00:40Z']):
                r=w.base('full');self.assertEqual(r['captured_at'],'2026-10-12T10:00:00Z')
class FinalizationCrashTests(unittest.TestCase):
    def prepared(self,d,lane,kind):
        m=module('worker',('finalize',));w=SnapshotCoherenceTests().fake(d);p=w.root/'spool'/(lane+'-payload');p.mkdir();(p/'data').write_bytes(b'actual capture');manifest={'generation':GEN,'captured_at':'2026-10-12T10:00:00Z','kind':kind,'previous_count':0,'first_log':1,'last_log':1,'coordinates':{'file':'suhoput2-binlog.000001','position':512},'files':m.tree_inventory(p)}
        if lane=='binlog':manifest.update(logs=[{'file':'suhoput2-binlog.000001','size':4,'sha256':'c'*64}],source_stats={'suhoput2-binlog.000001':[1,2,3]})
        import runtime;runtime.atomic_json(p/'manifest.json',manifest);runtime.atomic_json(w.root/'receipts'/lane/'state.json',{'generation':GEN,'confirmed':[{'id':'d'*64,'manifest_sha256':m.sha(p/'manifest.json'),'captured_at':manifest['captured_at'],'confirmed_at':manifest['captured_at'],'token':'e'*32}]});return m,w,p
    def test_confirmed_full_after_journal_crash_becomes_hourly_prerequisite(self):
        with tempfile.TemporaryDirectory() as d:
            m,w,p=self.prepared(d,'base','full');w.finalize('base',p,'d'*64);self.assertEqual(module('runtime').load_json(w.root/'receipts/full.json')['snapshot_id'],'d'*64)
            before=(w.root/'receipts/full.json').read_bytes();w.finalize('base',p,'d'*64);self.assertEqual(before,(w.root/'receipts/full.json').read_bytes())
    def test_confirmed_binlog_after_journal_crash_appends_once(self):
        with tempfile.TemporaryDirectory() as d:
            m,w,p=self.prepared(d,'binlog','binlog');w.finalize('binlog',p,'d'*64);w.finalize('binlog',p,'d'*64);chain=module('runtime').load_json(w.root/'receipts/binlog-chain.json');self.assertEqual(len(chain['logs']),1);self.assertEqual(chain['last_success_at'],'2026-10-12T10:00:00Z')
    def test_finalizer_rejects_unconfirmed_or_changed_payload(self):
        with tempfile.TemporaryDirectory() as d:
            m,w,p=self.prepared(d,'base','full');(p/'data').write_bytes(b'changed')
            with self.assertRaises(guards.GuardError):w.finalize('base',p,'d'*64)
            self.assertFalse((w.root/'receipts/full.json').exists())
class CaptureRecoveryTests(unittest.TestCase):
    def test_pre_upload_failure_can_retry_and_preserves_failed_capture(self):
        with tempfile.TemporaryDirectory() as d:
            w=SnapshotCoherenceTests().fake(d,True)
            with self.assertRaises(guards.GuardError):w.base('full')
            first=(w.root/'spool/base-payload/db.sql').read_bytes()
            w.dump=lambda path,**kw:path.write_bytes(dump())
            w.base('full')
            failed=list((w.root/'spool').glob('failed-base-*'))
            self.assertEqual(len(failed),1);self.assertEqual((failed[0]/'db.sql').read_bytes(),first)
    def test_confirmed_local_copies_remain_bounded_and_foreign_bytes_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            w=SnapshotCoherenceTests().fake(d);foreign=w.root/'spool/foreign';foreign.mkdir();(foreign/'keep').write_bytes(b'foreign')
            for i in range(5):
                w.base('full')
            self.assertEqual(list((w.root/'spool').glob('confirmed-*')),[])
            self.assertEqual((foreign/'keep').read_bytes(),b'foreign')
    def test_cleanup_crash_after_rename_recovers_without_second_capture(self):
        from unittest.mock import patch
        import runtime
        with tempfile.TemporaryDirectory() as d:
            w=SnapshotCoherenceTests().fake(d);w.base('full');real=runtime.atomic_json
            def crashing(path,value):
                if pathlib.Path(path).name=='cleanup-base.json' and value.get('phase')=='deleting':raise OSError('synthetic fsync failure')
                return real(path,value)
            with patch('runtime.atomic_json',side_effect=crashing),self.assertRaises(OSError):w.prepare_payload('base')
            self.assertFalse((w.root/'spool/base-payload').exists());self.assertEqual(len(list((w.root/'spool').glob('confirmed-*'))),1)
            w.prepare_payload('base');self.assertEqual(list((w.root/'spool').glob('confirmed-*')),[])
    def test_hourly_rejects_changed_application_and_generation(self):
        with tempfile.TemporaryDirectory() as d:
            w=SnapshotCoherenceTests().fake(d);(w.wp_volume/'index.php').write_bytes(b'original');w.base('full')
            (w.wp_volume/'index.php').write_bytes(b'changed')
            calls=[];w.upload=lambda *args:calls.append(args) or 'a'*64
            with self.assertRaises(guards.GuardError):w.base('hourly')
            self.assertEqual(calls,[])
    def test_attempted_upload_or_foreign_capture_cannot_be_quarantined(self):
        m=module('worker');import runtime
        for attempted in (True,False):
            with self.subTest(attempted=attempted),tempfile.TemporaryDirectory() as d:
                w=SnapshotCoherenceTests().fake(d);self.assertTrue(hasattr(w,'capture_intent'));p=w.prepare_payload('base');(p/'keep').write_bytes(b'unacknowledged')
                if attempted:
                    runtime.atomic_json(w.root/'receipts/capture-base.json',{**runtime.load_json(w.root/'receipts/capture-base.json'),'phase':'upload'})
                else:(p/'.capture.json').unlink()
                with self.assertRaises(guards.GuardError):w.prepare_payload('base')
                self.assertEqual((p/'keep').read_bytes(),b'unacknowledged')
if __name__=='__main__':unittest.main()