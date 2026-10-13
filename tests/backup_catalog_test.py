"""Synthetic admission/store fault tests; no native or external provenance claim."""
import contextlib, copy, datetime as dt, hashlib, importlib.util, json, os, pathlib, shutil, sqlite3, sys, tempfile, threading, unittest, weakref
from types import SimpleNamespace
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'infra'/'backup'))
import guards, runtime

GEN='a'*32; SID='1'*64; TREE='2'*64; TOKEN='3'*32
NOW=dt.datetime(2026,10,12,12,tzinfo=dt.timezone.utc)

def subject():
    unittest.TestCase().assertIsNotNone(importlib.util.find_spec('backup_catalog'),'Verified archive catalog missing')
    import backup_catalog
    return backup_catalog

class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=pathlib.Path(self.temp.name);os.chmod(self.root,0o700)
        for name in ('receipts','cache','spool'):(self.root/name).mkdir(mode=0o700)
        self.source={'root':'/srv/suhoput2-stage-20261011','generation':GEN}
        self.w=SimpleNamespace(root=self.root,source=self.source,c={'generation':GEN,'code_sha':'b'*40,'stage_app_sha':'c'*40,
            'repositories':{lane:'s3:https://s3.invalid/stage-test/suhoput2/stage-b/repositories/'+lane for lane in ('base','binlog')}})
        for lane,digit in [('base','7'),('binlog','8')]:runtime.atomic_json(self.root/'receipts'/('init-'+lane+'.json'),{'generation':GEN,'repository_id':digit*64})
        self.restored=self.root/'cache'/'restored';self.restored.mkdir(mode=0o700)
        (self.restored/'db.sql').write_bytes(b'synthetic database bytes');os.chmod(self.restored/'db.sql',0o600)
        self.manifest={'format':1,'generation':GEN,'kind':'full','source':self.source,'code_sha':'d'*40,'stage_app_sha':'c'*40,
            'captured_at':'2026-10-12T11:00:00Z','coordinates':{'file':'suhoput2-binlog.000001','position':4},'full_id':None,
            'application_sha256':'e'*64,'configuration_sha256':'f'*64,
            'files':[{'path':'db.sql','bytes':24,'sha256':hashlib.sha256(b'synthetic database bytes').hexdigest()}]}
        self.refresh()
    def refresh(self):
        self.raw=json.dumps(self.manifest,indent=1).encode()+b'\n'
        (self.restored/'manifest.json').write_bytes(self.raw);os.chmod(self.restored/'manifest.json',0o600)
        self.meta={'id':SID,'tree':TREE,'time':'2026-10-12T11:01:00Z','paths':[str(self.root/'spool'/'base-payload')],
            'tags':['task047','generation:'+GEN,'token:'+TOKEN,'manifest-sha:'+hashlib.sha256(self.raw).hexdigest()]}
    def catalog(self):return subject().ArchiveCatalog(self.w)
    def admit(self,c=None,**kwargs):return (c or self.catalog()).admit('base',SID,self.meta,self.raw,self.restored,**kwargs)
    def test_admission_preserves_original_raw_and_compact_verified_identity(self):
        c=self.catalog();self.admit(c);entry=c.entries()[SID]
        self.assertEqual(c.raw_manifest(SID),self.raw)
        self.assertEqual(entry['projection']['code_sha'],'d'*40)
        self.assertNotIn('files',entry['projection'])
        self.assertEqual(entry['native']['tree'],TREE)
        self.assertEqual(entry['repository_id'],'7'*64)
        self.assertEqual(entry['verified']['file_count'],2)
        self.assertEqual(entry['verified']['payload_bytes'],24)
        self.assertEqual(entry['verified']['code_sha'],'b'*40)
        self.w.c['code_sha']='9'*40
        self.assertEqual(c.entries()[SID]['verified']['code_sha'],'b'*40)
        self.admit(c);self.assertEqual(len(c.entries()),1)
    def test_reader_refresh_authenticates_only_append_tail_and_rejects_pending_or_rollback(self):
        c=self.catalog();self.admit(c)
        with c.open_reader() as reader:
            self.assertTrue(callable(getattr(reader,'refresh',None)),'Sealed append refresh missing')
            meta={**self.meta,'id':'4'*64,'tags':[x.replace(TOKEN,'5'*32) for x in self.meta['tags']]}
            c.admit('base','4'*64,meta,self.raw,self.restored)
            with mock.patch.object(c,'_scan',side_effect=AssertionError('Repeated historic scan')):
                fresh=reader.refresh()
                self.assertEqual(set(reader.entries()),{SID})
                self.assertEqual(set(fresh.entries()),{SID,'4'*64})
                self.assertEqual(fresh.refresh().head,fresh.head)
            runtime.atomic_json(c.pending,{'partial':True})
            with self.assertRaises(guards.GuardError):reader.refresh()
            c.pending.unlink()
            head=runtime.load_json(c.head);runtime.atomic_json(c.head,{**head,'sequence':1})
            with self.assertRaises(guards.GuardError):reader.refresh()
    def test_all_file_bytes_raw_manifest_and_metadata_drift_fail_admission(self):
        for change in ('bytes','raw','tree','source','generation','app','time','path','extra','duplicate_file'):
            with self.subTest(change=change):
                raw=self.raw;meta=copy.deepcopy(self.meta);manifest=copy.deepcopy(self.manifest)
                if change=='bytes':(self.restored/'db.sql').write_bytes(b'changed')
                if change=='raw':raw+=b' '
                if change=='tree':meta['tree']='short'
                if change=='source':manifest['source']={**self.source,'root':'/srv/production'}
                if change=='generation':manifest['generation']='0'*32
                if change=='app':manifest['stage_app_sha']='0'*40
                if change=='time':meta['time']='2026-10-12T10:59:00Z'
                if change=='path':meta['paths']=['/srv/production']
                if change=='extra':(self.restored/'extra').write_bytes(b'x')
                if change=='duplicate_file':manifest['files']*=2
                if manifest!=self.manifest:
                    raw=json.dumps(manifest).encode();(self.restored/'manifest.json').write_bytes(raw)
                    meta['tags'][-1]='manifest-sha:'+hashlib.sha256(raw).hexdigest()
                with self.assertRaises(guards.GuardError):self.catalog().admit('base',SID,meta,raw,self.restored)
                (self.restored/'db.sql').write_bytes(b'synthetic database bytes');(self.restored/'manifest.json').write_bytes(self.raw)
                if (self.restored/'extra').exists():(self.restored/'extra').unlink()
    def test_no_user_flags_replace_verified_root(self):
        with self.assertRaises((TypeError,guards.GuardError)):self.catalog().admit('base',SID,self.meta,self.raw,True)
    def test_duplicate_token_and_changed_snapshot_identity_fail(self):
        c=self.catalog();self.admit(c)
        with self.assertRaises(guards.GuardError):c.admit('base','4'*64,{**self.meta,'id':'4'*64},self.raw,self.restored)
        with self.assertRaises(guards.GuardError):c.admit('base',SID,{**self.meta,'tree':'4'*64},self.raw,self.restored)
    def test_edited_projection_raw_and_chain_cannot_be_authorized_by_local_digest_edits(self):
        c=self.catalog();self.admit(c);original=c.database.read_bytes()
        for sql in ("UPDATE archives SET record=replace(record, 'full', 'hourly')", "UPDATE archives SET body=x'00'", "UPDATE archives SET chain='"+'9'*64+"'", "DELETE FROM archives"):
            with self.subTest(sql=sql):
                c.database.write_bytes(original)
                with contextlib.closing(sqlite3.connect(c.database)) as db:
                    with db:db.execute(sql)
                with self.assertRaises(guards.GuardError):c.entries()
        c.database.write_bytes(original)
    def test_missing_database_head_or_raw_body_fail_without_rebuild(self):
        c=self.catalog();self.admit(c)
        for target in (c.database,c.head):
            original=target.read_bytes();target.unlink()
            with self.subTest(target=target.name),self.assertRaises(guards.GuardError):self.catalog().entries()
            target.write_bytes(original);os.chmod(target,0o600)
    def test_database_rollback_is_detected_by_independent_committed_head(self):
        c=self.catalog();initial=c.database.read_bytes();self.admit(c);c.database.write_bytes(initial)
        with self.assertRaises(guards.GuardError):c.entries()
    def test_recomputed_record_and_blob_digests_do_not_replace_committed_anchor(self):
        import zlib
        c=self.catalog();self.admit(c)
        with contextlib.closing(sqlite3.connect(c.database)) as db:
            row=db.execute('SELECT record FROM archives').fetchone()[0];record=json.loads(row)
            changed_raw=self.raw+b' ';changed_body=zlib.compress(changed_raw)
            record['manifest_sha256']=hashlib.sha256(changed_raw).hexdigest();record['raw_compressed_sha256']=hashlib.sha256(changed_body).hexdigest()
            forged_record=json.dumps(record,sort_keys=True,separators=(',',':')).encode();forged_chain=hashlib.sha256(bytes(32)+forged_record).hexdigest()
            with db:db.execute('UPDATE archives SET record=?,body=?,chain=?',(forged_record,changed_body,forged_chain))
        with self.assertRaises(guards.GuardError):c.entries()
    def test_missing_interior_record_and_reordered_chain_are_detected(self):
        c=self.catalog();self.admit(c)
        meta={**self.meta,'id':'4'*64,'tags':[x.replace(TOKEN,'5'*32) for x in self.meta['tags']]};c.admit('base','4'*64,meta,self.raw,self.restored)
        original=c.database.read_bytes()
        for sql in ('DELETE FROM archives WHERE sequence=1','UPDATE archives SET sequence=sequence+10'):
            c.database.write_bytes(original)
            with contextlib.closing(sqlite3.connect(c.database)) as db:
                with db:db.execute(sql)
            with self.subTest(sql=sql),self.assertRaises(guards.GuardError):c.entries()
    def test_interrupted_commit_blocks_until_explicit_identical_native_readback_reconciliation(self):
        c=self.catalog();writer=runtime.atomic_json
        def fail_head(path,value):
            if pathlib.Path(path)==c.head and value['sequence']>0:raise OSError('synthetic interruption after DB commit')
            return writer(path,value)
        with mock.patch('backup_catalog.runtime.atomic_json',side_effect=fail_head),self.assertRaises(OSError):self.admit(c)
        with self.assertRaises(guards.GuardError):c.entries()
        with self.assertRaises(guards.GuardError):self.admit(c)
        self.admit(c,reconcile=True);self.assertEqual(len(c.entries()),1)
    def test_changed_proof_cannot_reconcile_interrupted_admission(self):
        c=self.catalog();writer=runtime.atomic_json
        with mock.patch('backup_catalog.runtime.atomic_json',side_effect=lambda p,v: (_ for _ in ()).throw(OSError('crash')) if pathlib.Path(p)==c.head and v['sequence'] else writer(p,v)),self.assertRaises(OSError):self.admit(c)
        with self.assertRaises(guards.GuardError):c.admit('base',SID,{**self.meta,'tree':'9'*64},self.raw,self.restored,reconcile=True)
    def test_uncommitted_pending_cannot_forge_historical_verifier_source(self):
        c=self.catalog()
        with mock.patch.object(c,'_insert',side_effect=OSError('synthetic crash before DB commit')),self.assertRaises(OSError):self.admit(c)
        pending=runtime.load_json(c.pending);pending['record']['verified']['code_sha']='9'*40
        pending['record']['verified']['source_sha256']['worker.py']='9'*64;runtime.atomic_json(c.pending,pending)
        with self.assertRaises(guards.GuardError):self.admit(c,reconcile=True)
    def test_reader_refuses_store_exceeding_bounded_disk_footprint(self):
        c=self.catalog();self.admit(c)
        with mock.patch('backup_catalog.MAX_STORE_BYTES',1),self.assertRaises(guards.GuardError):c.entries()
    def test_hardlinked_store_and_payload_fail(self):
        c=self.catalog();self.admit(c);alias=self.root/'alias';os.link(c.database,alias)
        with self.assertRaises(guards.GuardError):c.entries()
        alias.unlink();os.link(self.restored/'db.sql',alias)
        with self.assertRaises(guards.GuardError):self.admit(c)
    @unittest.skipUnless(os.name=='posix','POSIX ownership and permission proof is run separately on Linux')
    def test_wrong_modes_and_symlink_ancestors_fail(self):
        c=self.catalog();self.admit(c);os.chmod(c.database,0o644)
        with self.assertRaises(guards.GuardError):c.entries()
        os.chmod(c.database,0o600);os.chmod(c.root,0o755)
        with self.assertRaises(guards.GuardError):self.catalog()
        os.chmod(c.root,0o700);link=self.root/'link';link.symlink_to(self.root/'receipts',target_is_directory=True)
        bad=SimpleNamespace(**vars(self.w));bad.root=link/'..'
        with self.assertRaises(guards.GuardError):subject().ArchiveCatalog(bad)
    def test_duplicate_json_nonfinite_and_decompression_limit_fail(self):
        c=self.catalog()
        for raw in (b'{"format":1,"format":1}',b'{"format":NaN}'):
            with self.assertRaises(guards.GuardError):subject().decode(raw)
        import zlib
        with self.assertRaises(guards.GuardError):subject().inflate(zlib.compress(b'x'*100),10)
    def test_capacity_guard_never_evicts_prior_records(self):
        c=self.catalog();self.admit(c);before=c.head.read_bytes()
        meta={**self.meta,'id':'4'*64,'tags':[x.replace(TOKEN,'5'*32) for x in self.meta['tags']]}
        with mock.patch('backup_catalog.MAX_STORE_BYTES',1),self.assertRaises(guards.GuardError):c.admit('base','4'*64,meta,self.raw,self.restored)
        self.assertEqual(c.head.read_bytes(),before);self.assertEqual(len(c.entries()),1)

    def binlog_fixture(self):
        sys.path.insert(0,str(pathlib.Path(__file__).parent))
        from backup_binlog_test import build
        raw,_=build();name='suhoput2-binlog.000001'
        (self.restored/'db.sql').unlink();(self.restored/'logs').mkdir(mode=0o700)
        (self.restored/'logs'/name).write_bytes(raw);os.chmod(self.restored/'logs'/name,0o600)
        descriptor={'file':name,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
        self.manifest={k:v for k,v in self.manifest.items() if k not in ('coordinates','full_id','stage_app_sha','application_sha256','configuration_sha256')}
        self.manifest.update(kind='binlog',logs=[descriptor],previous_count=0,first_log=1,last_log=1,active_file='suhoput2-binlog.000002',
            files=[{'path':'logs/'+name,'bytes':len(raw),'sha256':descriptor['sha256']}])
        self.refresh();self.meta['paths']=[str(self.root/'spool'/'binlog-payload')];return name,raw
    def test_actual_binlog_cache_is_hash_sealed_and_crc_row_validated(self):
        name,raw=self.binlog_fixture();c=self.catalog();c.admit('binlog',SID,self.meta,self.raw,self.restored)
        self.assertEqual(c.binlog_bytes(SID,name),raw)
        with contextlib.closing(sqlite3.connect(c.database)) as db:
            with db:db.execute("UPDATE logs SET body=x'00'")
        with self.assertRaises(guards.GuardError):c.binlog_bytes(SID,name)
        with self.assertRaises(guards.GuardError):c.entries()
    def test_corrupt_crc_cannot_be_admitted_with_rehashed_descriptor_and_manifest(self):
        name,raw=self.binlog_fixture();bad=bytearray(raw);bad[-6]^=1;bad=bytes(bad)
        (self.restored/'logs'/name).write_bytes(bad);digest=hashlib.sha256(bad).hexdigest()
        self.manifest['logs'][0]['sha256']=digest;self.manifest['files'][0]['sha256']=digest;self.refresh()
        self.meta['paths']=[str(self.root/'spool'/'binlog-payload')]
        with self.assertRaises(guards.GuardError):self.catalog().admit('binlog',SID,self.meta,self.raw,self.restored)
    def test_actual_sqlite_multirow_growth_refuses_before_commit_and_keeps_prior_store_readable(self):
        import zlib
        name,raw=self.binlog_fixture();c=self.catalog()
        for number in range(2,501):
            filename='suhoput2-binlog.'+str(number).zfill(6);path=self.restored/'logs'/filename;path.write_bytes(raw);os.chmod(path,0o600)
            self.manifest['logs'].append({'file':filename,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
            self.manifest['files'].append({'path':'logs/'+filename,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
        self.manifest['last_log']=500;self.manifest['active_file']='suhoput2-binlog.000501';self.refresh();self.meta['paths']=[str(self.root/'spool'/'binlog-payload')]
        record,body,logs=c._proof('binlog',SID,self.meta,self.raw,self.restored)
        estimate=len(body)+len(subject().canonical(record))+sum(len(value) for value in logs.values())+65536
        oldhead=c.head.read_bytes();oldsize=c.database.stat().st_size
        with mock.patch('backup_catalog.MAX_STORE_BYTES',oldsize+estimate+1),self.assertRaises(guards.GuardError):
            c.admit('binlog',SID,self.meta,self.raw,self.restored)
        self.assertEqual(c.head.read_bytes(),oldhead);self.assertEqual(c.entries(),{})
        self.assertFalse(c.pending.exists());self.assertEqual(c.database.stat().st_size,oldsize)
        c.admit('binlog',SID,self.meta,self.raw,self.restored);self.assertEqual(c.binlog_bytes(SID,name),raw)
    def test_measured_allocation_abort_preserves_preexisting_sealed_raw_bytes(self):
        c=self.catalog();self.admit(c);head=c.head.read_bytes()
        meta={**self.meta,'id':'4'*64,'tags':[x.replace(TOKEN,'5'*32) for x in self.meta['tags']]}
        with mock.patch.object(c,'_allocation_check',side_effect=subject().CatalogCapacityError('synthetic actual allocation refusal')),self.assertRaises(guards.GuardError):
            c.admit('base','4'*64,meta,self.raw,self.restored)
        self.assertEqual(c.head.read_bytes(),head);self.assertEqual(c.raw_manifest(SID),self.raw)
        self.assertEqual(set(c.entries()),{SID});self.assertFalse(c.pending.exists())
    def test_frozen_sealed_reader_amortizes_scan_and_allows_actual_new_append(self):
        name,raw=self.binlog_fixture();c=self.catalog();c.admit('binlog',SID,self.meta,self.raw,self.restored)
        with c.open_reader() as reader:
            with mock.patch.object(c,'_scan',side_effect=AssertionError('Rescanned old state per log')):
                self.assertEqual(reader.binlog_bytes(SID,name),raw)
                meta={**self.meta,'id':'4'*64,'tags':[x.replace(TOKEN,'5'*32) for x in self.meta['tags']]}
                c.admit('binlog','4'*64,meta,self.raw,self.restored)
                self.assertEqual(reader.binlog_bytes(SID,name),raw)
                self.assertEqual(set(reader.entries()),{SID})
                with self.assertRaises(guards.GuardError):reader.binlog_bytes('4'*64,name)
        self.assertEqual(len(c.entries()),2)
        with self.assertRaises(guards.GuardError):reader.entries()

    def test_frozen_reader_waits_for_actual_concurrent_admission_without_repeating_read(self):
        for operation in ('binlog','raw','refresh'):
            if operation!='binlog':self.setUp()
            name,raw=self.binlog_fixture();c=self.catalog();c.admit('binlog',SID,self.meta,self.raw,self.restored)
            meta={**self.meta,'id':'4'*64,'tags':[x.replace(TOKEN,'5'*32) for x in self.meta['tags']]}
            holding=threading.Event();release=threading.Event();done=threading.Event();errors=[];values=[];insert=c._insert
            def paused(*args,**kwargs):
                result=insert(*args,**kwargs);holding.set();self.assertTrue(release.wait(5));return result
            def write():
                try:c.admit('binlog','4'*64,meta,self.raw,self.restored)
                except BaseException as error:errors.append(error)
            with c.open_reader() as reader,mock.patch.object(c,'_insert',side_effect=paused):
                def read():
                    try:values.append(reader.binlog_bytes(SID,name) if operation=='binlog' else reader.raw_manifest(SID) if operation=='raw' else reader.refresh())
                    except BaseException as error:errors.append(error)
                    finally:done.set()
                writer=threading.Thread(target=write);reader_thread=threading.Thread(target=read);writer.start()
                try:
                    self.assertTrue(holding.wait(3));reader_thread.start()
                    with self.subTest(operation=operation):self.assertFalse(done.wait(.05),'Reader failed instead of waiting for ordinary append')
                finally:release.set();writer.join(5);reader_thread.join(5)
                self.assertEqual(errors,[]);self.assertFalse(writer.is_alive());self.assertFalse(reader_thread.is_alive())
                self.assertEqual(values[0],raw if operation=='binlog' else self.raw if operation=='raw' else values[0])
                if operation=='refresh':self.assertEqual(set(values[0].entries()),{SID,'4'*64})

    def test_frozen_reader_lock_wait_obeys_earlier_caller_deadline(self):
        import retention_cohort
        name,raw=self.binlog_fixture();c=self.catalog();c.admit('binlog',SID,self.meta,self.raw,self.restored)
        with c.open_reader() as reader:
            elapsed=[0.0]
            @contextlib.contextmanager
            def busy(path):raise runtime.LaneBusyError('Backup lane busy');yield
            def sleep(delay):elapsed[0]+=delay
            with mock.patch.object(runtime,'lane_lock',busy),mock.patch('time.monotonic',side_effect=lambda:elapsed[0]),mock.patch('time.sleep',side_effect=sleep),self.assertRaisesRegex(guards.GuardError,'read lock wait deadline'):
                reader.refresh(deadline=.1)
            self.assertLessEqual(elapsed[0],.1);self.assertEqual(retention_cohort.MAX_CRITICAL_SECONDS,55)

    def test_frozen_reader_never_retries_a_body_failure_even_if_it_is_busy_typed(self):
        name,raw=self.binlog_fixture();c=self.catalog();c.admit('binlog',SID,self.meta,self.raw,self.restored)
        with c.open_reader() as reader:
            with mock.patch.object(c,'_db',side_effect=runtime.LaneBusyError('body sentinel')) as read,mock.patch('time.sleep',side_effect=AssertionError('Retried body')),self.assertRaisesRegex(guards.GuardError,'body sentinel'):reader.binlog_bytes(SID,name)
            self.assertEqual(read.call_count,1)

    def test_lock_open_permission_and_noncontention_os_errors_are_not_retryable_busy(self):
        import errno
        c=self.catalog();denied=PermissionError(errno.EACCES,'file open denied')
        with mock.patch('runtime.os.open',side_effect=denied),self.assertRaises(PermissionError) as opened:
            with runtime.lane_lock(c.lock):self.fail('Open failure acquired a lock')
        self.assertIs(opened.exception,denied)
        failed=OSError(errno.EIO,'lock syscall I/O failure')
        target='msvcrt.locking' if os.name=='nt' else 'fcntl.flock'
        with mock.patch(target,side_effect=failed),self.assertRaises(OSError) as acquired:
            with runtime.lane_lock(c.lock):self.fail('I/O failure acquired a lock')
        self.assertIs(acquired.exception,failed)

    def test_admission_waits_for_reader_then_inserts_once_without_historic_rescan(self):
        c=self.catalog();holding=threading.Event();release=threading.Event();done=threading.Event();errors=[]
        def reader():
            with runtime.lane_lock(c.lock):holding.set();self.assertTrue(release.wait(5))
        def writer():
            try:self.admit(c)
            except BaseException as error:errors.append(error)
            finally:done.set()
        with mock.patch.object(c,'_insert',wraps=c._insert) as insert,mock.patch.object(c,'_scan',side_effect=AssertionError('Admission rescanned history')):
            read=threading.Thread(target=reader);write=threading.Thread(target=writer);read.start()
            try:
                self.assertTrue(holding.wait(3));write.start();self.assertFalse(done.wait(.05),'Writer rejected an ordinary reader')
            finally:release.set();read.join(5);write.join(5)
            self.assertEqual(errors,[]);self.assertEqual(insert.call_count,1);self.assertEqual(c._head()['sequence'],1)

    def test_admission_wait_is_five_seconds_or_remaining_job_budget(self):
        c=self.catalog()
        @contextlib.contextmanager
        def busy(path):raise runtime.LaneBusyError('held');yield
        for deadline,expected in ((None,5),(.1,.1)):
            elapsed=[0.0]
            def sleep(delay):elapsed[0]+=delay
            with self.subTest(deadline=deadline),mock.patch.object(runtime,'lane_lock',busy),mock.patch('time.monotonic',side_effect=lambda:elapsed[0]),mock.patch('time.sleep',side_effect=sleep),mock.patch.object(c,'_insert',side_effect=AssertionError('Expired wait inserted')),self.assertRaisesRegex(guards.GuardError,'admission lock wait deadline'):
                self.admit(c,deadline=deadline)
            self.assertAlmostEqual(elapsed[0],expected)

    def test_admission_never_retries_failure_after_acquisition(self):
        c=self.catalog()
        with mock.patch.object(c,'_insert',side_effect=runtime.LaneBusyError('body sentinel')) as insert,mock.patch('time.sleep',side_effect=AssertionError('Retried admission body')),self.assertRaisesRegex(guards.GuardError,'body sentinel'):self.admit(c)
        self.assertEqual(insert.call_count,1)
    def test_sealed_reader_detects_cache_mutation_after_capture(self):
        name,raw=self.binlog_fixture();c=self.catalog();c.admit('binlog',SID,self.meta,self.raw,self.restored)
        with c.open_reader() as reader:
            with contextlib.closing(sqlite3.connect(c.database)) as db:
                with db:db.execute("UPDATE logs SET body=x'00'")
            with self.assertRaises(guards.GuardError):reader.binlog_bytes(SID,name)
    def test_per_upload_admission_does_not_expand_or_scan_all_old_archives(self):
        c=self.catalog();self.admit(c)
        meta={**self.meta,'id':'4'*64,'tags':[x.replace(TOKEN,'5'*32) for x in self.meta['tags']]}
        with mock.patch.object(c,'_scan',side_effect=AssertionError('Admission scanned archive history')):
            c.admit('base','4'*64,meta,self.raw,self.restored)
        self.assertEqual(len(c.entries()),2)
    def test_missing_binlog_body_and_pending_unknown_publication_block_every_reader(self):
        name,raw=self.binlog_fixture();c=self.catalog();c.admit('binlog',SID,self.meta,self.raw,self.restored)
        with contextlib.closing(sqlite3.connect(c.database)) as db:
            with db:db.execute('DELETE FROM logs')
        with self.assertRaises(guards.GuardError):c.entries()
        runtime.atomic_json(c.pending,{'untrusted_flag':True})
        with self.assertRaises(guards.GuardError):c.entries()
        with self.assertRaises(guards.GuardError):
            with c.open_reader():self.fail('Opened incomplete catalog')

class WorkerAdmissionTests(unittest.TestCase):
    setUp=CatalogTests.setUp
    refresh=CatalogTests.refresh
    binlog_fixture=CatalogTests.binlog_fixture
    # Use real Worker method with synthetic native I/O only; store/readback is real.
    def worker_readback(self):
        import worker
        name,raw=self.binlog_fixture();w=worker.Worker.__new__(worker.Worker)
        w.root=self.root;w.c=self.w.c;w.source=self.source;w.bin=self.root;commands=[]
        self.drift=None;self.corrupt=False;self.foreign_repo=False
        self.restored_change=None
        def restic(lane,args,**kwargs):
            command=args[2:];commands.append(command)
            if command==['cat','config']:return json.dumps({'version':2,'id':('9' if self.foreign_repo else '8')*64}).encode()
            if command==['cat','snapshot',SID]:
                header=dict(self.meta)
                if self.drift:header['tree']='9'*64
                return json.dumps(header).encode()
            if command[0]=='restore':
                self.assertIn('--verify',command)
                target=pathlib.Path(command[command.index('--target')+1]);scope=pathlib.Path(self.meta['paths'][0]);destination=target/scope.relative_to(scope.anchor)
                shutil.copytree(self.restored,destination)
                if self.corrupt:(destination/'logs'/name).write_bytes(b'changed after native command')
                if self.restored_change:self.restored_change(target,destination,name)
                return b'synthetic native restore output'
            raise AssertionError('Unexpected native command')
        w.restic=restic;w.native=SimpleNamespace(run=lambda args,**kwargs:b'synthetic native checksum output')
        return w,name,raw,commands
    def test_worker_admits_actual_restore_before_cleanup(self):
        w,name,raw,commands=self.worker_readback()
        self.assertTrue(w.verify_archive('binlog',SID,self.manifest,native_metadata=self.meta,raw_manifest=self.raw))
        c=subject().ArchiveCatalog(w);self.assertEqual(c.binlog_bytes(SID,name),raw)
        self.assertFalse(list((self.root/'cache').glob('verify-*')))
        self.assertFalse(any(cmd[0]=='ls' for cmd in commands))
        self.assertIn(['cat','snapshot',SID],commands)

    def test_minute_admission_receives_original_job_deadline_after_prior_work(self):
        w,_,_,_=self.worker_readback();elapsed=[10.0]
        def job():
            elapsed[0]=64.0
            return w.verify_archive('binlog',SID,self.manifest,native_metadata=self.meta,raw_manifest=self.raw)
        with mock.patch('time.monotonic',side_effect=lambda:elapsed[0]),mock.patch.object(w,'_binlog',side_effect=job),mock.patch.object(subject().ArchiveCatalog,'admit') as admission:
            self.assertTrue(w.binlog())
        self.assertEqual(admission.call_count,1);self.assertEqual(admission.call_args.kwargs['deadline'],65.0)
        self.assertFalse(hasattr(w,'_binlog_job_deadline'))

    def test_worker_readback_waits_at_catalog_construction_then_admits_once(self):
        w,_,_,_=self.worker_readback();c=subject().ArchiveCatalog(w)
        holding=threading.Event();release=threading.Event();done=threading.Event();errors=[]
        def hold():
            with runtime.lane_lock(c.lock):holding.set();self.assertTrue(release.wait(5))
        def write():
            try:w.verify_archive('binlog',SID,self.manifest,native_metadata=self.meta,raw_manifest=self.raw)
            except BaseException as error:errors.append(error)
            finally:done.set()
        read=threading.Thread(target=hold);writer=threading.Thread(target=write);read.start()
        try:
            self.assertTrue(holding.wait(3));writer.start();self.assertFalse(done.wait(.1),'Worker constructor rejected ordinary reader')
        finally:release.set();read.join(5);writer.join(5)
        self.assertEqual(errors,[]);self.assertEqual(c._head()['sequence'],1)

    def test_cold_upload_proof_time_does_not_consume_the_acquisition_only_limit(self):
        w,_,_,_=self.worker_readback();elapsed=[0.0];proof=subject().ArchiveCatalog._proof
        def slow(catalog,*args,**kwargs):
            result=proof(catalog,*args,**kwargs);elapsed[0]+=6;return result
        with mock.patch('time.monotonic',side_effect=lambda:elapsed[0]),mock.patch.object(subject().ArchiveCatalog,'_proof',slow):
            self.assertTrue(w.verify_archive('binlog',SID,self.manifest,native_metadata=self.meta,raw_manifest=self.raw))
        self.assertEqual(subject().ArchiveCatalog(w)._head()['sequence'],1)
    def test_worker_drift_and_missing_actual_bytes_never_publish(self):
        w,_,_,commands=self.worker_readback();self.drift=True
        with self.assertRaises(guards.GuardError):w.verify_archive('binlog',SID,self.manifest,native_metadata=self.meta,raw_manifest=self.raw)
        self.assertFalse(any(cmd[0]=='restore' for cmd in commands))
        self.drift=False;self.corrupt=True
        with self.assertRaises(guards.GuardError):w.verify_archive('binlog',SID,self.manifest,native_metadata=self.meta,raw_manifest=self.raw)
        self.assertEqual(subject().ArchiveCatalog(w).entries(),{})
    def test_replaced_native_repository_cannot_be_admitted_using_old_protected_init(self):
        w,_,_,commands=self.worker_readback();self.foreign_repo=True
        with self.assertRaises(guards.GuardError):w.verify_archive('binlog',SID,self.manifest,native_metadata=self.meta,raw_manifest=self.raw)
        self.assertFalse(any(cmd[0]=='restore' for cmd in commands))

    def test_complete_restore_tree_rejects_missing_corrupt_foreign_linked_and_special_bytes(self):
        self.reject_restored_changes(('missing','extra_scoped','extra_outside','empty_outside','hardlink','raw_manifest'))

    @unittest.skipIf(os.name=='nt','Creating POSIX symlinks/FIFOs requires the mandatory Linux test environment')
    def test_restored_symlink_and_fifo_never_reach_catalog_admission(self):
        self.reject_restored_changes(('symlink','fifo'))

    def reject_restored_changes(self,kinds):
        for index,kind in enumerate(kinds):
            if index:self.setUp()
            w,_,_,commands=self.worker_readback()
            def change(target,destination,name):
                if kind=='missing':(destination/'logs'/name).unlink()
                elif kind=='extra_scoped':(destination/'extra').write_bytes(b'foreign')
                elif kind=='extra_outside':(target/'outside').write_bytes(b'foreign')
                elif kind=='empty_outside':(target/'foreign-empty').mkdir()
                elif kind=='symlink':(target/'link').symlink_to(destination/'logs'/name)
                elif kind=='fifo':os.mkfifo(destination/'fifo')
                elif kind=='hardlink':os.link(destination/'logs'/name,target/'linked')
                else:(destination/'manifest.json').write_bytes(self.raw+b' ')
            self.restored_change=change
            with self.subTest(kind=kind),self.assertRaises(guards.GuardError):w.verify_archive('binlog',SID,self.manifest,native_metadata=self.meta,raw_manifest=self.raw)
            self.assertEqual(subject().ArchiveCatalog(w).entries(),{})

class CatalogLifecycleTests(unittest.TestCase):
    def test_daily_proven_retirements_use_one_bounded_atomic_checkpoint(self):
        self.prepare();retired=[format(number,'064x') for number in range(100,357)]
        for number,sid in enumerate(retired):self.put(sid,format(number+1000,'032x'))
        survivor='f'*64;self.put(survivor,'e'*32);self.prove_absence(retired)
        result=self.c.checkpoint();self.assertEqual(result['retired_ids'],retired)
        self.assertEqual(set(self.c.entries()),{survivor});self.assertEqual(result['head']['checkpoint']['epoch'],1)

    def test_fixed_prefix_survives_four_admissions_during_one_long_reseal(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        insert=self.c._checkpoint_insert;native=self.w.restic;publish=self.c._publish_checkpoint_stage
        reseals=[];publishing=[False];elapsed=[0.0]
        def reseal(*args,**kwargs):
            result=insert(*args,**kwargs);reseals.append(True)
            for number in range(10,14):
                elapsed[0]+=65;self.put(format(number,'064x'),format(number+20,'032x'))
                self.assertFalse(self.c.checkpoint_pending.exists())
            return result
        def read(lane,args,**kwargs):
            self.assertTrue(publishing[0],'Preparation must not mislabel a changing remote observation as its fixed prefix')
            return native(lane,args,**kwargs)
        def publication(*args,**kwargs):
            publishing[0]=True
            try:return publish(*args,**kwargs)
            finally:publishing[0]=False
        self.w.restic=read
        with mock.patch.object(self.c,'_checkpoint_insert',side_effect=reseal),mock.patch.object(self.c,'_publish_checkpoint_stage',side_effect=publication),mock.patch('time.monotonic',side_effect=lambda:elapsed[0]):
            result=self.c.checkpoint()
        self.assertEqual(len(reseals),1);self.assertEqual(result['retired_ids'],[SID])
        self.assertEqual(set(self.c.entries()),{'4'*64,*[format(n,'064x') for n in range(10,14)]})
        with self.c._db() as db:witness=self.c._checkpoint_record(db,self.c._head())
        self.assertEqual(witness['format'],2);self.assertEqual(witness['prior_head']['sequence'],2)
        self.assertEqual(witness['survivor_count'],1);self.assertNotIn('native_inventory_sha256',witness)
        self.assertLessEqual(result['phase_seconds']['critical_max_seconds'],55)

    def test_tail_adoption_never_repeats_full_semantic_baseline_audits(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        scan=subject().ArchiveCatalog._scan;audits=[]
        def scanning(catalog,*args,**kwargs):
            audits.append(str(catalog.database));self.assertLessEqual(len(audits),2,'Repeated semantic baseline audit prevents continuous-minute convergence')
            result=scan(catalog,*args,**kwargs)
            number=10+len(audits);self.put(format(number,'064x'),format(number+20,'032x'))
            return result
        with mock.patch.object(subject().ArchiveCatalog,'_scan',scanning):result=self.c.checkpoint()
        self.assertEqual(len(audits),2);self.assertEqual(result['retired_ids'],[SID])
        self.assertEqual(set(self.c.entries()),{'4'*64,format(11,'064x'),format(12,'064x')})

    def test_arrival_while_waiting_for_publication_reuses_the_verified_stage(self):
        import retention_cohort
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        section=retention_cohort.upload_section;insert=self.c._checkpoint_insert;scanning=subject().ArchiveCatalog._scan;arrivals=[];reseals=[];scans=[]
        @contextlib.contextmanager
        def admitted(worker,**kwargs):
            if not arrivals:arrivals.append(True);self.put('6'*64,'7'*32)
            with section(worker,**kwargs) as started:yield started
        def reseal(*args,**kwargs):reseals.append(True);return insert(*args,**kwargs)
        def scan(catalog,*args,**kwargs):scans.append(True);return scanning(catalog,*args,**kwargs)
        with mock.patch.object(retention_cohort,'upload_section',admitted),mock.patch.object(self.c,'_checkpoint_insert',side_effect=reseal),mock.patch.object(subject().ArchiveCatalog,'_scan',scan):result=self.c.checkpoint()
        self.assertEqual(result['retired_ids'],[SID]);self.assertEqual(len(reseals),1);self.assertEqual(len(scans),2)
        self.assertEqual(set(self.c.entries()),{'4'*64,'6'*64})

    def test_activation_checks_do_not_consume_the_four_tail_adoptions(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        reserve=self.c._reserve_checkpoint_stage;append=self.c._append_private_tail;arrivals=[];folds=[]
        def activation(*args,**kwargs):
            if len(arrivals)<4:
                number=10+len(arrivals);self.put(format(number,'064x'),format(number+20,'032x'));arrivals.append(number)
            return reserve(*args,**kwargs)
        def adopt(*args,**kwargs):folds.append(True);return append(*args,**kwargs)
        with mock.patch.object(self.c,'_reserve_checkpoint_stage',side_effect=activation),mock.patch.object(self.c,'_append_private_tail',side_effect=adopt),mock.patch.object(self.c,'_publish_checkpoint_stage',wraps=self.c._publish_checkpoint_stage) as publication:result=self.c.checkpoint()
        self.assertEqual(result['retired_ids'],[SID]);self.assertEqual(len(folds),4)
        self.assertEqual(publication.call_count,1)
        self.assertEqual(set(self.c.entries()),{'4'*64,*[format(n,'064x') for n in arrivals]})

    def test_fifth_activation_arrival_cannot_expand_four_fold_limit(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        reserve=self.c._reserve_checkpoint_stage;append=self.c._append_private_tail;arrivals=[];folds=[]
        def activation(*args,**kwargs):
            number=10+len(arrivals);self.put(format(number,'064x'),format(number+20,'032x'));arrivals.append(number)
            return reserve(*args,**kwargs)
        def adopt(*args,**kwargs):folds.append(True);return append(*args,**kwargs)
        with mock.patch.object(self.c,'_reserve_checkpoint_stage',side_effect=activation),mock.patch.object(self.c,'_append_private_tail',side_effect=adopt),self.assertRaisesRegex(guards.GuardError,'bounded private tail'):
            self.c.checkpoint()
        self.assertEqual(len(folds),4);self.assertEqual(len(arrivals),5)
        self.assertFalse(self.c._checkpoint_incomplete());self.assertIn(SID,self.c.entries())

    def test_admitted_arrival_cannot_hide_changed_raw_source_prefix(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        insert=self.c._checkpoint_insert
        def corrupted(*args,**kwargs):
            result=insert(*args,**kwargs);self.put('6'*64,'7'*32)
            with self.c._db(write=True) as db:
                with db:db.execute('UPDATE archives SET body=? WHERE sid=?',(b'changed source prefix','4'*64))
            return result
        with mock.patch.object(self.c,'_checkpoint_insert',side_effect=corrupted),self.assertRaises(guards.GuardError):self.c.checkpoint()
        self.assertFalse(self.c.checkpoint_pending.exists());self.assertEqual(self.c._head()['sequence'],3)

    def test_full_reader_audit_does_not_hold_live_catalog_lock(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32)
        scan=subject().ArchiveCatalog._scan;added=[]
        def scanning(catalog,*args,**kwargs):
            if not added:
                added.append(True);self.put('6'*64,'7'*32)
            return scan(catalog,*args,**kwargs)
        with mock.patch.object(subject().ArchiveCatalog,'_scan',scanning):
            with self.c.open_reader() as reader:
                self.assertEqual(set(reader.entries()),{SID,'4'*64})
                self.assertEqual(set(reader.refresh().entries()),{SID,'4'*64,'6'*64})
        self.assertEqual(set(self.c.entries()),{SID,'4'*64,'6'*64})

    def test_arrivals_during_private_folds_use_their_frozen_journal_boundary(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        scan=subject().ArchiveCatalog._scan;raw=subject().ArchiveCatalog._raw_prefix_seals;arrivals=[];insert=self.c._checkpoint_insert;reseals=[]
        def arrive():
            if len(arrivals)<4:
                number=10+len(arrivals);self.put(format(number,'064x'),format(number+20,'032x'));arrivals.append(number)
        def scanning(catalog,*args,**kwargs):
            result=scan(catalog,*args,**kwargs)
            arrive()
            return result
        def sealing(catalog,*args,**kwargs):
            result=raw(catalog,*args,**kwargs)
            if 'catalog-readers' in catalog.database.parts:arrive()
            return result
        def reseal(*args,**kwargs):reseals.append(True);return insert(*args,**kwargs)
        with mock.patch.object(subject().ArchiveCatalog,'_scan',scanning),mock.patch.object(subject().ArchiveCatalog,'_raw_prefix_seals',sealing),mock.patch.object(self.c,'_checkpoint_insert',side_effect=reseal):self.c.checkpoint()
        self.assertEqual(arrivals,[10,11,12,13]);self.assertEqual(len(reseals),1)
        self.assertEqual(set(self.c.entries()),{'4'*64,*[format(n,'064x') for n in arrivals]})

    def test_genuine_tail_cannot_excuse_historical_journal_mutation(self):
        for mutation in ('timestamp','old_order','retirement','tail_order','watermark'):
            if mutation!='timestamp':self.setUp()
            self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
            insert=self.c._checkpoint_insert
            def changed(*args,**kwargs):
                result=insert(*args,**kwargs);self.put('6'*64,'7'*32);self.put('8'*64,'9'*32)
                path=self.root/'receipts/base/state.json';state=runtime.load_json(path)
                if mutation=='timestamp':state['confirmed'][0]['prepared_at']='2026-10-12T11:00:01Z'
                elif mutation=='old_order':state['confirmed'][:2]=reversed(state['confirmed'][:2])
                elif mutation=='retirement':state['retention'][0]['forgotten_at']='2026-10-12T12:01:01Z'
                elif mutation=='tail_order':state['confirmed'][-2:]=reversed(state['confirmed'][-2:])
                else:state['last_success_at']='2026-10-12T11:00:01Z'
                runtime.atomic_json(path,state);return result
            with self.subTest(mutation=mutation),mock.patch.object(self.c,'_checkpoint_insert',side_effect=changed),self.assertRaises(guards.GuardError):self.c.checkpoint()
            self.assertEqual(runtime.load_json(self.c.head)['sequence'],4);self.assertFalse(self.c.checkpoint_pending.exists())

    def test_derived_checkpoint_final_native_rejects_missing_unknown_and_reappeared_snapshots(self):
        for mutation in ('missing','unknown','retired','duplicate'):
            if mutation!='missing':self.setUp()
            self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
            native=self.w.restic;head=self.c.head.read_bytes()
            def changed(lane,args,**kwargs):
                raw=native(lane,args,**kwargs)
                if lane=='base' and args[2:]==['snapshots','--json']:
                    rows=json.loads(raw)
                    if mutation=='missing':rows=[]
                    elif mutation=='retired':rows.append(self.records[SID]['native'])
                    elif mutation=='duplicate':rows.append(rows[0])
                    else:rows.append({**rows[0],'id':'e'*64})
                    return json.dumps(rows).encode()
                return raw
            self.w.restic=changed
            with self.subTest(mutation=mutation),self.assertRaises(guards.GuardError):self.c.checkpoint()
            self.assertEqual(self.c.head.read_bytes(),head);self.assertFalse(self.c.checkpoint_pending.exists())

    def test_tail_target_blob_corruption_after_fsync_cannot_be_sealed_as_valid(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        insert=self.c._checkpoint_insert;sync=subject().ArchiveCatalog._sync_db;added=[];corrupted=[]
        def reseal(*args,**kwargs):
            result=insert(*args,**kwargs)
            if not added:
                added.append(True);CatalogTests.binlog_fixture(self)
                meta={**self.meta,'id':'6'*64,'tags':[x.replace(TOKEN,'7'*32) for x in self.meta['tags']]}
                record=self.c.admit('binlog','6'*64,meta,self.raw,self.restored);self.records['6'*64]=record;self.live.add('6'*64);self.journals()
            return result
        def synced(catalog):
            sync(catalog)
            if 'catalog-preparations' in catalog.database.parts and added and not corrupted:
                with contextlib.closing(sqlite3.connect(catalog.database)) as db:
                    if db.execute('SELECT 1 FROM logs WHERE sid=?',('6'*64,)).fetchone():
                        with db:db.execute('UPDATE logs SET body=? WHERE sid=?',(b'corrupted target bytes','6'*64))
                        corrupted.append(True)
        with mock.patch.object(self.c,'_checkpoint_insert',side_effect=reseal),mock.patch.object(subject().ArchiveCatalog,'_sync_db',synced),self.assertRaises(guards.GuardError):self.c.checkpoint()
        self.assertTrue(corrupted);self.assertFalse(self.c.checkpoint_pending.exists());self.assertEqual(self.c._head()['sequence'],3)

    def test_tail_append_cannot_reseal_corrupted_historical_target_body(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        insert=self.c._checkpoint_insert;sync=subject().ArchiveCatalog._sync_db;added=[];corrupted=[]
        def reseal(*args,**kwargs):
            result=insert(*args,**kwargs)
            if not added:added.append(True);self.put('6'*64,'7'*32)
            return result
        def synced(catalog):
            sync(catalog)
            if 'catalog-preparations' in catalog.database.parts and added and not corrupted:
                with contextlib.closing(sqlite3.connect(catalog.database)) as db:
                    if db.execute('SELECT 1 FROM archives WHERE sid=?',('6'*64,)).fetchone():
                        with db:db.execute('UPDATE archives SET body=? WHERE sid=?',(b'corrupted historical target payload','4'*64))
                        corrupted.append(True)
        with mock.patch.object(self.c,'_checkpoint_insert',side_effect=reseal),mock.patch.object(subject().ArchiveCatalog,'_sync_db',synced),self.assertRaisesRegex(guards.GuardError,'Authenticated raw target prefix changed'):self.c.checkpoint()
        self.assertTrue(corrupted);self.assertFalse(self.c.checkpoint_pending.exists());self.assertEqual(self.c._head()['sequence'],3)

    def test_no_tail_checkpoint_keeps_existing_authenticated_target_seal(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        prepared=self.c._derived_prepared
        def corrupted(stage,*args,**kwargs):
            result=prepared(stage,*args,**kwargs)
            with contextlib.closing(sqlite3.connect(stage.catalog.database)) as db:
                with db:db.execute('UPDATE archives SET body=? WHERE sid=?',(b'corrupted historical target payload','4'*64))
            return result
        with mock.patch.object(self.c,'_derived_prepared',side_effect=corrupted),self.assertRaisesRegex(guards.GuardError,'Prepared target changed'):self.c.checkpoint()
        self.assertFalse(self.c.checkpoint_pending.exists());self.assertEqual(self.c._head()['sequence'],2)

    def test_pointer_only_crash_retains_recoverable_unpublished_derived_stage(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        write=runtime.atomic_json
        def crashed(path,value):
            write(path,value)
            if pathlib.Path(path)==self.root/'receipts/catalog-checkpoint-stage.json':raise OSError('Process lost after pointer')
        with mock.patch('backup_catalog.runtime.atomic_json',side_effect=crashed),mock.patch.object(subject().CheckpointStage,'cleanup',side_effect=OSError('No process cleanup')),self.assertRaises(OSError):self.c.checkpoint()
        self.assertFalse(self.c.checkpoint_pending.exists());self.assertTrue((self.root/'receipts/catalog-checkpoint-stage.json').exists())
        with self.assertRaisesRegex(guards.GuardError,'Interrupted catalog'):self.c.entries()
        self.c.checkpoint(reconcile=True);self.assertEqual(set(self.c.entries()),{'4'*64})

    def test_referenced_unpublished_stage_is_not_removed_during_exception_cleanup(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        write=runtime.atomic_json
        def crashed(path,value):
            write(path,value)
            if pathlib.Path(path)==self.root/'receipts/catalog-checkpoint-stage.json':raise OSError('Process lost after pointer')
        def destructive_cleanup(stage):
            stage.manifest.unlink();raise OSError('Process lost during premature cleanup')
        with mock.patch.object(runtime,'atomic_json',side_effect=crashed),mock.patch.object(subject().CheckpointStage,'cleanup',destructive_cleanup),self.assertRaises(OSError):self.c.checkpoint()
        pointer=runtime.load_json(self.root/'receipts/catalog-checkpoint-stage.json')
        self.assertTrue((self.root/'receipts/catalog-preparations'/pointer['token']/'preparation.json').exists())
        self.c.checkpoint(reconcile=True);self.assertTrue(self.c.ready());self.assertEqual(set(self.c.entries()),{'4'*64})

    def test_completed_cleanup_crash_recovers_after_owned_stage_was_removed(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        cleanup=subject().CheckpointStage.cleanup
        def crashed(stage):
            cleanup(stage)
            if 'catalog-preparations' in stage.root.parts:raise OSError('Process lost after completed stage removal')
        with mock.patch.object(subject().CheckpointStage,'cleanup',crashed),self.assertRaises(OSError):self.c.checkpoint()
        self.assertFalse(self.c.checkpoint_pending.exists());self.assertTrue((self.root/'receipts/catalog-checkpoint-stage.json').exists())
        self.assertEqual(list((self.root/'receipts/catalog-preparations').iterdir()),[])
        with self.assertRaisesRegex(guards.GuardError,'Interrupted catalog'):self.c.ready()
        self.c.checkpoint(reconcile=True);self.assertTrue(self.c.ready());self.assertEqual(set(self.c.entries()),{'4'*64})

    def test_completed_cleanup_resumes_partial_paths_but_rejects_changed_authority(self):
        for change in ('partial_manifest','partial_directory','wrong_pointer','live_body','unknown_residue'):
            if change!='partial_manifest':self.setUp()
            self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
            cleanup=subject().CheckpointStage.cleanup
            def crashed(stage):
                if 'catalog-preparations' not in stage.root.parts:return cleanup(stage)
                stage.manifest.unlink()
                if change=='partial_directory':stage.catalog.root.rmdir()
                if change=='unknown_residue':
                    path=stage.root/'unknown.json';path.write_bytes(b'unknown');path.chmod(0o600)
                raise OSError('Process lost during owned cleanup')
            with mock.patch.object(subject().CheckpointStage,'cleanup',crashed),self.assertRaises(OSError):self.c.checkpoint()
            pointer=self.root/'receipts/catalog-checkpoint-stage.json'
            if change=='wrong_pointer':
                value=runtime.load_json(pointer);value['pending_sha256']='0'*64;runtime.atomic_json(pointer,value)
            if change=='live_body':
                with contextlib.closing(sqlite3.connect(self.c.database)) as db:
                    with db:db.execute('UPDATE archives SET body=? WHERE sid=?',(b'corrupted committed body','4'*64))
            if change.startswith('partial_'):
                self.c.checkpoint(reconcile=True);self.assertTrue(self.c.ready());self.assertFalse(pointer.exists())
            else:
                with self.subTest(change=change),self.assertRaises(guards.GuardError):self.c.checkpoint(reconcile=True)
                self.assertTrue(pointer.exists())

    def test_pointer_without_pending_blocks_upload_until_readonly_reconciliation(self):
        for point in ('pointer','cleared'):
            if point!='pointer':self.setUp()
            self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
            write=runtime.atomic_json;sync=runtime.directory_sync
            def crash_write(path,value):
                write(path,value)
                if point=='pointer' and pathlib.Path(path)==self.root/'receipts/catalog-checkpoint-stage.json':raise OSError('Process lost after pointer')
            def crash_sync(path):
                sync(path)
                if point=='cleared' and pathlib.Path(path)==self.c.root and not self.c.checkpoint_pending.exists() and self.c._head().get('checkpoint'):
                    raise OSError('Process lost after pending removal')
            with self.subTest(point=point),mock.patch('backup_catalog.runtime.atomic_json',side_effect=crash_write),mock.patch('backup_catalog.runtime.directory_sync',side_effect=crash_sync),mock.patch.object(subject().CheckpointStage,'cleanup',side_effect=OSError('No process cleanup')),self.assertRaises(OSError):self.c.checkpoint()
            self.assertFalse(self.c.checkpoint_pending.exists());self.assertTrue((self.root/'receipts/catalog-checkpoint-stage.json').exists())
            head=self.c.head.read_bytes();journal=(self.root/'receipts/base/state.json').read_bytes()
            with self.assertRaisesRegex(guards.GuardError,'Interrupted catalog'):self.c.ready()
            with self.assertRaisesRegex(guards.GuardError,'Interrupted catalog'):self.put('6'*64,'7'*32)
            self.assertEqual(self.c.head.read_bytes(),head);self.assertEqual((self.root/'receipts/base/state.json').read_bytes(),journal)
            self.c.checkpoint(reconcile=True)
            self.assertFalse((self.root/'receipts/catalog-checkpoint-stage.json').exists())
            self.assertTrue(self.c.ready());self.put('6'*64,'7'*32);self.assertEqual(set(self.c.entries()),{'4'*64,'6'*64})

    def test_tail_checkpoint_crash_reconciles_exact_source_tip_and_target_tip(self):
        for point in ('pending','replace','head'):
            if point!='pending':self.setUp()
            self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
            insert=self.c._checkpoint_insert;write=runtime.atomic_json;replace=os.replace;added=[]
            def reseal(*args,**kwargs):
                value=insert(*args,**kwargs)
                if not added:added.append(True);self.put('6'*64,'7'*32)
                return value
            def crash_write(path,value):
                write(path,value)
                if (point=='pending' and pathlib.Path(path)==self.c.checkpoint_pending or point=='head' and pathlib.Path(path)==self.c.head and value.get('checkpoint')):raise OSError('Durable tail checkpoint crash')
            def crash_replace(path,target):
                replace(path,target)
                if point=='replace' and pathlib.Path(target)==self.c.database:raise OSError('Durable tail image crash')
            with self.subTest(point=point),mock.patch.object(self.c,'_checkpoint_insert',side_effect=reseal),mock.patch('backup_catalog.runtime.atomic_json',side_effect=crash_write),mock.patch('backup_catalog.os.replace',side_effect=crash_replace),self.assertRaises(OSError):self.c.checkpoint()
            self.assertTrue(self.c.checkpoint_pending.exists())
            self.c.checkpoint(reconcile=True)
            self.assertFalse(self.c.checkpoint_pending.exists());self.assertEqual(set(self.c.entries()),{'4'*64,'6'*64})

    def test_source_copy_permits_writer_across_active_steps_or_chunks_without_join_pause(self):
        self.manifest['padding']=os.urandom(400000).hex();self.refresh()
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32)
        for number in range(12,22):self.put(format(number,'064x'),format(number+10,'032x'))
        self.prove_absence(SID);self.manifest.pop('padding');self.refresh()
        with contextlib.closing(sqlite3.connect(self.c.database)) as db:self.assertGreater(db.execute('PRAGMA page_count').fetchone()[0],128)
        connect=sqlite3.connect;openfd=os.open;fdopen=os.fdopen;source_fds=set();written=[];failures=[];active=[];started=[];copying=[False];writes_during_copy=[]
        def write():
            for number in range(24,29):
                try:
                    self.put(format(number,'064x'),format(number+10,'032x'));written.append(number)
                    if copying[0]:writes_during_copy.append(number)
                except Exception as error:failures.append(error)
        thread=threading.Thread(target=write)
        def continue_copy():
            if not started:started.append(True);thread.start()
            else:active.append(True)
        class OnlineCopy:
            def __init__(proxy,db):proxy.db=db
            def __getattr__(proxy,name):return getattr(proxy.db,name)
            def backup(proxy,target,**kwargs):
                callback=kwargs['progress']
                def progress(*args):
                    callback(*args)
                    if args[1]>0:continue_copy()
                copying[0]=True;result=proxy.db.backup(target,**{**kwargs,'progress':progress});copying[0]=False
                if started:thread.join(10)
                return result
        class RawCopy:
            def __init__(proxy,file):proxy.file=file
            def __getattr__(proxy,name):return getattr(proxy.file,name)
            def __enter__(proxy):proxy.file.__enter__();copying[0]=True;return proxy
            def __exit__(proxy,*args):
                result=proxy.file.__exit__(*args);copying[0]=False
                if started:thread.join(10)
                return result
            def read(proxy,size):
                value=proxy.file.read(size)
                if value:continue_copy()
                return value
        def connection(path,*args,**kwargs):
            db=connect(path,*args,**kwargs)
            return OnlineCopy(db) if str(path)==self.c.database.as_uri()+'?mode=ro' else db
        def open_file(path,*args,**kwargs):
            fd=openfd(path,*args,**kwargs)
            if pathlib.Path(path)==self.c.database:source_fds.add(fd)
            return fd
        def stream(fd,mode,*args,**kwargs):
            file=fdopen(fd,mode,*args,**kwargs)
            return RawCopy(file) if fd in source_fds and mode=='rb' else file
        result=None;failure=None
        with mock.patch('backup_catalog.sqlite3.connect',side_effect=connection),mock.patch('backup_catalog.os.open',side_effect=open_file),mock.patch('backup_catalog.os.fdopen',side_effect=stream):
            try:result=self.c.checkpoint()
            except guards.GuardError as error:failure=error
        self.assertFalse(thread.is_alive());self.assertTrue(active,'Actor must overlap continuing copy; callbacks cannot join/pause it')
        self.assertEqual(failures,[]);self.assertEqual(written,list(range(24,29)));self.assertFalse(self.c.pending.exists())
        self.assertTrue(writes_during_copy,'At least one genuine admission must complete while copying remains active')
        self.assertIsNone(failure);self.assertEqual(result['retired_ids'],[SID]);self.assertTrue({format(n,'064x') for n in written}<=set(self.c.entries()))
        self.assertGreaterEqual(result['phase_seconds']['copy_attempts'],2,'Changed initial bytes require a fresh exact image')
    def test_initial_raw_copy_mixed_bytes_identity_pending_or_sidecar_drift_cannot_publish(self):
        for change in ('stage','stage_with_arrival','source','path','path_with_arrival','journal','legacy_pending'):
            if change!='stage':self.setUp()
            self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
            if change=='legacy_pending':self.legacy_pending()
            head=[self.c.head.read_bytes()];database=[self.c.database.read_bytes()];raw_copy=self.c._raw_checkpoint_copy;calls=[]
            def mutate(stage,*args,**kwargs):
                value=raw_copy(stage,*args,**kwargs);calls.append(True)
                if change in ('stage','stage_with_arrival'):
                    stage.catalog.database.write_bytes(stage.catalog.database.read_bytes()+b'mixed')
                    if change=='stage_with_arrival':self.put('6'*64,'7'*32);head[0]=self.c.head.read_bytes();database[0]=self.c.database.read_bytes()
                elif change=='source':
                    with contextlib.closing(sqlite3.connect(self.c.database)) as db:
                        with db:db.execute('PRAGMA user_version=48')
                elif change in ('path','path_with_arrival'):
                    replacement=self.c.root/'replacement.sqlite';replacement.write_bytes(self.c.database.read_bytes());os.chmod(replacement,0o600);os.replace(replacement,self.c.database)
                    if change=='path_with_arrival':self.put('6'*64,'7'*32);head[0]=self.c.head.read_bytes();database[0]=self.c.database.read_bytes()
                elif change=='journal':
                    journal=pathlib.Path(str(self.c.database)+'-journal');journal.write_bytes(b'unknown active transaction');os.chmod(journal,0o600)
                else:self.c.checkpoint_pending.write_bytes(self.c.checkpoint_pending.read_bytes()+b' ')
                return value
            with self.subTest(change=change):
                with mock.patch.object(self.c,'_raw_checkpoint_copy',side_effect=mutate),self.assertRaises(guards.GuardError):self.c.checkpoint(reconcile=change=='legacy_pending')
                self.assertEqual(len(calls),1);self.assertEqual(self.c.head.read_bytes(),head[0])
                self.assertEqual(self.c.checkpoint_pending.exists(),change=='legacy_pending')
                if change!='source':self.assertEqual(self.c.database.read_bytes(),database[0])
    def test_copy_components_charge_failed_authenticated_attempt_outside_lock_deadline(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        raw_copy=self.c._raw_checkpoint_copy;elapsed=[0.0];changed=[]
        def drift(*args,**kwargs):
            value=raw_copy(*args,**kwargs)
            if not changed:self.put('6'*64,'7'*32);changed.append(True);elapsed[0]+=65
            return value
        with mock.patch.object(self.c,'_raw_checkpoint_copy',side_effect=drift),mock.patch('time.monotonic',side_effect=lambda:elapsed[0]):result=self.c.checkpoint()
        self.assertEqual(result['phase_seconds']['copy_attempts'],2);self.assertGreaterEqual(result['phase_seconds']['copy_seconds'],65)
        self.assertLessEqual(result['phase_seconds']['critical_max_seconds'],55);self.assertEqual(set(self.c.entries()),{'4'*64,'6'*64})
    def test_copy_fsync_corruption_before_source_drift_observation_blocks_without_recapture(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        openfd=os.open;fsync=os.fsync;targets={};corrupted=[];head=[];database=[];raw_copy=self.c._raw_checkpoint_copy;attempts=[]
        def opened(path,*args,**kwargs):
            fd=openfd(path,*args,**kwargs)
            if 'catalog-preparations' in pathlib.Path(path).parts and pathlib.Path(path).name=='index.sqlite3':targets[fd]=pathlib.Path(path)
            return fd
        def synced(fd):
            fsync(fd)
            if fd in targets and not corrupted:
                with targets[fd].open('ab') as file:file.write(b'independent target corruption')
                corrupted.append(True);self.put('6'*64,'7'*32);head.append(self.c.head.read_bytes());database.append(self.c.database.read_bytes())
        def copy(*args,**kwargs):attempts.append(True);return raw_copy(*args,**kwargs)
        with mock.patch.object(self.c,'_raw_checkpoint_copy',side_effect=copy),mock.patch('backup_catalog.os.open',side_effect=opened),mock.patch('backup_catalog.os.fsync',side_effect=synced),self.assertRaises(guards.GuardError):self.c.checkpoint()
        self.assertEqual(len(attempts),1);self.assertTrue(corrupted);self.assertEqual(self.c.head.read_bytes(),head[0]);self.assertEqual(self.c.database.read_bytes(),database[0]);self.assertFalse(self.c.checkpoint_pending.exists())
    def test_slow_preparation_catches_multiple_arrivals_without_resealing_fixed_prefix(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        elapsed=[0.0];original=self.c._checkpoint_insert;calls=[];copy=self.c._copy_checkpoint_image
        def reseal(*args,**kwargs):
            original(*args,**kwargs);elapsed[0]+=65;calls.append('reseal')
            self.assertFalse(self.c.checkpoint_pending.exists())
            self.put('6'*64,'7'*32);self.put('7'*64,'8'*32)
        with mock.patch.object(self.c,'_checkpoint_insert',side_effect=reseal),mock.patch.object(self.c,'_copy_checkpoint_image',wraps=copy) as copies,mock.patch('time.monotonic',side_effect=lambda:elapsed[0]):result=self.c.checkpoint()
        self.assertEqual(copies.call_count,2);self.assertEqual(len(calls),1);self.assertEqual(set(self.c.entries()),{'4'*64,'6'*64,'7'*64})
        self.assertEqual(result['retired_ids'],[SID]);self.assertLessEqual(result['phase_seconds']['critical_max_seconds'],55)
    def test_arrival_during_derived_preparation_is_authenticated_by_bounded_catchup(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        derive=self.c._derived_checkpoint_evidence;added=[]
        def derived(*args,**kwargs):
            result=derive(*args,**kwargs)
            if not added:self.put('6'*64,'7'*32);added.append(True)
            return result
        with mock.patch.object(self.c,'_derived_checkpoint_evidence',side_effect=derived):result=self.c.checkpoint()
        self.assertEqual(result['retired_ids'],[SID]);self.assertEqual(set(self.c.entries()),{'4'*64,'6'*64})
    def test_binlog_tail_copy_uses_bounded_chunks_and_allows_writer_between_them(self):
        from backup_binlog_test import build,query,table_map,rows
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        insert=self.c._checkpoint_insert;db_method=subject().ArchiveCatalog._db;added=[];chunks=[];interleaved=[]
        def binlog_arrival(*args,**kwargs):
            insert(*args,**kwargs)
            if added:return
            added.append(True);CatalogTests.binlog_fixture(self)
            raw,_=build([(2,query()),(19,table_map()),(23,rows()+os.urandom(2200000)),(16,(1).to_bytes(8,'little'))])
            name=self.manifest['logs'][0]['file'];(self.restored/'logs'/name).write_bytes(raw)
            descriptor={'file':name,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
            self.manifest['logs']=[descriptor];self.manifest['files']=[{'path':'logs/'+name,'bytes':len(raw),'sha256':descriptor['sha256']}];self.refresh()
            self.meta['paths']=[str(self.root/'spool/binlog-payload')]
            meta={**self.meta,'id':'6'*64,'tags':[x.replace(TOKEN,'7'*32) for x in self.meta['tags']]}
            record=self.c.admit('binlog','6'*64,meta,self.raw,self.restored);self.records['6'*64]=record;self.live.add('6'*64);self.journals()
        class Source:
            def __init__(proxy,db):proxy.db=db
            def __getattr__(proxy,name):return getattr(proxy.db,name)
            def execute(proxy,sql,parameters=()):
                self.assertNotIn('SELECT name,body FROM logs',sql)
                if 'SELECT substr(body' in sql:
                    chunks.append(parameters[1])
                    if not interleaved:
                        # A real live SQLite write while the private source
                        # cursor is open proves no live read transaction/flock.
                        with contextlib.closing(sqlite3.connect(self.c.database,timeout=0)) as live:
                            live.execute('BEGIN IMMEDIATE');live.rollback()
                        interleaved.append(True)
                return proxy.db.execute(sql,parameters)
        @contextlib.contextmanager
        def source(catalog,*args,**kwargs):
            with db_method(catalog,*args,**kwargs) as db:yield Source(db) if 'catalog-readers' in catalog.database.parts else db
        with mock.patch.object(self.c,'_checkpoint_insert',side_effect=binlog_arrival),mock.patch.object(subject().ArchiveCatalog,'_db',source):result=self.c.checkpoint()
        self.assertTrue(interleaved);self.assertGreaterEqual(len(chunks),3);self.assertLessEqual(max(chunks),1024*1024)
        self.assertEqual(result['retired_ids'],[SID]);self.assertEqual(set(self.c.entries()),{'4'*64,'6'*64})
    def test_preparation_releases_full_decoded_maps_before_final_authority(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        class Tracked(dict):pass
        refs=[];scan=subject().ArchiveCatalog._scan;final=self.c._final_checkpoint_native
        def tracked(catalog,*args,**kwargs):
            result=Tracked(scan(catalog,*args,**kwargs));refs.append(weakref.ref(result));return result
        def authority(*args,**kwargs):
            self.assertTrue(refs);self.assertTrue(all(ref() is None for ref in refs),'Completed preparation retained a full decoded map')
            return final(*args,**kwargs)
        with mock.patch.object(subject().ArchiveCatalog,'_scan',tracked),mock.patch.object(self.c,'_final_checkpoint_native',side_effect=authority):self.c.checkpoint()
    def test_each_private_scan_starts_after_prior_full_map_is_released_without_gc(self):
        for arrival in (False,True):
            if arrival:self.setUp()
            self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
            class Tracked(dict):pass
            refs=[];scan=subject().ArchiveCatalog._scan;added=[]
            def tracked(catalog,*args,**kwargs):
                expected=kwargs.get('expected_records')
                self.assertTrue(all(ref() is None or ref() is expected for ref in refs),'An unrelated complete map survived into the next full scan')
                result=Tracked(scan(catalog,*args,**kwargs));refs.append(weakref.ref(result))
                if expected is not None:self.assertTrue(all(value is expected[sid] for sid,value in result.items()),'Target audit duplicated source record objects')
                if arrival and not added:self.put('6'*64,'7'*32);added.append(True)
                return result
            with self.subTest(arrival_during_private_audit=arrival),mock.patch.object(subject().ArchiveCatalog,'_scan',tracked):
                self.c.checkpoint();self.assertGreaterEqual(len(refs),2);self.assertTrue(all(ref() is None for ref in refs))
    def test_prepared_raw_images_and_complete_authority_set_tampering_block_before_pending(self):
        for change in ('source','stage','manifest','intent','receipt','latest','marker','phase','init','added'):
            if change!='source':self.setUp()
            self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);directory=self.prove_absence(SID)
            head=self.c.head.read_bytes();publish=self.c._publish_checkpoint_stage
            def tamper(stage,prepared,profile):
                if change in ('source','stage'):
                    target=self.c.database if change=='source' else stage.catalog.database
                    with contextlib.closing(sqlite3.connect(target)) as db:
                        with db:db.execute('PRAGMA user_version=47')
                else:
                    target={'manifest':stage.manifest,'intent':directory/'intent.json','receipt':directory/('receipt-'+SID[:32]+'.json'),
                            'latest':directory/'latest.json','marker':directory/'journals-committed.json','phase':directory/'phase-base.json',
                            'init':self.root/'receipts/init-base.json','added':directory/('receipt-'+'e'*32+'.json')}[change]
                    if target.exists():target.write_bytes(target.read_bytes()+b' ')
                    else:runtime.atomic_json(target,{'changed':True})
                return publish(stage,prepared,profile)
            with self.subTest(change=change),mock.patch.object(self.c,'_publish_checkpoint_stage',side_effect=tamper),self.assertRaises(guards.GuardError):self.c.checkpoint()
            self.assertEqual(self.c.head.read_bytes(),head);self.assertFalse(self.c.checkpoint_pending.exists())
    def test_prepared_image_loss_blocks_and_does_not_remove_exact_legacy_pending(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID);marker=self.legacy_pending();head=self.c.head.read_bytes();publish=self.c._publish_checkpoint_stage
        def lost(stage,prepared,profile):stage.catalog.database.unlink();return publish(stage,prepared,profile)
        with mock.patch.object(self.c,'_publish_checkpoint_stage',side_effect=lost),self.assertRaises(guards.GuardError):self.c.checkpoint(reconcile=True)
        self.assertEqual(self.c.checkpoint_pending.read_bytes(),marker);self.assertEqual(self.c.head.read_bytes(),head)
        self.c.checkpoint(reconcile=True);self.assertEqual(set(self.c.entries()),{'4'*64})
    def test_referenced_stage_loss_or_corruption_blocks_without_resetting_pending(self):
        for corrupt in (False,True):
            if corrupt:self.setUp()
            self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
            replace=os.replace
            def stop(path,target):
                if pathlib.Path(target)==self.c.database:raise OSError('Before image activation')
                return replace(path,target)
            with mock.patch('backup_catalog.os.replace',side_effect=stop),self.assertRaises(OSError):self.c.checkpoint()
            marker=self.c.checkpoint_pending.read_bytes();head=self.c.head.read_bytes();pointer=runtime.load_json(self.root/'receipts/catalog-checkpoint-stage.json')
            image=self.root/'receipts/catalog-preparations'/pointer['token']/'catalog/index.sqlite3'
            if corrupt:image.write_bytes(b'corrupted private image')
            else:image.unlink()
            with self.subTest(corrupt=corrupt),self.assertRaises(guards.GuardError):self.c.checkpoint(reconcile=True)
            self.assertEqual(self.c.checkpoint_pending.read_bytes(),marker);self.assertEqual(self.c.head.read_bytes(),head)
    def test_unknown_preparation_content_blocks_without_live_changes(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID);head=self.c.head.read_bytes()
        parent=self.root/'receipts/catalog-preparations';parent.mkdir(mode=0o700);(parent/'foreign').mkdir(mode=0o700)
        with self.assertRaises(guards.GuardError):self.c.checkpoint()
        self.assertEqual(self.c.head.read_bytes(),head);self.assertFalse(self.c.checkpoint_pending.exists())
    def test_stage_foreign_or_linked_artifacts_block_before_activation_and_preserve_evidence(self):
        for change in ('foreign','hardlink','root_foreign','late_native'):
            if change!='foreign':self.setUp()
            self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
            head=self.c.head.read_bytes();database=self.c.database.read_bytes();publish=self.c._publish_checkpoint_stage;native=self.c._final_checkpoint_native;observed=[]
            def add(stage):
                unknown=stage.root/('foreign.json' if change=='root_foreign' else 'catalog/foreign.sqlite')
                if change=='hardlink':os.link(stage.catalog.database,unknown)
                else:unknown.write_bytes(b'unknown protected artifact');os.chmod(unknown,0o600)
                observed.append((stage,stage.manifest.read_bytes(),unknown))
            def publication(stage,prepared,profile):
                if change!='late_native':add(stage)
                return publish(stage,prepared,profile)
            def late(prepared,deadline):
                native(prepared,deadline)
                stage_root=next((self.root/'receipts/catalog-preparations').iterdir());add(subject().CheckpointStage(self.c,stage_root.name))
            with self.subTest(change=change):
                with mock.patch.object(self.c,'_publish_checkpoint_stage',side_effect=publication),mock.patch.object(self.c,'_final_checkpoint_native',side_effect=late if change=='late_native' else native),self.assertRaises(guards.GuardError):self.c.checkpoint()
                self.assertEqual(self.c.head.read_bytes(),head);self.assertEqual(self.c.database.read_bytes(),database)
                self.assertFalse(self.c.checkpoint_pending.exists());self.assertFalse((self.root/'receipts/catalog-checkpoint-stage.json').exists())
                stage,descriptor,unknown=observed[0];self.assertTrue(unknown.exists());self.assertEqual(stage.manifest.read_bytes(),descriptor)
                self.assertTrue(stage.catalog.head.exists());self.assertTrue(stage.catalog.database.exists())
    def test_preparation_reserves_both_images_and_rollback_before_copy(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID);head=self.c.head.read_bytes();copied=[];connect=sqlite3.connect
        def connection(path,*args,**kwargs):
            if 'catalog-preparations' in str(path):copied.append(str(path))
            return connect(path,*args,**kwargs)
        with mock.patch('backup_catalog.sqlite3.connect',side_effect=connection),mock.patch('backup_catalog.shutil.disk_usage',return_value=SimpleNamespace(free=5*1024**3+self.c.database.stat().st_size)),self.assertRaises(guards.GuardError):self.c.checkpoint()
        self.assertEqual(copied,[],'Capacity must refuse before allocating a private image')
        self.assertEqual(self.c.head.read_bytes(),head);self.assertFalse(self.c.checkpoint_pending.exists());self.assertEqual(list((self.root/'receipts/catalog-preparations').iterdir()),[])
    def test_accepted_append_does_not_hide_historic_blob_tampering(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID);head=self.c.head.read_bytes();original=self.c._checkpoint_insert;once=[]
        def tamper(*args,**kwargs):
            original(*args,**kwargs)
            if not once:
                self.put('6'*64,'7'*32);once.append(True)
                with contextlib.closing(sqlite3.connect(self.c.database)) as db:
                    with db:db.execute("UPDATE archives SET body=x'00' WHERE sid=?",('4'*64,))
        with mock.patch.object(self.c,'_checkpoint_insert',side_effect=tamper),self.assertRaises(guards.GuardError):self.c.checkpoint()
        self.assertFalse(self.c.checkpoint_pending.exists());self.assertEqual(runtime.load_json(self.c.head)['sequence'],3)
    def test_accepted_append_rejects_historic_sequence_chain_and_foreign_membership(self):
        for change in ('sequence','chain','extra_archive','extra_log'):
            if change!='sequence':self.setUp()
            self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.put('6'*64,'7'*32);self.prove_absence(SID)
            reseal=self.c._checkpoint_insert;changed=[]
            def tamper(*args,**kwargs):
                reseal(*args,**kwargs)
                if changed:return
                changed.append(True)
                with contextlib.closing(sqlite3.connect(self.c.database)) as db:
                    with db:
                        if change=='sequence':db.execute('UPDATE archives SET sequence=-sequence WHERE sid=?',('4'*64,))
                        elif change=='chain':db.execute('UPDATE archives SET chain=? WHERE sid=?',('0'*64,'4'*64))
                        elif change=='extra_archive':db.execute('INSERT INTO archives SELECT -1,?, ?, record,body,chain FROM archives WHERE sid=?',('e'*64,'f'*32,'4'*64))
                        else:db.execute('INSERT INTO logs VALUES (?,?,?)',('e'*64,'suhoput2-binlog.000001',b'foreign'))
                self.put('8'*64,'9'*32)
            with self.subTest(change=change):
                with mock.patch.object(self.c,'_checkpoint_insert',side_effect=tamper),self.assertRaises(guards.GuardError):self.c.checkpoint()
                self.assertTrue(changed);self.assertFalse(self.c.checkpoint_pending.exists());self.assertEqual(runtime.load_json(self.c.head)['sequence'],4)
    def test_stage_crashes_preserve_prior_next_dispositions_and_readonly_reconcile(self):
        for point in ('pending','pointer','replace','head','clear'):
            if point!='pending':self.setUp()
            self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
            write=runtime.atomic_json;replace=os.replace;sync=runtime.directory_sync;triggered=[]
            def crash_write(path,value):
                write(path,value)
                if (point=='pending' and pathlib.Path(path)==self.c.checkpoint_pending or point=='pointer' and pathlib.Path(path)==self.root/'receipts/catalog-checkpoint-stage.json' or point=='head' and pathlib.Path(path)==self.c.head):
                    triggered.append(True);raise OSError('Durable boundary crash')
            def crash_replace(path,target):
                replace(path,target)
                if point=='replace' and pathlib.Path(target)==self.c.database:triggered.append(True);raise OSError('Activated image crash')
            def crash_sync(path):
                sync(path)
                if point=='clear' and pathlib.Path(path)==self.c.root and not self.c.checkpoint_pending.exists() and runtime.load_json(self.c.head).get('checkpoint'):
                    triggered.append(True);raise OSError('Postclear durability crash')
            with self.subTest(point=point),mock.patch('backup_catalog.runtime.atomic_json',side_effect=crash_write),mock.patch('backup_catalog.os.replace',side_effect=crash_replace),mock.patch('backup_catalog.runtime.directory_sync',side_effect=crash_sync),self.assertRaises(OSError):self.c.checkpoint()
            self.assertTrue(triggered)
            if self.c.checkpoint_pending.exists():
                raw=self.c.checkpoint_pending.read_bytes()
                with self.assertRaises(guards.GuardError):self.c.entries()
                self.c.checkpoint(reconcile=True);self.assertFalse(self.c.checkpoint_pending.exists())
            elif (self.root/'receipts/catalog-checkpoint-stage.json').exists():
                # Both pre-pending and post-clear exceptions retain the
                # authenticated bridge until explicit read-only recovery.
                with self.assertRaises(guards.GuardError):self.c.ready()
                self.c.checkpoint(reconcile=True)
            self.assertEqual(set(self.c.entries()),{'4'*64})
            self.assertEqual(list((self.root/'receipts/catalog-preparations').iterdir()),[])
    def test_inode_close_is_outside_locks_only_on_posix_and_replace_cost_is_charged(self):
        import retention_cohort
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        opened=[];closed=[];openfd=os.open;closefd=os.close;replace=os.replace;elapsed=[0.0];publishing=[False];publish=self.c._publish_checkpoint_stage
        def publication(*args,**kwargs):
            publishing[0]=True
            try:return publish(*args,**kwargs)
            finally:publishing[0]=False
        def open_file(path,*args,**kwargs):
            fd=openfd(path,*args,**kwargs)
            if pathlib.Path(path)==self.c.database and publishing[0]:opened.append(fd)
            return fd
        def close_file(fd):
            if fd in opened:
                with retention_cohort.upload_section(self.w):closed.append('all-four-free')
            return closefd(fd)
        def slow(path,target):
            replace(path,target)
            if pathlib.Path(target)==self.c.database:elapsed[0]+=60
        with mock.patch.object(self.c,'_publish_checkpoint_stage',side_effect=publication),mock.patch('backup_catalog.os.open',side_effect=open_file),mock.patch('backup_catalog.os.close',side_effect=close_file),mock.patch('backup_catalog.os.replace',side_effect=slow),mock.patch('time.monotonic',side_effect=lambda:elapsed[0]),self.assertRaises(guards.GuardError):self.c.checkpoint()
        self.assertEqual(len(opened),1 if os.name=='posix' else 0);self.assertEqual(closed,['all-four-free'] if os.name=='posix' else [])
        self.assertEqual(self.c.last_checkpoint_timing['critical_max_seconds'],60);self.assertEqual(self.c.last_checkpoint_timing['promotion_seconds'],60)
        self.assertTrue(self.c.checkpoint_pending.exists());self.c.checkpoint(reconcile=True);self.assertEqual(set(self.c.entries()),{'4'*64})
    def test_checkpoint_heavy_reseal_and_full_scan_run_without_job_upload_locks(self):
        import retention_cohort
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        original=self.c._checkpoint_insert;elapsed=[0.0];calls=[]
        def reseal(*args,**kwargs):
            with retention_cohort.upload_section(self.w):calls.append('all-four-free')
            result=original(*args,**kwargs);elapsed[0]+=65;return result
        with mock.patch.object(self.c,'_checkpoint_insert',reseal),mock.patch('time.monotonic',side_effect=lambda:elapsed[0]):result=self.c.checkpoint()
        self.assertEqual(calls,['all-four-free']);self.assertEqual(result['retired_ids'],[SID])
        self.assertLessEqual(result['phase_seconds']['critical_max_seconds'],55)
    def test_long_private_reseal_keeps_live_source_until_final_activation(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        head=self.c.head.read_bytes();elapsed=[0.0];original=self.c._checkpoint_insert
        def slow(*args,**kwargs):
            original(*args,**kwargs);elapsed[0]+=60
            self.assertEqual(self.c.head.read_bytes(),head);self.assertEqual(len(self.c.entries()),2)
            self.assertFalse(self.c.checkpoint_pending.exists(),'Slow prep must not quarantine minute writers')
        with mock.patch.object(self.c,'_checkpoint_insert',slow),mock.patch('time.monotonic',side_effect=lambda:elapsed[0]):result=self.c.checkpoint()
        self.assertEqual(result['retired_ids'],[SID]);self.assertLessEqual(result['phase_seconds']['critical_max_seconds'],55)
    def test_checkpoint_charges_first_acquisition_and_stops_native_work_at_forty_five_seconds(self):
        import retention_cohort
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        elapsed=[0.0];original_section=retention_cohort.upload_section;original_read=self.w.restic;timeouts=[];head=self.c.head.read_bytes()
        @contextlib.contextmanager
        def section(worker,**kwargs):
            elapsed[0]+=8
            with original_section(worker,**kwargs):yield
        def read(lane,args,**kwargs):
            result=original_read(lane,args,**kwargs)
            if 'timeout' in kwargs:timeouts.append(kwargs['timeout']);elapsed[0]+=10
            return result
        self.w.restic=read
        with mock.patch.object(retention_cohort,'upload_section',section),mock.patch('time.monotonic',side_effect=lambda:elapsed[0]),self.assertRaises(guards.GuardError):self.c.checkpoint()
        self.assertTrue(timeouts);self.assertLessEqual(timeouts[0],37)
        self.assertEqual(self.c.head.read_bytes(),head);self.assertFalse(self.c.checkpoint_pending.exists())
    def test_completed_checkpoint_with_slow_unlock_reports_failure_without_undoing_committed_head(self):
        import retention_cohort
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        elapsed=[0.0];original=retention_cohort.upload_section
        @contextlib.contextmanager
        def section(worker,**kwargs):
            with original(worker,**kwargs):
                try:yield
                finally:elapsed[0]+=60
        with mock.patch.object(retention_cohort,'upload_section',section),mock.patch('time.monotonic',side_effect=lambda:elapsed[0]),self.assertRaises(guards.GuardError):self.c.checkpoint()
        self.assertFalse(self.c.checkpoint_pending.exists())
        with self.assertRaises(guards.GuardError):self.c.ready()
        self.assertEqual(self.c.last_checkpoint_timing['critical_seconds'],60)
        self.c.checkpoint(reconcile=True);self.assertEqual(set(self.c.entries()),{'4'*64})
    def test_private_reseal_capacity_abort_preserves_live_bytes_and_legacy_pending(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.put('6'*64,'7'*32);self.prove_absence(SID)
        marker=self.legacy_pending();before=self.c.head.read_bytes();database=self.c.database.read_bytes()
        with mock.patch.object(subject().ArchiveCatalog,'_allocation_check',side_effect=subject().CatalogCapacityError('Measured private transaction refusal')),self.assertRaises(guards.GuardError):self.c.checkpoint(reconcile=True)
        self.assertEqual(self.c.head.read_bytes(),before);self.assertEqual(self.c.database.read_bytes(),database)
        self.assertEqual(self.c.checkpoint_pending.read_bytes(),marker)
        self.c.checkpoint(reconcile=True);self.assertEqual(set(self.c.entries()),{'4'*64,'6'*64})
    def test_checkpoint_head_publication_timeout_retains_new_head_and_pending_until_explicit_reconcile(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        elapsed=[0.0];writer=runtime.atomic_json
        def slow(path,value):
            writer(path,value)
            if pathlib.Path(path)==self.c.head and value.get('checkpoint'):elapsed[0]+=60
        with mock.patch('backup_catalog.runtime.atomic_json',side_effect=slow),mock.patch('time.monotonic',side_effect=lambda:elapsed[0]),self.assertRaises(guards.GuardError):self.c.checkpoint()
        self.assertTrue(self.c.checkpoint_pending.exists());pending=runtime.load_json(self.c.checkpoint_pending)
        self.assertEqual(runtime.load_json(self.c.head),pending['next_head'])
        with self.assertRaises(guards.GuardError):self.c.entries()
        self.c.checkpoint(reconcile=True);self.assertEqual(set(self.c.entries()),{'4'*64})
    def test_private_full_scan_runs_outside_upload_locks_even_when_slow(self):
        import retention_cohort
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        elapsed=[0.0];original=subject().ArchiveCatalog._scan;observed=[]
        def scan(catalog,*args,**kwargs):
            if 'catalog-preparations' in catalog.database.parts:
                with retention_cohort.upload_section(self.w):observed.append('free')
                result=original(catalog,*args,**kwargs);elapsed[0]+=60;return result
            return original(catalog,*args,**kwargs)
        with mock.patch.object(subject().ArchiveCatalog,'_scan',scan),mock.patch('time.monotonic',side_effect=lambda:elapsed[0]):result=self.c.checkpoint()
        self.assertGreaterEqual(len(observed),2);self.assertEqual(result['retired_ids'],[SID]);self.assertLessEqual(result['phase_seconds']['critical_max_seconds'],55)
    def test_committed_reconcile_full_authority_over_work_budget_preserves_both_head_states_and_pending(self):
        for published in (False,True):
            if published:self.setUp()
            self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
            marker=self.legacy_pending(committed=True,published=published);head=self.c.head.read_bytes();elapsed=[0.0];authority=self.c._final_checkpoint_native
            def slow(*args,**kwargs):
                authority(*args,**kwargs);elapsed[0]+=46
            with self.subTest(next_head_published=published),mock.patch.object(self.c,'_final_checkpoint_native',slow),mock.patch('time.monotonic',side_effect=lambda:elapsed[0]),self.assertRaises(guards.GuardError):self.c.checkpoint(reconcile=True)
            self.assertEqual(self.c.head.read_bytes(),head);self.assertEqual(self.c.checkpoint_pending.read_bytes(),marker)
            self.c.checkpoint(reconcile=True);self.assertEqual(set(self.c.entries()),{'4'*64})
    def test_checkpoint_derived_audit_releases_upload_lanes_and_final_native_is_mandatory(self):
        import retention_cohort
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        original=self.c._derived_checkpoint_evidence;final=self.c._final_checkpoint_native;calls=[]
        def audit(*args,**kwargs):
            with retention_cohort.upload_section(self.w):calls.append('unlocked-audit')
            return original(*args,**kwargs)
        def current(*args,**kwargs):calls.append('final-check');return final(*args,**kwargs)
        with mock.patch.object(self.c,'_derived_checkpoint_evidence',audit),mock.patch.object(self.c,'_final_checkpoint_native',current):self.c.checkpoint()
        self.assertEqual(calls,['unlocked-audit','final-check'])
    setUp=CatalogTests.setUp
    refresh=CatalogTests.refresh
    def prepare(self):
        import retention_native
        self.records={};self.live=set();self.retired=[];self.c=subject().ArchiveCatalog(self.w)
        if os.name!='posix':
            # Windows exercises actual protected-file contents with synthetic
            # filesystem policy; Linux test run uses the real native guards.
            self.addCleanup(mock.patch.stopall)
            mock.patch.object(retention_native,'private_path',side_effect=lambda p:subject().safe(p)).start()
            mock.patch.object(retention_native,'protected_directory',side_effect=lambda p:subject().safe(p,directory=True)).start()
        for lane in ('base','binlog'):(self.root/'receipts'/lane).mkdir(mode=0o700)
        def native(lane,args,**kwargs):
            if args[2:]==['cat','config']:return json.dumps({'version':2,'id':('7' if lane=='base' else '8')*64}).encode()
            if args[2:]==['snapshots','--json']:return json.dumps([self.records[sid]['native'] for sid in sorted(self.live) if self.records[sid]['lane']==lane]).encode()
            raise AssertionError('Checkpoint attempted non-read-only/native operation')
        self.w.restic=native
    def put(self,sid,token):
        meta={**self.meta,'id':sid,'tags':[x.replace(TOKEN,token) for x in self.meta['tags']]}
        record=self.c.admit('base',sid,meta,self.raw,self.restored);self.records[sid]=record;self.live.add(sid)
        self.journals();return record
    def journals(self):
        for lane in ('base','binlog'):
            confirmed=[{'id':r['id'],'token':r['token'],'manifest_sha256':r['manifest_sha256'],'captured_at':r['projection']['captured_at'],'prepared_at':r['projection']['captured_at'],'confirmed_at':r['native']['time']} for r in self.records.values() if r['lane']==lane]
            state={'generation':GEN,'confirmed':confirmed,'retention':[r for r in self.retired if r['lane']==lane]}
            if confirmed:state.update(last_success_at=confirmed[-1]['captured_at'],last_confirmation_at=confirmed[-1]['confirmed_at'])
            runtime.atomic_json(self.root/'receipts'/lane/'state.json',state)
    def prove_absence(self,sid):
        import retention,retention_apply
        ids=sid if isinstance(sid,list) else [sid];sid=ids[0]
        snapshots=[{'id':r['id'],'lane':r['lane'],'token':r['token'],'manifest_sha256':r['manifest_sha256'],'kind':r['projection']['kind'],
                    'generation':GEN,'time':r['projection']['captured_at'],'snapshot_time':r['native']['time'],'tree':r['native']['tree']} for key,r in self.records.items() if key in self.live]
        before={'format':'authenticated-retention-identities-v1','generation':GEN,'repositories':{'base':'7'*64,'binlog':'8'*64},'source':self.source,'snapshots':snapshots}
        keep=sorted(self.live-set(ids));intent={'operation':'native-retention-forget','generation':GEN,'repositories':before['repositories'],'repository_paths':self.w.c['repositories'],
            'source':self.source,'token':sid[:32],'inventory_sha256':retention.inventory_digest(before),'before_inventory':before,'candidate_ids':ids,
            'keep_ids':keep,'anchor_id':keep[0] if keep else sid,'proof_sha256':{},'prepared_at':'2026-10-12T12:00:00Z'}
        intent['intent_sha256']=retention_apply.document_digest(intent)
        receipt={k:copy.deepcopy(intent[k]) for k in ('operation','token','generation','repositories','source','inventory_sha256','candidate_ids','keep_ids','anchor_id','proof_sha256','intent_sha256')}
        receipt.update(result='APPLIED',observation_error=None,forgotten_ids=ids,present_candidate_ids=[],post_inventory_sha256='9'*64,completed_at='2026-10-12T12:01:00Z')
        directory=self.root/'receipts'/'retention-applies'/intent['intent_sha256'];directory.mkdir(mode=0o700,parents=True,exist_ok=True);os.chmod(directory.parent,0o700)
        runtime.atomic_json(directory/'intent.json',intent);name='receipt-'+sid[:32]+'.json';runtime.atomic_json(directory/name,receipt)
        runtime.atomic_json(directory/'latest.json',{'file':name,'sha256':hashlib.sha256((directory/name).read_bytes()).hexdigest()})
        runtime.atomic_json(directory/'journals-committed.json',{'intent_sha256':intent['intent_sha256'],'receipt_sha256':retention_apply.document_digest(receipt)})
        self.retired.extend(retention_apply.retention_tombstones(intent,receipt));self.live.difference_update(ids);self.journals();return directory
    def legacy_pending(self,*,committed=False,published=False):
        """Real old-schema local state, never a native/provider proof claim."""
        records=self.c.entries();head=self.c._head();proofs,inventory=self.c._retirement_evidence(records)
        retired=[{'sequence':sequence,'record':record,'proof':proofs[sid]} for sequence,(sid,record) in enumerate(records.items(),1) if sid in proofs]
        ids={item['record']['id'] for item in retired};survivors=[record for sid,record in records.items() if sid not in ids]
        witness={'format':1,'operation':'native-verified-catalog-checkpoint','prior_head':head,'epoch':head.get('checkpoint',{}).get('epoch',0)+1,
                 'retired':retired,'survivor_count':len(survivors),'survivors_sha256':self.c._records_digest(survivors),
                 'native_inventory_sha256':__import__('retention').inventory_digest(inventory)}
        witness['lineage_sha256']=subject().digest(bytes.fromhex(head.get('checkpoint',{}).get('lineage_sha256',subject().ZERO))+subject().canonical(witness))
        nexthead=self.c._checkpoint_head(witness,survivors);runtime.atomic_json(self.c.checkpoint_pending,{'witness':witness,'next_head':nexthead})
        if committed:
            with self.c._db(write=True) as db:self.c._checkpoint_insert(db,witness,survivors,nexthead)
        if published:runtime.atomic_json(self.c.head,nexthead)
        return self.c.checkpoint_pending.read_bytes()
    def test_repeated_rolling_windows_reclaim_only_proven_absences_and_continue_admitting(self):
        self.prepare();self.assertTrue(hasattr(self.c,'checkpoint'),'Protected rolling catalog lifecycle missing')
        with mock.patch('backup_catalog.MAX_RECORDS',2):
            self.put(SID,TOKEN);survivor='4'*64;self.put(survivor,'5'*32);original=self.c.entries()[survivor]
            for number in range(6,14):
                retiring=next(key for key in self.live if key!=survivor);self.prove_absence(retiring)
                result=self.c.checkpoint();self.assertEqual(result['retired_ids'],[retiring]);self.assertEqual(self.c.entries()[survivor],original)
                fresh=format(number,'064x');self.put(fresh,format(number+20,'032x'))
            self.assertEqual(len(self.c.entries()),2)
            self.assertGreater(runtime.load_json(self.c.head)['checkpoint']['epoch'],1)
    def test_current_unknown_unproven_or_required_ids_cannot_be_retired(self):
        self.prepare();self.assertTrue(hasattr(self.c,'checkpoint'),'Protected rolling catalog lifecycle missing')
        self.put(SID,TOKEN);self.put('4'*64,'5'*32);directory=self.prove_absence(SID)
        self.live.add(SID)
        with self.assertRaises(guards.GuardError):self.c.checkpoint()
        self.live.remove(SID);state=runtime.load_json(self.root/'receipts'/'base'/'state.json');state['retention']=[];runtime.atomic_json(self.root/'receipts'/'base'/'state.json',state)
        with self.assertRaises(guards.GuardError):self.c.checkpoint()
    def test_checkpoint_keeps_surviving_frozen_reader_and_refuses_retired_reader_access(self):
        self.prepare();self.assertTrue(hasattr(self.c,'checkpoint'),'Protected rolling catalog lifecycle missing')
        self.put(SID,TOKEN);self.put('4'*64,'5'*32)
        with self.c.open_reader() as reader:
            self.prove_absence(SID);self.c.checkpoint()
            self.assertEqual(reader.raw_manifest('4'*64),self.raw)
            with self.assertRaises(guards.GuardError):reader.raw_manifest(SID)
    def test_interrupted_checkpoint_blocks_until_own_native_provenance_reconciliation(self):
        self.prepare();self.assertTrue(hasattr(self.c,'checkpoint'),'Protected rolling catalog lifecycle missing')
        self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID);writer=runtime.atomic_json
        def crash(path,value):
            if pathlib.Path(path)==self.c.head and value.get('checkpoint'):raise OSError('synthetic crash after checkpoint DB commit')
            return writer(path,value)
        with mock.patch('backup_catalog.runtime.atomic_json',side_effect=crash),self.assertRaises(OSError):self.c.checkpoint()
        with self.assertRaises(guards.GuardError):self.c.entries()
        with self.assertRaises(guards.GuardError):self.c.checkpoint()
        self.c.checkpoint(reconcile=True);self.assertEqual(set(self.c.entries()),{'4'*64})
    def test_checkpoint_head_lineage_or_retirement_witness_tamper_fails(self):
        self.prepare();self.assertTrue(hasattr(self.c,'checkpoint'),'Protected rolling catalog lifecycle missing')
        self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID);self.c.checkpoint()
        with contextlib.closing(sqlite3.connect(self.c.database)) as db:
            with db:db.execute("UPDATE catalog_checkpoint SET record=x'7b7d'")
        with self.assertRaises(guards.GuardError):self.c.entries()
    def test_missing_journal_commit_and_pending_upload_preserve_entire_store(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);directory=self.prove_absence(SID)
        head=self.c.head.read_bytes();(directory/'journals-committed.json').unlink()
        with self.assertRaises(guards.GuardError):self.c.checkpoint()
        self.assertEqual(self.c.head.read_bytes(),head);self.assertEqual(len(self.c.entries()),2)
    def test_surviving_hourly_arrival_protects_required_full_even_if_native_absence_is_proven(self):
        self.prepare();self.put(SID,TOKEN)
        self.manifest.update(kind='hourly',full_id=SID);self.refresh();self.put('4'*64,'5'*32);self.prove_absence(SID)
        head=self.c.head.read_bytes()
        with self.assertRaises(guards.GuardError):self.c.checkpoint()
        self.assertEqual(self.c.head.read_bytes(),head);self.assertEqual(len(self.c.entries()),2)
    def test_pending_checkpoint_blocks_worker_before_new_upload_intent(self):
        import worker
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        self.legacy_pending()
        payload=self.root/'spool'/'base-payload';shutil.copytree(self.restored,payload)
        w=worker.Worker.__new__(worker.Worker);w.root=self.root;w.c=self.w.c;w.source=self.source
        w.capture_intent=lambda *args:self.fail('New upload intent started before catalog readiness')
        with mock.patch('worker.restic_adapter.ResticAdapter',return_value=SimpleNamespace()),self.assertRaises(guards.GuardError):w.upload('base',payload)
    def test_rolling_checkpoint_reuses_real_freed_pages_with_fixed_database_ceiling(self):
        import random
        self.manifest['padding']=random.Random(47).randbytes(200000).hex();self.refresh();self.prepare()
        self.put(SID,TOKEN);survivor='4'*64;self.put(survivor,'5'*32)
        for number in range(6,9):
            retiring=next(key for key in self.live if key!=survivor);self.prove_absence(retiring);self.c.checkpoint();self.put(format(number,'064x'),format(number+20,'032x'))
        ceiling=self.c.database.stat().st_size+512*1024
        with mock.patch('backup_catalog.MAX_RECORDS',2),mock.patch('backup_catalog.MAX_STORE_BYTES',ceiling):
            for number in range(9,17):
                retiring=next(key for key in self.live if key!=survivor);self.prove_absence(retiring);self.c.checkpoint()
                with contextlib.closing(sqlite3.connect(self.c.database)) as db:self.assertGreater(db.execute('PRAGMA freelist_count').fetchone()[0],0)
                self.put(format(number,'064x'),format(number+20,'032x'));self.assertLessEqual(self.c.database.stat().st_size,ceiling)
        self.assertEqual(len(self.c.entries()),2)
    def test_checkpoint_transaction_capacity_abort_retains_prior_chain_and_bodies(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID);head=self.c.head.read_bytes()
        with mock.patch.object(subject().ArchiveCatalog,'_allocation_check',side_effect=subject().CatalogCapacityError('synthetic measured checkpoint refusal')),self.assertRaises(guards.GuardError):self.c.checkpoint()
        self.assertEqual(self.c.head.read_bytes(),head);self.assertEqual(self.c.raw_manifest(SID),self.raw)
        self.assertEqual(len(self.c.entries()),2);self.assertFalse(self.c.checkpoint_pending.exists())
    def test_checkpoint_precommit_interruption_can_only_reconcile_actual_own_proof(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        self.legacy_pending()
        pending=runtime.load_json(self.c.checkpoint_pending);pending['witness']['retired'][0]['record']['verified']['code_sha']='9'*40
        runtime.atomic_json(self.c.checkpoint_pending,pending)
        with self.assertRaises(guards.GuardError):self.c.checkpoint(reconcile=True)
    def test_foreign_repository_retirement_provenance_cannot_reclaim_current_catalog(self):
        import retention,retention_apply
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);directory=self.prove_absence(SID)
        intent=runtime.load_json(directory/'intent.json');intent['repositories']={'base':'e'*64,'binlog':'f'*64}
        intent['before_inventory']['repositories']=intent['repositories'];intent['inventory_sha256']=retention.inventory_digest(intent['before_inventory'])
        intent.pop('intent_sha256');intent['intent_sha256']=retention_apply.document_digest(intent)
        pointer=runtime.load_json(directory/'latest.json');receipt=runtime.load_json(directory/pointer['file'])
        for key in ('repositories','inventory_sha256','intent_sha256'):receipt[key]=intent[key]
        runtime.atomic_json(directory/'intent.json',intent);runtime.atomic_json(directory/pointer['file'],receipt)
        runtime.atomic_json(directory/'latest.json',{'file':pointer['file'],'sha256':hashlib.sha256((directory/pointer['file']).read_bytes()).hexdigest()})
        runtime.atomic_json(directory/'journals-committed.json',{'intent_sha256':intent['intent_sha256'],'receipt_sha256':retention_apply.document_digest(receipt)})
        self.retired=retention_apply.retention_tombstones(intent,receipt);self.journals()
        with self.assertRaises(guards.GuardError):self.c.checkpoint()
    def test_pretransaction_checkpoint_marker_blocks_every_fresh_read_and_capture(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        self.legacy_pending()
        for operation in (self.c.entries,self.c.ready,lambda:self.c.raw_manifest('4'*64)):
            with self.assertRaises(guards.GuardError):operation()
        with self.assertRaises(guards.GuardError):
            with self.c.open_reader():self.fail('Partial checkpoint opened a fresh reader')
        self.c.checkpoint(reconcile=True);self.assertEqual(set(self.c.entries()),{'4'*64})
    def test_checkpoint_witness_over_record_limit_uses_its_own_bounded_publication_limit(self):
        import random
        self.manifest['padding']=random.Random(48).randbytes(160000).hex();self.refresh();self.prepare()
        survivor='4'*64;self.put(survivor,'5'*32)
        retired=[]
        for number in range(10,18):
            sid=format(number,'064x');self.put(sid,format(number+40,'032x'));retired.append(sid)
        for sid in retired:self.prove_absence(sid)
        result=self.c.checkpoint();self.assertEqual(result['retired_ids'],sorted(retired))
        with contextlib.closing(sqlite3.connect(self.c.database)) as db:
            self.assertGreater(db.execute('SELECT length(record) FROM catalog_checkpoint').fetchone()[0],subject().MAX_RECORD_BYTES)
        self.assertEqual(set(self.c.entries()),{survivor});self.assertEqual(self.c.raw_manifest(survivor),self.raw)

if __name__=='__main__':unittest.main()
