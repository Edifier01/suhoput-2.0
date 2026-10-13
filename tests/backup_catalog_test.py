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
        def restic(lane,args,**kwargs):
            command=args[2:];commands.append(command)
            if command==['cat','config']:return json.dumps({'version':2,'id':('9' if self.foreign_repo else '8')*64}).encode()
            if command[0]=='ls':
                header={**self.meta,'message_type':'snapshot'}
                if self.drift:header['tree']='9'*64
                rows=[header,*[{'message_type':'node','type':'file','path':self.meta['paths'][0]+'/'+item['path'],'size':item['bytes']} for item in self.manifest['files']],
                      {'message_type':'node','type':'file','path':self.meta['paths'][0]+'/manifest.json','size':len(self.raw)}]
                return b'\n'.join(json.dumps(row).encode() for row in rows)
            if command[0]=='restore':
                self.assertIn('--verify',command)
                target=pathlib.Path(command[command.index('--target')+1]);scope=pathlib.Path(self.meta['paths'][0]);destination=target/scope.relative_to(scope.anchor)
                shutil.copytree(self.restored,destination)
                if self.corrupt:(destination/'logs'/name).write_bytes(b'changed after native command')
                return b'synthetic native restore output'
            raise AssertionError('Unexpected native command')
        w.restic=restic;w.native=SimpleNamespace(run=lambda args,**kwargs:b'synthetic native checksum output')
        return w,name,raw,commands
    def test_worker_admits_actual_restore_before_cleanup(self):
        w,name,raw,commands=self.worker_readback()
        self.assertTrue(w.verify_archive('binlog',SID,self.manifest,native_metadata=self.meta,raw_manifest=self.raw))
        c=subject().ArchiveCatalog(w);self.assertEqual(c.binlog_bytes(SID,name),raw)
        self.assertFalse(list((self.root/'cache').glob('verify-*')))
        self.assertTrue(any(cmd[:3]==['ls','--json','--recursive'] for cmd in commands))
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

class CatalogLifecycleTests(unittest.TestCase):
    def test_page_backup_permits_real_concurrent_catalog_writer_and_retains_arrival(self):
        self.manifest['padding']=os.urandom(400000).hex();self.refresh()
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        with contextlib.closing(sqlite3.connect(self.c.database)) as db:self.assertGreater(db.execute('PRAGMA page_count').fetchone()[0],128)
        connect=sqlite3.connect;written=[];failures=[];remaining_at_write=[]
        class OnlineCopy:
            def __init__(proxy,db):proxy.db=db
            def __getattr__(proxy,name):return getattr(proxy.db,name)
            def backup(proxy,target,**kwargs):
                callback=kwargs['progress']
                def progress(*args):
                    callback(*args)
                    if written:return
                    remaining_at_write.append(args[1]);self.assertGreater(args[1],0,'Writer must interleave before online copy completes')
                    written.append('attempted')
                    def write():
                        try:self.put('6'*64,'7'*32)
                        except Exception as error:failures.append(error)
                    thread=threading.Thread(target=write);thread.start();thread.join(5)
                    self.assertFalse(thread.is_alive(),'Backup step retained a source SQLite/catalog lock')
                return proxy.db.backup(target,**{**kwargs,'progress':progress})
        def connection(path,*args,**kwargs):
            db=connect(path,*args,**kwargs)
            return OnlineCopy(db) if str(path)==self.c.database.as_uri()+'?mode=ro' else db
        with mock.patch('backup_catalog.sqlite3.connect',side_effect=connection):result=self.c.checkpoint()
        self.assertEqual(failures,[]);self.assertEqual(result['retired_ids'],[SID]);self.assertEqual(set(self.c.entries()),{'4'*64,'6'*64})
        self.assertTrue(remaining_at_write)
    def test_slow_preparation_catches_multiple_minute_arrivals_without_recopy_or_pending(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        elapsed=[0.0];original=self.c._checkpoint_insert;calls=[];copy=self.c._copy_checkpoint_image
        def reseal(*args,**kwargs):
            original(*args,**kwargs);elapsed[0]+=65;calls.append('reseal')
            self.assertFalse(self.c.checkpoint_pending.exists())
            if len(calls)<=2:self.put(format(5+len(calls),'064x'),format(6+len(calls),'032x'))
        with mock.patch.object(self.c,'_checkpoint_insert',side_effect=reseal),mock.patch.object(self.c,'_copy_checkpoint_image',wraps=copy) as copies,mock.patch('time.monotonic',side_effect=lambda:elapsed[0]):result=self.c.checkpoint()
        self.assertEqual(copies.call_count,1);self.assertEqual(len(calls),3);self.assertEqual(set(self.c.entries()),{'4'*64,format(6,'064x'),format(7,'064x')})
        self.assertEqual(result['retired_ids'],[SID]);self.assertLessEqual(result['phase_seconds']['critical_max_seconds'],55)
    def test_arrival_during_native_preparation_is_authenticated_by_bounded_catchup(self):
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        read=self.w.restic;added=[]
        def native(lane,args,**kwargs):
            if not added and args[2:]==['snapshots','--json']:
                self.put('6'*64,'7'*32);added.append(True)
            return read(lane,args,**kwargs)
        self.w.restic=native;result=self.c.checkpoint()
        self.assertEqual(result['retired_ids'],[SID]);self.assertEqual(set(self.c.entries()),{'4'*64,'6'*64})
    def test_binlog_tail_copy_uses_bounded_chunks_and_allows_writer_between_them(self):
        from backup_binlog_test import build,query,table_map,rows
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        insert=self.c._checkpoint_insert;db_method=self.c._db;lock=runtime.lane_lock;added=[];chunks=[];waiting=[False];interleaved=[]
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
                    chunks.append(parameters[1]);waiting[0]=True
                return proxy.db.execute(sql,parameters)
        @contextlib.contextmanager
        def source(*args,**kwargs):
            with db_method(*args,**kwargs) as db:yield Source(db)
        @contextlib.contextmanager
        def short_lock(path):
            with lock(path):yield
            if pathlib.Path(path)==self.c.lock and waiting[0] and not interleaved:
                interleaved.append(True)
                # A real SQLite write succeeds between source chunks. It does
                # not alter catalog records/proofs or claim native admission.
                with contextlib.closing(sqlite3.connect(self.c.database,timeout=0)) as db:
                    db.execute('BEGIN IMMEDIATE');db.rollback()
        with mock.patch.object(self.c,'_checkpoint_insert',side_effect=binlog_arrival),mock.patch.object(self.c,'_db',side_effect=source),mock.patch('backup_catalog.runtime.lane_lock',side_effect=short_lock):result=self.c.checkpoint()
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
            refs=[];scan=subject().ArchiveCatalog._scan;read=self.w.restic;added=[]
            def native(lane,args,**kwargs):
                if arrival and not added and args[2:]==['snapshots','--json']:
                    self.put('6'*64,'7'*32);added.append(True)
                return read(lane,args,**kwargs)
            self.w.restic=native
            def tracked(catalog,*args,**kwargs):
                self.assertTrue(all(ref() is None for ref in refs),'A previous complete map survived into the next full scan')
                result=Tracked(scan(catalog,*args,**kwargs));refs.append(weakref.ref(result));return result
            with self.subTest(arrival_during_native_observation=arrival),mock.patch.object(subject().ArchiveCatalog,'_scan',tracked):
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
            self.assertEqual(set(self.c.entries()),{'4'*64})
            self.assertEqual(list((self.root/'receipts/catalog-preparations').iterdir()),[])
    def test_inode_close_is_outside_locks_only_on_posix_and_replace_cost_is_charged(self):
        import retention_cohort
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        opened=[];closed=[];openfd=os.open;closefd=os.close;replace=os.replace;elapsed=[0.0]
        def open_file(path,*args,**kwargs):
            fd=openfd(path,*args,**kwargs)
            if pathlib.Path(path)==self.c.database:opened.append(fd)
            return fd
        def close_file(fd):
            if fd in opened:
                with retention_cohort.upload_section(self.w):closed.append('all-four-free')
            return closefd(fd)
        def slow(path,target):
            replace(path,target)
            if pathlib.Path(target)==self.c.database:elapsed[0]+=60
        with mock.patch('backup_catalog.os.open',side_effect=open_file),mock.patch('backup_catalog.os.close',side_effect=close_file),mock.patch('backup_catalog.os.replace',side_effect=slow),mock.patch('time.monotonic',side_effect=lambda:elapsed[0]),self.assertRaises(guards.GuardError):self.c.checkpoint()
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
        def section(worker):
            elapsed[0]+=8
            with original_section(worker):yield
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
        def section(worker):
            with original(worker):
                try:yield
                finally:elapsed[0]+=60
        with mock.patch.object(retention_cohort,'upload_section',section),mock.patch('time.monotonic',side_effect=lambda:elapsed[0]),self.assertRaises(guards.GuardError):self.c.checkpoint()
        self.assertFalse(self.c.checkpoint_pending.exists());self.assertEqual(set(self.c.entries()),{'4'*64})
        self.assertEqual(self.c.last_checkpoint_timing['critical_seconds'],60)
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
    def test_checkpoint_initial_native_audit_releases_upload_lanes(self):
        import retention_cohort
        self.prepare();self.put(SID,TOKEN);self.put('4'*64,'5'*32);self.prove_absence(SID)
        original=self.c._retirement_evidence;final=self.c._final_checkpoint_native;calls=[]
        def audit(records,**kwargs):
            with retention_cohort.upload_section(self.w):calls.append('unlocked-audit')
            return original(records,**kwargs)
        def current(*args,**kwargs):calls.append('final-check');return final(*args,**kwargs)
        with mock.patch.object(self.c,'_retirement_evidence',audit),mock.patch.object(self.c,'_final_checkpoint_native',current):self.c.checkpoint()
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
            confirmed=[{'id':r['id'],'token':r['token'],'manifest_sha256':r['manifest_sha256'],'captured_at':r['projection']['captured_at'],'confirmed_at':r['native']['time']} for r in self.records.values() if r['lane']==lane]
            runtime.atomic_json(self.root/'receipts'/lane/'state.json',{'generation':GEN,'confirmed':confirmed,'retention':[r for r in self.retired if r['lane']==lane]})
    def prove_absence(self,sid):
        import retention,retention_apply
        snapshots=[{'id':r['id'],'lane':r['lane'],'token':r['token'],'manifest_sha256':r['manifest_sha256'],'kind':r['projection']['kind'],
                    'generation':GEN,'time':r['projection']['captured_at'],'snapshot_time':r['native']['time'],'tree':r['native']['tree']} for key,r in self.records.items() if key in self.live]
        before={'format':'authenticated-retention-identities-v1','generation':GEN,'repositories':{'base':'7'*64,'binlog':'8'*64},'source':self.source,'snapshots':snapshots}
        keep=sorted(self.live-{sid});intent={'operation':'native-retention-forget','generation':GEN,'repositories':before['repositories'],'repository_paths':self.w.c['repositories'],
            'source':self.source,'token':sid[:32],'inventory_sha256':retention.inventory_digest(before),'before_inventory':before,'candidate_ids':[sid],
            'keep_ids':keep,'anchor_id':keep[0] if keep else sid,'proof_sha256':{},'prepared_at':'2026-10-12T12:00:00Z'}
        intent['intent_sha256']=retention_apply.document_digest(intent)
        receipt={k:copy.deepcopy(intent[k]) for k in ('operation','token','generation','repositories','source','inventory_sha256','candidate_ids','keep_ids','anchor_id','proof_sha256','intent_sha256')}
        receipt.update(result='APPLIED',observation_error=None,forgotten_ids=[sid],present_candidate_ids=[],post_inventory_sha256='9'*64,completed_at='2026-10-12T12:01:00Z')
        directory=self.root/'receipts'/'retention-applies'/intent['intent_sha256'];directory.mkdir(mode=0o700,parents=True,exist_ok=True);os.chmod(directory.parent,0o700)
        runtime.atomic_json(directory/'intent.json',intent);name='receipt-'+sid[:32]+'.json';runtime.atomic_json(directory/name,receipt)
        runtime.atomic_json(directory/'latest.json',{'file':name,'sha256':hashlib.sha256((directory/name).read_bytes()).hexdigest()})
        runtime.atomic_json(directory/'journals-committed.json',{'intent_sha256':intent['intent_sha256'],'receipt_sha256':retention_apply.document_digest(receipt)})
        self.retired.extend(retention_apply.retention_tombstones(intent,receipt));self.live.remove(sid);self.journals();return directory
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
