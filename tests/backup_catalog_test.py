"""Synthetic admission/store fault tests; no native or external provenance claim."""
import contextlib, copy, datetime as dt, hashlib, importlib.util, json, os, pathlib, shutil, sqlite3, sys, tempfile, unittest
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

if __name__=='__main__':unittest.main()
