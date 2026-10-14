"""Physical cleanup guards; native rehearsal is explicitly selected with --native."""
import contextlib, copy, datetime as dt, json, os, pathlib, sys, tempfile, unittest
from types import SimpleNamespace
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'infra/backup'))
import guards, maintenance, retention_cohort, retention_native, runtime, worker

class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=pathlib.Path(self.temp.name)
        for name in ('receipts','receipts/base','receipts/binlog','measurements'):(self.root/name).mkdir(mode=0o700)
        self.c={'repositories':{'base':'s3:https://example.invalid/bucket/base','binlog':'s3:https://example.invalid/bucket/binlog'},'generation':'a'*32,'code_sha':'b'*40}
        self.repo='c'*64;self.snapshots=[{'id':'d'*64}];self.size=1000;self.calls=[];self.active=False;self.tick=0
        runtime.atomic_json(self.root/'receipts/init-base.json',{'generation':self.c['generation'],'repository_id':self.repo})
        self.w=SimpleNamespace(root=self.root,c=self.c,restic=self.restic,maintenance_prune=self.prune)
        self.enterContext(mock.patch.object(retention_cohort,'ready'))
        self.enterContext(mock.patch.object(retention_native,'verified_tombstones',return_value=[{'lane':'base','id':'e'*64}]))
        original=retention_cohort.upload_section
        @contextlib.contextmanager
        def section(w):
            with original(w):
                self.active=True
                try:yield
                finally:self.active=False
        self.enterContext(mock.patch.object(retention_cohort,'upload_section',section))
        if os.name=='nt':
            self.enterContext(mock.patch.object(maintenance,'private_path',lambda path:pathlib.Path(path)))
            self.enterContext(mock.patch.object(maintenance,'protected_directory',lambda path:pathlib.Path(path)))
        self.m=maintenance.Maintenance(self.w,inventory=self.inventory)
        import integrity
        self.integrity_ensure=self.enterContext(mock.patch.object(integrity,'ensure'))
        self.integrity_invalidate=self.enterContext(mock.patch.object(integrity,'invalidate_lane'))
        self.integrity_publish=self.enterContext(mock.patch.object(integrity,'publish_lane'))
    def restic(self,lane,args,*,timeout):
        self.assertEqual(lane,'base');self.assertEqual(args[:2],['--repo',self.c['repositories']['base']]);self.assertGreater(timeout,0)
        self.calls.append(args[2:])
        if args[2:]==['cat','config']:return json.dumps({'version':2,'id':self.repo}).encode()
        if args[2:]==['snapshots','--json']:return json.dumps(self.snapshots).encode()
        if args[2:] in (['check','--read-data'],['check','--with-cache']):
            self.assertFalse(self.active,'Post-effect verification must not pause the minute producer');return b''
        self.fail('Unexpected native command: '+repr(args))
    def prune(self,lane,*,timeout):
        self.assertTrue(self.active);self.assertLessEqual(timeout,45);self.assertTrue(self.m.pending('base').exists())
        self.assertEqual(self.integrity_invalidate.call_args,mock.call(self.w,lane))
        self.calls.append(['prune']);self.size=400;return b''
    def inventory(self,lane,*,repository_id,timeout):
        self.assertTrue(self.active);self.assertGreater(timeout,0);self.tick+=1
        path=self.root/'measurements'/str(self.tick)
        runtime.atomic_json(path,{'format':1,'generation':self.c['generation'],'code_sha':self.c['code_sha'],
            'lane':lane,'repository':self.c['repositories'][lane],'repository_id':repository_id,
            'observed_at':dt.datetime.now(dt.timezone.utc).isoformat(),'physical_bytes':self.size,'object_count':3,
            'scope':'current-repository-object-bytes','source':'synthetic unit fixture'})
        return path
    def test_complete_cleanup_retains_snapshots_and_actual_size_delta(self):
        result=self.m.run('base')
        self.assertEqual(result['result'],'APPLIED');self.assertEqual(result['physical_bytes_delta'],-600)
        self.assertEqual(result['before']['snapshot_ids'],['d'*64]);self.assertEqual(result['before']['snapshot_ids'],result['after']['snapshot_ids'])
        self.assertFalse(result['monthly_storage_bound_verified']);self.assertFalse(self.m.pending('base').exists())
        self.assertEqual(self.calls.count(['prune']),1)
        self.integrity_publish.assert_called_once();self.integrity_ensure.assert_not_called();self.integrity_invalidate.assert_called_once_with(self.w,'base')
    def test_wait_before_group_acquisition_does_not_consume_held_work_budget(self):
        elapsed=[0.0];prune=self.prune;timeouts=[]
        @contextlib.contextmanager
        def waited(w):
            elapsed[0]=20.0;self.active=True
            try:yield elapsed[0]
            finally:self.active=False
        def effect(lane,*,timeout):
            timeouts.append(timeout);prune(lane,timeout=timeout);elapsed[0]+=30
        self.w.maintenance_prune=effect
        with mock.patch.object(retention_cohort,'upload_section',waited),mock.patch.object(maintenance.time,'monotonic',side_effect=lambda:elapsed[0]):
            result=self.m.run('base')
        self.assertEqual(result['result'],'APPLIED');self.assertEqual(result['critical_seconds'],30)
        self.assertEqual(timeouts,[45])
        self.assertEqual(self.calls.count(['prune']),1);self.assertFalse(self.m.pending('base').exists())
    def test_failed_group_acquisition_never_enters_effect_or_creates_intent(self):
        attempts=[]
        @contextlib.contextmanager
        def unavailable(w):
            attempts.append(True);raise guards.GuardError('Acquisition deadline expired');yield
        with mock.patch.object(retention_cohort,'upload_section',unavailable),self.assertRaises(guards.GuardError):self.m.run('base')
        self.assertEqual(attempts,[True]);self.assertEqual(self.calls,[])
        self.assertEqual(list(self.m.root.glob('intent-*.json')),[]);self.assertFalse(self.m.pending('base').exists())
    def compact_fixture(self):
        original=self.inventory;self.index_count=16
        def inventory(*args,**kwargs):
            path=original(*args,**kwargs);doc=runtime.load_json(path)
            doc.update(object_count=32,index_object_count=self.index_count,index_bytes=self.index_count*10)
            runtime.atomic_json(path,doc);return path
        def compact(lane,*,timeout):
            self.assertTrue(self.active);self.assertGreater(timeout,0);self.assertLessEqual(timeout,45)
            intent=self.m.load(lane);self.assertEqual(intent['command'],['repair','index'])
            self.calls.append(['repair','index']);self.index_count=1;self.size=850
        self.m.inventory=inventory;self.w.maintenance_compact=compact
    def test_compact_before_first_retirement_preserves_every_snapshot(self):
        self.compact_fixture()
        self.integrity_ensure.side_effect=lambda *args,**kwargs:self.assertFalse(self.active,'Weekly proof must be checked before upload locks')
        with mock.patch.object(retention_native,'verified_tombstones',side_effect=AssertionError('Compaction must not need retirement')):
            result=self.m.run('base',operation='compact')
        self.assertEqual(result['operation'],'native-index-compaction');self.assertEqual(result['result'],'APPLIED')
        self.assertTrue(result['native_completed']);self.assertFalse(result['prune_completed'])
        self.assertEqual(result['before']['snapshot_ids'],result['after']['snapshot_ids'])
        self.assertEqual((result['before']['physical']['index_object_count'],result['after']['physical']['index_object_count']),(16,1))
        self.assertEqual(self.calls.count(['repair','index']),1);self.assertNotIn(['prune'],self.calls)
        self.assertIn(['check','--with-cache'],self.calls);self.assertNotIn(['check','--read-data'],self.calls)
        self.assertEqual(result['check_mode'],'metadata-with-cache');self.assertFalse(result['full_remote_read_verified'])
        self.assertFalse(self.m.pending('base').exists())
        self.integrity_ensure.assert_called_once_with(self.w);self.integrity_invalidate.assert_not_called();self.integrity_publish.assert_not_called()
    def test_compact_integrity_gate_blocks_before_intent_or_effect(self):
        self.compact_fixture();self.integrity_ensure.side_effect=guards.GuardError('Weekly proof unavailable')
        with self.assertRaises(guards.GuardError):self.m.run('base',operation='compact')
        self.assertFalse(self.m.pending('base').exists());self.assertNotIn(['repair','index'],self.calls)
    def test_lost_compact_response_requires_matching_readonly_reconciliation(self):
        self.compact_fixture();compact=self.w.maintenance_compact
        def lost(lane,**kwargs):compact(lane,**kwargs);raise worker.NativeError('lost repair response')
        self.w.maintenance_compact=lost
        result=self.m.run('base',operation='compact');self.assertEqual(result['result'],'RECONCILE_REQUIRED')
        with self.assertRaises(guards.GuardError):maintenance.require_clear(self.w)
        with self.assertRaises(guards.GuardError):self.m.run('base',operation='compact')
        with self.assertRaisesRegex(guards.GuardError,'operation'):self.m.run('base','reconcile')
        result=self.m.run('base','reconcile',operation='compact')
        self.assertEqual(result['result'],'RECONCILED');self.assertFalse(result['native_completed'])
        self.assertTrue(self.m.pending('base').exists());self.assertEqual(self.calls.count(['repair','index']),1)
        self.assertFalse(any('unlock' in call for call in self.calls))
        doc=self.m.load('base');doc['command']=['repair','index','--read-all-packs']
        body={key:value for key,value in doc.items() if key not in ('intent_sha256','native_completion','verification_failure')}
        doc['intent_sha256']=maintenance.digest(body);runtime.atomic_json(self.m.pending('base'),doc)
        with self.assertRaises(guards.GuardError):self.m.run('base','reconcile',operation='compact')
    def test_compaction_requires_real_index_counters_before_effect(self):
        self.compact_fixture();original=self.m.inventory
        for field,value in (('index_object_count',None),('index_object_count',0),('index_object_count',True),('index_bytes',None),('index_bytes',0),('index_bytes',1001)):
            def invalid(*args,**kwargs):
                path=original(*args,**kwargs);doc=runtime.load_json(path);doc[field]=value;runtime.atomic_json(path,doc);return path
            self.m.inventory=invalid
            with self.subTest(field=field,value=value),self.assertRaises(guards.GuardError):self.m.run('base',operation='compact')
        self.assertNotIn(['repair','index'],self.calls);self.assertFalse(self.m.pending('base').exists())
    def test_compact_changed_snapshot_blocks_and_deadline_is_not_reset(self):
        self.compact_fixture();original=self.m.inventory;elapsed=[0.0]
        def slow(*args,**kwargs):
            path=original(*args,**kwargs);elapsed[0]+=46;return path
        self.m.inventory=slow
        with mock.patch.object(maintenance.time,'monotonic',side_effect=lambda:elapsed[0]),self.assertRaises(guards.GuardError):self.m.run('base',operation='compact')
        self.assertNotIn(['repair','index'],self.calls)
        self.m.inventory=original;compact=self.w.maintenance_compact
        def change(lane,**kwargs):compact(lane,**kwargs);self.snapshots.append({'id':'f'*64})
        self.w.maintenance_compact=change
        self.assertEqual(self.m.run('base',operation='compact')['result'],'RECONCILE_REQUIRED')
        self.assertTrue(self.m.pending('base').exists())
    def test_worker_compact_boundary_is_fixed_repair_index_only(self):
        w=worker.Worker.__new__(worker.Worker);w.c=self.c|{'region':'ru-1'};w.root=self.root;w.password=self.root/'password';w.binary=self.root/'restic';w.credentials={}
        calls=[];w.native=SimpleNamespace(run=lambda args,**kwargs:calls.append((args,kwargs)))
        w.maintenance_compact('base',timeout=12);args,kwargs=calls[0]
        self.assertEqual(args[-4:],['--repo',self.c['repositories']['base'],'repair','index'])
        self.assertIn('s3.connections=2',args);self.assertEqual(kwargs['timeout'],12)
        for lane,timeout in (('foreign',10),('base',56),('base',0)):
            with self.subTest(lane=lane,timeout=timeout),self.assertRaises(guards.GuardError):w.maintenance_compact(lane,timeout=timeout)
        self.assertEqual(len(calls),1)
    def test_unknown_effect_has_durable_intent_and_never_retries_prune(self):
        def lost(lane,**kwargs):self.prune(lane,**kwargs);raise TimeoutError('lost native result')
        self.w.maintenance_prune=lost
        result=self.m.run('base');self.assertEqual(result['result'],'RECONCILE_REQUIRED')
        with self.assertRaisesRegex(guards.GuardError,'Unresolved physical cleanup'):self.m.run('base')
        result=self.m.run('base','reconcile');self.assertEqual(result['result'],'RECONCILED')
        self.assertFalse(result['prune_completed']);self.assertTrue(self.m.pending('base').exists())
        self.assertEqual(self.calls.count(['prune']),1)
    def test_changed_snapshot_or_repository_cannot_claim_success(self):
        for changed in ('snapshot','repository'):
            with self.subTest(changed=changed):
                def change(lane,**kwargs):
                    self.prune(lane,**kwargs)
                    if changed=='snapshot':self.snapshots=[]
                    else:self.repo='f'*64
                self.w.maintenance_prune=change
                result=self.m.run('base');self.assertEqual(result['result'],'RECONCILE_REQUIRED')
                self.assertTrue(self.m.pending('base').exists())
                # Reset only this independent test case's owned local receipt.
                self.m.pending('base').unlink();self.snapshots=[{'id':'d'*64}];self.repo='c'*64
    def test_missing_or_incomplete_storage_authority_blocks_before_native_effect(self):
        with self.assertRaisesRegex(guards.GuardError,'Physical inventory authority required'):
            maintenance.Maintenance(self.w).run('base')
        original=self.inventory
        def invalid(*args,**kwargs):
            path=original(*args,**kwargs);doc=runtime.load_json(path);doc['physical_bytes']=None;runtime.atomic_json(path,doc);return path
        self.m.inventory=invalid
        with self.assertRaises(guards.GuardError):self.m.run('base')
        self.assertNotIn(['prune'],self.calls);self.assertFalse(self.m.pending('base').exists())
    def test_foreign_or_replayed_storage_receipt_blocks_effect(self):
        for field,value in (('repository','foreign'),('repository_id','f'*64),('generation','f'*32),('observed_at','2020-01-01T00:00:00Z'),('object_count',True)):
            def invalid(*args,**kwargs):
                path=self.inventory(*args,**kwargs);doc=runtime.load_json(path);doc[field]=value;runtime.atomic_json(path,doc);return path
            self.m.inventory=invalid
            with self.subTest(field=field),self.assertRaises(guards.GuardError):self.m.run('base')
        self.assertNotIn(['prune'],self.calls)
    def test_prune_deadline_is_shared_with_observations_and_expiry_prevents_effect(self):
        elapsed=[0.0];original=self.inventory
        def slow(*args,**kwargs):
            path=original(*args,**kwargs);elapsed[0]+=46;return path
        self.m.inventory=slow
        with mock.patch.object(maintenance.time,'monotonic',side_effect=lambda:elapsed[0]),self.assertRaises(guards.GuardError):self.m.run('base')
        self.assertNotIn(['prune'],self.calls)
    def test_live_capture_and_missing_retirement_prevent_cleanup(self):
        with mock.patch.object(retention_native,'verified_tombstones',return_value=[]),self.assertRaises(guards.GuardError):self.m.run('base')
        runtime.atomic_json(self.root/'receipts/base/pending.json',{'attempted':True})
        with self.assertRaises(guards.GuardError):self.m.run('base')
        self.assertNotIn(['prune'],self.calls)
    def test_dedicated_worker_boundary_uses_exact_prune_and_two_connections(self):
        w=worker.Worker.__new__(worker.Worker);w.c=self.c|{'region':'ru-1'};w.root=self.root;w.password=self.root/'password';w.binary=self.root/'restic';w.credentials={}
        calls=[];w.native=SimpleNamespace(run=lambda args,**kwargs:calls.append((args,kwargs)))
        w.maintenance_prune('base',timeout=12)
        args,kwargs=calls[0]
        self.assertEqual(args[-5:],[self.c['repositories']['base'],'prune','--max-repack-size','0','--max-unused=unlimited'])
        self.assertIn('s3.connections=2',args);self.assertNotIn('--no-lock',args);self.assertEqual(kwargs['timeout'],12)
        for lane,timeout in (('foreign',10),('base',56),('base',0)):
            with self.subTest(lane=lane,timeout=timeout),self.assertRaises(guards.GuardError):w.maintenance_prune(lane,timeout=timeout)
        self.assertEqual(len(calls),1)
    def test_unknown_cleanup_stops_capture_and_upload_before_writes(self):
        runtime.atomic_json(self.m.pending('base'),{'unknown':True})
        w=worker.Worker.__new__(worker.Worker);w.root=self.root
        w.source_check=lambda:self.fail('Unresolved cleanup reached source access')
        w.gate=lambda:self.fail('Unresolved cleanup reached preflight')
        for action in (lambda:w.base('full'),w.binlog,lambda:w.upload('base',self.root/'absent')):
            with self.assertRaises((guards.GuardError,KeyError)):action()
    def test_completed_native_effect_allows_capture_during_unlocked_full_read(self):
        original=self.restic
        def read(lane,args,**kwargs):
            if args[2:]==['check','--read-data']:maintenance.require_clear(self.w)
            return original(lane,args,**kwargs)
        self.w.restic=read;self.assertEqual(self.m.run('base')['result'],'APPLIED')
    def test_failed_full_read_reblocks_capture_without_repeating_native_effect(self):
        original=self.restic
        def read(lane,args,**kwargs):
            if args[2:]==['check','--read-data']:raise worker.NativeError('check')
            return original(lane,args,**kwargs)
        self.w.restic=read;self.assertEqual(self.m.run('base')['result'],'RECONCILE_REQUIRED')
        with self.assertRaises(guards.GuardError):maintenance.require_clear(self.w)
        self.assertIn('native_completion',self.m.load('base'))
        self.assertEqual(self.calls.count(['prune']),1)
        self.integrity_publish.assert_not_called()
    def test_completed_effect_crash_allows_only_catalogued_journalled_arrivals(self):
        original=self.restic
        def crash(lane,args,**kwargs):
            if args[2:]==['check','--read-data']:raise KeyboardInterrupt('crash after durable native completion')
            return original(lane,args,**kwargs)
        self.w.restic=crash
        with self.assertRaises(KeyboardInterrupt):self.m.run('base')
        self.w.restic=original
        arrival={'id':'e'*64,'tree':'f'*64,'time':maintenance.clock().isoformat(),
                 'paths':[str(self.root/'spool/base-payload')],
                 'tags':['task047','generation:'+self.c['generation'],'token:'+'1'*32,'manifest-sha:'+'2'*64]}
        self.snapshots.append(arrival)
        record={'id':arrival['id'],'native':arrival,'lane':'base','repository_id':self.repo,'generation':self.c['generation'],'token':'1'*32,'manifest_sha256':'2'*64}
        journal={'generation':self.c['generation'],'confirmed':[{'id':arrival['id'],'token':'1'*32,'manifest_sha256':'2'*64}]}
        runtime.atomic_json(self.root/'receipts/base/state.json',journal)
        @contextlib.contextmanager
        def reader(*args,**kwargs):yield SimpleNamespace(_record=lambda sid:record)
        with mock.patch.object(maintenance.backup_catalog.ArchiveCatalog,'__init__',return_value=None),mock.patch.object(maintenance.backup_catalog.ArchiveCatalog,'open_reader',reader):
            # A known ID alone must not admit changed native metadata.
            record['native']={**arrival,'tree':'3'*64}
            self.assertEqual(self.m.run('base','reconcile')['result'],'RECONCILE_REQUIRED')
            record['native']=arrival
            runtime.atomic_json(self.root/'receipts/base/state.json',{'generation':self.c['generation'],'confirmed':[]})
            self.assertEqual(self.m.run('base','reconcile')['result'],'RECONCILE_REQUIRED')
            runtime.atomic_json(self.root/'receipts/base/state.json',journal)
            result=self.m.run('base','reconcile')
        self.assertEqual(result['result'],'RECONCILED');self.assertTrue(result['prune_completed']);self.assertFalse(self.m.pending('base').exists())
        self.assertEqual(result['authenticated_arrivals'],['e'*64]);self.assertEqual(self.calls.count(['prune']),1)

def native_rehearsal(binary):
    """Fresh real format-2 archives; authorization fixtures remain explicit."""
    import hashlib, signal, subprocess, time
    assert os.name=='posix' and os.getuid()==0
    binary=pathlib.Path(binary);assert worker.sha(binary)==worker.RESTIC_SHA
    observations=[]
    for scenario in ('complete','lost-result','interrupted'):
        with tempfile.TemporaryDirectory(prefix='physical-cleanup-') as temporary:
            root=pathlib.Path(temporary)
            for name in ('cache','receipts','receipts/base','receipts/binlog','measurements','payload'):(root/name).mkdir(mode=0o700)
            w=worker.Worker.__new__(worker.Worker);w.root=root;w.binary=binary;w.password=root/'password';w.password.write_text('disposable-native-test-password');w.password.chmod(0o600)
            w.credentials={};w.c={'repositories':{'base':str(root/'repo-base'),'binlog':str(root/'repo-binlog')},'region':'ru-1','generation':'a'*32,'code_sha':'b'*40}
            w.native=worker.NativeRunner(root/'cache')
            def command(args):return w.restic('base',['--repo',w.c['repositories']['base'],*args],timeout=30)
            command(['init','--repository-version','2']);repository_id=json.loads(command(['cat','config']))['id']
            runtime.atomic_json(root/'receipts/init-base.json',{'generation':w.c['generation'],'repository_id':repository_id})
            old=root/'payload/old.bin';old.write_bytes(os.urandom(4*1024*1024))
            def backup():
                rows=[json.loads(line) for line in command(['backup',str(root/'payload'),'--json']).splitlines()]
                return next(row['snapshot_id'] for row in rows if row.get('message_type')=='summary')
            expired=backup();old.unlink();survivor=root/'payload/survivor.bin';survivor.write_bytes(os.urandom(1024*1024));survivor_digest=worker.sha(survivor);retained=backup()
            w.retention_forget('base',[expired],timeout=30)
            samples=[]
            def inventory(lane,*,repository_id,timeout):
                started=time.monotonic();repo=pathlib.Path(w.c['repositories'][lane]);rows=[]
                for path in repo.rglob('*'):
                    assert not path.is_symlink()
                    if path.is_file():rows.append({'path':path.relative_to(repo).as_posix(),'bytes':path.stat().st_size})
                assert time.monotonic()-started<timeout
                path=root/'measurements'/('physical-'+str(len(samples))+'.json')
                doc={'format':1,'generation':w.c['generation'],'code_sha':w.c['code_sha'],'lane':lane,
                     'repository':w.c['repositories'][lane],'repository_id':repository_id,'observed_at':maintenance.clock().isoformat(),
                     'physical_bytes':sum(row['bytes'] for row in rows),'object_count':len(rows),
                     'scope':'current-repository-object-bytes','source':'fresh local filesystem regular-file size sum',
                     'objects_sha256':maintenance.digest(sorted(rows,key=lambda row:row['path']))}
                runtime.atomic_json(path,doc);samples.append(doc);return path
            m=maintenance.Maintenance(w,inventory=inventory);native_prune=w.maintenance_prune;calls=[]
            def prune(lane,*,timeout):
                assert m.pending(lane).exists();calls.append(lane)
                if scenario!='interrupted':
                    result=native_prune(lane,timeout=timeout)
                    if scenario=='lost-result':raise TimeoutError('deliberate loss AFTER actual native success')
                    return result
                # Kill the actual child after restic creates its native lock.
                # Never delete that lock or rerun prune to make the test pass.
                args=[str(binary),'--password-file',str(w.password),'--cache-dir',str(root/'cache/interrupt'),'-o','s3.connections=2',
                      '--repo',w.c['repositories'][lane],'prune','--max-repack-size','0','--max-unused=unlimited']
                process=subprocess.Popen(args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                deadline=time.monotonic()+min(timeout,10);locked=False
                try:
                    while process.poll() is None and time.monotonic()<deadline:
                        lockdir=pathlib.Path(w.c['repositories'][lane])/'locks'
                        if any(len(path.name)==64 and all(c in '0123456789abcdef' for c in path.name) for path in lockdir.glob('*')):
                            os.kill(process.pid,signal.SIGSTOP);os.waitpid(process.pid,os.WUNTRACED)
                            locked=any(len(path.name)==64 for path in lockdir.glob('*'))
                            if locked:break
                            os.kill(process.pid,signal.SIGCONT)
                        time.sleep(.001)
                    assert locked,'Native interruption did not observe an active lock'
                finally:
                    if process.poll() is None:process.kill()
                    process.wait(timeout=5)
                raise TimeoutError('actual restic child killed after exclusive lock acquisition')
            w.maintenance_prune=prune
            # This fixture proves actual native cleanup and survivor bytes;
            # protected weekly publication is exercised by integrity tests.
            with mock.patch.object(retention_cohort,'ready'),mock.patch.object(retention_native,'verified_tombstones',return_value=[{'lane':'base','id':expired}]),mock.patch('integrity.invalidate_lane'),mock.patch('integrity.publish_lane'):
                result=m.run('base')
                if scenario=='complete':
                    assert result['result']=='APPLIED' and result['physical_bytes_delta']<-3*1024*1024,result
                else:
                    assert result['result']=='RECONCILE_REQUIRED' and m.pending('base').exists(),result
                    try:m.run('base')
                    except guards.GuardError:pass
                    else:raise AssertionError('Unknown native cleanup was retried')
                    result=m.run('base','reconcile');assert result['result']=='RECONCILED' and not result['prune_completed'],result
                    assert m.pending('base').exists()
                assert calls==['base']
            command(['check','--read-data']);command(['restore',retained,'--target',str(root/'restored'),'--verify'])
            restored=root/'restored'/str(survivor).lstrip('/');assert worker.sha(restored)==survivor_digest
            snapshots=json.loads(command(['snapshots','--json']));assert [row['id'] for row in snapshots]==[retained]
            if scenario=='interrupted':assert list((root/'repo-base/locks').glob('*')),'Interrupted exclusive lock was unexpectedly removed'
            observations.append({'scenario':scenario,'result':result['result'],'before_bytes':samples[0]['physical_bytes'],
                'after_bytes':samples[-1]['physical_bytes'],'critical_seconds':result['critical_seconds'],
                'native_prune_calls':len(calls),'retained_snapshot_unchanged':True,'read_data_and_restore':'PASS',
                'native_lock_files_preserved':len(list((root/'repo-base/locks').glob('*')))})
    print(json.dumps({'result':'PASS','restic_sha256':worker.RESTIC_SHA,'native':observations,
        'retirement_authorization':'synthetic fixture after actual exact-ID forget','physical_measurement':'actual filesystem sums',
        'scope':'new disposable local repositories only','monthly_storage_bound_verified':False,'S3_operations':0,'VPS_operations':0}))

if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--native':native_rehearsal(sys.argv[2])
    else:unittest.main()
