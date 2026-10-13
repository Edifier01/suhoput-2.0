"""Frozen native proof boundaries, using isolated synthetic repositories."""
import copy, datetime as dt, hashlib, importlib.util, json, pathlib, sys, tempfile, unittest
from types import SimpleNamespace
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'infra/backup'))
import guards, retention, retention_apply, retention_native, runtime
from backup_retention_apply_test import fixture, NOW, OLD, LOG, SOURCE, MemoryIntent
import backup_catalog_test as catalog_tests
from backup_binlog_test import build
from unittest import mock
import os

class CohortTests(unittest.TestCase):
    def test_locked_executor_reads_once_per_authority_boundary_within_fifty_five_seconds(self):
        import contextlib
        for lanes in (1,2):
            inv,plan,evidence=fixture(split=lanes==2);original=copy.deepcopy(inv);store=MemoryIntent();active=[False];elapsed=[0.0];critical_reads=[];effects=[]
            @contextlib.contextmanager
            def section():
                active[0]=True
                try:yield
                finally:active[0]=False
            def read():
                if active[0]:
                    elapsed[0]+=18;critical_reads.append(tuple(effects))
                    guards.require(elapsed[0]<55,'Simulated observed native metadata deadline')
                return copy.deepcopy(inv)
            def effect(lane,args):
                self.assertTrue(active[0]);effects.append(lane);elapsed[0]+=.1
                inv['snapshots']=[r for r in inv['snapshots'] if r['id'] not in args[3:]]
                for sid in args[3:]:inv['manifests'].pop(sid)
            result=retention_apply.Executor(read,effect,store,lambda r:None,{'base':'base','binlog':'logs'},effect_section=section).apply(original,plan,evidence,NOW)
            with self.subTest(lanes=lanes):
                self.assertEqual(result['result'],'APPLIED')
                self.assertEqual(len(critical_reads),lanes+1)
                self.assertEqual(critical_reads[0],());self.assertEqual(len(critical_reads[-1]),lanes)
                if lanes==2:self.assertEqual(critical_reads[1],('base',))
                self.assertLess(elapsed[0],55)
    def test_later_locked_lane_requires_exact_confirmation_of_prior_lane_effect(self):
        import contextlib
        inv,plan,evidence=fixture(split=True);store=MemoryIntent();effects=[]
        @contextlib.contextmanager
        def section():yield
        def partial(lane,args):effects.append(lane)  # native success with absent exact effect
        result=retention_apply.Executor(lambda:copy.deepcopy(inv),partial,store,lambda r:None,{'base':'base','binlog':'logs'},effect_section=section).apply(inv,plan,evidence,NOW)
        self.assertEqual(effects,['base']);self.assertEqual(result['result'],'RECONCILE_REQUIRED')
        self.assertEqual(result['forgotten_ids'],[])

    def test_executor_scans_and_validates_before_short_effect_section(self):
        inv,plan,evidence=fixture();store=MemoryIntent();active=[False];events=[]
        import contextlib
        @contextlib.contextmanager
        def section():
            active[0]=True;events.append('lock')
            try:yield
            finally:active[0]=False;events.append('unlock')
        def read():
            events.append('critical-read' if active[0] else 'scan');return copy.deepcopy(inv)
        def effect(lane,args):
            self.assertTrue(active[0]);inv['snapshots']=[r for r in inv['snapshots'] if r['id'] not in args[3:]]
            for sid in args[3:]:inv['manifests'].pop(sid)
        def write(receipt):self.assertTrue(active[0]);events.append('journal')
        try:ex=retention_apply.Executor(read,effect,store,write,{'base':'base','binlog':'logs'},effect_section=section)
        except TypeError:self.fail('Executor has no short critical-section boundary')
        result=ex.apply(copy.deepcopy(inv),plan,evidence,NOW)
        self.assertEqual(result['result'],'APPLIED');self.assertEqual(events[0],'scan')
        self.assertLess(events.index('scan'),events.index('lock'));self.assertLess(events.index('journal'),events.index('unlock'))
    def test_final_dependency_work_cannot_publish_intent_after_fifteen_minute_deadline(self):
        inv,plan,evidence=fixture();store=MemoryIntent();current=[NOW];original=retention_apply.protected_dependencies
        def slow(*args):
            result=original(*args);current[0]=NOW+dt.timedelta(seconds=901);return result
        ex=retention_apply.Executor(lambda:copy.deepcopy(inv),lambda *args:self.fail('Expired native effect'),store,lambda r:None,{'base':'base','binlog':'logs'},clock=lambda:current[0])
        with mock.patch.object(retention_apply,'protected_dependencies',slow),self.assertRaises(guards.GuardError):ex.apply(inv,plan,evidence,NOW)
        self.assertIsNone(store.load(),'Expired final work must not create a new ambiguous attempt')
    def test_new_recovery_base_protects_expired_binlog_even_below_frozen_anchor(self):
        inv,plan,_=fixture(split=True)
        sid='9'*64
        inv['snapshots'].append({**inv['snapshots'][2],'id':sid,'token':'9'*32})
        inv['manifests'][sid]=copy.deepcopy(inv['manifests'][OLD])
        with self.assertRaises(guards.GuardError):
            retention_apply.protected_dependencies(inv,plan['candidates'],NOW)
    def test_inconsistent_new_base_blocks_even_when_only_full_is_deleted(self):
        inv,_,_=fixture();sid='9'*64
        inv['snapshots'].append({**inv['snapshots'][2],'id':sid,'token':'9'*32})
        inv['manifests'][sid]=copy.deepcopy(inv['manifests'][OLD]);inv['manifests'][sid]['coordinates']['file']='suhoput2-binlog.000099'
        with self.assertRaises(guards.GuardError):retention_apply.protected_dependencies(inv,[OLD],NOW)

    def test_application_only_old_full_does_not_require_obsolete_binlogs(self):
        inv,plan,_=fixture(split=True);sid='9'*64
        inv['snapshots'].append({**inv['snapshots'][1],'id':sid,'token':'9'*32,'kind':'hourly'})
        inv['manifests'][sid]={**copy.deepcopy(inv['manifests'][inv['snapshots'][1]['id']]),'full_id':OLD}
        retention_apply.protected_dependencies(inv,['5'*64],NOW)

    def test_origin_cannot_relabel_an_unrelated_cohort(self):
        inv,plan,evidence=fixture();doc=evidence['tip']['document'];raw=json.dumps(doc).encode()
        inv['cohort']={'sha256':'a'*64,'planned_at':NOW.isoformat(),'code_sha':'f'*40,'watermark':{'file':'suhoput2-binlog.000002','position':500}}
        origin={'format':1,'evidence_type':'tip','producer':'restore.py','code_sha':'f'*40,
                'document_sha256':retention_apply.document_digest(doc),'file_sha256':hashlib.sha256(raw).hexdigest(),
                'generation':inv['generation'],'repositories':inv['repositories'],'inventory_sha256':plan['inventory_sha256']}
        with self.assertRaises(guards.GuardError):retention_native.verify_origin('tip',raw,doc,origin,'f'*40,inv)

    def test_pure_validator_rejects_one_of_six_receipts_from_other_cohort(self):
        inv,plan,evidence=fixture()
        binding={'sha256':'a'*64,'planned_at':NOW.isoformat(),'code_sha':'f'*40,'watermark':{'file':'suhoput2-binlog.000002','position':500}}
        inv['cohort']=binding;plan['cohort']=binding
        for name,item in evidence.items():
            item['document']['cohort']=copy.deepcopy(binding)
            item['sha256']=retention_apply.document_digest(item['document']);plan['proof_sha256'][name]=item['sha256']
        evidence['budget']['document']['cohort']['sha256']='b'*64
        evidence['budget']['sha256']=retention_apply.document_digest(evidence['budget']['document']);plan['proof_sha256']['budget']=evidence['budget']['sha256']
        with self.assertRaises(guards.GuardError):retention_apply.validate_apply(inv,plan,evidence,NOW)
    def test_history_producer_rejects_sparse_journals_without_claiming_thirty_days(self):
        self.assertTrue(callable(getattr(runtime,'publish_history',None)),'Native history producer missing')
        inv,_,_=fixture()
        with tempfile.TemporaryDirectory() as temp:
            w=SimpleNamespace(root=pathlib.Path(temp),c={'generation':inv['generation']})
            for lane in ('base','binlog'):runtime.atomic_json(w.root/'receipts'/lane/'state.json',{'generation':inv['generation'],'confirmed':[]})
            with self.assertRaises(guards.GuardError):runtime.publish_history(w)
    def test_budget_producer_requires_actual_protected_inputs(self):
        import budget
        self.assertTrue(callable(getattr(budget,'publish_budget',None)),'Native budget publisher missing')
        with tempfile.TemporaryDirectory() as temp:
            w=SimpleNamespace(root=pathlib.Path(temp))
            with self.assertRaises((guards.GuardError,FileNotFoundError)):budget.publish_budget(w)
    def test_history_frequency_survives_authenticated_retirement_of_pre_window_samples(self):
        import contextlib,retention_cohort,backup_catalog
        with tempfile.TemporaryDirectory() as temp:
            w=SimpleNamespace(root=pathlib.Path(temp),c={'generation':'a'*32});live=[];old=[];journals={'base':[],'binlog':[]}
            if os.name=='nt':
                self.enterContext(mock.patch.object(retention_native,'private_path',lambda p:pathlib.Path(p)))
                self.enterContext(mock.patch.object(retention_native,'protected_directory',lambda p:pathlib.Path(p)))
            for kind,interval in (('binlog',60),('hourly',3600),('full',86400)):
                count=30*86400//interval
                for index in range(count+1):
                    at=NOW-dt.timedelta(seconds=(count-index)*interval);identity=hashlib.sha256((kind+str(index)).encode()).hexdigest()
                    row={'id':identity,'kind':kind,'lane':'binlog' if kind=='binlog' else 'base','token':identity[:32],
                         'manifest_sha256':identity,'generation':'a'*32,'time':at.isoformat()}
                    (old if index==0 else live).append(row)
                    journals[row['lane']].append({key:row[key] for key in ('id','token','manifest_sha256') }|{'captured_at':row['time'],'prepared_at':row['time'],'confirmed_at':row['time']})
            for lane,rows in journals.items():runtime.atomic_json(w.root/'receipts'/lane/'state.json',{'generation':'a'*32,'confirmed':rows})
            directory=w.root/'receipts/retention-applies'/('b'*64);directory.mkdir(mode=0o700,parents=True)
            body={'before_inventory':{'snapshots':old},'candidate_ids':[r['id'] for r in old]}
            runtime.atomic_json(directory/'intent.json',{**body,'intent_sha256':retention_apply.document_digest(body)})
            tombstones=[{key:row[key] for key in ('id','lane','token','manifest_sha256','generation')} for row in old]
            inventory={'snapshots':live,'cohort':{'planned_at':NOW.isoformat()}}
            @contextlib.contextmanager
            def reader(*args):yield None
            with mock.patch.object(backup_catalog.ArchiveCatalog,'__init__',return_value=None),mock.patch.object(backup_catalog.ArchiveCatalog,'open_reader',reader), \
                 mock.patch.object(retention_cohort.CohortStore,'__init__',return_value=None),mock.patch.object(retention_cohort.CohortStore,'load',return_value=inventory), \
                 mock.patch.object(retention_native,'verified_tombstones',return_value=tombstones),mock.patch.object(retention_native,'publish_evidence',side_effect=lambda w,n,d,*a:d):
                try:proof=runtime.publish_history(w)
                except guards.GuardError as error:self.fail('Authenticated rolling cadence was discarded: '+str(error))
                self.assertEqual(proof['result'],'PASS');self.assertEqual(guards.utc(proof['observed_from']),NOW-dt.timedelta(days=30))
                altered=runtime.load_json(directory/'intent.json');altered['before_inventory']['snapshots'][0]['time']=(NOW-dt.timedelta(days=29)).isoformat()
                runtime.atomic_json(directory/'intent.json',altered)
                with self.assertRaises(guards.GuardError):runtime.publish_history(w)


class NativeCohortTests(unittest.TestCase):
    refresh=catalog_tests.CatalogTests.refresh
    catalog=catalog_tests.CatalogTests.catalog
    def setUp(self):
        catalog_tests.CatalogTests.setUp(self);self.native={};self.w.bin=self.root/'bin';self.w.bin.mkdir(mode=0o700)
        for producer in retention_native.PRODUCERS.values():
            (self.w.bin/producer).write_text('synthetic installed producer');os.chmod(self.w.bin/producer,0o600)
        if os.name=='nt':
            for module in (retention_native,__import__('retention_cohort')):
                self.enterContext(mock.patch.object(module,'private_path',lambda p:pathlib.Path(p)))
                self.enterContext(mock.patch.object(module,'protected_directory',lambda p:pathlib.Path(p)))
        self.enterContext(mock.patch('retention_cohort.clock',return_value=NOW))
        inv,_,_=fixture(split=True);self.initial=inv
        for row in inv['snapshots']:
            manifest={**self.manifest,**inv['manifests'][row['id']],'kind':row['kind'],'source':self.w.source,
                      'stage_app_sha':self.w.c['stage_app_sha'],'captured_at':row['time']}
            for file in (self.restored/'logs',):
                if file.exists():
                    import shutil;shutil.rmtree(file)
            if row['lane']=='binlog':
                (self.restored/'db.sql').unlink(missing_ok=True);(self.restored/'logs').mkdir(mode=0o700)
                records=[];files=[]
                for item in manifest['logs']:
                    raw,_=build();path=self.restored/'logs'/item['file'];path.write_bytes(raw);os.chmod(path,0o600)
                    records.append({'file':item['file'],'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
                    files.append({'path':'logs/'+item['file'],'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
                manifest['logs']=records;manifest['files']=files;manifest['active_file']='suhoput2-binlog.%06d'%(manifest['last_log']+1)
            else:
                (self.restored/'db.sql').write_bytes(b'synthetic database bytes');os.chmod(self.restored/'db.sql',0o600)
            raw=json.dumps(manifest).encode();(self.restored/'manifest.json').write_bytes(raw);os.chmod(self.restored/'manifest.json',0o600)
            meta={'id':row['id'],'tree':hashlib.sha256(row['id'].encode()).hexdigest(),'time':row['time'],
                  'paths':[str(self.root/'spool'/(row['lane']+'-payload'))],
                  'tags':['task047','generation:'+inv['generation'],'token:'+row['token'],'manifest-sha:'+hashlib.sha256(raw).hexdigest()]}
            self.catalog().admit(row['lane'],row['id'],meta,raw,self.restored);self.native[row['id']]=(row['lane'],meta)
        def restic(lane,args,**kwargs):
            if args[2:]==['cat','config']:return json.dumps({'version':2,'id':inv['repositories'][lane]}).encode()
            if args[2:]==['snapshots','--json']:return json.dumps([m for l,m in self.native.values() if l==lane]).encode()
            raise AssertionError('Per-snapshot native readback forbidden on warm cohort')
        self.w.restic=restic
        inventory=retention.native_inventory(self.w,NOW,inv['repositories'])
        for lane in ('base','binlog'):
            runtime.atomic_json(self.root/'receipts'/lane/'state.json',{'generation':inv['generation'],
                'confirmed':[{k:r[k] for k in ('id','token','manifest_sha256')} for r in inventory['snapshots'] if r['lane']==lane]})
    def documents(self,cohort):
        _,_,evidence=fixture(split=True);plan=retention.inventory_plan(cohort,NOW)
        for name,item in evidence.items():
            doc=item['document'];doc.update(source=self.w.source,code_sha=self.w.c['code_sha'],inventory_sha256=plan['inventory_sha256'],cohort=cohort['cohort'])
            if name=='audit':doc.update(readback_snapshots={r['id']:r['manifest_sha256'] for r in cohort['snapshots']},verified_binlogs=plan['logs'])
            if name in ('anchor','tip'):
                row=next(r for r in cohort['snapshots'] if r['id']==doc['base_id']);manifest=cohort['manifests'][row['id']]
                doc.update(base_manifest_sha256=row['manifest_sha256'],full_manifest_sha256=row['manifest_sha256'],stage_app_sha=manifest['stage_app_sha'],
                           stop={'file':plan['chain_last_file'],'position':plan['chain_last_position']},
                           verified_binlogs=retention.replay_range(manifest['coordinates'],{'file':plan['chain_last_file'],'position':plan['chain_last_position']},plan['logs']))
        return evidence
    def prepared_apply(self):
        import retention_cohort
        cohort,_=retention_cohort.CohortStore(self.w).capture()
        for name,item in self.documents(cohort).items():retention_native.publish_evidence(self.w,name,item['document'],cohort,NOW.isoformat())
        self.w.gate=lambda:None;effects=[]
        def forget(lane,ids,**kwargs):
            effects.append((lane,ids))
            for sid in ids:del self.native[sid]
            return b''
        self.w.retention_forget=forget;native=retention_native.NativeApply.__new__(retention_native.NativeApply);native.w=self.w
        directory=self.root/'receipts/retention-applies';directory.mkdir(mode=0o700,exist_ok=True)
        store=retention_native.NewIntentStore(directory/cohort['cohort']['sha256'])
        return cohort,native,store,effects
    def test_partial_journal_without_global_commit_cannot_seed_a_new_cohort(self):
        import retention_cohort
        cohort,_=retention_cohort.CohortStore(self.w).capture()
        for name,item in self.documents(cohort).items():retention_native.publish_evidence(self.w,name,item['document'],cohort,NOW.isoformat())
        self.w.gate=lambda:None
        def forget(lane,ids,**kwargs):
            if lane=='binlog':raise TimeoutError('No second effect')
            for sid in ids:del self.native[sid]
            return b''
        self.w.retention_forget=forget;native=retention_native.NativeApply.__new__(retention_native.NativeApply);native.w=self.w
        self.assertEqual(native.run('apply')['result'],'RECONCILE_REQUIRED')
        store=retention_native.IntentStore(self.root/'receipts/retention-applies'/cohort['cohort']['sha256'])
        ex=retention_apply.Executor(lambda:retention.native_inventory(self.w,NOW,cohort['repositories']),lambda *args:self.fail('Reconciliation deletion'),store,store.receipt,self.w.c['repositories'])
        receipt=ex.reconcile(NOW);self.assertEqual(receipt['forgotten_ids'],['1'*64])
        runtime.UploadJournal(self.root/'receipts/base',self.w.c['generation']).retire(store.load(),receipt,'base')
        with self.assertRaises(guards.GuardError):retention_cohort.CohortStore(self.w).capture()
    def test_native_mixed_lanes_have_separate_twenty_seven_second_authority_phases(self):
        import retention_cohort
        cohort,_=retention_cohort.CohortStore(self.w).capture()
        for name,item in self.documents(cohort).items():retention_native.publish_evidence(self.w,name,item['document'],cohort,NOW.isoformat())
        elapsed=[0.0];effects=[];original=self.w.restic
        def read(lane,args,**kwargs):
            result=original(lane,args,**kwargs);elapsed[0]+=6.75;return result
        self.w.restic=read;self.w.gate=lambda:None
        def forget(lane,ids,**kwargs):
            effects.append(lane);elapsed[0]+=2
            for sid in ids:del self.native[sid]
            return b''
        self.w.retention_forget=forget;native=retention_native.NativeApply.__new__(retention_native.NativeApply);native.w=self.w
        with mock.patch('time.monotonic',side_effect=lambda:elapsed[0]):result=native.run('apply')
        self.assertEqual(result['result'],'APPLIED');self.assertEqual(effects,['base','binlog'])
        timing=runtime.load_json(self.root/'receipts/retention-applies'/cohort['cohort']['sha256']/'phase-timing.json')['phase_seconds']
        self.assertGreater(timing['critical_seconds'],55);self.assertLessEqual(timing['critical_max_seconds'],55)
        self.assertEqual([phase['name'] for phase in timing['critical_phases']],['base','binlog','publication'])
    def test_native_capture_publish_load_all_six_receipts_and_reject_missing_cohort_member(self):
        import retention_cohort
        cohort,_=retention_cohort.CohortStore(self.w).capture()
        evidence=self.documents(cohort)
        for name,item in evidence.items():
            try:published=retention_native.publish_evidence(self.w,name,item['document'],cohort,NOW.isoformat())
            except guards.GuardError as error:self.fail('Native cohort producer publication failed: '+str(error))
            self.assertEqual(published.get('cohort'),cohort['cohort'],'Producer dropped the authenticated shared cohort')
        loaded=retention_native.load_evidence(self.w,cohort)
        self.assertEqual(set(loaded),retention_apply.EVIDENCE_TYPES)
        plan=retention.inventory_plan(cohort,NOW);plan.update(planned_at=NOW.isoformat(),proof_sha256={n:i['sha256'] for n,i in loaded.items()})
        retention_apply.validate_apply(cohort,plan,loaded,NOW)
        del self.native[OLD]
        with self.catalog().open_reader() as reader,self.assertRaises(guards.GuardError):retention_cohort.CohortStore(self.w).load(reader)
    def test_producer_cannot_rebind_receipt_of_other_inventory_to_frozen_cohort(self):
        import retention_cohort
        cohort,_=retention_cohort.CohortStore(self.w).capture();doc=self.documents(cohort)['budget']['document'];doc['inventory_sha256']='0'*64
        with self.assertRaises(guards.GuardError):retention_native.publish_evidence(self.w,'budget',doc,cohort,NOW.isoformat())
    def test_native_apply_commits_exact_effect_and_journals_before_unlocked_checkpoint(self):
        import retention_cohort,backup_catalog
        cohort,_=retention_cohort.CohortStore(self.w).capture()
        for name,item in self.documents(cohort).items():retention_native.publish_evidence(self.w,name,item['document'],cohort,NOW.isoformat())
        self.w.gate=lambda:None;effects=[]
        def forget(lane,ids,**kwargs):
            effects.append((lane,ids))
            for sid in ids:del self.native[sid]
            return b''
        self.w.retention_forget=forget
        native=retention_native.NativeApply.__new__(retention_native.NativeApply);native.w=self.w
        checkpoint=backup_catalog.ArchiveCatalog.checkpoint
        def check(catalog,**kwargs):
            with retention_cohort.upload_section(self.w):
                intents=list((self.root/'receipts/retention-applies').iterdir())
                self.assertTrue((intents[0]/'journals-committed.json').exists())
                self.assertEqual(len(runtime.UploadJournal(self.root/'receipts/base',self.w.c['generation']).state()['retention']),1)
            return checkpoint(catalog,**kwargs)
        with mock.patch.object(backup_catalog.ArchiveCatalog,'checkpoint',check):result=native.run('apply')
        self.assertEqual(result['result'],'APPLIED');self.assertEqual(effects,[('base',[OLD]),('binlog',['5'*64])])
        self.assertEqual(set(self.catalog().entries()),{'2'*64,'3'*64,LOG})
        store=retention_native.IntentStore(self.root/'receipts/retention-applies'/cohort['cohort']['sha256'])
        self.assertEqual(result,store.latest())
        timing=runtime.load_json(store.root/'phase-timing.json')
        self.assertEqual(timing['receipt_sha256'],retention_apply.document_digest(result))
        self.assertEqual([phase['name'] for phase in timing['phase_seconds']['critical_phases']],['base','binlog','publication'])
    def test_every_publication_promotion_crash_is_read_only_recoverable_without_partial_reader_admission(self):
        import retention_cohort
        for step in ('receipt','base','binlog','latest','commit'):
            if step!='receipt':self.setUp()
            cohort,native,store,effects=self.prepared_apply();original=retention_native.StagedFiles.promote;crashed=[]
            def promote(staging,path,target):
                original(staging,path,target)
                target=pathlib.Path(target)
                selected=(target.name.startswith('receipt-') if step=='receipt' else
                          target==self.root/'receipts'/step/'state.json' if step in ('base','binlog') else
                          target==store.root/('latest.json' if step=='latest' else 'journals-committed.json'))
                if selected and not crashed:crashed.append(step);raise OSError('Crash after '+step+' promotion')
            with self.subTest(step=step),mock.patch.object(retention_native.StagedFiles,'promote',promote):
                result=native.run('apply');self.assertEqual(result['result'],'RECONCILE_REQUIRED')
            self.assertEqual([lane for lane,_ in effects],['base','binlog'])
            if step!='commit':
                with self.assertRaises(guards.GuardError):retention_cohort.CohortStore(self.w).capture()
            else:self.assertEqual(len(retention_native.verified_tombstones(self.w)),2)
            result=native.run('reconcile');self.assertEqual(result['result'],'RECONCILED',step)
            self.assertEqual([lane for lane,_ in effects],['base','binlog'],'Read-only recovery repeated an effect')
            self.assertEqual(len(retention_native.verified_tombstones(self.w)),2)
            self.assertEqual(set(self.catalog().entries()),{'2'*64,'3'*64,LOG})
    def test_safe_minute_between_lane_sections_is_witnessed_and_preserved(self):
        import contextlib,retention_cohort
        _,native,store,effects=self.prepared_apply();original=retention_cohort.upload_section;count=[0];arrival=[]
        @contextlib.contextmanager
        def section(worker):
            count[0]+=1
            with original(worker):yield
            if count[0]==1:arrival.append(self.append_minute())
        with mock.patch.object(retention_cohort,'upload_section',section):result=native.run('apply')
        self.assertEqual(result['result'],'APPLIED');self.assertEqual([lane for lane,_ in effects],['base','binlog'])
        self.assertEqual(result['protected_arrival_ids'],arrival);self.assertIn(arrival[0],self.native)
        intent=store.load();self.assertNotIn(arrival[0],[row['id'] for row in intent['before_inventory']['snapshots']])
        witness=store.phase_documents()['binlog'];self.assertEqual([row['id'] for row in witness['arrival_rows']],arrival)
        self.assertEqual(witness['prior_absence_ids'],[OLD]);self.assertIn('catalog_head',witness)
    def test_pending_expiry_and_lock_reacquisition_after_first_effect_stop_every_later_effect(self):
        import contextlib,retention_cohort
        for cause in ('pending','expiry','busy'):
            if cause!='pending':self.setUp()
            _,native,store,effects=self.prepared_apply();original=retention_cohort.upload_section;count=[0];at=[NOW]
            @contextlib.contextmanager
            def section(worker):
                count[0]+=1
                if count[0]==2 and cause=='busy':raise guards.GuardError('Actual nonblocking lane busy')
                with original(worker):yield
                if count[0]==1:
                    if cause=='pending':runtime.atomic_json(self.root/'receipts/binlog/pending.json',{'unknown':True})
                    if cause=='expiry':at[0]=NOW+dt.timedelta(seconds=901)
            with self.subTest(cause=cause),mock.patch.object(retention_cohort,'upload_section',section),mock.patch.object(retention_cohort,'clock',side_effect=lambda:at[0]):
                result=native.run('apply');self.assertEqual(result['result'],'RECONCILE_REQUIRED')
            self.assertEqual([lane for lane,_ in effects],['base']);self.assertIn('5'*64,self.native)
            self.assertEqual(set(store.phase_documents()),{'base'})
            with self.assertRaises(guards.GuardError):native.run('apply')
            (self.root/'receipts/binlog/pending.json').unlink(missing_ok=True)
            with mock.patch.object(retention_cohort,'clock',side_effect=lambda:NOW+dt.timedelta(seconds=1800)):
                result=native.run('reconcile')
            self.assertEqual(result['result'],'RECONCILED');self.assertEqual(result['present_candidate_ids'],['5'*64])
            self.assertEqual([lane for lane,_ in effects],['base'],'Expired read-only recovery executed unattempted binlog lane')
            with self.assertRaises(guards.GuardError):native.run('apply')
    def test_new_recovery_base_between_lanes_blocks_required_binlog_deletion(self):
        import contextlib,retention_cohort
        _,native,store,effects=self.prepared_apply();original=retention_cohort.upload_section;count=[0]
        @contextlib.contextmanager
        def section(worker):
            count[0]+=1
            with original(worker):yield
            if count[0]==1:self.append_base('suhoput2-binlog.000001')
        with mock.patch.object(retention_cohort,'upload_section',section):result=native.run('apply')
        self.assertEqual(result['result'],'RECONCILE_REQUIRED');self.assertEqual([lane for lane,_ in effects],['base'])
        self.assertIn('5'*64,self.native);self.assertEqual(set(store.phase_documents()),{'base'})
        self.assertFalse((store.root/'journals-committed.json').exists())
    def test_new_arrival_after_journal_staging_blocks_overwrite_and_read_only_recovery_preserves_it(self):
        _,native,store,effects=self.prepared_apply();original=retention_native.StagedPublication.stage;arrivals=[]
        def stage(writer,value):
            original(writer,value)
            if not arrivals:arrivals.append(self.append_minute())
        with mock.patch.object(retention_native.StagedPublication,'stage',stage):result=native.run('apply')
        self.assertEqual(result['result'],'RECONCILE_REQUIRED');self.assertFalse((store.root/'journals-committed.json').exists())
        confirmed=runtime.UploadJournal(self.root/'receipts/binlog',self.w.c['generation']).state()['confirmed']
        self.assertIn(arrivals[0],[row['id'] for row in confirmed])
        result=native.run('reconcile');self.assertEqual(result['result'],'RECONCILED')
        self.assertEqual([lane for lane,_ in effects],['base','binlog']);self.assertEqual(result['protected_arrival_ids'],arrivals)
        self.assertIn(arrivals[0],self.catalog().entries())
    def test_both_journal_union_and_raw_receipt_phase_marker_tampering_fail_closed(self):
        _,native,store,_=self.prepared_apply();result=native.run('apply');self.assertEqual(result['result'],'APPLIED')
        marker_path=store.root/'journals-committed.json';marker=runtime.load_json(marker_path)
        baseline={path:path.read_bytes() for path in (marker_path,self.root/'receipts/base/state.json',self.root/'receipts/binlog/state.json',store.root/'phase-base.json',store.root/marker['receipt_ref']['file'])}
        for mutation in ('missing','receipt','raw','rows','union','misplaced','phase','bytes'):
            for path,raw in baseline.items():path.write_bytes(raw)
            changed=copy.deepcopy(marker)
            if mutation=='missing':marker_path.unlink()
            elif mutation=='receipt':changed['receipt_sha256']='0'*64
            elif mutation=='raw':changed['receipt_ref']['sha256']='0'*64
            elif mutation=='rows':changed['retirement_sha256']['base']='0'*64
            elif mutation=='union':
                path=self.root/'receipts/binlog/state.json';state=runtime.load_json(path);state['retention']=[];runtime.atomic_json(path,state)
                # Even the compatible old envelope must reject one-lane-only
                # rows when its actual bound receipt acknowledges BOTH lanes.
                changed={k:marker[k] for k in ('intent_sha256','receipt_sha256')}
            elif mutation=='misplaced':
                base=self.root/'receipts/base/state.json';logs=self.root/'receipts/binlog/state.json'
                first=runtime.load_json(base);second=runtime.load_json(logs);second['retention']+=first['retention'];first['retention']=[]
                runtime.atomic_json(base,first);runtime.atomic_json(logs,second)
            elif mutation=='phase':
                path=store.root/'phase-base.json';doc=runtime.load_json(path);doc['operation']='forged-phase';runtime.atomic_json(path,doc)
            else:(store.root/marker['receipt_ref']['file']).write_bytes(b'{}\n')
            if mutation!='missing':runtime.atomic_json(marker_path,changed)
            with self.subTest(mutation=mutation),self.assertRaises(guards.GuardError):retention_native.verified_tombstones(self.w)
        for path,raw in baseline.items():path.write_bytes(raw)
        self.assertEqual(len(retention_native.verified_tombstones(self.w)),2)
    def test_later_read_only_receipt_preserves_original_rows_and_both_old_new_marker_compatibility(self):
        import retention_cohort
        _,native,store,effects=self.prepared_apply();result=native.run('apply');original=retention_native.verified_tombstones(self.w)
        marker=runtime.load_json(store.root/'journals-committed.json')
        runtime.atomic_json(store.root/'journals-committed.json',{k:marker[k] for k in ('intent_sha256','receipt_sha256')})
        self.assertEqual(retention_native.verified_tombstones(self.w),original)
        self.catalog().checkpoint()  # legacy complete marker bridge stays valid
        store.receipt({**result,'result':'RECONCILE_REQUIRED','error_type':'InterruptedAfterCompleteCommit'})
        with mock.patch.object(retention_cohort,'clock',return_value=NOW+dt.timedelta(hours=1)):new=native.run('reconcile')
        self.assertEqual(new['result'],'RECONCILED');self.assertNotEqual(retention_apply.document_digest(new),retention_apply.document_digest(result))
        self.assertEqual(retention_native.verified_tombstones(self.w),original,'Later latest pointer rewrote original retirement receipt/time')
        marker=runtime.load_json(store.root/'journals-committed.json');self.assertEqual(marker['format'],2)
        self.assertEqual(set(marker['receipt_refs']),{retention_apply.document_digest(result),retention_apply.document_digest(new)})
        self.assertEqual([lane for lane,_ in effects],['base','binlog'])
    def test_bulk_staging_and_unknown_receipt_are_outside_locks_and_promotion_uses_reserved_tail(self):
        import contextlib,retention_cohort
        _,native,store,effects=self.prepared_apply();elapsed=[0.0];active=[False];original_section=retention_cohort.upload_section
        original_read=self.w.restic;original_json=retention_native.exclusive_json;original_promote=retention_native.StagedFiles.promote
        @contextlib.contextmanager
        def section(worker):
            with original_section(worker):
                active[0]=True
                try:yield
                finally:active[0]=False
        def read(lane,args,**kwargs):
            result=original_read(lane,args,**kwargs)
            if active[0]:elapsed[0]+=6.75
            return result
        def write(path,value):
            path=pathlib.Path(path)
            if 'retention-staging' in path.parts:
                self.assertFalse(active[0],'Bulk serialization/fsync/readback holds job/upload locks');elapsed[0]+=60
            elif path.name.startswith('receipt-'):
                self.assertFalse(active[0],'Failure receipt was written inside the expired phase');elapsed[0]+=60
            original_json(path,value)
        def promote(staging,path,target):
            original_promote(staging,path,target)
            if pathlib.Path(target).name!='intent.json':elapsed[0]+=6
        self.w.restic=read
        with mock.patch.object(retention_cohort,'upload_section',section),mock.patch.object(retention_native,'exclusive_json',write),mock.patch.object(retention_native.StagedFiles,'promote',promote),mock.patch('time.monotonic',side_effect=lambda:elapsed[0]):
            result=native.run('apply')
        self.assertEqual(result['result'],'RECONCILE_REQUIRED');self.assertEqual([lane for lane,_ in effects],['base','binlog'])
        self.assertFalse((store.root/'journals-committed.json').exists())
        timing=runtime.load_json(store.root/'phase-timing.json')['phase_seconds']
        self.assertEqual(timing['critical_max_seconds'],45);self.assertEqual(timing['journal_seconds'],18)
        self.assertEqual(timing['critical_phases'][-1]['journal_seconds'],18)
        self.assertEqual(timing['staging_seconds'],180);self.assertEqual(list((self.root/'receipts/retention-staging').iterdir()),[])
        self.assertGreater(elapsed[0],55,'Model must include genuinely long unlocked writes')
        self.w.restic=original_read;self.assertEqual(native.run('reconcile')['result'],'RECONCILED')
    def test_actual_unlock_cleanup_overrun_is_recorded_and_stops_the_next_lane(self):
        import contextlib,retention_cohort
        _,native,store,effects=self.prepared_apply();elapsed=[0.0];original=retention_cohort.upload_section;read=self.w.restic
        @contextlib.contextmanager
        def section(worker):
            with original(worker):
                try:yield
                finally:elapsed[0]+=30  # modeled OS cleanup delay, charged before release
        def native_read(lane,args,**kwargs):
            value=read(lane,args,**kwargs)
            if 'timeout' in kwargs:elapsed[0]+=6.75
            return value
        self.w.restic=native_read
        with mock.patch.object(retention_cohort,'upload_section',section),mock.patch('time.monotonic',side_effect=lambda:elapsed[0]):result=native.run('apply')
        self.assertEqual(result['result'],'RECONCILE_REQUIRED');self.assertEqual([lane for lane,_ in effects],['base'])
        timing=runtime.load_json(store.root/'phase-timing.json')['phase_seconds'];self.assertEqual(timing['critical_max_seconds'],57)
        self.assertEqual(timing['critical_phases'][0]['readiness_validation_durability_cleanup_seconds'],30)
        self.assertEqual(timing['critical_seconds'],57);self.assertIn('5'*64,self.native)
    def test_phase_witness_sequence_operation_prior_absences_and_inventory_are_authenticated(self):
        _,native,store,_=self.prepared_apply();self.assertEqual(native.run('apply')['result'],'APPLIED')
        base=store.root/'phase-base.json';logs=store.root/'phase-binlog.json';original={p:p.read_bytes() for p in (base,logs)}
        failures={'first_missing':'Phase authorization changed','operation':'Phase authorization changed',
                  'prior_missing':'Unknown or incomplete prior phase effect/absence',
                  'native_hash':'Phase current inventory cannot be reconstructed','foreign_lane':'Unknown phase authorization file'}
        for mutation,error in failures.items():
            # Recreating a deleted witness must not inherit a permissive umask.
            for path,raw in original.items():path.write_bytes(raw);path.chmod(0o600)
            doc=runtime.load_json(logs)
            if mutation=='first_missing':base.unlink()
            elif mutation=='operation':doc['operation']='untrusted'
            elif mutation=='prior_missing':doc['prior_absence_ids']=[]
            elif mutation=='native_hash':doc['native_inventory_sha256']='0'*64
            else:runtime.atomic_json(store.root/'phase-foreign.json',doc)
            doc['phase_sha256']=retention_apply.document_digest({k:v for k,v in doc.items() if k!='phase_sha256'});runtime.atomic_json(logs,doc)
            with self.subTest(mutation=mutation),self.assertRaisesRegex(guards.GuardError,error):store.phase_documents()
            (store.root/'phase-foreign.json').unlink(missing_ok=True)
        for path,raw in original.items():path.write_bytes(raw);path.chmod(0o600)
        self.assertEqual(set(store.phase_documents()),{'base','binlog'})
    def test_completed_attempt_releases_heavy_views_before_catalog_checkpoint(self):
        import weakref,backup_catalog,retention_cohort
        _,native,_,effects=self.prepared_apply();refs={name:[] for name in ('inventories','plans','evidence','staged_intent','sealed_records')}
        class Tracked(dict):pass
        def tracked(name,value):
            result=Tracked(value);refs[name].append(weakref.ref(result));return result
        def wrap(name,original):
            def call(*args,**kwargs):return tracked(name,original(*args,**kwargs))
            return call
        original_stage=retention_native.NewIntentStore.stage;reader_init=backup_catalog.ArchiveReader.__init__;checkpoint=backup_catalog.ArchiveCatalog.checkpoint
        def stage(store,value):original_stage(store,tracked('staged_intent',value))
        def reader(reader,*args,**kwargs):
            reader_init(reader,*args,**kwargs);reader._records=tracked('sealed_records',reader._records)
        def check(catalog,**kwargs):
            for name,values in refs.items():
                self.assertTrue(values,'Lifetime fixture did not observe '+name)
            live={name:sum(ref() is not None for ref in values) for name,values in refs.items()}
            self.assertEqual(live,{name:0 for name in refs},'Completed attempt buffers retained through checkpoint')
            with retention_cohort.upload_section(self.w):pass
            return checkpoint(catalog,**kwargs)
        with mock.patch.object(retention,'native_inventory',wrap('inventories',retention.native_inventory)), \
             mock.patch.object(retention_cohort.CohortStore,'load',wrap('inventories',retention_cohort.CohortStore.load)), \
             mock.patch.object(retention,'bounded_plan',wrap('plans',retention.bounded_plan)), \
             mock.patch.object(retention_native,'load_evidence',wrap('evidence',retention_native.load_evidence)), \
             mock.patch.object(retention_native.NewIntentStore,'stage',stage), \
             mock.patch.object(backup_catalog.ArchiveReader,'__init__',reader), \
             mock.patch.object(backup_catalog.ArchiveCatalog,'checkpoint',check):result=native.run('apply')
        self.assertEqual(result['result'],'APPLIED');self.assertEqual([lane for lane,_ in effects],['base','binlog'])
    def test_checkpoint_failure_sidecar_records_actual_duration_without_mutating_applied_receipt(self):
        import contextlib,backup_catalog,retention_cohort
        _,native,store,effects=self.prepared_apply();elapsed=[0.0];checkpoint=backup_catalog.ArchiveCatalog.checkpoint;section=retention_cohort.upload_section
        @contextlib.contextmanager
        def slow(worker):
            with section(worker):
                try:yield
                finally:elapsed[0]+=60
        def check(catalog,**kwargs):
            with mock.patch.object(retention_cohort,'upload_section',slow),mock.patch('time.monotonic',side_effect=lambda:elapsed[0]):return checkpoint(catalog,**kwargs)
        with mock.patch.object(backup_catalog.ArchiveCatalog,'checkpoint',check),self.assertRaises(guards.GuardError):native.run('apply')
        receipt=store.latest();self.assertEqual(receipt['result'],'APPLIED');self.assertEqual([lane for lane,_ in effects],['base','binlog'])
        sidecar=runtime.load_json(store.root/'phase-timing.json')
        self.assertEqual(sidecar['receipt_sha256'],retention_apply.document_digest(receipt))
        measured=sidecar['phase_seconds']['checkpoint_phase_seconds']
        self.assertEqual(measured['critical_seconds'],60);self.assertEqual(measured['critical_max_seconds'],60)
        self.assertIn('copy_step_interval_upper_max_seconds',measured)
        self.assertFalse(self.catalog().checkpoint_pending.exists());self.assertEqual(len(retention_native.verified_tombstones(self.w)),2)
    def test_checkpoint_only_reconcile_reports_physical_section_and_never_repeats_native_effects(self):
        import backup_catalog
        _,native,store,effects=self.prepared_apply()
        original_replace=os.replace;database=self.catalog().database
        def crash(path,target):
            original_replace(path,target)
            if pathlib.Path(target)==database:raise OSError('After metadata image activation')
        with mock.patch('backup_catalog.os.replace',side_effect=crash),self.assertRaises(OSError):native.run('apply')
        original=store.latest();self.assertEqual(original['result'],'APPLIED');self.assertTrue(self.catalog().checkpoint_pending.exists())
        result=native.run('reconcile');self.assertEqual(result['result'],'RECONCILED');self.assertEqual(result['remote_delete_calls'],0)
        self.assertEqual([lane for lane,_ in effects],['base','binlog']);self.assertEqual(store.latest(),original)
        self.assertIn('checkpoint_phase_seconds',result['phase_seconds']);self.assertFalse(self.catalog().checkpoint_pending.exists())
    def test_cached_audit_reads_sealed_bytes_and_rejects_splitting_base_coordinate(self):
        import retention_cohort
        cohort,_=retention_cohort.CohortStore(self.w).capture();target=self.root/'audited';target.mkdir(mode=0o700)
        self.assertTrue(callable(getattr(retention,'cached_log_audit',None)),'Sealed CRC/ROW audit missing')
        with self.catalog().open_reader() as reader:
            result=retention.cached_log_audit(reader,cohort,target)
            self.assertEqual(result['files'],2);self.assertGreater(result['row_events'],0)
            bad=copy.deepcopy(cohort);bad['manifests']['2'*64]['coordinates']['position']=5
            with self.assertRaises(guards.GuardError):retention.cached_log_audit(reader,bad,target)
    def test_critical_native_listing_has_a_deadline_and_cannot_run_a_cold_full_scan(self):
        import retention_cohort
        elapsed=[0.0];calls=[];original=self.w.restic
        def slow(lane,args,**kwargs):
            calls.append(kwargs.get('timeout'))
            value=original(lane,args)
            if lane=='binlog' and args[2:]==['snapshots','--json']:elapsed[0]=56
            return value
        self.w.restic=slow
        with self.catalog().open_reader() as reader,mock.patch('time.monotonic',side_effect=lambda:elapsed[0]):
            try:
                with self.assertRaises(guards.GuardError):retention.native_inventory(self.w,NOW,retention_cohort.repository_ids(self.w),reader=reader,deadline=55)
            except TypeError:self.fail('Critical native inventory has no bounded deadline')
        self.assertTrue(all(type(x) in (int,float) and 0<x<=55 for x in calls))
    def append_minute(self):
        sid='9'*64;directory=self.root/'cache/new-minute';directory.mkdir(mode=0o700);(directory/'logs').mkdir(mode=0o700)
        raw,_=build();filename='suhoput2-binlog.000003';(directory/'logs'/filename).write_bytes(raw);os.chmod(directory/'logs'/filename,0o600)
        descriptor={'file':filename,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
        manifest={'format':1,'kind':'binlog','generation':self.w.c['generation'],'source':self.w.source,'code_sha':self.w.c['code_sha'],
                  'captured_at':NOW.isoformat(),'previous_count':2,'first_log':3,'last_log':3,'active_file':'suhoput2-binlog.000004','logs':[descriptor],
                  'files':[{'path':'logs/'+filename,'bytes':len(raw),'sha256':descriptor['sha256']}]}
        body=json.dumps(manifest).encode();(directory/'manifest.json').write_bytes(body);os.chmod(directory/'manifest.json',0o600)
        meta={'id':sid,'tree':'a'*64,'time':NOW.isoformat(),'paths':[str(self.root/'spool/binlog-payload')],
              'tags':['task047','generation:'+self.w.c['generation'],'token:'+'9'*32,'manifest-sha:'+hashlib.sha256(body).hexdigest()]}
        self.catalog().admit('binlog',sid,meta,body,directory);self.native[sid]=('binlog',meta)
        state=runtime.UploadJournal(self.root/'receipts/binlog',self.w.c['generation']).state()
        state['confirmed'].append({'id':sid,'token':'9'*32,'manifest_sha256':hashlib.sha256(body).hexdigest()});runtime.atomic_json(self.root/'receipts/binlog/state.json',state)
        return sid
    def append_base(self,filename):
        sid='a'*64;directory=self.root/'cache/new-base';directory.mkdir(mode=0o700)
        data=b'synthetic database bytes';(directory/'db.sql').write_bytes(data);os.chmod(directory/'db.sql',0o600)
        manifest={**self.manifest,**self.initial['manifests']['3'*64],'source':self.w.source,'kind':'full',
                  'captured_at':NOW.isoformat(),'stage_app_sha':self.w.c['stage_app_sha'],'coordinates':{'file':filename,'position':4}}
        body=json.dumps(manifest).encode();(directory/'manifest.json').write_bytes(body);os.chmod(directory/'manifest.json',0o600)
        meta={'id':sid,'tree':'b'*64,'time':NOW.isoformat(),'paths':[str(self.root/'spool/base-payload')],
              'tags':['task047','generation:'+self.w.c['generation'],'token:'+'a'*32,'manifest-sha:'+hashlib.sha256(body).hexdigest()]}
        self.catalog().admit('base',sid,meta,body,directory);self.native[sid]=('base',meta)
        state=runtime.UploadJournal(self.root/'receipts/base',self.w.c['generation']).state()
        state['confirmed'].append({'id':sid,'token':'a'*32,'manifest_sha256':hashlib.sha256(body).hexdigest()});runtime.atomic_json(self.root/'receipts/base/state.json',state)
        return sid
    def test_safe_minute_arrival_crosses_all_producers_origin_loader_pure_intent_and_exact_effect(self):
        import retention_cohort
        cohort,_=retention_cohort.CohortStore(self.w).capture()
        for name,item in self.documents(cohort).items():retention_native.publish_evidence(self.w,name,item['document'],cohort,NOW.isoformat())
        arrival=self.append_minute();loaded=retention_native.load_evidence(self.w,cohort)
        plan=retention.inventory_plan(cohort,NOW);plan.update(planned_at=NOW.isoformat(),proof_sha256={n:i['sha256'] for n,i in loaded.items()})
        retention_apply.validate_apply(cohort,plan,loaded,NOW)
        self.w.gate=lambda:None
        def forget(lane,ids,**kwargs):
            for sid in ids:del self.native[sid]
            return b''
        self.w.retention_forget=forget
        native=retention_native.NativeApply.__new__(retention_native.NativeApply);native.w=self.w
        result=native.run('apply');self.assertEqual(result['result'],'APPLIED');self.assertEqual(result['protected_arrival_ids'],[arrival])
        intent=retention_native.IntentStore(self.root/'receipts/retention-applies'/cohort['cohort']['sha256']).load()
        phases=runtime.load_json(self.root/'receipts/retention-applies'/cohort['cohort']['sha256']/'phase-timing.json')
        self.assertEqual(phases['receipt_sha256'],retention_apply.document_digest(result))
        for phase in ('scan_seconds','critical_seconds','effect_seconds','journal_seconds','checkpoint_seconds'):
            self.assertGreaterEqual(phases['phase_seconds'][phase],0)
        self.assertGreater(phases['phase_seconds']['checkpoint_seconds'],0)
        self.assertEqual(intent['cohort'],cohort['cohort']);self.assertIn(arrival,[r['id'] for r in intent['before_inventory']['snapshots']])
        self.assertEqual(intent['protected_arrival_ids'],[arrival]);self.assertIn(arrival,self.native)
    def test_arrival_between_unlocked_scan_and_upload_lock_is_captured_from_authority(self):
        import contextlib,retention_cohort
        cohort,_=retention_cohort.CohortStore(self.w).capture()
        for name,item in self.documents(cohort).items():retention_native.publish_evidence(self.w,name,item['document'],cohort,NOW.isoformat())
        original=retention_cohort.upload_section;arrival=[]
        @contextlib.contextmanager
        def section(worker):
            if not arrival:arrival.append(self.append_minute())
            with original(worker):yield
        self.w.gate=lambda:None
        def forget(lane,ids,**kwargs):
            for sid in ids:del self.native[sid]
            return b''
        self.w.retention_forget=forget;native=retention_native.NativeApply.__new__(retention_native.NativeApply);native.w=self.w
        with mock.patch.object(retention_cohort,'upload_section',section):result=native.run('apply')
        self.assertEqual(result['result'],'APPLIED');self.assertEqual(result['protected_arrival_ids'],arrival)
    def test_reconciliation_rechecks_arrivals_before_publishing_journal_absences(self):
        import contextlib,retention_cohort
        cohort,_=retention_cohort.CohortStore(self.w).capture()
        for name,item in self.documents(cohort).items():retention_native.publish_evidence(self.w,name,item['document'],cohort,NOW.isoformat())
        self.w.gate=lambda:None
        def forget(lane,ids,**kwargs):
            for sid in ids:del self.native[sid]
            if lane=='binlog':raise TimeoutError('Lost result after effect')
            return b''
        self.w.retention_forget=forget;native=retention_native.NativeApply.__new__(retention_native.NativeApply);native.w=self.w
        self.assertEqual(native.run('apply')['result'],'RECONCILE_REQUIRED')
        original=retention_cohort.upload_section
        @contextlib.contextmanager
        def section(worker):
            metadata=copy.deepcopy(self.native['3'*64][1]);metadata['id']='e'*64
            self.native['e'*64]=('base',metadata)
            with original(worker):yield
        with mock.patch.object(retention_cohort,'upload_section',section):
            try:native.run('reconcile')
            except guards.GuardError:pass
        for lane in ('base','binlog'):
            self.assertEqual(runtime.UploadJournal(self.root/'receipts'/lane,self.w.c['generation']).state().get('retention',[]),[],
                             'Reconciliation published absences before authenticating the final arrival')
    def test_native_two_lane_apply_reuses_same_observation_and_fits_eighteen_second_reads(self):
        import retention_cohort
        cohort,_=retention_cohort.CohortStore(self.w).capture()
        for name,item in self.documents(cohort).items():retention_native.publish_evidence(self.w,name,item['document'],cohort,NOW.isoformat())
        elapsed=[0.0];critical_calls=[];effects=[];original=self.w.restic
        marker=self.root/'receipts/retention-applies'/cohort['cohort']['sha256']/'journals-committed.json'
        def read(lane,args,**kwargs):
            result=original(lane,args,**kwargs)
            if 'timeout' in kwargs:
                elapsed[0]+=4.5
                if not marker.exists():critical_calls.append((lane,args[2]))
            return result
        self.w.restic=read;self.w.gate=lambda:None
        def forget(lane,ids,**kwargs):
            self.assertGreater(kwargs['timeout'],0);effects.append(lane)
            for sid in ids:del self.native[sid]
            return b''
        self.w.retention_forget=forget;native=retention_native.NativeApply.__new__(retention_native.NativeApply);native.w=self.w
        with mock.patch('time.monotonic',side_effect=lambda:elapsed[0]):result=native.run('apply')
        self.assertEqual(result['result'],'APPLIED');self.assertEqual(effects,['base','binlog'])
        self.assertEqual(len(critical_calls),12)
        phases=runtime.load_json(marker.parent/'phase-timing.json')['phase_seconds']
        self.assertEqual(phases['critical_seconds'],54)
    def test_pending_capture_partial_checkpoint_and_changed_cohort_fail_closed(self):
        import retention_cohort
        for kind in ('pending','capture','checkpoint','cohort'):
            cohort,_=retention_cohort.CohortStore(self.w).capture()
            if kind=='pending':path=self.root/'receipts/binlog/pending.json';runtime.atomic_json(path,{'unknown':True})
            elif kind=='capture':path=self.root/'receipts/capture-binlog.json';runtime.atomic_json(path,{'generation':self.w.c['generation'],'lane':'binlog','phase':'capture'})
            elif kind=='checkpoint':path=self.catalog().checkpoint_pending;runtime.atomic_json(path,{'partial':True})
            else:
                path=self.root/'receipts/retention-cohorts'/(cohort['cohort']['sha256']+'.json');value=runtime.load_json(path);value['planned_at']='2026-10-12T12:00:00Z';runtime.atomic_json(path,value)
            with self.subTest(kind=kind),self.assertRaises(guards.GuardError):
                if kind=='cohort':
                    with self.catalog().open_reader() as reader:retention_cohort.CohortStore(self.w).load(reader)
                else:retention_cohort.ready(self.w)
            path.unlink()
    def test_owner_publisher_preserves_human_time_and_revalidates_original_unchanged_archives(self):
        import base64,retention_cohort
        cohort,_=retention_cohort.CohortStore(self.w).capture();owner=self.documents(cohort)['owner']['document']
        digest,native=self.owner_source(cohort)
        self.assertTrue(callable(getattr(retention_native,'publish_owner',None)),'Protected owner revalidation producer missing')
        self.w.restic=(lambda old:self._owner_read(old))(self.w.restic)
        published=retention_native.publish_owner(self.w)
        self.assertEqual(published['completed_at'],NOW.isoformat());self.assertEqual(published['external_native_completed_at'],'2026-10-12T08:02:00Z')
        self.assertEqual(published['restore_receipt_sha256'],digest);self.assertEqual(published['cohort'],cohort['cohort'])
    def owner_source(self,cohort):
        import base64
        owner=self.documents(cohort)['owner']['document']
        row=next(r for r in cohort['snapshots'] if r['id']=='2'*64);logs=cohort['manifests'][LOG]['logs'];stop={'file':logs[-1]['file'],'position':logs[-1]['size']}
        native={'result':'PASS','generation':self.w.c['generation'],'code_sha':'c'*40,'started_at':'2026-10-12T08:00:00Z','completed_at':'2026-10-12T08:02:00Z',
                'source_reads':0,'s3_writes':0,'before_counts':[0]*4,'after_counts':[1]*4,'sql_import':'PASS','native_replay':'PASS',
                'verified_binlogs':logs,'closedchain_tip':stop,'row_event_guard':{'result':'PASS','files':logs,'stop':stop},
                'media':{'coverage':{'all_tables_innodb':True,'read_only_snapshot':True,'schema_metadata_stable':True}},
                'preparation':{'source':self.w.source,'stage_app_sha':self.w.c['stage_app_sha'],'base_id':row['id'],'full_id':row['id'],
                               'base_manifest_sha256':row['manifest_sha256'],'full_manifest_sha256':row['manifest_sha256'],'coordinates':cohort['manifests'][row['id']]['coordinates'],'application_sha256':cohort['manifests'][row['id']]['application_sha256'],'configuration_sha256':cohort['manifests'][row['id']]['configuration_sha256']}}
        raw=json.dumps(native).encode();digest=hashlib.sha256(raw).hexdigest();human='это я. Historical owner confirmation'
        source={'native_receipt':native,'native_receipt_raw_base64':base64.b64encode(raw).decode(),'native_receipt_sha256':digest,
                'human_confirmation':human,'human_confirmation_sha256':hashlib.sha256(human.encode()).hexdigest(),'bundle_inventory_sha256':'d'*64}
        runtime.atomic_json(self.root/'receipts'/('owner-source-'+digest+'.json'),source)
        owner.update(restore_receipt_sha256=digest,human_confirmation_sha256=source['human_confirmation_sha256'],
                     external_native_code_sha=native['code_sha'],external_native_started_at=native['started_at'],external_native_completed_at=native['completed_at'])
        runtime.atomic_json(self.root/'receipts/owner-attestation.json',owner)
        return digest,native
    def test_owner_historical_closure_survives_proven_retirement_of_original_archives(self):
        import retention_cohort
        original,_=retention_cohort.CohortStore(self.w).capture();digest,historical=self.owner_source(original)
        future=NOW+dt.timedelta(days=31)
        with mock.patch('retention_cohort.clock',return_value=future):
            cohort,_=retention_cohort.CohortStore(self.w).capture();plan=retention.inventory_plan(cohort,future)
            documents=self.documents(cohort)
            for name,item in documents.items():
                doc=item['document'];doc.update(started_at=future.isoformat(),completed_at=future.isoformat())
                if name=='owner':
                    doc=runtime.load_json(self.root/'receipts/owner-attestation.json');doc.pop('cohort');doc.pop('inventory_sha256')
                    doc.update(started_at=future.isoformat(),completed_at=future.isoformat())
                if name=='history':doc['observed_until']=future.isoformat()
                if name=='anchor':
                    sid=plan['anchor_id'];row=next(r for r in cohort['snapshots'] if r['id']==sid)
                    doc.update(base_id=sid,full_id=sid,base_manifest_sha256=row['manifest_sha256'],full_manifest_sha256=row['manifest_sha256'],coordinates=cohort['manifests'][sid]['coordinates'])
                retention_native.publish_evidence(self.w,name,doc,cohort,future.isoformat())
            self.w.gate=lambda:None
            def forget(lane,ids,**kwargs):
                for sid in ids:del self.native[sid]
                return b''
            self.w.retention_forget=forget;native=retention_native.NativeApply.__new__(retention_native.NativeApply);native.w=self.w
            result=native.run('apply');self.assertEqual(result['result'],'APPLIED');self.assertNotIn('2'*64,self.native)
            current,_=retention_cohort.CohortStore(self.w).capture();self.w.restic=self._owner_read(self.w.restic)
            try:published=retention_native.publish_owner(self.w)
            except guards.GuardError as error:self.fail('Closed historical owner capability was reopened after proven retirement: '+str(error))
            self.assertEqual(published['restore_receipt_sha256'],digest);self.assertEqual(published['external_native_completed_at'],historical['completed_at'])
            self.assertEqual(published['cohort'],current['cohort']);self.assertEqual(published['native_cohort_revalidation']['base_id'],'3'*64)
    def _owner_read(self,old):
        def run(lane,args,**kwargs):
            if args[2:]==['check','--read-data']:return b''
            return old(lane,args)
        return run
    def test_budget_native_source_pipeline_keeps_rounding_unknown_and_rejects_changed_raw_export(self):
        import budget,retention_cohort
        from backup_budget_test import csv_bytes,row,HEADER,inputs
        cohort,_=retention_cohort.CohortStore(self.w).capture();root=self.root/'receipts/budget-inputs';root.mkdir(mode=0o700)
        self.w.c.update(bucket='synthetic-bucket',region='ru-1');account='685956';access_account='11111111-1111-1111-1111-111111111111';pool='ru-1';project='synthetic-project'
        scope=budget.scope_fingerprint(account,project,self.w.c['bucket'],pool);account_sha=hashlib.sha256(account.encode()).hexdigest()
        specifications=[('space-mb','747520','MB*H','2.57'),('traffic-mb','1024','MB','1.38'),('traffic-req-put','1000','item','0.71'),('traffic-req-get','1000','item','0.05'),('traffic-req-delete','1000','item','0')]
        csvrows=[]
        for metric,quantity,unit,cost in specifications:
            fields=row(metric,quantity,unit,cost,period='2026-10-12 12:00:00');fields[0]=account;fields[2]=project;csvrows.append(fields+[self.w.c['bucket'],pool])
        (root/'billing.csv').write_bytes(csv_bytes(csvrows,HEADER+';Бакет;Пул'));os.chmod(root/'billing.csv',0o600)
        base=NOW-dt.timedelta(hours=1);jobs={};access=[]
        for index,job in enumerate(budget.JOBS):
            start=base+dt.timedelta(seconds=index*10);end=start+dt.timedelta(seconds=2);name='native-'+job+'.json'
            doc={'result':'PASS','generation':cohort['generation'],'source':self.w.source,'code_sha':self.w.c['code_sha'],'cohort':cohort['cohort'],
                 'started_at':start.isoformat(),'completed_at':end.isoformat()}
            runtime.atomic_json(self.root/'receipts'/name,doc)
            jobs[job]={'receipt_file':name,'receipt_sha256':hashlib.sha256((self.root/'receipts'/name).read_bytes()).hexdigest(),'retained_delta_bytes':4096,'new_objects':1}
            for stamp,method in ((start,'PUT'),(end,'GET')):
                access.append({'container_name':self.w.c['bucket'],'account_uuid':access_account,'timestamp':stamp.isoformat(),'http_method':method,'status':200,
                               'server_to_client_bytes':100,'client_to_server_bytes':100,'path':'https://s3.invalid/synthetic'})
        (root/'access.jsonl').write_bytes(b'\n'.join(json.dumps(x).encode() for x in access));os.chmod(root/'access.jsonl',0o600)
        _,_,_,rates=inputs();rates.update(tariff_basis='owner-approved-public-standard-ru1',tax_basis='inclusive');runtime.atomic_json(root/'rates.json',rates)
        selection={'source':'authenticated-selectel-console-selection','bucket':self.w.c['bucket'],'account_scope_sha256':account_sha,'provider_access_account_scope_sha256':hashlib.sha256(access_account.encode()).hexdigest(),'scope_mapping_source':'synthetic authenticated same console/bucket admission','covered_from':base.isoformat(),'covered_until':NOW.isoformat(),'storage_class':'standard','region':'ru-1',
                   'selected_from':base.isoformat(),'selected_until':(NOW+dt.timedelta(hours=1)).isoformat(),'timezone':'UTC'};runtime.atomic_json(root/'provider-selection.json',selection)
        provenance={'operation':'native-provider-export-admission','export_source':'authenticated-selectel-console',**{k:selection[k] for k in ('bucket','account_scope_sha256','provider_access_account_scope_sha256','scope_mapping_source','covered_from','covered_until','selected_from','selected_until','timezone')},
                    'billing_scope_sha256':scope,'downloaded_at':NOW.isoformat()}
        for name,key in (('billing.csv','billing_sha256'),('access.jsonl','access_sha256'),('rates.json','rates_sha256'),('provider-selection.json','selection_sha256')):provenance[key]=hashlib.sha256((root/name).read_bytes()).hexdigest()
        runtime.atomic_json(root/'provenance.json',provenance)
        inventory={**jobs['check'],'objects':100,'buckets':1,'storage_bytes':1024**3}
        runtime.atomic_json(root/'measurements.json',{'native_jobs':jobs,'inventory':inventory,'cadence':{'pre_update':1,'check':4,'retention':180,'restore':1}})
        if os.name=='nt':
            self.enterContext(mock.patch('worker.private_path',lambda p:pathlib.Path(p)))
            self.enterContext(mock.patch('worker.protected_directory',lambda p:pathlib.Path(p)))
        published=budget.publish_budget(self.w);self.assertEqual(published['result'],'PASS');self.assertEqual(published['cohort'],cohort['cohort'])
        self.assertEqual(published['projection']['projection_days'],31)
        self.assertEqual(published['bounded_retention_minimum_monthly_batches'],178)
        self.assertIn('account_rounding_basis_unverified',published['invoice_compatibility']['limitations'])
        self.assertFalse(published['projection']['budget_gate'])
        rates['tax_basis']='exclusive';runtime.atomic_json(root/'rates.json',rates)
        provenance['rates_sha256']=hashlib.sha256((root/'rates.json').read_bytes()).hexdigest();runtime.atomic_json(root/'provenance.json',provenance)
        with self.assertRaises(guards.GuardError):budget.publish_budget(self.w)
        (root/'billing.csv').write_bytes(b'changed raw bytes')
        with self.assertRaises(guards.GuardError):budget.publish_budget(self.w)

if __name__=='__main__':unittest.main()
