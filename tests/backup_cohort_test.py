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
        self.assertIn('phase_seconds',result)
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
