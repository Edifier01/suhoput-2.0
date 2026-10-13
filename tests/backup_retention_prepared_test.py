"""Native daily preparation and exact final equality; synthetic repositories."""
import contextlib,copy,datetime as dt,hashlib,json,pathlib,sys,unittest
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'infra/backup'))
import backup_catalog,guards,readiness_v2,retention,retention_apply,retention_cohort,retention_native,runtime
import backup_retention_native_test
from backup_retention_apply_test import NOW

class PreparedNativePhaseTests(unittest.TestCase):
    def case(self):
        return backup_retention_native_test.NativeBoundaryTests.v2_case(self)
    def test_final_native_equality_transfers_full_audit_without_repeating_manifest_work(self):
        case,_,executor,_,effects,evidence=self.case();active=[False];original=retention_cohort.upload_section
        inventory=retention.native_inventory
        @contextlib.contextmanager
        def section(worker,**kwargs):
            with original(worker,**kwargs) as acquired:
                active[0]=True
                try:yield acquired
                finally:active[0]=False
        def audit(*args,**kwargs):
            self.assertFalse(active[0],'Exact unfiltered native equality transfers the outside manifest audit')
            return inventory(*args,**kwargs)
        with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True), \
             mock.patch.object(retention_cohort,'upload_section',section),mock.patch.object(retention,'native_inventory',audit), \
             mock.patch.object(backup_catalog.ArchiveCatalog,'checkpoint',return_value={}):result=executor.run('apply')
        self.assertEqual(result['result'],'APPLIED');self.assertEqual(len(effects),2)

    def test_full_native_equality_accepts_only_top_level_snapshot_order_changes(self):
        case,_,executor,_,effects,evidence=self.case();native=case.w.restic;calls=[0]
        def read(lane,args,**kwargs):
            raw=native(lane,args,**kwargs)
            if args[2:]==['snapshots','--json']:
                calls[0]+=1
                if calls[0]%2:raw=json.dumps(list(reversed(json.loads(raw)))).encode()
            return raw
        case.w.restic=read
        with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True), \
             mock.patch.object(backup_catalog.ArchiveCatalog,'checkpoint',return_value={}):result=executor.run('apply')
        self.assertEqual(result['result'],'APPLIED');self.assertEqual(len(effects),2)

    def test_unprojected_native_field_drift_blocks_effect(self):
        case,_,executor,store,effects,evidence=self.case();active=[False];native=case.w.restic;original=retention_cohort.upload_section
        @contextlib.contextmanager
        def section(worker,**kwargs):
            with original(worker,**kwargs) as acquired:
                active[0]=True
                try:yield acquired
                finally:active[0]=False
        def read(lane,args,**kwargs):
            raw=native(lane,args,**kwargs)
            if active[0] and args[2:]==['snapshots','--json']:
                rows=json.loads(raw)
                if rows:rows[0]['hostname']='unexpected-native-field-drift'
                return json.dumps(rows).encode()
            return raw
        case.w.restic=read
        with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True), \
             mock.patch.object(retention_cohort,'upload_section',section),self.assertRaisesRegex(guards.GuardError,'Final unfiltered native'):
            executor.run('apply')
        self.assertEqual(effects,[]);self.assertFalse(store.path.exists())

    def test_native_view_digest_rejects_duplicate_ids_and_preserves_all_fields(self):
        config={'id':'a'*64,'version':2};rows=[{'id':'b'*64,'tags':['one','two'],'hostname':'fixture'}]
        initial=retention.native_view_digest(config,rows)
        with self.assertRaisesRegex(guards.GuardError,'Duplicate native'):
            retention.native_view_digest(config,rows+copy.deepcopy(rows))
        self.assertNotEqual(initial,retention.native_view_digest({**config,'version':3},rows))
        self.assertNotEqual(initial,retention.native_view_digest(config,[{**rows[0],'hostname':'changed'}]))
        self.assertNotEqual(initial,retention.native_view_digest(config,[{**rows[0],'tags':['two','one']}]))
    def test_heavy_validation_is_outside_groups_but_every_group_reads_full_native_inventory(self):
        case,_,executor,store,effects,evidence=self.case();active=[False];reads=[]
        original=retention_cohort.upload_section;dependencies=retention_apply.protected_dependencies;confirmed=retention_native._confirmed_active;native=case.w.restic
        @contextlib.contextmanager
        def section(worker,**kwargs):
            with original(worker,**kwargs) as acquired:
                active[0]=True
                try:yield acquired
                finally:active[0]=False
        def dependency(*args,**kwargs):
            self.assertFalse(active[0],'Full dependency validation belongs to the bound outside preparation')
            return dependencies(*args,**kwargs)
        def confirmation(*args,**kwargs):
            self.assertFalse(active[0],'Full journal validation belongs to the bound outside preparation')
            return confirmed(*args,**kwargs)
        def read(lane,args,**kwargs):
            if active[0]:reads.append((lane,args[2]))
            return native(lane,args,**kwargs)
        case.w.restic=read
        with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True), \
             mock.patch.object(retention_cohort,'upload_section',section),mock.patch.object(retention_apply,'protected_dependencies',dependency), \
             mock.patch.object(retention_native,'_confirmed_active',confirmation),mock.patch.object(backup_catalog.ArchiveCatalog,'checkpoint',return_value={}):
            result=executor.run('apply')
        self.assertEqual(result['result'],'APPLIED');self.assertEqual(len(effects),2)
        self.assertEqual(reads,[('base','cat'),('base','snapshots'),('binlog','cat'),('binlog','snapshots')]*3)
        self.assertTrue((store.root/'journals-committed.json').exists())

    def test_arrival_before_reservation_reprepares_without_repeating_effects(self):
        case,_,executor,store,effects,evidence=self.case();original=retention_cohort.upload_section;arrivals=[];groups=[]
        @contextlib.contextmanager
        def section(worker,**kwargs):
            if not groups:arrivals.append(case.append_minute())
            groups.append(True)
            with original(worker,**kwargs) as acquired:yield acquired
        with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True), \
             mock.patch.object(retention_cohort,'upload_section',section),mock.patch.object(backup_catalog.ArchiveCatalog,'checkpoint',return_value={}):
            result=executor.run('apply')
        self.assertEqual(result['result'],'APPLIED');self.assertEqual(len(effects),2)
        self.assertEqual(len(groups),4,'The changed preparation must release its group before refreshing')
        self.assertEqual(result['protected_arrival_ids'],arrivals);self.assertIn(arrivals[0],case.native)
        self.assertEqual(len(store.phase_documents()),2)

    def test_authenticated_append_during_authority_audit_does_not_restart_native_preparation(self):
        case,_,executor,store,effects,evidence=self.case();audit=backup_catalog.ArchiveCatalog._checkpoint_inputs;audits=[];arrivals=[]
        def concurrent(catalog,*args,**kwargs):
            value=audit(catalog,*args,**kwargs);audits.append(True)
            if not arrivals:arrivals.append(case.append_minute())
            return value
        with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True), \
             mock.patch.object(backup_catalog.ArchiveCatalog,'_checkpoint_inputs',concurrent),mock.patch.object(backup_catalog.ArchiveCatalog,'checkpoint',return_value={}):
            result=executor.run('apply')
        self.assertEqual(result['result'],'APPLIED');self.assertEqual(len(effects),2)
        self.assertEqual(len(audits),3,'An authenticated append already audited by the native view must not repeat preparation')
        self.assertEqual(result['protected_arrival_ids'],arrivals);self.assertIn(arrivals[0],case.native)
        self.assertTrue((store.root/'journals-committed.json').exists())

    def test_append_cannot_heal_a_changed_historical_confirmation(self):
        case,_,executor,store,effects,evidence=self.case();audit=backup_catalog.ArchiveCatalog._checkpoint_inputs;changed=[]
        def corrupt(catalog,*args,**kwargs):
            value=audit(catalog,*args,**kwargs)
            if not changed:
                case.append_minute();path=case.root/'receipts/binlog/state.json';state=runtime.load_json(path)
                state['confirmed'][0]['confirmed_at']='2026-10-12T00:00:00+00:00';runtime.atomic_json(path,state);changed.append(True)
            return value
        with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True), \
             mock.patch.object(backup_catalog.ArchiveCatalog,'_checkpoint_inputs',corrupt),self.assertRaises(guards.GuardError):executor.run('apply')
        self.assertEqual(effects,[]);self.assertFalse(store.path.exists())

    def test_authenticated_append_in_every_preparation_converges_and_keeps_every_arrival(self):
        case,_,executor,store,effects,evidence=self.case();audit=backup_catalog.ArchiveCatalog._checkpoint_inputs;arrivals=[]
        def concurrent(catalog,*args,**kwargs):
            value=audit(catalog,*args,**kwargs)
            if not arrivals:arrivals.append(case.append_minute());return value
            number=len(arrivals)+3;sid=format(number+4096,'064x');token=sid[-32:]
            source=case.root/'cache/new-minute';target=case.root/'cache'/('minute-'+str(number));target.mkdir(mode=0o700);(target/'logs').mkdir(mode=0o700)
            manifest=runtime.load_json(source/'manifest.json');name='suhoput2-binlog.'+format(number,'06d')
            body=(source/'logs/suhoput2-binlog.000003').read_bytes();path=target/'logs'/name;path.write_bytes(body);path.chmod(0o600)
            item={'file':name,'size':len(body),'sha256':hashlib.sha256(body).hexdigest()}
            manifest.update(previous_count=number-1,first_log=number,last_log=number,active_file='suhoput2-binlog.'+format(number+1,'06d'),logs=[item],
                            files=[{'path':'logs/'+name,'bytes':len(body),'sha256':item['sha256']}])
            raw=json.dumps(manifest).encode();(target/'manifest.json').write_bytes(raw);(target/'manifest.json').chmod(0o600)
            meta={'id':sid,'tree':sid,'time':NOW.isoformat(),'paths':[str(case.root/'spool/binlog-payload')],
                  'tags':['task047','generation:'+case.w.c['generation'],'token:'+token,'manifest-sha:'+hashlib.sha256(raw).hexdigest()]}
            case.catalog().admit('binlog',sid,meta,raw,target);case.native[sid]=('binlog',meta)
            journal=case.root/'receipts/binlog/state.json';state=runtime.load_json(journal)
            state['confirmed'].append({'id':sid,'token':token,'manifest_sha256':hashlib.sha256(raw).hexdigest()});runtime.atomic_json(journal,state);arrivals.append(sid)
            return value
        with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True), \
             mock.patch.object(backup_catalog.ArchiveCatalog,'_checkpoint_inputs',concurrent),mock.patch.object(backup_catalog.ArchiveCatalog,'checkpoint',return_value={}):
            result=executor.run('apply')
        self.assertEqual(result['result'],'APPLIED');self.assertEqual(len(effects),2);self.assertEqual(len(arrivals),3)
        self.assertEqual(set(result['protected_arrival_ids']),set(arrivals));self.assertTrue(set(arrivals)<=set(case.native))
        self.assertTrue((store.root/'journals-committed.json').exists())

    def test_repreparation_cannot_heal_changed_repository_receipt_bytes(self):
        case,_,executor,store,effects,evidence=self.case();audit=backup_catalog.ArchiveCatalog._checkpoint_inputs;changed=[]
        def corrupt(catalog,*args,**kwargs):
            value=audit(catalog,*args,**kwargs)
            if not changed:
                path=case.root/'receipts/init-base.json';doc=runtime.load_json(path);doc['extra']='changed';runtime.atomic_json(path,doc);changed.append(True)
            return value
        with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True), \
             mock.patch.object(backup_catalog.ArchiveCatalog,'_checkpoint_inputs',corrupt),self.assertRaisesRegex(guards.GuardError,'Original immutable'):
            executor.run('apply')
        self.assertEqual(effects,[]);self.assertFalse(store.path.exists())

    def test_repreparation_cannot_reseal_a_changed_but_well_formed_earlier_phase(self):
        case,_,executor,store,effects,evidence=self.case();audit=backup_catalog.ArchiveCatalog._checkpoint_inputs;changed=[]
        def corrupt(catalog,*args,**kwargs):
            value=audit(catalog,*args,**kwargs)
            if effects and not changed:
                path=store.root/'phase-0000.json';doc=runtime.load_json(path);doc['extra']='changed'
                doc['phase_sha256']=retention_apply.document_digest({key:value for key,value in doc.items() if key!='phase_sha256'})
                runtime.atomic_json(path,doc);changed.append(True)
            return value
        with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True), \
             mock.patch.object(backup_catalog.ArchiveCatalog,'_checkpoint_inputs',corrupt):result=executor.run('apply')
        self.assertEqual(result['result'],'RECONCILE_REQUIRED');self.assertEqual(len(effects),1)
        self.assertFalse((store.root/'journals-committed.json').exists())

    def test_immutable_phase_reconstruction_is_outside_the_effect_group(self):
        case,_,executor,_,effects,evidence=self.case();active=[False];original=retention_cohort.upload_section;phases=retention_native.IntentStore.phase_documents
        @contextlib.contextmanager
        def section(worker,**kwargs):
            with original(worker,**kwargs) as acquired:
                active[0]=True
                try:yield acquired
                finally:active[0]=False
        def documents(store):
            self.assertFalse(active[0],'Durable equal bytes transfer the already validated phase prefix')
            return phases(store)
        with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True), \
             mock.patch.object(retention_cohort,'upload_section',section),mock.patch.object(retention_native.IntentStore,'phase_documents',documents), \
             mock.patch.object(backup_catalog.ArchiveCatalog,'checkpoint',return_value={}):result=executor.run('apply')
        self.assertEqual(result['result'],'APPLIED');self.assertEqual(len(effects),2)

    def test_four_changed_preparations_stop_before_authorization_or_effect(self):
        case,_,executor,store,effects,evidence=self.case();original=retention_cohort.upload_section;groups=[]
        @contextlib.contextmanager
        def section(worker,**kwargs):
            groups.append(True)
            path=case.root/'receipts/binlog/state.json';path.write_bytes(path.read_bytes()+b'\n')
            with original(worker,**kwargs) as acquired:yield acquired
        with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True), \
             mock.patch.object(retention_cohort,'upload_section',section),self.assertRaisesRegex(guards.GuardError,'Four read-only effect preparations'):
            executor.run('apply')
        self.assertEqual(len(groups),4);self.assertEqual(effects,[]);self.assertFalse(store.path.exists())

    def test_native_only_drift_is_rejected_without_repreparing_or_effect(self):
        case,_,executor,store,effects,evidence=self.case();original=retention_cohort.upload_section;groups=[]
        @contextlib.contextmanager
        def section(worker,**kwargs):
            groups.append(True);case.native[next(iter(case.native))][1]['tree']='0'*64
            with original(worker,**kwargs) as acquired:yield acquired
        with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True), \
             mock.patch.object(retention_cohort,'upload_section',section),self.assertRaises(guards.GuardError):executor.run('apply')
        self.assertEqual(groups,[True]);self.assertEqual(effects,[]);self.assertFalse(store.path.exists())

    def test_expiry_after_preparation_still_blocks_before_durable_authorization(self):
        case,_,executor,store,effects,evidence=self.case();original=retention_cohort.upload_section;at=[NOW]
        @contextlib.contextmanager
        def section(worker,**kwargs):
            at[0]=NOW+dt.timedelta(seconds=901)
            with original(worker,**kwargs) as acquired:yield acquired
        with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True), \
             mock.patch.object(retention_cohort,'clock',side_effect=lambda:at[0]),mock.patch.object(retention_cohort,'upload_section',section), \
             self.assertRaisesRegex(guards.GuardError,'Plan expired immediately'):executor.run('apply')
        self.assertEqual(effects,[]);self.assertFalse(store.path.exists())

    def test_effect_failure_named_preparation_changed_is_never_retried(self):
        case,_,executor,_,effects,evidence=self.case();original=case.w.retention_forget
        def uncertain(*args,**kwargs):
            original(*args,**kwargs);raise retention_apply.PhasePreparationChanged('Lost effect response')
        case.w.retention_forget=uncertain
        with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True):result=executor.run('apply')
        self.assertEqual(result['result'],'RECONCILE_REQUIRED');self.assertEqual(len(effects),1)

    def test_changed_durable_phase_bytes_cannot_inherit_prepared_authority(self):
        case,_,executor,_,effects,evidence=self.case();phase=retention_native.IntentStore.phase;effect=retention_native.ExactRunner.__call__;checked=[]
        def corrupt(store,value):
            phase(store,value);(store.root/('phase-'+format(value['index'],'04d')+'.json')).write_bytes(b'{}\n')
        def verify(runner,*args):
            with self.assertRaisesRegex(guards.GuardError,'Prepared phase authority bytes changed'):effect(runner,*args)
            checked.append(True);raise guards.GuardError('Stop after confirmed corrupt authority rejection')
        with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True), \
             mock.patch.object(retention_native.IntentStore,'phase',corrupt),mock.patch.object(retention_native.ExactRunner,'__call__',verify),self.assertRaises((guards.GuardError,KeyError)):
            executor.run('apply')
        self.assertEqual(checked,[True]);self.assertEqual(effects,[])

    def test_arrival_during_publication_staging_restages_and_preserves_confirmation(self):
        case,_,executor,store,effects,evidence=self.case();stage=retention_native.StagedPublication.stage;arrivals=[]
        def append(writer,value):
            stage(writer,value)
            if not arrivals:arrivals.append(case.append_minute())
        with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True), \
             mock.patch.object(retention_native.StagedPublication,'stage',append),mock.patch.object(backup_catalog.ArchiveCatalog,'checkpoint',return_value={}):result=executor.run('apply')
        self.assertEqual(result['result'],'APPLIED');self.assertEqual(len(effects),2);self.assertEqual(result['protected_arrival_ids'],arrivals)
        self.assertTrue((store.root/'journals-committed.json').exists())
        self.assertIn(arrivals[0],[row['id'] for row in runtime.UploadJournal(case.root/'receipts/binlog',case.w.c['generation']).state()['confirmed']])
        self.assertEqual(list((case.root/'receipts/retention-staging').iterdir()),[])

    def test_publication_promotion_failure_cannot_be_retried_as_preparation(self):
        case,_,executor,_,effects,evidence=self.case();publish=retention_native.StagedPublication.__call__;promoted=[]
        def interrupted(writer,value):
            publish(writer,value)
            if value['result']=='APPLIED':promoted.append(True);raise retention_apply.PhasePreparationChanged('Crash after completed promotion')
        with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True), \
             mock.patch.object(retention_native.StagedPublication,'__call__',interrupted):result=executor.run('apply')
        self.assertEqual(result['result'],'RECONCILE_REQUIRED');self.assertEqual(promoted,[True]);self.assertEqual(len(effects),2)

if __name__=='__main__':unittest.main()
