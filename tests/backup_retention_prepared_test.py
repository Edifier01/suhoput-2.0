"""Native daily preparation and exact final equality; synthetic repositories."""
import contextlib,copy,datetime as dt,json,pathlib,sys,unittest
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
