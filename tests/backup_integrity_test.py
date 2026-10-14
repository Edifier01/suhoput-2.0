"""Full remote reads stay distinct from fresh metadata and verified arrivals."""
import copy, datetime as dt, hashlib, os, pathlib, sys, unittest
from types import SimpleNamespace
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'infra/backup'))
import guards

class AuditRecoveryDispatchTests(unittest.TestCase):
    def test_native_v2_audit_verifies_both_operational_profiles_and_preserves_legacy(self):
        import retention,retention_restore
        audit=object.__new__(retention.Inspector);audit.w=SimpleNamespace(c={'retention_readiness_policy':'native-v2'})
        inv={'snapshots':[{'id':'a'*64,'lane':'base','time':'2026-10-11T00:00:00Z'},
                          {'id':'b'*64,'lane':'base','time':'2026-10-12T00:00:00Z'}]};plan={'anchor_id':'a'*64}
        profiles=[];bindings=[]
        def recovery(worker,profile):
            profiles.append(profile)
            return SimpleNamespace(verify_existing=lambda:{'profile':profile,'verified_binlogs':[]})
        def bind(inventory,selected,proof):
            bindings.append((proof['profile'],selected['anchor_id']));return {'base_id':selected['anchor_id']}
        with mock.patch.object(retention_restore,'RetentionRecovery',side_effect=recovery),mock.patch.object(retention_restore,'bind_recovery',side_effect=bind),mock.patch.object(retention,'Recovery',side_effect=AssertionError('Legacy synthetic restore used')):
            result=audit.recovery_checks(inv,plan)
        self.assertEqual(profiles,['anchor','tip']);self.assertEqual(bindings,[('anchor','a'*64),('tip','b'*64)])
        self.assertEqual(result['tip'][1],{'base_id':'b'*64})
        with mock.patch.object(retention_restore,'RetentionRecovery',return_value=SimpleNamespace(verify_existing=lambda:{'profile':'tip'})):
            with self.assertRaises(guards.GuardError):audit.recovery_checks(inv,plan)

class IntegrityTests(unittest.TestCase):
    def setUp(self):
        import integrity
        self.m=integrity;self.at=dt.datetime(2026,10,13,tzinfo=dt.timezone.utc)
        self.a='a'*64;self.b='b'*64
        self.one=['c'*64,'d'*32,'e'*64]
        self.two=['f'*64,'1'*32,'2'*64]
        self.proof={'started_at':(self.at-dt.timedelta(days=2)).isoformat(),'completed_at':(self.at-dt.timedelta(days=2,seconds=-5)).isoformat(),'snapshots':{self.a:self.one}}
    def test_reuse_does_not_refresh_full_remote_timestamp(self):
        result=self.m.coverage(self.proof,{self.a:self.one},[],{},at=self.at,lane='binlog')
        self.assertEqual(result['full_remote_completed_at'],self.proof['completed_at'])
        self.assertEqual(result['verified_arrivals'],0)
    def test_admitted_new_archives_and_exact_retirements_preserve_coverage(self):
        retired=[{'id':self.a,'lane':'binlog','token':self.one[1],'manifest_sha256':self.one[2]}]
        result=self.m.coverage(self.proof,{self.b:self.two},retired,{self.b:self.two},at=self.at,lane='binlog')
        self.assertEqual(result['verified_arrivals'],1)
        self.assertEqual(result['verified_retirements'],1)
        for tombstones,admitted in (([],{self.b:self.two}),(retired,{})):
            with self.assertRaises(guards.GuardError):self.m.coverage(self.proof,{self.b:self.two},tombstones,admitted,at=self.at,lane='binlog')
    def test_changed_or_reappearing_snapshot_blocks(self):
        with self.assertRaises(guards.GuardError):self.m.coverage(self.proof,{self.a:self.two},[],{},at=self.at,lane='binlog')
        retired=[{'id':self.a,'lane':'binlog','token':self.one[1],'manifest_sha256':self.one[2]}]
        with self.assertRaises(guards.GuardError):self.m.coverage(self.proof,{self.a:self.one},retired,{},at=self.at,lane='binlog')
    def test_expiry_rollback_partial_identity_and_duplicate_tombstone_block(self):
        for at in (self.at+dt.timedelta(days=6),self.at-dt.timedelta(days=3)):
            with self.assertRaises(guards.GuardError):self.m.coverage(self.proof,{self.a:self.one},[],{},at=at,lane='binlog')
        for current in ({self.a:None},{self.a:self.one[:2]}):
            with self.assertRaises(guards.GuardError):self.m.coverage(self.proof,current,[],{},at=self.at,lane='binlog')
        retired={'id':self.a,'lane':'binlog','token':self.one[1],'manifest_sha256':self.one[2]}
        with self.assertRaises(guards.GuardError):self.m.coverage(self.proof,{},[retired,retired],{},at=self.at,lane='binlog')

@unittest.skipIf(os.name!='posix','Protected runtime ownership requires Linux root')
class ProtectedIntegrityTests(unittest.TestCase):
    def setUp(self):
        import backup_catalog_test as fixture, integrity, runtime
        self.case=fixture.CatalogTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.m=integrity;self.r=runtime;self.w=self.case.w;self.c=self.case.catalog();self.case.admit(self.c)
        self.w.bin=self.w.root/'bin';self.w.bin.mkdir(mode=0o700)
        for name in integrity.PRODUCERS:
            path=self.w.bin/name;path.write_bytes(('# installed protected '+name+'\n').encode());path.chmod(0o600)
        self.at=dt.datetime(2026,10,13,tzinfo=dt.timezone.utc);self.current=[self.at]
        self.enterContext(mock.patch.object(integrity,'clock',side_effect=lambda:self.current[0]))
        record=self.c.entries()[fixture.SID]
        self.inv={'generation':self.w.c['generation'],'repositories':{'base':'7'*64,'binlog':'8'*64},
                  'snapshots':[{'id':fixture.SID,'lane':'base','tree':fixture.TREE,'token':fixture.TOKEN,
                    'manifest_sha256':record['manifest_sha256'],'snapshot_time':record['native']['time']}],
                  'manifests':{fixture.SID:record['projection']}}
        for lane in ('base','binlog'):
            directory=self.w.root/'receipts'/lane;directory.mkdir(mode=0o700)
            runtime.atomic_json(directory/'state.json',{'generation':self.w.c['generation'],
                'confirmed':[{'id':r['id'],'token':r['token'],'manifest_sha256':r['manifest_sha256']} for r in self.inv['snapshots'] if r['lane']==lane]})
        self.calls=[]
        def native(lane,args,**kwargs):
            self.assertEqual(args,['--repo',self.w.c['repositories'][lane],'check','--read-data'])
            self.assertEqual(kwargs,{'timeout':900});self.calls.append(lane);return b''
        self.w.restic=native
        import retention_native
        self.enterContext(mock.patch.object(retention_native,'verified_tombstones',return_value=[]))
    def test_actual_check_publication_reuse_and_expiry_preserve_original_time(self):
        first=self.m.ensure(self.w,self.inv);self.assertEqual(self.calls,['base','binlog'])
        self.current[0]+=dt.timedelta(days=2);again=self.m.ensure(self.w,self.inv)
        self.assertEqual(self.calls,['base','binlog']);self.assertEqual(first['lanes'],again['lanes'])
        self.assertTrue(self.m.revalidate(self.w,again,at=self.current[0]))
        self.current[0]+=dt.timedelta(days=6)
        with self.assertRaises(guards.GuardError):self.m.revalidate(self.w,again,at=self.current[0])
        refreshed=self.m.ensure(self.w,self.inv);self.assertEqual(self.calls,['base','binlog']*2)
        self.assertEqual(refreshed['lanes']['base']['full_remote_completed_at'],self.current[0].isoformat())
    def test_failed_read_never_publishes_and_pending_maintenance_blocks_even_force(self):
        import worker
        self.w.restic=mock.Mock(side_effect=worker.NativeError('failed remote read'))
        with self.assertRaises(worker.NativeError):self.m.ensure(self.w,self.inv)
        self.assertFalse((self.w.root/'receipts/integrity/full-base.json').exists())
        directory=self.w.root/'receipts/maintenance';directory.mkdir(mode=0o700)
        self.r.atomic_json(directory/'pending-base.json',{'unresolved':True})
        with self.assertRaises(guards.GuardError):self.m.ensure(self.w,self.inv,force=True)
        self.assertEqual(self.w.restic.call_count,1)
    def test_nonce_invalidation_blocks_reference_then_requires_actual_new_read(self):
        report=self.m.ensure(self.w,self.inv);self.m.invalidate_lane(self.w,'base')
        with self.assertRaises(guards.GuardError):self.m.revalidate(self.w,report,at=self.at)
        new=self.m.ensure(self.w,self.inv);self.assertEqual(self.calls,['base','binlog','base'])
        self.assertNotEqual(new['lanes']['base']['nonce'],report['lanes']['base']['nonce'])
    def test_map_header_source_or_producer_tamper_blocks_without_remote_repair(self):
        for change in ('map','header','source','producer'):
            if change!='map':self.setUp()
            report=self.m.ensure(self.w,self.inv);root=self.w.root/'receipts/integrity'
            if change=='map':
                path=root/'maps'/(report['lanes']['base']['snapshots_sha256']+'.json');path.write_bytes(path.read_bytes()+b' ')
            elif change=='header':
                path=root/'full-base.json';value=self.r.load_json(path);value['completed_at']=self.at.isoformat()+'changed';self.r.atomic_json(path,value)
            elif change=='source':self.w.source={**self.w.source,'root':'/foreign'}
            else:(self.w.bin/'maintenance.py').write_bytes(b'changed')
            with self.subTest(change=change),self.assertRaises(guards.GuardError):self.m.ensure(self.w,self.inv,force=True)
            self.assertEqual(self.calls,['base','binlog'])
    def test_current_native_claim_requires_real_catalog_and_upload_confirmation(self):
        self.m.ensure(self.w,self.inv)
        for change in ('native','journal'):
            if change=='native':self.inv['snapshots'][0]['tree']='9'*64
            else:
                self.inv['snapshots'][0]['tree']='2'*64
                self.r.atomic_json(self.w.root/'receipts/base/state.json',{'generation':self.w.c['generation'],'confirmed':[]})
            with self.subTest(change=change),self.assertRaises(guards.GuardError):self.m.ensure(self.w,self.inv)
        self.assertEqual(self.calls,['base','binlog'])
    def test_real_admission_and_exact_retirement_reuse_the_original_read(self):
        import backup_catalog_test as fixture,retention_native
        first=self.m.ensure(self.w,self.inv);sid='4'*64;token='5'*32
        metadata={**self.case.meta,'id':sid,'tags':[tag.replace(fixture.TOKEN,token) for tag in self.case.meta['tags']]}
        self.c.admit('base',sid,metadata,self.case.raw,self.case.restored)
        row={**self.inv['snapshots'][0],'id':sid,'token':token};self.inv['snapshots'].append(row)
        state=self.r.load_json(self.w.root/'receipts/base/state.json');state['confirmed'].append({key:row[key] for key in ('id','token','manifest_sha256')})
        self.r.atomic_json(self.w.root/'receipts/base/state.json',state)
        added=self.m.ensure(self.w,self.inv);self.assertEqual(added['lanes']['base']['verified_arrivals'],1)
        old=self.inv['snapshots'].pop(0);retired=[{**old,'generation':self.w.c['generation'],
            'forgotten_at':self.at.isoformat(),**{key:'9'*64 for key in
                ('intent_sha256','receipt_sha256','pre_inventory_sha256','post_inventory_sha256')}}]
        with mock.patch.object(retention_native,'verified_tombstones',return_value=retired):
            removed=self.m.ensure(self.w,self.inv)
        self.assertEqual(removed['lanes']['base']['verified_retirements'],1)
        self.assertEqual(removed['lanes']['base']['full_remote_completed_at'],first['lanes']['base']['full_remote_completed_at'])
        self.assertEqual(self.calls,['base','binlog'])
    def test_frozen_cohort_reuses_authenticated_current_arrivals_without_recapture(self):
        import backup_catalog_test as fixture
        frozen=copy.deepcopy(self.inv);sid='4'*64;token='5'*32
        metadata={**self.case.meta,'id':sid,'tags':[tag.replace(fixture.TOKEN,token) for tag in self.case.meta['tags']]}
        self.c.admit('base',sid,metadata,self.case.raw,self.case.restored)
        row={**self.inv['snapshots'][0],'id':sid,'token':token};self.inv['snapshots'].append(row)
        state=self.r.load_json(self.w.root/'receipts/base/state.json');state['confirmed'].append({key:row[key] for key in ('id','token','manifest_sha256')})
        self.r.atomic_json(self.w.root/'receipts/base/state.json',state)
        report=self.m.ensure(self.w,frozen,current_inventory=self.inv)
        self.assertEqual(report['lanes']['base']['current_snapshot_count'],1)
        self.assertEqual(report['lanes']['base']['observed_current_snapshot_count'],2)
        self.assertTrue(self.m.validate_report(report,frozen,self.at))
        self.m.ensure(self.w,frozen,current_inventory=self.inv);self.assertEqual(self.calls,['base','binlog'])
        frozen['snapshots'][0]['tree']='9'*64
        with self.assertRaises(guards.GuardError):self.m.ensure(self.w,frozen,current_inventory=self.inv)
        self.assertEqual(self.calls,['base','binlog'])
    def test_trusted_cleanup_publication_can_replace_invalidated_proof_but_pending_still_blocks_use(self):
        first=self.m.ensure(self.w,self.inv);self.m.invalidate_lane(self.w,'base')
        directory=self.w.root/'receipts/maintenance';directory.mkdir(mode=0o700)
        self.r.atomic_json(directory/'pending-base.json',{'native_completion':'trusted cleanup fixture'})
        self.w.restic('base',['--repo',self.w.c['repositories']['base'],'check','--read-data'],timeout=900)
        self.m.publish_lane(self.w,'base','7'*64,[self.case.meta],self.at.isoformat(),self.at.isoformat())
        with self.assertRaises(guards.GuardError):self.m.ensure(self.w,self.inv)
        (directory/'pending-base.json').unlink()
        final=self.m.ensure(self.w,self.inv)
        self.assertNotEqual(first['lanes']['base']['nonce'],final['lanes']['base']['nonce'])
        self.assertEqual(self.calls,['base','binlog','base'])
    def test_phase_revalidation_uses_no_catalog_or_remote_access(self):
        report=self.m.ensure(self.w,self.inv)
        with mock.patch.object(self.m.backup_catalog,'ArchiveCatalog',side_effect=AssertionError('Critical graph scan')),mock.patch.object(self.w,'restic',side_effect=AssertionError('Critical remote I/O')):
            self.assertTrue(self.m.revalidate(self.w,report,at=self.at))
            self.assertEqual(set(self.m.status(self.w,at=self.at)),{'base','binlog'})
    def test_v2_phase_refuses_invalidated_weekly_authority_without_native_retry(self):
        import readiness_v2,retention_apply
        report=self.m.ensure(self.w,self.inv);budget={'synthetic':'already tested protected budget loader'}
        evidence={name:{'document':{},'sha256':'0'*64} for name in retention_apply.NATIVE_V2_EVIDENCE_TYPES}
        evidence['budget']={'document':budget,'sha256':retention_apply.document_digest(budget)}
        evidence['audit']['document']={'check_mode':self.m.MODE,'full_remote_integrity':report}
        with mock.patch.object(readiness_v2.budget,'load_commissioning_budget',return_value=budget),mock.patch.object(readiness_v2,'_live'):
            self.assertTrue(readiness_v2.revalidate_budget(self.w,evidence,at=self.at))
            self.m.invalidate_lane(self.w,'base')
            with self.assertRaises(guards.GuardError):readiness_v2.revalidate_budget(self.w,evidence,at=self.at)
        self.assertEqual(self.calls,['base','binlog'])
    def test_invalidation_during_remote_check_cannot_publish_using_new_nonce(self):
        native=self.w.restic
        def interrupted(lane,args,**kwargs):
            result=native(lane,args,**kwargs);self.m.invalidate_lane(self.w,lane);return result
        self.w.restic=interrupted
        with self.assertRaises(guards.GuardError):self.m.ensure(self.w,self.inv)
        self.assertFalse((self.w.root/'receipts/integrity/full-base.json').exists())

if __name__=='__main__':unittest.main()
