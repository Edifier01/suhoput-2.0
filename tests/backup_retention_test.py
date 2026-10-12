"""Synthetic retention faults; no S3/credentials/DB/remote deletion."""
import unittest,sys,pathlib,importlib.util,copy,hashlib,json,datetime as dt
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'infra/backup'))
from unittest import mock
import guards,runtime
GEN='a'*32;NOW=dt.datetime(2026,10,12,13,tzinfo=dt.timezone.utc)
def subject():
    unittest.TestCase().assertIsNotNone(importlib.util.find_spec('retention'),'Native inventory-bound retention audit absent')
    import retention
    return retention

def fixture():
    source={'generation':GEN,'root':'/srv/suhoput2-stage-20261011'}
    base={'id':'1'*64,'lane':'base','kind':'full','generation':GEN,'time':'2026-10-12T11:00:00Z','manifest_sha256':'b'*64,'token':'c'*32}
    log={'id':'2'*64,'lane':'binlog','kind':'binlog','generation':GEN,'time':'2026-10-12T12:00:00Z','manifest_sha256':'d'*64,'token':'e'*32}
    manifests={base['id']:{'source':source,'coordinates':{'file':'suhoput2-binlog.000001','position':4},'stage_app_sha':'f'*40,'application_sha256':'3'*64,'configuration_sha256':'4'*64},log['id']:{'source':source,'previous_count':0,'first_log':1,'last_log':2,'logs':[{'file':'suhoput2-binlog.000001','size':400,'sha256':'5'*64},{'file':'suhoput2-binlog.000002','size':500,'sha256':'6'*64}]}}
    return {'generation':GEN,'repositories':{'base':'7'*64,'binlog':'8'*64},'snapshots':[base,log],'manifests':manifests}
class InventoryBoundTests(unittest.TestCase):
    def test_many_base_coordinates_validate_the_chain_once_without_multiplicative_rescans(self):
        m=subject();inventory=fixture();manifest=inventory['manifests']['2'*64]
        manifest.update(first_log=1,last_log=100,previous_count=0,logs=[{'file':'suhoput2-binlog.%06d'%i,'size':500,'sha256':'5'*64} for i in range(1,101)])
        for i in range(24):
            sid=format(i+4096,'064x');inventory['snapshots'].append({**inventory['snapshots'][0],'id':sid,'token':sid[:32]})
            inventory['manifests'][sid]=copy.deepcopy(inventory['manifests']['1'*64]);inventory['manifests'][sid]['coordinates']['file']='suhoput2-binlog.%06d'%(i+1)
        checked=[0];original=guards.checked_logs
        def count(items):checked[0]+=len(items);return original(items)
        with mock.patch.object(guards,'checked_logs',count):plan=m.inventory_plan(inventory,NOW)
        self.assertEqual(plan['chain_last_file'],'suhoput2-binlog.000100')
        self.assertLessEqual(checked[0],300,'Each base rescans the entire already validated chain')
    def test_order_independent_digest_binds_repository_manifest_and_entire_inventory(self):
        m=subject();a=fixture();b=copy.deepcopy(a);b['snapshots'].reverse();self.assertEqual(m.inventory_digest(a),m.inventory_digest(b))
        for field in ('repository','manifest','extra'):
            b=copy.deepcopy(a)
            if field=='repository':b['repositories']['base']='9'*64
            if field=='manifest':b['snapshots'][0]['manifest_sha256']='9'*64
            if field=='extra':b['snapshots'].append({**b['snapshots'][0],'id':'9'*64})
            self.assertNotEqual(m.inventory_digest(a),m.inventory_digest(b))
            with self.assertRaises(guards.GuardError):m.same_inventory(a,b)
    def test_current_short_history_keeps_anchor_and_all_logs_without_authorizing_delete(self):
        m=subject();p=m.inventory_plan(fixture(),NOW);self.assertEqual(p['anchor_id'],'1'*64);self.assertEqual(p['keep'],['1'*64,'2'*64]);self.assertFalse(p['apply_allowed']);self.assertFalse(p['history_coverage_verified'])
    def test_missing_gap_overlap_or_reversed_manifest_range_is_rejected(self):
        m=subject()
        for change in ('gap','overlap','range','count','no_logs'):
            a=fixture();log=a['manifests']['2'*64]
            if change=='gap':log['logs'][1]['file']='suhoput2-binlog.000003'
            if change=='overlap':log['logs'][1]=copy.deepcopy(log['logs'][0])
            if change=='range':log['last_log']=3
            if change=='count':log['previous_count']=1
            if change=='no_logs':a['snapshots']=a['snapshots'][:1]
            with self.subTest(change=change),self.assertRaises(guards.GuardError):m.inventory_plan(a,NOW)
    def test_coherent_manifest_range_cannot_hide_missing_interior_log(self):
        m=subject();a=fixture();log=a['manifests']['2'*64];log['logs'][1]['file']='suhoput2-binlog.000003';log['last_log']=3
        with self.assertRaises(guards.GuardError):m.inventory_plan(a,NOW)
    def test_archive_coordinate_outside_chain_is_rejected(self):
        m=subject()
        for coordinate in ({'file':'suhoput2-binlog.000003','position':4},{'file':'suhoput2-binlog.000001','position':401}):
            a=fixture();a['manifests']['1'*64]['coordinates']=coordinate
            with self.assertRaises(guards.GuardError):m.inventory_plan(a,NOW)
    def proof(self):
        return {'result':'PASS','base_id':'1'*64,'base_manifest_sha256':'b'*64,'full_id':'1'*64,'full_manifest_sha256':'b'*64,'source':fixture()['manifests']['1'*64]['source'],'stage_app_sha':'f'*40,'coordinates':{'file':'suhoput2-binlog.000001','position':4},'stop':{'file':'suhoput2-binlog.000002','position':400},'replayed_logs':2,'verified_binlogs':fixture()['manifests']['2'*64]['logs'],'media':{'inventory':[]},'synthetic_order_after_base':True,'synthetic_operation_after_base':True,'later_order_operation_excluded':True}
    def test_restore_binding_requires_exact_anchor_digest_source_and_coordinates(self):
        m=subject();a=fixture();p=m.inventory_plan(a,NOW);m.bind_recovery(a,p,self.proof())
        for key,bad in [('base_id','9'*64),('base_manifest_sha256','9'*64),('source',{'generation':'9'*32}),('coordinates',{'file':'suhoput2-binlog.000001','position':5}),('replayed_logs',1),('full_manifest_sha256','9'*64)]:
            proof=self.proof();proof[key]=bad
            with self.subTest(key=key),self.assertRaises(guards.GuardError):m.bind_recovery(a,p,proof)
    def test_exact_tip_presence_receipt_requires_actual_tip_without_false_exclusion(self):
        m=subject();a=fixture();p=m.inventory_plan(a,NOW);proof={**self.proof(),'profile':'tip','stop':{'file':'suhoput2-binlog.000002','position':500},'later_order_operation_excluded':False,'additional_order_operation_present':True}
        m.bind_recovery(a,p,proof)
        for changed in ({'additional_order_operation_present':False},{'later_order_operation_excluded':True},{'stop':{'file':'suhoput2-binlog.000002','position':499}},{'profile':'arbitrary'}):
            with self.subTest(change=changed),self.assertRaises(guards.GuardError):m.bind_recovery(a,p,{**proof,**changed})
    def test_boolean_attestation_never_substitutes_native_receipt(self):
        m=subject();a=fixture();p=m.inventory_plan(a,NOW)
        with self.assertRaises(guards.GuardError):m.bind_recovery(a,p,{'restored':True,'integrity':True,'anchor_id':'1'*64})
    def test_full_needed_by_hourly_is_retained_and_bound_to_same_app(self):
        m=subject();a=fixture();full=a['snapshots'][0];full['time']='2026-09-01T11:00:00Z';hourly={**full,'id':'9'*64,'kind':'hourly','time':'2026-09-11T11:00:00Z'};a['snapshots'].append(hourly);a['manifests'][hourly['id']]={**a['manifests'][full['id']],'full_id':full['id']}
        p=m.inventory_plan(a,NOW);self.assertIn(full['id'],p['keep']);self.assertEqual(p['anchor_id'],hourly['id'])
        a['manifests'][hourly['id']]['application_sha256']='0'*64
        with self.assertRaises(guards.GuardError):m.inventory_plan(a,NOW)
    def test_missing_initial_prefix_and_hole_after_restore_stop_are_rejected(self):
        m=subject()
        for change in ('prefix','after_stop'):
            a=fixture();log=a['manifests']['2'*64]
            if change=='prefix':
                log['logs'][0]['file']='suhoput2-binlog.000002';log['logs'][1]['file']='suhoput2-binlog.000003';log['first_log']=2;log['last_log']=3;a['manifests']['1'*64]['coordinates']['file']='suhoput2-binlog.000002'
            else:log['logs'].append({'file':'suhoput2-binlog.000004','size':500,'sha256':'7'*64});log['last_log']=4
            with self.subTest(change=change),self.assertRaises(guards.GuardError):m.inventory_plan(a,NOW)
    def test_recovery_count_cannot_replace_selected_archive_hash_binding(self):
        m=subject();a=fixture();proof=self.proof();a['manifests']['2'*64]['logs'][0]['sha256']='9'*64;p=m.inventory_plan(a,NOW)
        with self.assertRaises(guards.GuardError):m.bind_recovery(a,p,proof)
    def test_expired_hourly_candidate_cannot_reference_future_full(self):
        m=subject();a=fixture();full=a['snapshots'][0];old={**full,'id':'3'*64,'time':'2026-09-10T11:00:00Z'};hourly={**full,'id':'9'*64,'kind':'hourly','time':'2026-09-01T11:00:00Z'};a['snapshots'].extend([old,hourly]);a['manifests'][old['id']]=copy.deepcopy(a['manifests'][full['id']]);a['manifests'][hourly['id']]={**a['manifests'][full['id']],'full_id':full['id']}
        with self.assertRaises(guards.GuardError):m.inventory_plan(a,NOW)
class NativeInventoryFaults(unittest.TestCase):
    def worker(self):
        from types import SimpleNamespace
        import tempfile,os
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);root=pathlib.Path(temp.name);os.chmod(root,0o700)
        for name in ('receipts','cache','spool'):(root/name).mkdir(mode=0o700)
        for lane,digit in [('base','7'),('binlog','8')]:runtime.atomic_json(root/'receipts'/('init-'+lane+'.json'),{'generation':GEN,'repository_id':digit*64})
        self.source={'root':'/srv/suhoput2-stage-20261011','generation':GEN};scope=str(root/'spool'/'base-payload')
        self.payload={'format':1,'generation':GEN,'source':self.source,'kind':'full','code_sha':'f'*40,'stage_app_sha':'f'*40,'captured_at':'2026-10-12T11:00:00Z','files':[]}
        self.body=json.dumps(self.payload).encode();self.metadata={'paths':[scope],'tree':'2'*64,'time':'2026-10-12T11:01:00Z','tags':['task047','generation:'+GEN,'token:'+'c'*32,'manifest-sha:'+hashlib.sha256(self.body).hexdigest()]};self.foreign=False;self.duplicate=False;self.commands=[];self.partial_list=False
        def restic(lane,args):
            command=args[2:]
            self.commands.append(command)
            if command==['cat','config']:return json.dumps({'version':2,'id':('7' if lane=='base' else '8')*64}).encode()
            if command==['snapshots','--json']:
                rows=[{'id':'1'*64,**({} if self.partial_list else self.metadata)}] if lane=='base' else []
                return json.dumps(rows*2 if self.duplicate else rows).encode()
            if command[:2]==['cat','snapshot']:return json.dumps(self.metadata).encode()
            if command[0]=='dump':return self.body
            raise AssertionError('Unexpected/destructive operation')
        w=SimpleNamespace(root=root,source=self.source,c={'generation':GEN,'code_sha':'f'*40,'stage_app_sha':'f'*40,'repositories':{'base':'base','binlog':'binlog'}},restic=restic)
        # Synthetic callback: real store/file verification, no native proof claim.
        def verify(lane,sid,manifest,**proof):
            import backup_catalog
            restored=root/'cache'/'synthetic-readback';restored.mkdir(mode=0o700,exist_ok=True)
            (restored/'manifest.json').write_bytes(proof['raw_manifest']);os.chmod(restored/'manifest.json',0o600)
            backup_catalog.ArchiveCatalog(w).admit(lane,sid,proof['native_metadata'],proof['raw_manifest'],restored)
            return True
        w.verify_archive=verify;return w
    def test_authenticate_unfiltered_inventory_and_reject_foreign_path_generation_digest_future_duplicate(self):
        m=subject();w=self.worker();ids={'base':'7'*64,'binlog':'8'*64};self.assertEqual(len(m.native_inventory(w,NOW,ids)['snapshots']),1)
        for mutation in ('path','generation','digest','future','duplicate','repository'):
            w=self.worker();expected=dict(ids)
            if mutation=='path':self.metadata['paths']=['/srv/production']
            if mutation=='generation':self.metadata['tags'][1]='generation:'+'0'*32
            if mutation=='digest':self.body+=b' '
            if mutation=='future':self.metadata['time']='2026-10-13T11:00:00Z'
            if mutation=='duplicate':self.duplicate=True
            if mutation=='repository':expected['base']='9'*64
            with self.subTest(mutation=mutation),self.assertRaises(guards.GuardError):m.native_inventory(w,NOW,expected)
    def test_unknown_or_missing_acknowledged_snapshot_stops_audit(self):
        m=subject();a=fixture();journals={lane:{'confirmed':[{'id':row['id'],'token':row['token'],'manifest_sha256':row['manifest_sha256']} for row in a['snapshots'] if row['lane']==lane]} for lane in ('base','binlog')};m.confirmed_inventory(a,journals)
        for mutation in ('unknown','missing','digest'):
            bad=copy.deepcopy(a)
            if mutation=='unknown':bad['snapshots'].append({**bad['snapshots'][0],'id':'9'*64})
            if mutation=='missing':bad['snapshots']=bad['snapshots'][1:]
            if mutation=='digest':bad['snapshots'][0]['manifest_sha256']='9'*64
            with self.assertRaises(guards.GuardError):m.confirmed_inventory(bad,journals)

    def test_trusted_observation_clock_accepts_snapshot_uploaded_during_scan(self):
        m=subject();w=self.worker();self.metadata['time']=(NOW+dt.timedelta(seconds=1)).isoformat()
        result=m.native_inventory(w,NOW,{'base':'7'*64,'binlog':'8'*64},lambda:NOW+dt.timedelta(seconds=2))
        self.assertEqual(len(result['snapshots']),1)
        self.assertEqual(guards.utc(result['observed_at']),NOW+dt.timedelta(seconds=2))

    def test_native_authenticated_listing_reuses_metadata_without_per_snapshot_cat(self):
        m=subject();w=self.worker();result=m.native_inventory(w,NOW,{'base':'7'*64,'binlog':'8'*64})
        self.assertEqual(len(result['snapshots']),1)
        self.assertFalse(any(cmd[:2]==['cat','snapshot'] for cmd in self.commands))
        self.assertEqual(len(self.commands),5)

    def test_partial_native_listing_metadata_is_rejected(self):
        m=subject();w=self.worker();self.partial_list=True
        with self.assertRaises(guards.GuardError):m.native_inventory(w,NOW,{'base':'7'*64,'binlog':'8'*64})

    def test_warm_inventory_requires_no_per_snapshot_dump_restore_or_full_array_expansion(self):
        import backup_catalog
        m=subject();w=self.worker();ids={'base':'7'*64,'binlog':'8'*64}
        first=m.native_inventory(w,NOW,ids);self.commands=[]
        with mock.patch('backup_catalog.inflate',side_effect=AssertionError('Warm inventory expanded raw files')):
            second=m.native_inventory(w,NOW,ids)
        self.assertEqual(first['snapshots'],second['snapshots']);self.assertNotIn('files',second['manifests']['1'*64])
        self.assertEqual(self.commands,[['cat','config'],['snapshots','--json'],['cat','config'],['snapshots','--json']])

    def test_warm_native_tree_scope_and_repository_drift_fail_closed(self):
        m=subject();ids={'base':'7'*64,'binlog':'8'*64}
        for field,value in [('tree','9'*64),('time','2026-10-12T11:02:00Z'),('paths',['/foreign'])]:
            w=self.worker();m.native_inventory(w,NOW,ids);self.metadata[field]=value
            with self.subTest(field=field),self.assertRaises(guards.GuardError):m.native_inventory(w,NOW,ids)

    def test_boolean_readback_cannot_admit_a_catalog_record(self):
        m=subject();w=self.worker();w.verify_archive=lambda *a,**proof:True
        with self.assertRaises(guards.GuardError):m.native_inventory(w,NOW,{'base':'7'*64,'binlog':'8'*64})

    def test_advancing_observation_clock_still_rejects_future_and_rollback(self):
        m=subject()
        for uploaded,observed in ((NOW+dt.timedelta(seconds=3),NOW+dt.timedelta(seconds=2)),(NOW,NOW-dt.timedelta(seconds=1))):
            w=self.worker();self.metadata['time']=uploaded.isoformat()
            with self.subTest(uploaded=uploaded),self.assertRaises(guards.GuardError):
                m.native_inventory(w,NOW,{'base':'7'*64,'binlog':'8'*64},lambda:observed)
if __name__=='__main__':unittest.main()
