"""Synthetic retention faults; no S3/credentials/DB/remote deletion."""
import unittest,sys,pathlib,importlib.util,copy,hashlib,json,datetime as dt
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'infra/backup'))
import guards
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
        self.source={'root':'/srv/suhoput2-stage-20261011','generation':GEN};scope='/srv/suhoput2-stage-20261011/backup/spool/base-payload'
        self.payload={'format':1,'generation':GEN,'source':self.source,'kind':'full','code_sha':'f'*40,'stage_app_sha':'f'*40,'captured_at':'2026-10-12T11:00:00Z','files':[]}
        self.body=json.dumps(self.payload).encode();self.metadata={'paths':[scope],'time':'2026-10-12T11:01:00Z','tags':['task047','generation:'+GEN,'token:'+'c'*32,'manifest-sha:'+hashlib.sha256(self.body).hexdigest()]};self.foreign=False;self.duplicate=False
        def restic(lane,args):
            command=args[2:]
            if command==['cat','config']:return json.dumps({'version':2,'id':('7' if lane=='base' else '8')*64}).encode()
            if command==['snapshots','--json']:
                rows=[{'id':'1'*64}] if lane=='base' else []
                return json.dumps(rows*2 if self.duplicate else rows).encode()
            if command[:2]==['cat','snapshot']:return json.dumps(self.metadata).encode()
            if command[0]=='dump':return self.body
            raise AssertionError('Unexpected/destructive operation')
        return SimpleNamespace(root=pathlib.PurePosixPath('/srv/suhoput2-stage-20261011/backup'),source=self.source,c={'generation':GEN,'stage_app_sha':'f'*40,'repositories':{'base':'base','binlog':'binlog'}},restic=restic)
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
if __name__=='__main__':unittest.main()
