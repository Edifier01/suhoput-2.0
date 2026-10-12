"""Synthetic bounded retention faults; no network or real deletion."""
import copy, datetime as dt, hashlib, importlib.util, json, pathlib, sys, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'infra/backup'))
import guards, retention
NOW = dt.datetime(2026, 10, 12, 13, tzinfo=dt.timezone.utc)
GEN = 'a' * 32
OLD, ANCHOR, TIP, LOG = [x * 64 for x in '1234']
SOURCE = {'generation': GEN, 'root': '/srv/suhoput2-stage-20261011'}
def subject():
    unittest.TestCase().assertIsNotNone(importlib.util.find_spec('retention_apply'), 'Bounded apply executor absent')
    import retention_apply
    return retention_apply
def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
def fixture(split=False):
    rows=[]; manifests={}
    for sid, stamp, file in [(OLD, '2026-08-01T12:00:00Z', 1), (ANCHOR, '2026-09-11T12:00:00Z', 2), (TIP, '2026-10-12T12:00:00Z', 2)]:
        rows.append({'id':sid, 'lane':'base', 'kind':'full', 'generation':GEN, 'time':stamp, 'snapshot_time':stamp, 'token':sid[:32], 'manifest_sha256':sid})
        manifests[sid]={'source':SOURCE, 'coordinates':{'file':'suhoput2-binlog.%06d'%file, 'position':4}, 'stage_app_sha':'f'*40, 'application_sha256':'5'*64, 'configuration_sha256':'6'*64}
    rows.append({'id':LOG, 'lane':'binlog', 'kind':'binlog', 'generation':GEN, 'time':'2026-10-12T12:00:00Z', 'snapshot_time':'2026-10-12T12:00:00Z', 'token':LOG[:32], 'manifest_sha256':LOG})
    logs=[{'file':'suhoput2-binlog.%06d'%i, 'size':500, 'sha256':str(i)*64} for i in (1,2)]
    manifests[LOG]={'source':SOURCE, 'first_log':1, 'last_log':2, 'previous_count':0, 'logs':logs}
    if split:
        old_log='5'*64
        rows.append({'id':old_log,'lane':'binlog','kind':'binlog','generation':GEN,'time':'2026-08-02T12:00:00Z','snapshot_time':'2026-08-02T12:00:00Z','token':'5'*32,'manifest_sha256':old_log})
        manifests[old_log]={'source':SOURCE,'first_log':1,'last_log':1,'previous_count':0,'logs':[logs[0]]}
        manifests[LOG]={'source':SOURCE,'first_log':2,'last_log':2,'previous_count':1,'logs':[logs[1]]}
    inventory={'generation':GEN, 'repositories':{'base':'7'*64,'binlog':'8'*64}, 'snapshots':rows,'manifests':manifests}
    plan=retention.inventory_plan(inventory,NOW); plan['planned_at']='2026-10-12T13:00:00Z'
    common={'result':'PASS','generation':GEN,'repositories':inventory['repositories'],'source':SOURCE,'inventory_sha256':plan['inventory_sha256'],'started_at':'2026-10-12T12:30:00Z','completed_at':'2026-10-12T13:00:00Z'}
    docs={'audit':{**common,'checked_repositories':inventory['repositories'],'readback_snapshots':{r['id']:r['manifest_sha256'] for r in rows},'verified_binlogs':logs,'check_mode':'read-data','binlog_check_mode':'native-checksum'},
          'history':{**common,'observed_from':'2026-09-01T12:00:00Z','observed_until':plan['planned_at'],'observation_source':'native-confirmed-upload-journal','journal_sha256':'9'*64},
          'budget':{**common,'measurement_from':'2026-10-01T00:00:00Z','measurement_until':'2026-10-12T12:30:00Z','provider_usage_sha256':'9'*64,'account_billing_sha256':'b'*64,'tariff_sha256':'c'*64,'projected_monthly_rub':300,'projected_storage_bytes':1000000,'measured_requests':{'PUT':100,'GET':200,'DELETE':0},'measured_egress_bytes':1024},
          'owner':{**common,'machine_id':'independent-owner-pc','source_machine_id':'vps-stage','medium_id':'physical-owner-disk','recovery_bundle_sha256':'d'*64,'restore_receipt_sha256':'e'*64,'restore_method':'full-native-database-media','origin':'independent-physical-medium','executed_by':'owner','bundle_storage_separate':True,'password_storage_separate':True}}
    for name,sid in [('anchor',ANCHOR),('tip',TIP)]:
        docs[name]={**common,'base_id':sid,'base_manifest_sha256':sid,'full_id':sid,'full_manifest_sha256':sid,'stage_app_sha':'f'*40,'coordinates':manifests[sid]['coordinates'],'stop':{'file':logs[-1]['file'],'position':500},'replayed_logs':1,'verified_binlogs':[logs[-1]],'media':{'inventory':[]},'synthetic_order_after_base':True,'synthetic_operation_after_base':True,'later_order_operation_excluded':True,'started_from':'private encrypted S3-B base+binlogs; original source reads=0'}
    docs['tip'].update(profile='tip',additional_order_operation_present=True,later_order_operation_excluded=False)
    evidence={}
    for name,doc in docs.items():
        doc['evidence_type']=name; evidence[name]={'sha256':digest(doc),'document':doc}
    plan['proof_sha256']={name:item['sha256'] for name,item in evidence.items()}
    return copy.deepcopy(inventory),copy.deepcopy(plan),copy.deepcopy(evidence)
class MemoryIntent:
    def __init__(self): self.value=None
    def load(self): return copy.deepcopy(self.value)
    def prepare(self,value):
        if self.value is not None: raise guards.GuardError('Intent exists')
        self.value=copy.deepcopy(value)
class ApplyTests(unittest.TestCase):
    def setUp(self): self.inventory,self.plan,self.evidence=fixture()
    def rebind(self,name):
        self.evidence[name]['sha256']=digest(self.evidence[name]['document'])
        self.plan['proof_sha256'][name]=self.evidence[name]['sha256']
    def test_large_expired_backlog_selects_safe_bounded_batch_and_protects_deferred_ids(self):
        for i in range(256):
            sid=format(i+16,'064x')
            self.inventory['snapshots'].append({**self.inventory['snapshots'][0],'id':sid,'token':format(i+16,'032x'),'manifest_sha256':sid})
            self.inventory['manifests'][sid]=copy.deepcopy(self.inventory['manifests'][OLD])
        full=retention.inventory_plan(self.inventory,NOW)
        self.plan=retention.bounded_plan(self.inventory,full);self.plan['planned_at']=NOW.isoformat();self.plan['proof_sha256']={}
        self.assertEqual(len(full['candidates']),257);self.assertEqual(len(self.plan['candidates']),256)
        deferred=set(full['candidates'])-set(self.plan['candidates']);self.assertEqual(len(deferred),1)
        self.assertTrue(deferred<=set(self.plan['keep']))
        for name,entry in self.evidence.items():
            entry['document']['inventory_sha256']=full['inventory_sha256']
            if name=='audit':entry['document']['readback_snapshots']={r['id']:r['manifest_sha256'] for r in self.inventory['snapshots']}
            self.rebind(name)
        before=copy.deepcopy(self.inventory);result=self.executor().apply(before,self.plan,self.evidence,NOW)
        self.assertEqual(result['result'],'APPLIED');self.assertEqual(len(result['forgotten_ids']),256)
        self.assertTrue(deferred<={r['id'] for r in self.inventory['snapshots']})
    def test_backlog_batch_keeps_hourly_full_dependencies_and_original_binlog_prefix(self):
        inv,_,_=fixture(split=True);rows=[];manifests={};old=copy.deepcopy(inv['snapshots'][-1])
        for i in range(1,261):
            sid=format(i+4096,'064x');stamp='2026-08-02T12:00:00Z' if i<259 else '2026-10-12T12:00:00Z'
            rows.append({**old,'id':sid,'token':format(i+4096,'032x'),'manifest_sha256':sid,'time':stamp,'snapshot_time':stamp})
            manifests[sid]={'source':SOURCE,'first_log':i,'last_log':i,'previous_count':i-1,
                            'logs':[{'file':'suhoput2-binlog.%06d'%i,'size':500,'sha256':sid}]}
        inv['snapshots']=[r for r in inv['snapshots'] if r['lane']=='base']+rows
        inv['manifests']={sid:m for sid,m in inv['manifests'].items() if sid in (OLD,ANCHOR,TIP)}|manifests
        inv['manifests'][ANCHOR]['coordinates']['file']='suhoput2-binlog.000259'
        inv['manifests'][TIP]['coordinates']['file']='suhoput2-binlog.000260'
        full=retention.inventory_plan(inv,NOW);batch=retention.bounded_plan(inv,full)
        selected=[r for r in rows if r['id'] in batch['candidates']]
        self.assertEqual([manifests[r['id']]['first_log'] for r in selected],list(range(1,256)))
        remaining={'generation':GEN,'repositories':inv['repositories'],
                   'snapshots':[r for r in inv['snapshots'] if r['id'] not in batch['candidates']],
                   'manifests':{sid:m for sid,m in inv['manifests'].items() if sid not in batch['candidates']}}
        self.assertEqual(retention.inventory_plan(remaining,NOW)['logs'][0]['file'],'suhoput2-binlog.000256')
        hourly=format(99999,'064x');inv['snapshots'].append({**inv['snapshots'][0],'kind':'hourly','id':hourly})
        inv['manifests'][hourly]={**inv['manifests'][OLD],'full_id':OLD}
        restricted=retention.bounded_plan(inv,retention.inventory_plan(inv,NOW),1)
        self.assertEqual(restricted['candidates'],[hourly]);self.assertIn(OLD,restricted['keep'])
    def executor(self,reader=None,runner=None,store=None,writer=None):
        self.calls=[]; self.receipts=[]; self.store=store or MemoryIntent()
        def invoke(lane,args):
            self.assertIsNotNone(self.store.load()); self.calls.append((lane,args))
            if runner: return runner(lane,args)
            ids=set(args[3:]); self.inventory['snapshots']=[r for r in self.inventory['snapshots'] if r['id'] not in ids]
            self.inventory['manifests']={sid:m for sid,m in self.inventory['manifests'].items() if sid not in ids}
        return subject().Executor(reader or (lambda:copy.deepcopy(self.inventory)),invoke,self.store,writer or self.receipts.append,{'base':'s3:private/base','binlog':'s3:private/binlog'})
    def test_exact_forget_after_durable_intent_has_bound_receipt(self):
        before=copy.deepcopy(self.inventory); result=self.executor().apply(before,self.plan,self.evidence,NOW)
        self.assertEqual(self.calls,[('base',['--repo','s3:private/base','forget',OLD])])
        self.assertEqual(result['result'],'APPLIED'); self.assertEqual(result['forgotten_ids'],[OLD])
        self.assertEqual(result['remote_delete_calls'],1); self.assertFalse(result['prune_run'])
        self.assertEqual(self.store.value['candidate_ids'],[OLD]); self.assertEqual(self.receipts[-1],result)
        self.assertEqual(result['generation'],GEN); self.assertEqual(result['repositories'],before['repositories'])
    def test_missing_or_boolean_spoofed_evidence_never_invokes_delete(self):
        for evidence in ({},{name:True for name in self.evidence},{name:{'document':{'result':'PASS','verified':True}} for name in self.evidence}):
            ex=self.executor()
            with self.subTest(evidence=evidence),self.assertRaises(guards.GuardError): ex.apply(self.inventory,self.plan,evidence,NOW)
            self.assertEqual(self.calls,[]); self.assertIsNone(self.store.value)
    def test_hash_source_inventory_generation_repository_and_tip_mismatch_block(self):
        for mutation in ('hash','source','inventory','generation','repository','stop','tip_base','readback','binlog'):
            self.setUp(); doc=self.evidence['tip']['document']
            if mutation=='hash': doc['extra']=1
            elif mutation=='source': doc['source']={'root':'foreign'}
            elif mutation=='inventory': doc['inventory_sha256']='0'*64
            elif mutation=='generation': doc['generation']='0'*32
            elif mutation=='repository': doc['repositories']={'base':'0'*64,'binlog':'8'*64}
            elif mutation=='stop': doc['stop']['position']=499
            elif mutation=='tip_base': doc['base_id']=ANCHOR
            elif mutation=='readback': self.evidence['audit']['document']['readback_snapshots'].pop(OLD); self.rebind('audit')
            elif mutation=='binlog': self.evidence['audit']['document']['verified_binlogs'][0]['sha256']='0'*64; self.rebind('audit')
            if mutation!='hash': self.rebind('tip')
            ex=self.executor()
            with self.subTest(mutation=mutation),self.assertRaises(guards.GuardError): ex.apply(self.inventory,self.plan,self.evidence,NOW)
            self.assertEqual(self.calls,[])
    def test_stale_clock_and_invented_plan_cannot_authorize(self):
        for mutation in ('stale','future','cutoff','anchor','candidate_keep','missing_candidate','prefix'):
            self.setUp(); at=NOW
            if mutation=='stale': at+=dt.timedelta(hours=1)
            elif mutation=='future': at-=dt.timedelta(seconds=1)
            elif mutation=='cutoff': self.evidence['history']['document']['observed_from']='2026-10-01T00:00:00Z'; self.rebind('history')
            elif mutation=='anchor': self.plan['anchor_id']=TIP
            elif mutation=='candidate_keep': self.plan['candidates']=[ANCHOR]
            elif mutation=='missing_candidate': self.plan['candidates']=['9'*64]
            elif mutation=='prefix': self.plan['candidates']=[OLD[:8]]
            ex=self.executor()
            with self.subTest(mutation=mutation),self.assertRaises(guards.GuardError): ex.apply(self.inventory,self.plan,self.evidence,at)
            self.assertEqual(self.calls,[])
    def test_owner_independence_and_unknown_budget_block(self):
        for name,key,value in [('owner','machine_id','vps-stage'),('owner','origin','vps-copy'),('owner','restore_method','decrypt-list-only'),('budget','projected_monthly_rub',501),('budget','projected_storage_bytes',11*1024**3),('budget','measured_requests',True),('budget','account_billing_sha256',None)]:
            self.setUp(); self.evidence[name]['document'][key]=value; self.rebind(name); ex=self.executor()
            with self.subTest(key=key),self.assertRaises(guards.GuardError): ex.apply(self.inventory,self.plan,self.evidence,NOW)
            self.assertEqual(self.calls,[])
    def test_same_owner_pc_with_separate_cloud_kit_is_allowed_but_agent_run_is_not(self):
        self.evidence['owner']['document'].update(machine_id='owner-current-pc',medium_id='owner-google-drive',origin='separately-stored-encrypted-kit')
        self.rebind('owner');subject().validate_apply(self.inventory,self.plan,self.evidence,NOW)
        for key,value in [('executed_by','agent'),('bundle_storage_separate',False),('password_storage_separate',False)]:
            self.evidence['owner']['document'][key]=value;self.rebind('owner')
            with self.subTest(key=key),self.assertRaises(guards.GuardError):subject().validate_apply(self.inventory,self.plan,self.evidence,NOW)
            self.evidence['owner']['document'][key]='owner' if key=='executed_by' else True
    def test_append_only_arrival_is_protected_without_invalidating_plan(self):
        before=copy.deepcopy(self.inventory); new={**self.inventory['snapshots'][2],'id':'9'*64,'token':'9'*32}
        self.inventory['snapshots'].append(new); self.inventory['manifests'][new['id']]=copy.deepcopy(self.inventory['manifests'][TIP])
        result=self.executor().apply(before,self.plan,self.evidence,NOW)
        self.assertEqual(result['result'],'APPLIED'); self.assertEqual(result['protected_arrival_ids'],['9'*64])
        self.assertIn('9'*64,[r['id'] for r in self.inventory['snapshots']])
    def test_known_entry_change_removal_or_unknown_source_blocks_before_delete(self):
        for mutation in ('change','remove','arrival'):
            self.setUp(); before=copy.deepcopy(self.inventory)
            if mutation=='change': self.inventory['manifests'][TIP]['configuration_sha256']='0'*64
            elif mutation=='remove': self.inventory['snapshots'].pop()
            else:
                self.inventory['snapshots'].append({**self.inventory['snapshots'][0],'id':'9'*64})
                self.inventory['manifests']['9'*64]={'source':{'root':'unknown'}}
            ex=self.executor()
            with self.subTest(mutation=mutation),self.assertRaises(guards.GuardError): ex.apply(before,self.plan,self.evidence,NOW)
            self.assertEqual(self.calls,[])
    def test_lost_response_is_reconciled_without_second_forget(self):
        before=copy.deepcopy(self.inventory)
        def lost(lane,args):
            self.inventory['snapshots']=[r for r in self.inventory['snapshots'] if r['id']!=OLD]
            self.inventory['manifests'].pop(OLD); raise TimeoutError('response lost')
        ex=self.executor(runner=lost); result=ex.apply(before,self.plan,self.evidence,NOW)
        self.assertEqual(result['result'],'RECONCILE_REQUIRED'); self.assertEqual(result['forgotten_ids'],[OLD])
        again=ex.apply(before,self.plan,self.evidence,NOW); self.assertEqual(again['result'],'RECONCILE_REQUIRED'); self.assertEqual(len(self.calls),1)
        resolved=ex.reconcile(NOW); self.assertEqual(resolved['result'],'RECONCILED'); self.assertEqual(resolved['present_candidate_ids'],[])
        self.assertEqual(len(self.calls),1)
    def test_zero_exit_without_effect_needs_reconciliation(self):
        ex=self.executor(runner=lambda lane,args:None); result=ex.apply(copy.deepcopy(self.inventory),self.plan,self.evidence,NOW)
        self.assertEqual(result['result'],'RECONCILE_REQUIRED'); self.assertEqual(result['present_candidate_ids'],[OLD])
        ex.reconcile(NOW); self.assertEqual(len(self.calls),1)
    def test_unknown_post_inventory_cannot_retry_delete(self):
        before=copy.deepcopy(self.inventory); reads=0
        def reader():
            nonlocal reads
            reads+=1
            if reads>2: raise TimeoutError('inventory response lost')
            return copy.deepcopy(self.inventory)
        ex=self.executor(reader=reader); result=ex.apply(before,self.plan,self.evidence,NOW)
        self.assertEqual(result['result'],'RECONCILE_REQUIRED'); self.assertIsNone(result['forgotten_ids'])
        ex.apply(before,self.plan,self.evidence,NOW); self.assertEqual(len(self.calls),1)
    def test_removal_of_keep_after_effect_is_not_success(self):
        before=copy.deepcopy(self.inventory)
        def bad(lane,args):
            self.inventory['snapshots']=[r for r in self.inventory['snapshots'] if r['id'] not in (OLD,ANCHOR)]
            self.inventory['manifests'].pop(OLD); self.inventory['manifests'].pop(ANCHOR)
        result=self.executor(runner=bad).apply(before,self.plan,self.evidence,NOW)
        self.assertEqual(result['result'],'RECONCILE_REQUIRED'); self.assertIsNone(result['forgotten_ids'])
    def test_prepare_failure_has_no_remote_effect(self):
        class BrokenStore(MemoryIntent):
            def prepare(self,value): raise OSError('fsync failed')
        ex=self.executor(store=BrokenStore())
        with self.assertRaises(OSError): ex.apply(self.inventory,self.plan,self.evidence,NOW)
        self.assertEqual(self.calls,[])
    def test_noop_without_prerequisites_is_auditable_and_never_accepts_30_days(self):
        self.inventory['snapshots']=[r for r in self.inventory['snapshots'] if r['id']!=OLD]
        self.inventory['manifests'].pop(OLD)
        self.plan=retention.inventory_plan(self.inventory,NOW); self.plan['planned_at']='2026-10-12T13:00:00Z'
        result=self.executor().apply(self.inventory,self.plan,{},NOW)
        self.assertEqual(result['result'],'NOOP'); self.assertEqual(result['remote_delete_calls'],0)
        self.assertFalse(result['history_coverage_accepted']); self.assertEqual(self.calls,[])
    def test_partial_effect_has_exact_sets_and_tombstones_require_explicit_reconcile(self):
        old2='9'*64
        self.inventory['snapshots'].append({**self.inventory['snapshots'][0],'id':old2,'token':'9'*32,'time':'2026-08-02T12:00:00Z','snapshot_time':'2026-08-02T12:00:00Z'})
        self.inventory['manifests'][old2]=copy.deepcopy(self.inventory['manifests'][OLD])
        self.plan=retention.inventory_plan(self.inventory,NOW); self.plan['planned_at']='2026-10-12T13:00:00Z'
        for name in self.evidence:
            self.evidence[name]['document']['inventory_sha256']=self.plan['inventory_sha256']
            if name=='audit': self.evidence[name]['document']['readback_snapshots'][old2]=OLD
        self.plan['proof_sha256']={}
        for name in self.evidence: self.rebind(name)
        before=copy.deepcopy(self.inventory)
        def partial(lane,args):
            self.inventory['snapshots']=[r for r in self.inventory['snapshots'] if r['id']!=OLD]
            self.inventory['manifests'].pop(OLD)
        ex=self.executor(runner=partial); result=ex.apply(before,self.plan,self.evidence,NOW)
        self.assertEqual(result['result'],'RECONCILE_REQUIRED')
        self.assertEqual(result['forgotten_ids'],[OLD]); self.assertEqual(result['present_candidate_ids'],[old2])
        with self.assertRaises(guards.GuardError): subject().retention_tombstones(self.store.value,result)
        receipt=ex.reconcile(NOW); tombstones=subject().retention_tombstones(self.store.value,receipt)
        self.assertEqual([row['id'] for row in tombstones],[OLD])
        self.assertEqual(tombstones[0]['manifest_sha256'],OLD)
        self.assertEqual(tombstones[0]['receipt_sha256'],digest(receipt))
        self.assertEqual(len(self.calls),1)
    def test_receipt_write_failure_leaves_intent_and_prevents_retry(self):
        before=copy.deepcopy(self.inventory)
        def lost_receipt(value): raise OSError('receipt fsync failed')
        ex=self.executor(writer=lost_receipt)
        with self.assertRaises(OSError): ex.apply(before,self.plan,self.evidence,NOW)
        self.assertEqual(len(self.calls),1); ex.write_receipt=self.receipts.append
        ex.apply(before,self.plan,self.evidence,NOW); self.assertEqual(len(self.calls),1)
    def test_intent_readback_failure_prevents_effect(self):
        class LostStore(MemoryIntent):
            def prepare(self,value): pass
        ex=self.executor(store=LostStore())
        with self.assertRaises(guards.GuardError): ex.apply(self.inventory,self.plan,self.evidence,NOW)
        self.assertEqual(self.calls,[])
    def test_tombstone_binding_cannot_be_changed_to_a_kept_snapshot(self):
        result=self.executor().apply(copy.deepcopy(self.inventory),self.plan,self.evidence,NOW)
        result['forgotten_ids']=[ANCHOR]
        with self.assertRaises(guards.GuardError): subject().retention_tombstones(self.store.value,result)

    def test_base_lane_ambiguous_effect_never_starts_binlog_forget(self):
        self.inventory,self.plan,self.evidence=fixture(split=True); before=copy.deepcopy(self.inventory)
        def lost(lane,args):
            self.inventory['snapshots']=[r for r in self.inventory['snapshots'] if r['id']!=OLD]
            self.inventory['manifests'].pop(OLD); raise TimeoutError('base response lost')
        result=self.executor(runner=lost).apply(before,self.plan,self.evidence,NOW)
        self.assertEqual(len(self.calls),1); self.assertEqual(self.calls[0][0],'base')
        self.assertEqual(result['forgotten_ids'],[OLD]); self.assertEqual(result['present_candidate_ids'],['5'*64])
    def test_two_lanes_forget_only_frozen_exact_candidate_ids(self):
        self.inventory,self.plan,self.evidence=fixture(split=True)
        result=self.executor().apply(copy.deepcopy(self.inventory),self.plan,self.evidence,NOW)
        self.assertEqual(self.calls,[('base',['--repo','s3:private/base','forget',OLD]),('binlog',['--repo','s3:private/binlog','forget','5'*64])])
        self.assertEqual(result['result'],'APPLIED'); self.assertEqual(result['forgotten_ids'],[OLD,'5'*64])
    def test_advancing_clock_accepts_authenticated_minute_arrivals(self):
        before=copy.deepcopy(self.inventory); reads=0
        def reader():
            nonlocal reads
            reads+=1
            if reads==2:
                self.inventory['snapshots'].append({**self.inventory['snapshots'][2],'id':'9'*64,'token':'9'*32,'time':'2026-10-12T13:01:00Z','snapshot_time':'2026-10-12T13:01:00Z'})
                self.inventory['manifests']['9'*64]=copy.deepcopy(self.inventory['manifests'][TIP])
            return copy.deepcopy(self.inventory)
        ex=self.executor(reader=reader); ex.clock=lambda:NOW+dt.timedelta(minutes=1)
        result=ex.apply(before,self.plan,self.evidence,NOW)
        self.assertEqual(result['result'],'APPLIED'); self.assertEqual(result['protected_arrival_ids'],['9'*64])
    def test_clock_rollback_before_lane_command_has_no_effect(self):
        # Inject at the observable durability boundary, not a clock-call count;
        # final dependency work now has its own pre-intent freshness check.
        before=copy.deepcopy(self.inventory);current=[NOW]
        class RollbackIntent(MemoryIntent):
            def prepare(self,value):super().prepare(value);current[0]=NOW-dt.timedelta(seconds=1)
        ex=self.executor(store=RollbackIntent());ex.clock=lambda:current[0]
        result=ex.apply(before,self.plan,self.evidence,NOW)
        self.assertEqual(self.calls,[]); self.assertEqual(result['result'],'RECONCILE_REQUIRED')

    def test_clock_rollback_during_initial_inventory_has_no_intent(self):
        before=copy.deepcopy(self.inventory);current=[NOW]
        def reader():
            current[0]=NOW-dt.timedelta(seconds=1)
            return copy.deepcopy(self.inventory)
        ex=self.executor(reader=reader);ex.clock=lambda:current[0]
        with self.assertRaises(guards.GuardError):ex.apply(before,self.plan,self.evidence,NOW)
        self.assertEqual(self.calls,[]);self.assertIsNone(self.store.value)

    def test_last_inventory_cannot_let_expired_plan_reach_forget(self):
        before=copy.deepcopy(self.inventory); current=[NOW]; reads=0
        def reader():
            nonlocal reads
            reads+=1
            if reads==2:current[0]=NOW+dt.timedelta(seconds=901)
            return copy.deepcopy(self.inventory)
        ex=self.executor(reader=reader);ex.clock=lambda:current[0]
        result=ex.apply(before,self.plan,self.evidence,NOW)
        self.assertEqual(self.calls,[])
        self.assertEqual(result['result'],'RECONCILE_REQUIRED')
        self.assertEqual(result['present_candidate_ids'],[OLD])
        self.assertEqual(result['remote_delete_calls'],0)
        ex.apply(before,self.plan,self.evidence,current[0])
        self.assertEqual(self.calls,[])

    def test_slow_initial_inventory_expires_before_durable_intent(self):
        before=copy.deepcopy(self.inventory);current=[NOW]
        def reader():
            current[0]=NOW+dt.timedelta(seconds=901)
            return copy.deepcopy(self.inventory)
        ex=self.executor(reader=reader);ex.clock=lambda:current[0]
        with self.assertRaises(guards.GuardError):ex.apply(before,self.plan,self.evidence,NOW)
        self.assertEqual(self.calls,[]);self.assertIsNone(self.store.value)

    def test_proof_age_is_relative_to_current_effect_clock(self):
        self.evidence['owner']['document']['started_at']=(NOW-dt.timedelta(minutes=15)).isoformat()
        self.evidence['owner']['document']['completed_at']=(NOW-dt.timedelta(minutes=14)).isoformat()
        self.rebind('owner')
        ex=self.executor();ex.clock=lambda:NOW+dt.timedelta(minutes=2)
        with self.assertRaises(guards.GuardError):ex.apply(copy.deepcopy(self.inventory),self.plan,self.evidence,NOW)
        self.assertEqual(self.calls,[]);self.assertIsNone(self.store.value)

    def test_final_validation_cannot_cross_freshness_deadline_or_roll_back(self):
        from unittest.mock import patch
        for final_time in (NOW+dt.timedelta(seconds=901),NOW+dt.timedelta(seconds=898)):
            self.setUp();before=copy.deepcopy(self.inventory);current=[NOW];reads=0;validations=0;m=subject();original=m.validate_apply
            def reader():
                nonlocal reads
                reads+=1
                if reads==2:current[0]=NOW+dt.timedelta(seconds=899)
                return copy.deepcopy(self.inventory)
            def validate(*args):
                nonlocal validations
                result=original(*args);validations+=1
                if validations==3:current[0]=final_time
                return result
            ex=self.executor(reader=reader);ex.clock=lambda:current[0]
            with self.subTest(final_time=final_time),patch.object(m,'validate_apply',validate):
                result=ex.apply(before,self.plan,self.evidence,NOW)
                self.assertEqual(self.calls,[]);self.assertEqual(result['result'],'RECONCILE_REQUIRED')
                self.assertEqual(result['present_candidate_ids'],[OLD])

    def test_noop_with_unknown_post_inventory_requires_reconcile(self):
        self.inventory['snapshots']=[r for r in self.inventory['snapshots'] if r['id']!=OLD]; self.inventory['manifests'].pop(OLD)
        self.plan=retention.inventory_plan(self.inventory,NOW); self.plan['planned_at']='2026-10-12T13:00:00Z'
        before=copy.deepcopy(self.inventory); reads=0
        def reader():
            nonlocal reads
            reads+=1
            if reads>1: raise TimeoutError('no-op inventory lost')
            return copy.deepcopy(self.inventory)
        result=self.executor(reader=reader).apply(before,self.plan,{},NOW)
        self.assertEqual(result['remote_delete_calls'],0); self.assertEqual(result['result'],'RECONCILE_REQUIRED')
        self.assertFalse(result['history_coverage_accepted'])

    def add_dependent_hourly(self):
        self.inventory['snapshots'].append({**self.inventory['snapshots'][2],'id':'9'*64,'token':'9'*32,'kind':'hourly'})
        self.inventory['manifests']['9'*64]={**copy.deepcopy(self.inventory['manifests'][TIP]),'full_id':OLD}
    def test_arriving_hourly_protects_frozen_expired_full_before_intent(self):
        before=copy.deepcopy(self.inventory); self.add_dependent_hourly(); ex=self.executor()
        with self.assertRaises(guards.GuardError): ex.apply(before,self.plan,self.evidence,NOW)
        self.assertEqual(self.calls,[]); self.assertIsNone(self.store.value)
    def test_hourly_arriving_after_intent_stops_full_forget(self):
        before=copy.deepcopy(self.inventory); reads=0
        def reader():
            nonlocal reads
            reads+=1
            if reads==2: self.add_dependent_hourly()
            return copy.deepcopy(self.inventory)
        result=self.executor(reader=reader).apply(before,self.plan,self.evidence,NOW)
        self.assertEqual(result['result'],'RECONCILE_REQUIRED'); self.assertEqual(self.calls,[])
        self.assertIn(OLD,[r['id'] for r in self.inventory['snapshots']])
    def test_hourly_arrival_referencing_just_forgotten_full_stops_next_lane(self):
        self.inventory,self.plan,self.evidence=fixture(split=True); before=copy.deepcopy(self.inventory)
        def effect(lane,args):
            self.add_dependent_hourly()
            self.inventory['snapshots']=[r for r in self.inventory['snapshots'] if r['id']!=OLD]
            self.inventory['manifests'].pop(OLD)
        result=self.executor(runner=effect).apply(before,self.plan,self.evidence,NOW)
        self.assertEqual(result['result'],'RECONCILE_REQUIRED'); self.assertEqual(len(self.calls),1)
        self.assertEqual(self.calls[0][0],'base'); self.assertIsNone(result['forgotten_ids'])

    def test_named_tip_evidence_cannot_be_missing_or_point_profile(self):
        for profile in ('missing','point'):
            self.setUp(); document=self.evidence['tip']['document']
            if profile=='missing': document.pop('profile')
            else: document['profile']='point'
            document['later_order_operation_excluded']=True
            self.rebind('tip'); ex=self.executor()
            with self.subTest(profile=profile),self.assertRaises(guards.GuardError): ex.apply(self.inventory,self.plan,self.evidence,NOW)
            self.assertEqual(self.calls,[]); self.assertIsNone(self.store.value)

if __name__=='__main__': unittest.main()
