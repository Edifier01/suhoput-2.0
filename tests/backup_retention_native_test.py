"""Protected retention boundary tests; synthetic receipts only, no S3."""
import copy, importlib.util, json, pathlib, sys, tempfile, unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'infra/backup'))
import guards, retention_apply, runtime
from unittest import mock
from backup_retention_apply_test import fixture, NOW

def subject():
    unittest.TestCase().assertIsNotNone(importlib.util.find_spec('retention_native'),'Trusted native retention integration absent')
    import retention_native
    return retention_native

class NativeBoundaryTests(unittest.TestCase):
    def test_operational_restore_origin_uses_its_exact_producer_and_profile(self):
        inv,_,_=fixture();doc={'operation':'native-retention-restore-v1','profile':'tip'}
        raw=json.dumps(doc).encode();m=subject()
        origin={'format':1,'evidence_type':'tip','producer':'retention_restore.py','code_sha':'f'*40,
                'generation':inv['generation'],'repositories':inv['repositories'],
                'inventory_sha256':__import__('retention').inventory_digest(inv),
                'file_sha256':__import__('hashlib').sha256(raw).hexdigest(),'document_sha256':retention_apply.document_digest(doc)}
        self.assertTrue(m.verify_origin('tip',raw,doc,origin,'f'*40,inv))
        for key,value in [('producer','restore.py'),('evidence_type','anchor')]:
            bad=copy.deepcopy(origin);bad[key]=value
            with self.subTest(key=key),self.assertRaises(guards.GuardError):m.verify_origin('tip',raw,doc,bad,'f'*40,inv)
        with self.assertRaises(guards.GuardError):m.producer_for('anchor',doc)
        with self.assertRaises(guards.GuardError):m.producer_for('audit',doc)
        self.assertEqual(m.producer_for('tip',{}),'restore.py')

    def v2_case(self):
        import backup_cohort_test,readiness_v2
        from backup_readiness_v2_test import v2_fixture
        case=backup_cohort_test.NativeCohortTests();case.setUp();self.addCleanup(case.doCleanups)
        cohort,executor,store,effects=case.prepared_apply();case.w.c['retention_readiness_policy']='native-v2'
        evidence=subject().load_evidence(case.w,cohort);evidence.pop('history')
        report=v2_fixture()[2]['budget']['document'];report.update(source=case.w.source,generation=case.w.c['generation'])
        evidence['budget']={'document':report,'sha256':retention_apply.document_digest(report)}
        for name in ('history','budget'):(case.root/'receipts'/subject().RECEIPTS[name]).unlink()
        return case,cohort,executor,store,effects,evidence

    def test_configured_native_v2_dispatches_exact_proofs_and_rechecks_every_apply_phase(self):
        import readiness_v2
        case,cohort,executor,store,effects,evidence=self.v2_case();events=[]
        confirmed=subject()._confirmed_active
        def confirmation(*args,**kwargs):events.append('confirmed');return confirmed(*args,**kwargs)
        def budget(*args,**kwargs):events.append('budget');return True
        with mock.patch.object(subject(),'load_evidence',side_effect=AssertionError('Legacy evidence must not load')), \
             mock.patch.object(readiness_v2,'load_evidence',return_value=evidence) as loaded, \
             mock.patch.object(readiness_v2,'revalidate_budget',side_effect=budget), \
             mock.patch.object(subject(),'_confirmed_active',side_effect=confirmation):
            result=executor.run('apply')
        loaded.assert_called_once();self.assertEqual(result['result'],'APPLIED')
        self.assertEqual(result['readiness_policy'],'native-v2');self.assertEqual(len(effects),2)
        self.assertEqual(events,['confirmed','budget']*3);self.assertEqual(store.load()['readiness_policy'],'native-v2')

    def test_v2_budget_expiry_or_cost_drift_after_load_blocks_before_intent_and_effect(self):
        import readiness_v2,budget,storage
        for change in ('cost_config','stale_live'):
            case,cohort,executor,store,effects,evidence=self.v2_case()
            report=evidence['budget']['document']
            observation={'format':'commissioning-live-observation-v1','bucket':report['bucket'],'scope_sha256':report['scope_sha256'],
                         'source':report['source'],'generation':report['generation'],'prefix':'','complete':True,
                         'observed_at':(NOW-__import__('datetime').timedelta(seconds=121)).isoformat()}
            def loader(*args,**kwargs):
                if change=='cost_config':raise budget.BudgetError('Changed installed cost configuration')
                return report
            with self.subTest(change=change),mock.patch.object(readiness_v2,'load_evidence',return_value=evidence), \
                 mock.patch.object(budget,'load_commissioning_budget',side_effect=loader), \
                 mock.patch.object(storage,'load_live_observation',return_value=observation),self.assertRaises(guards.GuardError):
                executor.run('apply')
            self.assertEqual(effects,[]);self.assertFalse(store.path.exists())

    def test_uncertain_native_v2_intent_reconciles_readonly_after_budget_freshness_expires(self):
        import readiness_v2,retention_cohort,datetime as dt
        case,cohort,executor,store,effects,evidence=self.v2_case();forget=case.w.retention_forget
        def lost(lane,ids,**kwargs):
            result=forget(lane,ids,**kwargs)
            if lane=='binlog':raise TimeoutError('Native response lost')
            return result
        case.w.retention_forget=lost
        with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True):
            self.assertEqual(executor.run('apply')['result'],'RECONCILE_REQUIRED')
        self.assertEqual(len(effects),2)
        with mock.patch.object(retention_cohort,'clock',return_value=NOW+dt.timedelta(seconds=901)), \
             mock.patch.object(readiness_v2,'load_evidence',side_effect=AssertionError('No new authorization for reconciliation')), \
             mock.patch.object(readiness_v2,'revalidate_budget',side_effect=AssertionError('Read-only reconciliation cannot require renewed budget')):
            result=executor.run('reconcile')
        self.assertEqual(result['result'],'RECONCILED');self.assertEqual(result['remote_delete_calls'],0);self.assertEqual(len(effects),2)

    def test_pointer_only_checkpoint_routes_supported_reconcile_without_new_native_attempt(self):
        import backup_catalog,backup_catalog_test
        case=backup_catalog_test.CatalogLifecycleTests('runTest');case.setUp();self.addCleanup(case.doCleanups)
        case.prepare();case.put(backup_catalog_test.SID,backup_catalog_test.TOKEN);case.put('4'*64,'5'*32);case.prove_absence(backup_catalog_test.SID)
        write=runtime.atomic_json
        def crashed(path,value):
            write(path,value)
            if pathlib.Path(path)==case.root/'receipts/catalog-checkpoint-stage.json':raise OSError('Process lost after pointer')
        with mock.patch.object(runtime,'atomic_json',side_effect=crashed),mock.patch.object(backup_catalog.CheckpointStage,'cleanup',side_effect=OSError('No process cleanup')),self.assertRaises(OSError):case.c.checkpoint()
        self.assertFalse(case.c.checkpoint_pending.exists());case.w.gate=lambda:None
        executor=subject().NativeApply.__new__(subject().NativeApply);executor.w=case.w
        with mock.patch.object(executor,'_attempt',side_effect=AssertionError('Pointer recovery must not start native effects')):
            with self.assertRaisesRegex(guards.GuardError,'Interrupted checkpoint'):executor.run('apply')
            result=executor.run('reconcile')
        self.assertEqual(result['result'],'RECONCILED');self.assertEqual(result['remote_delete_calls'],0)
        self.assertEqual(result['retired_ids'],[backup_catalog_test.SID]);self.assertTrue(case.c.ready());self.assertEqual(set(case.c.entries()),{'4'*64})

    def recorded_fixture(self,receipt_count=1):
        inv,plan,_=fixture();template=inv['snapshots'][0];manifest=inv['manifests'][template['id']]
        for index in range(255):
            sid=format(index+4096,'064x');inv['snapshots'].append({**template,'id':sid,'token':sid[-32:],'manifest_sha256':sid});inv['manifests'][sid]=manifest
        candidates=sorted(row['id'] for row in inv['snapshots'] if row['lane']=='base' and row['time']==template['time'])
        self.assertEqual(len(candidates),256)
        body={'operation':'native-retention-forget','token':'a'*32,'generation':inv['generation'],'repositories':inv['repositories'],
              'source':manifest['source'],'inventory_sha256':__import__('retention').inventory_digest(inv),'before_inventory':retention_apply.compact_authenticated_inventory(inv,NOW),
              'candidate_ids':candidates,'keep_ids':sorted(set(inv['manifests'])-set(candidates)),'anchor_id':plan['anchor_id'],
              'proof_sha256':{},'prepared_at':NOW.isoformat()}
        intent={**body,'intent_sha256':retention_apply.document_digest(body)};recorded={'base':[],'binlog':[]};documents={}
        for index in range(receipt_count):
            absent=candidates[:len(candidates)*(index+1)//receipt_count]
            receipt={k:copy.deepcopy(intent[k]) for k in ('operation','token','generation','repositories','source','inventory_sha256','candidate_ids','keep_ids','anchor_id','proof_sha256','intent_sha256')}
            receipt.update(result='APPLIED' if index==receipt_count-1 else 'RECONCILED',observation_error=None,forgotten_ids=absent,
                           present_candidate_ids=sorted(set(candidates)-set(absent)),post_inventory_sha256=str(index+1)*64,completed_at=NOW.isoformat())
            documents[retention_apply.document_digest(receipt)]={'document':receipt}
            existing={row['id'] for row in recorded['base']}
            recorded['base']+=[row for row in retention_apply.retention_tombstones(intent,receipt) if row['id'] not in existing]
        return intent,recorded,documents
    def test_256_recorded_rows_derive_full_intent_once_per_unique_original_receipt(self):
        for count in (1,2):
            intent,recorded,documents=self.recorded_fixture(count)
            with mock.patch.object(retention_apply,'retention_tombstones',wraps=retention_apply.retention_tombstones) as derive:
                result=subject()._verify_recorded(intent,recorded,documents)
            with self.subTest(receipts=count):
                self.assertEqual(result,recorded['base']);self.assertEqual(len(result),256)
                self.assertEqual(derive.call_count,count,'Whole intent hashing/indexing must grow with unique receipts, not journal rows')
    def test_cached_original_receipt_proofs_still_reject_row_receipt_lane_and_duplicate_tampering(self):
        intent,recorded,documents=self.recorded_fixture(2)
        for mutation in ('row','receipt','missing','lane','duplicate'):
            values=copy.deepcopy(recorded);proofs=copy.deepcopy(documents)
            if mutation=='row':values['base'][-1]['post_inventory_sha256']='0'*64
            elif mutation=='receipt':proofs[values['base'][-1]['receipt_sha256']]['document']['post_inventory_sha256']='0'*64
            elif mutation=='missing':del proofs[values['base'][-1]['receipt_sha256']]
            elif mutation=='lane':values['binlog'].append(values['base'].pop())
            else:values['base'].append(copy.deepcopy(values['base'][0]))
            with self.subTest(mutation=mutation),self.assertRaises(guards.GuardError):subject()._verify_recorded(intent,values,proofs)
    def test_thirty_day_intent_keeps_all_43200_ids_without_payload_duplication(self):
        inv,_,_=fixture();template=inv['snapshots'][-1];manifest=inv['manifests'][template['id']]
        for i in range(43200):
            sid=format(i+4096,'064x')
            inv['snapshots'].append({**template,'id':sid,'token':format(i+4096,'032x'),'manifest_sha256':sid})
            inv['manifests'][sid]=manifest
        files=[{'path':'wordpress/file-%05d.php'%i,'bytes':100,'sha256':'a'*64} for i in range(9331)]
        for i in range(31):
            sid=format(i+65536,'064x');inv['snapshots'].append({**inv['snapshots'][0],'id':sid,'token':format(i+65536,'032x'),'manifest_sha256':sid})
            inv['manifests'][sid]={**inv['manifests'][inv['snapshots'][0]['id']],'files':files}
        compact=retention_apply.compact_authenticated_inventory(inv,NOW)
        self.assertEqual(compact['snapshots'],inv['snapshots']);self.assertNotIn('manifests',compact)
        self.assertLess(len(json.dumps(compact,separators=(',',':')).encode()),24*1024*1024)
        retention_apply.compatible_inventory(compact,inv,NOW)
        inv['snapshots'][-1]['manifest_sha256']='0'*64
        with self.assertRaises(guards.GuardError):retention_apply.compatible_inventory(compact,inv,NOW)
    def test_native_proof_producers_have_fixed_publication_boundary(self):
        self.assertTrue(callable(getattr(subject(),'publish_evidence',None)),'Native producer publication absent')

    def test_exact_runner_rejects_short_id_extra_flag_wrong_lane_or_unknown_intent(self):
        class W:
            c={'repositories':{'base':'s3:private/base','binlog':'s3:private/binlog'}}
            def __init__(self):self.calls=[]
            def retention_forget(self,lane,ids):self.calls.append((lane,ids));return b''
        w=W();intent={'candidate_ids':['1'*64],'before_inventory':{'snapshots':[{'id':'1'*64,'lane':'base'}]}}
        run=subject().ExactRunner(w,lambda:intent)
        for lane,argv in [('base',['--repo','s3:private/base','forget','1'*8]),
                          ('base',['--repo','s3:private/base','forget','1'*64,'--prune']),
                          ('binlog',['--repo','s3:private/binlog','forget','1'*64]),
                          ('base',['--repo','s3:private/base','forget','2'*64]),
                          ('base',['--repo','s3:other/base','forget','1'*64])]:
            with self.subTest(argv=argv),self.assertRaises(guards.GuardError):run(lane,argv)
        self.assertEqual(w.calls,[])
        run('base',['--repo','s3:private/base','forget','1'*64]);self.assertEqual(w.calls,[('base',['1'*64])])

    def test_receipt_origin_binds_type_code_raw_digest_inventory_and_native_producer(self):
        inv,plan,evidence=fixture()
        doc=evidence['tip']['document'];raw=(json.dumps(doc,sort_keys=True)+'\n').encode()
        origin={'format':1,'evidence_type':'tip','producer':'restore.py','code_sha':'f'*40,
                'document_sha256':retention_apply.document_digest(doc),'file_sha256':__import__('hashlib').sha256(raw).hexdigest(),
                'generation':inv['generation'],'repositories':inv['repositories'],'inventory_sha256':plan['inventory_sha256']}
        subject().verify_origin('tip',raw,doc,origin,'f'*40,inv)
        for key,value in [('producer','user-flag'),('code_sha','0'*40),('file_sha256','0'*64),('inventory_sha256','0'*64),('evidence_type','anchor')]:
            bad=copy.deepcopy(origin);bad[key]=value
            with self.subTest(key=key),self.assertRaises(guards.GuardError):subject().verify_origin('tip',raw,doc,bad,'f'*40,inv)

    def test_retained_chain_keeps_original_history_but_hides_only_retired_prefix(self):
        inv,_,_=fixture(split=True)
        logs=[inv['manifests']['5'*64]['logs'][0],inv['manifests']['4'*64]['logs'][0]]
        chain={'generation':inv['generation'],'logs':logs,'snapshots':[{'id':'5'*64,'first_log':1,'last_log':1,'manifest_sha256':'5'*64},{'id':'4'*64,'first_log':2,'last_log':2,'manifest_sha256':'4'*64}]}
        original=copy.deepcopy(chain)
        out=subject().retained_chain(chain,[{'id':'5'*64,'lane':'binlog','manifest_sha256':'5'*64}])
        self.assertEqual(out['logs'],[logs[1]]);self.assertEqual(chain,original)
        with self.assertRaises(guards.GuardError):subject().retained_chain(chain,[{'id':'4'*64,'lane':'binlog','manifest_sha256':'4'*64}])
        with self.assertRaises(guards.GuardError):subject().retained_chain(chain,[{'id':'5'*64,'lane':'binlog','manifest_sha256':'0'*64}])

if __name__=='__main__':unittest.main()
