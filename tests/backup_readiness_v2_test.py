"""Native-v2 policy fixtures; no provider access or real deletion."""
import copy, datetime as dt, hashlib, importlib.util, os, pathlib, sys, unittest
from unittest import mock
sys.path[:0]=[str(pathlib.Path(__file__).resolve().parents[1]/'infra/backup')]
import guards, retention_apply
from backup_retention_apply_test import fixture, digest, NOW, GEN, SOURCE, OLD


def v2_fixture():
    inventory,plan,evidence=fixture()
    plan['readiness_policy']='native-v2';evidence.pop('history')
    report={'format':'commissioning_budget_pass','result':'PASS','source':SOURCE,'generation':GEN,
            'bucket':'stage-b','configuration_sha256':'a'*64,'scope_sha256':'b'*64,
            'actual_month_observed':False,'invoice_verified':False,'projected_monthly_rub':'300',
            'projected_storage_bytes':1000000,'completed_at':(NOW-dt.timedelta(days=2)).isoformat(),
            'valid_until':(NOW+dt.timedelta(days=20)).isoformat()}
    evidence['budget']={'document':report,'sha256':digest(report)}
    plan['proof_sha256']={name:item['sha256'] for name,item in evidence.items()}
    return inventory,plan,evidence


class NativeV2Tests(unittest.TestCase):
    def weekly_fixture(self,*,legacy=False):
        import integrity,retention
        inventory,plan,evidence=fixture() if legacy else v2_fixture()
        for row in inventory['snapshots']:row['tree']='9'*64
        lanes={}
        for lane in ('base','binlog'):
            current={r['id']:[r['tree'],r['token'],r['manifest_sha256']] for r in inventory['snapshots'] if r['lane']==lane}
            proof={'started_at':(NOW-dt.timedelta(days=2)).isoformat(),'completed_at':(NOW-dt.timedelta(days=2)).isoformat(),'snapshots':current}
            lanes[lane]={**integrity.coverage(proof,current,[],current,at=NOW,lane=lane),'repository_id':inventory['repositories'][lane],
                         'observed_current_snapshots_sha256':integrity.digest(current),'observed_current_snapshot_count':len(current),
                         'proof_sha256':'a'*64,'snapshots_sha256':'b'*64,'nonce':'c'*32}
        report={'format':integrity.MODE,'coverage_checked_at':NOW.isoformat(),'lanes':lanes}
        evidence['audit']['document'].update(check_mode=integrity.MODE,full_remote_integrity=report)
        evidence['owner']['document'].update(integrity_check_mode=integrity.MODE,full_remote_integrity=copy.deepcopy(report))
        plan['inventory_sha256']=retention.inventory_digest(inventory)
        for name,item in evidence.items():
            if name!='budget':item['document']['inventory_sha256']=plan['inventory_sha256']
            item['sha256']=digest(item['document'])
        plan['proof_sha256']={name:item['sha256'] for name,item in evidence.items()}
        return inventory,plan,evidence

    def test_weekly_coverage_is_explicit_native_v2_only_and_keeps_old_full_read_time(self):
        inventory,plan,evidence=self.weekly_fixture()
        retention_apply.validate_apply(inventory,plan,evidence,NOW)
        self.assertNotEqual(evidence['audit']['document']['completed_at'],evidence['audit']['document']['full_remote_integrity']['lanes']['base']['full_remote_completed_at'])
        inventory,plan,evidence=self.weekly_fixture(legacy=True)
        with self.assertRaises(guards.GuardError):retention_apply.validate_apply(inventory,plan,evidence,NOW)

    def test_weekly_age_and_exact_coverage_remain_mandatory_even_with_fresh_audit(self):
        for change in ('expired','future','identities','repository','partial'):
            inventory,plan,evidence=self.weekly_fixture();report=evidence['audit']['document']['full_remote_integrity'];row=report['lanes']['base']
            if change=='expired':row['full_remote_started_at']=row['full_remote_completed_at']=(NOW-dt.timedelta(days=8)).isoformat()
            elif change=='future':row['full_remote_completed_at']=(NOW+dt.timedelta(seconds=1)).isoformat()
            elif change=='identities':row['current_snapshots_sha256']='0'*64
            elif change=='repository':row['repository_id']='0'*64
            else:del report['lanes']['binlog']
            evidence['audit']['sha256']=digest(evidence['audit']['document']);plan['proof_sha256']['audit']=evidence['audit']['sha256']
            with self.subTest(change=change),self.assertRaises(guards.GuardError):retention_apply.validate_apply(inventory,plan,evidence,NOW)

    def test_runtime_config_defaults_to_legacy_and_accepts_only_fixed_policy_names(self):
        import worker
        from backup_worker_test import config
        self.assertEqual(worker.validate_config(config()).get('retention_readiness_policy'),'legacy-v1')
        for policy in ('legacy-v1','native-v2'):
            self.assertEqual(worker.validate_config({**config(),'retention_readiness_policy':policy})['retention_readiness_policy'],policy)
        for policy in (None,True,'native-v3',{'history':False}):
            with self.subTest(policy=policy),self.assertRaises(guards.GuardError):worker.validate_config({**config(),'retention_readiness_policy':policy})

    def test_native_v2_accepts_valid_forecast_without_history_and_preserves_policy(self):
        inventory,plan,evidence=v2_fixture()
        binding=retention_apply.validate_apply(inventory,plan,evidence,NOW)
        self.assertEqual(binding['candidate_ids'],[OLD]);self.assertEqual(binding['readiness_policy'],'native-v2')
        self.assertNotIn('history',binding['proof_sha256'])
        retention_apply.current_freshness(plan,evidence,NOW)

    def test_legacy_still_requires_six_current_inventory_bound_receipts(self):
        inventory,plan,evidence=fixture();retention_apply.validate_apply(inventory,plan,evidence,NOW)
        evidence.pop('history');plan['proof_sha256'].pop('history')
        with self.assertRaises(guards.GuardError):retention_apply.validate_apply(inventory,plan,evidence,NOW)
        inventory,plan,evidence=v2_fixture();plan.pop('readiness_policy')
        with self.assertRaises(guards.GuardError):retention_apply.validate_apply(inventory,plan,evidence,NOW)

    def test_policy_cannot_be_relaxed_or_unknown(self):
        for policy in ('native-v3',{'policy':'native-v2','max_age':999999},None,True):
            inventory,plan,evidence=v2_fixture();plan['readiness_policy']=policy
            with self.subTest(policy=policy),self.assertRaises(guards.GuardError):retention_apply.validate_apply(inventory,plan,evidence,NOW)

    def test_current_proofs_age_identity_and_owner_requirements_are_unchanged(self):
        cases=[('audit','completed_at',(NOW-dt.timedelta(seconds=901)).isoformat()),
               ('anchor','base_id',OLD),('tip','additional_order_operation_present',False),
               ('owner','executed_by','agent'),('owner','machine_id','vps-stage'),
               ('owner','completed_at',(NOW-dt.timedelta(seconds=901)).isoformat()),
               ('audit','inventory_sha256','0'*64)]
        for name,key,value in cases:
            inventory,plan,evidence=v2_fixture();evidence[name]['document'][key]=value
            evidence[name]['sha256']=digest(evidence[name]['document']);plan['proof_sha256'][name]=evidence[name]['sha256']
            with self.subTest(name=name,key=key),self.assertRaises(guards.GuardError):retention_apply.validate_apply(inventory,plan,evidence,NOW)

    def test_forecast_expiry_scope_limits_and_honest_format_are_required(self):
        changes=[('format','legacy'),('result','BLOCK'),('source',{'root':'foreign'}),('generation','0'*32),
                 ('configuration_sha256','bad'),('scope_sha256','bad'),('actual_month_observed',True),
                 ('invoice_verified',True),('valid_until',(NOW-dt.timedelta(seconds=1)).isoformat()),
                 ('completed_at',(NOW+dt.timedelta(seconds=1)).isoformat()),('projected_monthly_rub','501'),
                 ('projected_monthly_rub','NaN'),('projected_monthly_rub',True),('projected_storage_bytes',11*1024**3)]
        for key,value in changes:
            inventory,plan,evidence=v2_fixture();evidence['budget']['document'][key]=value
            evidence['budget']['sha256']=digest(evidence['budget']['document']);plan['proof_sha256']['budget']=evidence['budget']['sha256']
            with self.subTest(key=key,value=value),self.assertRaises(guards.GuardError):retention_apply.validate_apply(inventory,plan,evidence,NOW)

    def test_pre_effect_clock_does_not_extend_forecast_or_current_proofs(self):
        inventory,plan,evidence=v2_fixture()
        evidence['budget']['document']['valid_until']=(NOW+dt.timedelta(seconds=1)).isoformat()
        with self.assertRaises(guards.GuardError):retention_apply.current_freshness(plan,evidence,NOW+dt.timedelta(seconds=2))
        _,plan,evidence=v2_fixture();evidence['owner']['document']['completed_at']=(NOW-dt.timedelta(seconds=901)).isoformat()
        with self.assertRaises(guards.GuardError):retention_apply.current_freshness(plan,evidence,NOW)

    def test_v2_executor_preserves_exact_intent_and_readonly_reconciliation(self):
        from backup_retention_apply_test import ApplyTests
        case=ApplyTests();case.inventory,case.plan,case.evidence=v2_fixture()
        before=copy.deepcopy(case.inventory);executor=case.executor()
        result=executor.apply(before,case.plan,case.evidence,NOW)
        self.assertEqual(result['result'],'APPLIED');self.assertEqual(case.calls,[('base',['--repo','s3:private/base','forget',OLD])])
        self.assertEqual(case.store.value['readiness_policy'],'native-v2')
        self.assertEqual(result.get('readiness_policy'),'native-v2')
        self.assertEqual(case.store.value['proof_sha256'],case.plan['proof_sha256'])
        again=executor.apply(before,case.plan,case.evidence,NOW)
        self.assertEqual(again['result'],'RECONCILE_REQUIRED');self.assertEqual(len(case.calls),1)


@unittest.skipIf(os.name!='posix','Real protected producer ownership requires Linux root')
class ProtectedReadinessTests(unittest.TestCase):
    def fixture(self):
        from backup_budget_test import ProtectedCommissioningTests
        import retention,retention_native,runtime,storage
        case=ProtectedCommissioningTests();self.addCleanup(case.doCleanups)
        budget,worker,_=case.fixture();report=budget.publish_commissioning_budget(worker,now=NOW)
        inventory,_,evidence=v2_fixture();inventory['generation']=worker.c['generation']
        for row in inventory['snapshots']:row['generation']=worker.c['generation']
        for manifest in inventory['manifests'].values():manifest['source']=worker.source
        directory=worker.root/'receipts/retention-proofs';directory.mkdir(mode=0o700)
        for name in ('audit','anchor','tip','owner'):
            producer=worker.bin/retention_native.PRODUCERS[name]
            if not producer.exists():producer.write_bytes(b'# synthetic installed producer\n');os.chmod(producer,0o600)
            doc=evidence[name]['document'];doc.update(generation=worker.c['generation'],source=worker.source,
                inventory_sha256=retention.inventory_digest(inventory))
            path=worker.root/'receipts'/retention_native.RECEIPTS[name];runtime.atomic_json(path,doc)
            origin={'format':1,'evidence_type':name,'producer':producer.name,'producer_sha256':hashlib.sha256(producer.read_bytes()).hexdigest(),
                    'code_sha':worker.c['code_sha'],'file_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                    'document_sha256':digest(doc),'generation':inventory['generation'],'repositories':inventory['repositories'],
                    'inventory_sha256':retention.inventory_digest(inventory)}
            runtime.atomic_json(directory/(name+'.origin.json'),origin)
        self.assertIsNotNone(importlib.util.find_spec('readiness_v2'),'Protected native-v2 loader absent')
        import readiness_v2
        observation={'format':'commissioning-live-observation-v1','bucket':report['bucket'],'scope_sha256':report['scope_sha256'],
                     'generation':worker.c['generation'],'source':worker.source,'observed_at':NOW.isoformat(),
                     'prefix':'','complete':True,'physical_bytes':1024**3,'object_count':10,'workload':report['inventory']['workload']}
        storage.publish_live_observation(worker,report,observation)
        return readiness_v2,budget,worker,inventory,report

    def test_fixed_loader_uses_actual_protected_forecast_without_legacy_history_budget_files(self):
        module,budget,worker,inventory,report=self.fixture()
        evidence=module.load_evidence(worker,inventory,at=NOW)
        self.assertEqual(set(evidence),{'audit','anchor','tip','owner','budget'})
        self.assertEqual(evidence['budget'],{'document':report,'sha256':digest(report)})
        self.assertFalse((worker.root/'receipts/history.json').exists());self.assertFalse((worker.root/'receipts/budget-projection.json').exists())
        self.assertTrue(module.revalidate_budget(worker,evidence,at=NOW))

    def test_changed_origin_installed_producer_forecast_or_cost_config_blocks(self):
        import retention_native,runtime
        for kind in ('origin','producer','forecast','configuration'):
            module,budget,worker,inventory,report=self.fixture()
            evidence=module.load_evidence(worker,inventory,at=NOW)
            path={'origin':worker.root/'receipts/retention-proofs/owner.origin.json',
                  'producer':worker.bin/retention_native.PRODUCERS['owner'],
                  'forecast':worker.root/'receipts/commissioning-budget.json',
                  'configuration':worker.root/'receipts/commissioning-inputs/configuration.json'}[kind]
            if kind=='origin':
                origin=runtime.load_json(path);origin['producer_sha256']='0'*64;runtime.atomic_json(path,origin)
            else:path.write_bytes(path.read_bytes()+b' ')
            with self.subTest(kind=kind),self.assertRaises(guards.GuardError):module.load_evidence(worker,inventory,at=NOW)
            if kind in ('forecast','configuration'):
                with self.assertRaises(guards.GuardError):module.revalidate_budget(worker,evidence,at=NOW)

    def test_effect_revalidation_rejects_stale_or_changed_monitor_observation(self):
        import storage,runtime
        module,budget,worker,inventory,report=self.fixture();evidence=module.load_evidence(worker,inventory,at=NOW)
        with self.assertRaises(guards.GuardError):module.revalidate_budget(worker,evidence,at=NOW+dt.timedelta(seconds=121))
        path=worker.root/'receipts/commissioning-live.json';value=runtime.load_json(path)
        value['forecast_sha256']='0'*64;runtime.atomic_json(path,value)
        with self.assertRaises(guards.GuardError):module.revalidate_budget(worker,evidence,at=NOW)


if __name__=='__main__':unittest.main()
