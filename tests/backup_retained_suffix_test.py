"""Synthetic suffix and tombstone failures. No external effects."""
import copy
import datetime as dt
import pathlib
import sys
import tempfile
import unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'infra/backup'))
import guards, retention, retention_apply, runtime, restore
from backup_retention_apply_test import fixture, GEN, NOW, OLD

class RetainedSuffixTests(unittest.TestCase):
    def suffix(self):
        inventory, _, _ = fixture(split=True)
        gone = {OLD, '5'*64}
        inventory['snapshots'] = [r for r in inventory['snapshots'] if r['id'] not in gone]
        inventory['manifests'] = {sid:m for sid,m in inventory['manifests'].items() if sid not in gone}
        return inventory

    def test_authenticated_suffix_preserves_original_previous_count_and_base(self):
        inventory = self.suffix()
        plan = retention.inventory_plan(inventory, NOW)
        self.assertEqual([r['file'] for r in plan['logs']], ['suhoput2-binlog.000002'])
        self.assertEqual(plan['candidates'], [])
        restore.validate_tip_end({'file':'suhoput2-binlog.000002','position':500}, plan['logs'])

    def test_fabricated_zero_prefix_gap_and_base_before_retained_suffix_fail(self):
        for mode in ('zero','gap','base'):
            inventory = self.suffix()
            if mode == 'zero': inventory['manifests']['4'*64]['previous_count'] = 0
            elif mode == 'gap': inventory['manifests']['4'*64]['first_log'] = 3
            else: inventory['manifests']['2'*64]['coordinates']['file'] = 'suhoput2-binlog.000001'
            with self.subTest(mode=mode), self.assertRaises(guards.GuardError):
                retention.inventory_plan(inventory, NOW)

    def test_hourly_anchor_keeps_older_full_as_application_dependency(self):
        inventory=self.suffix()
        old,_,_=fixture(split=True)
        inventory['snapshots'].insert(0,old['snapshots'][0]);inventory['manifests'][OLD]=old['manifests'][OLD]
        inventory['snapshots'][1]['kind']='hourly';inventory['manifests']['2'*64]['full_id']=OLD
        plan=retention.inventory_plan(inventory,NOW)
        self.assertIn(OLD,plan['keep']);self.assertEqual(plan['candidates'],[])
        later=retention.inventory_plan(inventory,NOW+dt.timedelta(days=31))
        self.assertIn(OLD,later['candidates']);self.assertIn('2'*64,later['candidates'])

    def test_absent_confirmation_requires_exact_proven_tombstone(self):
        inventory, plan, evidence = fixture(split=True)
        before = copy.deepcopy(inventory)
        journals = {lane:{'confirmed':[{k:r[k] for k in ('id','token','manifest_sha256')}
                     for r in before['snapshots'] if r['lane']==lane]} for lane in ('base','binlog')}
        from backup_retention_apply_test import MemoryIntent
        store = MemoryIntent(); receipts=[]
        def forget(lane, argv):
            gone=set(argv[3:]); inventory['snapshots']=[r for r in inventory['snapshots'] if r['id'] not in gone]
            inventory['manifests']={sid:m for sid,m in inventory['manifests'].items() if sid not in gone}
        executor=retention_apply.Executor(lambda:copy.deepcopy(inventory),forget,store,receipts.append,
                                          {'base':'local-base','binlog':'local-binlog'})
        receipt=executor.apply(before,plan,evidence,NOW)
        self.assertEqual(receipt['result'],'APPLIED')
        tombstones=retention_apply.retention_tombstones(store.load(),receipt)
        with self.assertRaises(guards.GuardError): retention.confirmed_inventory(inventory,journals)
        retention.confirmed_inventory(inventory,journals,tombstones)
        for mode in ('missing','wrong-hash','arrival','duplicate'):
            bad=copy.deepcopy(tombstones)
            if mode=='missing':bad.pop()
            elif mode=='wrong-hash':bad[0]['manifest_sha256']='0'*64
            elif mode=='arrival':bad[0]['id']='4'*64
            else:bad.append(bad[0])
            with self.subTest(mode=mode),self.assertRaises(guards.GuardError):retention.confirmed_inventory(inventory,journals,bad)

    def test_journal_retirement_is_idempotent_and_does_not_rewrite_confirmations(self):
        inventory,plan,evidence=fixture(split=True)
        from backup_retention_apply_test import MemoryIntent
        store=MemoryIntent()
        before=copy.deepcopy(inventory)
        def forget(lane,argv):
            gone=set(argv[3:]);inventory['snapshots']=[r for r in inventory['snapshots'] if r['id'] not in gone]
            inventory['manifests']={sid:m for sid,m in inventory['manifests'].items() if sid not in gone}
        ex=retention_apply.Executor(lambda:copy.deepcopy(inventory),forget,store,lambda r:None,
                                    {'base':'local-base','binlog':'local-binlog'})
        receipt=ex.apply(before,plan,evidence,NOW)
        with tempfile.TemporaryDirectory() as temp:
            journal=runtime.UploadJournal(pathlib.Path(temp)/'base',GEN)
            confirmations=[{k:r[k] for k in ('id','token','manifest_sha256')} for r in before['snapshots'] if r['lane']=='base']
            runtime.atomic_json(journal.root/'state.json',{'generation':GEN,'confirmed':confirmations})
            journal.retire(store.load(),receipt,'base')
            saved=journal.state();self.assertEqual(saved['confirmed'],confirmations)
            journal.retire(store.load(),receipt,'base');self.assertEqual(journal.state(),saved)
            self.assertEqual([r['id'] for r in saved['retention']],[OLD])
            bad=copy.deepcopy(receipt);bad['result']='RECONCILE_REQUIRED'
            with self.assertRaises(guards.GuardError):journal.retire(store.load(),bad,'base')

if __name__ == '__main__':unittest.main()
