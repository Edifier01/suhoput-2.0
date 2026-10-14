"""Synthetic daily intents: bounded native commands, crash-safe phase prefix."""
import contextlib,copy,datetime as dt,json,os,pathlib,sys,tempfile,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'infra/backup'))
import guards,retention,retention_apply,retention_native,runtime
from unittest import mock
from backup_retention_apply_test import fixture,NOW,OLD

class DailyBatchTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=pathlib.Path(self.temp.name);os.chmod(self.root,0o700)
        (self.root/'receipts/retention-applies').mkdir(mode=0o700,parents=True)
        os.chmod(self.root/'receipts',0o700)
        if os.name=='nt':
            self.enterContext(mock.patch.object(retention_native,'private_path',lambda p:pathlib.Path(p)))
            self.enterContext(mock.patch.object(retention_native,'protected_directory',lambda p:pathlib.Path(p)))
    def case(self,count=530,hourly=False):
        inv,_,evidence=fixture();old=inv['snapshots'][0]
        for number in range(count-1):
            sid=format(number+100,'064x');row={**old,'id':sid,'token':format(number+100,'032x'),'manifest_sha256':sid}
            manifest=copy.deepcopy(inv['manifests'][OLD])
            if hourly:row['kind']='hourly';manifest['full_id']=OLD
            inv['snapshots'].append(row);inv['manifests'][sid]=manifest
        plan=retention.bounded_plan(inv,retention.inventory_plan(inv,NOW),1536)
        plan.update(planned_at=NOW.isoformat(),batch_protocol='daily-batches-v2')
        for name,item in evidence.items():
            item['document']['inventory_sha256']=plan['inventory_sha256']
            if name=='audit':item['document']['readback_snapshots']={row['id']:row['manifest_sha256'] for row in inv['snapshots']}
            item['sha256']=retention_apply.document_digest(item['document'])
        plan['proof_sha256']={name:item['sha256'] for name,item in evidence.items()}
        return inv,plan,evidence
    def execute(self,inv,plan,evidence,*,fail_after=None,clock=None):
        before=copy.deepcopy(inv);self.current=inv;self.calls=[];self.receipts=[];self.sections=[];self.active=False
        store=retention_native.NewIntentStore(self.root/'receipts/retention-applies'/'daily')
        @contextlib.contextmanager
        def section(name):
            self.assertFalse(self.active);self.active=True;self.sections.append(name)
            try:yield
            finally:self.active=False
        def effect(lane,ids,**kwargs):
            self.assertTrue(self.active);self.assertLessEqual(len(ids),256)
            self.calls.append((lane,list(ids)))
            remaining=[row for row in self.current['snapshots'] if row['id'] not in ids]
            for row in remaining:
                if row['kind']=='hourly':self.assertNotIn(self.current['manifests'][row['id']]['full_id'],ids)
            self.current['snapshots']=remaining
            self.current['manifests']={sid:m for sid,m in self.current['manifests'].items() if sid not in ids}
            if fail_after==len(self.calls):raise TimeoutError('Effect response lost')
            return b''
        worker=__import__('types').SimpleNamespace(c={'repositories':{'base':'s3:private/base','binlog':'s3:private/binlog'}},retention_forget=effect)
        runner=retention_native.ExactRunner(worker,store.load,phase_reader=store.phase_documents)
        executor=retention_apply.Executor(lambda:copy.deepcopy(self.current),runner,store,self.receipts.append,worker.c['repositories'],clock=clock,phase_section=section)
        return executor.apply(before,plan,evidence,NOW),executor,store,runner
    def test_one_frozen_daily_intent_releases_locks_between_three_bounded_commands(self):
        inv,plan,evidence=self.case();result,_,store,_=self.execute(inv,plan,evidence)
        self.assertEqual(result['result'],'APPLIED');self.assertEqual([len(ids) for _,ids in self.calls],[256,256,18])
        self.assertEqual(len(store.load()['candidate_ids']),530);self.assertEqual(len(self.receipts),1)
        phases=store.phase_documents();self.assertEqual(list(phases),['0000','0001','0002'])
        self.assertEqual([d['index'] for d in phases.values()],[0,1,2]);self.assertEqual(len(result['phase_witnesses']),3)
    def test_hourly_candidates_precede_their_full_across_command_boundaries(self):
        inv,plan,evidence=self.case(hourly=True);result,_,_,_=self.execute(inv,plan,evidence)
        self.assertEqual(result['result'],'APPLIED');self.assertNotIn(OLD,self.calls[0][1]+self.calls[1][1]);self.assertIn(OLD,self.calls[2][1])
    def test_unknown_second_batch_only_reconciles_observed_authorized_prefix(self):
        inv,plan,evidence=self.case();result,executor,store,_=self.execute(inv,plan,evidence,fail_after=2)
        self.assertEqual(result['result'],'RECONCILE_REQUIRED');self.assertEqual(len(self.calls),2)
        reconciled=executor.reconcile(NOW+dt.timedelta(days=1))
        self.assertEqual(reconciled['result'],'RECONCILED');self.assertEqual(len(reconciled['forgotten_ids']),512)
        self.assertEqual(len(reconciled['present_candidate_ids']),18);self.assertEqual(len(self.calls),2)
        self.assertEqual(len(store.phase_documents()),2)
    def test_missing_or_changed_ordered_phase_blocks_reconciliation(self):
        inv,plan,evidence=self.case();_,executor,store,_=self.execute(inv,plan,evidence,fail_after=2)
        (store.root/'phase-0000.json').unlink()
        # Missing authority cannot even authorize a new receipt: fail closed.
        with self.assertRaisesRegex(guards.GuardError,'Batch authorization gap'):executor.reconcile(NOW)
        self.assertEqual(len(self.calls),2)
    def test_daily_intent_and_native_command_have_separate_hard_bounds(self):
        inv,plan,evidence=self.case(1600);self.assertEqual(len(plan['candidates']),1536)
        result,_,store,runner=self.execute(inv,plan,evidence);self.assertEqual(result['result'],'APPLIED')
        self.assertEqual([len(ids) for _,ids in self.calls],[256]*6)
        with self.assertRaises(guards.GuardError):runner('base',['--repo','s3:private/base','forget',*store.load()['candidate_ids'][:257]])

    def test_binlog_commands_preserve_original_prefix_despite_reverse_native_ids(self):
        rows=[];manifests={}
        for number in range(1,531):
            sid=format(1000-number,'064x');rows.append({'id':sid,'lane':'binlog'});manifests[sid]={'first_log':number}
        batches=retention_apply.command_batches({'snapshots':rows,'manifests':manifests},[r['id'] for r in rows])
        self.assertEqual([len(batch['candidate_ids']) for batch in batches],[256,256,18])
        for index,batch in enumerate(batches):
            self.assertEqual(sorted(manifests[sid]['first_log'] for sid in batch['candidate_ids']),list(range(index*256+1,min((index+1)*256,530)+1)))

    def test_second_command_rechecks_original_nine_hundred_second_freshness(self):
        inv,plan,evidence=self.case()
        result,_,store,_=self.execute(inv,plan,evidence,clock=lambda:NOW+dt.timedelta(seconds=901 if self.calls else 0))
        self.assertEqual(result['result'],'RECONCILE_REQUIRED');self.assertEqual(len(self.calls),1)
        self.assertEqual(len(store.phase_documents()),1);self.assertEqual(len(result['forgotten_ids']),256)

    def test_unattempted_absence_is_unknown_after_partial_command_response(self):
        inv,plan,evidence=self.case();_,executor,store,_=self.execute(inv,plan,evidence,fail_after=1)
        sid=store.load()['batches'][1]['candidate_ids'][0]
        self.current['snapshots']=[row for row in self.current['snapshots'] if row['id']!=sid];del self.current['manifests'][sid]
        result=executor.reconcile(NOW);self.assertEqual(result['result'],'RECONCILE_REQUIRED')
        self.assertIsNone(result['forgotten_ids']);self.assertEqual(len(self.calls),1)

if __name__=='__main__':unittest.main()
