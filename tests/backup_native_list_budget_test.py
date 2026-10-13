"""A completed native LIST may evict arrivals; its overlap must be bounded."""
import pathlib, sys, time, unittest
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'infra/backup'))
import retention
import worker
import backup_cohort_test

class NativeListBudgetTests(unittest.TestCase):
    def case(self):
        c=backup_cohort_test.NativeCohortTests();c.setUp();self.addCleanup(c.doCleanups);return c

    def test_native_v2_snapshot_commands_have_finite_overlap_outside_group(self):
        c=self.case();c.w.c['retention_readiness_policy']='native-v2';calls=[];real=c.w.restic
        def native(lane,args,**kwargs):
            calls.append((args[2:],kwargs.copy()));return real(lane,args,**kwargs)
        c.w.restic=native
        retention.native_inventory(c.w,backup_cohort_test.NOW,c.initial['repositories'])
        lists=[kw for args,kw in calls if args==['snapshots','--json']]
        self.assertEqual(lists,[{'timeout':55},{'timeout':55}])
        self.assertTrue(all(not kw for args,kw in calls if args!=['snapshots','--json']))

    def test_existing_stricter_critical_deadline_still_wins(self):
        c=self.case();c.w.c['retention_readiness_policy']='native-v2';limits=[];real=c.w.restic
        def native(lane,args,**kwargs):
            limits.append(kwargs['timeout']);return real(lane,args,**kwargs)
        c.w.restic=native
        with c.catalog().open_reader() as reader:
            retention.native_inventory(c.w,backup_cohort_test.NOW,c.initial['repositories'],reader=reader,deadline=time.monotonic()+10)
        self.assertTrue(limits and all(0<v<=10 for v in limits))

    def test_snapshot_timeout_is_propagated_without_retry_or_effect(self):
        c=self.case();c.w.c['retention_readiness_policy']='native-v2';real=c.w.restic;calls=[]
        def native(lane,args,**kwargs):
            calls.append(args[2:])
            if args[2:]==['snapshots','--json']:raise TimeoutError('LIST overlap budget')
            return real(lane,args,**kwargs)
        c.w.restic=native
        with self.assertRaisesRegex(TimeoutError,'LIST overlap budget'):
            retention.native_inventory(c.w,backup_cohort_test.NOW,c.initial['repositories'])
        self.assertEqual(calls,[['cat','config'],['snapshots','--json']])
        self.assertFalse((c.root/'receipts/retention-applies').exists())

    def test_prepared_tail_refresh_also_bounds_snapshot_overlap(self):
        c=self.case();c.w.c['retention_readiness_policy']='native-v2';real=c.w.restic;calls=[]
        def native(lane,args,**kwargs):calls.append((args[2:],kwargs));return real(lane,args,**kwargs)
        with c.catalog().open_reader() as reader:
            views={};current=retention.native_inventory(c.w,backup_cohort_test.NOW,c.initial['repositories'],reader=reader,native_views=views)
            c.w.restic=native
            retention.refresh_prepared_inventory(c.w,current,views,reader,[],backup_cohort_test.NOW)
        self.assertEqual([kw for args,kw in calls if args==['snapshots','--json']],[{'timeout':55},{'timeout':55}])

    def test_outside_checkpoint_retirement_view_also_bounds_overlap(self):
        c=self.case();c.w.c['retention_readiness_policy']='native-v2';real=c.w.restic;calls=[]
        def native(lane,args,**kwargs):calls.append((args[2:],kwargs));return real(lane,args,**kwargs)
        c.w.restic=native
        with c.catalog().open_reader() as reader:c.catalog()._retirement_evidence(reader._records)
        self.assertEqual([kw for args,kw in calls if args==['snapshots','--json']],[{'timeout':55},{'timeout':55}])

    def test_worker_central_cap_covers_tagged_lists_and_keeps_stricter_deadline(self):
        c=self.case();w=worker.Worker.__new__(worker.Worker)
        w.c={**c.w.c,'retention_readiness_policy':'native-v2','region':'ru-1'};w.root=c.root
        w.credentials={};w.password=c.root/'password';w.binary=c.root/'restic';w.native=mock.Mock()
        w.native.run.return_value=b'[]';args=['--repo',w.c['repositories']['binlog'],'snapshots','--json','--tag','token:'+'a'*32]
        w.restic('binlog',args);self.assertEqual(w.native.run.call_args.kwargs['timeout'],55)
        w.restic('binlog',args,timeout=9);self.assertEqual(w.native.run.call_args.kwargs['timeout'],9)
        w.c['retention_readiness_policy']='legacy-v1';w.restic('binlog',args)
        self.assertEqual(w.native.run.call_args.kwargs['timeout'],900)

if __name__=='__main__':unittest.main()
