"""Actual local lock contention; no native commands or external services."""
import contextlib,datetime as dt,os,pathlib,sys,tempfile,threading,time,unittest
from types import SimpleNamespace
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'infra/backup'))
import guards,retention_cohort,runtime,worker

class RetentionLockTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=pathlib.Path(self.temp.name)
        (self.root/'receipts/base').mkdir(parents=True);(self.root/'receipts/binlog').mkdir()
        self.w=SimpleNamespace(root=self.root)
    def test_group_wait_releases_partial_locks_before_waiting_and_runs_body_once(self):
        attempted=threading.Event();entered=[];errors=[];original=runtime.lane_lock
        @contextlib.contextmanager
        def observed(path):
            if threading.current_thread().name=='retention' and pathlib.Path(path).name=='job-binlog.lock':attempted.set()
            with original(path):yield
        def run():
            try:
                with retention_cohort.upload_section(self.w):entered.append(True)
            except BaseException as error:errors.append(error)
        with original(self.root/'receipts/job-binlog.lock'),mock.patch.object(runtime,'lane_lock',observed):
            thread=threading.Thread(target=run,name='retention');thread.start();self.assertTrue(attempted.wait(2))
            time.sleep(.04)
            with original(self.root/'receipts/job-base.lock'):self.assertEqual(entered,[])
            self.assertTrue(thread.is_alive(),'Ordinary minute contention must wait')
        thread.join(2);self.assertFalse(thread.is_alive());self.assertEqual(errors,[]);self.assertEqual(entered,[True])
    def test_group_body_busy_is_never_reentered(self):
        calls=[]
        with self.assertRaises(runtime.LaneBusyError):
            with retention_cohort.upload_section(self.w):calls.append(True);raise runtime.LaneBusyError('Body failure')
        self.assertEqual(calls,[True])
        with retention_cohort.upload_section(self.w):pass
    def test_group_acquisition_deadline_releases_every_partial_lock(self):
        start=time.monotonic()
        with runtime.lane_lock(self.root/'receipts/job-binlog.lock'):
            with self.assertRaises(guards.GuardError):
                with retention_cohort.upload_section(self.w,deadline=start+.06):self.fail('Unavailable group entered')
        self.assertLess(time.monotonic()-start,.5)
        with retention_cohort.upload_section(self.w):pass
    def minute(self):
        w=worker.Worker.__new__(worker.Worker);w.root=self.root;w.source_check=lambda:None;w.gate=lambda:None
        calls=[];w.pending_payload=lambda lane:'existing-payload'
        w.upload=lambda lane,payload:(calls.append((lane,payload)) or 'a'*64)
        w.finalize=lambda *args:{'captured_at':dt.datetime.now(dt.timezone.utc).isoformat()}
        return w,calls
    def test_worker_minute_waits_once_for_retention_group_with_original_deadline(self):
        w,calls=self.minute();errors=[];results=[]
        def run():
            try:results.append(w.binlog())
            except BaseException as error:errors.append(error)
        with mock.patch('maintenance.require_clear',return_value=None),retention_cohort.upload_section(self.w):
            thread=threading.Thread(target=run);thread.start();time.sleep(.05)
            self.assertTrue(thread.is_alive(),'Minute must wait before its body');self.assertEqual(calls,[])
        thread.join(2);self.assertEqual(errors,[]);self.assertEqual(len(calls),1);self.assertTrue(results[0]['reconciled'])
        self.assertFalse(hasattr(w,'_binlog_job_deadline'))
    def test_worker_wait_never_restarts_expired_minute_budget(self):
        w,calls=self.minute();w._binlog_job_deadline=time.monotonic()+.06
        with mock.patch('maintenance.require_clear',return_value=None),retention_cohort.upload_section(self.w),self.assertRaises(guards.GuardError):w.binlog()
        self.assertEqual(calls,[])
    def test_waiting_minute_runs_between_back_to_back_retention_groups(self):
        import backup_catalog
        w,calls=self.minute();waiting=threading.Event();retry=threading.Event();second_attempt=threading.Event()
        order=[];errors=[];sleep=time.sleep;original_upload=w.upload
        def upload(*args):order.append('minute');return original_upload(*args)
        w.upload=upload
        def pause(seconds):
            if threading.current_thread().name=='minute' and not retry.is_set():
                waiting.set();self.assertTrue(retry.wait(2))
            else:sleep(seconds)
        def minute():
            try:w.binlog()
            except BaseException as error:errors.append(error)
        def next_group():
            second_attempt.set()
            try:
                with retention_cohort.upload_section(self.w,deadline=time.monotonic()+2):order.append('retention')
            except BaseException as error:errors.append(error)
        with mock.patch('maintenance.require_clear',return_value=None),mock.patch.object(backup_catalog.time,'sleep',pause):
            with retention_cohort.upload_section(self.w):
                writer=threading.Thread(target=minute,name='minute');writer.start();self.assertTrue(waiting.wait(2))
            second=threading.Thread(target=next_group,name='retention');second.start();self.assertTrue(second_attempt.wait(2));sleep(.06)
            before=list(order);retry.set();writer.join(2);second.join(2)
        self.assertEqual(before,[],'A queued minute must prevent the next retention group from overtaking it')
        self.assertEqual(errors,[]);self.assertEqual(order,['minute','retention']);self.assertEqual(len(calls),1)
        self.assertFalse(writer.is_alive());self.assertFalse(second.is_alive())

if __name__=='__main__':unittest.main()
