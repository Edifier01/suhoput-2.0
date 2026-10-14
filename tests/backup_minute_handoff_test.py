"""POSIX scheduling-only minute handoff; no archive/native/effect authority."""
import contextlib,hashlib,json,os,pathlib,socket,subprocess,sys,tempfile,threading,time,types,unittest,uuid
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'infra/backup'))
import backup_catalog,guards,retention_cohort,runtime

@unittest.skipUnless(os.name=='posix' and hasattr(socket,'AF_UNIX'),'POSIX scheduling primitive')
class MinuteHandoffTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=pathlib.Path(self.tmp.name);(self.root/'receipts').mkdir(mode=0o700)
        self.w=types.SimpleNamespace(root=self.root,c={'generation':'1'*32,'code_sha':'2'*40},source={'root':str(self.root),'generation':'1'*32})
    def channel(self):
        directory=self.root/'receipts/minute-turns';directory.mkdir(mode=0o700,exist_ok=True)
        nonce=uuid.uuid4().hex;path=directory/(nonce+'.sock');s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM);s.bind(str(path));path.chmod(0o600)
        self.addCleanup(s.close);return s,path,nonce
    def test_successful_completed_minute_signals_a_fresh_request_before_unlock(self):
        receiver,path,nonce=self.channel();receiver.settimeout(.1);steps=[]
        with retention_cohort.minute_job(self.w,time.monotonic()+1):steps.extend(['ACK','finalized'])
        try:raw=receiver.recv(4096)
        except socket.timeout:raw=None
        self.assertIsNotNone(raw,'Completed minute never handed its fresh reserved turn to Native')
        value=json.loads(raw);self.assertEqual(value['request'],nonce);self.assertEqual(value['generation'],self.w.c['generation']);self.assertEqual(value['code_sha'],self.w.c['code_sha'])
        self.assertEqual(value['source_sha256'],hashlib.sha256(backup_catalog.canonical(self.w.source)).hexdigest());self.assertEqual(steps,['ACK','finalized'])
    def wait_thread(self,deadline):
        result=[];errors=[]
        def run():
            try:result.append(retention_cohort.wait_for_minute_turn(self.w,deadline))
            except BaseException as error:errors.append(error)
        t=threading.Thread(target=run);t.start();self.addCleanup(lambda:t.join(timeout=2))
        start=time.monotonic();directory=self.root/'receipts/minute-turns'
        while not directory.exists() or not list(directory.glob('*.sock')):
            if errors:raise errors[0]
            self.assertLess(time.monotonic()-start,1);time.sleep(.005)
        return t,result,errors,list(directory.glob('*.sock'))[0]
    def test_wait_consumes_exact_nonce_once_and_holds_no_group_lock(self):
        t,result,errors,path=self.wait_thread(time.monotonic()+1)
        for name in ('job-base.lock','job-binlog.lock','base/lane.lock','binlog/lane.lock'):
            lock=self.root/'receipts'/name;lock.parent.mkdir(mode=0o700,exist_ok=True)
            with runtime.lane_lock(lock):pass
        with retention_cohort.minute_job(self.w,time.monotonic()+1):pass
        t.join(timeout=1);self.assertFalse(t.is_alive());self.assertEqual(errors,[]);self.assertEqual(len(result),1);self.assertFalse(path.exists())
        self.assertEqual(result[0]['request'],path.stem);self.assertNotIn('PASS',result[0]);self.assertNotIn('native',result[0])
    def test_handoff_works_across_distinct_real_processes_with_shared_OS_locks(self):
        t,result,errors,path=self.wait_thread(time.monotonic()+2)
        code="import pathlib,sys,time,types;sys.path.insert(0,sys.argv[2]);import retention_cohort;root=pathlib.Path(sys.argv[1]);w=types.SimpleNamespace(root=root,c={'generation':'1'*32,'code_sha':'2'*40},source={'root':str(root),'generation':'1'*32});"+"\nwith retention_cohort.minute_job(w,time.monotonic()+1):pass\n"
        run=subprocess.run([sys.executable,'-B','-c',code,str(self.root),str(pathlib.Path(retention_cohort.__file__).parent)],capture_output=True,timeout=3)
        t.join(timeout=1);self.assertEqual(run.returncode,0,run.stderr);self.assertFalse(t.is_alive());self.assertEqual(errors,[]);self.assertEqual(len(result),1);self.assertFalse(path.exists())
    def test_body_exception_and_expired_finalization_do_not_send_and_release_locks(self):
        for body_error in (ValueError('original'),KeyboardInterrupt('original'),guards.GuardError('original')):
            with self.subTest(error=type(body_error).__name__):
                receiver,path,nonce=self.channel();receiver.settimeout(.02)
                with self.assertRaises(type(body_error)) as caught:
                    with retention_cohort.minute_job(self.w,time.monotonic()+1):raise body_error
                self.assertIs(caught.exception,body_error)
                with self.assertRaises(socket.timeout):receiver.recv(4096)
                path.unlink()
        receiver,path,nonce=self.channel();receiver.settimeout(.02)
        with self.assertRaisesRegex(guards.GuardError,'Minute job original deadline exceeded'):
            with retention_cohort.minute_job(self.w,time.monotonic()+.03):time.sleep(.04)
        with self.assertRaises(socket.timeout):receiver.recv(4096)
        with runtime.lane_lock(self.root/'receipts/job-binlog-wait.lock'),runtime.lane_lock(self.root/'receipts/job-binlog.lock'):pass
    def test_wait_original_deadline_timeout_cleans_only_owned_socket(self):
        t,result,errors,path=self.wait_thread(time.monotonic()+.08);t.join(timeout=1)
        self.assertEqual(result,[]);self.assertEqual(len(errors),1);self.assertIsInstance(errors[0],guards.GuardError);self.assertFalse(path.exists())
    def test_no_request_is_original_minute_behavior_and_notify_is_nonblocking(self):
        with retention_cohort.minute_job(self.w,time.monotonic()+1):pass
        self.assertFalse((self.root/'receipts/minute-turns').exists())
        receiver,path,nonce=self.channel();receiver.close()
        start=time.monotonic()
        with retention_cohort.minute_job(self.w,time.monotonic()+1):pass
        self.assertLess(time.monotonic()-start,.2);self.assertTrue(path.exists())
    def test_foreign_message_cannot_schedule(self):
        t,result,errors,path=self.wait_thread(time.monotonic()+1)
        with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as sender:sender.sendto(b'{"request":"wrong"}',str(path))
        t.join(timeout=1);self.assertEqual(result,[]);self.assertEqual(len(errors),1);self.assertIsInstance(errors[0],guards.GuardError);self.assertFalse(path.exists())
    def test_wrong_generation_code_source_stale_future_duplicate_and_oversized_messages_reject(self):
        for change in ('generation','code_sha','source_sha256','stale','future','duplicate','oversized'):
            with self.subTest(change=change):
                t,result,errors,path=self.wait_thread(time.monotonic()+1)
                value=retention_cohort._minute_turn_binding(self.w,path.stem);value['sent_monotonic']=time.monotonic()
                if change in ('generation','code_sha','source_sha256'):value[change]='d'*len(value[change])
                elif change=='stale':value['sent_monotonic']-=2
                elif change=='future':value['sent_monotonic']+=2
                raw=backup_catalog.canonical(value)
                if change=='duplicate':raw=raw[:-1]+b',"request":"'+path.stem.encode()+b'"}'
                if change=='oversized':raw+=b' '*4097
                with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as sender:sender.sendto(raw,str(path))
                t.join(timeout=1);self.assertEqual(result,[]);self.assertEqual(len(errors),1);self.assertIsInstance(errors[0],guards.GuardError);self.assertFalse(path.exists())
    def test_replaced_socket_identity_never_grants_and_never_unlinks_foreign_object(self):
        t,result,errors,path=self.wait_thread(time.monotonic()+.08);path.unlink();path.write_bytes(b'foreign');path.chmod(0o600)
        t.join(timeout=1);self.assertEqual(result,[]);self.assertEqual(len(errors),1);self.assertEqual(path.read_bytes(),b'foreign')
    def test_malformed_or_wrong_mode_request_does_not_fail_successful_minute(self):
        receiver,path,nonce=self.channel();path.chmod(0o666);receiver.settimeout(.02)
        with retention_cohort.minute_job(self.w,time.monotonic()+1):pass
        with self.assertRaises(socket.timeout):receiver.recv(4096)
    def test_expired_wait_never_creates_a_request(self):
        with self.assertRaises(guards.GuardError):retention_cohort.wait_for_minute_turn(self.w,time.monotonic())
        self.assertFalse((self.root/'receipts/minute-turns').exists())
    def test_notifier_cannot_extend_original_minute_deadline(self):
        with mock.patch.object(retention_cohort,'signal_minute_turns',side_effect=lambda *_:time.sleep(.04)):
            with self.assertRaisesRegex(guards.GuardError,'Minute job original deadline exceeded'):
                with retention_cohort.minute_job(self.w,time.monotonic()+.03):pass
        with runtime.lane_lock(self.root/'receipts/job-binlog-wait.lock'),runtime.lane_lock(self.root/'receipts/job-binlog.lock'):pass
    def test_notification_occurs_after_body_check_while_both_real_locks_are_held(self):
        self.channel();original=retention_cohort.signal_minute_turns;steps=[]
        def notify(worker,deadline):
            self.assertEqual(steps,['ACK','finalized'])
            for name in ('job-binlog-wait.lock','job-binlog.lock'):
                with self.assertRaises(runtime.LaneBusyError):
                    with runtime.lane_lock(self.root/'receipts'/name):pass
            steps.append('signal');return original(worker,deadline)
        with mock.patch.object(retention_cohort,'signal_minute_turns',side_effect=notify):
            with retention_cohort.minute_job(self.w,time.monotonic()+1):steps.extend(['ACK','finalized'])
        self.assertEqual(steps,['ACK','finalized','signal'])
    def test_existing_foreign_socket_and_symlink_namespace_are_preserved_before_wait(self):
        receiver,path,nonce=self.channel()
        with self.assertRaisesRegex(guards.GuardError,'Prior minute turn'):retention_cohort.wait_for_minute_turn(self.w,time.monotonic()+1)
        self.assertTrue(path.exists());path.unlink();(self.root/'receipts/minute-turns').rmdir()
        elsewhere=self.root/'foreign';elsewhere.mkdir(mode=0o700);(self.root/'receipts/minute-turns').symlink_to(elsewhere,target_is_directory=True)
        with self.assertRaises(guards.GuardError):retention_cohort.wait_for_minute_turn(self.w,time.monotonic()+1)
        self.assertTrue((self.root/'receipts/minute-turns').is_symlink())
    def test_preexisting_temporary_collision_is_never_deleted(self):
        nonce=uuid.uuid4().hex;directory=self.root/'receipts/minute-turns';directory.mkdir(mode=0o700)
        # Simulate a bind collision appearing after the empty-directory check.
        original=retention_cohort._minute_turn_binding;path=directory/('.turn-'+nonce+'.pending')
        def binding(worker,request):path.write_bytes(b'foreign');return original(worker,request)
        with mock.patch.object(retention_cohort.uuid,'uuid4',return_value=types.SimpleNamespace(hex=nonce)),mock.patch.object(retention_cohort,'_minute_turn_binding',side_effect=binding):
            with self.assertRaises(guards.GuardError):retention_cohort.wait_for_minute_turn(self.w,time.monotonic()+1)
        self.assertEqual(path.read_bytes(),b'foreign')
    def test_final_publication_race_never_overwrites_or_deletes_foreign_file(self):
        nonce=uuid.uuid4().hex;directory=self.root/'receipts/minute-turns';path=directory/(nonce+'.sock')
        real_binding=retention_cohort._minute_turn_binding
        def binding(worker,request):path.write_bytes(b'foreign-before-publish');return real_binding(worker,request)
        with mock.patch.object(retention_cohort.uuid,'uuid4',return_value=types.SimpleNamespace(hex=nonce)),mock.patch.object(retention_cohort,'_minute_turn_binding',side_effect=binding):
            with self.assertRaises((guards.GuardError,OSError)):retention_cohort.wait_for_minute_turn(self.w,time.monotonic()+.04)
        self.assertTrue(path.exists(),'Foreign finalpath disappeared during publication/cleanup')
        self.assertEqual(path.read_bytes(),b'foreign-before-publish')
    def test_temporary_replaced_after_link_is_preserved_with_owned_final_socket(self):
        nonce=uuid.uuid4().hex;directory=self.root/'receipts/minute-turns';temporary=directory/('.turn-'+nonce+'.pending');path=directory/(nonce+'.sock')
        original=retention_cohort.os.link
        def link(source,target,**kwargs):
            original(source,target,**kwargs);temporary.unlink();temporary.write_bytes(b'foreign-after-link')
        with mock.patch.object(retention_cohort.uuid,'uuid4',return_value=types.SimpleNamespace(hex=nonce)),mock.patch.object(retention_cohort.os,'link',side_effect=link):
            with self.assertRaises((guards.GuardError,OSError)):retention_cohort.wait_for_minute_turn(self.w,time.monotonic()+.04)
        self.assertTrue(temporary.exists(),'Foreign temporary was deleted after socket publication')
        self.assertEqual(temporary.read_bytes(),b'foreign-after-link');self.assertTrue(path.exists())

if __name__=='__main__':unittest.main()
