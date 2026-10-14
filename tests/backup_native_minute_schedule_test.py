"""Exact scheduled-minute applicability; no command or external effect."""
import contextlib,datetime as dt,pathlib,sys,time,unittest
from types import SimpleNamespace
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'infra/backup'))
import backup_catalog,guards,readiness_v2,retention_cohort,retention_native

UNIT='suhoput2-stage-backup-binlog.timer'
def response(active='active',enabled='enabled',unit=UNIT):
 return ('Id='+unit+'\nActiveState='+active+'\nUnitFileState='+enabled+'\n').encode()
def probe(worker,deadline):
 return retention_native.scheduled_minute_producer(worker,deadline)

class ScheduledMinuteTests(unittest.TestCase):
 def worker(self,raw):return SimpleNamespace(native=SimpleNamespace(run=mock.Mock(return_value=raw)))
 def test_active_enabled_requires_handoff(self):
  self.assertTrue(probe(self.worker(response()),time.monotonic()+10))
 def test_inactive_disabled_is_no_scheduled_producer(self):
  w=self.worker(response('inactive','disabled'));self.assertFalse(probe(w,time.monotonic()+10))
  self.assertEqual(w.native.run.call_count,1)
 def test_observation_is_exact_local_command_with_original_remaining_timeout(self):
  w=self.worker(response());deadline=time.monotonic()+.25;probe(w,deadline)
  w.native.run.assert_called_once()
  args,kw=w.native.run.call_args
  self.assertEqual(args,(['systemctl','show',UNIT,'--property=Id,ActiveState,UnitFileState'],))
  self.assertGreater(kw['timeout'],0);self.assertLessEqual(kw['timeout'],.25)
 def test_transient_mixed_or_unknown_state_rejects(self):
  for a,e in [('activating','enabled'),('active','disabled'),('inactive','enabled'),('failed','enabled'),('unknown','disabled')]:
   with self.subTest(a=a,e=e),self.assertRaises(guards.GuardError):probe(self.worker(response(a,e)),time.monotonic()+10)
 def test_unknown_unit_duplicate_extra_missing_or_nonbytes_rejects(self):
  cases=[response(unit='unrelated.timer'),response()+b'ActiveState=inactive\n',response()+b'Unexpected=x\n',b'ActiveState=active\n',response().decode(),b'\xff']
  for raw in cases:
   with self.subTest(raw=repr(raw)),self.assertRaises(guards.GuardError):probe(self.worker(raw),time.monotonic()+10)
 def test_expired_original_deadline_makes_no_probe(self):
  w=self.worker(response())
  with self.assertRaises(guards.GuardError):probe(w,time.monotonic()-1)
  w.native.run.assert_not_called()
 def test_failed_local_probe_propagates_without_disabled_fallback(self):
  w=self.worker(response());error=RuntimeError('local probe failed');w.native.run.side_effect=error
  with self.assertRaises(RuntimeError) as found:probe(w,time.monotonic()+10)
  self.assertIs(found.exception,error)
 def test_probe_cannot_return_after_the_original_deadline(self):
  w=self.worker(response());deadline=time.monotonic()+.01
  def slow(*args,**kw):time.sleep(.02);return response()
  w.native.run.side_effect=slow
  with self.assertRaises(guards.GuardError):probe(w,deadline)

class NativeMinuteTurnIntegrationTests(unittest.TestCase):
 def case(self):
  from backup_retention_native_test import NativeBoundaryTests
  return NativeBoundaryTests.v2_case(self)
 def test_every_effect_and_publication_waits_outside_groups_and_closes_actual_arrival(self):
  case,_,executor,_,effects,evidence=self.case();original=retention_cohort.upload_section;active=[False];events=[];arrivals=[]
  @contextlib.contextmanager
  def group(worker,**kw):
   events.append('group')
   with original(worker,**kw) as acquired:
    active[0]=True
    try:yield acquired
    finally:active[0]=False
  def waited(worker,deadline):
   self.assertFalse(active[0]);self.assertGreater(deadline,time.monotonic());self.assertLessEqual(deadline-time.monotonic(),900)
   from backup_retention_prepared_test import PreparedNativePhaseTests
   events.append('wait');PreparedNativePhaseTests.append_next_minute(self,case,arrivals);return {'request':'scheduling only'}
  with mock.patch.object(retention_native,'scheduled_minute_producer',return_value=True) as scheduled, \
       mock.patch.object(retention_cohort,'wait_for_minute_turn',create=True,side_effect=waited) as wait, \
       mock.patch.object(retention_cohort,'upload_section',group), \
       mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True), \
       mock.patch.object(backup_catalog.ArchiveCatalog,'checkpoint',return_value={}):
   result=executor.run('apply')
  self.assertEqual(result['result'],'APPLIED');self.assertEqual(len(effects),2)
  self.assertEqual(wait.call_count,3);self.assertEqual(scheduled.call_count,3)
  self.assertEqual(events,['wait','group']*3);self.assertEqual(result['protected_arrival_ids'],sorted(arrivals))
 def test_disabled_timer_has_no_handoff_wait(self):
  case,_,executor,_,effects,evidence=self.case()
  with mock.patch.object(retention_native,'scheduled_minute_producer',return_value=False) as scheduled, \
       mock.patch.object(retention_cohort,'wait_for_minute_turn',create=True,side_effect=AssertionError('Disabled timer must not wait')) as wait, \
       mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True), \
       mock.patch.object(backup_catalog.ArchiveCatalog,'checkpoint',return_value={}):result=executor.run('apply')
  self.assertEqual(result['result'],'APPLIED');self.assertEqual(len(effects),2);self.assertEqual(scheduled.call_count,3);wait.assert_not_called()
 def test_failed_handoff_has_no_group_or_effect_and_preserves_original_error(self):
  case,_,executor,_,effects,evidence=self.case();error=guards.GuardError('Original turn/proof deadline expired')
  with mock.patch.object(retention_native,'scheduled_minute_producer',return_value=True), \
       mock.patch.object(retention_cohort,'wait_for_minute_turn',create=True,side_effect=error), \
       mock.patch.object(retention_cohort,'upload_section',side_effect=AssertionError('No group after failed handoff')), \
       mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True), \
       self.assertRaises(guards.GuardError) as caught:executor.run('apply')
  self.assertIs(caught.exception,error);self.assertEqual(effects,[])
 def test_readonly_reconciliation_uses_its_actual_observation_after_old_proof_expires(self):
  from backup_retention_apply_test import NOW
  case,_,executor,_,effects,evidence=self.case();forget=case.w.retention_forget
  def lost(lane,ids,**kw):
   result=forget(lane,ids,**kw)
   if lane=='binlog':raise TimeoutError('Response lost')
   return result
  case.w.retention_forget=lost
  with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True):
   self.assertEqual(executor.run('apply')['result'],'RECONCILE_REQUIRED')
  self.assertEqual(len(effects),2)
  def waited(worker,deadline):self.assertGreater(deadline-time.monotonic(),899);return {'request':'scheduling only'}
  with mock.patch.object(retention_cohort,'clock',return_value=NOW+dt.timedelta(seconds=901)), \
       mock.patch.object(retention_native,'scheduled_minute_producer',return_value=True) as scheduled, \
       mock.patch.object(retention_cohort,'wait_for_minute_turn',side_effect=waited) as wait, \
       mock.patch.object(readiness_v2,'load_evidence',side_effect=AssertionError('No renewed effect proof')), \
       mock.patch.object(readiness_v2,'revalidate_budget',side_effect=AssertionError('No renewed budget')):
   result=executor.run('reconcile')
  self.assertEqual(result['result'],'RECONCILED');self.assertEqual(result['remote_delete_calls'],0);self.assertEqual(len(effects),2)
  self.assertGreater(wait.call_count,0);self.assertEqual(scheduled.call_count,wait.call_count)

if __name__=='__main__':unittest.main()
