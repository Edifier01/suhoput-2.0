"""One trusted loader observation is consumed only as the entry baseline."""
import copy,datetime as dt,json,pathlib,sqlite3,sys,unittest
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'infra/backup'))
import backup_catalog,guards,readiness_v2,retention,retention_apply,retention_cohort,runtime
from backup_retention_apply_test import NOW
import backup_retention_native_test

class NativeEntryReuseTests(unittest.TestCase):
    def case(self):return backup_retention_native_test.NativeBoundaryTests.v2_case(self)
    def consume(self,worker,current,reader):
        self.assertTrue(callable(getattr(retention_cohort,'_consume_entry_observation',None)),'One-use entry consumption absent')
        return retention_cohort._consume_entry_observation(worker,current,reader)
    def test_exactly_one_entry_quartet_is_reused_and_phase_audits_remain(self):
        case,_,executor,_,effects,evidence=self.case();calls=[];phase_starts=[];native=case.w.restic
        phase=retention_apply.Executor._phase_data
        def restic(lane,args,**kwargs):
            calls.append((lane,args[2:]));return native(lane,args,**kwargs)
        def prepare(*args,**kwargs):
            phase_starts.append(len(calls));return phase(*args,**kwargs)
        case.w.restic=restic
        with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True), \
             mock.patch.object(retention_apply.Executor,'_phase_data',prepare),mock.patch.object(backup_catalog.ArchiveCatalog,'checkpoint',return_value={}):
            result=executor.run('apply')
        self.assertEqual(result['result'],'APPLIED');self.assertEqual(len(effects),2)
        self.assertEqual(phase_starts[0],4,'Loader is the only native entry observation before phase preparation')
        quartet=[('base',['cat','config']),('base',['snapshots','--json']),('binlog',['cat','config']),('binlog',['snapshots','--json'])]
        self.assertEqual(phase_starts,[4,12],'Each actual effect phase retains its own outside and locked observation')
        self.assertEqual(calls,quartet*8,'Loader1 + effect phases2 + final observation1 + publication audit1 + locked closures3')

    def test_real_loader_handle_consumed_once_without_native_or_retime(self):
        case,_,_,_,_,_=self.case();current={}
        with case.catalog().open_reader() as reader:
            retention_cohort.CohortStore(case.w).load(reader,current_out=current)
            before=retention_cohort._observation_digest(current);at=current['observed_at'];rows=current['snapshots']
            with mock.patch.object(case.w,'restic',side_effect=AssertionError('Consumption cannot read native')):
                self.assertIs(self.consume(case.w,current,reader.refresh()),current)
                self.assertEqual(current['observed_at'],at);self.assertIs(current['snapshots'],rows)
                self.assertEqual(retention_cohort._observation_digest(current),before)
                with self.assertRaisesRegex(guards.GuardError,'consumed'):self.consume(case.w,current,reader)

    def test_copied_json_and_forged_handles_never_grant_entry_reuse(self):
        for mode in ('plain','json','copied','forged','registry'):
            with self.subTest(mode=mode):
                case,_,_,_,_,_=self.case();current={}
                with case.catalog().open_reader() as reader:
                    retention_cohort.CohortStore(case.w).load(reader,current_out=current)
                    if mode=='plain':current['snapshots']=list(current['snapshots'])
                    elif mode=='json':current=json.loads(json.dumps(current))
                    elif mode=='copied':current=copy.deepcopy(current)
                    elif mode=='forged':
                        rows=retention_cohort._ObservedSnapshots(current['snapshots']);rows._observation=current['snapshots']._observation;current['snapshots']=rows
                    else:del retention_cohort._OBSERVATIONS[current['snapshots']]
                    with self.assertRaises(guards.GuardError):self.consume(case.w,current,reader)

    def test_source_reader_clock_and_inventory_drift_fail_without_healing(self):
        for mode in ('source','code','generation','repositories','foreign_reader','closed_reader','expired','rollback','row','manifest','journal','raw','reader_record','reader_key','schema','log'):
            with self.subTest(mode=mode):
                case,_,_,_,_,_=self.case();current={}
                with case.catalog().open_reader() as reader:
                    retention_cohort.CohortStore(case.w).load(reader,current_out=current)
                    use=reader;at=NOW
                    if mode=='source':case.w.source={**case.w.source,'host':'foreign'}
                    elif mode=='code':case.w.c['code_sha']='e'*40
                    elif mode=='generation':case.w.c['generation']='e'*32
                    elif mode=='repositories':case.w.c['repositories']={**case.w.c['repositories'],'base':'foreign'}
                    elif mode=='foreign_reader':
                        use=copy.copy(reader);use.catalog=copy.copy(reader.catalog);use.catalog.worker=copy.copy(case.w)
                    elif mode=='closed_reader':reader.active=False
                    elif mode=='expired':at=NOW+dt.timedelta(seconds=901)
                    elif mode=='rollback':at=NOW-dt.timedelta(seconds=1)
                    elif mode=='row':current['snapshots'][0]['tree']='e'*64
                    elif mode=='manifest':current['manifests'][next(iter(current['manifests']))]['captured_at']=at.isoformat()+'changed'
                    elif mode=='journal':
                        path=case.root/'receipts/base/state.json';state=runtime.load_json(path);state['confirmed'][0]['confirmed_at']='2099-01-01T00:00:00+00:00';runtime.atomic_json(path,state)
                    elif mode=='reader_record':reader._records[next(iter(reader._records))]['projection']['captured_at']='2099-01-01T00:00:00+00:00'
                    elif mode=='reader_key':reader._records['e'*64]=reader._records.pop(next(iter(reader._records)))
                    elif mode=='schema':
                        with sqlite3.connect(case.catalog().database) as db:db.execute('CREATE TABLE foreign_authority(x TEXT)')
                    elif mode=='log':
                        with sqlite3.connect(case.catalog().database) as db:
                            row=db.execute('SELECT rowid,body FROM logs LIMIT 1').fetchone();db.execute('UPDATE logs SET body=? WHERE rowid=?',(row[1]+b'changed',row[0]))
                    else:
                        with sqlite3.connect(case.catalog().database) as db:
                            row=db.execute('SELECT body FROM archives WHERE sequence=1').fetchone();db.execute('UPDATE archives SET body=? WHERE sequence=1',(row[0]+b'changed',))
                    with mock.patch.object(retention_cohort,'clock',return_value=at),mock.patch.object(case.w,'restic',side_effect=AssertionError('No fallback native read')):
                        with self.assertRaises(guards.GuardError):self.consume(case.w,current,use)

    def test_new_confirmed_tail_is_authenticated_without_adding_unlisted_row(self):
        case,_,_,_,_,_=self.case();current={}
        with case.catalog().open_reader() as reader:
            retention_cohort.CohortStore(case.w).load(reader,current_out=current)
            before=retention_cohort._observation_digest(current);sid=case.append_minute()
            with mock.patch.object(case.w,'restic',side_effect=AssertionError('No native call for tail confirmation')):
                self.consume(case.w,current,reader.refresh())
            self.assertNotIn(sid,current['manifests']);self.assertNotIn(sid,[row['id'] for row in current['snapshots']])
            self.assertEqual(retention_cohort._observation_digest(current),before)

    def test_confirmation_failure_is_original_and_burns_entry_handle(self):
        case,_,_,_,_,_=self.case();current={};error=RuntimeError('Entry local closure failed')
        with case.catalog().open_reader() as reader:
            retention_cohort.CohortStore(case.w).load(reader,current_out=current)
            with mock.patch.object(retention_cohort,'confirm_observation',side_effect=error):
                with self.assertRaises(RuntimeError) as caught:self.consume(case.w,current,reader)
            self.assertIs(caught.exception,error)
            with self.assertRaisesRegex(guards.GuardError,'consumed'):self.consume(case.w,current,reader)

    def test_changed_loader_output_blocks_before_effect_with_no_native_fallback(self):
        for mode in ('copied','row','journal','reader_record'):
            with self.subTest(mode=mode):
                case,_,executor,store,effects,evidence=self.case();load=retention_cohort.CohortStore.load;calls=[];native=case.w.restic
                def observed(lane,args,**kwargs):calls.append((lane,args[2:]));return native(lane,args,**kwargs)
                def changed(owner,reader,**kwargs):
                    value=load(owner,reader,**kwargs);current=kwargs['current_out']
                    if mode=='copied':current['snapshots']=list(current['snapshots'])
                    elif mode=='row':current['snapshots'][0]['tree']='e'*64
                    elif mode=='reader_record':reader._records[next(iter(reader._records))]['projection']['captured_at']='2099-01-01T00:00:00+00:00'
                    else:
                        path=case.root/'receipts/base/state.json';state=runtime.load_json(path);state['confirmed'][0]['confirmed_at']='2099-01-01T00:00:00+00:00';runtime.atomic_json(path,state)
                    return value
                case.w.restic=observed
                with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True), \
                     mock.patch.object(retention_cohort.CohortStore,'load',changed),self.assertRaises(guards.GuardError):executor.run('apply')
                self.assertEqual(len(calls),4);self.assertEqual(effects,[]);self.assertFalse(store.path.exists())

    def test_unadmitted_native_after_entry_reuse_still_blocks_in_normal_phase_audit(self):
        case,_,executor,store,effects,evidence=self.case();load=retention_cohort.CohortStore.load;calls=[];native=case.w.restic
        def observed(lane,args,**kwargs):calls.append((lane,args[2:]));return native(lane,args,**kwargs)
        def unknown(owner,reader,**kwargs):
            value=load(owner,reader,**kwargs);lane,metadata=next(iter(case.native.values()));metadata=copy.deepcopy(metadata);metadata['id']='e'*64
            case.native['e'*64]=(lane,metadata);return value
        case.w.restic=observed
        with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True), \
             mock.patch.object(retention_cohort.CohortStore,'load',unknown),self.assertRaises(guards.GuardError):executor.run('apply')
        self.assertEqual(len(calls),6,'Normal phase stops on unknown base ID before binlog commands, without retry')
        self.assertEqual(effects,[]);self.assertFalse(store.path.exists())

if __name__=='__main__':unittest.main()
