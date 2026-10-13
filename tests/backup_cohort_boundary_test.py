"""Cohort native/list/journal boundary races; authenticated synthetic fixtures."""
import copy,json,pathlib,sys,unittest,zlib,dataclasses,types,datetime as dt,contextlib,threading,shutil,hashlib
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'infra/backup'))
import guards,retention,retention_cohort,runtime,backup_catalog
import backup_cohort_test


class CohortBoundaryTests(unittest.TestCase):
    def flight(self,case,*,listed=True,busy=True,real_lock=None,failed=False,corrupt_old=False):
        real_lock=real_lock or runtime.lane_lock
        path=case.root/'receipts/binlog/state.json';old=runtime.load_json(path);saved=[];admit=backup_catalog.ArchiveCatalog.admit
        def defer(c,*args,**kwargs):saved.append(args)
        with mock.patch.object(backup_catalog.ArchiveCatalog,'admit',defer):sid=case.append_minute()
        runtime.atomic_json(path,old);payload=case.root/'spool/binlog-payload';shutil.copytree(saved[0][4],payload)
        marker={'generation':case.w.c['generation'],'lane':'binlog','token':'8'*32}
        runtime.atomic_json(payload/'.capture.json',marker);runtime.atomic_json(case.root/'receipts/capture-binlog.json',{**marker,'phase':'upload'})
        manifest=runtime.load_json(payload/'manifest.json');body=(payload/'.capture.json').read_bytes()
        manifest['files'].append({'path':'.capture.json','bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()});manifest['files'].sort(key=lambda row:row['path'])
        runtime.atomic_json(payload/'manifest.json',manifest);raw=(payload/'manifest.json').read_bytes();md=hashlib.sha256(raw).hexdigest();meta=case.native[sid][1]
        meta['tags']=[tag for tag in meta['tags'] if not tag.startswith('manifest-sha:')]+['manifest-sha:'+md]
        meta.update(hostname='actual-native-host',username='root',program_version='restic 0.19.1',short_id=sid[:8],summary={'total_files_processed':3})
        at=backup_cohort_test.NOW.isoformat();pending={'token':'9'*32,'generation':case.w.c['generation'],'payload':str(payload),'manifest_sha256':md,'attempted':True,'prepared_at':at,'captured_at':at,'parent_id':old['confirmed'][-1]['id']}
        runtime.atomic_json(case.root/'receipts/binlog/pending.json',pending)
        if not listed:del case.native[sid]
        started=threading.Event();finish=threading.Event();errors=[]
        def producer():
            try:
                with real_lock(case.root/'receipts/job-binlog.lock'),real_lock(case.root/'receipts/binlog/lane.lock'):
                    started.set();finish.wait(10)
                    if failed:return
                    fake=types.SimpleNamespace(datetime=types.SimpleNamespace(now=lambda tz:backup_cohort_test.NOW),timezone=types.SimpleNamespace(utc=backup_cohort_test.NOW.tzinfo))
                    with mock.patch.object(backup_catalog,'dt',fake):admit(case.catalog(),'binlog',sid,meta,raw,payload)
                    if corrupt_old:
                        with case.catalog()._db(write=True) as db:db.execute('UPDATE archives SET body=? WHERE sid=?',(b'changed-old-body','3'*64));db.commit()
                    state=runtime.load_json(path);state['confirmed'].append({'id':sid,'token':pending['token'],'manifest_sha256':md,'captured_at':at,'prepared_at':at,'confirmed_at':at})
                    state.update(last_success_at=at,last_confirmation_at=at);runtime.atomic_json(path,state)
                    (case.root/'receipts/binlog/pending.json').unlink();runtime.atomic_json(case.root/'receipts/binlog/finalized.json',{'manifest_sha256':md,'snapshot_id':sid,'domains':{}})
                    case.native[sid]=('binlog',meta)
            except BaseException as error:errors.append(error);started.set()
        thread=threading.Thread(target=producer)
        if busy:thread.start();self.assertTrue(started.wait(5))
        original=real_lock;waits=[]
        @contextlib.contextmanager
        def lock(p):
            try:
                with original(p):yield
            except runtime.LaneBusyError:
                if pathlib.Path(p)==case.root/'receipts/job-binlog.lock':waits.append(True);finish.set()
                raise
        def cleanup():
            finish.set()
            if busy:thread.join(5);self.assertFalse(thread.is_alive());self.assertEqual(errors,[])
        self.addCleanup(cleanup)
        return sid,lock,waits

    def test_producer_wait_rejects_abandoned_foreign_failed_or_second_flight(self):
        for mutation in ('free-job','token','capture','payload','failed','second','old-body','timeout'):
            with self.subTest(mutation=mutation):
                case=self.case();_,_,_,current=self.loaded(case)
                sid,lock,waits=self.flight(case,busy=mutation!='free-job',failed=mutation in ('failed','payload'),corrupt_old=mutation=='old-body')
                if mutation=='free-job':
                    with runtime.lane_lock(case.root/'receipts/job-binlog.lock'):pass
                if mutation=='token':
                    path=case.root/'receipts/binlog/pending.json';value=runtime.load_json(path);value['token']='a'*32;runtime.atomic_json(path,value)
                if mutation=='capture':runtime.atomic_json(case.root/'receipts/capture-binlog.json',{'unknown':True})
                if mutation=='payload':(case.root/'spool/binlog-payload/logs/suhoput2-binlog.000003').write_bytes(b'changed')
                if mutation=='second':retention_cohort._FLIGHT_USED.add(current['snapshots']._observation.flight)
                with case.catalog().open_reader() as reader,mock.patch.object(runtime,'lane_lock',lock),contextlib.ExitStack() as stack:
                    if mutation=='timeout':stack.enter_context(mock.patch.object(retention_cohort,'upload_section',side_effect=guards.GuardError('original deadline exhausted')))
                    with self.assertRaises(guards.GuardError):retention_cohort.confirm_observation(case.w,current,reader)
                if mutation in ('free-job','capture','second'):self.assertFalse(waits)

    def test_native_published_before_admission_waits_only_for_authenticated_live_producer(self):
        case=self.case();store=retention_cohort.CohortStore(case.w);store.capture();native=case.w.restic;flight=[];calls=[]
        def read(lane,args,**kwargs):
            calls.append((lane,args[2:]))
            if lane=='binlog' and args[2:]==['snapshots','--json'] and not flight:flight.append(self.flight(case,real_lock=real_lock))
            return native(lane,args,**kwargs)
        case.w.restic=read
        @contextlib.contextmanager
        def lock(path):
            if flight:
                with flight[0][1](path):yield
            else:
                with real_lock(path):yield
        real_lock=runtime.lane_lock
        with case.catalog().open_reader() as reader,mock.patch.object(runtime,'lane_lock',lock):
            current={};store.load(reader,current_out=current)
        self.assertIn(flight[0][0],current['manifests']);self.assertTrue(flight[0][2]);self.assertEqual(len(calls),4)

    def test_pending_not_listed_waits_and_authenticates_late_ack_without_adding_native_row(self):
        case=self.case();_,_,_,current=self.loaded(case);before=copy.deepcopy(dict(current));sid,lock,waits=self.flight(case,listed=False)
        with case.catalog().open_reader() as reader,mock.patch.object(runtime,'lane_lock',lock):retention_cohort.confirm_observation(case.w,current,reader)
        self.assertTrue(waits);self.assertNotIn(sid,current['manifests']);self.assertEqual(dict(current),before)

    def test_raw_prefix_cannot_reseal_an_uncommitted_checkpoint(self):
        case=self.case()
        with case.catalog().open_reader() as reader:
            with case.catalog()._db(write=True) as db:
                db.execute('CREATE TABLE IF NOT EXISTS catalog_checkpoint (slot INTEGER PRIMARY KEY CHECK(slot=1), record BLOB NOT NULL)')
                db.execute('INSERT INTO catalog_checkpoint VALUES(1,?)',(b'{}',));db.commit()
            with self.assertRaisesRegex(guards.GuardError,'checkpoint.*original head'):
                retention.reader_raw_prefix_seal(reader,verify=True)

    def case(self):
        case=backup_cohort_test.NativeCohortTests();case.setUp();self.addCleanup(case.doCleanups)
        original=case.append_minute;at=backup_cohort_test.NOW
        def append():
            fake=types.SimpleNamespace(datetime=types.SimpleNamespace(now=lambda tz:at),timezone=types.SimpleNamespace(utc=at.tzinfo))
            with mock.patch.object(backup_catalog,'dt',fake):sid=original()
            path=case.root/'receipts/binlog/state.json';state=runtime.load_json(path)
            state['confirmed'][-1].update(captured_at=at.isoformat(),prepared_at=at.isoformat(),confirmed_at=at.isoformat())
            state.update(last_success_at=at.isoformat(),last_confirmation_at=at.isoformat());runtime.atomic_json(path,state);return sid
        case.append_minute=append;return case

    def test_ack_after_outside_native_view_is_closed_by_final_locked_boundary(self):
        case=self.case();native=retention.native_inventory;arrivals=[];calls=[]
        def observed(*args,**kwargs):
            value=native(*args,**kwargs);calls.append(kwargs.get('deadline'))
            if not arrivals:arrivals.append(case.append_minute())
            return value
        store=retention_cohort.CohortStore(case.w)
        with mock.patch.object(retention,'native_inventory',observed):cohort,_=store.capture()
        self.assertNotIn(arrivals[0],{row['id'] for row in cohort['snapshots']})
        self.assertIn(arrivals[0],case.native);self.assertEqual(len(calls),2);self.assertIsNone(calls[0]);self.assertIsNotNone(calls[1])
        document=store._document();self.assertEqual(document['inventory_sha256'],retention.inventory_digest(cohort))
        self.assertNotIn(arrivals[0],document['catalog_seals'])

    def test_ack_tail_cannot_heal_rewritten_historical_confirmation(self):
        case=self.case();native=retention.native_inventory;changed=[];store=retention_cohort.CohortStore(case.w)
        def observed(*args,**kwargs):
            value=native(*args,**kwargs)
            if not changed:
                case.append_minute();path=case.root/'receipts/binlog/state.json';state=runtime.load_json(path)
                state['confirmed'][0]['confirmed_at']='2026-10-12T00:00:00+00:00';runtime.atomic_json(path,state);changed.append(True)
            return value
        with mock.patch.object(retention,'native_inventory',observed),self.assertRaisesRegex(guards.GuardError,'Original confirmation or retirement prefix'):
            store.capture()
        self.assertFalse(store.pointer.exists());self.assertEqual(list(store.root.iterdir()),[])

    def test_tail_cannot_hide_lost_frozen_member_or_unprojected_native_field_drift(self):
        for mutation in ('lost','hostname'):
            with self.subTest(mutation=mutation):
                case=self.case();native=retention.native_inventory;changed=[];store=retention_cohort.CohortStore(case.w)
                def observed(*args,**kwargs):
                    value=native(*args,**kwargs)
                    if not changed:
                        case.append_minute();sid=next(sid for sid,(lane,_) in case.native.items() if lane=='base')
                        if mutation=='lost':del case.native[sid]
                        else:case.native[sid][1]['hostname']='rewritten-after-observation'
                        changed.append(True)
                    return value
                with mock.patch.object(retention,'native_inventory',observed),self.assertRaises(guards.GuardError):store.capture()
                self.assertFalse(store.pointer.exists());self.assertEqual(list(store.root.iterdir()),[])

    def test_unadmitted_native_tail_blocks_final_boundary(self):
        case=self.case();native=retention.native_inventory;changed=[];store=retention_cohort.CohortStore(case.w)
        def observed(*args,**kwargs):
            value=native(*args,**kwargs)
            if not changed:
                _,metadata=next(iter(case.native.values()));foreign=copy.deepcopy(metadata);foreign['id']='f'*64;foreign['tree']='e'*64
                case.native['f'*64]=('binlog',foreign);changed.append(True)
            return value
        with mock.patch.object(retention,'native_inventory',observed),self.assertRaises(guards.GuardError):store.capture()
        self.assertFalse(store.pointer.exists());self.assertEqual(list(store.root.iterdir()),[])

    def test_load_has_same_unlocked_late_ack_race(self):
        case=self.case();store=retention_cohort.CohortStore(case.w);frozen,_=store.capture()
        native=retention.native_inventory;arrivals=[]
        def observed(*args,**kwargs):
            value=native(*args,**kwargs)
            if not arrivals:arrivals.append(case.append_minute())
            return value
        with case.catalog().open_reader() as reader,mock.patch.object(retention,'native_inventory',observed):
            current={};loaded=store.load(reader,current_out=current)
        self.assertEqual(loaded['cohort'],frozen['cohort']);self.assertNotIn(arrivals[0],loaded['manifests'])

    def test_capture_late_ack_cannot_reseal_changed_old_catalog_body(self):
        case=self.case();native=retention.native_inventory;changed=[];store=retention_cohort.CohortStore(case.w)
        def observed(*args,**kwargs):
            value=native(*args,**kwargs)
            if not changed:
                case.append_minute()
                with case.catalog()._db(write=True) as db:db.execute('UPDATE archives SET body=? WHERE sid=?',(zlib.compress(b'{}'),'3'*64));db.commit()
                changed.append(True)
            return value
        with mock.patch.object(retention,'native_inventory',observed),self.assertRaisesRegex(guards.GuardError,'old row or raw manifest'):
            store.capture()
        self.assertFalse(store.pointer.exists())

    def test_capture_rechecks_old_body_mutation_inside_closing_native_read(self):
        case=self.case();native=case.w.restic;calls=[];store=retention_cohort.CohortStore(case.w)
        def read(lane,args,**kwargs):
            value=native(lane,args,**kwargs)
            if lane=='base' and args[2:]==['cat','config']:
                calls.append(True)
                if len(calls)==2:
                    with case.catalog()._db(write=True) as db:db.execute('UPDATE archives SET body=? WHERE sid=?',(zlib.compress(b'{}'),'3'*64));db.commit()
            return value
        case.w.restic=read
        with self.assertRaisesRegex(guards.GuardError,'Original captured catalog raw/body'):store.capture()
        self.assertFalse(store.pointer.exists())

    def loaded(self,case):
        store=retention_cohort.CohortStore(case.w);frozen,_=store.capture();current={}
        with case.catalog().open_reader() as reader:loaded=store.load(reader,current_out=current)
        return store,frozen,loaded,current

    def test_observation_projection_never_changes_native_current_and_integrity_reuses_it(self):
        import integrity
        case=self.case();_,_,_,current=self.loaded(case);before=copy.deepcopy(dict(current));sid=case.append_minute()
        repositories,rows,_=integrity._current(case.w,current)
        self.assertEqual(repositories,current['repositories']);self.assertNotIn(sid,rows['binlog'])
        self.assertEqual(dict(current),before);self.assertNotIn(sid,current['manifests'])

    def test_missing_old_or_copied_provenance_and_plain_json_never_hide_ack(self):
        import integrity
        for mutation in ('old-missing','copy','json','fields','manifest','clock','forged'):
            with self.subTest(mutation=mutation):
                case=self.case();_,_,_,current=self.loaded(case);case.append_minute()
                if mutation=='old-missing':current['snapshots'].pop(0)
                elif mutation=='copy':current['snapshots']=copy.copy(current['snapshots'])
                elif mutation=='forged':
                    rows=retention_cohort._ObservedSnapshots(current['snapshots']);rows._observation=dataclasses.replace(current['snapshots']._observation,owner=id(rows))
                    current['snapshots']=rows
                elif mutation=='json':current=json.loads(json.dumps(current))
                elif mutation=='fields':current['snapshots'][0]['tree']='f'*64
                elif mutation=='manifest':current['manifests'][current['snapshots'][0]['id']]['captured_at']='2020-01-01T00:00:00+00:00'
                else:current['observed_at']='2020-01-01T00:00:00+00:00'
                with self.assertRaises(guards.GuardError):integrity._current(case.w,current)

    def test_excluded_late_ack_must_have_exact_raw_crc_and_original_journal_history(self):
        import integrity
        for mutation in ('raw','crc','journal','unknown-ack','pending'):
            with self.subTest(mutation=mutation):
                case=self.case();_,_,_,current=self.loaded(case);sid=case.append_minute();path=case.root/'receipts/binlog/state.json'
                if mutation in ('raw','crc'):
                    with case.catalog()._db(write=True) as db:
                        table='archives' if mutation=='raw' else 'logs';db.execute('UPDATE '+table+' SET body=? WHERE sid=?',(zlib.compress(b'corrupt body'),sid));db.commit()
                elif mutation=='pending':runtime.atomic_json(case.root/'receipts/binlog/pending.json',{'unknown':True})
                else:
                    state=runtime.load_json(path)
                    if mutation=='journal':state['confirmed'][0]['confirmed_at']='2020-01-01T00:00:00+00:00'
                    else:state['confirmed'][-1]['id']='f'*64
                    runtime.atomic_json(path,state)
                with self.assertRaises(guards.GuardError):integrity._current(case.w,current)

    def test_new_excluded_ack_requires_all_production_clock_fields(self):
        import integrity
        case=self.case();_,_,_,current=self.loaded(case);case.append_minute();path=case.root/'receipts/binlog/state.json'
        state=runtime.load_json(path);state['confirmed'][-1]={key:state['confirmed'][-1][key] for key in ('id','token','manifest_sha256')}
        runtime.atomic_json(path,state)
        with self.assertRaisesRegex(guards.GuardError,'Late ACK fields'):integrity._current(case.w,current)

    def test_retained_observation_has_original_900_second_age_and_rollback_guard(self):
        import integrity
        case=self.case();_,_,_,current=self.loaded(case);case.append_minute();observed=guards.utc(current['observed_at'])
        with mock.patch.object(retention_cohort,'clock',return_value=observed+dt.timedelta(seconds=900)):
            integrity._current(case.w,current)
        for delta in (901,-1):
            with self.subTest(delta=delta),mock.patch.object(retention_cohort,'clock',return_value=observed+dt.timedelta(seconds=delta)), \
                 self.assertRaisesRegex(guards.GuardError,'expired or clock rolled back'):integrity._current(case.w,current)


if __name__=='__main__':unittest.main()
