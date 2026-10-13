"""Authenticated late ACK closure; synthetic local repositories, no transport."""
import contextlib,copy,json,time,unittest
from unittest import mock
import backup_retention_prepared_test as prepared
import backup_catalog,guards,retention,retention_cohort,retention_native,readiness_v2,runtime
from backup_retention_apply_test import NOW

class NativeTailClosureTests(unittest.TestCase):
    def case(self):return prepared.PreparedNativePhaseTests.case(self)
    def append(self,case,arrivals):
        prepared.PreparedNativePhaseTests.append_next_minute(self,case,arrivals)
    def test_reserved_group_hashes_the_borrowed_observation_only_after_the_final_list(self):
        case,_,executor,_,effects,evidence=self.case();original=retention_cohort.upload_section;active=[False];events=[]
        digest=retention_cohort._observation_digest;native=case.w.restic
        @contextlib.contextmanager
        def section(worker,**kwargs):
            with original(worker,**kwargs) as acquired:
                active[0]=True;events.append('group')
                try:yield acquired
                finally:active[0]=False
        def hashed(value):
            if active[0]:events.append('full-observation-hash')
            return digest(value)
        def read(lane,args,**kwargs):
            value=native(lane,args,**kwargs)
            if active[0] and lane=='binlog' and args[2:]==['snapshots','--json']:events.append('final-native-list')
            return value
        case.w.restic=read
        with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True),mock.patch.object(backup_catalog.ArchiveCatalog,'checkpoint',return_value={}),mock.patch.object(retention_cohort,'upload_section',section),mock.patch.object(retention_cohort,'_observation_digest',hashed):
            self.assertEqual(executor.run('apply')['result'],'APPLIED')
        self.assertEqual(len(effects),2)
        self.assertEqual(events,['group','final-native-list','full-observation-hash']*3)
    def test_final_native_old_and_full_seals_canonicalize_each_actual_row_once(self):
        case,_,executor,_,effects,evidence=self.case();original=retention_cohort.upload_section;group=[None];calls={};canonical=retention.canonical
        @contextlib.contextmanager
        def section(worker,**kwargs):
            with original(worker,**kwargs) as acquired:
                group[0]=len(calls);calls[group[0]]={}
                try:yield acquired
                finally:group[0]=None
        def encoded(value):
            if group[0] is not None and isinstance(value,dict) and {'id','paths','tags'}<=set(value):
                rows=calls[group[0]];rows[value['id']]=rows.get(value['id'],0)+1
            return canonical(value)
        with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True),mock.patch.object(backup_catalog.ArchiveCatalog,'checkpoint',return_value={}),mock.patch.object(retention_cohort,'upload_section',section),mock.patch.object(retention,'canonical',encoded):
            self.assertEqual(executor.run('apply')['result'],'APPLIED')
        self.assertEqual(len(effects),2);self.assertEqual(len(calls),3)
        self.assertTrue(all(rows and set(rows.values())=={1} for rows in calls.values()),calls)
    def test_paired_native_seals_equal_legacy_for_unicode_unknown_fields_and_configs(self):
        rows=[{'id':'a'*64,'paths':['/путь/🙂'],'tags':['z','a'],'unknown':{'nested':['雪',7,None,{'quoted':'a"b'}]}},
              {'id':'b'*64,'unknown':['new',{'key':'значение'}]}]
        config={'version':2,'id':'c'*64,'unknown':{'escaped':'\\\n','unicode':'é'}}
        for selected in (set(),{'b'*64},{'a'*64,'b'*64}):
            pair=retention.native_view_pair(config,list(reversed(rows)),selected)
            self.assertEqual(pair,(retention.native_view_digest(config,rows),retention.native_view_digest(config,[r for r in rows if r['id'] not in selected])))
        for value in (rows+[copy.deepcopy(rows[0])],rows+[{'id':'short'}]):
            with self.assertRaises(guards.GuardError):retention.native_view_pair(config,value,set())
    def test_ack_after_each_outside_response_closes_without_an_extra_native_read(self):
        case,_,executor,store,effects,evidence=self.case();native=case.w.restic;arrivals=[];reads=[];observations=[]
        inventory=retention.native_inventory
        def audit(*args,**kwargs):
            value=inventory(*args,**kwargs);observations.append((value,copy.deepcopy(value)));return value
        def read(lane,args,**kwargs):
            raw=native(lane,args,**kwargs)
            if args[2:]==['snapshots','--json']:
                reads.append(lane)
            return raw
        retired=retention_native._retirements
        def advancing(worker,active_store=None):
            value=retired(worker,active_store)
            if active_store is not None and len(arrivals)<2:self.append(case,arrivals)
            return value
        case.w.restic=read
        with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True),mock.patch.object(backup_catalog.ArchiveCatalog,'checkpoint',return_value={}),mock.patch.object(retention,'native_inventory',audit),mock.patch.object(retention,'refresh_prepared_inventory',side_effect=AssertionError('No extra full native refresh')):
            with mock.patch.object(retention_native,'_retirements',advancing):result=executor.run('apply')
        self.assertEqual(result['result'],'APPLIED');self.assertEqual(len(effects),2)
        self.assertTrue(set(arrivals)<=set(result['protected_arrival_ids']))
        # Every outside audit is the original full reader; closure adds no
        # refresh_prepared_inventory observation and never mutates its result.
        self.assertEqual(reads,['base','binlog']*(len(observations)+3))
        for actual,before in observations:self.assertEqual(actual,before,'Actual outside rows and timestamps stay frozen')
        for phase in store.phase_documents().values():
            self.assertEqual(phase['phase_sha256'],retention_native.retention_apply.document_digest({k:v for k,v in phase.items() if k!='phase_sha256'}))

    def rejection(self,mutation):
        case,_,executor,store,effects,evidence=self.case();original=retention_cohort.upload_section;active=[False];arrivals=[];changed=[];native=case.w.restic
        retired=retention_native._retirements
        def advance(worker,active_store=None):
            result=retired(worker,active_store)
            if active_store is not None and not arrivals:
                self.append(case,arrivals)
                if mutation in ('legacy-ack','ack-clock','all-files'):
                    if mutation=='all-files':
                        with case.catalog()._db(write=True) as db:
                            raw=db.execute('SELECT record FROM archives WHERE sid=?',(arrivals[0],)).fetchone()[0]
                            record=json.loads(raw);record['verified']['all_files_sha256']='f'*64
                            db.execute('UPDATE archives SET record=? WHERE sid=?',(backup_catalog.canonical(record),arrivals[0]));db.commit()
                    else:
                        path=case.root/'receipts/binlog/state.json';state=runtime.load_json(path);ack=state['confirmed'][-1]
                        if mutation=='legacy-ack':
                            for key in ('captured_at','prepared_at','confirmed_at'):ack.pop(key)
                        else:ack['prepared_at']='2026-10-12T13:01:00+00:00'
                        runtime.atomic_json(path,state)
            return result
        @contextlib.contextmanager
        def section(worker,**kwargs):
            with original(worker,**kwargs) as acquired:
                active[0]=True
                try:yield acquired
                finally:active[0]=False
        audit=retention.native_inventory;captured=[]
        def observation(*args,**kwargs):
            value=audit(*args,**kwargs);captured.append((value,kwargs.get('reader_out',[None])[0]));return value
        def read(lane,args,**kwargs):
            raw=native(lane,args,**kwargs)
            if active[0] and not changed and lane=='binlog' and args[2:]==['snapshots','--json']:
                changed.append(True);rows=json.loads(raw)
                if mutation=='missing-new':rows=[row for row in rows if row['id']!=arrivals[0]]
                elif mutation=='unknown-new':rows.append({**rows[0],'id':'f'*64})
                elif mutation=='old-native':next(row for row in rows if row['id']!=arrivals[0])['hostname']='changed'
                elif mutation=='new-native':next(row for row in rows if row['id']==arrivals[0])['tree']='f'*64
                elif mutation=='projection':captured[-1][0]['snapshots'][0]['token']='f'*32
                elif mutation=='record':next(iter(captured[-1][1]._records.values()))['verified']['all_files_sha256']='f'*64
                elif mutation=='record-key':
                    records=captured[-1][1]._records;key=next(iter(records));records['e'*64]=records.pop(key)
                elif mutation in ('raw-body','old-log','fresh-body','fresh-log','extra-fresh-log','missing-fresh-log','fresh-record','fresh-ordinal'):
                    with case.catalog()._db(write=True) as db:
                        if mutation=='raw-body':db.execute("UPDATE archives SET body=? WHERE sid=(SELECT sid FROM archives ORDER BY sequence LIMIT 1)",(b'corrupt',))
                        elif mutation=='old-log':db.execute('UPDATE logs SET body=? WHERE rowid=(SELECT rowid FROM logs ORDER BY rowid LIMIT 1)',(b'corrupt',))
                        elif mutation=='fresh-body':db.execute('UPDATE archives SET body=? WHERE sid=?',(b'corrupt',arrivals[0]))
                        elif mutation=='fresh-log':db.execute('UPDATE logs SET body=? WHERE sid=?',(b'corrupt',arrivals[0]))
                        elif mutation=='extra-fresh-log':db.execute('INSERT INTO logs(sid,name,body) VALUES(?,?,?)',(arrivals[0],'suhoput2-binlog.000099',b'extra'))
                        elif mutation=='missing-fresh-log':db.execute('DELETE FROM logs WHERE sid=?',(arrivals[0],))
                        elif mutation=='fresh-record':db.execute('UPDATE archives SET record=? WHERE sid=?',(b'{}',arrivals[0]))
                        else:db.execute('UPDATE archives SET token=? WHERE sid=?',('f'*32,arrivals[0]))
                        db.commit()
                return json.dumps(rows).encode()
            return raw
        case.w.restic=read
        with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True),mock.patch.object(retention_native,'_retirements',advance),mock.patch.object(retention_cohort,'upload_section',section),mock.patch.object(retention,'native_inventory',observation),mock.patch.object(backup_catalog.ArchiveCatalog,'checkpoint',return_value={}):
            with self.assertRaises(guards.GuardError):executor.run('apply')
        self.assertEqual(effects,[]);self.assertFalse(store.path.exists())
    def test_complete_closure_rejects_missing_unknown_and_changed_native_rows(self):
        for change in ('missing-new','unknown-new','old-native','new-native'):
            with self.subTest(change=change):self.rejection(change)
    def test_old_raw_body_and_borrowed_projection_mutation_during_final_list_block(self):
        for change in ('raw-body','old-log','projection','record','record-key'):
            with self.subTest(change=change):self.rejection(change)
    def test_new_tail_projection_mutation_during_final_native_observation_blocks(self):
        case,_,executor,store,effects,evidence=self.case();retired=retention_native._retirements;verify=retention.verify_native_views;arrivals=[]
        def advance(worker,active_store=None):
            value=retired(worker,active_store)
            if active_store is not None and not arrivals:self.append(case,arrivals)
            return value
        def corrupt(*args,**kwargs):
            value=verify(*args,**kwargs)
            kwargs['reader']._records[arrivals[0]]['projection']['last_log']+=1
            return value
        with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True),mock.patch.object(retention_native,'_retirements',advance),mock.patch.object(retention,'verify_native_views',corrupt):
            with self.assertRaisesRegex(guards.GuardError,'tail memory changed'):executor.run('apply')
        self.assertEqual(effects,[]);self.assertFalse(store.path.exists())
    def test_new_tail_live_manifest_and_logs_corruption_during_final_list_blocks_before_effect(self):
        for change in ('fresh-body','fresh-log','extra-fresh-log','missing-fresh-log','fresh-record','fresh-ordinal'):
            with self.subTest(change=change):self.rejection(change)
    def test_derived_tail_rejects_legacy_ack_bad_causal_clock_and_file_proof(self):
        for change in ('legacy-ack','ack-clock','all-files'):
            with self.subTest(change=change):self.rejection(change)
    def test_tail_over_32_or_expired_work_deadline_cannot_gain_native_authority(self):
        case,cohort,_,_,_,_=self.case()
        with case.catalog().open_reader() as reader:
            with self.assertRaisesRegex(guards.GuardError,'32 unique'):
                retention.authenticated_tail_inventory(case.w,cohort,reader,{'binlog':{'confirmed':[{'id':format(i+4096,'064x')} for i in range(33)]}},[])
            with self.assertRaisesRegex(guards.GuardError,'deadline'):
                retention.authenticated_tail_inventory(case.w,cohort,reader,{},[],deadline=time.monotonic()-1)
    def test_valid_rehashed_unpublished_phase_mutation_cannot_be_resealed(self):
        case,_,executor,store,effects,evidence=self.case();phase=retention_native.NewIntentStore.phase_document
        def changed(owner,*args,**kwargs):
            value=phase(owner,*args,**kwargs);value['authorized_at']='2026-10-12T12:59:59+00:00'
            value['phase_sha256']=retention_native.retention_apply.document_digest({k:v for k,v in value.items() if k!='phase_sha256'})
            return value
        with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True),mock.patch.object(retention_native.NewIntentStore,'phase_document',changed):
            with self.assertRaisesRegex(guards.GuardError,'original staged seal'):executor.run('apply')
        self.assertEqual(effects,[]);self.assertFalse(store.path.exists())

    def test_publication_tail_restaging_spends_original_work_deadline_before_promotion(self):
        case,_,executor,store,effects,evidence=self.case();stage=retention_native.StagedPublication.stage;arrivals=[];groups=[0]
        original=retention_cohort.upload_section
        @contextlib.contextmanager
        def section(worker,**kwargs):
            groups[0]+=1
            with original(worker,**kwargs) as acquired:yield acquired
        def late(writer,value):
            if writer.prepared is not None and groups[0]==3:
                writer.store.work_deadline=lambda:time.monotonic()-1
            stage(writer,value)
            if not arrivals:self.append(case,arrivals)
        with mock.patch.object(readiness_v2,'load_evidence',return_value=evidence),mock.patch.object(readiness_v2,'revalidate_budget',return_value=True),mock.patch.object(retention_cohort,'upload_section',section),mock.patch.object(retention_native.StagedPublication,'stage',late),mock.patch.object(backup_catalog.ArchiveCatalog,'checkpoint',return_value={}):
            result=executor.run('apply')
        self.assertEqual(result['result'],'RECONCILE_REQUIRED');self.assertEqual(len(effects),2)
        self.assertFalse((store.root/'journals-committed.json').exists())
        self.assertEqual(runtime.UploadJournal(case.root/'receipts/binlog',case.w.c['generation']).state().get('retention',[]),[])

if __name__=='__main__':unittest.main()
