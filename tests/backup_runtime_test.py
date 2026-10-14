"""Synthetic fault controls; no DB, S3, secrets or server changes."""
import datetime as dt
import pathlib
import sys
import unittest
import tempfile
import hashlib
import json
import itertools
from unittest import mock
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'infra' / 'backup'))
import guards
import runtime
import restic_adapter

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 10, 12, 12, tzinfo=UTC)
GEN = 'a' * 32
SHA = 'b' * 64

def snapshot(number, kind, days, **extra):
    return {'id': f'{number:064x}', 'generation': GEN, 'kind': kind,
            'time': (NOW - dt.timedelta(days=days)).isoformat(), **extra}

class BackupRuntimeGuards(unittest.TestCase):
    def test_source_accepts_only_isolated_stage(self):
        source = guards.source_scope('/srv/suhoput2-stage-20261001', 'suhoput2_stage', GEN)
        self.assertEqual(source['db_container'], 'suhoput2-stage-20261001-db-1')
        self.assertEqual(source['wordpress_volume'], 'suhoput2-stage-20261001_wordpress')

    def test_source_rejects_old_site_and_traversal(self):
        for root in ['/srv/suhoput', '/srv/suhoput2-stage-20261001/../suhoput', '/srv/other', '/srv/suhoput2-stage-20261001/backup']:
            with self.subTest(root=root), self.assertRaises(guards.GuardError):
                guards.source_scope(root, 'suhoput2_stage', GEN)

    def test_wrong_schema_and_generation_rejected(self):
        for schema, generation in [('production', GEN), ('suhoput2_stage', 'wrong')]:
            with self.assertRaises(guards.GuardError):
                guards.source_scope('/srv/suhoput2-stage-20261001', schema, generation)

    def test_s3_scope_is_fixed_prefix_and_https(self):
        self.assertEqual(guards.repository_url('https://s3.invalid', 'stage-test', 'base'),
                         's3:https://s3.invalid/stage-test/suhoput2/stage-b/repositories/base')

    def test_bad_endpoint_and_lane_rejected(self):
        for endpoint in ['http://s3.invalid', 'https://user:pass@s3.invalid', 'https://s3.invalid/path', 'https://s3.invalid?token=x']:
            with self.assertRaises(guards.GuardError): guards.repository_url(endpoint, 'stage-test', 'base')
        for lane in ['old', '../base', 'base/../../prod']:
            with self.assertRaises(guards.GuardError): guards.repository_url('https://s3.invalid', 'stage-test', lane)

    def test_media_path_only_relative_files(self):
        self.assertEqual(guards.media_path('2026/10/test.png'), '2026/10/test.png')
        for path in ['/etc/passwd', '../a', 'a/../b', r'a\b', 'https://x/a', 'a//b', 'a\x00b', 'a/']:
            with self.subTest(path=path), self.assertRaises(guards.GuardError): guards.media_path(path)

    def test_ack_requires_single_matching_snapshot(self):
        pending={'token':'c'*32,'generation':GEN,'manifest_sha256':SHA}
        matches=[{'id':'d'*64, **pending}]
        self.assertEqual(guards.confirm_upload(pending, matches), 'd'*64)
        for wrong in [[], matches*2, [{'id':'d'*64, **pending, 'generation':'e'*32}], [{'id':'d'*64, **pending, 'manifest_sha256':'f'*64}]]:
            with self.assertRaises(guards.GuardError): guards.confirm_upload(pending, wrong)

    def test_next_logs_require_every_sequence_and_same_bytes(self):
        known=[{'file':'suhoput2-binlog.000001','sha256':SHA,'size':512}]
        available=known+[{'file':'suhoput2-binlog.000002','sha256':'c'*64,'size':600}]
        self.assertEqual([x['file'] for x in guards.new_logs(known, available)], ['suhoput2-binlog.000002'])
        for wrong in [known+[{'file':'suhoput2-binlog.000003','sha256':SHA,'size':512}],
                      [{'file':'suhoput2-binlog.000001','sha256':'e'*64,'size':512}],
                      [{'file':'other.000002','sha256':SHA,'size':512}]]:
            with self.assertRaises(guards.GuardError): guards.new_logs(known, wrong)

    def test_expired_local_logs_need_not_remain_after_verified_upload(self):
        known=[{'file':'suhoput2-binlog.000001','sha256':SHA,'size':512}]
        self.assertEqual(guards.new_logs(known,[{'file':'suhoput2-binlog.000002','sha256':SHA,'size':512}])[0]['file'], 'suhoput2-binlog.000002')

    def test_gap_in_confirmed_history_is_not_accepted(self):
        known=[{'file':'suhoput2-binlog.000001','sha256':SHA,'size':512},
               {'file':'suhoput2-binlog.000003','sha256':SHA,'size':512}]
        with self.assertRaises(guards.GuardError): guards.new_logs(known,[])

    def test_clock_rollback_and_lag_raise(self):
        for uploaded in [NOW+dt.timedelta(seconds=1), NOW-dt.timedelta(seconds=61)]:
            with self.assertRaises(guards.GuardError): guards.upload_lag(uploaded.isoformat(), NOW)
        self.assertEqual(guards.upload_lag((NOW-dt.timedelta(seconds=20)).isoformat(), NOW), 20)

    def test_retention_keeps_pre_window_anchor_and_older_full_dependency(self):
        full=snapshot(1,'full',40)
        anchor=snapshot(2,'hourly',31,full_id=full['id'],first_log=12)
        recent=snapshot(3,'hourly',1,full_id=full['id'],first_log=50)
        older=snapshot(4,'hourly',45,full_id=full['id'],first_log=1)
        log_old=snapshot(5,'binlog',40,first_log=1,last_log=11)
        log_keep=snapshot(6,'binlog',31,first_log=12,last_log=12)
        plan=guards.retention_candidates([full,anchor,recent,older,log_old,log_keep],GEN,NOW)
        self.assertIn(full['id'], plan['keep'])
        self.assertIn(anchor['id'], plan['keep'])
        self.assertIn(log_keep['id'], plan['keep'])
        self.assertIn(older['id'], plan['candidates'])
        self.assertIn(log_old['id'], plan['candidates'])
        self.assertFalse(plan['apply_allowed'])
    def test_retention_anchor_time_ties_keep_every_base_and_full_dependency_in_any_order(self):
        older=snapshot(1,'full',40,first_log=1)
        dependency=snapshot(5,'full',60,first_log=1)
        ties=[snapshot(3,'full',31,first_log=12),snapshot(2,'pre-update',31,first_log=10),snapshot(4,'hourly',31,first_log=11,full_id=dependency['id'])]
        logs=[snapshot(6,'binlog',40,first_log=1,last_log=9),snapshot(7,'binlog',31,first_log=10,last_log=20)]
        expected=None
        for order in itertools.permutations(ties):
            plan=guards.retention_candidates([older,*order,dependency,*logs],GEN,NOW)
            self.assertEqual(plan['anchor_id'],ties[1]['id'])
            self.assertTrue({x['id'] for x in ties}|{dependency['id']}<=set(plan['keep']))
            self.assertTrue({older['id'],logs[0]['id']}<=set(plan['candidates']))
            self.assertFalse({x['id'] for x in ties}&set(plan['candidates']))
            if expected is None:expected=plan
            else:self.assertEqual(plan,expected)
        tied_first=[{**x,'first_log':10} for x in ties]
        for order in itertools.permutations(tied_first):self.assertEqual(guards.retention_candidates([older,*order,dependency,*logs],GEN,NOW)['anchor_id'],ties[1]['id'])
    def test_anchor_ties_at_cutoff_and_short_history_are_all_kept(self):
        for days in (30,1):
            full=snapshot(1,'full',days,first_log=1);pre=snapshot(2,'pre-update',days,first_log=1)
            hourly=snapshot(3,'hourly',days,full_id=pre['id'],first_log=1)
            for bases in itertools.permutations([full,pre,hourly]):
                plan=guards.retention_candidates([*bases,snapshot(4,'binlog',days,first_log=1,last_log=2)],GEN,NOW)
                self.assertEqual(plan['anchor_id'],full['id']);self.assertEqual(plan['candidates'],[])
                self.assertEqual(plan['pre_window_anchor_present'],days==30)

    def test_unknown_snapshot_and_missing_dependency_stop_retention(self):
        full=snapshot(1,'full',31)
        anchor=snapshot(2,'hourly',30,full_id=full['id'],first_log=1)
        for snapshots in [[full,anchor,snapshot(3,'unrelated',35)], [anchor],
                          [full,anchor,{**snapshot(3,'full',35),'generation':'c'*32}]]:
            with self.assertRaises(guards.GuardError): guards.retention_candidates(snapshots, GEN, NOW)

    def test_new_system_cannot_claim_30_day_history(self):
        full=snapshot(1,'full',1)
        plan=guards.retention_candidates([full],GEN,NOW)
        self.assertFalse(plan['history_coverage_verified'])
        self.assertFalse(plan['apply_allowed'])

    def test_opaque_restore_receipt_never_authorizes_deletion(self):
        plan={'anchor_id':'1'*64,'keep':['1'*64], 'candidates':['2'*64], 'apply_allowed':False}
        for proof in [{}, {'restored':True}, {'anchor_id':'3'*64,'generation':GEN,'integrity':True,'pitr':True,'all_media':True,'owner_kit':True}]:
            with self.assertRaises(guards.GuardError): guards.authorize_retention(plan, proof, GEN)

    def test_boolean_restore_flags_never_authorize_native_deletion(self):
        plan={'anchor_id':'1'*64,'keep':['1'*64], 'candidates':['2'*64], 'apply_allowed':False}
        proof={'anchor_id':'1'*64,'generation':GEN,'integrity':True,'pitr':True,
               'all_media':True,'owner_kit':True,'chain_verified':True}
        with self.assertRaises(guards.GuardError): guards.authorize_retention(plan,proof,GEN)

    def test_retention_rejects_gap_after_anchor(self):
        rows=[snapshot(1,'full',31,first_log=12),snapshot(2,'full',40,first_log=1),
              snapshot(3,'binlog',32,first_log=1,last_log=11),
              snapshot(4,'binlog',30,first_log=12,last_log=12),
              snapshot(5,'binlog',1,first_log=14,last_log=14)]
        with self.assertRaises(guards.GuardError): guards.retention_candidates(rows,GEN,NOW)

class MemoryArchive:
    def __init__(self):
        self.records=[]
        self.put_count=0
        self.lose_response=False
        self.no_effect=False
        self.find_count=0
    def find(self,token):
        self.find_count+=1
        return [x for x in self.records if x['token']==token]
    def put(self,payload,pending):
        self.put_count+=1
        if not self.no_effect: self.records.append({'id':'d'*64,**pending})
        if self.lose_response: raise TimeoutError('synthetic lost response')

class UploadJournalFaults(unittest.TestCase):
    def setUp(self):
        self.fixture_root=pathlib.Path(__file__).resolve().parents[1]/'.cache'/'backup-runtime-tests'
        self.fixture_root.mkdir(parents=True,exist_ok=True)
        self.tmp=tempfile.TemporaryDirectory(dir=self.fixture_root,prefix='synthetic-')
        self.root=pathlib.Path(self.tmp.name)
        self.backend=MemoryArchive()
        self.payload=self.root/'payload'
        self.payload.mkdir()
        (self.payload/'manifest.json').write_text(json.dumps({'synthetic':True,'generation':GEN,'captured_at':NOW.isoformat()}),encoding='utf-8')
        self.sha=hashlib.sha256((self.payload/'manifest.json').read_bytes()).hexdigest()
    def tearDown(self):
        self.assertEqual(self.root.resolve().parent,self.fixture_root.resolve())
        self.assertTrue(self.root.name.startswith('synthetic-'))
        self.tmp.cleanup()
    def journal(self,**kw): return runtime.UploadJournal(self.root/'journal',GEN,clock=lambda:NOW,**kw)
    def test_success_confirms_only_after_read_reconciliation(self):
        journal=self.journal()
        self.assertEqual(journal.upload(self.payload,self.sha,self.backend),'d'*64)
        self.assertEqual(journal.state()['last_success_at'],NOW.isoformat())
        self.assertEqual(self.backend.put_count,1)
        self.assertEqual(self.backend.find_count,1)
    def test_lost_response_recovered_in_new_instance_without_second_put(self):
        self.backend.lose_response=True
        with self.assertRaises(TimeoutError): self.journal().upload(self.payload,self.sha,self.backend)
        self.assertNotIn('last_success_at',self.journal().state())
        self.assertEqual(self.journal().upload(self.payload,self.sha,self.backend),'d'*64)
        self.assertEqual(self.backend.put_count,1)
    def test_unknown_without_snapshot_never_retries_put(self):
        self.backend.lose_response=True;self.backend.no_effect=True
        with self.assertRaises(TimeoutError): self.journal().upload(self.payload,self.sha,self.backend)
        with self.assertRaises(guards.GuardError): self.journal().upload(self.payload,self.sha,self.backend)
        self.assertEqual(self.backend.put_count,1)
        self.assertNotIn('last_success_at',self.journal().state())
    def test_duplicate_or_wrong_archive_proof_stops_heartbeat(self):
        self.backend.lose_response=True
        with self.assertRaises(TimeoutError): self.journal().upload(self.payload,self.sha,self.backend)
        self.backend.records*=2
        with self.assertRaises(guards.GuardError): self.journal().upload(self.payload,self.sha,self.backend)
        self.assertNotIn('last_success_at',self.journal().state())
    def test_changed_pending_payload_never_uploaded_or_confirmed(self):
        self.backend.lose_response=True
        with self.assertRaises(TimeoutError): self.journal().upload(self.payload,self.sha,self.backend)
        (self.payload/'manifest.json').write_text('changed',encoding='utf-8')
        with self.assertRaises(guards.GuardError): self.journal().upload(self.payload,self.sha,self.backend)
        self.assertEqual(self.backend.put_count,1)
    def test_state_commit_failure_recovers_same_snapshot(self):
        fail=[True]
        def write(path,data):
            if path.name=='state.json' and fail[0]:
                fail[0]=False;raise OSError('synthetic storage fault')
            runtime.atomic_json(path,data)
        with self.assertRaises(OSError): self.journal(writer=write).upload(self.payload,self.sha,self.backend)
        self.assertEqual(self.journal().upload(self.payload,self.sha,self.backend),'d'*64)
        self.assertEqual(self.backend.put_count,1)
    def test_generation_change_stops_reconciliation(self):
        self.backend.lose_response=True
        with self.assertRaises(TimeoutError): self.journal().upload(self.payload,self.sha,self.backend)
        other=runtime.UploadJournal(self.root/'journal','e'*32,clock=lambda:NOW)
        with self.assertRaises(guards.GuardError): other.upload(self.payload,self.sha,self.backend)

    def test_late_reconciliation_does_not_refresh_data_watermark(self):
        self.backend.lose_response=True
        with self.assertRaises(TimeoutError): self.journal().upload(self.payload,self.sha,self.backend)
        late=runtime.UploadJournal(self.root/'journal',GEN,clock=lambda:NOW+dt.timedelta(minutes=10))
        late.upload(self.payload,self.sha,self.backend)
        self.assertEqual(late.state()['last_success_at'],NOW.isoformat())
        with self.assertRaises(guards.GuardError): guards.upload_lag(late.state()['last_success_at'],NOW+dt.timedelta(minutes=10))
        self.assertEqual(self.backend.put_count,1)

    def test_clock_rollback_between_uploads_rejected_before_put(self):
        self.journal().upload(self.payload,self.sha,self.backend)
        earlier=runtime.UploadJournal(self.root/'journal',GEN,clock=lambda:NOW-dt.timedelta(minutes=5))
        with self.assertRaises(guards.GuardError): earlier.upload(self.payload,self.sha,self.backend)
        self.assertEqual(self.backend.put_count,1)

    def test_clock_rollback_after_saved_intent_rejected_before_put(self):
        (self.payload/'manifest.json').write_text(json.dumps({'generation':GEN,'captured_at':(NOW-dt.timedelta(seconds=10)).isoformat()}),encoding='utf-8')
        self.sha=hashlib.sha256((self.payload/'manifest.json').read_bytes()).hexdigest()
        def interrupt(path,data):
            runtime.atomic_json(path,data)
            raise OSError('synthetic interrupt after saved intent')
        with self.assertRaises(OSError): self.journal(writer=interrupt).upload(self.payload,self.sha,self.backend)
        earlier=runtime.UploadJournal(self.root/'journal',GEN,clock=lambda:NOW-dt.timedelta(seconds=5))
        with self.assertRaises(guards.GuardError): earlier.upload(self.payload,self.sha,self.backend)
        self.assertEqual(self.backend.put_count,0)

class ResticReadProofs(unittest.TestCase):
    def native(self,row):
        return {'tree':'2'*64,'time':'2026-10-12T11:01:00Z','paths':['/isolated/payload'],**row}
    def tree(self,row,nodes):
        return b'\n'.join(json.dumps(x).encode() for x in [{'message_type':'snapshot','id':'d'*64,**row},*nodes])
    def adapter(self,responses):
        calls=[]
        def runner(args):
            calls.append(args)
            return responses[len(calls)-1]
        adapter=restic_adapter.ResticAdapter('s3:https://s3.invalid/stage-test/suhoput2/stage-b/repositories/base',
                    GEN,'/isolated/payload',runner=runner,verify_archive=lambda sid,metadata,**proof:True)
        return adapter,calls
    def test_remote_manifest_authenticated_bytes_match_tag_digest(self):
        body=json.dumps({'synthetic':True,'generation':GEN,'files':[]}).encode()
        sha=hashlib.sha256(body).hexdigest();token='a'*32
        row=self.native({'id':'d'*64,'tags':['task047','generation:'+GEN,'token:'+token,'manifest-sha:'+sha]})
        listing=self.tree(row,[{'message_type':'node','type':'file','path':'/isolated/payload/manifest.json','size':len(body)}]);adapter,calls=self.adapter([json.dumps([row]).encode(),body,listing])
        result=adapter.find(token)
        self.assertEqual(result[0]['manifest_sha256'],sha)
        self.assertEqual(calls[1],['--repo',adapter.repository,'dump','d'*64,'/isolated/payload/manifest.json'])
        self.assertTrue(all(call[:2]==['--repo',adapter.repository] for call in calls))
    def test_remote_tag_digest_does_not_replace_actual_read(self):
        token='a'*32
        row=self.native({'id':'d'*64,'tags':['task047','generation:'+GEN,'token:'+token,'manifest-sha:'+SHA]})
        adapter,calls=self.adapter([json.dumps([row]).encode(),b'corrupt'])
        with self.assertRaises(guards.GuardError): adapter.find(token)
    def test_wrong_generation_and_unrelated_snapshot_are_rejected(self):
        for tags in [['task047','generation:'+'e'*32,'token:'+'a'*32,'manifest-sha:'+SHA], ['other']]:
            row=self.native({'id':'d'*64,'tags':tags})
            adapter,calls=self.adapter([json.dumps([row]).encode()])
            with self.assertRaises(guards.GuardError): adapter.find('a'*32)
            self.assertEqual(len(calls),1)
    def test_partial_snapshot_with_manifest_but_missing_database_is_rejected(self):
        body=json.dumps({'generation':GEN,'files':[{'path':'db.sql','bytes':100,'sha256':'c'*64}]}).encode();digest=hashlib.sha256(body).hexdigest();token='a'*32
        row=self.native({'id':'d'*64,'tags':['task047','generation:'+GEN,'token:'+token,'manifest-sha:'+digest]})
        listing=self.tree(row,[{'message_type':'node','type':'file','path':'/isolated/payload/manifest.json','size':len(body)}])
        with self.assertRaises(guards.GuardError):restic_adapter.verify_tree_listing(listing,'d'*64,'/isolated/payload',row,body)
    def test_archive_requires_actual_data_verifier_after_metadata(self):
        body=json.dumps({'generation':GEN,'files':[]}).encode();digest=hashlib.sha256(body).hexdigest();token='a'*32
        row=self.native({'id':'d'*64,'tags':['task047','generation:'+GEN,'token:'+token,'manifest-sha:'+digest]})
        listing=self.tree(row,[{'message_type':'node','type':'file','path':'/isolated/payload/manifest.json','size':len(body)}])
        adapter,calls=self.adapter([json.dumps([row]).encode(),body,listing]);adapter.verify_archive=lambda sid,metadata,**proof:False
        with self.assertRaises(guards.GuardError):adapter.find(token)
    def test_wrong_prefix_rejected_before_any_external_call(self):
        with self.assertRaises(guards.GuardError):
            restic_adapter.ResticAdapter('s3:https://s3.invalid/stage-test/old',GEN,'/isolated/payload',runner=lambda args:None)

    def test_put_hint_uses_exact_authenticated_snapshot_read_without_inventory_scan(self):
        body=json.dumps({'synthetic':True,'generation':GEN,'files':[]}).encode();sha=hashlib.sha256(body).hexdigest();token='a'*32
        row=self.native({'tags':['task047','generation:'+GEN,'token:'+token,'manifest-sha:'+sha]})
        summary={'message_type':'summary','snapshot_id':'d'*64}
        listing=self.tree(row,[{'message_type':'node','type':'file','path':'/isolated/payload/manifest.json','size':len(body)}]);adapter,calls=self.adapter([json.dumps(summary).encode(),json.dumps(row).encode(),body,listing])
        with mock.patch('restic_adapter.pathlib.Path') as path:
            manifest=path.return_value.__truediv__.return_value
            manifest.is_symlink.return_value=False;manifest.is_file.return_value=True;manifest.read_bytes.return_value=body
            adapter.put('/isolated/payload',{'generation':GEN,'token':token,'manifest_sha256':sha,'parent_id':'e'*64})
        self.assertEqual(adapter.find(token)[0]['id'],'d'*64)
        self.assertEqual(calls[1][2:],['cat','snapshot','d'*64])
        self.assertIn('--parent',calls[0]);self.assertIn('e'*64,calls[0]);self.assertIn('--json',calls[0])
        self.assertFalse(any('snapshots' in call for call in calls))
        self.assertFalse(any('ls' in call for call in calls),'Exact SID verification must not list every repository snapshot')

    def test_invalid_put_summary_never_becomes_read_hint(self):
        body=json.dumps({'synthetic':True,'generation':GEN,'files':[]}).encode();sha=hashlib.sha256(body).hexdigest()
        adapter,calls=self.adapter([b'{"message_type":"summary","snapshot_id":"short"}'])
        with mock.patch('restic_adapter.pathlib.Path') as path:
            manifest=path.return_value.__truediv__.return_value
            manifest.is_symlink.return_value=False;manifest.is_file.return_value=True;manifest.read_bytes.return_value=body
            with self.assertRaises(guards.GuardError):
                adapter.put('/isolated/payload',{'generation':GEN,'token':'a'*32,'manifest_sha256':sha})

    def test_callback_receives_exact_raw_manifest_and_authenticated_native_tree(self):
        body=json.dumps({'generation':GEN,'files':[]},indent=1).encode()+b'\n';digest=hashlib.sha256(body).hexdigest();token='a'*32
        row=self.native({'id':'d'*64,'tags':['task047','generation:'+GEN,'token:'+token,'manifest-sha:'+digest]})
        listing=self.tree(row,[{'message_type':'node','type':'file','path':'/isolated/payload/manifest.json','size':len(body)}])
        adapter,_=self.adapter([json.dumps([row]).encode(),body,listing]);seen=[]
        def verify(sid,manifest,**proof):seen.append(proof);return True
        adapter.verify_archive=verify;adapter.find(token)
        self.assertEqual(seen,[{'native_metadata':row,'raw_manifest':body}])

    def test_actual_listing_tree_time_paths_and_tags_cannot_differ_from_snapshot(self):
        body=json.dumps({'generation':GEN,'files':[]}).encode();digest=hashlib.sha256(body).hexdigest();token='a'*32
        row=self.native({'id':'d'*64,'tags':['task047','generation:'+GEN,'token:'+token,'manifest-sha:'+digest]})
        for key,value in [('tree','4'*64),('time','2026-10-12T11:02:00Z'),('paths',['/foreign']),('tags',['task047'])]:
            listing=self.tree({**row,key:value},[{'message_type':'node','type':'file','path':'/isolated/payload/manifest.json','size':len(body)}])
            with self.subTest(key=key),self.assertRaises(guards.GuardError):restic_adapter.verify_tree_listing(listing,'d'*64,'/isolated/payload',row,body)

class RestoredTreeOrderingTests(unittest.TestCase):
    def fixture(self, directory):
        import worker
        target=pathlib.Path(directory);scope=pathlib.Path(target.anchor)/'isolated/payload'
        payload=target/scope.relative_to(scope.anchor);js=payload/'wordpress/wp-admin/js'
        (js/'widgets').mkdir(parents=True)
        (js/'widgets.js').write_bytes(b'actual top-level widget source')
        (js/'widgets/custom-html-widgets.js').write_bytes(b'actual nested widget source')
        manifest={'files':worker.tree_inventory(payload)};raw=json.dumps(manifest).encode()
        (payload/'manifest.json').write_bytes(raw)
        worker.verify_payload(payload,manifest)
        return target,scope,payload,manifest,raw

    def test_worker_path_component_order_accepts_complete_wordpress_widgets_tree(self):
        import worker
        with tempfile.TemporaryDirectory() as directory:
            target,scope,payload,manifest,raw=self.fixture(directory)
            actual=worker.tree_inventory(target)
            self.assertNotEqual(actual,sorted(actual,key=lambda row:row['path']))
            self.assertEqual(restic_adapter.verify_restored_tree(target,str(scope),manifest,raw,worker.tree_inventory),payload)
            worker.verify_payload(payload,manifest)  # Original manifest order is unchanged.

    def test_canonical_order_still_rejects_missing_extra_corrupt_and_duplicate_files(self):
        import worker
        for mutation in ('missing','extra','corrupt','duplicate','malformed'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as directory:
                target,scope,payload,manifest,raw=self.fixture(directory);inventory=worker.tree_inventory
                path=payload/'wordpress/wp-admin/js/widgets.js'
                if mutation=='missing':path.unlink()
                elif mutation=='extra':(target/'outside-payload').write_bytes(b'foreign')
                elif mutation=='corrupt':path.write_bytes(b'changed')
                elif mutation=='duplicate':inventory=lambda root:worker.tree_inventory(root)+[worker.tree_inventory(root)[0]]
                else:inventory=lambda root:[{'path':None,'bytes':1,'sha256':'a'*64}]
                with self.assertRaises(guards.GuardError):restic_adapter.verify_restored_tree(target,str(scope),manifest,raw,inventory)

    @unittest.skipUnless(__import__('os').name=='posix','Native symlink creation requires POSIX')
    def test_canonical_order_still_rejects_symlink(self):
        import worker
        with tempfile.TemporaryDirectory() as directory:
            target,scope,payload,manifest,raw=self.fixture(directory)
            path=payload/'wordpress/wp-admin/js/widgets.js';original=path.read_bytes();path.unlink()
            other=target/'other';other.write_bytes(original);path.symlink_to(other)
            with self.assertRaises(guards.GuardError):restic_adapter.verify_restored_tree(target,str(scope),manifest,raw,worker.tree_inventory)

if __name__=='__main__': unittest.main()
