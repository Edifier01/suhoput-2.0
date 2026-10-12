"""Synthetic fault controls; no DB, S3, secrets or server changes."""
import datetime as dt
import pathlib
import sys
import unittest
import tempfile
import hashlib
import json
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
    def adapter(self,responses):
        calls=[]
        def runner(args):
            calls.append(args)
            return responses[len(calls)-1]
        adapter=restic_adapter.ResticAdapter('s3:https://s3.invalid/stage-test/suhoput2/stage-b/repositories/base',
                    GEN,'/isolated/payload',runner=runner)
        return adapter,calls
    def test_remote_manifest_authenticated_bytes_match_tag_digest(self):
        body=b'{"synthetic":true}'
        sha=hashlib.sha256(body).hexdigest();token='a'*32
        row={'id':'d'*64,'tags':['task047','generation:'+GEN,'token:'+token,'manifest-sha:'+sha]}
        adapter,calls=self.adapter([json.dumps([row]).encode(),body])
        result=adapter.find(token)
        self.assertEqual(result[0]['manifest_sha256'],sha)
        self.assertEqual(calls[-1],['--repo',adapter.repository,'dump','d'*64,'/isolated/payload/manifest.json'])
        self.assertTrue(all(call[:2]==['--repo',adapter.repository] for call in calls))
    def test_remote_tag_digest_does_not_replace_actual_read(self):
        token='a'*32
        row={'id':'d'*64,'tags':['task047','generation:'+GEN,'token:'+token,'manifest-sha:'+SHA]}
        adapter,calls=self.adapter([json.dumps([row]).encode(),b'corrupt'])
        with self.assertRaises(guards.GuardError): adapter.find(token)
    def test_wrong_generation_and_unrelated_snapshot_are_rejected(self):
        for tags in [['task047','generation:'+'e'*32,'token:'+'a'*32,'manifest-sha:'+SHA], ['other']]:
            row={'id':'d'*64,'tags':tags}
            adapter,calls=self.adapter([json.dumps([row]).encode()])
            with self.assertRaises(guards.GuardError): adapter.find('a'*32)
            self.assertEqual(len(calls),1)
    def test_wrong_prefix_rejected_before_any_external_call(self):
        with self.assertRaises(guards.GuardError):
            restic_adapter.ResticAdapter('s3:https://s3.invalid/stage-test/old',GEN,'/isolated/payload',runner=lambda args:None)

    def test_put_hint_uses_exact_authenticated_snapshot_read_without_inventory_scan(self):
        body=b'{"synthetic":true}';sha=hashlib.sha256(body).hexdigest();token='a'*32
        row={'tags':['task047','generation:'+GEN,'token:'+token,'manifest-sha:'+sha]}
        summary={'message_type':'summary','snapshot_id':'d'*64}
        adapter,calls=self.adapter([json.dumps(summary).encode(),json.dumps(row).encode(),body])
        with mock.patch('restic_adapter.pathlib.Path') as path:
            manifest=path.return_value.__truediv__.return_value
            manifest.is_symlink.return_value=False;manifest.is_file.return_value=True;manifest.read_bytes.return_value=body
            adapter.put('/isolated/payload',{'generation':GEN,'token':token,'manifest_sha256':sha,'parent_id':'e'*64})
        self.assertEqual(adapter.find(token)[0]['id'],'d'*64)
        self.assertEqual(calls[1][2:],['cat','snapshot','d'*64])
        self.assertIn('--parent',calls[0]);self.assertIn('e'*64,calls[0]);self.assertIn('--json',calls[0])
        self.assertFalse(any('snapshots' in call for call in calls))

    def test_invalid_put_summary_never_becomes_read_hint(self):
        body=b'{"synthetic":true}';sha=hashlib.sha256(body).hexdigest()
        adapter,calls=self.adapter([b'{"message_type":"summary","snapshot_id":"short"}'])
        with mock.patch('restic_adapter.pathlib.Path') as path:
            manifest=path.return_value.__truediv__.return_value
            manifest.is_symlink.return_value=False;manifest.is_file.return_value=True;manifest.read_bytes.return_value=body
            with self.assertRaises(guards.GuardError):
                adapter.put('/isolated/payload',{'generation':GEN,'token':'a'*32,'manifest_sha256':sha})

if __name__=='__main__': unittest.main()
