"""PITR boundary and source-scope checks, synthetic; no credentials/network."""
import sys,pathlib,unittest,importlib.util
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'infra/backup'))
import guards
class ReplayPlanTests(unittest.TestCase):
    def module(self):self.assertIsNotNone(importlib.util.find_spec('restore'),'Missing native restore guard');return __import__('restore')
    def logs(self):return [{'file':f'suhoput2-binlog.{i:06d}','size':1000,'sha256':'a'*64} for i in range(1,4)]
    def test_committed_stop_uses_base_first_and_target_last_not_later_file(self):
        m=self.module();selected=m.replay_range({'file':'suhoput2-binlog.000001','position':600},{'file':'suhoput2-binlog.000002','position':700},self.logs());self.assertEqual([x['file'] for x in selected],['suhoput2-binlog.000001','suhoput2-binlog.000002'])
    def test_fresh_restore_reaches_container_creation_after_new_owned_volume(self):
        import tempfile,json
        from backup_worker_test import SnapshotCoherenceTests,dump
        import runtime
        m=self.module()
        class ReachedCreation(Exception):pass
        with tempfile.TemporaryDirectory() as d:
            w=SnapshotCoherenceTests().fake(d);w.gate=lambda:None;w.restic=lambda *a,**kw:b'{}'
            p=w.root/'base';p.mkdir();(p/'db.sql').write_bytes(dump());runtime.atomic_json(p/'media.json',{'inventory':[]});(p/'logs').mkdir()
            logs=[{'file':'suhoput2-binlog.000001','size':4,'sha256':__import__('hashlib').sha256(b'\xfebin').hexdigest()}];(p/'logs'/logs[0]['file']).write_bytes(b'\xfebin')
            chain={'generation':w.c['generation'],'logs':logs,'snapshots':[{'id':'b'*64,'manifest_sha256':'c'*64,'first_log':1,'last_log':1}]};runtime.atomic_json(w.root/'receipts/binlog-chain.json',chain)
            identity={'application_sha256':'d'*64,'configuration_sha256':'e'*64};base={'kind':'full','generation':w.c['generation'],'source':w.source,'stage_app_sha':w.c['stage_app_sha'],'coordinates':{'file':logs[0]['file'],'position':4},**identity};w.captured_identity=lambda *a:identity
            r=m.Recovery.__new__(m.Recovery);r.w=w;r.plan={'token':'f'*32,'base_id':'a'*64,'full_id':'a'*64,'stop':{'file':logs[0]['file'],'position':4}};r.root=w.root/'control-restore'/'fresh';r.root.parent.mkdir();r.intent=w.root/'receipts/restore-intent.json';r.snapshot=lambda lane,sid,**kw:((base if lane=='base' else {'kind':'binlog','logs':logs}),p,('0'*64 if lane=='base' else 'c'*64));r.decoder=lambda logs,target,**kw:target.write_bytes(b'synthetic replay')
            calls=[]
            class Native:
                def run(self,args,**kw):
                    calls.append(args)
                    if args[:3]==['docker','volume','inspect']:return json.dumps([{'Name':m.VOLUME,'Labels':{'task047.generation':w.c['generation'],'task047.restore-token':r.plan['token']}}]).encode()
                    if args[:3]==['docker','run','-d']:raise ReachedCreation()
                    return b''
            w.native=Native()
            with self.assertRaises(ReachedCreation):r.run()
            self.assertTrue(any(x[:3]==['docker','volume','create'] for x in calls))
    def test_before_base_ids_use_exact_native_columns_not_free_text(self):
        m=self.module();from backup_worker_test import dump
        ddl=b"\nCREATE TABLE `wp_wc_orders` (\n  `id` bigint,\n  `note` longtext\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\nCREATE TABLE `wp_suhoput_operations` (\n  `operation_id` varchar(36),\n  `note` longtext\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n"
        rows=b"INSERT INTO `wp_wc_orders` (`id`, `note`) VALUES (1,'12');\nINSERT INTO `wp_suhoput_operations` (`operation_id`, `note`) VALUES ('base','target');\n"
        self.assertEqual(m.control_records(dump()+ddl+rows),{'orders':[1],'operations':['base']})
        with self.assertRaises(guards.GuardError):m.control_records(dump())
        with self.assertRaises(guards.GuardError):m.control_records(dump()+ddl+rows+rows)
    def test_unknown_docker_inventory_is_not_evidence_of_absence(self):
        m=self.module();self.assertTrue(hasattr(m,'objects_absent'),'Missing verified absence guard')
        class Unavailable:
            def run(self,args):raise m.NativeError('daemon unavailable')
        with self.assertRaises(m.NativeError):m.objects_absent(Unavailable())
    def test_existing_control_volume_rejected_by_complete_inventory(self):
        m=self.module();self.assertTrue(hasattr(m,'objects_absent'),'Missing verified absence guard')
        class Existing:
            def run(self,args):return b'' if args[1]=='container' else b'"suhoput2-stage-restore-047_db"\n'
        with self.assertRaises(guards.GuardError):m.objects_absent(Existing())
    def test_gap_truncation_reverse_or_foreign_binlog_rejected(self):
        m=self.module();start={'file':'suhoput2-binlog.000001','position':600};end={'file':'suhoput2-binlog.000002','position':700}
        for logs,target in [(self.logs()[1:],end),([self.logs()[0],self.logs()[2]],end),(self.logs(),{**end,'position':1001}),(self.logs(),{**start,'position':500}),(self.logs(),{'file':'prod-binlog.000001','position':700})]:
            with self.subTest(target=target),self.assertRaises(guards.GuardError):m.replay_range(start,target,logs)
class TipProfileTests(unittest.TestCase):
    def subject(self):import restore;return restore
    def plan(self):
        return {'format':1,'generation':'a'*32,'base_id':'b'*64,'full_id':'b'*64,'token':'c'*32,'stop':{'file':'suhoput2-binlog.000003','position':1000},'first_order':12,'second_order':13,'first_operation':'11111111-1111-1111-1111-111111111111','second_operation':'22222222-2222-2222-2222-222222222222'}
    def test_fixed_tip_profile_preserves_prior_control_and_rejects_arbitrary_targets(self):
        m=self.subject();self.assertTrue(hasattr(m,'control_profile'),'Closed-tip independent profile missing')
        tip=m.control_profile('tip');self.assertEqual(tip['control'],'suhoput2-stage-restore-tip-047-db-1');self.assertNotEqual(tip['volume'],m.VOLUME)
        with self.assertRaises(guards.GuardError):m.control_profile('production')
    def test_end_must_be_exact_last_closed_archived_position(self):
        m=self.subject();self.assertTrue(hasattr(m,'validate_tip_end'),'Closed-tip end binding missing');logs=ReplayPlanTests().logs();m.validate_tip_end(self.plan()['stop'],logs)
        for stop in ({'file':'suhoput2-binlog.000002','position':1000},{'file':'suhoput2-binlog.000003','position':999},{'file':'suhoput2-binlog.000004','position':1000}):
            with self.assertRaises(guards.GuardError):m.validate_tip_end(stop,logs)
    def test_tip_presence_controls_are_both_after_base_and_not_point_exclusion(self):
        m=self.subject();self.assertTrue(hasattr(m,'validate_tip_plan'),'Tip controls missing');p=m.validate_tip_plan(self.plan(),'a'*32)
        r=m.Recovery.__new__(m.Recovery);r.profile='tip';r.plan=p
        self.assertEqual(r.controls()[:2],(12,13));self.assertEqual(r.expected_counts(),[1,1,1,1])
        bad=self.plan();bad['second_order']=12
        with self.assertRaises(guards.GuardError):m.validate_tip_plan(bad,'a'*32)
    def test_absence_check_ignores_preserved_old_control_but_rejects_tip_collision(self):
        m=self.subject();self.assertTrue(hasattr(m,'control_profile'),'Tip profile missing')
        class Previous:
            def run(self,args):return b'"suhoput2-stage-restore-047-db-1"\n' if args[1]=='container' else b'"suhoput2-stage-restore-047_db"\n'
        m.objects_absent(Previous(),profile='tip')
        class Collision:
            def run(self,args):return b'"suhoput2-stage-restore-tip-047-db-1"\n' if args[1]=='container' else b''
        with self.assertRaises(guards.GuardError):m.objects_absent(Collision(),profile='tip')
class NativeProgressReceiptTests(unittest.TestCase):
    def existing_fixture(self,directory,profile='tip'):
        import json,hashlib,runtime,restore
        from backup_worker_test import dump
        r,before,after=self.fixture(directory,profile);r.control=restore.control_profile(profile)['control'];r.volume=restore.control_profile(profile)['volume']
        r.w.root=r.root/'worker';(r.w.root/'receipts').mkdir(parents=True);r.intent=r.w.root/'receipts'/'intent.json';runtime.atomic_json(r.intent,{'generation':'a'*32,'token':r.plan['token']})
        (r.root/'control.password').write_text('f'*64)
        p=r.root/'base';p.mkdir();ddl=b"\nCREATE TABLE `wp_wc_orders` (\n  `id` bigint\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\nCREATE TABLE `wp_suhoput_operations` (\n  `operation_id` varchar(36)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n";(p/'db.sql').write_bytes(dump()+ddl)
        identity={'application_sha256':'e'*64,'configuration_sha256':'f'*64};base={'kind':'full','generation':'a'*32,'stage_app_sha':'1'*40,'source':{},'coordinates':{'file':'suhoput2-binlog.000001','position':4},**identity};r.w.c['stage_app_sha']='1'*40;r.w.captured_identity=lambda *args:identity;r.snapshot=lambda *args,**kwargs:(base,p,'d'*64)
        logs=[];(r.root/'logs').mkdir()
        for index in range(1,4):
            data=b'\xfebin'+bytes(996);name=f'suhoput2-binlog.{index:06d}';(r.root/'logs'/name).write_bytes(data);logs.append({'file':name,'size':1000,'sha256':hashlib.sha256(data).hexdigest()})
        runtime.atomic_json(r.w.root/'receipts/binlog-chain.json',{'generation':'a'*32,'logs':logs,'snapshots':[{'id':'3'*64,'first_log':1,'last_log':3,'manifest_sha256':'4'*64}]})
        row={'Id':'9'*64,'Config':{'Image':restore.DB_IMAGE,'Labels':{'task047.generation':'a'*32}},'HostConfig':{'NetworkMode':'none'},'NetworkSettings':{'Ports':{}},'Mounts':[{'Source':str(r.root/'socket'),'Destination':'/run/mysqld','Type':'bind'},{'Name':r.volume,'Destination':'/var/lib/mysql'}]}
        class Native:
            def run(self,args,**kwargs):
                if args[:2]==['docker','inspect']:return json.dumps([row]).encode()
                if args[:3]==['docker','volume','inspect']:return json.dumps([{'Name':r.volume,'Labels':{'task047.generation':'a'*32,'task047.restore-token':r.plan['token']}}]).encode()
                raise AssertionError('Resume must not perform native writes')
        r.w.native=Native();r.w.sql=lambda query,**kwargs:b'OFF\t1\t0' if query.startswith('SELECT @@') else '\n'.join(map(str,r.expected_counts())).encode()
        decoded=[]
        def decoder(logs,target,**kwargs):decoded.append(target);target.write_bytes(b'Authenticated selected native replay\n')
        r.decoder=decoder;r.verify_result=lambda *args:{'kind':r.before_proof_kind,'proof':r.before_proof}
        return r,decoded

    def test_existing_tip_requires_receipts_and_uses_truthful_four_presence_proof(self):
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as d:
            r,decoded=self.existing_fixture(d)
            with patch('restore.private_path',side_effect=lambda path:path):result=r.verify_existing()
            self.assertEqual(result['kind'],'native-journals');self.assertIn('tip after counts 1/1/1/1',result['proof']);self.assertNotIn('counts1/0/1/0',result['proof'])
            self.assertEqual(len(decoded),1)
            (r.root/'base-imported.json').unlink();(r.root/'replay-applied.json').unlink()
            with patch('restore.private_path',side_effect=lambda path:path),self.assertRaises(guards.GuardError):r.verify_existing()
            self.assertEqual(len(decoded),1)

    def test_existing_legacy_point_proof_states_native_journal_unavailable(self):
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as d:
            r,decoded=self.existing_fixture(d,'point');(r.root/'base-imported.json').unlink();(r.root/'replay-applied.json').unlink()
            with patch('restore.private_path',side_effect=lambda path:path):result=r.verify_existing()
            self.assertEqual(result['kind'],'legacy-point-authenticated-base-absence');self.assertIn('original native replay journals unavailable',result['proof']);self.assertEqual(len(decoded),1)

    def test_existing_tip_rejects_regenerated_sql_different_from_applied_bytes(self):
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as d:
            r,decoded=self.existing_fixture(d);r.decoder=lambda logs,target,**kwargs:target.write_bytes(b'Different regenerated replay')
            with patch('restore.private_path',side_effect=lambda path:path),self.assertRaises(guards.GuardError):r.verify_existing()

    def fixture(self,directory,profile='tip'):
        import json,hashlib
        from types import SimpleNamespace
        import restore,runtime
        r=restore.Recovery.__new__(restore.Recovery);r.profile=profile;r.root=pathlib.Path(directory)
        r.w=SimpleNamespace(c={'generation':'a'*32});r.plan=TipProfileTests().plan()
        if profile=='point':r.plan.update(expected_order=12,excluded_order=13,expected_operation=r.plan['first_operation'],excluded_operation=r.plan['second_operation'])
        replay=b'Authenticated selected native replay\n';(r.root/'replay.sql').write_bytes(replay)
        before={'token':r.plan['token'],'generation':'a'*32,'control_id':'9'*64,'base_id':r.plan['base_id'],'base_manifest_sha256':'d'*64,'before_counts':[0,0,0,0]}
        after={'token':r.plan['token'],'generation':'a'*32,'control_id':'9'*64,'base_id':r.plan['base_id'],'base_manifest_sha256':'d'*64,'stop':r.plan['stop'],'after_counts':r.expected_counts(),'replay_sha256':hashlib.sha256(replay).hexdigest()}
        runtime.atomic_json(r.root/'base-imported.json',before);runtime.atomic_json(r.root/'replay-applied.json',after)
        return r,before,after
    def subject(self):
        import restore
        self.assertTrue(hasattr(restore.Recovery,'verify_native_progress'),'Existing restore never verifies native replay journals')
        return restore
    def test_tip_journals_bind_generation_attempt_control_base_stop_counts_and_replay(self):
        import tempfile,copy,runtime
        self.subject()
        with tempfile.TemporaryDirectory() as d:
            r,before,after=self.fixture(d)
            self.assertTrue(r.verify_native_progress('d'*64,'9'*64))
            cases=[('before','token','e'*32),('after','token','e'*32),('before','generation','e'*32),('after','generation','e'*32),
                   ('before','control_id','e'*64),('after','control_id','e'*64),('before','base_id','e'*64),('after','base_id','e'*64),
                   ('before','base_manifest_sha256','e'*64),('after','base_manifest_sha256','e'*64),
                   ('before','before_counts',[0,0,0,1]),('after','after_counts',[1,0,1,0]),
                   ('before','before_counts',[False]*4),('after','after_counts',[True]*4),
                   ('after','stop',{'file':'suhoput2-binlog.000002','position':1000}),('after','replay_sha256','e'*64)]
            for name,key,value in cases:
                bad_before,bad_after=copy.deepcopy(before),copy.deepcopy(after)
                (bad_before if name=='before' else bad_after)[key]=value
                runtime.atomic_json(r.root/'base-imported.json',bad_before);runtime.atomic_json(r.root/'replay-applied.json',bad_after)
                with self.subTest(journal=name,field=key),self.assertRaises(guards.GuardError):r.verify_native_progress('d'*64,'9'*64)
    def test_tip_missing_partial_or_changed_replay_is_rejected(self):
        import tempfile,runtime
        self.subject()
        with tempfile.TemporaryDirectory() as d:
            r,before,after=self.fixture(d)
            (r.root/'replay.sql').write_bytes(b'Changed SQL')
            with self.assertRaises(guards.GuardError):r.verify_native_progress('d'*64,'9'*64)
            (r.root/'replay-applied.json').unlink()
            with self.assertRaises(guards.GuardError):r.verify_native_progress('d'*64,'9'*64)
            (r.root/'base-imported.json').unlink()
            with self.assertRaises(guards.GuardError):r.verify_native_progress('d'*64,'9'*64)
    def test_legacy_point_allows_only_both_absent_journals(self):
        import tempfile,runtime
        self.subject()
        with tempfile.TemporaryDirectory() as d:
            r,before,after=self.fixture(d,'point')
            self.assertTrue(r.verify_native_progress('d'*64,'9'*64))
            (r.root/'replay-applied.json').unlink()
            with self.assertRaises(guards.GuardError):r.verify_native_progress('d'*64,'9'*64)
            (r.root/'base-imported.json').unlink()
            self.assertFalse(r.verify_native_progress('d'*64,'9'*64))

class FreshReplayExecutionTests(unittest.TestCase):
    def test_fresh_tip_import_replay_and_four_native_count_guards_write_bound_journals(self):
        import tempfile,json,hashlib,runtime,restore
        from backup_worker_test import SnapshotCoherenceTests,dump
        self.assertTrue(hasattr(restore.Recovery,'verify_native_progress'),'Native post-replay receipt verification absent')
        with tempfile.TemporaryDirectory() as d:
            w=SnapshotCoherenceTests().fake(d);w.restic=lambda *a,**kw:b'{}'
            p=w.root/'base';p.mkdir();db=dump();(p/'db.sql').write_bytes(db);runtime.atomic_json(p/'media.json',{'inventory':[]});(p/'logs').mkdir()
            logbytes=b'\xfebin';logs=[{'file':'suhoput2-binlog.000001','size':4,'sha256':hashlib.sha256(logbytes).hexdigest()}];(p/'logs'/logs[0]['file']).write_bytes(logbytes)
            chain={'generation':w.c['generation'],'logs':logs,'snapshots':[{'id':'b'*64,'manifest_sha256':'c'*64,'first_log':1,'last_log':1}]};runtime.atomic_json(w.root/'receipts/binlog-chain.json',chain)
            identity={'application_sha256':'d'*64,'configuration_sha256':'e'*64};base={'kind':'full','generation':w.c['generation'],'source':w.source,'stage_app_sha':w.c['stage_app_sha'],'coordinates':{'file':logs[0]['file'],'position':4},**identity};w.captured_identity=lambda *a:identity
            r=restore.Recovery.__new__(restore.Recovery);r.w=w;r.profile='tip';target=restore.control_profile('tip');r.control=target['control'];r.volume=target['volume'];r.project=target['project'];r.plan=TipProfileTests().plan();r.plan.update(generation=w.c['generation'],base_id='a'*64,full_id='a'*64,stop={'file':logs[0]['file'],'position':4})
            r.root=w.root/'control-restore'/'fresh-tip';r.root.parent.mkdir();r.intent=w.root/'receipts/restore-tip-intent.json';r.snapshot=lambda lane,sid,**kw:((base if lane=='base' else {'kind':'binlog','logs':logs}),p,('0'*64 if lane=='base' else 'c'*64));replay=b'native decoded replay';r.decoder=lambda logs,target,**kw:target.write_bytes(replay)
            imports=[];count_queries=[];state={'phase':'empty'}
            container={'Id':'9'*64,'Config':{'Image':restore.DB_IMAGE,'Labels':{'task047.generation':w.c['generation']}},'HostConfig':{'NetworkMode':'none'},'NetworkSettings':{'Ports':{}},'Mounts':[{'Source':str(r.root/'socket'),'Destination':'/run/mysqld','Type':'bind'},{'Name':r.volume,'Destination':'/var/lib/mysql','Type':'volume'}]}
            class Native:
                def run(self,args,**kw):
                    if args[:3]==['docker','volume','inspect']:return json.dumps([{'Name':r.volume,'Labels':{'task047.generation':w.c['generation'],'task047.restore-token':r.plan['token']}}]).encode()
                    if args[:2]==['docker','inspect']:return json.dumps([container]).encode()
                    if args[:3]==['docker','exec','-i']:
                        if args[3]!=r.control:raise AssertionError('Wrong control target')
                        imports.append(kw['data']);state['phase']='base' if len(imports)==1 else 'replayed'
                    return b''
            def sql(query,*,container):
                self.assertEqual(container,r.control)
                if query=='SELECT 1;':return b'1'
                if query=='SELECT @@event_scheduler,@@skip_networking,@@log_bin;':return b'OFF\t1\t0'
                if query.startswith('SELECT COUNT(*) FROM information_schema'):return b'0'
                count_queries.append(query)
                return b'0\n0\n0\n0\n' if state['phase']=='base' else b'1\n1\n1\n1\n'
            w.native=Native();w.sql=sql
            def verify(*args):
                self.assertEqual(imports,[db,replay])
                self.assertTrue(r.verify_native_progress('0'*64,'9'*64))
                return 'verified after native replay'
            r.verify_result=verify
            self.assertEqual(r.run(),'verified after native replay')
            expected="SELECT COUNT(*) FROM suhoput2_stage.wp_wc_orders WHERE id=12;SELECT COUNT(*) FROM suhoput2_stage.wp_wc_orders WHERE id=13;SELECT COUNT(*) FROM suhoput2_stage.wp_suhoput_operations WHERE operation_id='11111111-1111-1111-1111-111111111111';SELECT COUNT(*) FROM suhoput2_stage.wp_suhoput_operations WHERE operation_id='22222222-2222-2222-2222-222222222222';"
            self.assertEqual(count_queries,[expected,expected])
            before=runtime.load_json(r.root/'base-imported.json');after=runtime.load_json(r.root/'replay-applied.json')
            self.assertEqual(before['before_counts'],[0,0,0,0]);self.assertEqual(after['after_counts'],[1,1,1,1]);self.assertEqual(after['base_manifest_sha256'],'0'*64)

if __name__=='__main__':unittest.main()
