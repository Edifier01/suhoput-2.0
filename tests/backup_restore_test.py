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
if __name__=='__main__':unittest.main()
