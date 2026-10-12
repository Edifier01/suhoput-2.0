"""PITR boundary and source-scope checks, synthetic; no credentials/network."""
import sys,pathlib,unittest,importlib.util
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'infra/backup'))
import guards
class ReplayPlanTests(unittest.TestCase):
    def module(self):self.assertIsNotNone(importlib.util.find_spec('restore'),'Missing native restore guard');return __import__('restore')
    def logs(self):return [{'file':f'suhoput2-binlog.{i:06d}','size':1000,'sha256':'a'*64} for i in range(1,4)]
    def test_committed_stop_uses_base_first_and_target_last_not_later_file(self):
        m=self.module();selected=m.replay_range({'file':'suhoput2-binlog.000001','position':600},{'file':'suhoput2-binlog.000002','position':700},self.logs());self.assertEqual([x['file'] for x in selected],['suhoput2-binlog.000001','suhoput2-binlog.000002'])
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
