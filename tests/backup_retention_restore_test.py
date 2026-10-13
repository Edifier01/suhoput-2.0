"""Native-v2 operational restore boundaries; synthetic tests make no S3/DB calls."""
import copy,datetime as dt,hashlib,importlib.util,json,pathlib,sys,tempfile,types,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'infra/backup'))
import guards
import contextlib,os
from unittest import mock
from backup_binlog_test import build,data,FILE

def subject():
    unittest.TestCase().assertIsNotNone(importlib.util.find_spec('retention_restore'),'Operational restore producer absent')
    import retention_restore
    return retention_restore

def fixture():
    raw,_=build();_,logs=data(raw);generation='a'*32;source={'generation':generation,'root':'/srv/suhoput2-stage-20261011'}
    cohort={'sha256':'b'*64,'planned_at':'2026-10-13T11:00:00+00:00','x':'fixed'}
    coords={'file':FILE,'position':4};base='c'*64;sid='d'*64
    manifests={base:{'kind':'full','generation':generation,'source':source,'stage_app_sha':'e'*40,'coordinates':coords,
                     'application_sha256':'1'*64,'configuration_sha256':'2'*64},
               sid:{'kind':'binlog','source':source,'generation':generation,'logs':logs}}
    inv={'generation':generation,'cohort':cohort,'repositories':{'base':'3'*64,'binlog':'4'*64},'manifests':manifests,
         'snapshots':[{'id':base,'lane':'base','kind':'full','manifest_sha256':'5'*64},{'id':sid,'lane':'binlog','kind':'binlog','manifest_sha256':'6'*64}]}
    plan={'format':'native-retention-restore-plan-v1','profile':'tip','generation':generation,'source':source,'cohort':cohort,
          'token':'7'*32,'base_id':base,'full_id':base,'stop':{'file':FILE,'position':len(raw)}}
    reader=types.SimpleNamespace(binlog_bytes=lambda owner,name:raw)
    return inv,plan,logs,reader,raw

class OperationalRestoreTests(unittest.TestCase):
    def test_plan_uses_fixed_profile_token_targets_and_rejects_arbitrary_paths(self):
        m=subject();inv,plan,_,_,_=fixture();m.validate_plan(plan,inv,'tip')
        target=m.targets(plan)
        self.assertEqual(target['control'],'suhoput2-stage-retention-tip-'+plan['token']+'-db')
        for change in ('profile','token','generation','cohort','target','foreign_base'):
            bad=copy.deepcopy(plan)
            if change=='profile':bad['profile']='production'
            elif change=='token':bad['token']='../production'
            elif change=='generation':bad['generation']='f'*32
            elif change=='cohort':bad['cohort']['sha256']='f'*64
            elif change=='target':bad['volume']='source-db'
            else:bad['base_id']='f'*64
            with self.subTest(change=change),self.assertRaises(guards.GuardError):m.validate_plan(bad,inv,'tip')

    def test_hydration_uses_verified_catalog_and_checks_all_row_bytes(self):
        m=subject();inv,plan,logs,reader,raw=fixture();calls=[]
        reader.binlog_bytes=lambda sid,name:(calls.append((sid,name)) or raw)
        with tempfile.TemporaryDirectory() as directory:
            target=pathlib.Path(directory);report=m.hydrate_binlogs(reader,inv,logs,{'file':FILE,'position':4},plan['stop'],target)
            self.assertEqual((target/FILE).read_bytes(),raw);self.assertEqual(report['selected_row_events'],1)
            self.assertEqual(calls,[('d'*64,FILE)])
            self.assertEqual(report['files'],logs)
            m.hydrate_binlogs(reader,inv,logs,{'file':FILE,'position':4},plan['stop'],target,existing=True)

    def test_corrupt_catalog_bytes_descriptor_foreign_owner_and_partial_slice_fail(self):
        m=subject()
        for change in ('bytes','crc','descriptor','missing','duplicate','endpoint'):
            inv,plan,logs,reader,raw=fixture()
            if change=='bytes':reader.binlog_bytes=lambda *a:raw+b'x'
            elif change=='crc':
                bad=raw[:-1]+bytes([raw[-1]^1]);reader.binlog_bytes=lambda *a:bad
                logs[0]['sha256']=hashlib.sha256(bad).hexdigest();inv['manifests']['d'*64]['logs']=logs
            elif change=='descriptor':logs=copy.deepcopy(logs);logs[0]['sha256']='f'*64
            elif change=='missing':inv['snapshots']=inv['snapshots'][:1]
            elif change=='duplicate':inv['snapshots'].append(copy.deepcopy(inv['snapshots'][-1]))
            else:plan['stop']['position']-=1
            with tempfile.TemporaryDirectory() as directory,self.subTest(change=change),self.assertRaises(guards.GuardError):
                m.hydrate_binlogs(reader,inv,logs,{'file':FILE,'position':4},plan['stop'],pathlib.Path(directory))

    def test_existing_hydration_never_overwrites_missing_or_changed_bytes(self):
        m=subject();inv,plan,logs,reader,raw=fixture()
        with tempfile.TemporaryDirectory() as directory:
            target=pathlib.Path(directory)
            with self.assertRaises(guards.GuardError):m.hydrate_binlogs(reader,inv,logs,{'file':FILE,'position':4},plan['stop'],target,existing=True)
            (target/FILE).write_bytes(b'changed')
            with self.assertRaises(guards.GuardError):m.hydrate_binlogs(reader,inv,logs,{'file':FILE,'position':4},plan['stop'],target,existing=True)
            self.assertEqual((target/FILE).read_bytes(),b'changed')

    def test_target_absence_requires_native_inventory_and_keeps_existing_objects(self):
        m=subject();_,plan,_,_,_=fixture();names=m.targets(plan)
        native=types.SimpleNamespace(run=lambda args:json.dumps(names['volume']).encode()+b'\n' if args[1]=='volume' else b'')
        with self.assertRaises(guards.GuardError):m.objects_absent(native,names)
        def unavailable(args):raise RuntimeError('daemon unavailable')
        with self.assertRaises(RuntimeError):m.objects_absent(types.SimpleNamespace(run=unavailable),names)

    def test_decoder_batches_preserve_order_and_only_first_last_boundaries(self):
        m=subject();inv,plan,logs,reader,raw=fixture()
        with tempfile.TemporaryDirectory() as directory:
            recovery=object.__new__(m.RetentionRecovery);recovery.root=pathlib.Path(directory);recovery.plan=plan;calls=[]
            def decoder(batch,target,**kwargs):calls.append((batch,kwargs));target.write_bytes(str(len(calls)).encode())
            recovery.decoder=decoder;many=[{'file':f'suhoput2-binlog.{n:06d}'} for n in range(1,2050)]
            target=recovery.root/'replay.sql';recovery.decode(many,{'file':FILE,'position':123},target)
            self.assertEqual([len(x[0]) for x in calls],[1024,1024,1]);self.assertEqual(target.read_bytes(),b'123')
            self.assertEqual([x[1] for x in calls],[{'start':123,'stop':None},{'start':None,'stop':None},{'start':None,'stop':plan['stop']['position']}])
            with self.assertRaises(FileExistsError):recovery.decode(many,{'file':FILE,'position':123},target)

    def test_sql_state_queries_only_derived_control_and_rejects_foreign_schema(self):
        m=subject();_,plan,*_=fixture();recovery=object.__new__(m.RetentionRecovery);recovery.plan=plan;recovery.control=m.targets(plan)['control']
        recovery.base_catalog={'catalog':{'wp_posts':['ID']}};queries=[]
        def sql(query,*,container):
            queries.append((query,container));return b'wp_posts\tInnoDB\tBASE TABLE\nCOLUMN\twp_posts\tID\n' if 'information_schema' in query else b'2\n'
        commands=[]
        recovery.w=types.SimpleNamespace(sql=sql,native=types.SimpleNamespace(run=lambda args:(commands.append(args) or b'stable native dump')))
        result=recovery.state();self.assertEqual(result['table_counts'],{'wp_posts':2})
        self.assertTrue(all(container==recovery.control for _,container in queries));self.assertTrue(all(args[2]==recovery.control for args in commands))
        recovery.base_catalog={'catalog':{'foreign':['ID']}}
        with self.assertRaises(guards.GuardError):recovery.state()


@unittest.skipUnless(os.name=='posix','Protected Linux execution boundary')
class OperationalExecutionTests(unittest.TestCase):
    def setup_recovery(self,directory):
        m=subject();inv,plan,logs,reader,raw=fixture();root=pathlib.Path(directory);os.chmod(root,0o700)
        (root/'receipts').mkdir(mode=0o700);(root/'control-restore').mkdir(mode=0o700)
        recovery=object.__new__(m.RetentionRecovery);recovery.plan=plan;recovery.profile='tip'
        for key,value in m.targets(plan).items():setattr(recovery,key,value)
        recovery.root=root/'control-restore'/'new-control';recovery.intent=root/'receipts'/'attempt.json';recovery.lock=root/'receipts'/'lock'
        recovery.inventory=inv;recovery.calls=[];recovery.w=types.SimpleNamespace(root=root,c={'generation':inv['generation']},gate=lambda:None)
        def native(args,**kw):
            recovery.calls.append((args,kw))
            if args[:3]==['docker','volume','inspect']:
                return json.dumps([{'Name':recovery.volume,'Labels':{'task047.generation':inv['generation'],'task047.restore-token':plan['token']}}]).encode()
            return b''
        recovery.w.native=types.SimpleNamespace(run=native)
        recovery.prepare=lambda _:None;recovery.fresh=lambda:None;recovery.ready=lambda:None
        recovery.inspect_control=lambda expected_id=None:{'Id':'8'*64,'State':{'Running':False}}
        recovery.sql=lambda query:b'0'
        recovery.state=lambda:{'schema_sha256':'9'*64,'table_rows_sha256':'a'*64,'table_counts':{'wp_posts':2}}
        def inputs(*,existing=False):
            payload=recovery.root/'payload'
            if not existing:payload.mkdir(mode=0o700);(payload/'db.sql').write_bytes(b'BASE SQL')
            return {'coordinates':{'file':FILE,'position':4}},payload,'5'*64,{},payload,'5'*64,logs
        recovery.inputs=inputs
        recovery.decode=lambda logs,start,target:(target.write_bytes(b'REPLAY SQL'),os.chmod(target,0o600))
        def finish(inputs,control_id,**kwargs):recovery.journals(inputs[2],control_id);return {'result':'PASS','completed_at':m.now()}
        recovery.finish=finish;recovery.stop=lambda control_id:recovery.calls.append((['stop',control_id],{}))
        catalog=types.SimpleNamespace(open_reader=lambda:contextlib.nullcontext(reader))
        patches=[mock.patch.object(m.backup_catalog,'ArchiveCatalog',return_value=catalog),mock.patch('retention_native.publish_evidence',side_effect=lambda w,p,r,*a:r)]
        for patch in patches:patch.start();self.addCleanup(patch.stop)
        return recovery

    def test_actual_sql_order_durable_journals_and_only_owned_control_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            recovery=self.setup_recovery(directory);result=recovery.run();self.assertEqual(result['result'],'PASS')
            sql=[(args,kwargs['data']) for args,kwargs in recovery.calls if args[:2]==['docker','exec']]
            self.assertEqual([raw for _,raw in sql],[b'BASE SQL',b'REPLAY SQL']);self.assertTrue(all(args[3]==recovery.control for args,_ in sql))
            self.assertTrue(recovery.intent.exists());self.assertTrue((recovery.root/'base-imported.json').exists());self.assertTrue((recovery.root/'replay-applied.json').exists())
            self.assertEqual(recovery.calls[-1][0],['stop','8'*64])
            before=list(recovery.calls)
            with self.assertRaises(guards.GuardError):recovery.run()
            self.assertEqual(before,recovery.calls)

    def test_unknown_replay_never_retries_or_starts_existing_control(self):
        with tempfile.TemporaryDirectory() as directory:
            recovery=self.setup_recovery(directory);original=recovery.w.native.run
            def failed(args,**kwargs):
                result=original(args,**kwargs)
                if kwargs.get('data')==b'REPLAY SQL':raise RuntimeError('lost native response')
                return result
            recovery.w.native.run=failed
            with self.assertRaises(RuntimeError):recovery.run()
            self.assertTrue((recovery.root/'base-imported.json').exists());self.assertFalse((recovery.root/'replay-applied.json').exists())
            self.assertEqual(recovery.calls[-1][0],['stop','8'*64])
            before=list(recovery.calls)
            with self.assertRaises(guards.GuardError):recovery.run()
            with self.assertRaises((guards.GuardError,FileNotFoundError)):recovery.verify_existing()
            self.assertEqual(before,recovery.calls)

    def test_volume_identity_is_checked_before_any_database_container_start(self):
        with tempfile.TemporaryDirectory() as directory:
            recovery=self.setup_recovery(directory);original=recovery.w.native.run
            def foreign(args,**kw):
                result=original(args,**kw)
                return json.dumps([{'Name':recovery.volume,'Labels':{}}]).encode() if args[:3]==['docker','volume','inspect'] else result
            recovery.w.native.run=foreign
            with self.assertRaises(guards.GuardError):recovery.run()
            self.assertFalse(any(args[:2]==['docker','run'] for args,_ in recovery.calls))

    def test_existing_success_redecodes_reads_and_stops_without_sql_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            recovery=self.setup_recovery(directory);recovery.run();recovery.calls=[]
            result=recovery.verify_existing();self.assertEqual(result['result'],'PASS')
            self.assertEqual([args for args,_ in recovery.calls],[['docker','start',recovery.control],['stop','8'*64]])
            after=recovery.root/'replay-applied.json';value=json.loads(after.read_bytes());value['replay_sha256']='f'*64
            import runtime
            runtime.atomic_json(after,value);recovery.calls=[]
            with self.assertRaises(guards.GuardError):recovery.verify_existing()
            self.assertEqual(recovery.calls,[])

if __name__=='__main__':unittest.main()
