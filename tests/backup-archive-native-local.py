"""Native pinned-restic exact-SID readback on disposable local storage, no S3."""
import hashlib,json,os,pathlib,subprocess,sys,tempfile
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'infra/backup'))
import backup_catalog,guards,restic_adapter,worker

def main(binary):
    executable=pathlib.Path(binary).resolve()
    assert worker.sha(executable)==worker.RESTIC_SHA
    with tempfile.TemporaryDirectory(prefix='archive-native-') as directory:
        root=pathlib.Path(directory);payload=root/'spool/base-payload';payload.mkdir(parents=True)
        (payload/'nested').mkdir();(payload/'nested/data.bin').write_bytes(bytes(range(256))*8192)
        manifest={'generation':'a'*32,'files':worker.tree_inventory(payload)}
        raw=(json.dumps(manifest,sort_keys=True)+'\n').encode();(payload/'manifest.json').write_bytes(raw)
        password=root/'password';password.write_text('synthetic-local-test-only',encoding='ascii');os.chmod(password,0o600)
        commands=[]
        def native(*args):
            commands.append(list(args))
            result=subprocess.run([str(executable),'--repo',str(root/'repository'),'--password-file',str(password),
                                   '--cache-dir',str(root/'cache'),*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
            if result.returncode:raise RuntimeError('Pinned restic local command failed: '+args[0])
            return result.stdout
        native('init')
        rows=[json.loads(line) for line in native('backup',str(payload),'--json','--host','task047-stage-b',
              '--tag','task047','--tag','generation:'+'a'*32,'--tag','token:'+'b'*32,
              '--tag','manifest-sha:'+hashlib.sha256(raw).hexdigest()).splitlines()]
        sid=next(row['snapshot_id'] for row in rows if row.get('message_type')=='summary');guards.hex_id(sid,64)
        metadata=json.loads(native('cat','snapshot',sid))
        _,_,digest=backup_catalog.native_identity(metadata,sid,str(payload),'a'*32)
        assert digest==hashlib.sha256(raw).hexdigest()
        target=root/'restored';native('restore',sid,'--target',str(target),'--verify')
        restored=restic_adapter.verify_restored_tree(target,str(payload),manifest,raw,worker.tree_inventory)
        assert (restored/'manifest.json').read_bytes()==raw
        assert (restored/'nested/data.bin').read_bytes()==(payload/'nested/data.bin').read_bytes()
        (target/'outside').write_bytes(b'foreign')
        try:restic_adapter.verify_restored_tree(target,str(payload),manifest,raw,worker.tree_inventory)
        except guards.GuardError:pass
        else:raise AssertionError('Native restored foreign bytes accepted')
        assert not any(command[0] in ('ls','snapshots') for command in commands)
        print(json.dumps({'result':'PASS','scenario':'native-local-exact-SID-restore-and-complete-tree',
                          'restic_sha256':worker.RESTIC_SHA,'native_commands':[command[0] for command in commands],
                          'all_file_sha256_verified':True,'foreign_target_rejected':True,'s3_requests':0,
                          'provider_cost_observed':False},sort_keys=True))

if __name__=='__main__':main(sys.argv[1])
