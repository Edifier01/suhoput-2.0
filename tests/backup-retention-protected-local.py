"""Native protected cohort/catalog/exact-ID rehearsal on fresh Linux tmpfs.

Dates and six prerequisite documents are synthetic. This proves local native
mechanics, never actual 30-day observation, owner execution or provider cost.
"""
import copy, datetime as dt, hashlib, json, os, pathlib, subprocess, sys, shutil
sys.path[:0]=['/source/infra/backup','/source/tests']
import backup_catalog,guards,retention,retention_apply,retention_cohort,retention_native,runtime
from backup_retention_apply_test import fixture,GEN,NOW as FIXTURE_NOW
from backup_binlog_test import build
os.umask(0o077)
root=pathlib.Path('/control/protected-retention');root.mkdir(mode=0o700)
for name in ('spool','cache','receipts','bin'):(root/name).mkdir(mode=0o700)
binary=pathlib.Path('/binary/restic')
assert hashlib.sha256(binary.read_bytes()).hexdigest()=='20d4142678d0d95ec11a4759def1b73fd9190abc9ca19e4b62d067c0b387e639'
password=root/'password';password.write_text('synthetic-temporary-password-not-a-live-key\n');password.chmod(0o600)
env={'PATH':'/usr/bin:/bin','HOME':str(root),'TMPDIR':str(root)}
repos={lane:str(root/('repo-'+lane)) for lane in ('base','binlog')}
def command(lane,args,timeout=90):
    result=subprocess.run([str(binary),'--password-file',str(password),'--repo',repos[lane],*args],capture_output=True,env=env,timeout=timeout)
    if result.returncode:raise guards.GuardError('Native local command failed: '+result.stderr.decode(errors='replace'))
    return result.stdout
for lane in repos:command(lane,['init','--repository-version','2'])
repoids={lane:json.loads(command(lane,['cat','config']))['id'] for lane in repos}
for lane in repos:
    (root/'receipts'/lane).mkdir(mode=0o700)
    runtime.atomic_json(root/'receipts'/('init-'+lane+'.json'),{'generation':GEN,'repository_id':repoids[lane]})
for path in pathlib.Path('/source/infra/backup').glob('*'):
    if path.suffix in ('.py','.php'):shutil.copyfile(path,root/'bin'/path.name);(root/'bin'/path.name).chmod(0o600)
NOW=dt.datetime.now(dt.timezone.utc)
def shifted(value):
    if isinstance(value,dict):return {key:shifted(item) for key,item in value.items()}
    if isinstance(value,list):return [shifted(item) for item in value]
    if isinstance(value,str) and value.startswith('2026-') and 'T' in value and value.endswith('Z'):
        return (guards.utc(value)+(NOW-FIXTURE_NOW)).isoformat().replace('+00:00','Z')
    return value
original,_,_=shifted(fixture(split=True));mapping={};known={};attempt=None
class LocalWorker:
    c={'repositories':repos,'generation':GEN,'code_sha':'f'*40,'stage_app_sha':'f'*40}
    root=root;bin=root/'bin';source=original['manifests'][original['snapshots'][0]['id']]['source']
    def __init__(self):self.calls=[]
    def gate(self):pass  # Source/disk/NTP are explicitly synthetic here.
    def restic(self,lane,args,**kwargs):
        assert args[:2]==['--repo',repos[lane]]
        return command(lane,args[2:],timeout=kwargs.get('timeout',90))
    def retention_forget(self,lane,ids,**kwargs):
        self.calls.append((lane,ids));assert retention_native.IntentStore(attempt).load() is not None
        output=command(lane,['forget',*ids],timeout=kwargs.get('timeout',90))
        if lane=='binlog':raise TimeoutError('Synthetic lost result AFTER actual native forget')
        return output
w=LocalWorker();catalog=backup_catalog.ArchiveCatalog(w)
for row in original['snapshots']:
    payload=root/'spool'/(row['lane']+'-payload')
    if payload.exists():shutil.rmtree(payload)
    payload.mkdir(mode=0o700)
    manifest={**copy.deepcopy(original['manifests'][row['id']]),'format':1,'generation':GEN,'kind':row['kind'],'code_sha':'f'*40,'stage_app_sha':'f'*40,'captured_at':row['time']}
    (payload/'content.txt').write_text('synthetic bytes '+row['id'])
    if row['lane']=='binlog':
        (payload/'logs').mkdir(mode=0o700);descriptors=[]
        for item in manifest['logs']:
            data,_=build();(payload/'logs'/item['file']).write_bytes(data)
            descriptors.append({'file':item['file'],'size':len(data),'sha256':hashlib.sha256(data).hexdigest()})
        manifest.update(logs=descriptors,active_file='suhoput2-binlog.%06d'%(manifest['last_log']+1))
        # Binlog archive payload contains exactly its authenticated log files.
        (payload/'content.txt').unlink()
    manifest['files']=[]
    for path in sorted(payload.rglob('*')):
        if path.is_file():
            path.chmod(0o600);manifest['files'].append({'path':path.relative_to(payload).as_posix(),'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    raw=json.dumps(manifest,sort_keys=True,separators=(',',':')).encode();(payload/'manifest.json').write_bytes(raw);(payload/'manifest.json').chmod(0o600)
    output=command(row['lane'],['backup',str(payload),'--json','--time',row['snapshot_time'].replace('T',' ').removesuffix('Z'),
        '--tag','task047','--tag','generation:'+GEN,'--tag','token:'+row['token'],'--tag','manifest-sha:'+hashlib.sha256(raw).hexdigest()])
    summaries=[json.loads(line) for line in output.splitlines() if json.loads(line).get('message_type')=='summary'];sid=summaries[0]['snapshot_id'];mapping[row['id']]=sid
    metadata=json.loads(command(row['lane'],['cat','snapshot',sid]));target=root/'cache'/('verified-'+sid)
    command(row['lane'],['restore',sid,'--target',str(target),'--verify'])
    for path in [target,*target.rglob('*')]:path.chmod(0o700 if path.is_dir() else 0o600)
    restored=target/str(payload).lstrip('/')
    catalog.admit(row['lane'],sid,metadata,raw,restored)
    known[sid]={'id':sid,'token':row['token'],'manifest_sha256':hashlib.sha256(raw).hexdigest(),'lane':row['lane']}
for lane in repos:
    runtime.atomic_json(root/'receipts'/lane/'state.json',{'generation':GEN,'confirmed':[{k:r[k] for k in ('id','token','manifest_sha256')} for r in known.values() if r['lane']==lane]})
cohort,_=retention_cohort.CohortStore(w).capture();planned=guards.utc(cohort['cohort']['planned_at']);plan=retention.bounded_plan(cohort,retention.inventory_plan(cohort,planned));plan['planned_at']=planned.isoformat()
_,_,proofs=shifted(fixture(split=True))
for name,entry in proofs.items():
    doc=entry['document'];doc.update(repositories=repoids,inventory_sha256=plan['inventory_sha256'],cohort=cohort['cohort'],started_at=NOW.isoformat(),completed_at=dt.datetime.now(dt.timezone.utc).isoformat())
    if name=='history':doc['observed_until']=plan['planned_at']
    if name=='audit':doc.update(checked_repositories=repoids,readback_snapshots={r['id']:r['manifest_sha256'] for r in cohort['snapshots']},verified_binlogs=plan['logs'])
    if name in ('anchor','tip'):
        doc['base_id']=mapping[doc['base_id']];doc['full_id']=mapping[doc['full_id']]
        doc['base_manifest_sha256']=known[doc['base_id']]['manifest_sha256'];doc['full_manifest_sha256']=known[doc['full_id']]['manifest_sha256']
        doc['stop']={'file':plan['chain_last_file'],'position':plan['chain_last_position']}
        doc['verified_binlogs']=retention.replay_range(cohort['manifests'][doc['base_id']]['coordinates'],doc['stop'],plan['logs'])
    retention_native.publish_evidence(w,name,doc,cohort,NOW.isoformat())
loaded=retention_native.load_evidence(w,cohort);assert set(loaded)==retention_apply.EVIDENCE_TYPES
attempt=root/'receipts/retention-applies'/cohort['cohort']['sha256']
native=retention_native.NativeApply.__new__(retention_native.NativeApply);native.w=w
receipt=native.run('apply');store=retention_native.IntentStore(attempt)
assert receipt['result']=='RECONCILE_REQUIRED' and set(receipt['forgotten_ids'])==set(plan['candidates']) and len(w.calls)==2
try:native.run('apply')
except guards.GuardError:pass
else:raise AssertionError('Ambiguous native apply repeated')
assert len(w.calls)==2
receipt=native.run('reconcile');assert receipt['result']=='RECONCILED' and receipt['present_candidate_ids']==[] and store.latest()==receipt and len(w.calls)==2
try:store.prepare(store.load())
except FileExistsError:pass
else:raise AssertionError('Immutable intent overwritten')
bad=root/'symlink';bad.symlink_to(attempt,target_is_directory=True)
try:retention_native.IntentStore(bad)
except guards.GuardError:pass
else:raise AssertionError('Symlink store accepted')
tombstones=retention_apply.retention_tombstones(store.load(),receipt);journals={}
for lane in repos:
    journal=runtime.UploadJournal(root/'receipts'/lane,GEN);journal.retire(store.load(),receipt,lane);journals[lane]=journal.state()
    assert journals[lane]['confirmed']==[{k:r[k] for k in ('id','token','manifest_sha256')} for r in known.values() if r['lane']==lane]
after=retention.native_inventory(w,dt.datetime.now(dt.timezone.utc),repoids,lambda:dt.datetime.now(dt.timezone.utc));retention.confirmed_inventory(after,journals,tombstones)
assert retention_native.verified_tombstones(w)==[r for lane in ('base','binlog') for r in journals[lane]['retention']]
suffix=retention.inventory_plan(after,dt.datetime.now(dt.timezone.utc));assert suffix['logs'][0]['file']=='suhoput2-binlog.000002'
assert len(catalog.entries())==3
for lane in repos:command(lane,['check','--read-data'])
tip=mapping['3'*64];command('base',['restore',tip,'--target',str(root/'restored'),'--verify'])
restored=root/'restored'/str(root/'spool/base-payload/content.txt').lstrip('/');assert restored.read_text()=='synthetic bytes '+'3'*64
print(json.dumps({'result':'PASS','environment':'fresh tmpfs/Linux root/network none/local restic0.19.1/format2',
 'snapshot_dates':'synthetic; NOT actual 30-day history','prerequisites':'six synthetic immutable cohort-bound documents',
 'native_all_file_admission':'PASS','durable_intent_exclusive_fsync':'PASS','lost_result_no_retry':'PASS','native_local_forget_calls':len(w.calls),
 'journal_tombstones':'PASS','protected_producer_loader_NativeApply':'PASS with synthetic prerequisites','catalog_checkpoint_after_journals':'PASS',
 'retained_suffix_first_log':suffix['logs'][0]['file'],'remaining_check_read_data':'PASS','remaining_native_restore_sha256':hashlib.sha256(restored.read_bytes()).hexdigest(),
 'live_s3_deletion':'not_run','s3_requests':0,'prune':False}))
