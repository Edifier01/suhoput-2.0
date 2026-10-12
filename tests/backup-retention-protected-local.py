"""Native exact-ID/store/journal rehearsal on fresh Linux tmpfs repositories.

Snapshot dates and the six prerequisite documents are explicitly synthetic.
This proves local mechanics, never live eligibility, actual 30 days or S3 cost.
"""
import copy, datetime as dt, hashlib, json, os, pathlib, subprocess, sys, shutil
sys.path[:0]=['/source/infra/backup','/source/tests']
import guards, retention, retention_apply, retention_native, runtime
from backup_retention_apply_test import fixture, GEN, NOW as FIXTURE_NOW
os.umask(0o077)
root=pathlib.Path('/control/protected-retention');root.mkdir(mode=0o700)
binary=pathlib.Path('/binary/restic')
assert hashlib.sha256(binary.read_bytes()).hexdigest()=='20d4142678d0d95ec11a4759def1b73fd9190abc9ca19e4b62d067c0b387e639'
password=root/'password';password.write_text('synthetic-temporary-password-not-a-live-key\n');password.chmod(0o600)
env={'PATH':'/usr/bin:/bin','HOME':str(root),'TMPDIR':str(root)}
repos={lane:str(root/('repo-'+lane)) for lane in ('base','binlog')}
def command(lane,args):
    result=subprocess.run([str(binary),'--password-file',str(password),'--repo',repos[lane],*args],
                           capture_output=True,env=env,timeout=90)
    if result.returncode:raise guards.GuardError('Native local command failed: '+result.stderr.decode(errors='replace'))
    return result.stdout
for lane in repos:command(lane,['init','--repository-version','2'])
NOW=dt.datetime.now(dt.timezone.utc)
def shifted(value):
    if isinstance(value,dict):return {key:shifted(item) for key,item in value.items()}
    if isinstance(value,list):return [shifted(item) for item in value]
    if isinstance(value,tuple):return tuple(shifted(item) for item in value)
    if isinstance(value,str) and value.startswith('2026-') and 'T' in value and value.endswith('Z'):
        return (guards.utc(value)+(NOW-FIXTURE_NOW)).isoformat().replace('+00:00','Z')
    return value
original,_,_=shifted(fixture(split=True));mapping={};manifests={};real_rows=[]
for row in original['snapshots']:
    payload=root/'payload';payload.mkdir(mode=0o700,exist_ok=True)
    manifest={**original['manifests'][row['id']],'generation':GEN,'kind':row['kind'],'captured_at':row['time']}
    raw=json.dumps(manifest,sort_keys=True,separators=(',',':')).encode();(payload/'manifest.json').write_bytes(raw)
    (payload/'content.txt').write_text('synthetic bytes '+row['id'])
    output=command(row['lane'],['backup',str(payload),'--json','--time',row['snapshot_time'].replace('T',' ').removesuffix('Z'),
                               '--tag','task047','--tag','generation:'+GEN,'--tag','token:'+row['token'],
                               '--tag','manifest-sha:'+hashlib.sha256(raw).hexdigest()])
    summaries=[json.loads(line) for line in output.splitlines() if json.loads(line).get('message_type')=='summary']
    sid=summaries[0]['snapshot_id'];mapping[row['id']]=sid;manifests[sid]=manifest
    real_rows.append({**row,'id':sid,'manifest_sha256':hashlib.sha256(raw).hexdigest()})
repoids={lane:json.loads(command(lane,['cat','config']))['id'] for lane in repos}
known={r['id']:r for r in real_rows}
def read_inventory():
    rows=[];authenticated={}
    for lane in repos:
        for listed in json.loads(command(lane,['snapshots','--json'])):
            sid=listed['id'];metadata=json.loads(command(lane,['cat','snapshot',sid]));row=known[sid]
            assert metadata['paths']==[str(root/'payload')] and guards.utc(metadata['time'])==guards.utc(row['snapshot_time'])
            raw=command(lane,['dump',sid,str(root/'payload/manifest.json')])
            assert hashlib.sha256(raw).hexdigest()==row['manifest_sha256']
            assert 'manifest-sha:'+row['manifest_sha256'] in metadata['tags']
            rows.append(row);authenticated[sid]=json.loads(raw)
    return {'generation':GEN,'repositories':repoids,'snapshots':rows,'manifests':authenticated}
inventory=read_inventory();plan=retention.inventory_plan(inventory,NOW);plan['planned_at']=NOW.isoformat()
# Hash-bind the explicit synthetic proof documents to real local snapshot IDs.
_,_,proofs=shifted(fixture(split=True))
for name,entry in proofs.items():
    doc=entry['document'];doc['repositories']=repoids;doc['inventory_sha256']=plan['inventory_sha256'];doc['started_at']=NOW.isoformat();doc['completed_at']=NOW.isoformat()
    if name=='history':doc['observed_until']=plan['planned_at']
    if name=='audit':doc['checked_repositories']=repoids;doc['readback_snapshots']={r['id']:r['manifest_sha256'] for r in real_rows}
    if name in ('anchor','tip'):
        doc['base_id']=mapping[doc['base_id']];doc['full_id']=mapping[doc['full_id']]
        doc['base_manifest_sha256']=known[doc['base_id']]['manifest_sha256'];doc['full_manifest_sha256']=known[doc['full_id']]['manifest_sha256']
    entry['sha256']=retention_apply.document_digest(doc)
plan['proof_sha256']={name:entry['sha256'] for name,entry in proofs.items()}
receipts=root/'receipts';receipts.mkdir(mode=0o700);public=root/'bin';public.mkdir(mode=0o700)
for path in pathlib.Path('/source/infra/backup').glob('*'):
    if path.suffix in ('.py','.php'):shutil.copyfile(path,public/path.name);(public/path.name).chmod(0o600)
for lane in repos:
    journal=runtime.UploadJournal(receipts/lane,GEN)
    runtime.atomic_json(journal.root/'state.json',{'generation':GEN,'confirmed':[{k:r[k] for k in ('id','token','manifest_sha256')} for r in inventory['snapshots'] if r['lane']==lane]})
    runtime.atomic_json(receipts/('init-'+lane+'.json'),{'repository_id':repoids[lane]})
attempt=receipts/'retention-applies'/plan['inventory_sha256']
store=None
class LocalWorker:
    c={'repositories':repos,'generation':GEN,'code_sha':'f'*40}
    def __init__(self):self.calls=[]
    root=root;bin=public;source=inventory['manifests'][inventory['snapshots'][0]['id']]['source']
    def gate(self):pass  # Source/disk/NTP in this local scenario are synthetic.
    def retention_forget(self,lane,ids):
        self.calls.append((lane,ids));assert retention_native.IntentStore(attempt).load() is not None
        output=command(lane,['forget',*ids])
        # Both lanes remove their exact snapshots; the second loses its result.
        if lane=='binlog':raise TimeoutError('Synthetic lost native result')
        return output
w=LocalWorker()
for name,entry in proofs.items():retention_native.publish_evidence(w,name,entry['document'],inventory,NOW.isoformat())
loaded=retention_native.load_evidence(w,inventory);assert set(loaded)==retention_apply.EVIDENCE_TYPES
native=retention_native.NativeApply.__new__(retention_native.NativeApply);native.w=w
retention.native_inventory=lambda *args:read_inventory()  # Real native local manifest reader, no fake IDs.
receipt=native.run('apply');store=retention_native.IntentStore(attempt)
assert receipt['result']=='RECONCILE_REQUIRED'
assert set(receipt['forgotten_ids'])==set(plan['candidates']) and len(w.calls)==2
try:native.run('apply')
except guards.GuardError:pass
else:raise AssertionError('Ambiguous apply repeated')
assert len(w.calls)==2
receipt=native.run('reconcile');assert receipt['result']=='RECONCILED' and receipt['present_candidate_ids']==[]
assert store.latest()==receipt and len(w.calls)==2
try:store.prepare(store.load())
except FileExistsError:pass
else:raise AssertionError('Immutable intent overwritten')
bad=root/'symlink';bad.symlink_to(attempt,target_is_directory=True)
try:retention_native.IntentStore(bad)
except guards.GuardError:pass
else:raise AssertionError('Symlink store accepted')
tombstones=retention_apply.retention_tombstones(store.load(),receipt)
journals={}
for lane in repos:
    journal=runtime.UploadJournal(receipts/lane,GEN)
    confirmations=[{k:r[k] for k in ('id','token','manifest_sha256')} for r in inventory['snapshots'] if r['lane']==lane]
    journal.retire(store.load(),receipt,lane)
    journals[lane]=journal.state();assert journals[lane]['confirmed']==confirmations
after=read_inventory();retention.confirmed_inventory(after,journals,tombstones)
assert retention_native.verified_tombstones(w)==[r for lane in ('base','binlog') for r in journals[lane]['retention']]
suffix=retention.inventory_plan(after,NOW);assert suffix['logs'][0]['file']=='suhoput2-binlog.000002'
for lane in repos:command(lane,['check','--read-data'])
tip=mapping['3'*64];command('base',['restore',tip,'--target',str(root/'restored'),'--verify'])
restored=root/'restored'/str(root/'payload/content.txt').lstrip('/')
assert restored.read_text()=='synthetic bytes '+'3'*64
print(json.dumps({'result':'PASS','environment':'fresh tmpfs/Linux root/network none/local restic0.19.1/format2',
                  'snapshot_dates':'explicit synthetic fixtures; NOT real 30-day history','prerequisites':'six synthetic hash-bound documents',
                  'durable_intent_exclusive_fsync':'PASS','lost_result_no_retry':'PASS','native_local_forget_calls':len(w.calls),
                  'journal_tombstones':'PASS','protected_producer_loader_NativeApply':'PASS with synthetic prerequisites','retained_suffix_first_log':suffix['logs'][0]['file'],
                  'remaining_check_read_data':'PASS','remaining_native_restore_sha256':hashlib.sha256(restored.read_bytes()).hexdigest(),
                  'live_s3_deletion':'not_run','s3_requests':0,'prune':False}))
