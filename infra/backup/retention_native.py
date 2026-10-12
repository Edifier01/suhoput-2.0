"""Root-owned native retention boundary. No proof flags, prune or retry.

Only fixed protected receipt paths are admitted. Each evidence document needs
a separately persisted origin binding its bytes, producer and installed code.
Missing producers/30-day observation/budget/owner evidence fail closed. Original
upload/chain journals stay append-only; tombstones describe exact absences.
"""
import argparse, copy, datetime as dt, hashlib, json, os, pathlib, uuid
import guards, runtime, retention_apply
from worker import private_path, protected_directory, sha

PRODUCERS={'audit':'retention.py','anchor':'restore.py','tip':'restore.py',
           'owner':'owner-full.php','budget':'budget.py','history':'runtime.py'}
RECEIPTS={'audit':'retention-audit.json','anchor':'restored-anchor.json','tip':'restored-tip.json',
          'owner':'owner-attestation.json','budget':'budget-projection.json','history':'history.json'}

def verify_origin(name,raw,document,origin,code_sha,inventory):
    guards.require(name in PRODUCERS and origin.get('format')==1 and
                   origin.get('evidence_type')==name and origin.get('producer')==PRODUCERS[name] and
                   origin.get('code_sha')==guards.hex_id(code_sha,40),'Untrusted receipt producer/version')
    guards.require(origin.get('file_sha256')==hashlib.sha256(raw).hexdigest() and
                   origin.get('document_sha256')==retention_apply.document_digest(document),'Receipt origin bytes differ')
    for key,value in (('generation',inventory['generation']),('repositories',inventory['repositories']),
                      ('inventory_sha256',__import__('retention').inventory_digest(inventory))):
        guards.require(origin.get(key)==value,'Receipt origin inventory differs')
    return True

def exclusive_json(path,value):
    path=pathlib.Path(path);protected_directory(path.parent)
    data=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()+b'\n'
    guards.require(len(data)<=64*1024*1024,'Durable JSON exceeds native readback bound; no intent created')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(fd,'wb') as output:output.write(data);output.flush();os.fsync(output.fileno())
    runtime.directory_sync(path.parent);private_path(path)
    guards.require(path.read_bytes()==data,'Exclusive durable write readback differs')

class IntentStore:
    def __init__(self,root):self.root=protected_directory(root);self.path=self.root/'intent.json'
    def load(self):
        return runtime.load_json(private_path(self.path)) if self.path.exists() or self.path.is_symlink() else None
    def prepare(self,value):exclusive_json(self.path,value)
    def receipt(self,value):
        intent=self.load();guards.require(intent and value['intent_sha256']==intent['intent_sha256'],'Receipt intent changed')
        name='receipt-'+uuid.uuid4().hex+'.json';path=self.root/name;exclusive_json(path,value)
        runtime.atomic_json(self.root/'latest.json',{'file':name,'sha256':sha(path)})
    def latest(self):
        pointer=runtime.load_json(private_path(self.root/'latest.json'));name=pointer['file']
        guards.require(isinstance(name,str) and name.startswith('receipt-') and name.endswith('.json'),'Invalid receipt pointer')
        guards.hex_id(name[8:-5],32);path=private_path(self.root/name)
        guards.require(sha(path)==pointer['sha256'],'Durable receipt hash differs');return runtime.load_json(path)

class ExactRunner:
    def __init__(self,worker,intent_reader):self.w=worker;self.intent_reader=intent_reader
    def __call__(self,lane,argv):
        guards.require(lane in ('base','binlog') and isinstance(argv,list) and len(argv)>3 and
                       argv[:3]==['--repo',self.w.c['repositories'][lane],'forget'],'Exact native forget only')
        ids=argv[3:];guards.require(ids==sorted(set(ids)),'Unordered or duplicate forget IDs')
        for sid in ids:guards.hex_id(sid,64)
        intent=self.intent_reader();guards.require(isinstance(intent,dict),'Durable intent required before effect')
        expected=sorted(r['id'] for r in intent['before_inventory']['snapshots']
                        if r['lane']==lane and r['id'] in intent['candidate_ids'])
        guards.require(ids==expected,'Native forget differs from exact frozen lane intent')
        return self.w.retention_forget(lane,ids)

def load_evidence(worker,inventory):
    result={};directory=protected_directory(worker.root/'receipts/retention-proofs')
    for name in sorted(retention_apply.EVIDENCE_TYPES):
        path=private_path(worker.root/'receipts'/RECEIPTS[name]);raw=path.read_bytes();document=runtime.load_json(path)
        origin=runtime.load_json(private_path(directory/(name+'.origin.json')))
        verify_origin(name,raw,document,origin,worker.c['code_sha'],inventory)
        guards.require(origin.get('producer_sha256')==sha(private_path(worker.bin/PRODUCERS[name])),
                       'Installed native producer differs')
        result[name]={'document':document,'sha256':retention_apply.document_digest(document)}
    return result

def publish_evidence(worker,name,document,inventory,started_at):
    """Native producers publish after controls; CLI accepts no proof flags.

    Root file protection is the trust boundary. A crash between document and
    origin writes makes the loader fail closed on the exact raw-byte digest.
    """
    import retention
    guards.require(name in PRODUCERS and document.get('result')=='PASS','Completed native producer required')
    guards.require(inventory['generation']==worker.c['generation'] and
                   all(m['source']==worker.source for m in inventory['manifests'].values()),'Producer source differs')
    completed=document['completed_at'];guards.require(guards.utc(started_at)<=guards.utc(completed),'Producer clock rollback')
    document={**document,'evidence_type':name,'code_sha':worker.c['code_sha'],'generation':inventory['generation'],
              'repositories':inventory['repositories'],'source':worker.source,'inventory_sha256':retention.inventory_digest(inventory),'started_at':started_at}
    directory=worker.root/'receipts/retention-proofs'
    if not directory.exists():directory.mkdir(mode=0o700);runtime.directory_sync(directory.parent)
    protected_directory(directory)
    path=worker.root/'receipts'/RECEIPTS[name];runtime.atomic_json(path,document);raw=private_path(path).read_bytes()
    origin={'format':1,'evidence_type':name,'producer':PRODUCERS[name],'producer_sha256':sha(private_path(worker.bin/PRODUCERS[name])),
            'code_sha':worker.c['code_sha'],'generation':inventory['generation'],'repositories':inventory['repositories'],
            'inventory_sha256':document['inventory_sha256'],'document_sha256':retention_apply.document_digest(document),'file_sha256':hashlib.sha256(raw).hexdigest()}
    runtime.atomic_json(directory/(name+'.origin.json'),origin)
    verify_origin(name,raw,runtime.load_json(path),runtime.load_json(private_path(directory/(name+'.origin.json'))),worker.c['code_sha'],inventory)
    return document

def verified_tombstones(worker):
    """Re-derive every journal absence from immutable root intent/receipt bytes."""
    directory=worker.root/'receipts/retention-applies'
    journals={lane:runtime.UploadJournal(worker.root/'receipts'/lane,worker.c['generation']).state() for lane in ('base','binlog')}
    recorded=[row for journal in journals.values() for row in journal.get('retention',[])]
    if not directory.exists():
        guards.require(not recorded,'Retirement store missing');return []
    protected_directory(directory);derived={}
    for path in sorted(directory.iterdir()):
        guards.hex_id(path.name,64);store=IntentStore(path);intent=store.load()
        guards.require(intent and intent['generation']==worker.c['generation'] and
                       intent['repository_paths']==worker.c['repositories'],'Foreign retirement store')
        if not (path/'latest.json').exists():continue
        # Journals can bind an earlier immutable observation after a later
        # read-only reconciliation. Revalidate those exact receipt bytes.
        for receipt_path in sorted(path.glob('receipt-*.json')):
            receipt=runtime.load_json(private_path(receipt_path))
            if receipt['result'] not in ('APPLIED','RECONCILED'):continue
            for row in retention_apply.retention_tombstones(intent,receipt):
                matching=[r for r in recorded if r['id']==row['id'] and r['receipt_sha256']==row['receipt_sha256']]
                if matching:
                    sid=row['id'];guards.require(sid not in derived or derived[sid]==row,'Conflicting proven retirement');derived[sid]=row
    # A crash can leave only one lane committed. Absences are accepted only
    # after explicit reconciliation completes both journal writes.
    guards.require(len(recorded)==len({r['id'] for r in recorded}) and
                   all(derived.get(r['id'])==r for r in recorded),'Journal retirement provenance differs')
    # Missing commitment is caught by NativeApply before effects. Reader may
    # accept exactly committed journal rows without accepting unknown absences.
    return recorded

def retained_chain(chain,tombstones):
    result=copy.deepcopy(chain);retired={r['id']:r for r in tombstones if r['lane']=='binlog'}
    rows=chain['snapshots'];ids={r['id'] for r in rows}
    guards.require(set(retired)<=ids,'Unknown retired chain snapshot')
    removed=set();kept=[];first_kept=False
    for row in rows:
        if row['id'] in retired:
            guards.require(not first_kept and row['manifest_sha256']==retired[row['id']]['manifest_sha256'],'Only exact binlog prefix may be retired')
            removed.update(range(row['first_log'],row['last_log']+1))
        else:first_kept=True;kept.append(row)
    result['snapshots']=kept;result['logs']=[r for r in chain['logs'] if guards.log_number(r['file']) not in removed]
    guards.retained_logs(result['logs']);return result

class NativeApply:
    def __init__(self,config):
        from worker import Worker
        self.w=Worker(config)
    def run(self,mode):
        import retention
        w=self.w;w.gate();directory=w.root/'receipts/retention-applies'
        if not directory.exists():directory.mkdir(mode=0o700);runtime.directory_sync(directory.parent)
        protected_directory(directory)
        with runtime.lane_lock(w.root/'receipts/retention-apply.lock'), \
             runtime.lane_lock(w.root/'receipts/base/lane.lock'),runtime.lane_lock(w.root/'receipts/binlog/lane.lock'):
            for lane in ('base','binlog'):guards.require(not (w.root/'receipts'/lane/'pending.json').exists(),'Unknown pending upload; preserve')
            ids={lane:runtime.load_json(private_path(w.root/'receipts'/('init-'+lane+'.json')))['repository_id'] for lane in ('base','binlog')}
            read=lambda:retention.native_inventory(w,dt.datetime.now(dt.timezone.utc),ids)
            unfinished=[]
            for path in directory.iterdir():
                guards.hex_id(path.name,64);old=IntentStore(path)
                guards.require(old.load() is not None,'Incomplete prior apply directory; investigate')
                receipt=old.latest() if (path/'latest.json').exists() else None
                finished=receipt is not None and (receipt['result'] in ('APPLIED','NOOP') or (receipt['result']=='RECONCILED' and receipt['present_candidate_ids']==[]))
                if not finished or not (path/'journals-committed.json').exists():unfinished.append(old)
            if unfinished:
                guards.require(mode=='reconcile' and len(unfinished)==1,'Prior ambiguous apply requires read-only reconciliation')
                store=unfinished[0];ex=retention_apply.Executor(read,ExactRunner(w,store.load),store,store.receipt,w.c['repositories'],clock=lambda:dt.datetime.now(dt.timezone.utc))
                receipt=ex.reconcile(dt.datetime.now(dt.timezone.utc))
            else:
                guards.require(mode=='apply','No unfinished intent to reconcile')
                inventory=read();journals={lane:runtime.UploadJournal(w.root/'receipts'/lane,w.c['generation']).state() for lane in ('base','binlog')}
                retention.confirmed_inventory(inventory,journals,verified_tombstones(w))
                at=dt.datetime.now(dt.timezone.utc);plan=retention.bounded_plan(inventory,retention.inventory_plan(inventory,at));plan['planned_at']=at.isoformat()
                evidence=load_evidence(w,inventory) if plan['candidates'] else {}
                if evidence:
                    planned=guards.utc(evidence['history']['document']['observed_until'])
                    plan=retention.bounded_plan(inventory,retention.inventory_plan(inventory,planned));plan['planned_at']=planned.isoformat()
                plan['proof_sha256']={key:value['sha256'] for key,value in evidence.items()}
                if plan['candidates']:retention_apply.validate_apply(inventory,plan,evidence,at)
                key=retention.inventory_digest(inventory);path=directory/key
                guards.require(not path.exists() and not path.is_symlink(),'Existing inventory attempt; preserve, no retry')
                path.mkdir(mode=0o700);runtime.directory_sync(directory);store=IntentStore(path)
                ex=retention_apply.Executor(read,ExactRunner(w,store.load),store,store.receipt,w.c['repositories'],clock=lambda:dt.datetime.now(dt.timezone.utc))
                receipt=ex.apply(inventory,plan,evidence,at)
            if receipt['result'] in ('APPLIED','RECONCILED'):
                intent=store.load()
                for lane in ('base','binlog'):runtime.UploadJournal(w.root/'receipts'/lane,w.c['generation']).retire(intent,receipt,lane)
                # Reconciled present candidates remain quarantined: never retry.
                runtime.atomic_json(store.root/'journals-committed.json',{'intent_sha256':intent['intent_sha256'],'receipt_sha256':retention_apply.document_digest(receipt)})
            elif receipt['result']=='NOOP':runtime.atomic_json(store.root/'journals-committed.json',{'no_deletion':True})
            return receipt

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True);parser.add_argument('mode',choices=('apply','reconcile'));args=parser.parse_args()
    try:result=NativeApply(args.config).run(args.mode);print(json.dumps(result,sort_keys=True));return 0 if result['result'] in ('APPLIED','NOOP','RECONCILED') else 1
    except Exception as error:print(json.dumps({'result':'BLOCK','error_type':type(error).__name__,'delete_retry':False}));return 1
if __name__=='__main__':raise SystemExit(main())
