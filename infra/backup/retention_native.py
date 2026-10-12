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
    if 'cohort' in inventory:
        guards.require(origin.get('cohort')==inventory['cohort'] and document.get('cohort')==inventory['cohort'],
                       'Receipt origin frozen cohort differs')
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

class NewIntentStore(IntentStore):
    """Publish the new attempt directory only after final native admission."""
    def __init__(self,root):
        self.root=pathlib.Path(root);self.path=self.root/'intent.json'
        protected_directory(self.root.parent)
        guards.require(not self.root.exists() and not self.root.is_symlink(),'Retention attempt already exists')
    def load(self):
        if not self.root.exists():return None
        protected_directory(self.root);return super().load()
    def prepare(self,value):
        self.root.mkdir(mode=0o700);runtime.directory_sync(self.root.parent)
        super().prepare(value)

class ExactRunner:
    def __init__(self,worker,intent_reader,deadline=None):self.w=worker;self.intent_reader=intent_reader;self.deadline=deadline
    def __call__(self,lane,argv):
        guards.require(lane in ('base','binlog') and isinstance(argv,list) and len(argv)>3 and
                       argv[:3]==['--repo',self.w.c['repositories'][lane],'forget'],'Exact native forget only')
        ids=argv[3:];guards.require(ids==sorted(set(ids)),'Unordered or duplicate forget IDs')
        for sid in ids:guards.hex_id(sid,64)
        intent=self.intent_reader();guards.require(isinstance(intent,dict),'Durable intent required before effect')
        expected=sorted(r['id'] for r in intent['before_inventory']['snapshots']
                        if r['lane']==lane and r['id'] in intent['candidate_ids'])
        guards.require(ids==expected,'Native forget differs from exact frozen lane intent')
        if self.deadline is None:return self.w.retention_forget(lane,ids)
        import time
        remaining=self.deadline()-time.monotonic();guards.require(remaining>0,'Native effect critical deadline exceeded')
        return self.w.retention_forget(lane,ids,timeout=remaining)

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
    import retention_cohort,backup_catalog
    guards.require(name in PRODUCERS and document.get('result')=='PASS','Completed native producer required')
    with backup_catalog.ArchiveCatalog(worker).open_reader() as reader:
        frozen=retention_cohort.CohortStore(worker).load(reader)
    guards.require(inventory.get('cohort')==frozen['cohort'] and retention.inventory_digest(inventory)==retention.inventory_digest(frozen),
                   'Producer did not consume the protected frozen cohort')
    for key,value in (('source',worker.source),('inventory_sha256',retention.inventory_digest(frozen)),('cohort',frozen['cohort'])):
        guards.require(key not in document or document[key]==value,'Producer receipt belongs to another source/inventory/cohort')
    guards.require(inventory['generation']==worker.c['generation'] and
                   all(m['source']==worker.source for m in inventory['manifests'].values()),'Producer source differs')
    completed=document['completed_at'];guards.require(guards.utc(started_at)<=guards.utc(completed),'Producer clock rollback')
    document={**document,'evidence_type':name,'code_sha':worker.c['code_sha'],'generation':inventory['generation'],
              'repositories':inventory['repositories'],'source':worker.source,'inventory_sha256':retention.inventory_digest(inventory),
              'cohort':inventory['cohort'],'started_at':started_at}
    directory=worker.root/'receipts/retention-proofs'
    if not directory.exists():directory.mkdir(mode=0o700);runtime.directory_sync(directory.parent)
    protected_directory(directory)
    path=worker.root/'receipts'/RECEIPTS[name];runtime.atomic_json(path,document);raw=private_path(path).read_bytes()
    origin={'format':1,'evidence_type':name,'producer':PRODUCERS[name],'producer_sha256':sha(private_path(worker.bin/PRODUCERS[name])),
            'code_sha':worker.c['code_sha'],'generation':inventory['generation'],'repositories':inventory['repositories'],
            'inventory_sha256':document['inventory_sha256'],'cohort':inventory['cohort'],'source':worker.source,
            'document_sha256':retention_apply.document_digest(document),'file_sha256':hashlib.sha256(raw).hexdigest()}
    runtime.atomic_json(directory/(name+'.origin.json'),origin)
    verify_origin(name,raw,runtime.load_json(path),runtime.load_json(private_path(directory/(name+'.origin.json'))),worker.c['code_sha'],inventory)
    return document

def publish_owner(worker):
    """Fresh native binding of the already completed historical owner run.

    Human confirmation, external code/times, kit/password storage and receipt
    hashes retain their original meaning. This does not claim a new human run.
    """
    import base64,backup_catalog,retention_cohort,retention,binlog
    w=worker;started=retention_cohort.clock()
    historical=runtime.load_json(private_path(w.root/'receipts/owner-attestation.json'))
    receipt_sha=guards.hex_id(historical['restore_receipt_sha256'],64)
    path=private_path(w.root/'receipts'/('owner-source-'+receipt_sha+'.json'));source=runtime.load_json(path)
    try:raw=base64.b64decode(source['native_receipt_raw_base64'],validate=True)
    except (ValueError,TypeError) as error:raise guards.GuardError('Historical native owner bytes invalid') from error
    native=retention.decode(raw)
    guards.require(hashlib.sha256(raw).hexdigest()==receipt_sha==source['native_receipt_sha256'] and native==source['native_receipt'],
                   'Historical native owner receipt hash differs')
    human=source['human_confirmation'];guards.require(isinstance(human,str) and human.strip() and
                     hashlib.sha256(human.encode()).hexdigest()==source['human_confirmation_sha256']==historical['human_confirmation_sha256'],
                     'Historical human confirmation differs')
    guards.require(native['result']=='PASS' and native['source_reads']==native['s3_writes']==0 and native['before_counts']==[0]*4 and
                   native['after_counts']==[1]*4 and native['sql_import']==native['native_replay']=='PASS' and native['generation']==w.c['generation'],
                   'Historical native owner execution absent')
    preparation=native['preparation'];guards.require(preparation['source']==w.source and preparation['stage_app_sha']==w.c['stage_app_sha'],
                                                    'Historical owner source/application differs')
    guard=native['row_event_guard'];logs=native['verified_binlogs'];stop=native['closedchain_tip']
    guards.require(guard['result']=='PASS' and guard['files']==logs and guard['stop']==stop and
                   all(native['media']['coverage'][key] is True for key in ('all_tables_innodb','read_only_snapshot','schema_metadata_stable')),
                   'Historical native owner ROW/media proof absent')
    guards.require(guards.utc(native['started_at'])<=guards.utc(native['completed_at'])<=started,'Historical owner clock differs')
    guards.hex_id(native['code_sha'],40)
    with backup_catalog.ArchiveCatalog(w).open_reader() as reader:
        inventory=retention_cohort.CohortStore(w).load(reader);indexed={r['id']:r for r in inventory['snapshots']}
        retired={row['id']:row for row in verified_tombstones(w)}
        for name in ('base','full'):
            sid=preparation[name+'_id'];row=indexed.get(sid) or retired.get(sid)
            guards.require(row is not None and row['manifest_sha256']==preparation[name+'_manifest_sha256'] and row['lane']=='base',
                           'Historical owner archive changed or lacks protected retirement provenance')
        for original in preparation.get('binlog_snapshots',[]):
            row=indexed.get(original['id']) or retired.get(original['id'])
            guards.require(row is not None and row['lane']=='binlog' and row['manifest_sha256']==original['manifest_sha256'],
                           'Historical owner binlog changed or lacks protected retirement provenance')
        current=retention.inventory_plan(inventory,guards.utc(inventory['cohort']['planned_at']))
        base_row=max((row for row in inventory['snapshots'] if row['lane']=='base'),key=lambda row:(guards.utc(row['time']),row['id']))
        base_id=base_row['id'];base=inventory['manifests'][base_id];full_id=base['full_id'] if base_row['kind']=='hourly' else base_id
        full_row=indexed[full_id];full=inventory['manifests'][full_id]
        guards.require(all(base[key]==full[key]==preparation[key] for key in ('source','stage_app_sha','application_sha256','configuration_sha256')),
                       'Current owner archive compatibility differs; independent compatibility proof required')
        stop={'file':current['chain_last_file'],'position':current['chain_last_position']}
        selected=retention.replay_range(base['coordinates'],stop,current['logs'])
        owners={item['file']:row['id'] for row in inventory['snapshots'] if row['lane']=='binlog' for item in inventory['manifests'][row['id']]['logs']}
        for item in selected:
            data=reader.binlog_bytes(owners[item['file']],item['file'])
            start=base['coordinates'] if item['file']==base['coordinates']['file'] else {'file':item['file'],'position':4}
            end=stop if item['file']==stop['file'] else {'file':item['file'],'position':item['size']}
            binlog.validate_chain({item['file']:data},[item],start,end)
        current_binding={'base_id':base_id,'full_id':full_id,'base_manifest_sha256':base_row['manifest_sha256'],
                         'full_manifest_sha256':full_row['manifest_sha256'],'coordinates':base['coordinates'],
                         'verified_binlogs':selected,'stop':stop,'operation':'compatible-current-cohort-after-historical-owner-run',
                         'historical_archives':'unchanged-live-or-proven-retired','SQL_writes':0}
    for lane in ('base','binlog'):w.restic(lane,['--repo',w.c['repositories'][lane],'check','--read-data'])
    fields=('machine_id','source_machine_id','medium_id','origin','restore_method','executed_by','bundle_storage_separate','password_storage_separate')
    proof={key:historical[key] for key in fields}
    guards.require(historical['recovery_bundle_sha256']==source['bundle_inventory_sha256'],'Historical kit identity differs')
    proof.update(result='PASS',recovery_bundle_sha256=source['bundle_inventory_sha256'],restore_receipt_sha256=receipt_sha,
                 human_confirmation_sha256=source['human_confirmation_sha256'],source_input_sha256=sha(path),
                 external_native_code_sha=native['code_sha'],external_native_started_at=native['started_at'],external_native_completed_at=native['completed_at'],
                 native_cohort_revalidation=current_binding,
                 completed_at=retention_cohort.clock().isoformat())
    return publish_evidence(w,'owner',proof,inventory,started.isoformat())

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
        import retention,retention_cohort,backup_catalog,time
        w=self.w;w.gate();directory=w.root/'receipts/retention-applies'
        if not directory.exists():directory.mkdir(mode=0o700);runtime.directory_sync(directory.parent)
        protected_directory(directory);scan_started=time.monotonic()
        timing={key:0 for key in ('scan_seconds','critical_seconds','effect_seconds','journal_seconds','checkpoint_seconds')}
        with runtime.lane_lock(w.root/'receipts/retention-apply.lock'):
            catalog=backup_catalog.ArchiveCatalog(w)
            # A interrupted own checkpoint is never silently reset. Explicit
            # reconciliation below is performed after this coordination lock.
            if catalog.checkpoint_pending.exists():
                guards.require(mode=='reconcile','Interrupted checkpoint requires explicit read-only native reconciliation')
                checkpoint_only=True;receipt=None
            else:
                checkpoint_only=False
                with catalog.open_reader() as reader:
                    ids=retention_cohort.repository_ids(w)
                    current_reader=[reader]
                    critical_deadline=[None]
                    def read():
                        current_reader[0]=current_reader[0].refresh()
                        return retention.native_inventory(w,retention_cohort.clock(),ids,retention_cohort.clock,reader=current_reader[0],deadline=critical_deadline[0])
                    unfinished=[]
                    for path in directory.iterdir():
                        guards.hex_id(path.name,64);old=IntentStore(path)
                        guards.require(old.load() is not None,'Incomplete prior apply directory; investigate')
                        previous=old.latest() if (path/'latest.json').exists() else None
                        finished=previous is not None and (previous['result'] in ('APPLIED','NOOP') or
                                 (previous['result']=='RECONCILED' and previous['present_candidate_ids']==[]))
                        if not finished or not (path/'journals-committed.json').exists():unfinished.append(old)
                    if unfinished:
                        guards.require(mode=='reconcile' and len(unfinished)==1,'Prior ambiguous apply requires read-only reconciliation')
                        store=unfinished[0]
                        # Read-only reconciliation may be expensive; only its
                        # exact protected journal publication needs lane locks.
                        ex=retention_apply.Executor(read,ExactRunner(w,store.load),store,store.receipt,w.c['repositories'],clock=retention_cohort.clock)
                        receipt=ex.reconcile(retention_cohort.clock())
                        timing['scan_seconds']=time.monotonic()-scan_started;critical=time.monotonic()
                        with retention_cohort.upload_section(w):
                            critical_deadline[0]=time.monotonic()+retention_cohort.MAX_CRITICAL_SECONDS
                            try:
                                retention_cohort.ready(w)
                                # Arrivals can occur between the unlocked scan
                                # and this publication. Derive a fresh immutable
                                # observation while upload jobs are excluded.
                                receipt=ex.reconcile(retention_cohort.clock())
                                journal_started=time.monotonic();self._journals(store,receipt)
                                timing['journal_seconds']+=time.monotonic()-journal_started
                            finally:critical_deadline[0]=None
                        timing['critical_seconds']=time.monotonic()-critical
                    else:
                        guards.require(mode=='apply','No unfinished intent to reconcile')
                        inventory=retention_cohort.CohortStore(w).load(reader)
                        at=retention_cohort.clock();planned=guards.utc(inventory['cohort']['planned_at'])
                        plan=retention.bounded_plan(inventory,retention.inventory_plan(inventory,planned));plan['planned_at']=planned.isoformat()
                        evidence=load_evidence(w,inventory) if plan['candidates'] else {}
                        plan['proof_sha256']={key:value['sha256'] for key,value in evidence.items()}
                        if plan['candidates']:retention_apply.validate_apply(inventory,plan,evidence,at)
                        key=inventory['cohort']['sha256'];path=directory/key
                        guards.require(not path.exists() and not path.is_symlink(),'Existing cohort attempt; preserve, no retry')
                        store=NewIntentStore(path)
                        from contextlib import contextmanager
                        @contextmanager
                        def section():
                            timing['scan_seconds']=time.monotonic()-scan_started;critical=time.monotonic()
                            with retention_cohort.upload_section(w):
                                critical_deadline[0]=time.monotonic()+retention_cohort.MAX_CRITICAL_SECONDS
                                retention_cohort.ready(w)
                                try:yield
                                finally:timing['critical_seconds']=time.monotonic()-critical;critical_deadline[0]=None
                        def write(value):
                            value['phase_seconds']=dict(timing)
                            # Includes exact effect/readback elapsed time so far.
                            value['phase_seconds']['critical_seconds']=time.monotonic()-critical_started[0]
                            journal_started=time.monotonic();store.receipt(value);self._journals(store,value)
                            timing['journal_seconds']+=time.monotonic()-journal_started
                        critical_started=[0]
                        @contextmanager
                        def measured_section():
                            with section():critical_started[0]=time.monotonic();yield
                        runner=ExactRunner(w,store.load,deadline=lambda:critical_deadline[0])
                        def effect(lane,argv):
                            effect_started=time.monotonic()
                            try:return runner(lane,argv)
                            finally:timing['effect_seconds']+=time.monotonic()-effect_started
                        ex=retention_apply.Executor(read,effect,store,write,w.c['repositories'],clock=retention_cohort.clock,
                             effect_section=measured_section,pre_effect=lambda current:retention_cohort.confirmed(w,current))
                        receipt=ex.apply(inventory,plan,evidence,at);receipt=store.latest()
        # Native exact effects and both protected journals precede checkpoint.
        # checkpoint() owns its own upload locks, so no caller locks remain.
        if checkpoint_only:
            result=catalog.checkpoint(reconcile=True)
            return {'result':'RECONCILED','operation':'native-catalog-checkpoint','remote_delete_calls':0,**result,'phase_seconds':timing}
        def save_timing():
            # This sidecar records actual completed phase durations without
            # rewriting the immutable receipt hash acknowledged by journals.
            runtime.atomic_json(store.root/'phase-timing.json',{'operation':'native-retention-phase-timing',
                                'receipt_sha256':retention_apply.document_digest(receipt),'phase_seconds':dict(timing)})
        save_timing()
        if receipt['result'] in ('APPLIED','RECONCILED') and receipt.get('present_candidate_ids')==[]:
            checkpoint_started=time.monotonic()
            try:catalog.checkpoint()
            finally:timing['checkpoint_seconds']=time.monotonic()-checkpoint_started;save_timing()
        return receipt
    def _journals(self,store,receipt):
        w=self.w
        if receipt['result'] in ('APPLIED','RECONCILED'):
            intent=store.load()
            for lane in ('base','binlog'):runtime.UploadJournal(w.root/'receipts'/lane,w.c['generation']).retire(intent,receipt,lane)
            runtime.atomic_json(store.root/'journals-committed.json',{'intent_sha256':intent['intent_sha256'],'receipt_sha256':retention_apply.document_digest(receipt)})
        elif receipt['result']=='NOOP':runtime.atomic_json(store.root/'journals-committed.json',{'no_deletion':True})


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True);parser.add_argument('mode',choices=('apply','reconcile'));args=parser.parse_args()
    try:result=NativeApply(args.config).run(args.mode);print(json.dumps(result,sort_keys=True));return 0 if result['result'] in ('APPLIED','NOOP','RECONCILED') else 1
    except Exception as error:print(json.dumps({'result':'BLOCK','error_type':type(error).__name__,'delete_retry':False}));return 1
if __name__=='__main__':raise SystemExit(main())
