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

def producer_for(name,document):
    guards.require(name in PRODUCERS,'Unknown evidence producer')
    if document.get('operation')=='native-retention-restore-v1':
        guards.require(name in ('anchor','tip') and document.get('profile')==name,'Operational restore profile differs')
        return 'retention_restore.py'
    return PRODUCERS[name]

def verify_origin(name,raw,document,origin,code_sha,inventory):
    guards.require(name in PRODUCERS and origin.get('format')==1 and
                   origin.get('evidence_type')==name and origin.get('producer')==producer_for(name,document) and
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
    def phase_documents(self):
        intent=self.load()
        guards.require(intent.get('phase_protocol') in (None,'bounded-lanes-v1',retention_apply.BATCH_PHASE_PROTOCOL),'Unknown phase protocol')
        if intent.get('phase_protocol')==retention_apply.BATCH_PHASE_PROTOCOL:return self._batch_phase_documents(intent)
        baseline={row['id']:row for row in intent['before_inventory']['snapshots']};known=dict(baseline);result={};attempted=set()
        expected_lanes=[lane for lane in ('base','binlog') if any(row['lane']==lane and row['id'] in intent['candidate_ids'] for row in baseline.values())] or ['no-op']
        guards.require(all(path.name in ('phase-base.json','phase-binlog.json','phase-no-op.json','phase-timing.json') for path in self.root.glob('phase-*.json')),'Unknown phase authorization file')
        for lane in ('base','binlog','no-op'):
            path=self.root/('phase-'+lane+'.json')
            if not path.exists():continue
            doc=runtime.load_json(private_path(path));body={key:value for key,value in doc.items() if key!='phase_sha256'}
            guards.require(len(result)<len(expected_lanes) and lane==expected_lanes[len(result)] and doc['operation']=='native-retention-phase-authorization' and
                           doc['phase_sha256']==retention_apply.document_digest(body) and doc['intent_sha256']==intent['intent_sha256'] and
                           doc['lane']==lane and doc['previous']=={key:value['phase_sha256'] for key,value in result.items()},'Phase authorization changed')
            expected=sorted(row['id'] for row in baseline.values() if row['lane']==lane and row['id'] in intent['candidate_ids'])
            guards.require(doc['candidate_ids']==expected and doc['prior_absence_ids']==sorted(set(doc['prior_absence_ids'])) and
                           set(doc['prior_absence_ids'])==attempted,'Unknown or incomplete prior phase effect/absence')
            for row in doc['arrival_rows']:
                guards.require(row['id'] not in baseline and (row['id'] not in known or known[row['id']]==row),'Phase arrival identity changed');known[row['id']]=row
            snapshot_rows=[row for sid,row in known.items() if sid not in doc['prior_absence_ids']]
            view={'generation':intent['generation'],'repositories':intent['repositories'],'snapshots':snapshot_rows}
            guards.require(__import__('retention').inventory_digest(view)==doc['native_inventory_sha256'],'Phase current inventory cannot be reconstructed')
            authorized=guards.utc(doc['authorized_at'])
            guards.require(authorized>=guards.utc(intent['prepared_at']) and all(authorized>=guards.utc(row['authorized_at']) for row in result.values()),'Phase authorization clock rollback')
            attempted.update(expected);result[lane]=doc
        return result
    def _batch_phase_documents(self,intent):
        batches=retention_apply.intent_batches(intent);baseline={row['id']:row for row in intent['before_inventory']['snapshots']};known=dict(baseline);result={};attempted=set()
        allowed={'phase-'+format(batch['index'],'04d')+'.json' for batch in batches}|{'phase-timing.json'}
        guards.require(all(path.name in allowed for path in self.root.glob('phase-*.json')),'Unknown batch authorization file')
        missing=False
        for batch in batches:
            key=format(batch['index'],'04d');path=self.root/('phase-'+key+'.json')
            if not path.exists():missing=True;continue
            guards.require(not missing,'Batch authorization gap')
            doc=runtime.load_json(private_path(path));body={key:value for key,value in doc.items() if key!='phase_sha256'}
            guards.require(type(doc.get('index')) is int and doc['operation']=='native-retention-batch-authorization' and doc['phase_sha256']==retention_apply.document_digest(body) and
                           doc['intent_sha256']==intent['intent_sha256'] and all(doc[field]==batch[field] for field in ('index','lane','candidate_ids')) and
                           doc['previous']=={key:value['phase_sha256'] for key,value in result.items()} and doc['prior_absence_ids']==sorted(attempted),'Batch authorization identity/prefix differs')
            for row in doc['arrival_rows']:
                guards.require(row['id'] not in baseline and (row['id'] not in known or known[row['id']]==row),'Batch arrival identity changed');known[row['id']]=row
            view={'generation':intent['generation'],'repositories':intent['repositories'],'snapshots':[row for sid,row in known.items() if sid not in attempted]}
            guards.require(__import__('retention').inventory_digest(view)==doc['native_inventory_sha256'],'Batch current inventory cannot be reconstructed')
            authorized=guards.utc(doc['authorized_at'])
            guards.require(authorized>=guards.utc(intent['prepared_at']) and all(authorized>=guards.utc(previous['authorized_at']) for previous in result.values()),'Batch authorization clock rollback')
            attempted.update(batch['candidate_ids']);result[key]=doc
        return result
    def phase_refs(self):
        return {lane:{'file':'phase-'+lane+'.json','sha256':sha(private_path(self.root/('phase-'+lane+'.json'))),'document_sha256':doc['phase_sha256']}
                for lane,doc in self.phase_documents().items()}
    def attempted_ids(self):return sorted({sid for doc in self.phase_documents().values() for sid in doc['candidate_ids']})
    def phase_document(self,lane,current,prior_absences,at,*,index=None):
        intent=getattr(self,'staged_intent',None) or self.load();baseline={row['id']:row for row in intent['before_inventory']['snapshots']}
        previous=self.phase_documents() if self.root.exists() else {}
        batch=None
        if intent.get('phase_protocol')==retention_apply.BATCH_PHASE_PROTOCOL:
            batches=retention_apply.intent_batches(intent)
            guards.require(type(index) is int and index==len(previous) and index<len(batches),'Existing or out-of-order batch never resumes')
            batch=batches[index];guards.require(batch['lane']==lane,'Batch lane differs')
        else:guards.require(index is None and lane not in previous and lane in ('base','binlog','no-op'),'Existing phase never resumes')
        selected=set(intent['candidate_ids'])
        body={'operation':'native-retention-phase-authorization','intent_sha256':intent['intent_sha256'],'lane':lane,
              'candidate_ids':batch['candidate_ids'] if batch is not None else sorted(row['id'] for row in baseline.values() if row['lane']==lane and row['id'] in selected),
              'authorized_at':at.isoformat(),'native_inventory_sha256':__import__('retention').inventory_digest(current),
              'prior_absence_ids':list(prior_absences),'arrival_rows':[row for row in current['snapshots'] if row['id'] not in baseline],
              'previous':{key:value['phase_sha256'] for key,value in previous.items()}}
        if batch is not None:body.update(operation='native-retention-batch-authorization',index=index,candidate_ids=batch['candidate_ids'])
        if callable(getattr(self,'catalog_head',None)):body['catalog_head']=copy.deepcopy(self.catalog_head())
        guards.require(len(json.dumps(body,sort_keys=True,separators=(',',':')).encode())<=1024*1024,'Phase witness too large; capture a new outside-lock cohort')
        self.ensure_work()
        return {**body,'phase_sha256':retention_apply.document_digest(body)}
    def ensure_work(self):
        if callable(getattr(self,'work_deadline',None)):
            import time
            deadline=self.work_deadline()
            if deadline is not None:guards.require(time.monotonic()<deadline,'Reserved phase durability/cleanup budget reached')
    def phase(self,value):
        self.ensure_work();key=format(value['index'],'04d') if value['operation']=='native-retention-batch-authorization' else value['lane']
        exclusive_json(self.root/('phase-'+key+'.json'),value)

class StagedFiles:
    """Owned fsynced payloads prepared without holding upload/job locks."""
    def __init__(self,root):
        parent=root/'receipts/retention-staging';parent.mkdir(mode=0o700,exist_ok=True);protected_directory(parent)
        self.root=parent/uuid.uuid4().hex;self.root.mkdir(mode=0o700);self.files=[]
    def json(self,name,value):
        path=self.root/name;exclusive_json(path,value);self.files.append(path);return path
    def promote(self,path,target):
        guards.require(path in self.files and path.exists(),'Unknown staged publication')
        os.replace(private_path(path),target);runtime.directory_sync(pathlib.Path(target).parent);private_path(target)
    def cleanup(self):
        # Only this object's fixed owned paths are removed, after all four
        # job/upload locks release. Unknown content preserves the orphan.
        for path in self.files:
            if path.exists():private_path(path).unlink()
        for parent in sorted({path.parent for path in self.files if path.parent!=self.root},key=lambda path:len(path.parts),reverse=True):parent.rmdir()
        self.root.rmdir();runtime.directory_sync(self.root.parent)

class NewIntentStore(IntentStore):
    """Publish the new attempt directory only after final native admission."""
    def __init__(self,root):
        self.root=pathlib.Path(root);self.path=self.root/'intent.json'
        protected_directory(self.root.parent)
        guards.require(not self.root.exists() and not self.root.is_symlink(),'Retention attempt already exists')
    def load(self):
        if not self.root.exists():return None
        protected_directory(self.root);return super().load()
    def stage(self,value):
        self.staged_intent=value;self.staging=StagedFiles(self.root.parents[2])
        self.staged_path=self.staging.json('intent.json',value);self.staged_sha=sha(self.staged_path)
    def prepare(self,value):
        self.ensure_work()
        if hasattr(self,'staged_path'):
            guards.require(value==self.staged_intent and sha(self.staged_path)==self.staged_sha,'Staged intent bytes changed')
        self.root.mkdir(mode=0o700);runtime.directory_sync(self.root.parent)
        if hasattr(self,'staged_path'):self.staging.promote(self.staged_path,self.path)
        else:super().prepare(value)
    def phase_document(self,*args,**kwargs):
        value=super().phase_document(*args,**kwargs)
        if getattr(self,'prepared_effect_readback',False):
            phases=self.phase_documents() if self.root.exists() else {}
            key=format(value['index'],'04d');phases[key]=value
            files={'intent.json':self.staged_sha}
            for name,document in phases.items():
                filename='phase-'+name+'.json'
                files[filename]=hashlib.sha256((json.dumps(document,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()).hexdigest() if name==key else sha(private_path(self.root/filename))
            self.prepared_authority=(self.staged_intent,phases,files)
        return value
    def _effect_authority(self):
        """Read back every bound byte without reconstructing historic rows."""
        import backup_catalog
        self.ensure_work();intent,phases,expected=self.prepared_authority
        deadline=self.work_deadline() if callable(getattr(self,'work_deadline',None)) else None
        names={path.name for path in self.root.glob('phase-*.json') if path.name!='phase-timing.json'}|{'intent.json'}
        guards.require(names==set(expected),'Prepared phase authority path set changed')
        guards.require(all(backup_catalog.file_digest(private_path(self.root/name),deadline)==digest for name,digest in expected.items()),'Prepared phase authority bytes changed')
        guards.require(retention_apply.document_digest({key:value for key,value in intent.items() if key!='intent_sha256'})==intent['intent_sha256'],
                       'Prepared intent memory changed')
        guards.require(all(retention_apply.document_digest({key:value for key,value in doc.items() if key!='phase_sha256'})==doc['phase_sha256'] for doc in phases.values()),
                       'Prepared phase memory changed')
        return intent,phases
    def effect_intent(self):return self._effect_authority()[0]
    def effect_phases(self):return self._effect_authority()[1]

class ExactRunner:
    def __init__(self,worker,intent_reader,deadline=None,*,phase_reader=None):self.w=worker;self.intent_reader=intent_reader;self.deadline=deadline;self.phase_reader=phase_reader
    def __call__(self,lane,argv):
        guards.require(lane in ('base','binlog') and isinstance(argv,list) and len(argv)>3 and
                       argv[:3]==['--repo',self.w.c['repositories'][lane],'forget'],'Exact native forget only')
        ids=argv[3:];guards.require(ids==sorted(set(ids)) and len(ids)<=retention_apply.MAX_FORGET_IDS,'Unordered, duplicate or oversized forget IDs')
        for sid in ids:guards.hex_id(sid,64)
        intent=self.intent_reader();guards.require(isinstance(intent,dict),'Durable intent required before effect')
        if intent.get('phase_protocol')==retention_apply.BATCH_PHASE_PROTOCOL:
            batches=retention_apply.intent_batches(intent);guards.require(callable(self.phase_reader),'Durable batch authorization required')
            phases=self.phase_reader();guards.require(phases,'Missing batch authorization');phase=list(phases.values())[-1]
            expected=batches[phase['index']];guards.require(phase['lane']==lane and ids==phase['candidate_ids']==expected['candidate_ids'],'Native forget differs from exact authorized batch')
        else:
            selected=set(intent['candidate_ids']);expected=sorted(r['id'] for r in intent['before_inventory']['snapshots'] if r['lane']==lane and r['id'] in selected)
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
        guards.require(producer_for(name,document)==PRODUCERS[name],'Legacy readiness requires legacy restore proof')
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
    producer=producer_for(name,document)
    guards.require(producer==PRODUCERS[name] or worker.c.get('retention_readiness_policy')=='native-v2',
                   'Operational restore requires explicit native-v2 policy')
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
    origin={'format':1,'evidence_type':name,'producer':producer,'producer_sha256':sha(private_path(worker.bin/producer)),
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
    current_inventory={}
    with backup_catalog.ArchiveCatalog(w).open_reader() as reader:
        inventory=retention_cohort.CohortStore(w).load(reader,current_out=current_inventory);indexed={r['id']:r for r in inventory['snapshots']}
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
    integrity_report=None
    if w.c.get('retention_readiness_policy','legacy-v1')=='native-v2':
        import integrity
        integrity_report=integrity.ensure(w,inventory,current_inventory=current_inventory)
    else:
        for lane in ('base','binlog'):w.restic(lane,['--repo',w.c['repositories'][lane],'check','--read-data'])
    fields=('machine_id','source_machine_id','medium_id','origin','restore_method','executed_by','bundle_storage_separate','password_storage_separate')
    proof={key:historical[key] for key in fields}
    guards.require(historical['recovery_bundle_sha256']==source['bundle_inventory_sha256'],'Historical kit identity differs')
    proof.update(result='PASS',recovery_bundle_sha256=source['bundle_inventory_sha256'],restore_receipt_sha256=receipt_sha,
                 human_confirmation_sha256=source['human_confirmation_sha256'],source_input_sha256=sha(path),
                 external_native_code_sha=native['code_sha'],external_native_started_at=native['started_at'],external_native_completed_at=native['completed_at'],
                 native_cohort_revalidation=current_binding,
                 completed_at=retention_cohort.clock().isoformat())
    if integrity_report is not None:proof.update(integrity_check_mode=integrity.MODE,full_remote_integrity=integrity_report)
    return publish_evidence(w,'owner',proof,inventory,started.isoformat())

def _receipt_documents(store):
    result={}
    for path in sorted(store.root.glob('receipt-*.json')):
        raw=private_path(path).read_bytes();doc=runtime.load_json(path)
        guards.require(raw==json.dumps(doc,sort_keys=True,separators=(',',':'),allow_nan=False).encode()+b'\n','Immutable receipt bytes differ')
        key=retention_apply.document_digest(doc)
        result.setdefault(key,{'document':doc,'file':path.name,'sha256':hashlib.sha256(raw).hexdigest()})
    return result

def _recorded_retirements(worker,intent):
    journals={lane:runtime.UploadJournal(worker.root/'receipts'/lane,worker.c['generation']).state() for lane in ('base','binlog')}
    return {lane:[row for row in journal.get('retention',[]) if row['intent_sha256']==intent['intent_sha256']] for lane,journal in journals.items()}

def _verify_recorded(intent,recorded,documents):
    for lane,values in recorded.items():guards.require(all(row['lane']==lane for row in values),'Retirement recorded in the wrong lane journal')
    rows=[row for values in recorded.values() for row in values];derived={};proofs={}
    for row in rows:
        key=row['receipt_sha256'];item=documents.get(key);guards.require(item is not None,'Original retirement receipt missing')
        if key not in proofs:proofs[key]={r['id']:r for r in retention_apply.retention_tombstones(intent,item['document'])}
        proof=proofs[key]
        guards.require(proof.get(row['id'])==row,'Journal retirement provenance differs')
        guards.require(row['id'] not in derived,'Duplicate retirement identity');derived[row['id']]=row
    return rows

def verify_journal_commit(worker,store,*,receipt=None):
    """One complete-commit verifier for closed readers and catalog checkpoints."""
    intent=store.load();body={key:value for key,value in intent.items() if key!='intent_sha256'}
    guards.require(retention_apply.document_digest(body)==intent['intent_sha256'] and intent['generation']==worker.c['generation'] and
                   intent['repository_paths']==worker.c['repositories'] and intent['source']==worker.source,'Foreign or changed retirement intent')
    marker=runtime.load_json(private_path(store.root/'journals-committed.json'));documents=_receipt_documents(store)
    guards.require(set(marker) in ({'no_deletion'},{'intent_sha256','receipt_sha256'},
                   {'format','operation','intent_sha256','receipt_sha256','receipt_ref','retirement_sha256','receipt_refs'}),'Malformed global journal commitment')
    recorded=_recorded_retirements(worker,intent)
    if marker=={'no_deletion':True}:
        doc=store.latest();guards.require(doc['result']=='NOOP' and intent['candidate_ids']==[] and not any(recorded.values()),'No-op commitment differs')
        return {'receipt':doc,'rows':[]}
    guards.require(marker['intent_sha256']==intent['intent_sha256'],'Journal commit intent differs')
    item=documents.get(marker['receipt_sha256']);guards.require(item is not None,'Committed immutable receipt missing');doc=item['document']
    if receipt is not None:guards.require(doc==receipt,'Checkpoint latest receipt is not committed')
    rows=_verify_recorded(intent,recorded,documents)
    guards.require(doc['result'] in ('APPLIED','RECONCILED') and sorted(row['id'] for row in rows)==doc['forgotten_ids'],
                   'Both journal retirement sets do not equal committed native absences')
    # Revalidate the current committed observation even if original rows refer
    # to older immutable observations after later read-only reconciliation.
    retention_apply.retention_tombstones(intent,doc)
    if intent.get('phase_protocol') in ('bounded-lanes-v1',retention_apply.BATCH_PHASE_PROTOCOL):
        guards.require(doc.get('phase_witnesses')==store.phase_refs() and set(doc['forgotten_ids'])<=set(store.attempted_ids()),'Committed phase authorization differs')
    if set(marker)!={'intent_sha256','receipt_sha256'}:
        guards.require(marker['format']==2 and marker['operation']=='native-retention-journals-commit','Unknown journal commitment')
        guards.require(marker['retirement_sha256']=={lane:retention_apply.document_digest(values) for lane,values in recorded.items()},'Journal commit hashes differ')
        keys={row['receipt_sha256'] for row in rows}|{marker['receipt_sha256']}
        guards.require(set(marker['receipt_refs'])==keys and marker['receipt_ref']==marker['receipt_refs'][marker['receipt_sha256']],
                       'Original immutable receipt references differ')
        for key,ref in marker['receipt_refs'].items():
            name=ref['file'];guards.require(pathlib.PurePath(name).name==name and name.startswith('receipt-') and name.endswith('.json'),'Foreign immutable receipt path')
            path=private_path(store.root/name)
            guards.require(sha(path)==ref['sha256'] and retention_apply.document_digest(runtime.load_json(path))==key,'Immutable receipt raw binding differs')
    return {'receipt':doc,'rows':rows}

def _retirements(worker,active_store=None):
    directory=worker.root/'receipts/retention-applies'
    journals={lane:runtime.UploadJournal(worker.root/'receipts'/lane,worker.c['generation']).state() for lane in ('base','binlog')}
    recorded=[row for journal in journals.values() for row in journal.get('retention',[])];derived={}
    guards.require(len(recorded)==len({row['id'] for row in recorded}),'Duplicate retired identity')
    if not directory.exists():guards.require(not recorded,'Retirement store missing');return [],[]
    protected_directory(directory);active=[]
    for path in sorted(directory.iterdir()):
        guards.hex_id(path.name,64);store=IntentStore(path);intent=store.load()
        guards.require(intent and intent['generation']==worker.c['generation'] and intent['repository_paths']==worker.c['repositories'] and
                       intent['source']==worker.source and retention_apply.document_digest({k:v for k,v in intent.items() if k!='intent_sha256'})==intent['intent_sha256'],
                       'Foreign or changed retirement store')
        own=_recorded_retirements(worker,intent)
        if active_store is not None and path==active_store.root:
            # Explicit read-only recovery may follow a crash while replacing
            # an older complete publication. These exact rows are internal
            # to this intent, never exposed as globally committed absences.
            rows=_verify_recorded(intent,own,_receipt_documents(store));active=rows;continue
        elif (path/'journals-committed.json').exists():rows=verify_journal_commit(worker,store)['rows']
        else:guards.require(not any(own.values()),'Incomplete journal publication; read-only reconciliation required');rows=[]
        for row in rows:guards.require(row['id'] not in derived,'Conflicting retired identity');derived[row['id']]=row
    guards.require(all(derived.get(row['id'])==row or row in active for row in recorded),'Unknown journal retirement intent')
    return list(derived.values()),active

def verified_tombstones(worker):
    """Only complete global publication authorizes ordinary reader absences."""
    rows,_=_retirements(worker);return rows

def _confirmed_active(worker,current,intent,absent,store,*,_tail=None):
    """Pending absence is internal to this exact protected live attempt only."""
    committed,partial=_retirements(worker,store)
    original={row['id']:row for row in intent['before_inventory']['snapshots']};absent=set(absent)
    guards.require(absent<=set(intent['candidate_ids']) and absent<=set(original),'Unknown active absence')
    guards.require(all(row['id'] in absent for row in partial),'Partial journal does not match actual active absence')
    journals={lane:runtime.UploadJournal(worker.root/'receipts'/lane,worker.c['generation']).state() for lane in ('base','binlog')}
    expected=current if _tail is None else _tail(current,journals,{row['id'] for row in committed}|absent)
    for lane in ('base','binlog'):
        state=journals[lane]
        confirmed={row['id']:(row['token'],row['manifest_sha256']) for row in state['confirmed']}
        guards.require(len(confirmed)==len(state['confirmed']),'Duplicate active confirmation')
        retired={row['id']:(row['token'],row['manifest_sha256']) for row in committed if row['lane']==lane}
        active={sid:(original[sid]['token'],original[sid]['manifest_sha256']) for sid in absent if original[sid]['lane']==lane}
        guards.require(not set(retired)&set(active) and all(confirmed.get(sid)==value for sid,value in {**retired,**active}.items()),'Active original confirmation differs')
        actual={row['id']:(row['token'],row['manifest_sha256']) for row in expected['snapshots'] if row['lane']==lane}
        guards.require({sid:value for sid,value in confirmed.items() if sid not in retired and sid not in active}==actual,'Unknown active confirmation/native arrival')

class StagedPublication:
    """Complete receipt/journals prepared outside lanes; final marker is last."""
    def __init__(self,worker,store,timing=None):self.w=worker;self.store=store;self.prepared=None;self.timing=timing
    def stage(self,value):
        import time
        started=time.monotonic()
        try:
            if self.prepared is not None:
                self.prepared['staging'].cleanup();self.prepared=None
            self._stage(value)
        finally:
            if self.timing is not None:self.timing['staging_seconds']+=time.monotonic()-started
    def _stage(self,value):
        w=self.w;store=self.store;store.ensure_work();intent=store.load();staging=StagedFiles(w.root)
        name='receipt-'+uuid.uuid4().hex+'.json';receipt_path=staging.json(name,value)
        documents=_receipt_documents(store);key=retention_apply.document_digest(value)
        documents[key]={'document':value,'file':name,'sha256':sha(receipt_path)}
        sources={};states={};row_hashes={};refs=set()
        for lane in ('base','binlog'):
            store.ensure_work()
            source=private_path(w.root/'receipts'/lane/'state.json');raw=source.read_bytes();sources[lane]=hashlib.sha256(raw).hexdigest()
            target=staging.root/lane;target.mkdir(mode=0o700);state_path=target/'state.json'
            with open(state_path,'xb') as output:output.write(raw);output.flush();os.fsync(output.fileno())
            os.chmod(state_path,0o600);staging.files.append(state_path)
            journal=runtime.UploadJournal(target,w.c['generation'])
            if value['result']!='NOOP':journal.retire(intent,value,lane)
            state=journal.state();own=[row for row in state.get('retention',[]) if row['intent_sha256']==intent['intent_sha256']]
            row_hashes[lane]=retention_apply.document_digest(own);refs.update(row['receipt_sha256'] for row in own)
            del state,own,raw
            store.ensure_work()
            guards.require(sha(source)==sources[lane],'Journal changed during outside-lock staging');states[lane]=state_path
        refs.add(key)
        marker={'no_deletion':True} if value['result']=='NOOP' else {
            'format':2,'operation':'native-retention-journals-commit','intent_sha256':intent['intent_sha256'],'receipt_sha256':key,
            'receipt_ref':{field:documents[key][field] for field in ('file','sha256')},'retirement_sha256':row_hashes,
            'receipt_refs':{ref:{field:documents[ref][field] for field in ('file','sha256')} for ref in refs}}
        latest=staging.json('latest.json',{'file':name,'sha256':sha(receipt_path)});commit=staging.json('journals-committed.json',marker)
        store.ensure_work()
        self.prepared={'value':value,'staging':staging,'name':name,'receipt':receipt_path,'states':states,'sources':sources,'latest':latest,'commit':commit}
    def __call__(self,value):
        if value['result']=='RECONCILE_REQUIRED':self.store.receipt(value);return
        prepared=self.prepared;guards.require(prepared is not None and prepared['value']==value,'Completed publication was not staged')
        for lane,digest in prepared['sources'].items():
            guards.require(sha(private_path(self.w.root/'receipts'/lane/'state.json'))==digest,'Final journal source changed; do not overwrite arrivals')
        self.store.ensure_work()
        import time
        started=time.monotonic()
        try:
            staging=prepared['staging'];staging.promote(prepared['receipt'],self.store.root/prepared['name'])
            for lane,path in prepared['states'].items():self.store.ensure_work();staging.promote(path,self.w.root/'receipts'/lane/'state.json')
            self.store.ensure_work()
            staging.promote(prepared['latest'],self.store.root/'latest.json')
            self.store.ensure_work()
            staging.promote(prepared['commit'],self.store.root/'journals-committed.json')
        finally:
            if self.timing is not None:self.timing['journal_seconds']+=time.monotonic()-started

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

def _phase_input_bytes(catalog,deadline=None):
    """Byte equality only; full authority validation precedes preparation.

    Include the complete path set, so a new, missing or renamed authorization
    cannot inherit a previous validation. This map never authorizes an effect
    by itself, and never replaces the final unfiltered native inventory.
    """
    import backup_catalog
    root=catalog.receipts
    paths=[root/lane/'state.json' for lane in ('base','binlog')]
    paths += [root/('init-'+lane+'.json') for lane in ('base','binlog')]+[catalog.head]
    directory=root/'retention-applies'
    if directory.exists():
        protected_directory(directory)
        for attempt in sorted(directory.iterdir()):
            guards.hex_id(attempt.name,64);protected_directory(attempt)
            paths.extend(path for path in sorted(attempt.iterdir()) if path.name!='phase-timing.json')
    return {path.relative_to(root).as_posix():backup_catalog.file_digest(private_path(path),deadline) for path in paths}

def _phase_journals(catalog,inputs):
    """Capture exactly the journal bytes named by the preparation seal."""
    result={}
    for lane in ('base','binlog'):
        key=lane+'/state.json';raw=private_path(catalog.receipts/key).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=inputs[key]:
            raise retention_apply.PhasePreparationChanged('Journal advanced during preparation seal')
        result[lane]=json.loads(raw,object_pairs_hook=runtime.no_duplicates)
    return result

def _journal_prefix_seal(state,count=None):
    rows=state['confirmed'];count=len(rows) if count is None else count
    guards.require(isinstance(rows,list) and len(rows)>=count,'Confirmation prefix shortened')
    stable={k:v for k,v in state.items() if k not in ('confirmed','last_success_at','last_confirmation_at')}
    return {'count':count,'prefix':retention_apply.document_digest(rows[:count]),
            'stable':retention_apply.document_digest(stable)}

def _prepared_append(catalog,before,after,prior,journals,current,reader):
    """Transfer only appends already authenticated by the prepared native view.

    The reader refresh checks the captured catalog chain prefix. Every other
    authority path and raw byte remains exact, and original confirmation rows
    retain all fields, including historical timestamps and retirement links.
    """
    mutable={'base/state.json','binlog/state.json',catalog.head.relative_to(catalog.receipts).as_posix()}
    if set(before)!=set(after) or any(before[k]!=after[k] for k in before if k not in mutable):return False
    indexed={row['id']:row for row in current['snapshots']};appended=0
    for lane in ('base','binlog'):
        old=prior[lane];new=journals[lane];count=old['count']
        guards.require(old==_journal_prefix_seal(new,count),'Prepared historical confirmation or retirement changed')
        fresh=new['confirmed'][count:];appended+=len(fresh)
        if not fresh:
            if before[lane+'/state.json']!=after[lane+'/state.json']:return False
            continue
        guards.require(len({row['id'] for row in new['confirmed']})==len(new['confirmed']),'Duplicate appended confirmation')
        for row in fresh:
            native=indexed.get(row['id'])
            if native is None:return False # Arrival after the native read needs a fresh outside audit.
            guards.require(native['lane']==lane and all(row[k]==native[k] for k in ('token','manifest_sha256')),
                           'Appended confirmation differs from prepared native identity')
            keys=set(row)
            guards.require(keys in ({'id','token','manifest_sha256'},{'id','token','manifest_sha256','captured_at','prepared_at','confirmed_at'}),
                           'Unknown appended confirmation fields')
            if 'captured_at' in row:
                guards.require(row['captured_at']==native['time'] and guards.utc(row['captured_at'])<=guards.utc(row['prepared_at'])<=guards.utc(row['confirmed_at']),
                               'Appended confirmation clock or capture differs')
        guards.require(new.get('last_success_at')==fresh[-1].get('captured_at') and new.get('last_confirmation_at')==fresh[-1].get('confirmed_at'),
                       'Appended journal watermark differs')
    head=hashlib.sha256((json.dumps(reader.head,sort_keys=True,separators=(',',':'))+'\n').encode()).hexdigest()
    return appended>0 and head==after[catalog.head.relative_to(catalog.receipts).as_posix()]


class NativeApply:
    def __init__(self,config):
        from worker import Worker
        self.w=Worker(config)
    def run(self,mode):
        import backup_catalog,time
        w=self.w;w.gate();directory=w.root/'receipts/retention-applies'
        if not directory.exists():directory.mkdir(mode=0o700);runtime.directory_sync(directory.parent)
        protected_directory(directory);scan_started=time.monotonic()
        timing={key:0 for key in ('scan_seconds','critical_seconds','critical_max_seconds','effect_seconds','journal_seconds','checkpoint_seconds','staging_seconds','staging_cleanup_seconds')}
        timing['critical_phases']=[]
        with runtime.lane_lock(w.root/'receipts/retention-apply.lock'):
            catalog=backup_catalog.ArchiveCatalog(w)
            # A interrupted own checkpoint is never silently reset. Explicit
            # reconciliation below is performed after this coordination lock.
            if catalog._checkpoint_incomplete():
                guards.require(mode=='reconcile','Interrupted checkpoint requires explicit read-only native reconciliation')
                checkpoint_only=True;receipt=None
            else:
                checkpoint_only=False
                receipt,attempt_path=self._attempt(catalog,directory,mode,timing,scan_started)
        # Native exact effects and both protected journals precede checkpoint.
        # checkpoint() owns its own upload locks, so no caller locks remain.
        if checkpoint_only:
            checkpoint_started=time.monotonic()
            try:result=catalog.checkpoint(reconcile=True)
            finally:
                timing['checkpoint_seconds']=time.monotonic()-checkpoint_started
                if hasattr(catalog,'last_checkpoint_timing'):timing['checkpoint_phase_seconds']=dict(catalog.last_checkpoint_timing)
            return {'result':'RECONCILED','operation':'native-catalog-checkpoint','remote_delete_calls':0,**result,'phase_seconds':timing}
        store=IntentStore(attempt_path)
        def save_timing():
            # This sidecar records actual completed phase durations without
            # rewriting the immutable receipt hash acknowledged by journals.
            runtime.atomic_json(store.root/'phase-timing.json',{'operation':'native-retention-phase-timing',
                                'receipt_sha256':retention_apply.document_digest(receipt),'intent_sha256':receipt['intent_sha256'],
                                'phase_witnesses':receipt.get('phase_witnesses',{}),'phase_seconds':dict(timing)})
        save_timing()
        if receipt['result'] in ('APPLIED','RECONCILED') and receipt.get('present_candidate_ids')==[]:
            checkpoint_started=time.monotonic()
            try:catalog.checkpoint()
            finally:
                timing['checkpoint_seconds']=time.monotonic()-checkpoint_started
                if hasattr(catalog,'last_checkpoint_timing'):timing['checkpoint_phase_seconds']=dict(catalog.last_checkpoint_timing)
                save_timing()
        return receipt
    def _attempt(self,catalog,directory,mode,timing,scan_started):
        """End the lifetime of all heavy attempt views before checkpoint starts."""
        import retention,retention_cohort,backup_catalog,time
        w=self.w
        with catalog.open_reader() as reader:
            ids=retention_cohort.repository_ids(w)
            current_reader=[reader]
            critical_deadline=[None]
            active_phase=[None]
            prepared_inputs=[None];phase_budget=[None];prepared_native={};prepared_current=[None];journal_prefix=[None];fixed_authorities=[None]
            # This closure-owned frame cannot be granted by a copied inventory
            # or a JSON field. The actual outside view remains untouched.
            native_frame=[None]
            ordinal=[0];outside_reads={}
            def charge_native_read():
                if w.c.get('retention_readiness_policy')!='native-v2':return
                used=outside_reads.get(ordinal[0],0)
                guards.require(used<4,'Four outside native observations exhausted for durable phase')
                outside_reads[ordinal[0]]=used+1
            def read():
                started=time.monotonic()
                try:
                    charge_native_read()
                    current_reader[0]=current_reader[0].refresh(deadline=critical_deadline[0])
                    prepared_native.clear()
                    result=retention.native_inventory(w,retention_cohort.clock(),ids,retention_cohort.clock,reader=current_reader[0],deadline=critical_deadline[0],reader_out=current_reader,native_views=prepared_native)
                    working=dict(result) if w.c.get('retention_readiness_policy')=='native-v2' else result
                    if w.c.get('retention_readiness_policy')=='native-v2':
                        sealed_reader=current_reader[0]
                        native_frame[0]={'owner':working,'actual':result,'digest':retention_cohort._observation_digest(result),
                            'reader':sealed_reader,'head':copy.deepcopy(sealed_reader.head),
                            'raw':retention.reader_raw_prefix_seal(sealed_reader,verify=True),
                            'records':retention.reader_projection_seal(sealed_reader),
                            'expected':working,'excluded':set()}
                    prepared_current[0]=working;return working
                finally:
                    if active_phase[0] is not None:active_phase[0]['native_inventory_seconds']+=time.monotonic()-started
            from contextlib import contextmanager
            @contextmanager
            def preparation():
                before=_phase_input_bytes(catalog)
                mutable={'base/state.json','binlog/state.json',catalog.head.relative_to(catalog.receipts).as_posix()}
                if fixed_authorities[0] is None:fixed_authorities[0]={key:value for key,value in before.items() if key not in mutable}
                guards.require(all(before.get(key)==value for key,value in fixed_authorities[0].items()),
                               'Original immutable preparation authority changed')
                if hasattr(store,'prepared_authority'):
                    # The final staged phase can legitimately be absent after a
                    # pre-effect retry; existing own intent/phase bytes can never
                    # be resealed as different valid documents on that retry.
                    prefix=store.root.relative_to(catalog.receipts).as_posix()+'/'
                    guards.require(all(before[prefix+name]==digest for name,digest in store.prepared_authority[2].items() if prefix+name in before),
                                   'Previously prepared immutable phase authority changed')
                    fixed_authorities[0].update({prefix+name:digest for name,digest in store.prepared_authority[2].items() if prefix+name in before})
                prior=_phase_journals(catalog,before)
                if journal_prefix[0] is None:journal_prefix[0]={lane:_journal_prefix_seal(state) for lane,state in prior.items()}
                for lane,state in prior.items():
                    guards.require(_journal_prefix_seal(state,journal_prefix[0][lane]['count'])==journal_prefix[0][lane],
                                   'Original confirmation or retirement prefix changed')
                prior={lane:_journal_prefix_seal(state) for lane,state in prior.items()}
                prepared_current[0]=None
                # Failed audits/bodies must propagate unchanged. Only a clean
                # preparation may transfer authenticated concurrent arrivals.
                # Unknown/malformed ordinal authorities are rejected here;
                # only equal raw bytes may transfer this complete audit.
                catalog._checkpoint_inputs()
                yield
                after=_phase_input_bytes(catalog)
                if before!=after:
                    journals=_phase_journals(catalog,after)
                    frame=native_frame[0]
                    if frame is not None and prepared_current[0] is frame['owner']:
                        current_reader[0]=current_reader[0].refresh()
                        intent=getattr(store,'staged_intent',None) or store.load()
                        frame['expected']=retention.authenticated_tail_inventory(w,frame['actual'],current_reader[0],journals,intent['candidate_ids'],frame['excluded'])
                    transferred=prepared_current[0] is not None and _prepared_append(catalog,before,after,prior,journals,frame['expected'] if frame else prepared_current[0],current_reader[0])
                    if not transferred:
                        raise retention_apply.PhasePreparationChanged('Read-only phase authority advanced')
                prepared_inputs[0]=after
                if native_frame[0] is not None:
                    native_frame[0]['journals']={lane:_journal_prefix_seal(state) for lane,state in _phase_journals(catalog,after).items()}
            def verify_prepared(expected):
                frame=native_frame[0];deadline=critical_deadline[0]
                guards.require(frame is not None and expected is frame['owner'] and expected is prepared_current[0],
                               'Prepared tail owner changed or copied')
                guards.require(expected['snapshots'] is frame['actual']['snapshots'] and expected['manifests'] is frame['actual']['manifests'] and
                               all(expected[key]==frame['actual'][key] for key in ('generation','repositories','observed_at')),
                               'Prepared outside projection changed')
                before=prepared_inputs[0];inputs=_phase_input_bytes(catalog,deadline)
                journals=_phase_journals(catalog,inputs)
                intent=getattr(store,'staged_intent',None) or store.load()
                current_reader[0]=current_reader[0].refresh(deadline=deadline)
                derived=retention.authenticated_tail_inventory(w,frame['actual'],current_reader[0],journals,intent['candidate_ids'],frame['excluded'],deadline=deadline)
                if inputs!=before and not _prepared_append(catalog,before,inputs,frame['journals'],journals,derived,current_reader[0]):
                    raise retention_apply.PhasePreparationChanged('Phase authority advanced before reservation')
                original_ids={row['id'] for row in frame['actual']['snapshots']}
                tail_seals={row['id']:(row,retention_apply.document_digest(row),retention_apply.document_digest(current_reader[0]._record(row['id'])))
                            for row in derived['snapshots'] if row['id'] not in original_ids}
                started=time.monotonic()
                try:closed,views=retention.verify_native_views(w,prepared_native,deadline,current=frame['actual'],derived=derived,reader=current_reader[0])
                finally:
                    if active_phase[0] is not None:active_phase[0]['native_inventory_seconds']+=time.monotonic()-started
                guards.require(retention.reader_raw_prefix_seal(current_reader[0],head=frame['head'],deadline=deadline)==frame['raw'] and
                               retention.reader_projection_seal(frame['reader'],deadline=deadline)==frame['records'] and
                               retention_cohort._observation_digest(frame['actual'])==frame['digest'],'Prepared old raw/body or projection authority changed')
                guards.require(all(retention_apply.document_digest(row)==row_seal and retention_apply.document_digest(current_reader[0]._record(sid))==record_seal
                                   for sid,(row,row_seal,record_seal) in tail_seals.items()),'Authenticated tail memory changed during final native observation')
                retention.verify_reader_tail(current_reader[0],frame['head'],tail_seals,deadline=deadline)
                guards.require(_phase_input_bytes(catalog,deadline)==inputs,'Phase authority changed inside reserved group')
                baseline={row['id'] for row in intent['before_inventory']['snapshots']}
                if hasattr(store,'prepared_authority'):
                    _,phases,files=store.prepared_authority;key=next(reversed(phases));filename='phase-'+key+'.json'
                    if not (store.root/filename).exists():
                        phase=phases[key]
                        guards.require(retention_apply.document_digest({k:v for k,v in phase.items() if k!='phase_sha256'})==phase['phase_sha256'],
                                       'Unpublished phase witness changed before closure')
                        pending_raw=(json.dumps(phase,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
                        guards.require(hashlib.sha256(pending_raw).hexdigest()==files[filename],
                                       'Unpublished phase memory differs from original staged seal')
                        phase.update(native_inventory_sha256=retention.inventory_digest(closed),authorized_at=closed['observed_at'],
                                     arrival_rows=[row for row in closed['snapshots'] if row['id'] not in baseline],catalog_head=copy.deepcopy(current_reader[0].head))
                        phase['phase_sha256']=retention_apply.document_digest({k:v for k,v in phase.items() if k!='phase_sha256'})
                        raw=(json.dumps(phase,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
                        guards.require(len(raw)<=1024**2,'Closed phase witness too large');files[filename]=hashlib.sha256(raw).hexdigest()
                if publication.prepared is not None:
                    value=publication.prepared['value'];current_sha=retention.inventory_digest(closed)
                    pending_raw=(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
                    guards.require(sha(private_path(publication.prepared['receipt']))==hashlib.sha256(pending_raw).hexdigest(),
                                   'Unpublished receipt memory differs from staged bytes')
                    if value['post_inventory_sha256']!=current_sha:
                        value.update(post_inventory_sha256=current_sha,completed_at=closed['observed_at'],
                                     protected_arrival_ids=sorted(set(value['protected_arrival_ids'])|{row['id'] for row in closed['snapshots'] if row['id'] not in baseline}))
                        publication.stage(value)
                expected.clear();expected.update(closed);prepared_native.clear();prepared_native.update(views)
                prepared_inputs[0]=inputs;store.ensure_work()
                guards.require(_phase_input_bytes(catalog,deadline)==inputs,'Phase authority changed during closure durability staging')
                if phase_budget[0] is not None:phase_budget[0]()
            def pre_phase(current,intent,absent):
                def tail(actual,journals,excluded):
                    frame=native_frame[0]
                    guards.require(frame is not None and actual is frame['owner'],'Prepared tail owner changed or copied')
                    current_reader[0]=current_reader[0].refresh()
                    frame['excluded']=excluded
                    frame['expected']=retention.authenticated_tail_inventory(w,frame['actual'],current_reader[0],journals,intent['candidate_ids'],excluded)
                    return frame['expected']
                _confirmed_active(w,current,intent,absent,store,**({'_tail':tail} if w.c.get('retention_readiness_policy')=='native-v2' else {}))
            @contextmanager
            def section(name):
                # Native work ends before the reserved durability and
                # termination tail. Timestamp precedes the first lock;
                # final measurement follows the last lock release.
                started=time.monotonic()
                phase={'name':name,'seconds':0,'native_inventory_seconds':0,'effect_seconds':0,'journal_seconds':0}
                effect_before=timing['effect_seconds'];journal_before=timing['journal_seconds'];active_phase[0]=phase;completed=False
                if not timing['critical_phases']:timing['scan_seconds']=started-scan_started
                try:
                    with retention_cohort.upload_section(w) as acquired:
                        if acquired is not None:started=acquired
                        critical_deadline[0]=started+retention_cohort.MAX_CRITICAL_SECONDS-10
                        retention_cohort.ready(w,deadline=critical_deadline[0]);yield;completed=True
                finally:
                    critical_deadline[0]=None;elapsed=time.monotonic()-started
                    active_phase[0]=None;phase.update(seconds=elapsed,effect_seconds=timing['effect_seconds']-effect_before,journal_seconds=timing['journal_seconds']-journal_before)
                    phase['readiness_validation_durability_cleanup_seconds']=max(0,elapsed-phase['native_inventory_seconds']-phase['effect_seconds']-phase['journal_seconds'])
                    timing['critical_seconds']+=elapsed;timing['critical_max_seconds']=max(timing['critical_max_seconds'],elapsed)
                    timing['critical_phases'].append(phase)
                    guards.require(elapsed<=retention_cohort.MAX_CRITICAL_SECONDS,'Actual continuous phase lock limit exceeded')
                    if completed and name!='publication' and hasattr(store,'prepared_authority'):
                        filename='phase-'+format(ordinal[0],'04d')+'.json';expected=store.prepared_authority[2].get(filename)
                        path=store.root/filename
                        if expected is not None and path.exists():
                            guards.require(sha(private_path(path))==expected,'Completed durable phase quota binding changed')
                            ordinal[0]+=1
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
                store.work_deadline=lambda:critical_deadline[0]
                publication=StagedPublication(w,store,timing)
                ex=retention_apply.Executor(read,ExactRunner(w,store.load),store,publication,w.c['repositories'],clock=retention_cohort.clock,
                     phase_section=section,pre_phase=pre_phase,
                     **({'phase_preparation':preparation,'phase_verify':verify_prepared} if w.c.get('retention_readiness_policy')=='native-v2' else {}))
                try:receipt=ex.reconcile(retention_cohort.clock())
                finally:
                    if publication.prepared is not None:
                        started=time.monotonic();publication.prepared['staging'].cleanup();timing['staging_cleanup_seconds']+=time.monotonic()-started
            else:
                guards.require(mode=='apply','No unfinished intent to reconcile')
                inventory=retention_cohort.CohortStore(w).load(reader)
                at=retention_cohort.clock();planned=guards.utc(inventory['cohort']['planned_at'])
                policy=w.c.get('retention_readiness_policy','legacy-v1')
                guards.require(policy in ('legacy-v1','native-v2'),'Unknown configured readiness policy')
                plan=retention.bounded_plan(inventory,retention.inventory_plan(inventory,planned),retention_apply.MAX_INTENT_CANDIDATES if policy=='native-v2' else retention_apply.MAX_CANDIDATES);plan['planned_at']=planned.isoformat()
                if policy=='native-v2':plan['batch_protocol']=retention_apply.DAILY_BATCH_PROTOCOL
                if policy=='native-v2':plan['readiness_policy']=retention_apply.NATIVE_V2_POLICY
                if plan['candidates'] and policy=='native-v2':
                    import readiness_v2
                    evidence=readiness_v2.load_evidence(w,inventory,at=at)
                else:evidence=load_evidence(w,inventory) if plan['candidates'] else {}
                plan['proof_sha256']={key:value['sha256'] for key,value in evidence.items()}
                if plan['candidates']:retention_apply.validate_apply(inventory,plan,evidence,at)
                key=inventory['cohort']['sha256'];path=directory/key
                guards.require(not path.exists() and not path.is_symlink(),'Existing cohort attempt; preserve, no retry')
                store=NewIntentStore(path)
                store.work_deadline=lambda:critical_deadline[0];store.catalog_head=lambda:current_reader[0].head
                publication=StagedPublication(w,store,timing)
                store.prepared_effect_readback=policy=='native-v2'
                runner=ExactRunner(w,store.effect_intent if store.prepared_effect_readback else store.load,deadline=lambda:critical_deadline[0],
                                   phase_reader=store.effect_phases if store.prepared_effect_readback else store.phase_documents)
                def effect(lane,argv):
                    effect_started=time.monotonic()
                    try:return runner(lane,argv)
                    finally:timing['effect_seconds']+=time.monotonic()-effect_started
                if policy=='native-v2' and plan['candidates']:
                    phase_budget[0]=lambda:readiness_v2.revalidate_budget(w,evidence,at=retention_cohort.clock())
                ex=retention_apply.Executor(read,effect,store,publication,w.c['repositories'],clock=retention_cohort.clock,
                     phase_section=section,pre_phase=pre_phase,
                     **({'phase_preparation':preparation,'phase_verify':verify_prepared} if policy=='native-v2' else {}))
                try:receipt=ex.apply(inventory,plan,evidence,at);receipt=store.latest()
                finally:
                    started=time.monotonic()
                    if hasattr(store,'staging'):store.staging.cleanup()
                    if publication.prepared is not None:publication.prepared['staging'].cleanup()
                    timing['staging_cleanup_seconds']+=time.monotonic()-started
        return store.latest(),store.root
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
