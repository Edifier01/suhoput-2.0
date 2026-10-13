"""Selected-repository cleanup/index compaction, separate from snapshot retirement.

The inventory authority must measure current repository object bytes. Restic
live-blob statistics are not that measurement. No backend authority is invented
here; production needs worker.maintenance_inventory or an explicit trusted
producer returning a fresh root-owned receipt. Shared packs may remain forever
with zero repacking, so this operation never certifies a monthly storage bound.
Provider versions, incomplete uploads and billable metadata remain separate.
"""
import datetime as dt, hashlib, json, pathlib, time, uuid
import backup_catalog, guards, retention_cohort, retention_native, runtime
from worker import private_path, protected_directory

def clock():return dt.datetime.now(dt.timezone.utc)
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
OPERATIONS={'cleanup':('native-physical-cleanup',['prune','--max-repack-size','0','--max-unused=unlimited']),
            'compact':('native-index-compaction',['repair','index'])}

def load_intent(worker,path):
    doc=runtime.load_json(private_path(path));body={key:value for key,value in doc.items() if key not in ('intent_sha256','native_completion','verification_failure')}
    lane=doc.get('lane')
    guards.require(doc.get('intent_sha256')==digest(body) and
                   any(doc.get('operation')==name and doc.get('command')==command for name,command in OPERATIONS.values()) and
                   lane in ('base','binlog') and doc.get('generation')==worker.c['generation'] and
                   doc.get('code_sha')==worker.c['code_sha'] and doc.get('repository')==worker.c['repositories'][lane],
                   'Physical cleanup intent changed')
    if 'native_completion' in doc:
        completion=doc['native_completion'];content={key:value for key,value in completion.items() if key!='sha256'}
        guards.require(completion.get('sha256')==digest(content) and completion.get('intent_sha256')==doc['intent_sha256'] and
                       completion['after']['repository_id']==doc['before']['repository_id'] and
                       completion['after']['snapshot_ids']==doc['before']['snapshot_ids'],'Physical cleanup completion changed')
    return doc

def require_clear(worker):
    """Constant-size producer gate; completed native work permits new uploads."""
    directory=worker.root/'receipts/maintenance'
    if not directory.exists() and not directory.is_symlink():return
    protected_directory(directory)
    for lane in ('base','binlog'):
        path=directory/('pending-'+lane+'.json')
        if path.exists() or path.is_symlink():
            doc=load_intent(worker,path)
            guards.require(doc['lane']==lane and 'native_completion' in doc and 'verification_failure' not in doc,'Unresolved physical cleanup blocks capture/upload')

class Maintenance:
    def __init__(self,worker,*,inventory=None):
        self.w=worker;self.inventory=inventory or getattr(worker,'maintenance_inventory',None)
        self.root=worker.root/'receipts/maintenance'
        self.root.mkdir(mode=0o700,exist_ok=True);protected_directory(self.root)
    def pending(self,lane):return self.root/('pending-'+lane+'.json')
    def remaining(self,deadline):
        seconds=deadline-time.monotonic();guards.require(seconds>0,'Physical cleanup work deadline exceeded');return seconds
    def read(self,lane,args,deadline):
        return json.loads(self.w.restic(lane,['--repo',self.w.c['repositories'][lane],*args],timeout=self.remaining(deadline)),object_pairs_hook=runtime.no_duplicates)
    def observe(self,lane,deadline,*,require_indexes=False):
        w=self.w;init=runtime.load_json(private_path(w.root/'receipts'/('init-'+lane+'.json')))
        guards.require(init['generation']==w.c['generation'],'Physical cleanup initialization generation changed')
        config=self.read(lane,['cat','config'],deadline)
        guards.require(config.get('version')==2 and config.get('id')==init['repository_id'],'Physical cleanup repository identity changed')
        repository_id=guards.hex_id(config['id'],64)
        rows=self.read(lane,['snapshots','--json'],deadline)
        guards.require(isinstance(rows,list) and rows,'Physical cleanup requires retained snapshots')
        ids=sorted(guards.hex_id(row['id'],64) for row in rows)
        guards.require(len(ids)==len(set(ids)),'Duplicate native snapshot identity')
        self.observed_rows={row['id']:row for row in rows}
        started=clock()
        # Contract: inventory(lane, repository_id=ID, timeout=seconds) returns a
        # newly published absolute 0600 receipt, not caller-supplied counters.
        path=private_path(self.inventory(lane,repository_id=repository_id,timeout=self.remaining(deadline)))
        raw=path.read_bytes();guards.require(len(raw)<=65536,'Physical inventory receipt oversized')
        measured=json.loads(raw,object_pairs_hook=runtime.no_duplicates);self.remaining(deadline)
        expected={'format':1,'generation':w.c['generation'],'code_sha':w.c['code_sha'],'lane':lane,
                  'repository':w.c['repositories'][lane],'repository_id':repository_id,'scope':'current-repository-object-bytes'}
        guards.require(isinstance(measured,dict) and all(measured.get(key)==value for key,value in expected.items()),'Physical inventory scope changed')
        guards.require(started<=guards.utc(measured['observed_at'])<=clock(),'Physical inventory receipt is not fresh')
        for field in ('physical_bytes','object_count'):
            guards.require(type(measured.get(field)) is int and 0<measured[field]<2**63,'Physical inventory counters are unknown')
        if require_indexes:
            for field,total in (('index_object_count','object_count'),('index_bytes','physical_bytes')):
                guards.require(type(measured.get(field)) is int and 0<measured[field]<=measured[total],
                               'Physical index inventory counters are unknown')
        guards.require(isinstance(measured.get('source'),str) and 0<len(measured['source'])<=512,'Physical inventory producer missing')
        return {'repository_id':repository_id,'snapshot_ids':ids,'physical':measured,
                'physical_receipt':{'path':str(path),'sha256':hashlib.sha256(raw).hexdigest()}}
    def load(self,lane):
        doc=load_intent(self.w,self.pending(lane));guards.require(doc['lane']==lane,'Physical cleanup intent lane changed')
        return doc
    def survivors(self,lane,intent,after,deadline,*,allow_arrivals):
        guards.require(after['repository_id']==intent['before']['repository_id'],'Physical cleanup repository changed')
        prior=set(intent['before']['snapshot_ids']);current=set(after['snapshot_ids']);arrivals=sorted(current-prior)
        guards.require(prior<=current and (allow_arrivals or not arrivals),'Physical cleanup changed retained snapshots')
        if arrivals:
            # A crash after proven completion can overlap genuine new uploads.
            # Authenticate each additional ID against both the sealed admission
            # catalog and confirmed upload journal, never accept it from flags.
            journal=runtime.UploadJournal(self.w.root/'receipts'/lane,self.w.c['generation']).state()
            confirmed={row['id']:row for row in journal['confirmed']}
            with backup_catalog.ArchiveCatalog(self.w).open_reader() as reader:
                for sid in arrivals:
                    self.remaining(deadline);record=reader._record(sid)
                    native,token,manifest=backup_catalog.native_identity(self.observed_rows[sid],sid,
                        str(self.w.root/'spool'/(lane+'-payload')),self.w.c['generation'])
                    guards.require(record['lane']==lane and record['generation']==self.w.c['generation'] and
                                   record['repository_id']==after['repository_id'] and record['native']==native and
                                   record['manifest_sha256']==manifest and record['token']==token,
                                   'Cleanup arrival differs from authenticated catalog')
                    row=confirmed.get(sid)
                    guards.require(row is not None and row['token']==token and row['manifest_sha256']==manifest,
                                   'Cleanup arrival lacks confirmed upload journal')
            self.remaining(deadline)
        return arrivals
    def run(self,lane,mode='apply',*,operation='cleanup'):
        import integrity
        w=self.w;guards.require(lane in ('base','binlog') and mode in ('apply','reconcile'),'Unknown physical cleanup mode/lane')
        guards.require(operation in OPERATIONS,'Unknown maintenance operation');operation_name,command=OPERATIONS[operation]
        guards.require(callable(self.inventory),'Physical inventory authority required')
        # Serialize against snapshot retirement, including the later check.
        # Upload/capture locks cover only the short native effect phase.
        with runtime.lane_lock(w.root/'receipts/retention-apply.lock'):
            pending=self.pending(lane)
            guards.require(not pending.is_symlink(),'Physical cleanup intent symlink')
            if mode=='apply':
                guards.require(not pending.exists(),'Unresolved physical cleanup requires read-only reconciliation')
                retention_cohort.ready(w)
                if operation=='cleanup':
                    guards.require(any(row['lane']==lane for row in retention_native.verified_tombstones(w)),
                                   'Physical cleanup requires authenticated exact retirement')
                else:integrity.ensure(w)
                intent=None
            else:
                guards.require(pending.exists(),'No physical cleanup intent to reconcile');intent=self.load(lane)
                guards.require(intent['operation']==operation_name,'Maintenance reconciliation operation differs')
            started=time.monotonic();deadline=started+retention_cohort.MAX_CRITICAL_SECONDS-10
            after=None;completed=bool(intent and 'native_completion' in intent);result=None;arrivals=[]
            try:
                with retention_cohort.upload_section(w) as acquired:
                    if acquired is not None:
                        started=acquired;deadline=started+retention_cohort.MAX_CRITICAL_SECONDS-10
                    retention_cohort.ready_uploads(w)
                    before=self.observe(lane,deadline,require_indexes=operation=='compact')
                    if mode=='apply':
                        body={'format':1,'operation':operation_name,'attempt':uuid.uuid4().hex,
                              'generation':w.c['generation'],'code_sha':w.c['code_sha'],'lane':lane,
                              'repository':w.c['repositories'][lane],'prepared_at':clock().isoformat(),'before':before,
                              'command':command}
                        if operation=='cleanup':integrity.invalidate_lane(w,lane)
                        intent={**body,'intent_sha256':digest(body)}
                        runtime.atomic_json(self.root/('intent-'+intent['attempt']+'.json'),intent)
                        runtime.atomic_json(pending,intent)
                        effect=w.maintenance_prune if operation=='cleanup' else w.maintenance_compact
                        effect(lane,timeout=self.remaining(deadline));completed=True
                        after=self.observe(lane,deadline,require_indexes=operation=='compact')
                    else:after=before
                    arrivals=self.survivors(lane,intent,after,deadline,allow_arrivals=mode=='reconcile' and completed)
                    self.remaining(deadline)
                    if completed and mode=='apply':
                        # Authenticated completion releases the producer gate
                        # before the unlocked full read. The original intent
                        # remains durable for crash recovery and cannot retry.
                        content={'intent_sha256':intent['intent_sha256'],'after':after}
                        intent['native_completion']={**content,'sha256':digest(content)}
                        runtime.atomic_json(pending,intent);self.remaining(deadline)
                critical_seconds=time.monotonic()-started
                guards.require(critical_seconds<=retention_cohort.MAX_CRITICAL_SECONDS,'Physical cleanup actual lock limit exceeded')
                # Metadata checking after index-only compaction does not renew
                # the independent weekly full remote read. Physical cleanup
                # still requires every retained data byte to be read remotely.
                # Neither check holds job/upload locks; unknown native effects
                # are never retried and their native locks are never removed.
                check_mode='full-remote-read' if operation=='cleanup' else 'metadata-with-cache'
                read_started=clock().isoformat()
                w.restic(lane,['--repo',w.c['repositories'][lane],'check','--read-data' if operation=='cleanup' else '--with-cache'],timeout=900)
                if operation=='cleanup':integrity.publish_lane(w,lane,after['repository_id'],list(self.observed_rows.values()),read_started,clock().isoformat())
                result='APPLIED' if mode=='apply' else 'RECONCILED'
            except Exception as error:
                if intent is None:raise
                intent['verification_failure']={'at':clock().isoformat(),'error_type':type(error).__name__}
                runtime.atomic_json(pending,intent)
                result='RECONCILE_REQUIRED';error_type=type(error).__name__
            outcome={'operation':operation_name,'result':result,'intent_sha256':intent['intent_sha256'],
                     'lane':lane,'before':intent['before'],'after':after,'native_completed':completed,
                     'prune_completed':completed and operation=='cleanup','authenticated_arrivals':arrivals,
                     'intent_file':str(self.root/('intent-'+intent['attempt']+'.json')),
                     'critical_seconds':locals().get('critical_seconds',time.monotonic()-started),
                     'completed_at':clock().isoformat(),'monthly_storage_bound_verified':False,
                     'check_mode':locals().get('check_mode'),
                     'full_remote_read_verified':operation=='cleanup' and result in ('APPLIED','RECONCILED')}
            if after is not None:outcome['physical_bytes_delta']=after['physical']['physical_bytes']-intent['before']['physical']['physical_bytes']
            if result=='RECONCILE_REQUIRED':outcome['error_type']=error_type
            if 'native_completion' in intent:outcome['native_completion']=intent['native_completion']
            path=self.root/('outcome-'+uuid.uuid4().hex+'.json');runtime.atomic_json(path,outcome)
            if result in ('APPLIED','RECONCILED') and completed:pending.unlink();runtime.directory_sync(self.root)
            # Read-only reconciliation proves current integrity, not completion
            # of the unknown prune. Preserve its intent; never auto-repeat it.
            return {**outcome,'receipt':str(path)}
