"""Atomic upload intentions and reconciliation, independent of backend/DB.

The archive adapter must read and authenticate remote manifests; a command's
exit status alone is never an upload proof. This module does not schedule jobs,
extract DB references or implement retention/S3/MariaDB by itself.
"""
from contextlib import contextmanager
import datetime as dt
import hashlib
import json
import os
import pathlib
import tempfile
import uuid
import guards

def directory_sync(directory):
    if os.name=='nt':
        return  # Windows test harness; Linux runtime also fsyncs the directory.
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)

def atomic_json(path,data):
    path=pathlib.Path(path)
    guards.require(not path.is_symlink() and not path.parent.is_symlink(),'Symlink in journal')
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    descriptor,name=tempfile.mkstemp(prefix='.writing-',dir=path.parent)
    try:
        with os.fdopen(descriptor,'w',encoding='utf-8',newline='\n') as output:
            json.dump(data,output,sort_keys=True,separators=(',',':'))
            output.write('\n');output.flush();os.fsync(output.fileno())
        os.replace(name,path)
        directory_sync(path.parent)
    finally:
        if os.path.exists(name): os.unlink(name)

def no_duplicates(pairs):
    result={}
    for key,value in pairs:
        guards.require(key not in result,'Duplicate journal fields')
        result[key]=value
    return result

def load_json(path):
    guards.require(not path.is_symlink(),'Symlink in journal')
    guards.require(path.stat().st_size<=64*1024*1024,'Journal oversized')
    try:
        value=json.loads(path.read_text(encoding='utf-8'),object_pairs_hook=no_duplicates)
        guards.require(isinstance(value,dict),'Journal object required')
        return value
    except (ValueError,UnicodeError) as error:
        raise guards.GuardError('Invalid journal JSON') from error

def publish_history(worker):
    """Derive actual cadence from protected confirmations, never fixture flags."""
    import backup_catalog,retention_cohort,retention_native
    started=retention_cohort.clock();w=worker
    # Empty/sparse native journals cannot become observation proof even when
    # archives were bulk backfilled with old capture dates.
    journals={lane:UploadJournal(w.root/'receipts'/lane,w.c['generation']).state() for lane in ('base','binlog')}
    guards.require(all(journal['confirmed'] for journal in journals.values()),'Native cadence journal absent')
    with backup_catalog.ArchiveCatalog(w).open_reader() as reader:inventory=retention_cohort.CohortStore(w).load(reader)
    planned=guards.utc(inventory['cohort']['planned_at']);cutoff=planned-dt.timedelta(days=30)
    indexed={row['id']:row for row in inventory['snapshots']};groups={'binlog':[],'hourly':[],'full':[]}
    # Cadence spans the original confirmations, including an archive at the
    # cutoff that a prior exact native retention legitimately removed. Its
    # identity/time must still match the verified immutable original intent.
    retired={row['id']:row for row in retention_native.verified_tombstones(w)}
    if retired:
        for path in (w.root/'receipts/retention-applies').iterdir():
            intent=retention_native.IntentStore(path).load()
            body={key:value for key,value in intent.items() if key!='intent_sha256'}
            guards.require(retention_native.retention_apply.document_digest(body)==intent['intent_sha256'],'Historical retention intent changed')
            for row in intent['before_inventory']['snapshots']:
                proof=retired.get(row['id'])
                if proof is None:continue
                guards.require(row['id'] in intent['candidate_ids'] and all(row[key]==proof[key] for key in ('id','lane','token','manifest_sha256','generation')),
                               'Historical cadence retirement identity differs')
                if row['id'] in indexed:guards.require(indexed[row['id']]==row,'Conflicting historical cadence identity')
                else:indexed[row['id']]=row
    for lane,journal in journals.items():
        for proof in journal['confirmed']:
            row=indexed.get(proof['id'])
            if row is None:continue
            guards.require(proof['token']==row['token'] and proof['manifest_sha256']==row['manifest_sha256'] and
                           proof['captured_at']==row['time'],'History confirmation identity differs')
            captured=guards.utc(proof['captured_at']);prepared=guards.utc(proof['prepared_at']);confirmed=guards.utc(proof['confirmed_at'])
            interval=60 if lane=='binlog' else 3600
            guards.require(captured<=prepared<=confirmed<=captured+dt.timedelta(seconds=interval),'Late/backfilled confirmation cannot prove cadence')
            kind=row['kind'];group='binlog' if lane=='binlog' else ('hourly' if kind=='hourly' else 'full')
            groups[group].append(captured)
    cadence={'binlog':60,'hourly':3600,'full':86400};first=[]
    for kind,limit in cadence.items():
        times=sorted(set(groups[kind]));guards.require(times and times[0]<=cutoff and times[-1]<=planned and
                              (planned-times[-1]).total_seconds()<=limit,'Actual 30-day frequency coverage absent')
        window=[max(t for t in times if t<=cutoff)]+[t for t in times if t>cutoff]
        guards.require(all(0<(b-a).total_seconds()<=limit for a,b in zip(window,window[1:])),'Actual native cadence gap')
        first.append(window[0])
    document={'result':'PASS','observed_from':max(first).isoformat(),'observed_until':planned.isoformat(),
              'observation_source':'native-confirmed-upload-journal','cadence_seconds':cadence,
              'journal_sha256':retention_native.retention_apply.document_digest(journals),'completed_at':retention_cohort.clock().isoformat()}
    return retention_native.publish_evidence(w,'history',document,inventory,started.isoformat())

class LaneBusyError(guards.GuardError):
    """Only an OS nonblocking lock acquisition reported contention."""

@contextmanager
def lane_lock(path):
    fd=os.open(path,os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0),0o600)
    acquired=False
    try:
        if os.name=='nt':
            import msvcrt
            if os.fstat(fd).st_size==0: os.write(fd,b'0')
            os.lseek(fd,0,os.SEEK_SET)
        else: import fcntl
        try:
            if os.name=='nt':
                msvcrt.locking(fd,msvcrt.LK_NBLCK,1)
            else:
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            acquired=True
        except OSError as error:
            import errno
            if error.errno not in (errno.EAGAIN,errno.EACCES):raise
            raise LaneBusyError('Backup lane busy') from error
        yield
    finally:
        if acquired:
            if os.name=='nt':
                os.lseek(fd,0,os.SEEK_SET);msvcrt.locking(fd,msvcrt.LK_UNLCK,1)
            else: fcntl.flock(fd,fcntl.LOCK_UN)
        os.close(fd)

class UploadJournal:
    def __init__(self,root,generation,clock=None,writer=atomic_json):
        self.root=pathlib.Path(root)
        guards.require(not self.root.is_symlink(),'Symlink in journal')
        self.root.mkdir(mode=0o700,parents=True,exist_ok=True)
        self.generation=guards.hex_id(generation,32)
        self.clock=clock or (lambda:dt.datetime.now(dt.timezone.utc))
        self.writer=writer

    def state(self):
        path=self.root/'state.json'
        value=load_json(path) if path.exists() else {'generation':self.generation,'confirmed':[]}
        guards.require(value.get('generation')==self.generation and isinstance(value.get('confirmed'),list),'Journal generation mismatch')
        return value

    def retire(self,intent,receipt,lane):
        """Append bound absences; the native caller holds this lane's lock.

        Confirmed rows and original binlog coordinates remain immutable. The
        caller must load the intent/receipt from the protected native store.
        """
        import retention_apply
        guards.require(lane in ('base','binlog') and intent['generation']==self.generation,'Retirement scope mismatch')
        rows=[r for r in retention_apply.retention_tombstones(intent,receipt) if r['lane']==lane]
        state=self.state();confirmed={r['id']:r for r in state['confirmed']}
        retired=state.setdefault('retention',[]);indexed={r['id']:r for r in retired}
        guards.require(len(indexed)==len(retired),'Duplicate retired identity')
        for row in rows:
            known=confirmed.get(row['id'])
            guards.require(known and all(known[k]==row[k] for k in ('id','token','manifest_sha256')),'Unknown retired confirmation')
            if row['id'] in indexed:
                guards.require(all(indexed[row['id']][k]==row[k] for k in ('id','lane','token','manifest_sha256','generation','intent_sha256','pre_inventory_sha256')),'Retirement identity drift')
            else:retired.append(row);indexed[row['id']]=row
        self.writer(self.root/'state.json',state)
        guards.require(self.state()==state,'Retirement durable readback differs')
        return rows

    def upload(self,payload,manifest_sha256,backend):
        with lane_lock(self.root/'lane.lock'):
            state=self.state()
            prepared_at=self.clock().isoformat();guards.utc(prepared_at)
            if 'last_confirmation_at' in state:
                guards.require(guards.utc(prepared_at)>=guards.utc(state['last_confirmation_at']),'Clock rollback between uploads')
            path=self.root/'pending.json'
            payload=pathlib.Path(payload).resolve(strict=True)
            manifest=payload/'manifest.json'
            guards.require(manifest.is_file() and not manifest.is_symlink(),'Manifest missing')
            actual=hashlib.sha256(manifest.read_bytes()).hexdigest()
            guards.require(actual==guards.hex_id(manifest_sha256,64),'Pending payload changed')
            metadata=load_json(manifest)
            guards.require(metadata.get('generation')==self.generation,'Manifest generation mismatch')
            captured_at=metadata.get('captured_at');guards.utc(captured_at)
            guards.require(guards.utc(captured_at)<=guards.utc(prepared_at),'Future payload or clock rollback')
            if 'last_success_at' in state:
                guards.require(guards.utc(captured_at)>=guards.utc(state['last_success_at']),'Payload watermark rollback')
            if path.exists():
                pending=load_json(path)
                guards.require(pending.get('generation')==self.generation and pending.get('payload')==str(payload)
                    and pending.get('manifest_sha256')==actual and pending.get('captured_at')==captured_at,'Pending identity or bytes changed')
            else:
                pending={'token':uuid.uuid4().hex,'generation':self.generation,'payload':str(payload),
                    'manifest_sha256':actual,'attempted':False,'prepared_at':prepared_at,'captured_at':captured_at}
                if state['confirmed']:
                    pending['parent_id']=guards.hex_id(state['confirmed'][-1]['id'],64)
                guards.utc(pending['prepared_at'])
                self.writer(path,pending)
            guards.require(guards.utc(prepared_at)>=guards.utc(pending['prepared_at']),'Clock rollback after saved intent')
            # attempted=False is durable proof that this intent has not made
            # its external call. Avoid a full inventory scan for each new job.
            matches=backend.find(pending['token']) if pending.get('attempted') is True else []
            if not matches:
                guards.require(pending.get('attempted') is False,'Unknown upload; reconcile, no automatic retry')
                pending['attempted']=True
                self.writer(path,pending)  # Durable intent BEFORE the external call.
                backend.put(payload,pending)
                matches=backend.find(pending['token'])  # Read authenticated manifest.
            sid=guards.confirm_upload(pending,matches)
            confirmed_at=self.clock().isoformat();guards.utc(confirmed_at)
            guards.require(guards.utc(confirmed_at)>=guards.utc(pending['prepared_at']),'Clock rollback')
            guards.require(guards.utc(confirmed_at)>=guards.utc(prepared_at),'Clock rollback during confirmation')
            previous=[x for x in state['confirmed'] if x['id']==sid]
            if previous:
                guards.require(len(previous)==1 and previous[0]['manifest_sha256']==actual and previous[0]['token']==pending['token'],'Conflicting confirmation')
            else:
                state['confirmed'].append({'id':sid,'token':pending['token'],'manifest_sha256':actual,
                                          'confirmed_at':confirmed_at,'prepared_at':pending['prepared_at'],'captured_at':captured_at})
            # The data watermark stays old after late reconciliation. A later
            # authentication time must never disguise stale binlog coverage.
            state['last_success_at']=captured_at
            state['last_confirmation_at']=confirmed_at
            self.writer(self.root/'state.json',state)
            path.unlink();directory_sync(self.root)
            return sid
