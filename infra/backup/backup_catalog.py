"""Root protected native-readback catalog, with an independent committed head.

Only Worker calls admission after native restore --verify, tree/file/media checks.
There is no command-line proof import. The independent receipts head is the trust
anchor: changing/rolling back the mutable SQLite payload cannot change that head.
Compromise/rollback of the entire root protected trust anchor is outside this
boundary, just as for the existing protected upload/retention journals.

Admission checks its indexed identity and committed tail; it does not rehash all
historic archives. Readers verify the complete ordered chain and compressed blob
seals before returning compact projections. Interrupted publication blocks every
reader and normal writer. Explicit reconciliation requires the same actual fresh
native readback; no database repair/rebuild or implicit recovery is performed.
Windows exercises synthetic filesystem logic only; Worker requires Linux root.
"""
import contextlib
import copy
import datetime as dt
import hashlib
import json
import os
import pathlib
import shutil
import sqlite3
import stat
import time
import uuid
import zlib

import guards
import runtime

MAX_RAW_BYTES=64*1024**2
MAX_RECORD_BYTES=2*1024**2
MAX_CHECKPOINT_BYTES=8*1024**2
MAX_CHECKPOINT_RETIREMENTS=1536
MAX_FILE_BYTES=256*1024**2
MAX_ARCHIVE_BYTES=1024**3
MAX_STORE_BYTES=10*1024**3
MAX_RECORDS=100000
ZERO='0'*64

class CatalogCapacityError(guards.GuardError):
    """Transaction was rolled back; prior committed data remains authoritative."""

class CheckpointArrival(guards.GuardError):
    """A native member was not in the private prefix; admit-chain catch-up only."""

class CheckpointCopyCorrupt(guards.GuardError):
    """Owned stream/readback differs; an appended head cannot excuse it."""

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

def digest(value):return hashlib.sha256(value).hexdigest()

def _check_deadline(deadline):
    if deadline is not None:guards.require(time.monotonic()<deadline,'Catalog checkpoint critical deadline exceeded')

def file_digest(path,deadline=None):
    path=safe(path);before=path.stat();value=hashlib.sha256()
    with path.open('rb') as source:
        while True:
            _check_deadline(deadline);block=source.read(1024*1024)
            if not block:break
            value.update(block)
    after=path.stat()
    guards.require((before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
                   (after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'Catalog file changed during sealed read')
    return value.hexdigest()

class CheckpointStage:
    """Owned sibling image; never a caller-supplied retirement proof."""
    def __init__(self,catalog,token=None,*,reader=False):
        parent=catalog.receipts/('catalog-readers' if reader else 'catalog-preparations');parent.mkdir(mode=0o700,exist_ok=True);safe(parent,directory=True)
        self.root=parent/(guards.hex_id(token,32) if token is not None else uuid.uuid4().hex)
        if token is None:self.root.mkdir(mode=0o700)
        safe(self.root,directory=True);root=self.root/'catalog'
        if token is None:root.mkdir(mode=0o700)
        safe(root,directory=True)
        self.catalog=object.__new__(ArchiveCatalog)
        for key in ('worker','receipts','binding','lock'):setattr(self.catalog,key,getattr(catalog,key))
        self.catalog.root=root;self.catalog.database=root/'index.sqlite3';self.catalog.head=self.root/'head.json'
        self.catalog.pending=root/'pending.json';self.catalog.checkpoint_pending=root/'checkpoint-pending.json'
        self.manifest=self.root/'preparation.json';self.files=[]
    def check_layout(self,*,sealed=False):
        safe(self.root,directory=True);safe(self.catalog.root,directory=True)
        names={p.name for p in self.root.iterdir()};images={p.name for p in self.catalog.root.iterdir()}
        expected={'catalog','head.json','preparation.json'};journals={'journal-base.json','journal-binlog.json'}
        guards.require(names in (expected,expected|journals) if sealed else names<=expected|journals,'Unknown/incomplete preparation root')
        guards.require(images=={'index.sqlite3'} if sealed else images<= {'index.sqlite3'},'Unknown/incomplete preparation image layout')
        for path in (self.manifest,self.catalog.head,self.catalog.database,*(self.root/name for name in journals)):
            if path.exists() or path.is_symlink():safe(path)
    def cleanup(self):
        # Fixed owned paths only; unknown content keeps the orphan for review.
        self.release_activation()
        self.check_layout()
        for path in (self.manifest,self.catalog.head,self.catalog.database,self.root/'journal-base.json',self.root/'journal-binlog.json'):
            if path.exists():safe(path).unlink()
        self.catalog.root.rmdir();self.root.rmdir();runtime.directory_sync(self.root.parent)
    def release_activation(self):
        stack=getattr(self,'activation',None)
        if stack is not None:
            self.activation=None;stack.close()

def decode(raw,limit=MAX_RAW_BYTES):
    guards.require(isinstance(raw,bytes) and len(raw)<=limit,'Catalog JSON oversized')
    try:
        result=json.loads(raw,object_pairs_hook=runtime.no_duplicates,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))
        guards.require(isinstance(result,dict),'Catalog JSON object required')
        return result
    except (ValueError,UnicodeError,RecursionError) as error:
        raise guards.GuardError('Invalid catalog JSON') from error

def inflate(raw,limit):
    guards.require(isinstance(raw,bytes) and len(raw)<=limit,'Catalog compressed blob oversized')
    try:
        stream=zlib.decompressobj();value=stream.decompress(raw,limit+1)
        guards.require(len(value)<=limit and stream.eof and not stream.unused_data and not stream.unconsumed_tail,
                       'Catalog decompression limit/format differs')
        return value
    except zlib.error as error:raise guards.GuardError('Catalog compressed blob corrupt') from error

def safe(path,*,directory=False):
    p=pathlib.Path(path)
    guards.require(p.is_absolute() and '..' not in p.parts,'Canonical catalog path required')
    for ancestor in [*reversed(p.parents),p]:guards.require(not ancestor.is_symlink(),'Catalog symlink ancestor')
    try:value=p.stat()
    except OSError as error:raise guards.GuardError('Catalog protected path missing') from error
    guards.require(stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode) and value.st_nlink==1,
                   'Catalog file type/link mismatch')
    if os.name=='posix':guards.require(value.st_uid==0 and stat.S_IMODE(value.st_mode)==(0o700 if directory else 0o600),
                                      'Catalog protected owner/mode mismatch')
    return p

def read_file(path,limit):
    p=safe(path);before=p.stat();guards.require(before.st_size<=limit,'Catalog file oversized')
    raw=p.read_bytes();after=p.stat()
    guards.require((before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
                   (after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) and len(raw)==before.st_size,
                   'Catalog bytes changed during read')
    return raw

def native_identity(row,sid,scope,generation):
    guards.hex_id(sid,64);guards.require(isinstance(row,dict) and row.get('id',sid)==sid,'Native snapshot identity mismatch')
    guards.hex_id(row['tree'],64);guards.utc(row['time']);tags=row['tags']
    guards.require(row['paths']==[scope] and isinstance(tags,list) and len(tags)<=32 and
                   all(isinstance(x,str) and len(x)<=256 for x in tags) and len(tags)==len(set(tags)) and 'task047' in tags,
                   'Native catalog source/tags differ')
    def tag(prefix):
        values=[x[len(prefix):] for x in tags if x.startswith(prefix)]
        guards.require(len(values)==1,'Ambiguous catalog identity tag');return values[0]
    guards.require(tag('generation:')==generation,'Native catalog generation differs')
    return {'id':sid,'tree':row['tree'],'time':row['time'],'paths':row['paths'],'tags':tags},guards.hex_id(tag('token:'),32),guards.hex_id(tag('manifest-sha:'),64)

@contextlib.contextmanager
def _catalog_lock(path,limit,deadline,label):
    """Retry only typed acquisition contention, never the protected body."""
    end=time.monotonic()+limit
    if deadline is not None:end=min(end,deadline)
    with contextlib.ExitStack() as acquired:
        while True:
            remaining=end-time.monotonic()
            guards.require(remaining>0,'Catalog '+label+' lock wait deadline exceeded')
            try:acquired.enter_context(runtime.lane_lock(path))
            except runtime.LaneBusyError:time.sleep(min(.025,remaining))
            else:break
        yield

class ArchiveReader:
    """Frozen verified records, short per-blob reads; no long-lived write lock.

    A new append does not change the captured set. Every accessed blob is checked
    against this reader's already sealed digest, including after concurrent append.
    Native live inventory must still be rechecked before any retention effect.
    """
    def __init__(self,catalog,head,records,lifetime=None):
        self.catalog=catalog;self.head=copy.deepcopy(head);self._records=records;self._lifetime=lifetime or {'active':True}
    @property
    def active(self):return self._lifetime['active']
    @active.setter
    def active(self,value):self._lifetime['active']=value
    def entries(self):
        guards.require(self.active,'Catalog reader closed');return copy.deepcopy(self._records)
    @contextlib.contextmanager
    def _read_lock(self,deadline=None):
        # Wait only for acquisition. Never retry a body/verification error or
        # retain another catalog image merely to outlive an ordinary append.
        from retention_cohort import MAX_CRITICAL_SECONDS
        with _catalog_lock(self.catalog.lock,MAX_CRITICAL_SECONDS,deadline,'read'):yield

    def refresh(self,*,deadline=None):
        """Authenticate indexed appends from the captured independent head.

        Epoch changes require reopening and full revalidation outside upload
        locks. Previously captured identities and blob seals stay immutable.
        """
        guards.require(self.active,'Catalog reader closed');c=self.catalog
        with self._read_lock(deadline),c._db() as db:
            guards.require(not c._incomplete(),'Interrupted catalog publication blocks refresh')
            head=c._head();c._tail(db,head)
            guards.require(head.get('checkpoint')==self.head.get('checkpoint') and head['sequence']>=self.head['sequence'],
                           'Catalog epoch or captured prefix changed; reopen outside upload locks')
            anchor=db.execute('SELECT chain FROM archives WHERE sequence=?',(self.head['sequence'],)).fetchone()
            guards.require((anchor[0] if anchor else c._seed(head))==self.head['chain'],'Catalog captured head changed')
            previous=self.head['chain'];sequence=self.head['sequence'];fresh={}
            tokens={r['token'] for r in self._records.values()}
            for row in db.execute('SELECT sequence,sid,token,record,body,chain FROM archives WHERE sequence>? ORDER BY sequence',(sequence,)):
                _check_deadline(deadline)
                sequence+=1;record=c._row(row);expected=digest(bytes.fromhex(previous)+row[3])
                guards.require(row[0]==sequence and row[5]==expected and row[1] not in self._records and row[1] not in fresh and row[2] not in tokens,
                               'Catalog appended chain/identity differs')
                guards.require(record['generation']==c.binding['generation'] and record['projection']['source']==c.binding['source'] and
                               record['repository']==c.binding['repository_paths'][record['lane']],'Catalog append scope differs')
                cached={x['file']:x for x in record['cached_logs']}
                for name,body in db.execute('SELECT name,body FROM logs WHERE sid=?',(record['id'],)):
                    _check_deadline(deadline)
                    item=cached.pop(name,None)
                    guards.require(item is not None and isinstance(body,bytes) and len(body)<=MAX_FILE_BYTES and digest(body)==item['compressed_sha256'],
                                   'Catalog appended binlog seal differs')
                guards.require(not cached,'Catalog appended binlog missing')
                fresh[row[1]]=record;tokens.add(row[2]);previous=expected
            guards.require(sequence==head['sequence'] and previous==head['chain'],'Catalog appended head differs')
            _check_deadline(deadline)
            return ArchiveReader(c,head,{**self._records,**fresh},self._lifetime)
    def _record(self,sid):
        guards.require(self.active,'Catalog reader closed');guards.hex_id(sid,64)
        record=self._records.get(sid);guards.require(record is not None,'Snapshot outside sealed catalog reader');return record
    def raw_manifest(self,sid,*,deadline=None):
        record=self._record(sid)
        with self._read_lock(deadline),self.catalog._db() as db:
            row=db.execute('SELECT body FROM archives WHERE sid=?',(sid,)).fetchone()
            guards.require(row is not None and isinstance(row[0],bytes) and digest(row[0])==record['raw_compressed_sha256'],'Sealed reader raw body differs')
            raw=inflate(row[0],MAX_RAW_BYTES);guards.require(digest(raw)==record['manifest_sha256'],'Sealed reader original manifest differs');return raw
    def binlog_bytes(self,sid,filename,*,deadline=None):
        record=self._record(sid);guards.log_number(filename)
        item=next((x for x in record['cached_logs'] if x['file']==filename),None)
        guards.require(record['lane']=='binlog' and item is not None,'Sealed reader binlog descriptor missing')
        with self._read_lock(deadline),self.catalog._db() as db:
            row=db.execute('SELECT body FROM logs WHERE sid=? AND name=?',(sid,filename)).fetchone()
            guards.require(row is not None and isinstance(row[0],bytes) and len(row[0])<=MAX_FILE_BYTES and digest(row[0])==item['compressed_sha256'],'Sealed reader binlog body differs')
            raw=inflate(row[0],MAX_FILE_BYTES)
            guards.require(len(raw)==item['size'] and digest(raw)==item['sha256'],'Sealed reader binlog hash differs');return raw

class ArchiveCatalog:
    def __init__(self,worker,*,deadline=None):
        self.worker=worker;self.receipts=safe(worker.root/'receipts',directory=True)
        self.root=self.receipts/'archive-catalog';self.database=self.root/'index.sqlite3'
        self.head=self.receipts/'archive-catalog-head.json';self.pending=self.root/'pending.json';self.lock=self.receipts/'archive-catalog.lock'
        self.checkpoint_pending=self.root/'checkpoint-pending.json'
        self.binding={'format':1,'generation':guards.hex_id(worker.c['generation'],32),'source':worker.source,
                      'repository_paths':worker.c['repositories']}
        if not self.lock.exists():
            fd=os.open(self.lock,os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,'O_NOFOLLOW',0),0o600);os.close(fd)
            os.chmod(self.lock,0o600);runtime.directory_sync(self.receipts)
        safe(self.lock)
        with (_catalog_lock(self.lock,5,deadline,'initialization') if deadline is not None else runtime.lane_lock(self.lock)):
            if not self.root.exists():
                guards.require(not self.head.exists() and not self.head.is_symlink(),'Catalog payload missing; never rebuild')
                self.root.mkdir(mode=0o700);runtime.directory_sync(self.receipts)
                # A crash while bootstrapping leaves this directory incomplete.
                with contextlib.closing(sqlite3.connect(self.database)) as db:
                    db.execute('PRAGMA journal_mode=DELETE');db.execute('PRAGMA synchronous=FULL')
                    db.execute('CREATE TABLE archives (sequence INTEGER PRIMARY KEY, sid TEXT UNIQUE NOT NULL, token TEXT UNIQUE NOT NULL, record BLOB NOT NULL, body BLOB NOT NULL, chain TEXT NOT NULL)')
                    db.execute('CREATE TABLE logs (sid TEXT NOT NULL, name TEXT NOT NULL, body BLOB NOT NULL, PRIMARY KEY(sid,name))')
                    db.execute('CREATE TABLE catalog_checkpoint (slot INTEGER PRIMARY KEY CHECK(slot=1), record BLOB NOT NULL)')
                os.chmod(self.database,0o600);self._sync_db()
                runtime.atomic_json(self.head,{**self.binding,'sequence':0,'chain':ZERO})
            self._layout()

    def _layout(self):
        safe(self.receipts,directory=True);safe(self.root,directory=True);safe(self.database);safe(self.head);safe(self.lock)
        guards.require(self.database.stat().st_size<=MAX_STORE_BYTES,'Catalog disk footprint oversized')
        allowed={'index.sqlite3','pending.json','checkpoint-pending.json'}
        guards.require(all(p.name in allowed for p in self.root.iterdir()),'Incomplete or foreign catalog publication')
        if self.pending.exists():safe(self.pending)
        guards.require(not self.pending.is_symlink(),'Catalog pending symlink')
        if self.checkpoint_pending.exists():safe(self.checkpoint_pending)
        guards.require(not self.checkpoint_pending.is_symlink(),'Catalog checkpoint pending symlink')

    def _head(self):
        value=decode(read_file(self.head,MAX_RECORD_BYTES),MAX_RECORD_BYTES)
        keys=set(self.binding)|{'sequence','chain'}
        guards.require(set(value) in (keys,keys|{'checkpoint'}) and all(value.get(k)==v for k,v in self.binding.items()),'Catalog head binding mismatch')
        guards.require(type(value['sequence']) is int and 0<=value['sequence']<=MAX_RECORDS,'Catalog sequence bound')
        guards.hex_id(value['chain'],64)
        if 'checkpoint' in value:
            item=value['checkpoint'];guards.require(set(item)=={'epoch','sha256','lineage_sha256'} and type(item['epoch']) is int and item['epoch']>=1,'Catalog checkpoint head differs')
            guards.hex_id(item['sha256'],64);guards.hex_id(item['lineage_sha256'],64)
        return value

    @contextlib.contextmanager
    def _db(self,write=False):
        self._layout()
        try:
            db=sqlite3.connect(self.database.as_uri()+('?mode=rw' if write else '?mode=ro'),uri=True)
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,MAX_FILE_BYTES+MAX_RECORD_BYTES)
            db.execute('PRAGMA trusted_schema=OFF');db.execute('PRAGMA busy_timeout=0')
            db.execute('PRAGMA temp_store=MEMORY')
            if write:db.execute('PRAGMA journal_mode=DELETE');db.execute('PRAGMA synchronous=FULL')
            try:yield db
            finally:db.close()
        except sqlite3.Error as error:raise guards.GuardError('Catalog index corrupt/incomplete') from error

    def _sync_db(self):
        fd=os.open(self.database,os.O_RDWR|getattr(os,'O_NOFOLLOW',0))
        try:os.fsync(fd)
        finally:os.close(fd)
        runtime.directory_sync(self.root)

    def _tail(self,db,head):
        row=db.execute('SELECT sequence,chain FROM archives ORDER BY sequence DESC LIMIT 1').fetchone()
        guards.require((row or (0,self._seed(head)))==(head['sequence'],head['chain']),'Catalog committed tail mismatch')

    @staticmethod
    def _seed(head):return head.get('checkpoint',{}).get('sha256',ZERO)

    def _checkpoint_incomplete(self):
        # The bridge is durable before pending and outlives its removal. Both
        # crash windows retain exact source/journal authority for reconciliation.
        return self.checkpoint_pending.exists() or (self.receipts/'catalog-checkpoint-stage.json').exists()

    def _incomplete(self):return self.pending.exists() or self._checkpoint_incomplete()

    def ready(self,*,deadline=None):
        """Bounded pre-upload readiness; never scan historic file arrays/blobs."""
        with (_catalog_lock(self.lock,5,deadline,'readiness') if deadline is not None else runtime.lane_lock(self.lock)),self._db() as db:
            guards.require(not self._incomplete(),'Interrupted catalog publication; upload must not start')
            self._tail(db,self._head());return True

    def _checkpoint_record(self,db,head):
        exists=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='catalog_checkpoint'").fetchone()
        rows=db.execute('SELECT slot,record FROM catalog_checkpoint').fetchall() if exists else []
        if 'checkpoint' not in head:
            guards.require(not rows,'Unexpected uncommitted catalog checkpoint');return None
        guards.require(len(rows)==1 and rows[0][0]==1 and isinstance(rows[0][1],bytes),'Catalog checkpoint witness missing')
        raw=rows[0][1];value=decode(raw,MAX_CHECKPOINT_BYTES);proof=head['checkpoint']
        guards.require(canonical(value)==raw and digest(raw)==proof['sha256'],'Catalog checkpoint witness seal differs')
        common={'format','operation','prior_head','epoch','retired','survivor_count','survivors_sha256','lineage_sha256'}
        if value.get('format')==2:
            guards.require(set(value)==common|{'derived_inventory_sha256'} and value['operation']=='derived-prefix-catalog-checkpoint',
                           'Derived checkpoint schema differs')
            guards.hex_id(value['derived_inventory_sha256'],64)
        else:
            guards.require(value.get('format')==1 and set(value)==common|{'native_inventory_sha256'} and value['operation']=='native-verified-catalog-checkpoint',
                           'Legacy checkpoint schema differs')
            guards.hex_id(value['native_inventory_sha256'],64)
        prior=value['prior_head'];guards.require(all(prior.get(k)==v for k,v in self.binding.items()),'Catalog checkpoint prior source differs')
        guards.require(value['epoch']==proof['epoch']==prior.get('checkpoint',{}).get('epoch',0)+1 and
                       value['lineage_sha256']==proof['lineage_sha256']==digest(bytes.fromhex(prior.get('checkpoint',{}).get('lineage_sha256',ZERO))+canonical({k:v for k,v in value.items() if k!='lineage_sha256'})),
                       'Catalog checkpoint prior-head lineage differs')
        guards.require(type(value['survivor_count']) is int and 0<=value['survivor_count']<=head['sequence'] and
                       isinstance(value['retired'],list) and 0<len(value['retired'])<=(MAX_CHECKPOINT_RETIREMENTS if value['format']==2 else 256),'Catalog checkpoint survivor/retirement bound')
        return value

    def _row(self,row):
        sequence,sid,token,raw,body,chain=row
        guards.require(type(sequence) is int and isinstance(raw,bytes) and isinstance(body,bytes) and len(body)<=MAX_RAW_BYTES,'Malformed catalog row')
        record=decode(raw,MAX_RECORD_BYTES)
        guards.require(canonical(record)==raw and record['id']==sid and record['token']==token,'Catalog index/record differs')
        guards.hex_id(sid,64);guards.hex_id(token,32);guards.hex_id(chain,64)
        guards.require(record['raw_compressed_sha256']==digest(body),'Catalog raw body seal differs')
        return record

    @staticmethod
    def _cached_blob_seal(db,rowid,size,*,deadline=None):
        guards.require(type(size) is int and 0<=size<=MAX_FILE_BYTES,'Catalog cached binlog size differs')
        guards.require(db.execute('SELECT typeof(body) FROM logs WHERE rowid=?',(rowid,)).fetchone()==('blob',),'Catalog cached binlog type differs')
        value=hashlib.sha256();remaining=size
        with db.blobopen('logs','body',rowid,readonly=True) as blob:
            while remaining:
                _check_deadline(deadline);block=blob.read(min(1024*1024,remaining))
                guards.require(block and len(block)<=remaining,'Catalog cached binlog truncated');value.update(block);remaining-=len(block)
            guards.require(blob.read(1)==b'','Catalog cached binlog grew')
        return value.hexdigest()

    def _scan(self,db,head,*,deadline=None,expected_records=None):
        _check_deadline(deadline)
        self._tail(db,head);witness=self._checkpoint_record(db,head);result={};previous=self._seed(head);sequence=0;tokens=set();baseline=[]
        for row in db.execute('SELECT sequence,sid,token,record,body,chain FROM archives ORDER BY sequence'):
            _check_deadline(deadline)
            sequence+=1;guards.require(row[0]==sequence and sequence<=MAX_RECORDS,'Catalog record missing/reordered')
            record=self._row(row);expected=digest(bytes.fromhex(previous)+row[3])
            guards.require(row[5]==expected and row[1] not in result and row[2] not in tokens,'Catalog ordered chain/identity differs')
            guards.require(record['generation']==self.binding['generation'] and record['projection']['source']==self.binding['source'] and
                           record['repository']==self.binding['repository_paths'][record['lane']],'Catalog record scope differs')
            if expected_records is not None:
                guards.require(record==expected_records.get(row[1]),'Durable private target differs from audited source')
                # A second private audit must not retain a second historical
                # object graph while the full source proof is still live.
                record=expected_records[row[1]]
            previous=expected;tokens.add(row[2]);result[row[1]]=record
            if witness and sequence<=witness['survivor_count']:baseline.append(record)
        guards.require(sequence==head['sequence'] and previous==head['chain'],'Catalog head/index differs')
        if witness:self._reconstruct(witness,baseline,deadline=deadline)
        expected={(sid,item['file']):item for sid,record in result.items() for item in record['cached_logs']}
        for rowid,sid,name,size in db.execute('SELECT rowid,sid,name,length(body) FROM logs ORDER BY sid,name'):
            _check_deadline(deadline)
            item=expected.pop((sid,name),None)
            guards.require(item is not None and self._cached_blob_seal(db,rowid,size,deadline=deadline)==item['compressed_sha256'],'Catalog cached binlog seal differs')
        guards.require(not expected,'Catalog cached binlog missing');_check_deadline(deadline);return result

    def entries(self):
        with self.open_reader() as reader:return reader._records

    @contextlib.contextmanager
    def open_reader(self):
        self.ready();stage=CheckpointStage(self,reader=True)
        try:
            head,marker,captured,committed,_=self._copy_checkpoint_image(stage,self._checkpoint_profile(),authority=False)
            guards.require(marker is None and not committed,'Interrupted catalog publication; sealed reader unavailable')
            with stage.catalog._db() as db:records=stage.catalog._scan(db,captured)
        finally:stage.cleanup()
        reader=ArchiveReader(self,head,records)
        try:yield reader
        finally:reader.active=False

    def raw_manifest(self,sid):
        guards.hex_id(sid,64)
        with self.open_reader() as reader:return reader.raw_manifest(sid)

    def binlog_bytes(self,sid,filename):
        guards.hex_id(sid,64);guards.log_number(filename)
        with self.open_reader() as reader:return reader.binlog_bytes(sid,filename)

    def _proof(self,lane,sid,metadata,raw,root):
        from worker import tree_inventory
        guards.require(lane in ('base','binlog') and isinstance(root,(str,pathlib.Path)),'Actual verified archive root required')
        root=safe(root,directory=True);scope=str(self.worker.root/'spool'/(lane+'-payload'))
        native,token,rawsha=native_identity(metadata,sid,scope,self.binding['generation'])
        manifest=decode(raw);guards.require(digest(raw)==rawsha and read_file(root/'manifest.json',MAX_RAW_BYTES)==raw,'Catalog raw manifest differs from actual readback')
        guards.require(type(manifest['format']) is int and manifest['format']==1 and manifest['generation']==self.binding['generation'] and manifest['source']==self.binding['source'],'Catalog manifest source/generation differs')
        guards.require(manifest['kind'] in (('full','hourly','pre-update') if lane=='base' else ('binlog',)),'Catalog archive lane/kind differs')
        guards.hex_id(manifest['code_sha'],40)
        captured=guards.utc(manifest['captured_at']);uploaded=guards.utc(native['time'])
        guards.require(captured<=uploaded<=dt.datetime.now(dt.timezone.utc),'Catalog native capture/upload time differs')
        if lane=='base':guards.require(manifest['stage_app_sha']==self.worker.c['stage_app_sha'],'Catalog stage application differs')
        files=manifest['files'];guards.require(isinstance(files,list) and len(files)<=100000,'Catalog file array bound')
        names=set();size=0
        for item in files:
            name=guards.media_path(item['path']);guards.hex_id(item['sha256'],64)
            guards.require(set(item)=={'path','bytes','sha256'} and name not in names and name!='manifest.json' and type(item['bytes']) is int and 0<=item['bytes']<=MAX_FILE_BYTES,'Catalog file descriptor differs')
            names.add(name);size+=item['bytes']
        guards.require(size<=MAX_ARCHIVE_BYTES,'Catalog verified archive oversized')
        for p in root.rglob('*'):safe(p,directory=p.is_dir())
        actual=tree_inventory(root)
        guards.require([x for x in actual if x['path']!='manifest.json']==files,'Catalog actual all-file readback differs')
        initialization=decode(read_file(self.receipts/('init-'+lane+'.json'),MAX_RECORD_BYTES),MAX_RECORD_BYTES)
        guards.require(initialization['generation']==self.binding['generation'],'Catalog repository initialization generation differs')
        repository_id=guards.hex_id(initialization['repository_id'],64)
        projection={k:v for k,v in manifest.items() if k!='files'};compressed=zlib.compress(raw)
        cached=[];logs={}
        if lane=='binlog':
            import binlog
            descriptors=manifest['logs'];guards.checked_logs(descriptors);guards.require(descriptors,'Catalog empty binlog batch')
            expected_names={'logs/'+item['file'] for item in descriptors}
            if '.capture.json' in names:
                # Worker owns capture and upload with separate UUIDs. The marker
                # is part of the authenticated all-file tree checked above.
                marker=decode(read_file(root/'.capture.json',MAX_RECORD_BYTES),MAX_RECORD_BYTES)
                guards.require(set(marker)=={'generation','lane','token'} and marker['generation']==self.binding['generation'] and
                               marker['lane']==lane,'Catalog capture ownership differs')
                guards.hex_id(marker['token'],32);expected_names.add('.capture.json')
            guards.require(names==expected_names,'Catalog binlog descriptor/file set differs')
            for item in descriptors:
                value=read_file(root/'logs'/item['file'],MAX_FILE_BYTES)
                guards.require(len(value)==item['size'] and digest(value)==item['sha256'],'Catalog actual binlog hash differs')
                logs[item['file']]=value
            binlog.validate_chain(logs,descriptors,{'file':descriptors[0]['file'],'position':4},
                                  {'file':descriptors[-1]['file'],'position':descriptors[-1]['size']})
            for item in descriptors:
                value=zlib.compress(logs[item['file']]);logs[item['file']]=value;cached.append({**item,'compressed_sha256':digest(value)})
        source_files={name:digest(pathlib.Path(__file__).with_name(name).read_bytes()) for name in
                      ('backup_catalog.py','worker.py','restic_adapter.py','runtime.py','guards.py','binlog.py','dump_records.py')}
        record={'id':sid,'lane':lane,'generation':self.binding['generation'],'token':token,'manifest_sha256':rawsha,
                'raw_compressed_sha256':digest(compressed),'repository':self.binding['repository_paths'][lane],
                'repository_id':repository_id,'native':native,'projection':projection,'cached_logs':cached,
                'verified':{'code_sha':self.worker.c['code_sha'],'source_sha256':source_files,
                            'restic':'0.19.1','mariadb':'10.11.19','verified_at':dt.datetime.now(dt.timezone.utc).isoformat(),
                            'file_count':len(actual),'payload_bytes':size,'all_files_sha256':digest(canonical(actual))}}
        guards.require(len(canonical(record))<=MAX_RECORD_BYTES,'Catalog projection oversized');return record,compressed,logs

    @staticmethod
    def _same_proof(old,fresh):
        return {k:v for k,v in old.items() if k!='verified'}=={k:v for k,v in fresh.items() if k!='verified'} and all(
            old['verified'][k]==fresh['verified'][k] for k in ('file_count','payload_bytes','all_files_sha256'))

    def admit(self,lane,sid,native_metadata,raw_manifest,verified_root,*,reconcile=False,deadline=None):
        """Trusted Worker readback only. No booleans/tags/CLI evidence are accepted."""
        try:record,body,logs=self._proof(lane,sid,native_metadata,raw_manifest,verified_root)
        except (KeyError,TypeError,ValueError,AttributeError,OSError,RecursionError) as error:raise guards.GuardError('Invalid actual catalog admission proof') from error
        with _catalog_lock(self.lock,5,deadline,'admission'),self._db(write=True) as db:
            guards.require(not self._checkpoint_incomplete(),'Interrupted catalog checkpoint; explicit native reconciliation required')
            head=self._head()
            if self.pending.exists():
                guards.require(reconcile is True,'Interrupted catalog admission; explicit native reconciliation required')
                pending=decode(read_file(self.pending,MAX_RECORD_BYTES),MAX_RECORD_BYTES)
                guards.require(self._same_proof(pending['record'],record),'Interrupted admission fresh proof differs')
                prior=pending['prior_head'];guards.require(all(prior.get(k)==v for k,v in self.binding.items()),'Interrupted admission binding differs')
                expected=digest(bytes.fromhex(prior['chain'])+canonical(pending['record']))
                committed={**prior,'sequence':prior['sequence']+1,'chain':expected}
                guards.require(head in (prior,committed),'Interrupted admission head differs')
                if head==prior:
                    # An uncommitted record is not rooted in the trust anchor.
                    # Its claimed verifier must match this actual native proof,
                    # including source bytes; no forged upgrade attestation.
                    old=pending['record']['verified'];fresh=record['verified']
                    guards.require({k:v for k,v in old.items() if k!='verified_at'}=={k:v for k,v in fresh.items() if k!='verified_at'} and
                                   guards.utc(record['native']['time'])<=guards.utc(old['verified_at'])<=guards.utc(fresh['verified_at']),
                                   'Uncommitted catalog verifier provenance differs')
                tail=db.execute('SELECT sequence,chain FROM archives ORDER BY sequence DESC LIMIT 1').fetchone() or (0,self._seed(prior))
                if tail==(prior['sequence'],prior['chain']):
                    try:self._insert(db,prior,pending['record'],body,logs,expected)
                    except CatalogCapacityError:
                        self._tail(db,prior);self.pending.unlink();runtime.directory_sync(self.root);raise
                else:
                    guards.require(tail==(committed['sequence'],committed['chain']),'Unknown interrupted admission index')
                self._scan(db,committed)
                runtime.atomic_json(self.head,committed);self.pending.unlink();runtime.directory_sync(self.root)
                return pending['record']
            self._tail(db,head)
            old=db.execute('SELECT sequence,sid,token,record,body,chain FROM archives WHERE sid=?',(sid,)).fetchone()
            if old is not None:
                oldrecord=self._row(old);guards.require(self._same_proof(oldrecord,record),'Previously verified catalog identity changed');return oldrecord
            guards.require(db.execute('SELECT 1 FROM archives WHERE token=?',(record['token'],)).fetchone() is None,'Duplicate catalog upload token')
            growth=len(body)+len(canonical(record))+sum(len(x) for x in logs.values())+65536
            guards.require(head['sequence']<MAX_RECORDS and
                           shutil.disk_usage(self.root).free>=5*1024**3+2*self.database.stat().st_size+growth+MAX_RECORD_BYTES,
                           'Catalog capacity/disk/journal reserve exceeded; no eviction')
            chain=digest(bytes.fromhex(head['chain'])+canonical(record))
            runtime.atomic_json(self.pending,{'prior_head':head,'record':record})
            try:self._insert(db,head,record,body,logs,chain)
            except CatalogCapacityError:
                self._tail(db,head);self.pending.unlink();runtime.directory_sync(self.root);raise
            runtime.atomic_json(self.head,{**head,'sequence':head['sequence']+1,'chain':chain})
            self.pending.unlink();runtime.directory_sync(self.root);return record

    def _insert(self,db,head,record,body,logs,chain):
        try:
            self._allocation_limit(db)
            db.execute('BEGIN IMMEDIATE')
            db.execute('INSERT INTO archives VALUES (?,?,?,?,?,?)',(head['sequence']+1,record['id'],record['token'],canonical(record),body,chain))
            db.executemany('INSERT INTO logs VALUES (?,?,?)',[(record['id'],name,value) for name,value in logs.items()])
            self._allocation_check(db);db.commit()
        except (sqlite3.Error,CatalogCapacityError) as error:
            db.rollback()
            if isinstance(error,CatalogCapacityError) or getattr(error,'sqlite_errorcode',None)==sqlite3.SQLITE_FULL:
                raise CatalogCapacityError('Catalog actual page allocation exceeded; prior commit preserved') from error
            raise
        self._sync_db()

    def _allocation_limit(self,db):
        page=db.execute('PRAGMA page_size').fetchone()[0];pages=db.execute('PRAGMA page_count').fetchone()[0]
        available=shutil.disk_usage(self.root).free-5*1024**3-2*self.database.stat().st_size-MAX_RECORD_BYTES
        if available<0:raise CatalogCapacityError('Catalog rollback journal/temp reserve unavailable')
        maximum=min(MAX_STORE_BYTES//page,pages+available//page)
        guards.require(maximum>0,'Catalog page ceiling below schema')
        actual=db.execute('PRAGMA max_page_count='+str(maximum)).fetchone()[0]
        if actual>maximum:raise CatalogCapacityError('Catalog page allocation already exceeds ceiling')

    def _allocation_check(self,db):
        page=db.execute('PRAGMA page_size').fetchone()[0];pages=db.execute('PRAGMA page_count').fetchone()[0]
        if pages*page>MAX_STORE_BYTES or shutil.disk_usage(self.root).free<5*1024**3:
            raise CatalogCapacityError('Catalog measured allocation/disk reserve exceeded before commit')

    @staticmethod
    def _records_digest(records,*,deadline=None):
        value=hashlib.sha256()
        for record in records:
            _check_deadline(deadline);value.update(bytes.fromhex(record['id']));value.update(bytes.fromhex(digest(canonical(record))))
        _check_deadline(deadline)
        return value.hexdigest()

    def _reconstruct(self,witness,survivors,*,deadline=None):
        """Reconstruct the prior committed compact chain, including retired rows.

        This roots a pending checkpoint in the old independent head even if its
        SQLite transaction committed before the new head. Pending JSON alone is
        never authority to forge a survivor, verifier, or retirement proof.
        """
        prior=witness['prior_head'];retired={item['sequence']:item for item in witness['retired']}
        guards.require(len(retired)==len(witness['retired']) and len(survivors)==witness['survivor_count'] and
                       self._records_digest(survivors,deadline=deadline)==witness['survivors_sha256'] and
                       len(survivors)+len(retired)==prior['sequence'],'Catalog checkpoint reconstructed record set differs')
        previous=self._seed(prior);iterator=iter(survivors);ids=set()
        for sequence in range(1,prior['sequence']+1):
            _check_deadline(deadline)
            if sequence in retired:
                item=retired[sequence];record=item['record'];proof=item['proof']
                guards.require(all(record[key]==proof[key] for key in ('id','lane','token','manifest_sha256','generation')),'Catalog retired proof identity differs')
            else:
                record=next(iterator,None);guards.require(record is not None,'Catalog checkpoint survivor missing')
            guards.require(record['id'] not in ids,'Catalog checkpoint duplicated prior identity');ids.add(record['id'])
            previous=digest(bytes.fromhex(previous)+canonical(record))
        guards.require(previous==prior['chain'],'Catalog checkpoint prior-head reconstruction differs');_check_deadline(deadline)
        if witness.get('format')==2:
            # This is explicitly a derived admitted prefix, not an earlier
            # remote observation. Fresh native authority is publication-only.
            inventory=self._projection_inventory(survivors)
            guards.require(__import__('retention').inventory_digest(inventory)==witness['derived_inventory_sha256'],
                           'Derived checkpoint prefix inventory differs')

    def _retirement_authority(self):
        import retention_native
        w=self.worker
        for lane in ('base','binlog'):
            guards.require(not (self.receipts/lane/'pending.json').exists(),'Pending upload blocks catalog retirement')
        repositories={lane:guards.hex_id(decode(read_file(self.receipts/('init-'+lane+'.json'),MAX_RECORD_BYTES))['repository_id'],64) for lane in ('base','binlog')}
        tombstones=retention_native.verified_tombstones(w)
        directory=self.receipts/'retention-applies'
        if directory.exists():
            for path in sorted(directory.iterdir()):
                safe(path,directory=True);store=retention_native.IntentStore(path);intent=store.load()
                guards.require(intent is not None and (path/'latest.json').exists() and (path/'journals-committed.json').exists(),'Unfinished native effect blocks catalog retirement')
                guards.require(intent['repositories']==repositories and intent['source']==w.source and intent['generation']==self.binding['generation'],
                               'Foreign native retirement repository/source provenance')
                receipt=store.latest();marker=decode(read_file(path/'journals-committed.json',MAX_RECORD_BYTES),MAX_RECORD_BYTES)
                if receipt['result']=='NOOP':guards.require(marker=={'no_deletion':True},'Native no-op commitment differs')
                else:
                    guards.require(receipt['result'] in ('APPLIED','RECONCILED') and receipt['present_candidate_ids']==[],'Unfinished native retirement')
                    retention_native.verify_journal_commit(w,store,receipt=receipt)
        return {row['id']:row for row in tombstones}

    def _projection_inventory(self,records):
        """Expected membership from admitted seals; never a native observation."""
        snapshots=[];manifests={};tokens=set()
        repositories={lane:guards.hex_id(decode(read_file(self.receipts/('init-'+lane+'.json'),MAX_RECORD_BYTES))['repository_id'],64) for lane in ('base','binlog')}
        at=dt.datetime.now(dt.timezone.utc)
        for record in records:
            sid=record['id'];lane=record['lane'];manifest=record['projection']
            native,token,rawsha=native_identity(record['native'],sid,str(self.worker.root/'spool'/(lane+'-payload')),self.binding['generation'])
            guards.require(sid not in manifests and token not in tokens and record['repository_id']==repositories[lane] and record['repository']==self.binding['repository_paths'][lane] and
                           token==record['token'] and rawsha==record['manifest_sha256'] and manifest['source']==self.binding['source'] and record['generation']==self.binding['generation'] and
                           guards.utc(manifest['captured_at'])<=guards.utc(native['time'])<=at,'Derived admitted inventory identity differs')
            tokens.add(token);manifests[sid]=manifest
            snapshots.append({'id':sid,'lane':lane,'token':token,'manifest_sha256':rawsha,'kind':manifest['kind'],
                              'generation':self.binding['generation'],'time':manifest['captured_at'],'snapshot_time':native['time'],'tree':native['tree']})
        return {'generation':self.binding['generation'],'repositories':repositories,'snapshots':snapshots,'manifests':manifests}

    def _derived_checkpoint_evidence(self,records,stage,proofs):
        import retention,retention_apply
        inventory=self._projection_inventory(record for sid,record in records.items() if sid not in proofs)
        journals={lane:decode(read_file(stage.root/('journal-'+lane+'.json'),MAX_RAW_BYTES)) for lane in ('base','binlog')}
        for lane in journals:
            guards.require(file_digest(stage.root/('journal-'+lane+'.json'))==stage.authority[lane+'/state.json'],'Frozen source journal bytes changed')
        retention.confirmed_inventory(inventory,journals,list(proofs.values()))
        if inventory['snapshots']:retention_apply.protected_dependencies(inventory,list(proofs),dt.datetime.now(dt.timezone.utc))
        if any(record['lane']=='binlog' for record in records.values()) and any(row['lane']=='binlog' for row in proofs.values()):
            plan=retention.inventory_plan(inventory,dt.datetime.now(dt.timezone.utc));first=guards.log_number(plan['logs'][0]['file'])
            for sid in proofs:
                record=records.get(sid)
                if record and record['lane']=='binlog':guards.require(record['projection']['last_log']<first,'Retired cache is required by current binlog suffix')
        return inventory

    def _journal_growth(self,prior,current,tail):
        """Exact historical prefix and ordered one-to-one admitted additions."""
        for lane in ('base','binlog'):
            old=decode(read_file(prior.root/('journal-'+lane+'.json'),MAX_RAW_BYTES))
            new=decode(read_file(current.root/('journal-'+lane+'.json'),MAX_RAW_BYTES))
            previous=old['confirmed'];rows=new['confirmed'];extras=rows[len(previous):]
            guards.require(rows[:len(previous)]==previous,'Historical confirmation prefix changed')
            mutable={'confirmed','last_success_at','last_confirmation_at'}
            guards.require({k:v for k,v in old.items() if k not in mutable}=={k:v for k,v in new.items() if k not in mutable},'Historical journal authority changed')
            expected=[record for record in tail if record['lane']==lane]
            guards.require(len(extras)==len(expected),'Journal/source tail count differs')
            for row,record in zip(extras,expected):
                guards.require(all(row[k]==record[k] for k in ('id','token','manifest_sha256')) and row['captured_at']==record['projection']['captured_at'],
                               'Journal/source tail order or identity differs')
                captured=guards.utc(row['captured_at']);prepared=guards.utc(row['prepared_at']);confirmed=guards.utc(row['confirmed_at'])
                guards.require(captured<=prepared<=guards.utc(record['native']['time'])<=confirmed<=dt.datetime.now(dt.timezone.utc),'Journal admission clock differs')
            if extras:
                guards.require(new.get('last_success_at')==extras[-1]['captured_at'] and new.get('last_confirmation_at')==extras[-1]['confirmed_at'],
                               'Journal tail watermarks differ')
            else:guards.require(new==old,'Journal changed without an admitted arrival')

    def _retirement_evidence(self,records,deadline=None):
        import retention,retention_apply,retention_native,restic_adapter
        w=self.worker;at=dt.datetime.now(dt.timezone.utc)
        for lane in ('base','binlog'):
            guards.require(not (self.receipts/lane/'pending.json').exists(),'Pending upload blocks catalog retirement')
            safe(self.receipts/lane,directory=True);safe(self.receipts/lane/'state.json')
        expected_repositories={lane:guards.hex_id(decode(read_file(self.receipts/('init-'+lane+'.json'),MAX_RECORD_BYTES))['repository_id'],64) for lane in ('base','binlog')}
        tombstones=retention_native.verified_tombstones(w)
        directory=self.receipts/'retention-applies'
        if directory.exists():
            for path in sorted(directory.iterdir()):
                safe(path,directory=True);store=retention_native.IntentStore(path);intent=store.load()
                guards.require(intent is not None and (path/'latest.json').exists() and (path/'journals-committed.json').exists(),'Unfinished native effect blocks catalog retirement')
                guards.require(intent['repositories']==expected_repositories and intent['source']==w.source and intent['generation']==self.binding['generation'],
                               'Foreign native retirement repository/source provenance')
                receipt=store.latest();marker=decode(read_file(path/'journals-committed.json',MAX_RECORD_BYTES),MAX_RECORD_BYTES)
                if receipt['result']=='NOOP':guards.require(marker=={'no_deletion':True},'Native no-op commitment differs')
                else:
                    guards.require(receipt['result'] in ('APPLIED','RECONCILED') and receipt['present_candidate_ids']==[],
                                   'Unfinished native retirement')
                    retention_native.verify_journal_commit(w,store,receipt=receipt)
        repositories={};snapshots=[];manifests={};tokens=set()
        for lane in ('base','binlog'):
            init=decode(read_file(self.receipts/('init-'+lane+'.json'),MAX_RECORD_BYTES),MAX_RECORD_BYTES)
            repo=w.c['repositories'][lane]
            def native_read(args):
                if deadline is None:return w.restic(lane,['--repo',repo,*args])
                remaining=deadline-time.monotonic();guards.require(remaining>0,'Checkpoint final native deadline exceeded')
                output=w.restic(lane,['--repo',repo,*args],timeout=remaining)
                guards.require(time.monotonic()<deadline,'Checkpoint final native deadline exceeded');return output
            config=decode(native_read(['cat','config']))
            rid=guards.hex_id(init['repository_id'],64)
            guards.require(init['generation']==self.binding['generation'] and config['version']==2 and config['id']==rid,'Native checkpoint repository changed')
            repositories[lane]=rid;listed=restic_adapter.strict_json(native_read(['snapshots','--json']))
            guards.require(isinstance(listed,list) and len(listed)<=MAX_RECORDS,'Complete bounded native checkpoint inventory required')
            for metadata in listed:
                if deadline is not None:guards.require(time.monotonic()<deadline,'Checkpoint final metadata deadline exceeded')
                sid=guards.hex_id(metadata['id'],64);record=records.get(sid)
                if record is None:raise CheckpointArrival('Unknown native checkpoint arrival')
                guards.require(sid not in manifests,'Duplicate native checkpoint ID')
                native,token,rawsha=native_identity(metadata,sid,str(w.root/'spool'/(lane+'-payload')),self.binding['generation'])
                guards.require(record['native']==native and record['lane']==lane and record['repository_id']==rid and record['manifest_sha256']==rawsha and token not in tokens,
                               'Native checkpoint identity differs');tokens.add(token)
                manifest=record['projection'];guards.require(guards.utc(manifest['captured_at'])<=guards.utc(native['time'])<=at,'Checkpoint native clock differs')
                snapshots.append({'id':sid,'lane':lane,'token':token,'manifest_sha256':rawsha,'kind':manifest['kind'],
                                  'generation':self.binding['generation'],'time':manifest['captured_at'],'snapshot_time':native['time'],'tree':native['tree']})
                manifests[sid]=manifest
        inventory={'generation':self.binding['generation'],'repositories':repositories,'snapshots':snapshots,'manifests':manifests}
        journals={lane:runtime.load_json(safe(self.receipts/lane/'state.json')) for lane in ('base','binlog')}
        retention.confirmed_inventory(inventory,journals,tombstones)
        if snapshots:retention_apply.protected_dependencies(inventory,[row['id'] for row in tombstones],at)
        # A retired cached binlog must be strictly below the actual retained
        # suffix. Reuse the same complete range/base dependency validation.
        if any(record['lane']=='binlog' for record in records.values()) and any(row['lane']=='binlog' for row in tombstones):
            plan=retention.inventory_plan(inventory,at)
            first=guards.log_number(plan['logs'][0]['file'])
            for row in tombstones:
                record=records.get(row['id'])
                if record and record['lane']=='binlog':guards.require(record['projection']['last_log']<first,'Retired cache is required by current binlog suffix')
        return {row['id']:row for row in tombstones},inventory

    def _checkpoint_inputs(self,deadline=None):
        paths=[self.receipts/lane/'state.json' for lane in ('base','binlog')]
        paths += [self.receipts/('init-'+lane+'.json') for lane in ('base','binlog')]
        directory=self.receipts/'retention-applies'
        if directory.exists():
            safe(directory,directory=True)
            for root in sorted(directory.iterdir()):
                guards.hex_id(root.name,64);safe(root,directory=True)
                batch_names=None
                for path in sorted(root.iterdir()):
                    name=path.name
                    if name=='phase-timing.json':safe(path);continue
                    allowed=name in ('intent.json','latest.json','journals-committed.json','phase-base.json','phase-binlog.json','phase-no-op.json')
                    if name in {'phase-'+format(index,'04d')+'.json' for index in range(8)}:
                        if batch_names is None:
                            import retention_native
                            batch_names={'phase-'+key+'.json' for key in retention_native.IntentStore(root).phase_documents()}
                        allowed=name in batch_names
                    if name.startswith('receipt-') and name.endswith('.json'):guards.hex_id(name[8:-5],32);allowed=True
                    guards.require(allowed,'Unknown checkpoint authority file');paths.append(path)
        return {path.relative_to(self.receipts).as_posix():file_digest(path,deadline) for path in paths}

    def _checkpoint_state(self):
        with runtime.lane_lock(self.lock),self._db() as db:
            guards.require(not self.pending.exists(),'Interrupted admission blocks catalog checkpoint')
            head=self._head();raw=read_file(self.checkpoint_pending,MAX_CHECKPOINT_BYTES) if self.checkpoint_pending.exists() else None
            dbhead=head;committed=False
            if raw is not None:
                pending=decode(raw,MAX_CHECKPOINT_BYTES);guards.require(set(pending)=={'witness','next_head'},'Checkpoint pending envelope differs')
                prior=pending['witness']['prior_head'];nexthead=pending['next_head']
                if pending['witness'].get('format')==2:prior=self._derived_bridge(raw)['source_tip']
                guards.require(head in (prior,nexthead),'Interrupted checkpoint head differs')
                exists=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='catalog_checkpoint'").fetchone()
                row=db.execute('SELECT record FROM catalog_checkpoint WHERE slot=1').fetchone() if exists else None
                committed=row is not None and digest(row[0])==nexthead['checkpoint']['sha256']
                dbhead=nexthead if committed else prior
            self._tail(db,dbhead)
            guards.require(all(not pathlib.Path(str(self.database)+suffix).exists() for suffix in ('-journal','-wal','-shm')),'Live SQLite sidecar blocks image publication')
            return head,raw,dbhead,committed

    @staticmethod
    def _pending_bytes(witness,nexthead):
        # Byte contract of runtime.atomic_json, including its final newline.
        return (json.dumps({'witness':witness,'next_head':nexthead},sort_keys=True,separators=(',',':'))+'\n').encode()

    def _derived_bridge(self,raw=None):
        pointer=decode(read_file(self.receipts/'catalog-checkpoint-stage.json',MAX_RECORD_BYTES),MAX_RECORD_BYTES)
        guards.require(set(pointer)=={'token','manifest_sha256','pending_sha256'},'Malformed derived checkpoint pointer')
        token=guards.hex_id(pointer['token'],32);stage=CheckpointStage(self,token)
        guards.require(file_digest(stage.manifest)==pointer['manifest_sha256'],'Derived checkpoint descriptor changed')
        prepared=decode(read_file(stage.manifest,MAX_RAW_BYTES))
        guards.require(prepared['witness'].get('format')==2 and prepared['source']==self.worker.source and
                       prepared['source_head']==prepared['source_tip'] and prepared['already_committed'] is False,
                       'Foreign derived checkpoint source-tip bridge')
        expected=self._pending_bytes(prepared['witness'],prepared['next_head'])
        guards.require(digest(expected)==pointer['pending_sha256'] and (raw is None or raw==expected),'Derived fixed pending differs')
        return prepared

    def _completed_stage_cleanup(self,value,roots):
        """Recover cleanup after activation, including a partly removed stage.

        The surviving pointer seals the exact witness and committed target
        head. Prove all live bytes against that head before deleting only the
        known temporary paths; a pointer alone never proves completion.
        """
        if self.pending.exists() or self.checkpoint_pending.exists():return
        head=self._head()
        with self._db() as db:witness=self._checkpoint_record(db,head)
        if witness is None or digest(self._pending_bytes(witness,head))!=value['pending_sha256']:return
        token=guards.hex_id(value['token'],32)
        guards.require({path.name for path in roots}<={token},'Unknown preparation blocks completed cleanup')
        before=file_digest(self.database)
        with self._db() as db:self._scan(db,head)
        guards.require(self._head()==head and file_digest(self.database)==before,'Completed live catalog changed during cleanup proof')
        root=self.receipts/'catalog-preparations'/token;paths=[]
        if root.exists():
            safe(root,directory=True)
            guards.require({path.name for path in root.iterdir()}<={'catalog','head.json','preparation.json','journal-base.json','journal-binlog.json'},'Unknown completed preparation layout')
            image=root/'catalog'
            if image.exists():
                safe(image,directory=True);guards.require({path.name for path in image.iterdir()}<={'index.sqlite3'},'Unknown completed catalog layout')
                if (image/'index.sqlite3').exists():guards.require(file_digest(image/'index.sqlite3')==before,'Completed staging image differs from live authority')
            manifest=root/'preparation.json'
            if manifest.exists():guards.require(file_digest(manifest)==value['manifest_sha256'],'Completed stage descriptor changed')
            if (root/'head.json').exists():guards.require(decode(read_file(root/'head.json',MAX_RECORD_BYTES))==head,'Completed stage head changed')
            paths=[path for path in (manifest,root/'head.json',image/'index.sqlite3',root/'journal-base.json',root/'journal-binlog.json') if path.exists()]
            for path in paths:safe(path)
            for path in paths:path.unlink()
            if image.exists():image.rmdir()
            root.rmdir();runtime.directory_sync(root.parent)
        (self.receipts/'catalog-checkpoint-stage.json').unlink();runtime.directory_sync(self.receipts)
        return {'witness':witness,'next_head':head}

    def _checkpoint_stage_reference(self,reconcile):
        pointer=self.receipts/'catalog-checkpoint-stage.json'
        parent=self.receipts/'catalog-preparations'
        roots=list(parent.iterdir()) if parent.exists() else []
        for root in roots:guards.hex_id(root.name,32);safe(root,directory=True)
        if not pointer.exists():
            guards.require(not roots,'Unreferenced preparation requires protected investigation')
            return
        guards.require(reconcile,'Existing stage requires explicit pending reconciliation')
        value=decode(read_file(pointer,MAX_RECORD_BYTES),MAX_RECORD_BYTES)
        guards.require(set(value)=={'token','manifest_sha256','pending_sha256'},'Malformed stage integrity reference')
        completed=self._completed_stage_cleanup(value,roots)
        if completed:return None,completed
        token=guards.hex_id(value['token'],32);root=safe(self.receipts/'catalog-preparations'/token,directory=True)
        guards.require({path.name for path in roots}=={token},'Unknown/orphan preparation blocks reconciliation')
        guards.require({p.name for p in root.iterdir()} in ({'catalog','head.json','preparation.json'},{'catalog','head.json','preparation.json','journal-base.json','journal-binlog.json'}) and
                       {p.name for p in safe(root/'catalog',directory=True).iterdir()}<= {'index.sqlite3'},'Unknown preparation layout')
        path=root/'preparation.json';guards.require(file_digest(path)==value['manifest_sha256'],'Stage descriptor changed')
        prepared=decode(read_file(path,MAX_RAW_BYTES));image=root/'catalog/index.sqlite3'
        if prepared['witness'].get('format')==2:
            raw=read_file(self.checkpoint_pending,MAX_CHECKPOINT_BYTES) if self.checkpoint_pending.exists() else None
            guards.require(self._derived_bridge(raw)==prepared,'Derived checkpoint bridge differs')
            head,marker,dbhead,committed=self._checkpoint_state()
            guards.require(self._checkpoint_inputs()==prepared['authority'],'Recovery authority set/bytes changed')
            if image.exists():guards.require(file_digest(image)==prepared['stage_sha256'],'Prepared image corrupted')
            activated=file_digest(self.database)==prepared['stage_sha256'] and head in (prepared['source_tip'],prepared['next_head']) and (committed or head==prepared['next_head'])
            if not image.exists():guards.require(activated,'Prepared image lost before confirmed live activation')
            if not activated:
                guards.require(head==prepared['source_tip'] and file_digest(self.database)==prepared['source_sha256'],'Unpublished source tip changed; investigate preserved stage')
            prepared={**prepared,'manifest_sha256':value['manifest_sha256'],'pending_sha256':digest(raw) if raw is not None else None,
                      'source_head':head,'source_sha256':file_digest(self.database),'already_committed':activated}
            return CheckpointStage(self,token),prepared
        guards.require(self.checkpoint_pending.exists() and file_digest(self.checkpoint_pending)==value['pending_sha256'],'Legacy fixed pending changed')
        guards.require(prepared['pending_sha256'] in (None,value['pending_sha256']) and prepared['source']==self.worker.source,
                       'Foreign stage reference')
        guards.require(decode(read_file(self.checkpoint_pending,MAX_CHECKPOINT_BYTES),MAX_CHECKPOINT_BYTES)==
                       {'witness':prepared['witness'],'next_head':prepared['next_head']},'Prepared fixed witness differs')
        head,marker,dbhead,committed=self._checkpoint_state()
        if image.exists():guards.require(file_digest(image)==prepared['stage_sha256'],'Prepared image corrupted')
        else:guards.require(committed and file_digest(self.database)==prepared['stage_sha256'],'Prepared image lost before confirmed live activation')
        guards.require(self._checkpoint_inputs()==prepared['authority'],'Recovery authority set/bytes changed')
        if image.exists() and head==prepared['source_head'] and file_digest(self.database)==prepared['source_sha256']:
            prepared['manifest_sha256']=value['manifest_sha256'];prepared['pending_sha256']=value['pending_sha256']
            guards.require(committed==prepared['already_committed'],'Recovery disposition changed')
            return CheckpointStage(self,token),prepared
        return CheckpointStage(self,token),None

    def _revalidate_checkpoint_stage(self,stage,prepared,profile):
        if prepared['witness'].get('format')==2:return self._revalidate_derived_stage(stage,prepared,profile)
        records=self._checkpoint_records(stage,prepared['next_head'],profile)
        self._reconstruct(prepared['witness'],list(records.values()))
        proofs,inventory=self._retirement_evidence(records)
        guards.require(__import__('retention').inventory_digest(inventory)==prepared['native_sha256'] and
                       all(proofs.get(item['record']['id'])==item['proof'] for item in prepared['witness']['retired']),
                       'Recovered stage native/provenance changed')
        indexed={row['id']:row for row in inventory['snapshots']}
        compact={sid:{'native_sha256':digest(canonical(record['native'])),'snapshot':indexed[sid]} for sid,record in records.items()}
        guards.require(compact==prepared['compact'],'Recovered stage compact bindings changed')
        return prepared

    def _revalidate_derived_stage(self,stage,prepared,profile):
        if not stage.catalog.database.exists():
            guards.require(prepared['already_committed'],'Prepared source image missing')
            self._copy_checkpoint_image(stage,profile)
            guards.require(file_digest(stage.catalog.database)==prepared['stage_sha256'],'Recovered committed image differs')
        stage.authority=prepared['authority'];records=self._checkpoint_records(stage,prepared['next_head'],profile)
        witness=prepared['witness'];values=list(records.values());baseline=values[:witness['survivor_count']]
        self._reconstruct(witness,baseline)
        chain=witness['prior_head']['chain']
        for record in values[witness['survivor_count']:]:chain=digest(bytes.fromhex(chain)+canonical(record))
        reconstructed={**witness['prior_head'],'sequence':witness['prior_head']['sequence']+len(values)-witness['survivor_count'],'chain':chain}
        guards.require(reconstructed==prepared['source_tip'],'Recovered source-to-target tail bridge differs')
        proofs=self._retirement_authority()
        guards.require(all(proofs.get(item['record']['id'])==item['proof'] for item in witness['retired']),'Recovered fixed retirement authority differs')
        inventory=self._derived_checkpoint_evidence(records,stage,proofs)
        indexed={row['id']:row for row in inventory['snapshots']}
        compact={sid:{'native_sha256':digest(canonical(record['native'])),'snapshot':indexed[sid]} for sid,record in records.items()}
        guards.require(compact==prepared['compact'] and __import__('retention').inventory_digest(inventory)==prepared['native_sha256'],
                       'Recovered derived target membership differs')
        return prepared

    @staticmethod
    def _copy_stat(value):
        return (value.st_dev,value.st_ino,value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)

    def _raw_checkpoint_copy(self,stage,identity,profile):
        """One ordinary protected FD, no source SQLite read-lock interval."""
        seal=hashlib.sha256();remaining=identity[3]
        sourcefd=os.open(safe(self.database),os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
        with os.fdopen(sourcefd,'rb') as source:
            fd_identity=self._copy_stat(os.fstat(source.fileno()))
            # Windows path/fd ctime representations differ. Bind path ctime
            # and fd ctime independently; all other identity fields join.
            guards.require(fd_identity[:-1]==identity[:-1],'Copy source FD identity changed')
            targetfd=os.open(stage.catalog.database,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
            with os.fdopen(targetfd,'wb') as target:
                while remaining:
                    chunk=time.monotonic();block=source.read(min(1024*1024,remaining))
                    guards.require(block and len(block)<=min(1024*1024,remaining),'Copy source size changed')
                    target.write(block);seal.update(block);remaining-=len(block)
                    interval=time.monotonic()-chunk
                    profile['copy_step_interval_upper_max_seconds']=max(profile['copy_step_interval_upper_max_seconds'],interval)
                    profile['copy_chunk_max_seconds']=max(profile['copy_chunk_max_seconds'],interval)
                extra=len(source.read(1))
                target.flush();os.fsync(target.fileno())
            fd_after=self._copy_stat(os.fstat(source.fileno()));path_after=self._copy_stat(safe(self.database).stat())
        os.chmod(stage.catalog.database,0o600);runtime.directory_sync(stage.catalog.root)
        # Return measured identity observations together with stream SHA. A
        # source drift cannot hide independent target corruption before retry.
        return {'sha256':seal.hexdigest(),'fd_before':fd_identity,'fd_after':fd_after,'path_after':path_after,'extra_bytes':extra}

    def _copy_checkpoint_image(self,stage,profile,*,authority=True):
        journals={'base/state.json','binlog/state.json'}
        inputs_now=lambda:self._checkpoint_inputs() if authority else {}
        for attempt in range(4):
            head,marker,dbhead,committed=self._checkpoint_state();inputs=inputs_now();identity=self._copy_stat(safe(self.database).stat())
            guards.require(identity[3]<=MAX_STORE_BYTES and shutil.disk_usage(self.root).free>=5*1024**3+2*identity[3]+MAX_CHECKPOINT_BYTES+MAX_RECORD_BYTES,
                           'Private source/image/journal reserve unavailable')
            profile['copy_attempts']=attempt+1
            copied=None
            try:
                hashed=time.monotonic()
                try:before=file_digest(self.database)
                finally:profile['copy_hash_seconds']+=time.monotonic()-hashed
                copying=time.monotonic()
                try:copied=self._raw_checkpoint_copy(stage,identity,profile)
                finally:profile['copy_seconds']+=time.monotonic()-copying
                hashed=time.monotonic()
                try:
                    try:staged=file_digest(stage.catalog.database)
                    except guards.GuardError as error:raise CheckpointCopyCorrupt('Owned copied image readback failed') from error
                    if staged!=copied['sha256']:raise CheckpointCopyCorrupt('Owned copied bytes differ from fsynced readback')
                    after=file_digest(self.database)
                finally:profile['copy_hash_seconds']+=time.monotonic()-hashed
                current,current_marker,current_dbhead,current_committed=self._checkpoint_state()
                guards.require(before==copied['sha256']==staged==after and copied['fd_before']==copied['fd_after'] and copied['path_after']==identity and copied['extra_bytes']==0 and
                               self._copy_stat(safe(self.database).stat())==identity and
                               (current,current_marker,current_dbhead,current_committed)==(head,marker,dbhead,committed) and inputs_now()==inputs,
                               'Initial source/image byte seals or fixed state changed')
            except CheckpointCopyCorrupt:raise
            except guards.GuardError:
                if stage.catalog.database.exists():
                    if copied is None:raise CheckpointCopyCorrupt('Unsealed target cannot authorize source-drift retry')
                    try:staged=file_digest(stage.catalog.database)
                    except guards.GuardError as error:raise CheckpointCopyCorrupt('Retry target readback failed') from error
                    if staged!=copied['sha256']:raise CheckpointCopyCorrupt('Retry target differs from measured stream')
                guards.require(self._copy_stat(safe(self.database).stat())[:3]==identity[:3],
                               'Source device/inode/link replacement is not admitted append drift')
                current,current_marker,_,_=self._checkpoint_state();now=inputs_now()
                guards.require(marker is None and current_marker is None and current.get('checkpoint')==head.get('checkpoint') and current['sequence']>head['sequence'] and
                               {k:v for k,v in now.items() if k not in journals}=={k:v for k,v in inputs.items() if k not in journals},
                               'Copy drift lacks unchanged authenticated admitted prefix')
                with runtime.lane_lock(self.lock),self._db() as source:
                    anchor=source.execute('SELECT chain FROM archives WHERE sequence=?',(head['sequence'],)).fetchone()
                    guards.require((anchor[0] if anchor else self._seed(head))==head['chain'],'Copy drift changed original protected prefix')
                guards.require(attempt<3,'Minute arrivals outran bounded initial byte copy')
                stage.check_layout()
                if stage.catalog.database.exists():safe(stage.catalog.database).unlink()
                continue
            runtime.atomic_json(stage.catalog.head,dbhead);stage.catalog._sync_db()
            if authority:
                for lane in ('base','binlog'):
                    raw=read_file(self.receipts/lane/'state.json',MAX_RAW_BYTES)
                    guards.require(digest(raw)==inputs[lane+'/state.json'],'Journal advanced beyond captured source boundary')
                    target=stage.root/('journal-'+lane+'.json')
                    with target.open('wb') as output:output.write(raw);output.flush();os.fsync(output.fileno())
                    os.chmod(target,0o600)
                guards.require(inputs_now()==inputs and self._checkpoint_state()==(head,marker,dbhead,committed),'Source/journal boundary changed')
                runtime.directory_sync(stage.root)
            stage.authority=inputs
            return head,marker,dbhead,committed,after

    def _checkpoint_records(self,stage,head,profile):
        started=time.monotonic()
        with stage.catalog._db() as db:records=stage.catalog._scan(db,head)
        profile['full_scan_seconds']+=time.monotonic()-started
        return records

    def _raw_prefix_seals(self,db,head,boundary):
        """Exact logical byte equality to a previously audited private image.

        SQLite may rewrite old pages on append. Hash typed, length-framed
        columns and every cached blob instead of trusting page or head identity.
        No JSON parsing or second historic object graph is needed. Both seals
        come from one bounded-memory pass; unknown schema/orphan rows are bound
        or rejected, and empty/missing/extra values cannot alias each other.
        """
        guards.require(type(boundary) is int and 0<=boundary<=head['sequence'],'Raw prefix boundary differs')
        self._tail(db,head);whole=hashlib.sha256();prefix=hashlib.sha256()
        def field(seal,value):
            if value is None:tag=b'n';raw=b''
            elif type(value) is int:tag=b'i';raw=str(value).encode()
            elif isinstance(value,str):tag=b's';raw=value.encode()
            else:guards.require(isinstance(value,bytes),'Raw prefix SQLite value type differs');tag=b'b';raw=value
            seal.update(tag);seal.update(len(raw).to_bytes(8,'big'));seal.update(raw)
        def row(values,in_prefix=True):
            for value in values:
                field(whole,value)
                if in_prefix:field(prefix,value)
        row(('catalog-raw-prefix-v1',))
        for values in db.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name'):row(('schema',*values))
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='catalog_checkpoint'").fetchone():
            for values in db.execute('SELECT slot,record FROM catalog_checkpoint ORDER BY slot'):row(('checkpoint',*values))
        sequence=0
        for values in db.execute('SELECT sequence,sid,token,record,body,chain FROM archives ORDER BY sequence'):
            sequence+=1;guards.require(values[0]==sequence,'Raw prefix archive order/membership differs')
            row(('archive',*values),sequence<=boundary)
        guards.require(sequence==head['sequence'],'Raw prefix archive count differs')
        counts=[0,0]
        query='''SELECT a.sequence,l.rowid,l.sid,l.name,typeof(l.body),length(l.body),
                 CASE WHEN length(l.body)<=1048576 THEN l.body ELSE NULL END
                 FROM logs l LEFT JOIN archives a ON a.sid=l.sid ORDER BY a.sequence,l.name'''
        for seq,rowid,sid,name,kind,size,body in db.execute(query):
            guards.require(type(seq) is int and 1<=seq<=sequence and kind=='blob' and type(size) is int and 0<=size<=MAX_FILE_BYTES,
                           'Raw prefix cached membership/type differs')
            seal=digest(body) if body is not None else self._cached_blob_seal(db,rowid,size)
            row(('cached',seq,sid,name,size,seal),seq<=boundary);counts[1]+=1
            if seq<=boundary:counts[0]+=1
        for seal,count,logs in ((prefix,boundary,counts[0]),(whole,sequence,counts[1])):
            for value in ('end',count,logs):field(seal,value)
        return prefix.hexdigest(),whole.hexdigest()

    def _private_tail_records(self,db,captured,current,known):
        """Semantic audit of only newly admitted rows and all their blobs."""
        self._tail(db,current);sequence=captured['sequence'];chain=captured['chain'];result={};tokens={record['token'] for record in known.values()}
        for row in db.execute('SELECT sequence,sid,token,record,body,chain FROM archives WHERE sequence>? ORDER BY sequence',(sequence,)):
            sequence+=1;record=self._row(row);chain=digest(bytes.fromhex(chain)+row[3])
            guards.require(row[0]==sequence and row[5]==chain and row[1] not in known and row[1] not in result and row[2] not in tokens,'Private source tail chain/identity differs')
            guards.require(record['generation']==self.binding['generation'] and record['projection']['source']==self.binding['source'] and
                           record['repository']==self.binding['repository_paths'][record['lane']],'Private source tail scope differs')
            expected={item['file']:item for item in record['cached_logs']}
            for rowid,name,size in db.execute('SELECT rowid,name,length(body) FROM logs WHERE sid=?',(row[1],)):
                item=expected.pop(name,None)
                guards.require(item is not None and self._cached_blob_seal(db,rowid,size)==item['compressed_sha256'],'Private source tail cached seal differs')
            guards.require(not expected,'Private source tail cached member missing');result[row[1]]=record;tokens.add(row[2])
        guards.require(sequence==current['sequence'] and chain==current['chain'],'Private source tail head differs');return result

    def _checkpoint_append(self,stage,captured,current,retired,records,profile):
        guards.require(current.get('checkpoint')==captured.get('checkpoint') and current['sequence']>=captured['sequence'],'Checkpoint append epoch/prefix changed')
        previous=captured['chain'];started=time.monotonic()
        # One admitted record per source transaction. No source cursor or
        # catalog lock spans the full copy/reseal/scan.
        for sequence in range(captured['sequence']+1,current['sequence']+1):
            with runtime.lane_lock(self.lock),self._db() as source:
                anchor=source.execute('SELECT chain FROM archives WHERE sequence=?',(sequence-1,)).fetchone()
                guards.require((anchor[0] if anchor else self._seed(current))==previous,'Captured source prefix changed')
                row=source.execute('SELECT sequence,sid,token,record,body,chain FROM archives WHERE sequence=?',(sequence,)).fetchone()
                guards.require(row is not None,'Checkpoint append missing');record=self._row(row)
                guards.require(row[5]==digest(bytes.fromhex(previous)+row[3]),'Checkpoint appended chain differs')
                logs=dict(source.execute('SELECT name,length(body) FROM logs WHERE sid=?',(row[1],)))
            guards.require(record['generation']==self.binding['generation'] and record['projection']['source']==self.binding['source'] and
                           record['repository']==self.binding['repository_paths'][record['lane']],'Foreign checkpoint append')
            expected={item['file']:item for item in record['cached_logs']}
            guards.require(set(logs)==set(expected) and all(type(size) is int and 0<=size<=MAX_FILE_BYTES for size in logs.values()),'Checkpoint append cached membership/size differs')
            with stage.catalog._db(write=True) as target:
                stage.catalog._allocation_limit(target);target.execute('BEGIN IMMEDIATE')
                target.execute('INSERT INTO archives VALUES (?,?,?,?,?,?)',(sequence-len(retired),record['id'],record['token'],row[3],row[4],row[5]))
                for name,size in logs.items():
                    target.execute('INSERT INTO logs VALUES (?,?,zeroblob(?))',(record['id'],name,size))
                    blobid=target.execute('SELECT rowid FROM logs WHERE sid=? AND name=?',(record['id'],name)).fetchone()[0];seal=hashlib.sha256()
                    with target.blobopen('logs','body',blobid) as blob:
                        for offset in range(0,size,1024*1024):
                            # A source read transaction/catalog lock covers one
                            # bounded chunk, never the entire admitted archive.
                            with runtime.lane_lock(self.lock),self._db() as source:
                                block=source.execute('SELECT substr(body,?,?) FROM logs WHERE sid=? AND name=?',(offset+1,min(1024*1024,size-offset),record['id'],name)).fetchone()
                            guards.require(block is not None and isinstance(block[0],bytes) and len(block[0])==min(1024*1024,size-offset),'Checkpoint append blob changed/missing')
                            seal.update(block[0]);blob.write(block[0])
                    guards.require(seal.hexdigest()==expected[name]['compressed_sha256'],'Checkpoint append cached seal differs')
                stage.catalog._allocation_check(target);target.commit()
            guards.require(record['id'] not in records,'Duplicate appended staged identity');records[record['id']]=record
            previous=row[5];del logs,row
        guards.require(previous==current['chain'],'Checkpoint append final head differs')
        profile['catchup_seconds']+=time.monotonic()-started

    def _checkpoint_source_seal(self,records,retired,head):
        """Prove the entire admitted source, in short per-row/chunk reads.

        A changed raw DB cannot be excused solely by a legitimate appended
        head: every historic body/record/blob must still match the private
        sealed graph. No live read cursor/transaction spans this full pass.
        """
        before=file_digest(self.database);_,_,dbhead,committed=self._checkpoint_state()
        accepted=dbhead if committed else head
        removed={item['sequence']:item['record'] for item in retired};iterator=iter(records.values());previous=self._seed(accepted);log_count=0
        guards.require(len(records)+len(removed)==accepted['sequence'] and len(removed)==len(retired),'Accepted source membership differs')
        for sequence in range(1,accepted['sequence']+1):
            record=removed.get(sequence) or next(iterator);sid=record['id']
            with runtime.lane_lock(self.lock),self._db() as source:
                row=source.execute('SELECT sequence,sid,token,record,body,chain FROM archives WHERE sequence=?',(sequence,)).fetchone()
                guards.require(row is not None and row[0]==sequence and row[1]==sid and self._row(row)==record,'Historic source sequence/record/body changed during append')
                previous=digest(bytes.fromhex(previous)+row[3]);guards.require(row[5]==previous,'Historic source chain changed during append')
                logs=dict(source.execute('SELECT name,length(body) FROM logs WHERE sid=?',(sid,)))
            seals={item['file']:item['compressed_sha256'] for item in record['cached_logs']}
            guards.require(set(logs)==set(seals),'Historic source cached set changed');log_count+=len(seals)
            for name,size in logs.items():
                guards.require(type(size) is int and 0<=size<=MAX_FILE_BYTES,'Historic source cached size differs');seal=hashlib.sha256()
                for offset in range(0,size,1024*1024):
                    with runtime.lane_lock(self.lock),self._db() as source:
                        block=source.execute('SELECT substr(body,?,?) FROM logs WHERE sid=? AND name=?',(offset+1,min(1024*1024,size-offset),sid,name)).fetchone()
                    guards.require(block is not None and isinstance(block[0],bytes) and len(block[0])==min(1024*1024,size-offset),'Historic source cached body missing')
                    seal.update(block[0])
                guards.require(seal.hexdigest()==seals[name],'Historic source cached body changed')
        del iterator
        guards.require(previous==accepted['chain'],'Accepted complete source head chain differs')
        current,_,current_dbhead,_=self._checkpoint_state()
        with runtime.lane_lock(self.lock),self._db() as source:
            guards.require(source.execute('SELECT COUNT(*) FROM archives').fetchone()[0]==current_dbhead['sequence'] and
                           source.execute('SELECT 1 FROM logs LEFT JOIN archives ON archives.sid=logs.sid WHERE archives.sid IS NULL LIMIT 1').fetchone() is None,
                           'Unknown source archive/cached membership')
            if current==head:guards.require(source.execute('SELECT COUNT(*) FROM logs').fetchone()[0]==log_count,'Unknown complete source cached membership')
        after=file_digest(self.database)
        if current==head:guards.require(before==after,'Source bytes changed during complete accepted prefix verification')
        return current,after

    def _reseal_checkpoint_stage(self,stage,head,marker,records,frozen,profile):
        started=time.monotonic();inputs=self._checkpoint_inputs()
        proofs,inventory=self._retirement_evidence(records)
        native_sha=__import__('retention').inventory_digest(inventory)
        if marker is not None:
            pending=decode(marker,MAX_CHECKPOINT_BYTES);witness=pending['witness'];nexthead=pending['next_head']
            retired=witness['retired'];ids={item['record']['id'] for item in retired}
            survivors=[record for record in records.values() if record['id'] not in ids]
            self._reconstruct(witness,survivors)
            guards.require(self._checkpoint_head(witness,survivors)==nexthead and native_sha==witness['native_inventory_sha256'] and
                           all(proofs.get(item['record']['id'])==item['proof'] for item in retired),'Legacy pending exact authority differs')
        else:
            if frozen is None:
                retired=[]
                for sequence,record in enumerate(records.values(),1):
                    if record['id'] not in proofs:continue
                    item={'sequence':sequence,'record':record,'proof':proofs[record['id']]}
                    if len(canonical(retired+[item]))>MAX_CHECKPOINT_BYTES//2 or len(retired)==256:break
                    retired.append(item)
            else:retired=frozen
            ids={item['record']['id'] for item in retired};survivors=[record for record in records.values() if record['id'] not in ids]
            guards.require(all(proofs.get(item['record']['id'])==item['proof'] for item in retired),'Frozen checkpoint retirement proof changed')
            if not retired:return None
            witness={'format':1,'operation':'native-verified-catalog-checkpoint','prior_head':head,'epoch':head.get('checkpoint',{}).get('epoch',0)+1,
                     'retired':retired,'survivor_count':len(survivors),'survivors_sha256':self._records_digest(survivors),'native_inventory_sha256':native_sha}
            witness['lineage_sha256']=digest(bytes.fromhex(head.get('checkpoint',{}).get('lineage_sha256',ZERO))+canonical(witness))
            nexthead=self._checkpoint_head(witness,survivors)
        guards.require(len(retired)<=256 and len(records)<=MAX_RECORDS,'Checkpoint image membership exceeds limits')
        compact={}
        indexed={row['id']:row for row in inventory['snapshots']}
        for record in survivors:
            row=indexed.get(record['id']);guards.require(row is not None,'Staged survivor is not current native identity')
            compact[record['id']]={'native_sha256':digest(canonical(record['native'])),'snapshot':row}
        with stage.catalog._db(write=True) as db:self._checkpoint_insert(db,witness,survivors,nexthead,catalog=stage.catalog)
        runtime.atomic_json(stage.catalog.head,nexthead)
        after=self._checkpoint_inputs();journals={'base/state.json','binlog/state.json'}
        guards.require({k:v for k,v in after.items() if k not in journals}=={k:v for k,v in inputs.items() if k not in journals},
                       'Retirement/init authority changed during private reseal')
        profile['reseal_seconds']+=time.monotonic()-started
        return {'witness':witness,'next_head':nexthead,'compact':compact,'authority':inputs,'native_sha256':native_sha}

    def _prepare_checkpoint_stage(self,stage,reconcile,profile):
        # Already published legacy uncertainty keeps its exact historical
        # protocol. New attempts never invent an initial native observation.
        if self.checkpoint_pending.exists():return self._prepare_legacy_checkpoint_stage(stage,reconcile,profile)
        head,marker,captured,committed,source_sha=self._copy_checkpoint_image(stage,profile)
        guards.require(marker is None and not committed,'New derived checkpoint requires a complete source')
        records=self._checkpoint_records(stage,captured,profile)
        with stage.catalog._db() as db:_,source_raw=stage.catalog._raw_prefix_seals(db,captured,captured['sequence'])
        guards.require(file_digest(stage.catalog.database)==source_sha,'Audited source image changed before prefix seal')
        proofs=self._retirement_authority()
        inventory=self._derived_checkpoint_evidence(records,stage,proofs);retired=[];retired_bytes=2
        for sequence,(sid,record) in enumerate(records.items(),1):
            if sid not in proofs:continue
            item={'sequence':sequence,'record':record,'proof':proofs[sid]}
            item_bytes=len(canonical(item))+(1 if retired else 0)
            if len(retired)==MAX_CHECKPOINT_RETIREMENTS or retired_bytes+item_bytes>MAX_CHECKPOINT_BYTES//2:break
            retired.append(item);retired_bytes+=item_bytes
        if not retired:return None
        ids={item['record']['id'] for item in retired};survivors=[record for sid,record in records.items() if sid not in ids]
        guards.require(all(record['id'] in inventory['manifests'] for record in survivors),'Unselected absence exceeds bounded checkpoint')
        witness={'format':2,'operation':'derived-prefix-catalog-checkpoint','prior_head':captured,'epoch':captured.get('checkpoint',{}).get('epoch',0)+1,
                 'retired':retired,'survivor_count':len(survivors),'survivors_sha256':self._records_digest(survivors),
                 'derived_inventory_sha256':__import__('retention').inventory_digest(inventory)}
        witness['lineage_sha256']=digest(bytes.fromhex(captured.get('checkpoint',{}).get('lineage_sha256',ZERO))+canonical(witness))
        nexthead=self._checkpoint_head(witness,survivors);started=time.monotonic()
        with stage.catalog._db(write=True) as db:self._checkpoint_insert(db,witness,survivors,nexthead,catalog=stage.catalog)
        runtime.atomic_json(stage.catalog.head,nexthead);profile['reseal_seconds']+=time.monotonic()-started
        del records,survivors,inventory
        # Verify the resealed baseline once. Subsequent logical byte equality
        # transfers this audit; only new rows need semantic revalidation.
        target_sha=file_digest(stage.catalog.database)
        records=self._checkpoint_records(stage,nexthead,profile)
        with stage.catalog._db() as db:_,target_raw=stage.catalog._raw_prefix_seals(db,nexthead,nexthead['sequence'])
        prepared=self._derived_prepared(stage,witness,nexthead,records,captured,source_sha,proofs)
        guards.require(prepared['stage_sha256']==target_sha,'Audited target changed before prefix seal')
        folds=0
        while True:
            current,current_marker,dbhead,current_committed=self._checkpoint_state()
            guards.require(current_marker is None and not current_committed,'Pending changed during derived preparation')
            if current==captured:
                guards.require(file_digest(stage.catalog.database)==prepared['stage_sha256'],'Prepared target changed after its authenticated audit')
                prepared.update(authority=stage.authority,source_head=captured,source_sha256=source_sha)
                runtime.atomic_json(stage.manifest,prepared);prepared['manifest_sha256']=file_digest(stage.manifest)
                try:self._reserve_checkpoint_stage(stage,prepared)
                except CheckpointArrival:continue
                return prepared
            # Activation checks do not adopt data. In particular, a writer
            # finishing during group acquisition must not spend a second
            # fold merely to return to this already verified private image.
            guards.require(folds<4,'Minute arrivals outran bounded private tail adoption; live catalog unchanged')
            folds+=1
            guards.require(current.get('checkpoint')==captured.get('checkpoint') and current['sequence']>captured['sequence'],'Source epoch or prefix changed')
            audit=CheckpointStage(self,reader=True)
            try:
                newhead,newmarker,_,newcommitted,newsha=self._copy_checkpoint_image(audit,profile)
                guards.require(newmarker is None and not newcommitted and newhead.get('checkpoint')==captured.get('checkpoint') and newhead['sequence']>captured['sequence'],
                               'Source snapshot is not an ordinary admitted tail')
                journals={'base/state.json','binlog/state.json'}
                guards.require({k:v for k,v in stage.authority.items() if k not in journals}=={k:v for k,v in audit.authority.items() if k not in journals},
                               'Retirement/init authority changed during derived preparation')
                started=time.monotonic()
                with audit.catalog._db() as db:
                    prefix,new_source_raw=audit.catalog._raw_prefix_seals(db,newhead,captured['sequence'])
                    guards.require(prefix==source_raw,'Authenticated raw source prefix changed')
                    anchor=db.execute('SELECT chain FROM archives WHERE sequence=?',(captured['sequence'],)).fetchone()
                    guards.require((anchor[0] if anchor else self._seed(captured))==captured['chain'],'Private source historical prefix changed')
                    known={**records,**{item['record']['id']:item['record'] for item in retired}}
                    tail=audit.catalog._private_tail_records(db,captured,newhead,known);del known
                guards.require(file_digest(audit.catalog.database)==newsha,'Audited private source bytes changed')
                profile['source_seal_seconds']+=time.monotonic()-started
                self._journal_growth(stage,audit,list(tail.values()));records.update(tail)
                # Validate dependencies against this source's frozen journal,
                # never against a newer live confirmation observed mid-audit.
                inventory=self._derived_checkpoint_evidence(records,audit,proofs);del inventory
                guards.require(file_digest(stage.catalog.database)==prepared['stage_sha256'],'Prepared target changed before tail append')
                prior_target=nexthead
                nexthead=self._append_private_tail(stage,audit,captured,newhead,prior_target,len(retired),profile)
                target_sha=file_digest(stage.catalog.database)
                # Historical logical bytes must remain exactly equal after
                # SQLite rewrites pages. Newly durable rows retain full checks.
                started=time.monotonic()
                with stage.catalog._db() as db:
                    prefix,new_target_raw=stage.catalog._raw_prefix_seals(db,nexthead,prior_target['sequence'])
                    guards.require(prefix==target_raw,'Authenticated raw target prefix changed')
                    prior_records={sid:record for sid,record in records.items() if sid not in tail}
                    guards.require(stage.catalog._private_tail_records(db,prior_target,nexthead,prior_records)==tail,'Durable private target differs from audited source');del prior_records
                profile['source_seal_seconds']+=time.monotonic()-started
                captured=newhead;source_sha=newsha;source_raw=new_source_raw;target_raw=new_target_raw
                prepared=self._derived_prepared(stage,witness,nexthead,records,captured,source_sha,proofs)
                guards.require(prepared['stage_sha256']==target_sha,'Audited target changed during tail validation');del tail
                for lane in ('base','binlog'):
                    target=stage.root/('journal-'+lane+'.json');source=audit.root/target.name
                    os.replace(safe(source),target)
                runtime.directory_sync(stage.root);stage.authority=audit.authority
            finally:audit.cleanup()
    def _derived_prepared(self,stage,witness,nexthead,records,source_head,source_sha,proofs):
        inventory=self._projection_inventory(record for sid,record in records.items() if sid not in proofs)
        indexed={row['id']:row for row in inventory['snapshots']}
        compact={sid:{'native_sha256':digest(canonical(record['native'])),'snapshot':indexed[sid]} for sid,record in records.items() if sid not in proofs}
        return {'witness':witness,'next_head':nexthead,'compact':compact,'native_sha256':__import__('retention').inventory_digest(inventory),
                'source_tip':source_head,'source_head':source_head,'source_sha256':source_sha,'pending_sha256':None,
                'stage_sha256':file_digest(stage.catalog.database),'authority':stage.authority,
                'source':self.worker.source,'code_sha':self.worker.c['code_sha'],'already_committed':False}

    def _append_private_tail(self,stage,audit,captured,current,target_head,retired_count,profile):
        started=time.monotonic();chain=target_head['chain'];sequence=target_head['sequence']
        guards.require(sequence==captured['sequence']-retired_count,'Source/target tail offset differs')
        with audit.catalog._db() as source,stage.catalog._db(write=True) as target:
            stage.catalog._tail(target,target_head)
            for row in source.execute('SELECT sequence,sid,token,record,body,chain FROM archives WHERE sequence>? ORDER BY sequence',(captured['sequence'],)):
                record=audit.catalog._row(row);sequence+=1;chain=digest(bytes.fromhex(chain)+row[3])
                guards.require(sequence==row[0]-retired_count,'Private tail reordered')
                stage.catalog._allocation_limit(target)
                try:
                    target.execute('BEGIN IMMEDIATE');target.execute('INSERT INTO archives VALUES (?,?,?,?,?,?)',(sequence,row[1],row[2],row[3],row[4],chain))
                    for item in record['cached_logs']:
                        name=item['file'];size=source.execute('SELECT length(body) FROM logs WHERE sid=? AND name=?',(row[1],name)).fetchone()[0]
                        guards.require(type(size) is int and 0<=size<=MAX_FILE_BYTES,'Private tail cached size differs')
                        target.execute('INSERT INTO logs VALUES (?,?,zeroblob(?))',(row[1],name,size))
                        blobid=target.execute('SELECT rowid FROM logs WHERE sid=? AND name=?',(row[1],name)).fetchone()[0];seal=hashlib.sha256()
                        with target.blobopen('logs','body',blobid) as blob:
                            for offset in range(0,size,1024*1024):
                                block=source.execute('SELECT substr(body,?,?) FROM logs WHERE sid=? AND name=?',(offset+1,min(1024*1024,size-offset),row[1],name)).fetchone()[0]
                                guards.require(isinstance(block,bytes) and len(block)==min(1024*1024,size-offset),'Private tail cached bytes missing')
                                seal.update(block);blob.write(block)
                        guards.require(seal.hexdigest()==item['compressed_sha256'],'Private tail cached seal differs')
                    stage.catalog._allocation_check(target);target.commit()
                except (sqlite3.Error,guards.GuardError):target.rollback();raise
                stored=target.execute('SELECT sequence,sid,token,record,body,chain FROM archives WHERE sequence=?',(sequence,)).fetchone()
                guards.require(stored==(sequence,row[1],row[2],row[3],row[4],chain),'Private tail durable row differs')
            guards.require(sequence==current['sequence']-retired_count,'Private tail count differs')
        nexthead={**target_head,'sequence':sequence,'chain':chain};stage.catalog._sync_db()
        # Read the newly durable target bytes, not just the source that was
        # copied. The historical baseline already has its own complete seal.
        previous=target_head['chain'];verified=target_head['sequence']
        with stage.catalog._db() as target:
            for row in target.execute('SELECT sequence,sid,token,record,body,chain FROM archives WHERE sequence>? ORDER BY sequence',(verified,)):
                record=stage.catalog._row(row);verified+=1;previous=digest(bytes.fromhex(previous)+row[3])
                guards.require(row[0]==verified and row[5]==previous,'Durable private tail chain differs')
                expected={item['file']:item for item in record['cached_logs']}
                for rowid,name,size in target.execute('SELECT rowid,name,length(body) FROM logs WHERE sid=?',(row[1],)):
                    item=expected.pop(name,None)
                    guards.require(item is not None and self._cached_blob_seal(target,rowid,size)==item['compressed_sha256'],'Durable private tail cached seal differs')
                guards.require(not expected,'Durable private tail cached member missing')
        guards.require(verified==nexthead['sequence'] and previous==nexthead['chain'],'Durable private target tip differs')
        runtime.atomic_json(stage.catalog.head,nexthead)
        profile['catchup_seconds']+=time.monotonic()-started;return nexthead

    def _prepare_legacy_checkpoint_stage(self,stage,reconcile,profile):
        head,marker,captured,committed,source_sha=self._copy_checkpoint_image(stage,profile)
        guards.require(marker is None or reconcile,'Existing checkpoint requires explicit read-only reconciliation')
        records=self._checkpoint_records(stage,captured,profile);frozen=None;retired=[]
        for turn in range(4):
            current,current_marker,dbhead,current_committed=self._checkpoint_state()
            guards.require(current_marker==marker,'Pending changed during preparation')
            if marker is None and current!=captured:
                self._checkpoint_append(stage,captured,current,retired,records,profile);captured=current
            # A compact overlay restores original retired rows without copying
            # payload/manifest graphs; the staged DB itself keeps only survivors.
            original={}
            iterator=iter(records.values());removed={item['sequence']:item['record'] for item in retired}
            for sequence in range(1,captured['sequence']+1):original[sequence]=removed.get(sequence) or next(iterator)
            ordered={record['id']:record for record in original.values()};del original,iterator
            inputs=self._checkpoint_inputs()
            try:prepared=self._reseal_checkpoint_stage(stage,captured,marker,ordered,frozen,profile)
            except CheckpointArrival:
                new_head,new_marker,_,_=self._checkpoint_state();after=self._checkpoint_inputs();journals={'base/state.json','binlog/state.json'}
                guards.require(marker is None and new_marker is None and new_head.get('checkpoint')==captured.get('checkpoint') and new_head['sequence']>captured['sequence'] and
                               {k:v for k,v in after.items() if k not in journals}=={k:v for k,v in inputs.items() if k not in journals},
                               'Unknown native arrival lacks unchanged authenticated admission prefix')
                del ordered
                continue
            del ordered,records
            if prepared is None:return None
            records=self._checkpoint_records(stage,prepared['next_head'],profile)
            retired=prepared['witness']['retired'];frozen=retired
            sealing=time.monotonic();new_head,new_sha=self._checkpoint_source_seal(records,[] if committed else retired,current)
            profile['source_seal_seconds']+=time.monotonic()-sealing
            observed,new_marker,new_dbhead,new_committed=self._checkpoint_state()
            guards.require(observed==new_head,'Source advanced during final preparation seal')
            if new_head==current and new_marker==marker:
                # The accepted snapshot must not conceal same-head content drift.
                if current==head:guards.require(new_sha==source_sha,'Source content changed with unchanged independent head')
                guards.require(self._checkpoint_inputs()==prepared['authority'],'Prepared authority drifted')
                stage.catalog._sync_db();stage_sha=file_digest(stage.catalog.database)
                value={**prepared,'source_head':new_head,'source_sha256':new_sha,'pending_sha256':digest(marker) if marker is not None else None,
                       'stage_sha256':stage_sha,'source':self.worker.source,'code_sha':self.worker.c['code_sha'],'already_committed':new_committed}
                profile['authority_bytes']=sum(safe(self.receipts/path).stat().st_size for path in prepared['authority'])
                profile['authority_files']=len(prepared['authority'])
                runtime.atomic_json(stage.manifest,value);value['manifest_sha256']=file_digest(stage.manifest)
                del records
                return value
            guards.require(marker is None and new_marker is None,'Fixed pending cannot absorb a new arrival')
            head=current;source_sha=new_sha
        raise guards.GuardError('Minute arrivals outran bounded stage catch-up; live catalog unchanged')

    def _final_checkpoint_native(self,prepared,deadline):
        import retention,restic_adapter
        at=dt.datetime.now(dt.timezone.utc);snapshots=[];tokens=set();seen=set();repositories={}
        for lane in ('base','binlog'):
            repo=self.worker.c['repositories'][lane]
            def read(args):
                _check_deadline(deadline);result=self.worker.restic(lane,['--repo',repo,*args],timeout=deadline-time.monotonic());_check_deadline(deadline);return result
            config=decode(read(['cat','config']));init=decode(read_file(self.receipts/('init-'+lane+'.json'),MAX_RECORD_BYTES))
            guards.require(config['version']==2 and config['id']==init['repository_id'] and init['generation']==self.binding['generation'],'Final staged repository differs')
            repositories[lane]=config['id'];listed=restic_adapter.strict_json(read(['snapshots','--json']))
            guards.require(isinstance(listed,list) and len(listed)<=MAX_RECORDS,'Complete native staged authority required')
            for metadata in listed:
                _check_deadline(deadline);sid=guards.hex_id(metadata['id'],64);item=prepared['compact'].get(sid)
                guards.require(item is not None and sid not in seen,'Unknown final arrival or duplicate native ID')
                native,token,rawsha=native_identity(metadata,sid,str(self.worker.root/'spool'/(lane+'-payload')),self.binding['generation'])
                row=item['snapshot']
                guards.require(row['lane']==lane and token==row['token'] and rawsha==row['manifest_sha256'] and digest(canonical(native))==item['native_sha256'] and
                               guards.utc(row['time'])<=guards.utc(native['time'])<=at and token not in tokens,'Final native staged identity differs')
                tokens.add(token);seen.add(sid);snapshots.append(row)
            del listed
        guards.require(seen==set(prepared['compact']) and retention.inventory_digest({'generation':self.binding['generation'],'repositories':repositories,'snapshots':snapshots})==prepared['native_sha256'],
                       'Final complete native set differs from checked dependencies')

    def _reserve_checkpoint_stage(self,stage,prepared):
        """Reserve final activation, or return to the existing private tail.

        A writer may finish while the group is acquired. Detect its new head
        before native observation or any publication, release the whole group,
        and preserve the already verified image for another bounded tail fold.
        """
        import retention_cohort
        stack=contextlib.ExitStack();started=time.monotonic()
        try:
            acquired=stack.enter_context(retention_cohort.upload_section(self.worker,extra_locks=(self.lock,)))
            if acquired is not None:started=acquired
            guards.require(not self._incomplete(),'Interrupted catalog blocks activation reservation')
            current=self._head()
            with self._db() as db:self._tail(db,current)
            if current!=prepared['source_head']:
                guards.require(current.get('checkpoint')==prepared['source_head'].get('checkpoint') and current['sequence']>prepared['source_head']['sequence'],
                               'Source epoch/prefix changed while acquiring activation')
                raise CheckpointArrival('Admitted arrival while acquiring activation')
            stage.activation=stack;stage.activation_started=started
        except BaseException:stack.close();raise

    @contextlib.contextmanager
    def _checkpoint_activation(self,stage):
        import retention_cohort
        if getattr(stage,'activation',None) is not None:
            try:yield stage.activation_started
            finally:stage.release_activation()
        else:
            started=time.monotonic()
            with retention_cohort.upload_section(self.worker,extra_locks=(self.lock,)) as acquired:
                yield acquired if acquired is not None else started

    def _publish_checkpoint_stage(self,stage,prepared,profile):
        import retention_cohort
        started=None;oldfd=None
        try:
            with self._checkpoint_activation(stage) as started:
                work=started+45;hard=started+retention_cohort.MAX_CRITICAL_SECONDS
                retention_cohort.ready_uploads(self.worker);self._layout()
                stage.check_layout(sealed=True)
                guards.require(not self.pending.exists() and self._head()==prepared['source_head'] and self.worker.source==prepared['source'],'Source/head changed before image activation')
                guards.require(self.worker.c['code_sha']==prepared['code_sha'] and self.worker.c['generation']==self.binding['generation'] and
                               self.worker.c['repositories']==self.binding['repository_paths'],'Prepared code/generation/repositories changed')
                raw=read_file(self.checkpoint_pending,MAX_CHECKPOINT_BYTES) if self.checkpoint_pending.exists() else None
                guards.require((digest(raw) if raw is not None else None)==prepared['pending_sha256'],'Exact pending changed')
                for suffix in ('-journal','-wal','-shm'):
                    guards.require(not pathlib.Path(str(self.database)+suffix).exists() and not pathlib.Path(str(stage.catalog.database)+suffix).exists(),'SQLite handle/sidecar publication unfinished')
                hashed=time.monotonic()
                guards.require(file_digest(self.database,work)==prepared['source_sha256'] and file_digest(stage.catalog.database,work)==prepared['stage_sha256'] and
                               file_digest(stage.manifest,work)==prepared['manifest_sha256'],'Source/stage raw bytes changed')
                guards.require(self._checkpoint_inputs(work)==prepared['authority'],'Complete retirement authority set/bytes changed')
                profile['hash_seconds']+=time.monotonic()-hashed
                native=time.monotonic();self._final_checkpoint_native(prepared,work);profile['final_native_seconds']+=time.monotonic()-native
                guards.require(shutil.disk_usage(self.root).free>=5*1024**3+2*max(self.database.stat().st_size,stage.catalog.database.stat().st_size)+MAX_CHECKPOINT_BYTES+MAX_RECORD_BYTES,
                               'Final staged image/journal reserve exceeded')
                stage.check_layout(sealed=True)
                _check_deadline(work);promotion=time.monotonic()
                if os.name=='posix':oldfd=os.open(safe(self.database),os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
                if prepared['witness'].get('format')==2:
                    # The authenticated source-tip bridge must survive even a
                    # crash immediately after pending publication.
                    runtime.atomic_json(self.receipts/'catalog-checkpoint-stage.json',{'token':stage.root.name,'manifest_sha256':prepared['manifest_sha256'],
                                        'pending_sha256':digest(self._pending_bytes(prepared['witness'],prepared['next_head']))})
                    _check_deadline(hard)
                    if raw is None:runtime.atomic_json(self.checkpoint_pending,{'witness':prepared['witness'],'next_head':prepared['next_head']})
                else:
                    if raw is None:runtime.atomic_json(self.checkpoint_pending,{'witness':prepared['witness'],'next_head':prepared['next_head']})
                    _check_deadline(hard)
                    runtime.atomic_json(self.receipts/'catalog-checkpoint-stage.json',{'token':stage.root.name,'manifest_sha256':prepared['manifest_sha256'],
                                        'pending_sha256':file_digest(self.checkpoint_pending,hard)})
                if not prepared['already_committed']:
                    guards.require(self.database.stat().st_dev==stage.catalog.database.stat().st_dev,'Cross-filesystem image replacement prohibited')
                    os.replace(safe(stage.catalog.database),self.database);runtime.directory_sync(self.root)
                _check_deadline(hard);runtime.atomic_json(self.head,prepared['next_head']);_check_deadline(hard)
                self.checkpoint_pending.unlink();runtime.directory_sync(self.root);_check_deadline(hard)
        finally:
            if 'promotion' in locals():profile['promotion_seconds']+=time.monotonic()-promotion
            elapsed=time.monotonic()-started if started is not None else 0;profile['critical_seconds']=elapsed;profile['critical_max_seconds']=elapsed
            # Retaining only a plain POSIX fd defers large inode cleanup; no
            # SQLite connection is held at activation. Windows holds no fd.
            cleanup=time.monotonic()
            if oldfd is not None:os.close(oldfd)
            profile['outside_cleanup_seconds']+=time.monotonic()-cleanup
            self.last_checkpoint_timing=dict(profile)
            guards.require(elapsed<=retention_cohort.MAX_CRITICAL_SECONDS,'Actual catalog checkpoint continuous lock limit exceeded')

    @staticmethod
    def _checkpoint_profile():
        return {key:0.0 for key in ('copy_seconds','copy_hash_seconds','copy_step_interval_upper_max_seconds','copy_chunk_max_seconds','copy_attempts','catchup_seconds','reseal_seconds','full_scan_seconds','source_seal_seconds','hash_seconds','final_native_seconds','promotion_seconds','outside_cleanup_seconds','critical_seconds','critical_max_seconds','authority_bytes','authority_files')}

    def checkpoint(self,*,reconcile=False):
        profile=self._checkpoint_profile()
        stage=None;prior_stage=None;published=False
        with runtime.lane_lock(self.receipts/'retention-apply.lock'):
            try:
                recovered=self._checkpoint_stage_reference(reconcile)
                if recovered:
                    stage,prepared=recovered
                    if stage is None:
                        return {'retired_ids':sorted(item['record']['id'] for item in prepared['witness']['retired']),'head':prepared['next_head'],'phase_seconds':dict(profile)}
                    if prepared is None:
                        prior_stage=stage;stage=CheckpointStage(self);prepared=self._prepare_checkpoint_stage(stage,reconcile,profile)
                    else:prepared=self._revalidate_checkpoint_stage(stage,prepared,profile)
                else:
                    stage=CheckpointStage(self);prepared=self._prepare_checkpoint_stage(stage,reconcile,profile)
                if prepared is None:return {'retired_ids':[],'head':self._head(),'phase_seconds':profile}
                profile['authority_bytes']=sum(safe(self.receipts/path).stat().st_size for path in prepared['authority'])
                profile['authority_files']=len(prepared['authority'])
                self._publish_checkpoint_stage(stage,prepared,profile)
                published=True
                result={'retired_ids':sorted(item['record']['id'] for item in prepared['witness']['retired']),'head':prepared['next_head']}
            finally:
                # A pending attempt keeps every owned artifact for explicit
                # read-only recovery. Never reset/clear an uncertain checkpoint.
                if stage is not None:stage.release_activation()
                pointer=self.receipts/'catalog-checkpoint-stage.json'
                referenced=False
                if pointer.exists():
                    value=decode(read_file(pointer,MAX_RECORD_BYTES),MAX_RECORD_BYTES);referenced=stage is not None and value.get('token')==stage.root.name
                if stage is not None and (not referenced or published and not self.checkpoint_pending.exists()):
                    started=time.monotonic();stage.cleanup();profile['outside_cleanup_seconds']+=time.monotonic()-started
                    if referenced:pointer.unlink();runtime.directory_sync(self.receipts)
                if prior_stage is not None and (not pointer.exists() or runtime.load_json(pointer)['token']!=prior_stage.root.name):
                    started=time.monotonic();prior_stage.cleanup();profile['outside_cleanup_seconds']+=time.monotonic()-started
                self.last_checkpoint_timing=dict(profile)
        return {**result,'phase_seconds':dict(profile)}

    def _checkpoint_head(self,witness,survivors,*,deadline=None):
        seed=digest(canonical(witness));chain=seed
        for record in survivors:_check_deadline(deadline);chain=digest(bytes.fromhex(chain)+canonical(record))
        _check_deadline(deadline)
        return {**self.binding,'sequence':len(survivors),'chain':chain,
                'checkpoint':{'epoch':witness['epoch'],'sha256':seed,'lineage_sha256':witness['lineage_sha256']}}

    def _checkpoint_insert(self,db,witness,survivors,nexthead,*,deadline=None,catalog=None):
        target=catalog or self
        try:
            _check_deadline(deadline)
            target._allocation_limit(db);db.execute('BEGIN IMMEDIATE')
            for item in witness['retired']:
                _check_deadline(deadline)
                sid=item['record']['id'];db.execute('DELETE FROM logs WHERE sid=?',(sid,));db.execute('DELETE FROM archives WHERE sid=?',(sid,))
            db.execute('UPDATE archives SET sequence=-sequence')
            chain=self._seed(nexthead)
            for sequence,record in enumerate(survivors,1):
                _check_deadline(deadline);chain=digest(bytes.fromhex(chain)+canonical(record));_check_deadline(deadline)
                db.execute('UPDATE archives SET sequence=?,chain=? WHERE sid=?',(sequence,chain,record['id']))
            _check_deadline(deadline)
            db.execute('CREATE TABLE IF NOT EXISTS catalog_checkpoint (slot INTEGER PRIMARY KEY CHECK(slot=1), record BLOB NOT NULL)')
            db.execute('INSERT OR REPLACE INTO catalog_checkpoint VALUES(1,?)',(canonical(witness),))
            target._allocation_check(db);_check_deadline(deadline);db.commit();_check_deadline(deadline)
        except (sqlite3.Error,guards.GuardError) as error:
            db.rollback()
            if isinstance(error,CatalogCapacityError) or getattr(error,'sqlite_errorcode',None)==sqlite3.SQLITE_FULL:
                raise CatalogCapacityError('Catalog checkpoint allocation refused; prior sealed data preserved') from error
            raise
        _check_deadline(deadline);target._sync_db();_check_deadline(deadline)
