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
import zlib

import guards
import runtime

MAX_RAW_BYTES=64*1024**2
MAX_RECORD_BYTES=2*1024**2
MAX_CHECKPOINT_BYTES=8*1024**2
MAX_FILE_BYTES=256*1024**2
MAX_ARCHIVE_BYTES=1024**3
MAX_STORE_BYTES=10*1024**3
MAX_RECORDS=100000
ZERO='0'*64

class CatalogCapacityError(guards.GuardError):
    """Transaction was rolled back; prior committed data remains authoritative."""

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

def digest(value):return hashlib.sha256(value).hexdigest()

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

class ArchiveReader:
    """Frozen verified records, short per-blob reads; no long-lived write lock.

    A new append does not change the captured set. Every accessed blob is checked
    against this reader's already sealed digest, including after concurrent append.
    Native live inventory must still be rechecked before any retention effect.
    """
    def __init__(self,catalog,head,records):
        self.catalog=catalog;self.head=copy.deepcopy(head);self._records=records;self.active=True
    def entries(self):
        guards.require(self.active,'Catalog reader closed');return copy.deepcopy(self._records)
    def _record(self,sid):
        guards.require(self.active,'Catalog reader closed');guards.hex_id(sid,64)
        record=self._records.get(sid);guards.require(record is not None,'Snapshot outside sealed catalog reader');return record
    def raw_manifest(self,sid):
        record=self._record(sid)
        with runtime.lane_lock(self.catalog.lock),self.catalog._db() as db:
            row=db.execute('SELECT body FROM archives WHERE sid=?',(sid,)).fetchone()
            guards.require(row is not None and isinstance(row[0],bytes) and digest(row[0])==record['raw_compressed_sha256'],'Sealed reader raw body differs')
            raw=inflate(row[0],MAX_RAW_BYTES);guards.require(digest(raw)==record['manifest_sha256'],'Sealed reader original manifest differs');return raw
    def binlog_bytes(self,sid,filename):
        record=self._record(sid);guards.log_number(filename)
        item=next((x for x in record['cached_logs'] if x['file']==filename),None)
        guards.require(record['lane']=='binlog' and item is not None,'Sealed reader binlog descriptor missing')
        with runtime.lane_lock(self.catalog.lock),self.catalog._db() as db:
            row=db.execute('SELECT body FROM logs WHERE sid=? AND name=?',(sid,filename)).fetchone()
            guards.require(row is not None and isinstance(row[0],bytes) and len(row[0])<=MAX_FILE_BYTES and digest(row[0])==item['compressed_sha256'],'Sealed reader binlog body differs')
            raw=inflate(row[0],MAX_FILE_BYTES)
            guards.require(len(raw)==item['size'] and digest(raw)==item['sha256'],'Sealed reader binlog hash differs');return raw

class ArchiveCatalog:
    def __init__(self,worker):
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
        with runtime.lane_lock(self.lock):
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

    def _incomplete(self):return self.pending.exists() or self.checkpoint_pending.exists()

    def ready(self):
        """Bounded pre-upload readiness; never scan historic file arrays/blobs."""
        with runtime.lane_lock(self.lock),self._db() as db:
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
        prior=value['prior_head'];guards.require(all(prior.get(k)==v for k,v in self.binding.items()),'Catalog checkpoint prior source differs')
        guards.require(value['epoch']==proof['epoch']==prior.get('checkpoint',{}).get('epoch',0)+1 and
                       value['lineage_sha256']==proof['lineage_sha256']==digest(bytes.fromhex(prior.get('checkpoint',{}).get('lineage_sha256',ZERO))+canonical({k:v for k,v in value.items() if k!='lineage_sha256'})),
                       'Catalog checkpoint prior-head lineage differs')
        guards.require(type(value['survivor_count']) is int and 0<=value['survivor_count']<=head['sequence'] and
                       isinstance(value['retired'],list) and 0<len(value['retired'])<=256,'Catalog checkpoint survivor/retirement bound')
        return value

    def _row(self,row):
        sequence,sid,token,raw,body,chain=row
        guards.require(type(sequence) is int and isinstance(raw,bytes) and isinstance(body,bytes) and len(body)<=MAX_RAW_BYTES,'Malformed catalog row')
        record=decode(raw,MAX_RECORD_BYTES)
        guards.require(canonical(record)==raw and record['id']==sid and record['token']==token,'Catalog index/record differs')
        guards.hex_id(sid,64);guards.hex_id(token,32);guards.hex_id(chain,64)
        guards.require(record['raw_compressed_sha256']==digest(body),'Catalog raw body seal differs')
        return record

    def _scan(self,db,head):
        self._tail(db,head);witness=self._checkpoint_record(db,head);result={};previous=self._seed(head);sequence=0;tokens=set();baseline=[]
        for row in db.execute('SELECT sequence,sid,token,record,body,chain FROM archives ORDER BY sequence'):
            sequence+=1;guards.require(row[0]==sequence and sequence<=MAX_RECORDS,'Catalog record missing/reordered')
            record=self._row(row);expected=digest(bytes.fromhex(previous)+row[3])
            guards.require(row[5]==expected and row[1] not in result and row[2] not in tokens,'Catalog ordered chain/identity differs')
            guards.require(record['generation']==self.binding['generation'] and record['projection']['source']==self.binding['source'] and
                           record['repository']==self.binding['repository_paths'][record['lane']],'Catalog record scope differs')
            previous=expected;tokens.add(row[2]);result[row[1]]=record
            if witness and sequence<=witness['survivor_count']:baseline.append(record)
        guards.require(sequence==head['sequence'] and previous==head['chain'],'Catalog head/index differs')
        if witness:self._reconstruct(witness,baseline)
        expected={(sid,item['file']):item for sid,record in result.items() for item in record['cached_logs']}
        for sid,name,body in db.execute('SELECT sid,name,body FROM logs ORDER BY sid,name'):
            item=expected.pop((sid,name),None)
            guards.require(item is not None and isinstance(body,bytes) and len(body)<=MAX_FILE_BYTES and digest(body)==item['compressed_sha256'],'Catalog cached binlog seal differs')
        guards.require(not expected,'Catalog cached binlog missing');return result

    def entries(self):
        with runtime.lane_lock(self.lock),self._db() as db:
            guards.require(not self._incomplete(),'Interrupted catalog publication; explicit native reconciliation required')
            return self._scan(db,self._head())

    @contextlib.contextmanager
    def open_reader(self):
        with runtime.lane_lock(self.lock),self._db() as db:
            guards.require(not self._incomplete(),'Interrupted catalog publication; sealed reader unavailable')
            head=self._head();records=self._scan(db,head)
        reader=ArchiveReader(self,head,records)
        try:yield reader
        finally:reader.active=False

    def raw_manifest(self,sid):
        guards.hex_id(sid,64)
        with runtime.lane_lock(self.lock),self._db() as db:
            guards.require(not self._incomplete(),'Interrupted catalog publication')
            records=self._scan(db,self._head());guards.require(sid in records,'Catalog manifest missing')
            body=db.execute('SELECT body FROM archives WHERE sid=?',(sid,)).fetchone()[0]
            raw=inflate(body,MAX_RAW_BYTES);guards.require(digest(raw)==records[sid]['manifest_sha256'],'Catalog original manifest digest differs')
            return raw

    def binlog_bytes(self,sid,filename):
        guards.hex_id(sid,64);guards.log_number(filename)
        with runtime.lane_lock(self.lock),self._db() as db:
            guards.require(not self._incomplete(),'Interrupted catalog publication')
            records=self._scan(db,self._head());record=records.get(sid)
            guards.require(record is not None and record['lane']=='binlog','Catalog binlog archive missing')
            item=next((x for x in record['cached_logs'] if x['file']==filename),None)
            guards.require(item is not None,'Catalog binlog descriptor missing')
            row=db.execute('SELECT body FROM logs WHERE sid=? AND name=?',(sid,filename)).fetchone()
            guards.require(row is not None,'Catalog binlog bytes missing')
            raw=inflate(row[0],MAX_FILE_BYTES)
            guards.require(len(raw)==item['size'] and digest(raw)==item['sha256'],'Catalog cached binlog hash differs');return raw

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
            guards.require(names=={'logs/'+item['file'] for item in descriptors},'Catalog binlog descriptor/file set differs')
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

    def admit(self,lane,sid,native_metadata,raw_manifest,verified_root,*,reconcile=False):
        """Trusted Worker readback only. No booleans/tags/CLI evidence are accepted."""
        try:record,body,logs=self._proof(lane,sid,native_metadata,raw_manifest,verified_root)
        except (KeyError,TypeError,ValueError,AttributeError,OSError,RecursionError) as error:raise guards.GuardError('Invalid actual catalog admission proof') from error
        with runtime.lane_lock(self.lock),self._db(write=True) as db:
            guards.require(not self.checkpoint_pending.exists(),'Interrupted catalog checkpoint; explicit native reconciliation required')
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
    def _records_digest(records):
        value=hashlib.sha256()
        for record in records:value.update(bytes.fromhex(record['id']));value.update(bytes.fromhex(digest(canonical(record))))
        return value.hexdigest()

    def _reconstruct(self,witness,survivors):
        """Reconstruct the prior committed compact chain, including retired rows.

        This roots a pending checkpoint in the old independent head even if its
        SQLite transaction committed before the new head. Pending JSON alone is
        never authority to forge a survivor, verifier, or retirement proof.
        """
        prior=witness['prior_head'];retired={item['sequence']:item for item in witness['retired']}
        guards.require(len(retired)==len(witness['retired']) and len(survivors)==witness['survivor_count'] and
                       self._records_digest(survivors)==witness['survivors_sha256'] and
                       len(survivors)+len(retired)==prior['sequence'],'Catalog checkpoint reconstructed record set differs')
        previous=self._seed(prior);iterator=iter(survivors);ids=set()
        for sequence in range(1,prior['sequence']+1):
            if sequence in retired:
                item=retired[sequence];record=item['record'];proof=item['proof']
                guards.require(all(record[key]==proof[key] for key in ('id','lane','token','manifest_sha256','generation')),'Catalog retired proof identity differs')
            else:
                record=next(iterator,None);guards.require(record is not None,'Catalog checkpoint survivor missing')
            guards.require(record['id'] not in ids,'Catalog checkpoint duplicated prior identity');ids.add(record['id'])
            previous=digest(bytes.fromhex(previous)+canonical(record))
        guards.require(previous==prior['chain'],'Catalog checkpoint prior-head reconstruction differs')

    def _retirement_evidence(self,records):
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
                    guards.require(receipt['result'] in ('APPLIED','RECONCILED') and receipt['present_candidate_ids']==[] and
                                   marker=={'intent_sha256':intent['intent_sha256'],'receipt_sha256':retention_apply.document_digest(receipt)},
                                   'Unfinished or uncommitted native retirement')
        repositories={};snapshots=[];manifests={};tokens=set()
        for lane in ('base','binlog'):
            init=decode(read_file(self.receipts/('init-'+lane+'.json'),MAX_RECORD_BYTES),MAX_RECORD_BYTES)
            repo=w.c['repositories'][lane];config=decode(w.restic(lane,['--repo',repo,'cat','config']))
            rid=guards.hex_id(init['repository_id'],64)
            guards.require(init['generation']==self.binding['generation'] and config['version']==2 and config['id']==rid,'Native checkpoint repository changed')
            repositories[lane]=rid;listed=restic_adapter.strict_json(w.restic(lane,['--repo',repo,'snapshots','--json']))
            guards.require(isinstance(listed,list) and len(listed)<=MAX_RECORDS,'Complete bounded native checkpoint inventory required')
            for metadata in listed:
                sid=guards.hex_id(metadata['id'],64);record=records.get(sid)
                guards.require(record is not None and sid not in manifests,'Unknown native checkpoint arrival or duplicate ID')
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

    def checkpoint(self,*,reconcile=False):
        """Reclaim at most256 exact proven native absences; no caller IDs or flags.

        Invoke after native retirement and BOTH journals are committed, outside
        caller-held lane/retention locks. This method takes those lane locks,
        loads fixed protected intent/receipt/journal evidence and authenticates
        unfiltered live native metadata itself. It never calls native forget.
        SQLite freed pages are reused: count/bytes bound the rolling active set,
        not lifetime uploads. The last witness plus cumulative lineage is sealed.
        """
        with runtime.lane_lock(self.receipts/'base'/'lane.lock'),runtime.lane_lock(self.receipts/'binlog'/'lane.lock'),runtime.lane_lock(self.lock),self._db(write=True) as db:
            guards.require(not self.pending.exists(),'Interrupted admission blocks catalog checkpoint');head=self._head()
            if self.checkpoint_pending.exists():
                guards.require(reconcile is True,'Interrupted catalog checkpoint; explicit native reconciliation required')
                pending=decode(read_file(self.checkpoint_pending,MAX_CHECKPOINT_BYTES),MAX_CHECKPOINT_BYTES)
                witness=pending['witness'];prior=witness['prior_head'];nexthead=pending['next_head']
                guards.require(head in (prior,nexthead),'Interrupted catalog checkpoint head differs')
                exists=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='catalog_checkpoint'").fetchone()
                current=db.execute('SELECT record FROM catalog_checkpoint WHERE slot=1').fetchone() if exists else None
                committed=current is not None and digest(current[0])==nexthead['checkpoint']['sha256']
                records=self._scan(db,nexthead if committed else prior)
                survivors=list(records.values()) if committed else [r for r in records.values() if r['id'] not in {item['record']['id'] for item in witness['retired']}]
                self._reconstruct(witness,survivors)
                guards.require(self._checkpoint_head(witness,survivors)==nexthead,'Interrupted catalog checkpoint publication differs')
                proofs,_=self._retirement_evidence(records)
                guards.require(all(proofs.get(item['record']['id'])==item['proof'] for item in witness['retired']),'Interrupted checkpoint native retirement proof differs')
                if not committed:
                    guards.require(head==prior,'Checkpoint prior index after new head publication')
                    try:self._checkpoint_insert(db,witness,survivors,nexthead)
                    except CatalogCapacityError:
                        self._tail(db,prior);self.checkpoint_pending.unlink();runtime.directory_sync(self.root);raise
                runtime.atomic_json(self.head,nexthead);self.checkpoint_pending.unlink();runtime.directory_sync(self.root)
                return {'retired_ids':[item['record']['id'] for item in witness['retired']],'head':nexthead}
            records=self._scan(db,head);proofs,inventory=self._retirement_evidence(records)
            eligible=[(sequence,record) for sequence,record in enumerate(records.values(),1) if record['id'] in proofs]
            if not eligible:return {'retired_ids':[],'head':head}
            retired=[]
            for sequence,record in eligible[:256]:
                item={'sequence':sequence,'record':record,'proof':proofs[record['id']]}
                # Leave enough room for bounded marker/witness publication.
                if len(canonical(retired+[item]))>MAX_CHECKPOINT_BYTES//2:break
                retired.append(item)
            guards.require(retired,'Retirement witness exceeds bounded publication; no data removed')
            ids={item['record']['id'] for item in retired};survivors=[r for r in records.values() if r['id'] not in ids]
            witness={'format':1,'operation':'native-verified-catalog-checkpoint','prior_head':head,'epoch':head.get('checkpoint',{}).get('epoch',0)+1,
                     'retired':retired,'survivor_count':len(survivors),'survivors_sha256':self._records_digest(survivors),
                     'native_inventory_sha256':__import__('retention').inventory_digest(inventory)}
            witness['lineage_sha256']=digest(bytes.fromhex(head.get('checkpoint',{}).get('lineage_sha256',ZERO))+canonical(witness))
            nexthead=self._checkpoint_head(witness,survivors)
            guards.require(shutil.disk_usage(self.root).free>=5*1024**3+2*self.database.stat().st_size+len(canonical(witness))+MAX_RECORD_BYTES,'Catalog checkpoint journal reserve exceeded')
            runtime.atomic_json(self.checkpoint_pending,{'witness':witness,'next_head':nexthead})
            try:self._checkpoint_insert(db,witness,survivors,nexthead)
            except CatalogCapacityError:
                self._tail(db,head);self.checkpoint_pending.unlink();runtime.directory_sync(self.root);raise
            runtime.atomic_json(self.head,nexthead);self.checkpoint_pending.unlink();runtime.directory_sync(self.root)
            return {'retired_ids':sorted(ids),'head':nexthead}

    def _checkpoint_head(self,witness,survivors):
        seed=digest(canonical(witness));chain=seed
        for record in survivors:chain=digest(bytes.fromhex(chain)+canonical(record))
        return {**self.binding,'sequence':len(survivors),'chain':chain,
                'checkpoint':{'epoch':witness['epoch'],'sha256':seed,'lineage_sha256':witness['lineage_sha256']}}

    def _checkpoint_insert(self,db,witness,survivors,nexthead):
        try:
            self._allocation_limit(db);db.execute('BEGIN IMMEDIATE')
            for item in witness['retired']:
                sid=item['record']['id'];db.execute('DELETE FROM logs WHERE sid=?',(sid,));db.execute('DELETE FROM archives WHERE sid=?',(sid,))
            db.execute('UPDATE archives SET sequence=-sequence')
            chain=self._seed(nexthead)
            for sequence,record in enumerate(survivors,1):
                chain=digest(bytes.fromhex(chain)+canonical(record));db.execute('UPDATE archives SET sequence=?,chain=? WHERE sid=?',(sequence,chain,record['id']))
            db.execute('CREATE TABLE IF NOT EXISTS catalog_checkpoint (slot INTEGER PRIMARY KEY CHECK(slot=1), record BLOB NOT NULL)')
            db.execute('INSERT OR REPLACE INTO catalog_checkpoint VALUES(1,?)',(canonical(witness),))
            self._allocation_check(db);db.commit()
        except (sqlite3.Error,CatalogCapacityError) as error:
            db.rollback()
            if isinstance(error,CatalogCapacityError) or getattr(error,'sqlite_errorcode',None)==sqlite3.SQLITE_FULL:
                raise CatalogCapacityError('Catalog checkpoint allocation refused; prior sealed data preserved') from error
            raise
        self._sync_db();self._scan(db,nexthead)
