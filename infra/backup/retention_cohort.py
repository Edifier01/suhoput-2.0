"""Protected immutable retention cohort shared by all native proof producers.

The pointer only selects an exclusively published hash-bound document. Native
current listing, admission seals and journals authenticate it on every load;
neither a receipt nor a caller list can create archive provenance.
"""
import contextlib, copy, datetime as dt, time, hashlib, json, math, os, socket, stat, uuid
import weakref
from dataclasses import dataclass
import backup_catalog, guards, runtime, retention, retention_apply
from worker import private_path, protected_directory, sha, verify_payload

def clock():return dt.datetime.now(dt.timezone.utc)
MAX_CRITICAL_SECONDS=55
_OBSERVATION_KEY=object()
_OBSERVATIONS=weakref.WeakKeyDictionary()
_FLIGHT_USED=weakref.WeakSet()
_ENTRY_OBSERVATIONS_USED=weakref.WeakSet()

# Ephemeral OS-local scheduling only. These messages carry no archive, ACK,
# catalog, frame or effect authority and never renew an existing proof clock.
MAX_MINUTE_TURN_AGE_SECONDS=1

def _minute_turn_directory(worker,*,create=False):
    root=worker.root/'receipts/minute-turns'
    if create:
        protected_directory(worker.root);protected_directory(worker.root/'receipts')
        if not root.exists() and not root.is_symlink():root.mkdir(mode=0o700)
    for parent in (root,*root.parents):guards.require(not parent.is_symlink(),'Minute turn directory symlink')
    return protected_directory(root)

def _minute_turn_identity(path):
    guards.require(path.name==guards.hex_id(path.stem,32)+'.sock' and not path.is_symlink(),'Minute turn request name/link differs')
    value=path.lstat()
    guards.require(stat.S_ISSOCK(value.st_mode) and value.st_uid==0 and value.st_nlink==1 and stat.S_IMODE(value.st_mode)==0o600,
                   'Minute turn socket owner/type/mode differs')
    return (value.st_dev,value.st_ino,value.st_uid,value.st_mode,value.st_nlink,value.st_ctime_ns)

def _minute_turn_binding(worker,request):
    guards.hex_id(worker.c['generation'],32);guards.hex_id(worker.c['code_sha'],40)
    guards.require(isinstance(worker.source,dict) and worker.source.get('generation')==worker.c['generation'],'Minute turn source generation differs')
    return {'format':'minute-turn-ready-v1','request':request,'generation':worker.c['generation'],'code_sha':worker.c['code_sha'],
            'source_sha256':hashlib.sha256(backup_catalog.canonical(worker.source)).hexdigest()}

def wait_for_minute_turn(worker,deadline_monotonic):
    """Wait for ONE newly completed minute, outside every group lock.

    The caller supplies the conservative monotonic bound of its ORIGINAL
    cohort/plan deadline. A new random request belongs only to that local
    invocation/phase. The returned nonce is scheduling data, never a grant.
    """
    guards.require(os.name=='posix' and hasattr(socket,'AF_UNIX'),'POSIX minute turn required')
    guards.require(type(deadline_monotonic) in (int,float) and math.isfinite(deadline_monotonic) and time.monotonic()<deadline_monotonic,
                   'Original minute turn wait deadline exceeded')
    root=_minute_turn_directory(worker,create=True)
    guards.require(not any(root.iterdir()),'Prior minute turn request preserved; investigate')
    request=uuid.uuid4().hex;path=root/(request+'.sock');temporary=root/('.turn-'+request+'.pending')
    guards.require(len(os.fsencode(path))<108 and not path.exists() and not path.is_symlink(),'Minute turn socket path invalid')
    binding=_minute_turn_binding(worker,request);identity=None;temporary_identity=None;started=time.monotonic()
    guards.require(not temporary.exists() and not temporary.is_symlink(),'Prior temporary minute turn socket preserved')
    channel=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
    try:
        channel.bind(str(temporary));value=temporary.lstat()
        temporary_identity=(value.st_dev,value.st_ino,value.st_uid,stat.S_IFMT(value.st_mode),value.st_nlink)
        guards.require(stat.S_ISSOCK(value.st_mode) and value.st_uid==0 and value.st_nlink==1,'Temporary minute turn socket identity differs')
        temporary.chmod(0o600)
        # Publish only the final600 socket. The notifier never observes its
        # bind/chmod interval as a malformed ordinary producer request.
        # link is an atomic NO-REPLACE publication, including a collision
        # introduced after the earlier absence check. A socket briefly has
        # two links; the notifier ignores it until the owned temporary goes.
        os.link(temporary,path,follow_symlinks=False)
        value=temporary.lstat();linked=(value.st_dev,value.st_ino,value.st_uid,stat.S_IFMT(value.st_mode),value.st_nlink)
        guards.require(linked==(*temporary_identity[:4],2) and stat.S_IMODE(value.st_mode)==0o600,
                       'Published minute turn temporary changed; preserve')
        temporary.unlink();identity=_minute_turn_identity(path)
        while True:
            remaining=deadline_monotonic-time.monotonic()
            guards.require(remaining>0,'Original minute turn wait deadline exceeded')
            guards.require(_minute_turn_identity(path)==identity,'Minute turn socket changed')
            channel.settimeout(min(.1,remaining))
            try:raw=channel.recv(4097)
            except socket.timeout:continue
            now=time.monotonic();guards.require(now<deadline_monotonic,'Original minute turn wait deadline exceeded')
            guards.require(len(raw)<=4096,'Minute turn message oversized')
            def pairs(items):
                result={}
                for key,value in items:guards.require(key not in result,'Duplicate minute turn message');result[key]=value
                return result
            try:value=json.loads(raw,object_pairs_hook=pairs)
            except (ValueError,UnicodeError) as error:raise guards.GuardError('Malformed minute turn message') from error
            guards.require(isinstance(value,dict) and set(value)==set(binding)|{'sent_monotonic'} and
                           {key:value[key] for key in binding}==binding,'Foreign minute turn message')
            sent=value['sent_monotonic']
            guards.require(type(sent) in (int,float) and math.isfinite(sent) and started<=sent<=now and now-sent<=MAX_MINUTE_TURN_AGE_SECONDS,
                           'Stale or future minute turn message')
            guards.require(_minute_turn_identity(path)==identity,'Minute turn socket changed')
            return {'request':request,'sent_monotonic':sent,'received_monotonic':now}
    finally:
        channel.close()
        if identity is not None:
            try:
                _minute_turn_directory(worker)
                if _minute_turn_identity(path)==identity:path.unlink()
            except (OSError,guards.GuardError):pass # Preserve a replaced/foreign object.
        elif temporary_identity is not None and temporary.exists() and not temporary.is_symlink():
            # A failed publish owns only its exclusively bound temporary.
            try:
                _minute_turn_directory(worker);value=temporary.lstat()
                current=(value.st_dev,value.st_ino,value.st_uid,stat.S_IFMT(value.st_mode),value.st_nlink)
                if current==temporary_identity:temporary.unlink()
            except (OSError,guards.GuardError):pass

def signal_minute_turns(worker,deadline_original55):
    """Best-effort nonblocking scheduling notice; no request changes a minute.

    Called only after the original minute body and its first55 check. Broken,
    malformed, stale or backpressured queue endpoints never fail a successful
    upload/finalization; the waiting Native side fails closed on its own bound.
    """
    if os.name!='posix' or not hasattr(socket,'AF_UNIX') or not (worker.root/'receipts/minute-turns').exists():return 0
    try:
        if time.monotonic()>=deadline_original55:return 0
        root=_minute_turn_directory(worker);paths=[]
        # At most one active Native phase. Bounded iteration also prevents a
        # foreign directory from spending an unbounded producer55 budget.
        with os.scandir(root) as entries:
            for entry in entries:
                if len(paths)==1:return 0
                paths.append(root/entry.name)
        if not paths:return 0
        path=paths[0];identity=_minute_turn_identity(path);binding=_minute_turn_binding(worker,path.stem)
        with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as channel:
            channel.setblocking(False);channel.connect(str(path))
            guards.require(_minute_turn_identity(path)==identity,'Minute turn socket changed')
            if time.monotonic()>=deadline_original55:return 0
            body=backup_catalog.canonical({**binding,'sent_monotonic':time.monotonic()})
            guards.require(len(body)<=4096,'Minute turn message oversized');channel.send(body)
        return 1
    except (OSError,guards.GuardError,AttributeError,KeyError,TypeError,ValueError):return 0

class _FlightWait:
    """One bounded producer turn for an actual read-only observation."""
    __slots__=('__weakref__',)

def _completed_transition(worker,reader,lanes,saved,unknown,original_head,prefix,native_seals,end):
    """A vanished pending file grants nothing; actual fresh ACK/body does."""
    original_ids=frozenset(reader._records);reader=reader.refresh(deadline=end);completed=dict(saved)
    for lane in lanes:
        if lane in completed:continue
        state=runtime.UploadJournal(worker.root/'receipts'/lane,worker.c['generation']).state()
        selected={row['id'] for row_lane,row in unknown if row_lane==lane}
        if not selected:selected={sid for sid,record in reader._records.items() if sid not in original_ids and record['lane']==lane}
        if not selected and not any(row_lane==lane for row_lane,_ in unknown):
            # Admission and ACK may both precede the final pending unlink.
            # Bind that exact completed capture rather than guessing last ACK.
            payload=worker.root/'spool'/(lane+'-payload')
            capture=runtime.load_json(private_path(worker.root/'receipts'/('capture-'+lane+'.json')))
            marker=runtime.load_json(private_path(payload/'.capture.json'))
            guards.require(isinstance(capture,dict) and set(capture)=={'generation','lane','token','phase'} and capture['generation']==worker.c['generation'] and
                           capture['lane']==lane and capture['phase']=='upload' and marker=={key:capture[key] for key in ('generation','lane','token')},
                           'Completed producer capture ownership differs')
            guards.hex_id(capture['token'],32);manifest_path=private_path(payload/'manifest.json')
            verify_payload(payload,runtime.load_json(manifest_path));md=sha(manifest_path)
            selected={ack['id'] for ack in state['confirmed'] if ack['manifest_sha256']==md}
        matches=[ack for ack in state['confirmed'] if ack['id'] in selected]
        guards.require(len(matches)==1 and selected=={matches[0]['id']},'Uncatalogued current arrival lacks one fresh admitted acknowledgement')
        completed[lane]=matches[0]
    guards.require(all(lane in completed for lane,_ in unknown),'Unknown native row has no completed producer')
    # Authenticate before waiting for the producer's remaining finalization.
    _finished_admissions(worker,reader,completed,unknown)
    with upload_section(worker,deadline=end):
        ready(worker,deadline=end);_finished_admissions(worker,reader,completed,unknown)
        guards.require(retention.reader_raw_prefix_seal(reader,head=original_head,deadline=end)==prefix,'Original producer observation catalog prefix changed')
        guards.require(all(backup_catalog.digest(backup_catalog.canonical(row))==seal for row,seal in native_seals),'Original complete producer native fields changed')
    guards.require(time.monotonic()<end,'Protected producer wait deadline exceeded');return reader

def _finished_admissions(worker,reader,saved,unknown):
    for lane,value in saved.items():
        state=runtime.UploadJournal(worker.root/'receipts'/lane,worker.c['generation']).state()
        matches=[row for row in state['confirmed'] if row['token']==value['token']]
        guards.require(len(matches)==1,'Finished producer lacks one exact acknowledgement');ack=matches[0]
        guards.require(set(ack)=={'id','token','manifest_sha256','captured_at','prepared_at','confirmed_at'} and
                       all(ack[key]==value[key] for key in ('token','manifest_sha256','captured_at','prepared_at')),
                       'Finished producer acknowledgement differs')
        record=reader._record(ack['id']);raw=reader.raw_manifest(ack['id']);manifest=retention.decode(raw)
        native,token,md=backup_catalog.native_identity(record['native'],ack['id'],str(worker.root/'spool'/(lane+'-payload')),worker.c['generation'])
        guards.require(record['lane']==lane and record['repository']==worker.c['repositories'][lane] and record['repository_id']==repository_ids(worker)[lane] and
                       token==value['token'] and md==value['manifest_sha256'] and {key:item for key,item in manifest.items() if key!='files'}==record['projection'] and
                       manifest['format']==1 and manifest['generation']==worker.c['generation'] and manifest['source']==worker.source and manifest['captured_at']==ack['captured_at'] and
                       manifest['kind'] in (('full','pre-update','hourly') if lane=='base' else ('binlog',)),
                       'Finished producer native admission differs')
        guards.hex_id(manifest['code_sha'],40)
        if lane=='base':guards.require(manifest['stage_app_sha']==worker.c['stage_app_sha'],'Finished producer application differs')
        for row_lane,row in unknown:
            if row_lane==lane:guards.require(row['id']==ack['id'] and backup_catalog.native_identity(row,row['id'],str(worker.root/'spool'/(lane+'-payload')),worker.c['generation'])[0]==native,
                                           'Original uncatalogued native authority changed')
        guards.require(guards.utc(ack['captured_at'])<=guards.utc(value['prepared_at'])<=guards.utc(native['time'])<=guards.utc(record['verified']['verified_at'])<=guards.utc(ack['confirmed_at'])<=clock(),
                       'Finished producer admission/acknowledgement clock differs')
        files=manifest['files'];full=sorted([*files,{'path':'manifest.json','bytes':len(raw),'sha256':md}],key=lambda item:item['path'])
        guards.require(len(full)==record['verified']['file_count'] and sum(item['bytes'] for item in files)==record['verified']['payload_bytes'] and
                       backup_catalog.digest(backup_catalog.canonical(full))==record['verified']['all_files_sha256'],'Finished producer all-file admission differs')
        if lane=='binlog':
            for item in manifest['logs']:
                body=reader.binlog_bytes(ack['id'],item['file'])
                __import__('binlog').validate_chain({item['file']:body},[item],{'file':item['file'],'position':4},{'file':item['file'],'position':item['size']})

def _settle_producer(worker,reader,wait,*,unknown=(),deadline=None):
    pending_paths={lane:worker.root/'receipts'/lane/'pending.json' for lane in ('base','binlog')}
    lanes=[lane for lane,path in pending_paths.items() if path.exists() or path.is_symlink()]
    if not lanes and not unknown:return reader
    guards.require(type(wait) is _FlightWait and wait not in _FLIGHT_USED,'Only one protected producer wait is allowed per observation')
    _FLIGHT_USED.add(wait);end=time.monotonic()+MAX_CRITICAL_SECONDS
    if deadline is not None:end=min(end,deadline)
    saved={};now=clock();original_head=copy.deepcopy(reader.head)
    native_seals=[(row,backup_catalog.digest(backup_catalog.canonical(row))) for _,row in unknown]
    prefix=retention.reader_raw_prefix_seal(reader,verify=True,deadline=end)
    if not lanes:
        return _completed_transition(worker,reader,sorted({lane for lane,_ in unknown}),saved,unknown,original_head,prefix,native_seals,end)
    for lane in lanes:
        journal=runtime.UploadJournal(worker.root/'receipts'/lane,worker.c['generation']).state()
        try:value=runtime.load_json(private_path(pending_paths[lane]))
        except FileNotFoundError:
            return _completed_transition(worker,reader,lanes,saved,unknown,original_head,prefix,native_seals,end)
        payload=worker.root/'spool'/(lane+'-payload')
        required={'token','generation','payload','manifest_sha256','attempted','prepared_at','captured_at'}
        guards.require(set(value) in (required,required|{'parent_id'}) and value['attempted'] is True and value['generation']==worker.c['generation'] and
                       value['payload']==str(payload),'Pending producer authority differs')
        token=guards.hex_id(value['token'],32);md=guards.hex_id(value['manifest_sha256'],64)
        try:
            capture=runtime.load_json(private_path(worker.root/'receipts'/('capture-'+lane+'.json')))
            marker=runtime.load_json(private_path(payload/'.capture.json'))
        except FileNotFoundError:
            return _completed_transition(worker,reader,lanes,{**saved,lane:value},unknown,original_head,prefix,native_seals,end)
        guards.require(isinstance(capture,dict) and set(capture)=={'generation','lane','token','phase'} and capture['generation']==worker.c['generation'] and capture['lane']==lane and
                       capture['phase']=='upload' and marker=={key:capture[key] for key in ('generation','lane','token')},'Pending producer capture ownership differs')
        guards.hex_id(capture['token'],32)
        selected=[row for row_lane,row in unknown if row_lane==lane]
        guards.require(len(selected)<=1,'Multiple uncatalogued arrivals cannot share one producer')
        for row in selected:
            native,row_token,row_md=backup_catalog.native_identity(row,row['id'],str(payload),worker.c['generation'])
            guards.require(row_token==token and row_md==md and guards.utc(value['prepared_at'])<=guards.utc(native['time'])<=now,
                           'Uncatalogued native row differs from protected producer')
        job=private_path(worker.root/'receipts'/('job-'+lane+'.lock'))
        try:
            with runtime.lane_lock(job):pass
        except runtime.LaneBusyError:pass
        else:
            guards.require(not pending_paths[lane].exists() and not pending_paths[lane].is_symlink(),'Pending producer is abandoned; job lock is free')
            return _completed_transition(worker,reader,lanes,{**saved,lane:value},unknown,original_head,prefix,native_seals,end)
        manifest_path=private_path(payload/'manifest.json');manifest=runtime.load_json(manifest_path)
        guards.require(sha(manifest_path)==md and manifest['generation']==worker.c['generation'] and manifest['source']==worker.source and
                       manifest['format']==1 and manifest['captured_at']==value['captured_at'] and
                       manifest['kind'] in (('full','pre-update','hourly') if lane=='base' else ('binlog',)),'Pending producer payload identity differs')
        guards.hex_id(manifest['code_sha'],40);verify_payload(payload,manifest)
        guards.require(guards.utc(value['captured_at'])<=guards.utc(value['prepared_at'])<=now,'Pending producer clock differs')
        guards.require(value.get('parent_id')==(journal['confirmed'][-1]['id'] if journal['confirmed'] else None),'Pending producer parent differs')
        saved[lane]=value
    guards.require(all(lane in saved for lane,_ in unknown),'Unknown native row has no matching live producer')
    with upload_section(worker,deadline=end):
        ready(worker,deadline=end);reader=reader.refresh(deadline=end)
        for lane,value in saved.items():
            state=runtime.UploadJournal(worker.root/'receipts'/lane,worker.c['generation']).state()
            matches=[row for row in state['confirmed'] if row['token']==value['token']]
            guards.require(len(matches)==1,'Finished producer lacks one exact acknowledgement');ack=matches[0]
            guards.require(set(ack)=={'id','token','manifest_sha256','captured_at','prepared_at','confirmed_at'} and
                           all(ack[key]==value[key] for key in ('token','manifest_sha256','captured_at','prepared_at')),
                           'Finished producer acknowledgement differs')
            record=reader._record(ack['id']);raw=reader.raw_manifest(ack['id']);manifest=retention.decode(raw)
            native,token,md=backup_catalog.native_identity(record['native'],ack['id'],str(worker.root/'spool'/(lane+'-payload')),worker.c['generation'])
            guards.require(record['lane']==lane and record['repository']==worker.c['repositories'][lane] and record['repository_id']==repository_ids(worker)[lane] and
                           token==value['token'] and md==value['manifest_sha256'] and {key:item for key,item in manifest.items() if key!='files'}==record['projection'],
                           'Finished producer native admission differs')
            for row_lane,row in unknown:
                if row_lane==lane:guards.require(row['id']==ack['id'] and backup_catalog.native_identity(row,row['id'],str(worker.root/'spool'/(lane+'-payload')),worker.c['generation'])[0]==native,
                                               'Original uncatalogued native authority changed')
            guards.require(guards.utc(value['prepared_at'])<=guards.utc(native['time'])<=guards.utc(record['verified']['verified_at'])<=guards.utc(ack['confirmed_at'])<=clock(),
                           'Finished producer admission/acknowledgement clock differs')
            files=manifest['files'];full=sorted([*files,{'path':'manifest.json','bytes':len(raw),'sha256':md}],key=lambda item:item['path'])
            guards.require(len(full)==record['verified']['file_count'] and sum(item['bytes'] for item in files)==record['verified']['payload_bytes'] and
                           backup_catalog.digest(backup_catalog.canonical(full))==record['verified']['all_files_sha256'],'Finished producer all-file admission differs')
            if lane=='binlog':
                for item in manifest['logs']:
                    body=reader.binlog_bytes(ack['id'],item['file'])
                    __import__('binlog').validate_chain({item['file']:body},[item],{'file':item['file'],'position':4},{'file':item['file'],'position':item['size']})
        guards.require(retention.reader_raw_prefix_seal(reader,head=original_head,deadline=end)==prefix,'Original producer observation catalog prefix changed')
        guards.require(all(backup_catalog.digest(backup_catalog.canonical(row))==seal for row,seal in native_seals),'Original complete producer native fields changed')
    guards.require(time.monotonic()<end,'Protected producer wait deadline exceeded');return reader

@dataclass(frozen=True)
class _Observation:
    key:object
    owner:int
    inventory_sha256:str
    source_sha256:str
    head_raw:bytes
    original_ids:frozenset
    raw_prefix:str
    journal_prefix:tuple
    native_views:tuple
    flight:_FlightWait

class _ObservedSnapshots(list):
    """Ephemeral provenance; copying/JSON import never grants confirmation."""
    __hash__=object.__hash__

def _observation_digest(inventory):
    import hashlib
    result=hashlib.sha256()
    def item(value):
        raw=backup_catalog.canonical(value);result.update(len(raw).to_bytes(8,'big'));result.update(raw)
    for key in ('generation','repositories','observed_at'):item(key);item(inventory[key])
    item('snapshots');item(len(inventory['snapshots']))
    for row in inventory['snapshots']:item(row)
    item('manifests');item(len(inventory['manifests']))
    for sid in sorted(inventory['manifests']):item(sid);item(inventory['manifests'][sid])
    return result.hexdigest()

def _journal_proofs(worker):
    from retention_native import _journal_prefix_seal
    result=[]
    for lane in ('base','binlog'):
        seal=_journal_prefix_seal(runtime.UploadJournal(worker.root/'receipts'/lane,worker.c['generation']).state())
        result.append((lane,seal['count'],seal['prefix'],seal['stable']))
    return tuple(result)

def _consume_entry_observation(worker,inventory,reader):
    """Consume a loader-minted observation once as an initial baseline only.

    This grants no prepared effect frame. Every effect still obtains its own
    full phase observation and reserved native/raw authority closure.
    """
    rows=inventory['snapshots'];proof=getattr(rows,'_observation',None)
    guards.require(type(rows) is _ObservedSnapshots and type(proof) is _Observation and
                   _OBSERVATIONS.get(rows) is proof and proof.key is _OBSERVATION_KEY and proof.owner==id(rows),
                   'Entry observation must be the original loader-minted handle')
    guards.require(rows not in _ENTRY_OBSERVATIONS_USED,'Entry observation already consumed')
    # A rejected closure cannot be healed by consuming the same handle again.
    _ENTRY_OBSERVATIONS_USED.add(rows)
    guards.require(type(reader) is backup_catalog.ArchiveReader and reader.active and
                   reader.catalog.worker is worker and reader.catalog.receipts==worker.root/'receipts' and
                   reader.catalog.binding=={'format':1,'generation':worker.c['generation'],'source':worker.source,
                                            'repository_paths':worker.c['repositories']},
                   'Entry observation requires an active reader of the same worker/scope')
    guards.require(retention.reader_raw_prefix_seal(reader,head=backup_catalog.decode(proof.head_raw),verify=True)==proof.raw_prefix,
                   'Original entry reader projection or catalog raw/body prefix changed')
    confirm_observation(worker,inventory,reader)
    return inventory

def confirm_observation(worker,inventory,reader,*,journals=None,tombstones=None):
    """Validate only authenticated ACKs strictly beyond a native observation.

    Actual native inventory/timestamps never gain unlisted rows. Effects and
    catalog publication retain their separate strict current validators.
    """
    from retention_native import verified_tombstones,_journal_prefix_seal
    journals=journals or {lane:runtime.UploadJournal(worker.root/'receipts'/lane,worker.c['generation']).state() for lane in ('base','binlog')}
    tombstones=verified_tombstones(worker) if tombstones is None else tombstones
    rows=inventory['snapshots'];proof=getattr(rows,'_observation',None)
    if type(rows) is not _ObservedSnapshots or proof is None:
        retention.confirmed_inventory(inventory,journals,tombstones);return journals
    guards.require(type(proof) is _Observation and _OBSERVATIONS.get(rows) is proof and proof.key is _OBSERVATION_KEY and proof.owner==id(rows) and
                   proof.inventory_sha256==_observation_digest(inventory) and
                   proof.source_sha256==retention_apply.document_digest({'source':worker.source,'generation':worker.c['generation'],'repositories':worker.c['repositories'],'code_sha':worker.c['code_sha']}),
                   'Native observation provenance changed or copied')
    observed_at=guards.utc(inventory['observed_at']);at=clock()
    guards.require(0<=(at-observed_at).total_seconds()<=900,'Native observation expired or clock rolled back')
    head=backup_catalog.decode(proof.head_raw)
    guards.require(retention.reader_raw_prefix_seal(reader,head=head)==proof.raw_prefix,'Original observed catalog raw/body prefix changed')
    guards.require(set(dict(proof.native_views))=={'base','binlog'} and all(guards.hex_id(value,64) for _,value in proof.native_views),
                   'Complete native observation views missing')
    # The original native view was admitted before this proof was minted.
    # Later pending work grants no row or wait to this read-only observation;
    # effects and publication still require their strict current readiness.
    journals={lane:runtime.UploadJournal(worker.root/'receipts'/lane,worker.c['generation']).state() for lane in ('base','binlog')}
    reader=reader.refresh();indexed={row['id']:row for row in rows};excluded=[];observed={};at=clock()
    for lane,count,prefix,stable in proof.journal_prefix:
        state=journals[lane];seal=_journal_prefix_seal(state,count)
        guards.require(seal=={'count':count,'prefix':prefix,'stable':stable},'Original confirmation or retirement prefix changed')
        missing=[]
        for ack in state['confirmed'][count:]:
            sid=guards.hex_id(ack['id'],64)
            if sid in indexed:continue
            guards.require(sid not in proof.original_ids,'Historical missing native ID cannot become a late ACK')
            record=reader._record(sid);native=record['native'];manifest=retention.decode(reader.raw_manifest(sid))
            actual,token,md=backup_catalog.native_identity(native,sid,str(worker.root/'spool'/(lane+'-payload')),worker.c['generation'])
            guards.require(record['lane']==lane and record['repository_id']==inventory['repositories'][lane] and
                           record['repository']==worker.c['repositories'][lane] and actual==native and token==record['token'] and md==record['manifest_sha256'] and
                           {key:value for key,value in manifest.items() if key!='files'}==record['projection'] and manifest['source']==worker.source and
                           manifest['generation']==worker.c['generation'] and manifest['format']==1,'Late ACK native admission/manifest differs')
            guards.require(set(ack)=={'id','token','manifest_sha256','captured_at','prepared_at','confirmed_at'} and
                           ack['token']==token and ack['manifest_sha256']==md,'Late ACK fields or identity differ')
            captured=guards.utc(manifest['captured_at']);uploaded=guards.utc(native['time']);verified=guards.utc(record['verified']['verified_at'])
            guards.require(captured<=uploaded<=verified<=at,'Late ACK capture/native/admission clock differs')
            guards.require(ack['captured_at']==manifest['captured_at'] and captured<=guards.utc(ack['prepared_at'])<=uploaded and
                           verified<=guards.utc(ack['confirmed_at'])<=at,'Late ACK confirmation clock differs')
            guards.hex_id(manifest['code_sha'],40)
            files=manifest['files'];full=sorted([*files,{'path':'manifest.json','bytes':len(reader.raw_manifest(sid)),'sha256':md}],key=lambda item:item['path'])
            guards.require(len(full)==record['verified']['file_count'] and sum(item['bytes'] for item in files)==record['verified']['payload_bytes'] and
                           backup_catalog.digest(backup_catalog.canonical(full))==record['verified']['all_files_sha256'],'Late ACK actual all-file admission differs')
            guards.require(manifest['kind'] in (('full','pre-update','hourly') if lane=='base' else ('binlog',)),'Late ACK lane/kind differs')
            if lane=='base':guards.require(manifest['stage_app_sha']==worker.c['stage_app_sha'],'Late ACK application differs')
            else:
                for item in manifest['logs']:
                    raw=reader.binlog_bytes(sid,item['file'])
                    __import__('binlog').validate_chain({item['file']:raw},[item],{'file':item['file'],'position':4},{'file':item['file'],'position':item['size']})
            excluded.append({'id':sid,'lane':lane,'token':token,'manifest_sha256':md,'kind':manifest['kind'],'generation':worker.c['generation'],
                             'time':manifest['captured_at'],'snapshot_time':native['time'],'tree':native['tree']})
            observed.setdefault('manifests',{})[sid]=record['projection'];missing.append(sid)
        missing=set(missing);observed[lane]={**state,'confirmed':[ack for ack in state['confirmed'] if ack['id'] not in missing]}
    guards.require(len({row['id'] for row in excluded})==len(excluded),'Duplicate late ACK identity')
    if excluded:
        augmented={**inventory,'snapshots':[ *rows,*excluded],'manifests':{**inventory['manifests'],**observed['manifests']}}
        retention.inventory_plan(augmented,at);retention_apply.protected_dependencies(augmented,[],at)
    retention.confirmed_inventory(inventory,{lane:observed[lane] for lane in ('base','binlog')},tombstones)
    guards.require(retention.reader_raw_prefix_seal(reader,head=head)==proof.raw_prefix,'Original observed catalog raw/body prefix changed')
    guards.require(0<=(clock()-observed_at).total_seconds()<=900,'Native observation expired or clock rolled back')
    return journals

@contextlib.contextmanager
def minute_job(worker,deadline):
    """Reserve the next job turn while an existing retention group finishes.

    Both acquisitions and the completed body spend the original minute
    deadline. The OS releases the reservation on process death; it carries
    no durable authority. An original body exception propagates unchanged.
    """
    with backup_catalog._catalog_lock(worker.root/'receipts/job-binlog-wait.lock',MAX_CRITICAL_SECONDS,deadline,'minute turn'):
        with backup_catalog._catalog_lock(worker.root/'receipts/job-binlog.lock',MAX_CRITICAL_SECONDS,deadline,'minute job'):
            yield
            guards.require(time.monotonic()<deadline,'Minute job original deadline exceeded')
            signal_minute_turns(worker,deadline)
            guards.require(time.monotonic()<deadline,'Minute job original deadline exceeded')

@contextlib.contextmanager
def upload_section(worker,*,deadline=None,extra_locks=()):
    """Acquire the complete group; never wait with a partial group held.

    Only OS acquisition contention is retried. The caller's body and every
    unlock run once. Return the first acquire time of the successful attempt
    so its 45/55s work/held budget cannot omit intermediate lock acquisitions.
    """
    end=time.monotonic()+MAX_CRITICAL_SECONDS
    if deadline is not None:end=min(end,deadline)
    paths=[worker.root/'receipts'/name for name in ('job-base.lock','job-binlog.lock','base/lane.lock','binlog/lane.lock')]+list(extra_locks)
    while True:
        guards.require(time.monotonic()<end,'Retention lock acquisition deadline exceeded')
        stack=contextlib.ExitStack();priority=contextlib.ExitStack();started=time.monotonic()
        try:
            priority.enter_context(runtime.lane_lock(worker.root/'receipts/job-binlog-wait.lock'))
            for path in paths:stack.enter_context(runtime.lane_lock(path))
        except runtime.LaneBusyError:
            with priority:stack.close()
            remaining=end-time.monotonic()
            guards.require(remaining>0,'Retention lock acquisition deadline exceeded')
            time.sleep(min(.025,remaining));continue
        except BaseException:
            with priority:stack.close()
            raise
        # A minute may queue during this body and own the next group turn.
        # Unlock failure is outside acquisition retry and releases the group.
        try:priority.close()
        except BaseException:stack.close();raise
        break
    with stack:yield started

def ready(worker,*,deadline=None):
    for lane in ('base','binlog'):
        pending=worker.root/'receipts/maintenance'/('pending-'+lane+'.json')
        guards.require(not pending.exists() and not pending.is_symlink(),'Unfinished physical cleanup blocks retention')
    backup_catalog.ArchiveCatalog(worker,deadline=deadline).ready(deadline=deadline)
    ready_uploads(worker)

def ready_uploads(worker):
    for lane in ('base','binlog'):
        root=worker.root/'receipts';pending=root/lane/'pending.json'
        guards.require(not pending.exists() and not pending.is_symlink(),'Unfinished upload blocks cohort/effect')
        capture=root/('capture-'+lane+'.json')
        if capture.exists() or capture.is_symlink():
            value=runtime.load_json(private_path(capture))
            guards.require(value['generation']==worker.c['generation'] and value['lane']==lane and value['phase']=='upload',
                           'Unfinished capture blocks cohort/effect')
            payload=worker.root/'spool'/(lane+'-payload');manifest=private_path(payload/'manifest.json')
            marker=runtime.load_json(private_path(root/lane/'finalized.json'))
            guards.require(marker['manifest_sha256']==sha(manifest),'Unfinished finalization blocks cohort/effect')
            state=runtime.UploadJournal(root/lane,worker.c['generation']).state()
            guards.require(any(row['id']==marker['snapshot_id'] and row['manifest_sha256']==marker['manifest_sha256'] for row in state['confirmed']),
                           'Finalization lacks confirmed upload')
            for name,digest in marker['domains'].items():
                guards.require(name in ('full.json','base-full.json','base-hourly.json','base-pre-update.json','binlog-chain.json','binlog-last.json') and
                               sha(private_path(root/name))==digest,'Finalized domain changed')
        cleanup=root/('cleanup-'+lane+'.json')
        if cleanup.exists() or cleanup.is_symlink():
            guards.require(runtime.load_json(private_path(cleanup)).get('done') is True,'Unfinished cleanup blocks cohort/effect')

def repository_ids(worker):
    return {lane:runtime.load_json(private_path(worker.root/'receipts'/('init-'+lane+'.json')))['repository_id'] for lane in ('base','binlog')}

def confirmed(worker,inventory):
    from retention_native import verified_tombstones
    journals={lane:runtime.UploadJournal(worker.root/'receipts'/lane,worker.c['generation']).state() for lane in ('base','binlog')}
    retention.confirmed_inventory(inventory,journals,verified_tombstones(worker));return journals

def seals(reader,inventory):
    result={}
    for row in inventory['snapshots']:
        record=reader._record(row['id'])
        guards.require(record['manifest_sha256']==row['manifest_sha256'] and record['native']['tree']==row['tree'],
                       'Cohort catalog/native identity differs')
        result[row['id']]=retention_apply.document_digest(record)
    return result

def binding(document):
    return {'sha256':document['cohort_sha256'],'planned_at':document['planned_at'],
            'code_sha':document['code_sha'],'watermark':copy.deepcopy(document['watermark'])}

class CohortStore:
    def __init__(self,worker):
        self.w=worker;self.root=worker.root/'receipts/retention-cohorts';self.pointer=worker.root/'receipts/retention-cohort.json'
        if not self.root.exists():self.root.mkdir(mode=0o700);runtime.directory_sync(self.root.parent)
        protected_directory(self.root)
    def capture(self):
        """Native audit begins a new cohort; no imported proof or chosen IDs."""
        w=self.w;start=time.monotonic();catalog=backup_catalog.ArchiveCatalog(w)
        with catalog.open_reader() as reader:
            from retention_native import _journal_prefix_seal
            # Native observation and its following journal read are not atomic
            # outside upload locks. Pin old history before observing, then close
            # all acknowledgements against the complete final locked view.
            journal_prefix={}
            for lane in ('base','binlog'):
                state=runtime.UploadJournal(w.root/'receipts'/lane,w.c['generation']).state()
                journal_prefix[lane]=_journal_prefix_seal(state)
            del state
            reader=reader.refresh()
            current_reader=[reader];native_views={}
            inventory=retention.native_inventory(w,clock(),repository_ids(w),clock,reader=reader,reader_out=current_reader,native_views=native_views)
            reader=current_reader[0]
            raw_prefix=retention.reader_raw_prefix_seal(reader,verify=True)
            planned=clock();plan=retention.inventory_plan(inventory,planned)
            compact=retention_apply.compact_authenticated_inventory(inventory,planned)
            captured_seals=seals(reader,inventory);captured_head=copy.deepcopy(reader.head)
            native_prefix={'ids':{lane:{row['id'] for row in inventory['snapshots'] if row['lane']==lane} for lane in ('base','binlog')},'views':native_views}
            critical=time.monotonic()
            with upload_section(w) as acquired:
                if acquired is not None:critical=acquired
                deadline=critical+MAX_CRITICAL_SECONDS
                ready(w,deadline=deadline);reader=reader.refresh(deadline=deadline);current=retention.native_inventory(w,clock(),inventory['repositories'],clock,reader=reader,deadline=deadline,native_prefix=native_prefix)
                journals=confirmed(w,current)
                for lane,state in journals.items():
                    guards.require(_journal_prefix_seal(state,journal_prefix[lane]['count'])==journal_prefix[lane],
                                   'Original confirmation or retirement prefix changed')
                del journals,state
                retention_apply.compatible_inventory(inventory,current,clock())
                guards.require(retention.reader_raw_prefix_seal(reader,head=captured_head,deadline=deadline)==raw_prefix,
                               'Original captured catalog raw/body prefix changed')
                # Capture the scanned set exactly. Current arrivals remain out
                # of the cohort, independently authenticated and protected.
                body={'format':1,'operation':'native-retention-cohort','code_sha':w.c['code_sha'],
                      'planned_at':planned.isoformat(),'inventory_sha256':retention.inventory_digest(inventory),
                      'inventory':compact,'catalog_head':captured_head,'catalog_seals':captured_seals,
                      'watermark':{'file':plan['chain_last_file'],'position':plan['chain_last_position']}}
                document={**body,'cohort_sha256':retention_apply.document_digest(body)}
                guards.require(time.monotonic()<deadline,'Cohort critical validation deadline exceeded')
                from retention_native import exclusive_json
                path=self.root/(document['cohort_sha256']+'.json')
                if path.exists() or path.is_symlink():guards.require(runtime.load_json(private_path(path))==document,'Existing immutable cohort differs')
                else:exclusive_json(path,document)
                runtime.atomic_json(self.pointer,{'sha256':document['cohort_sha256'],'file_sha256':sha(path)})
            inventory['cohort']=binding(document)
            return inventory,{'scan_seconds':critical-start,'critical_seconds':time.monotonic()-critical}
    def _document(self):
        pointer=runtime.load_json(private_path(self.pointer));key=guards.hex_id(pointer['sha256'],64)
        path=private_path(self.root/(key+'.json'));guards.require(sha(path)==pointer['file_sha256'],'Cohort pointer bytes differ')
        document=runtime.load_json(path);body={k:v for k,v in document.items() if k!='cohort_sha256'}
        guards.require(document['cohort_sha256']==key==retention_apply.document_digest(body),'Immutable cohort hash differs')
        inventory=document['inventory'];w=self.w
        guards.require(document['format']==1 and document['operation']=='native-retention-cohort' and document['code_sha']==w.c['code_sha'] and
                       inventory['generation']==w.c['generation'] and inventory['source']==w.source and inventory['repositories']==repository_ids(w),
                       'Cohort source/version/repositories differ')
        guards.require(retention.inventory_digest(inventory)==document['inventory_sha256'],'Cohort inventory digest differs')
        return document
    def _inventory(self,document,reader):
        compact=document['inventory'];result={k:copy.deepcopy(v) for k,v in compact.items() if k!='format'}
        result['manifests']={row['id']:copy.deepcopy(reader._record(row['id'])['projection']) for row in compact['snapshots']}
        guards.require(seals(reader,result)==document['catalog_seals'],'Captured cohort catalog seals changed')
        result.pop('source');result['cohort']=binding(document)
        plan=retention.inventory_plan(result,guards.utc(document['planned_at']))
        guards.require(document['watermark']=={'file':plan['chain_last_file'],'position':plan['chain_last_position']},'Cohort watermark differs')
        return result
    def load(self,reader,*,current_out=None):
        # Capture the earliest supplied reader boundary, before a post-list
        # refresh can already include an ACK unseen by that native response.
        head_raw=backup_catalog.canonical(reader.head);original_ids=frozenset(reader._records)
        raw_prefix=retention.reader_raw_prefix_seal(reader,verify=True);prefix=_journal_proofs(self.w)
        reader=reader.refresh();document=self._document();inventory=self._inventory(document,reader)
        views={};current_reader=[reader];flight=_FlightWait()
        current=retention.native_inventory(self.w,clock(),inventory['repositories'],clock,reader=reader,reader_out=current_reader,native_views=views,_flight_wait=flight)
        reader=current_reader[0];rows=_ObservedSnapshots(current['snapshots']);current['snapshots']=rows
        rows._observation=_Observation(_OBSERVATION_KEY,id(rows),_observation_digest(current),
            retention_apply.document_digest({'source':self.w.source,'generation':self.w.c['generation'],'repositories':self.w.c['repositories'],'code_sha':self.w.c['code_sha']}),
            head_raw,original_ids,raw_prefix,prefix,tuple(sorted(views.items())),flight)
        _OBSERVATIONS[rows]=rows._observation
        confirm_observation(self.w,current,reader);retention_apply.compatible_inventory(inventory,current,clock())
        if current_out is not None:
            guards.require(isinstance(current_out,dict) and not current_out,'Empty current inventory output required')
            current_out.update(current)
        return inventory
