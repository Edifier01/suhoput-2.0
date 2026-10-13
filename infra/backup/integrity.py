"""Weekly uncached remote reads plus exact authenticated archive admissions.

Coverage refreshes never change a full read's original timestamps. Small fixed
headers reference immutable compact identity maps; critical phase revalidation
hashes their bytes without loading another catalog graph or doing remote I/O.
"""
import datetime as dt, hashlib, uuid
import backup_catalog, guards, runtime
from worker import private_path, protected_directory, sha

LANES=('base','binlog')
MAX_AGE=dt.timedelta(days=7)
MODE='weekly-read-data-and-verified-admissions'
PRODUCERS=('integrity.py','retention.py','maintenance.py','worker.py','backup_catalog.py','runtime.py','restic_adapter.py')
def clock():return dt.datetime.now(dt.timezone.utc)
def digest(value):return hashlib.sha256(backup_catalog.canonical(value)).hexdigest()

def identities(value):
    guards.require(isinstance(value,dict) and len(value)<=backup_catalog.MAX_RECORDS,'Invalid integrity identity map')
    for sid,row in value.items():
        guards.hex_id(sid,64)
        guards.require(isinstance(row,list) and len(row)==3,'Incomplete integrity identity')
        for item,size in zip(row,(64,32,64)):guards.hex_id(item,size)
    return value

def times(proof,at,*,fresh=True):
    guards.require(isinstance(at,dt.datetime) and at.tzinfo is not None,'Integrity observation clock required')
    started=guards.utc(proof['started_at']);completed=guards.utc(proof['completed_at'])
    guards.require(started<=completed<=at,'Integrity full-read clock differs')
    if fresh:guards.require(at-completed<=MAX_AGE,'Weekly full remote read expired')
    return completed

def coverage(proof,current,tombstones,admitted,*,at,lane):
    return _coverage(proof,current,tombstones,admitted,at=at,lane=lane,fresh=True)

def _coverage(proof,current,tombstones,admitted,*,at,lane,fresh):
    guards.require(lane in LANES,'Unknown integrity lane');times(proof,at,fresh=fresh)
    previous=identities(proof['snapshots']);identities(current);identities(admitted)
    retired={};seen=set()
    for row in tombstones:
        sid=guards.hex_id(row['id'],64);guards.require(sid not in seen,'Duplicate integrity tombstone');seen.add(sid)
        guards.require(row['lane'] in LANES,'Unknown integrity retirement lane')
        token=guards.hex_id(row['token'],32);manifest=guards.hex_id(row['manifest_sha256'],64)
        if row['lane']==lane:retired[sid]=(token,manifest)
    guards.require(not set(current)&set(retired),'Retired snapshot reappeared')
    missing=0;arrivals=0
    for sid,row in previous.items():
        if sid in current:guards.require(current[sid]==row,'Full-read snapshot identity changed')
        else:
            guards.require(retired.get(sid)==tuple(row[1:]),'Missing full-read snapshot lacks exact retirement');missing+=1
    for sid,row in current.items():
        if sid not in previous:
            guards.require(admitted.get(sid)==row,'New snapshot lacks actual verified admission');arrivals+=1
    return {'full_remote_started_at':proof['started_at'],'full_remote_completed_at':proof['completed_at'],
            'verified_arrivals':arrivals,'verified_retirements':missing,'current_snapshots_sha256':digest(current),
            'current_snapshot_count':len(current)}

def _root(w):
    root=w.root/'receipts/integrity';root.mkdir(mode=0o700,exist_ok=True);protected_directory(root)
    maps=root/'maps';maps.mkdir(mode=0o700,exist_ok=True);protected_directory(maps);return root

def _binding(w,lane,repository_id):
    guards.require(lane in LANES,'Unknown integrity lane')
    return {'generation':w.c['generation'],'source':w.source,'code_sha':w.c['code_sha'],'lane':lane,
            'repository':w.c['repositories'][lane],'repository_id':guards.hex_id(repository_id,64),
            'producer_sha256':{name:sha(private_path(w.bin/name)) for name in PRODUCERS}}

def _nonce(w,lane,*,create=False):
    root=_root(w);path=root/('nonce-'+lane+'.json')
    if not path.exists() and not path.is_symlink() and create:
        guards.require(not (root/('full-'+lane+'.json')).exists(),'Integrity nonce missing from existing proof')
        runtime.atomic_json(path,{'format':1,'lane':lane,'generation':w.c['generation'],'nonce':uuid.uuid4().hex})
    value=runtime.load_json(private_path(path))
    guards.require(set(value)=={'format','lane','generation','nonce'} and value['format']==1 and
                   value['lane']==lane and value['generation']==w.c['generation'],'Integrity nonce binding differs')
    return guards.hex_id(value['nonce'],32)

def invalidate_lane(w,lane):
    """Durably invalidate old read authority before a cleanup intent/effect."""
    guards.require(lane in LANES,'Unknown integrity lane');root=_root(w)
    runtime.atomic_json(root/('nonce-'+lane+'.json'),{'format':1,'lane':lane,'generation':w.c['generation'],'nonce':uuid.uuid4().hex})

def _load(w,lane,repository_id,at,*,load_map=False):
    root=_root(w);path=private_path(root/('full-'+lane+'.json'));raw=path.read_bytes()
    guards.require(len(raw)<=65536,'Integrity header oversized');proof=backup_catalog.decode(raw)
    body={key:value for key,value in proof.items() if key!='sha256'}
    guards.require(proof.get('format')=='weekly-remote-read-v1' and proof.get('check_mode')=='read-data-no-cache' and
                   proof.get('sha256')==digest(body) and all(proof.get(k)==v for k,v in _binding(w,lane,repository_id).items()),
                   'Integrity proof binding/digest differs')
    times(proof,at,fresh=False);guards.hex_id(proof['nonce'],32)
    key=guards.hex_id(proof['snapshots_sha256'],64);mapping=private_path(root/'maps'/(key+'.json'))
    guards.require(sha(mapping)==key,'Integrity identity map bytes changed')
    if load_map:
        guards.require(mapping.stat().st_size<=64*1024*1024,'Integrity identity map oversized')
        proof['snapshots']=identities(backup_catalog.decode(mapping.read_bytes()))
    return proof

def _publish(w,lane,repository_id,current,started_at,completed_at,*,expected_nonce=None):
    identities(current);root=_root(w);nonce=_nonce(w,lane,create=True)
    guards.require(expected_nonce is None or nonce==expected_nonce,'Integrity invalidated during remote read')
    proof={'format':'weekly-remote-read-v1',**_binding(w,lane,repository_id),'nonce':nonce,
           'check_mode':'read-data-no-cache','started_at':started_at,'completed_at':completed_at,
           'snapshots_sha256':hashlib.sha256(backup_catalog.canonical(current)+b'\n').hexdigest()}
    times(proof,clock());mapping=root/'maps'/(proof['snapshots_sha256']+'.json')
    if mapping.exists() or mapping.is_symlink():guards.require(sha(private_path(mapping))==proof['snapshots_sha256'],'Existing integrity map differs')
    else:
        runtime.atomic_json(mapping,current)
    proof['sha256']=digest(proof);runtime.atomic_json(root/('full-'+lane+'.json'),proof);return proof

def publish_lane(w,lane,repository_id,rows,started_at,completed_at):
    """Trusted full-read success callback; metadata-only checks never call this."""
    current={}
    for row in rows:
        sid=guards.hex_id(row['id'],64);native,token,manifest=backup_catalog.native_identity(row,sid,str(w.root/'spool'/(lane+'-payload')),w.c['generation'])
        guards.require(sid not in current,'Duplicate full-read native snapshot');current[sid]=[native['tree'],token,manifest]
    return _publish(w,lane,repository_id,current,started_at,completed_at)

def _clear(w):
    for lane in LANES:
        path=w.root/'receipts/maintenance'/('pending-'+lane+'.json')
        guards.require(not path.exists() and not path.is_symlink(),'Pending maintenance blocks integrity reuse')

def _current(w,inventory):
    import retention,retention_cohort,retention_native
    with backup_catalog.ArchiveCatalog(w).open_reader() as reader:
        if inventory is None:inventory=retention.native_inventory(w,clock(),retention_cohort.repository_ids(w),clock,reader=reader)
        guards.require(inventory['generation']==w.c['generation'],'Integrity inventory generation differs')
        guards.require(inventory['repositories']==retention_cohort.repository_ids(w),'Integrity initialized repositories differ')
        tombstones=retention_native.verified_tombstones(w)
        journals={lane:runtime.UploadJournal(w.root/'receipts'/lane,w.c['generation']).state() for lane in LANES}
        retention.confirmed_inventory(inventory,journals,tombstones)
        current={lane:{} for lane in LANES}
        for row in inventory['snapshots']:
            lane=row['lane'];guards.require(lane in LANES,'Unknown integrity current lane');sid=row['id'];record=reader._record(sid)
            value=[row['tree'],row['token'],row['manifest_sha256']]
            guards.require(record['lane']==lane and record['repository_id']==inventory['repositories'][lane] and
                           record['generation']==w.c['generation'] and record['projection']['source']==w.source and
                           [record['native']['tree'],record['token'],record['manifest_sha256']]==value and
                           record['native']['time']==row['snapshot_time'],'Integrity current snapshot differs from verified catalog')
            guards.require(sid not in current[lane],'Duplicate current integrity ID');current[lane][sid]=value
        return inventory['repositories'],current,tombstones

def ensure(w,inventory=None,force=False,*,current_inventory=None):
    """Reuse coverage; current_inventory comes only from trusted CohortStore.load.

    The full read covers the authenticated current repository, including arrivals.
    Receipt current_snapshot fields bind the frozen consumer inventory; observed
    current fields retain the independently verified complete live coverage.
    """
    guards.require(type(force) is bool,'Explicit integrity force boolean required');root=_root(w)
    with runtime.lane_lock(root/'integrity.lock'):
        _clear(w);repositories,current,tombstones=_current(w,current_inventory if current_inventory is not None else inventory);reports={}
        bound=current
        if current_inventory is not None:
            guards.require(inventory is not None and inventory['generation']==w.c['generation'] and inventory['repositories']==repositories,
                           'Frozen integrity source/repositories differ')
            bound={lane:{} for lane in LANES}
            observed={row['id']:row for row in current_inventory['snapshots']}
            for row in inventory['snapshots']:
                sid=row['id'];lane=row['lane']
                guards.require(lane in LANES and sid not in bound[lane] and observed.get(sid)==row,
                               'Frozen integrity snapshot differs from authenticated current inventory')
                bound[lane][sid]=current[lane][sid]
        for lane in LANES:
            at=clock();nonce=_nonce(w,lane,create=True);path=root/('full-'+lane+'.json');proof=None
            if path.exists() or path.is_symlink():proof=_load(w,lane,repositories[lane],at,load_map=True)
            # A nonce invalidation requires real rereading, never relabelling.
            refresh=force or proof is None or proof['nonce']!=nonce or at-guards.utc(proof['completed_at'])>MAX_AGE
            if proof is not None:_coverage(proof,current[lane],tombstones,current[lane],at=at,lane=lane,fresh=False)
            if refresh:
                started=clock().isoformat();w.restic(lane,['--repo',w.c['repositories'][lane],'check','--read-data'],timeout=900)
                _clear(w);proof=_publish(w,lane,repositories[lane],current[lane],started,clock().isoformat(),expected_nonce=nonce);proof['snapshots']=current[lane]
            report=coverage(proof,current[lane],tombstones,current[lane],at=clock(),lane=lane)
            reports[lane]={**report,'observed_current_snapshots_sha256':report['current_snapshots_sha256'],
                           'observed_current_snapshot_count':report['current_snapshot_count'],
                           'current_snapshots_sha256':digest(bound[lane]),'current_snapshot_count':len(bound[lane]),
                           'repository_id':repositories[lane],'proof_sha256':proof['sha256'],
                           'snapshots_sha256':proof['snapshots_sha256'],'nonce':proof['nonce']}
        _clear(w);return {'format':MODE,'lanes':reports,'coverage_checked_at':clock().isoformat()}

def validate_report(report,inventory,at):
    guards.require(isinstance(report,dict) and report.get('format')==MODE and set(report['lanes'])==set(LANES),'Weekly integrity coverage absent')
    checked=guards.utc(report['coverage_checked_at']);guards.require(checked<=at and (at-checked).total_seconds()<=900,'Integrity coverage observation expired')
    for lane in LANES:
        row=report['lanes'][lane];times({'started_at':row['full_remote_started_at'],'completed_at':row['full_remote_completed_at']},at)
        current={r['id']:[r['tree'],r['token'],r['manifest_sha256']] for r in inventory['snapshots'] if r['lane']==lane};identities(current)
        guards.require(row['repository_id']==inventory['repositories'][lane] and row['current_snapshots_sha256']==digest(current) and
                       type(row['current_snapshot_count']) is int and row['current_snapshot_count']==len(current),'Integrity coverage inventory differs')
        guards.hex_id(row['observed_current_snapshots_sha256'],64)
        guards.require(type(row['observed_current_snapshot_count']) is int and row['observed_current_snapshot_count']>=len(current),
                       'Complete live integrity coverage must include frozen inventory')
        for key in ('proof_sha256','snapshots_sha256'):guards.hex_id(row[key],64)
        guards.hex_id(row['nonce'],32)
        for key in ('verified_arrivals','verified_retirements'):guards.require(type(row[key]) is int and row[key]>=0,'Integrity coverage counter differs')
    return True

def revalidate(w,report,*,at):
    """No catalog graph or remote I/O: prove frozen authority still unchanged."""
    import retention_cohort
    _clear(w);guards.require(report.get('format')==MODE and set(report['lanes'])==set(LANES),'Integrity report absent')
    ids=retention_cohort.repository_ids(w)
    for lane in LANES:
        expected=report['lanes'][lane];proof=_load(w,lane,expected['repository_id'],at)
        times(proof,at)
        guards.require(expected['repository_id']==ids[lane] and proof['sha256']==expected['proof_sha256'] and proof['snapshots_sha256']==expected['snapshots_sha256'] and
                       proof['nonce']==expected['nonce']==_nonce(w,lane) and proof['started_at']==expected['full_remote_started_at'] and
                       proof['completed_at']==expected['full_remote_completed_at'],'Weekly integrity authority changed after plan')
    return True

def status(w,*,at=None):
    """Local expiry/invalidation monitor; never renews or performs remote I/O."""
    import retention_cohort
    _clear(w);at=at or clock();ids=retention_cohort.repository_ids(w);result={}
    for lane in LANES:
        proof=_load(w,lane,ids[lane],at);times(proof,at)
        guards.require(proof['nonce']==_nonce(w,lane),'Weekly integrity invalidated')
        result[lane]=proof['completed_at']
    return result
