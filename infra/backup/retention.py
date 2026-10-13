"""Read-only native inventory/anchor audit. No remote deletion or scheduling."""
import argparse,contextlib,datetime as dt,hashlib,io,json,os,pathlib,sys,uuid,time
import guards,runtime,restic_adapter,backup_catalog
from worker import Worker,DB_IMAGE,sha,private_path,now
from restore import Recovery,replay_range

MAX_RETENTION_INTENT=1536

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':')).encode()

def inventory_digest(inventory):
    value={'generation':inventory['generation'],'repositories':inventory['repositories'],
           'snapshots':sorted(inventory['snapshots'],key=lambda x:(x['lane'],x['id']))}
    return hashlib.sha256(canonical(value)).hexdigest()

def same_inventory(before,after):
    guards.require(inventory_digest(before)==inventory_digest(after),'Remote inventory changed during audit; deletion disabled')
    return True

def decode(data):
    try:
        guards.require(isinstance(data,bytes) and len(data)<=64*1024*1024,'Native JSON oversized')
        return json.loads(data,object_pairs_hook=runtime.no_duplicates,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))
    except (ValueError,UnicodeError,RecursionError) as error:
        raise guards.GuardError('Invalid authenticated JSON') from error

def native_view_digest(config,listed):
    """Seal every decoded native field, independent of list iteration order."""
    guards.require(isinstance(config,dict) and isinstance(listed,list),'Complete native view required')
    seen=set();digest=hashlib.sha256();digest.update(canonical(config));digest.update(b'\n')
    for row in sorted(listed,key=lambda value:guards.hex_id(value['id'],64)):
        sid=row['id'];guards.require(sid not in seen,'Duplicate native snapshot identity');seen.add(sid)
        digest.update(canonical(row));digest.update(b'\n')
    return digest.hexdigest()

def verify_native_views(worker,expected,deadline):
    """Re-read unfiltered config and snapshots under the reserved group.

    The complete manifest/dependency audit and its exact protected authority
    bytes were checked outside. Equality transfers that audit; no native field
    is projected away, and unknown or duplicate snapshots cannot inherit it.
    """
    guards.require(set(expected)=={'base','binlog'},'Prepared native views missing')
    for lane in ('base','binlog'):
        def read(args):
            remaining=deadline-time.monotonic();guards.require(remaining>0,'Native critical inventory deadline exceeded')
            raw=worker.restic(lane,['--repo',worker.c['repositories'][lane],*args],timeout=remaining)
            guards.require(time.monotonic()<deadline,'Native critical inventory deadline exceeded');return decode(raw)
        config=read(['cat','config']);listed=read(['snapshots','--json'])
        guards.require(native_view_digest(config,listed)==expected[lane],'Final unfiltered native inventory differs from prepared proof')
        del config,listed
        guards.require(time.monotonic()<deadline,'Native critical metadata deadline exceeded')

def verify_reader_prefix(reader):
    """Recheck every cached old row/blob byte in short independent read batches."""
    c=reader.catalog;previous=c._seed(reader.head);count=reader.head['sequence']
    for first in range(1,count+1,256):
        last=min(count,first+255);expected={}
        with reader._read_lock(),c._db() as db:
            rows=db.execute('SELECT sequence,sid,token,record,body,chain FROM archives WHERE sequence BETWEEN ? AND ? ORDER BY sequence',(first,last))
            sequence=first-1
            for seq,sid,token,raw,body,chain in rows:
                sequence+=1;record=reader._records.get(sid)
                guards.require(seq==sequence and record is not None and token==record['token'] and raw==backup_catalog.canonical(record) and
                               isinstance(body,bytes) and hashlib.sha256(body).hexdigest()==record['raw_compressed_sha256'],
                               'Prepared catalog old row or raw manifest bytes changed')
                previous=hashlib.sha256(bytes.fromhex(previous)+raw).hexdigest()
                guards.require(chain==previous,'Prepared catalog old ordinal chain changed')
                expected.update({(sid,item['file']):item for item in record['cached_logs']})
            guards.require(sequence==last,'Prepared catalog old prefix shortened')
            for sid,name,body in db.execute('SELECT l.sid,l.name,l.body FROM logs l JOIN archives a ON a.sid=l.sid WHERE a.sequence BETWEEN ? AND ?',(first,last)):
                item=expected.pop((sid,name),None)
                guards.require(item is not None and isinstance(body,bytes) and len(body)<=backup_catalog.MAX_FILE_BYTES and
                               hashlib.sha256(body).hexdigest()==item['compressed_sha256'],'Prepared catalog old binlog bytes changed')
            guards.require(not expected,'Prepared catalog old binlog missing')
    guards.require(previous==reader.head['chain'],'Prepared catalog old head changed')
    with reader._read_lock(),c._db() as db:
        guards.require(db.execute('SELECT 1 FROM logs l LEFT JOIN archives a ON a.sid=l.sid WHERE a.sid IS NULL LIMIT 1').fetchone() is None,
                       'Prepared catalog foreign binlog row')

def reader_raw_prefix_seal(reader,*,head=None,verify=False,deadline=None):
    """Hash exact old logical bytes using independent 256-row read batches.

    Outside preparation compares every byte seal to its original reader.
    Later digest equality transfers that audit without a second object graph.
    """
    c=reader.catalog;head=head or reader.head;boundary=head['sequence'];value=hashlib.sha256()
    def check():
        if deadline is not None:guards.require(time.monotonic()<deadline,'Catalog raw-prefix deadline exceeded')
    def add(item):
        if item is None:tag=b'n';raw=b''
        elif type(item) is int:tag=b'i';raw=str(item).encode()
        elif isinstance(item,str):tag=b's';raw=item.encode()
        else:guards.require(isinstance(item,bytes),'Catalog raw-prefix type differs');tag=b'b';raw=item
        value.update(tag);value.update(len(raw).to_bytes(8,'big'));value.update(raw)
    def state(db):
        check();current=c._head();c._tail(db,current)
        guards.require(current.get('checkpoint')==head.get('checkpoint') and current['sequence']>=boundary,'Original catalog prefix epoch changed')
        return list(db.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name'))
    def checkpoints(db,schema):
        if not any(row[1]=='catalog_checkpoint' and row[0]=='table' for row in schema):return []
        result=[]
        for slot,raw in db.execute('SELECT slot,record FROM catalog_checkpoint ORDER BY slot'):
            check();guards.require(isinstance(raw,bytes),'Original catalog checkpoint body type differs')
            result.append((slot,len(raw),hashlib.sha256(raw).hexdigest()))
        return result
    with reader._read_lock(deadline),c._db() as db:
        schema=state(db);checkpoint=checkpoints(db,schema)
    proof=head.get('checkpoint')
    guards.require((not checkpoint if proof is None else len(checkpoint)==1 and checkpoint[0][0]==1 and checkpoint[0][2]==proof['sha256']),
                   'Catalog checkpoint differs from original head')
    for row in schema:
        add('schema')
        for item in row:add(item)
    for row in checkpoint:
        add('checkpoint')
        for item in row:add(item)
    previous=c._seed(head);sequence=0;logs=0
    for first in range(1,boundary+1,256):
        last=min(boundary,first+255);expected_logs=0;batch_logs=0
        with reader._read_lock(deadline),c._db() as db:
            guards.require(state(db)==schema,'Original catalog schema changed between batches')
            for row in db.execute('SELECT sequence,sid,token,record,body,chain FROM archives WHERE sequence BETWEEN ? AND ? ORDER BY sequence',(first,last)):
                check();seq,sid,token,raw,body,chain=row;sequence+=1
                guards.require(seq==sequence and isinstance(raw,bytes) and isinstance(body,bytes),'Original catalog prefix membership differs')
                if verify:
                    record=reader._records.get(sid)
                    guards.require(record is not None and token==record['token'] and raw==backup_catalog.canonical(record) and
                                   hashlib.sha256(body).hexdigest()==record['raw_compressed_sha256'],'Prepared catalog old row or raw manifest bytes changed')
                    expected_logs+=len(record['cached_logs'])
                previous=hashlib.sha256(bytes.fromhex(previous)+raw).hexdigest()
                guards.require(chain==previous,'Original catalog raw-prefix chain changed');add('archive')
                for item in (seq,sid,token,raw,hashlib.sha256(body).digest(),chain):add(item)
            guards.require(sequence==last,'Original catalog prefix shortened')
            query="""SELECT a.sequence,l.rowid,l.sid,l.name,typeof(l.body),length(l.body),
                     CASE WHEN length(l.body)<=1048576 THEN l.body ELSE NULL END FROM logs l JOIN archives a ON a.sid=l.sid
                     WHERE a.sequence BETWEEN ? AND ? ORDER BY a.sequence,l.name"""
            for seq,rowid,sid,name,kind,size,body in db.execute(query,(first,last)):
                check();guards.require(kind=='blob' and type(size) is int and 0<=size<=backup_catalog.MAX_FILE_BYTES,'Original cached body type/size differs')
                if body is None:
                    compressed=hashlib.sha256()
                    with db.blobopen('logs','body',rowid,readonly=True) as blob:
                        while block:=blob.read(1024**2):check();compressed.update(block)
                    seal=compressed.hexdigest()
                else:
                    guards.require(isinstance(body,bytes),'Original cached body type differs');seal=hashlib.sha256(body).hexdigest()
                if verify:
                    item=next((item for item in reader._records[sid]['cached_logs'] if item['file']==name),None)
                    guards.require(item is not None and item['compressed_sha256']==seal,'Prepared catalog old binlog bytes changed')
                add('cached')
                for item in (seq,sid,name,kind,size,seal):add(item)
                logs+=1;batch_logs+=1
            if verify:guards.require(batch_logs==expected_logs,'Original cached body membership differs')
    guards.require(sequence==boundary and previous==head['chain'],'Original catalog raw-prefix head changed')
    with reader._read_lock(deadline),c._db() as db:
        guards.require(state(db)==schema,'Original catalog schema changed after batches')
        guards.require(checkpoints(db,schema)==checkpoint,'Original catalog checkpoint raw body changed')
        guards.require(db.execute('SELECT 1 FROM logs l LEFT JOIN archives a ON a.sid=l.sid WHERE a.sid IS NULL LIMIT 1').fetchone() is None,'Catalog foreign cached row')
    for item in ('end',boundary,logs):add(item)
    check();return value.hexdigest()

def refresh_prepared_inventory(worker,current,views,reader,candidates,at):
    """Transfer the old complete audit; validate only authenticated appended IDs.

    One unfiltered native refresh seals every field again. Filtering exactly
    new catalog IDs must reproduce the prior complete native digest; old
    identities, configurations, source bodies and ordinals never get resealed.
    """
    import binlog,retention_cohort
    prior_reader=reader
    indexed={row['id']:row for row in current['snapshots']};fresh=[];manifests=dict(current['manifests']);updated_views={}
    for lane in ('base','binlog'):
        repo=worker.c['repositories'][lane];config=decode(worker.restic(lane,['--repo',repo,'cat','config']))
        bounded={'timeout':55} if worker.c.get('retention_readiness_policy')=='native-v2' else {}
        listed=decode(worker.restic(lane,['--repo',repo,'snapshots','--json'],**bounded));reader=reader.refresh()
        observed=retention_cohort.clock();guards.require(observed>=at,'Prepared refresh clock rollback');at=observed
        old={sid for sid,row in indexed.items() if row['lane']==lane};new={row['id'] for row in listed}-old
        # The prior reader may already contain a concurrent admission that
        # finished after the earlier native response. New membership is relative
        # to that complete native view, rather than the newer catalog view.
        # Old native fields remain exact below; every new row still requires its
        # authenticated catalog seal, full manifest/file proof and journal check.
        guards.require(not new&set(indexed) and new<=set(reader._records),
                       'Native refresh contains an unknown or cross-lane arrival')
        guards.require(native_view_digest(config,[row for row in listed if row['id'] not in new])==views[lane],
                       'Prepared old complete native fields or configuration changed')
        updated_views[lane]=native_view_digest(config,listed)
        for metadata in listed:
            sid=metadata['id']
            if sid not in new:continue
            record=reader._record(sid);scope=str(worker.root/'spool'/(lane+'-payload'))
            native,token,digest=backup_catalog.native_identity(metadata,sid,scope,worker.c['generation'])
            guards.require(record['lane']==lane and record['repository_id']==config['id'] and record['native']==native and record['manifest_sha256']==digest,
                           'Prepared arrival native metadata differs from catalog')
            raw=reader.raw_manifest(sid);manifest=decode(raw)
            guards.require({k:v for k,v in manifest.items() if k!='files'}==record['projection'] and
                           manifest['source']==worker.source and manifest['generation']==worker.c['generation'] and manifest['format']==1,
                           'Prepared arrival full manifest differs')
            guards.hex_id(manifest['code_sha'],40);captured=guards.utc(manifest['captured_at']);uploaded=guards.utc(metadata['time'])
            guards.require(captured<=uploaded<=at,'Prepared arrival timestamp differs')
            guards.require(manifest['kind'] in (('full','pre-update','hourly') if lane=='base' else ('binlog',)), 'Prepared arrival lane/kind differs')
            if lane=='base':guards.require(manifest['stage_app_sha']==worker.c['stage_app_sha'],'Prepared arrival application differs')
            files=manifest['files'];actual=sorted([*files,{'path':'manifest.json','bytes':len(raw),'sha256':digest}],key=lambda item:item['path'])
            guards.require(len(actual)==record['verified']['file_count'] and sum(item['bytes'] for item in files)==record['verified']['payload_bytes'] and
                           backup_catalog.digest(backup_catalog.canonical(actual))==record['verified']['all_files_sha256'],
                           'Prepared arrival actual all-file proof differs')
            if lane=='binlog':
                for item in manifest['logs']:
                    body=reader.binlog_bytes(sid,item['file'])
                    binlog.validate_chain({item['file']:body},[item],{'file':item['file'],'position':4},{'file':item['file'],'position':item['size']})
            fresh.append({'id':sid,'lane':lane,'token':token,'manifest_sha256':digest,'kind':manifest['kind'],'generation':worker.c['generation'],
                          'time':manifest['captured_at'],'snapshot_time':metadata['time'],'tree':native['tree']})
            manifests[sid]=record['projection']
            del actual,files,raw,manifest
        del listed,config
    guards.require(len({row['id'] for row in fresh})==len(fresh) and not set(candidates)&{row['id'] for row in fresh},'Prepared arrival identity overlaps frozen authority')
    rows=[*current['snapshots'],*fresh];all_rows={row['id']:row for row in rows};tokens=[row['token'] for row in rows]
    guards.require(len(tokens)==len(set(tokens)),'Prepared arrival token duplicate')
    last=max(manifest['last_log'] for sid,manifest in current['manifests'].items() if indexed[sid]['lane']=='binlog')
    for row in sorted((row for row in fresh if row['lane']=='binlog'),key=lambda row:manifests[row['id']]['first_log']):
        m=manifests[row['id']];guards.checked_logs(m['logs'])
        guards.require(m['previous_count']==last and m['first_log']==last+1 and guards.log_number(m['logs'][0]['file'])==last+1 and
                       m['last_log']==guards.log_number(m['logs'][-1]['file']),'Prepared appended chain range differs')
        last=m['last_log']
    descriptors={item['file']:item for sid,m in manifests.items() if all_rows[sid]['lane']=='binlog' for item in m['logs']}
    last_deleted=max((manifests[sid]['last_log'] for sid in candidates if sid in all_rows and all_rows[sid]['lane']=='binlog'),default=0)
    for row in fresh:
        if row['lane']!='base':continue
        m=manifests[row['id']];start=m['coordinates'];descriptor=descriptors.get(start['file'])
        guards.require(descriptor is not None and type(start['position']) is int and 4<=start['position']<=descriptor['size'] and
                       last_deleted<guards.log_number(start['file']),'Prepared base arrival requires a frozen binlog candidate')
        if row['kind']=='hourly':
            full_id=guards.hex_id(m['full_id'],64);full=all_rows.get(full_id)
            guards.require(full is not None and full['kind'] in ('full','pre-update') and full_id not in candidates and guards.utc(full['time'])<=guards.utc(row['time']) and
                           all(m[key]==manifests[full_id][key] for key in ('source','stage_app_sha','application_sha256','configuration_sha256')),
                           'Prepared hourly arrival requires a frozen or different full')
    verify_reader_prefix(prior_reader)
    return {**current,'snapshots':rows,'manifests':manifests,'observed_at':at.isoformat()},updated_views,reader

def native_inventory(worker,at,repository_ids,clock=None,*,reader=None,deadline=None,reader_out=None,native_views=None,native_prefix=None,_flight_wait=None):
    guards.require(native_views is None or isinstance(native_views,dict) and not native_views,'Empty native view output required')
    guards.require(reader_out is None or (reader is not None and isinstance(reader_out,list) and len(reader_out)==1 and reader_out[0] is reader),
                   'Native reader output must hold the supplied frozen reader')
    if native_prefix is not None:
        guards.require(isinstance(native_prefix,dict) and set(native_prefix)=={'ids','views'} and
                       set(native_prefix['ids'])==set(native_prefix['views'])=={'base','binlog'}, 'Complete original native prefix required')
    w=worker;entries=[];manifests={};tokens=set();observed=at
    catalog=backup_catalog.ArchiveCatalog(w)
    if reader is not None:records=reader._records
    else:records=catalog.entries()
    if reader is not None:
        import retention_cohort
        _flight_wait=_flight_wait if _flight_wait is not None else retention_cohort._FlightWait()
    backfilled=False;live={}
    for lane in ('base','binlog'):
        repo=w.c['repositories'][lane];scope=str(w.root/'spool'/(lane+'-payload'))
        def run(args):
            if deadline is None:
                # Native cache.Clear can remove arrivals missed by this LIST.
                # Bound that overlap before issuing a commissioned v2 view.
                if w.c.get('retention_readiness_policy')=='native-v2' and args==['snapshots','--json']:
                    return w.restic(lane,['--repo',repo,*args],timeout=55)
                return w.restic(lane,['--repo',repo,*args])
            remaining=deadline-time.monotonic();guards.require(remaining>0,'Native critical inventory deadline exceeded')
            result=w.restic(lane,['--repo',repo,*args],timeout=remaining)
            guards.require(time.monotonic()<deadline,'Native critical inventory deadline exceeded');return result
        config=decode(run(['cat','config']))
        guards.require(config['version']==2 and config['id']==guards.hex_id(repository_ids[lane],64),'Repository identity changed')
        listed=decode(run(['snapshots','--json']));guards.require(isinstance(listed,list),'Complete snapshot inventory required')
        if native_views is not None:native_views[lane]=native_view_digest(config,listed)
        if native_prefix is not None:
            guards.require(native_view_digest(config,[row for row in listed if row['id'] in native_prefix['ids'][lane]])==native_prefix['views'][lane],
                           'Original complete native fields or configuration changed')
        if reader is not None:
            # A full native listing can finish after a normal upload has been
            # admitted. Authenticate its exact indexed tail before checking
            # those IDs; neither native tags nor an unknown ID admit a row.
            # Keep the caller's frozen reader unchanged until both lanes pass.
            reader=reader.refresh(deadline=deadline)
            unknown=[(lane,row) for row in listed if row['id'] not in reader._records]
            reader=retention_cohort._settle_producer(w,reader,_flight_wait,unknown=unknown,deadline=deadline);records=reader._records
        for row in listed:
            if deadline is not None:guards.require(time.monotonic()<deadline,'Native critical metadata deadline exceeded')
            sid=guards.hex_id(row['id'],64);guards.require(sid not in manifests,'Duplicate snapshot across inventory')
            # Native snapshots --json already decrypts/authenticates each
            # snapshot. Reopening the same metadata in N new native processes
            # adds no proof; manifests still require actual archived raw bytes.
            metadata=row
            guards.require(all(key in metadata for key in ('tags','paths','time','tree')),
                           'Incomplete native authenticated snapshot metadata')
            guards.hex_id(metadata['tree'],64);tags=metadata['tags']
            guards.require(metadata['paths']==[scope] and isinstance(tags,list) and all(isinstance(x,str) for x in tags) and len(tags)==len(set(tags)) and 'task047' in tags,'Unknown snapshot source or tags')
            def tag(prefix):
                values=[x[len(prefix):] for x in tags if x.startswith(prefix)]
                guards.require(len(values)==1,'Ambiguous authenticated tag');return values[0]
            guards.require(tag('generation:')==w.c['generation'],'Foreign generation in repository')
            token=guards.hex_id(tag('token:'),32);digest=guards.hex_id(tag('manifest-sha:'),64)
            guards.require(token not in tokens,'Duplicate upload token');tokens.add(token)
            native,_,_=backup_catalog.native_identity(metadata,sid,scope,w.c['generation'])
            # A supplied reader forbids cold backfill, so it needs no second
            # retained graph of every native identity after exact comparison.
            if reader is None:live[sid]=(lane,native)
            if sid in records:
                record=records[sid]
                guards.require(record['lane']==lane and record['repository_id']==config['id'] and record['native']==native and record['manifest_sha256']==digest,
                               'Native metadata differs from verified catalog')
                manifest=record['projection']
            else:
                guards.require(reader is None,'Uncatalogued current arrival; native admission required before capture/effect')
                # Cold backfill reuses native unfiltered metadata, then performs
                # actual all-file restore verification. No tags/flags import.
                body=run(['dump',sid,scope+'/manifest.json']);guards.require(isinstance(body,bytes) and hashlib.sha256(body).hexdigest()==digest,'Authenticated manifest digest differs')
                manifest=decode(body)
            kind=manifest['kind']
            guards.require(manifest['format']==1 and manifest['generation']==w.c['generation'] and manifest['source']==w.source,'Foreign snapshot manifest')
            guards.require(kind in (('full','pre-update','hourly') if lane=='base' else ('binlog',)),'Wrong snapshot lane/kind')
            guards.hex_id(manifest['code_sha'],40)
            captured=guards.utc(manifest['captured_at']);uploaded=guards.utc(metadata['time'])
            if clock is not None:
                current=clock()
                guards.require(isinstance(current,dt.datetime) and current.tzinfo is not None and current>=observed,
                               'Trusted observation clock rolled back')
                observed=current.astimezone(dt.timezone.utc)
            guards.require(captured<=uploaded<=observed,'Future snapshot or capture timestamp mismatch')
            if lane=='base':guards.require(manifest['stage_app_sha']==w.c['stage_app_sha'],'Unknown stage application')
            if sid not in records:
                guards.require(callable(getattr(w,'verify_archive',None)) and
                               w.verify_archive(lane,sid,manifest,native_metadata=metadata,raw_manifest=body) is True,
                               'Actual native catalog backfill required');backfilled=True
            if sid in records:
                # Reuse equal immutable scalar strings from the sealed record;
                # the mutable projected row remains a separate dictionary.
                sid=record['id'];token=record['token'];digest=record['manifest_sha256'];metadata=record['native']
            entries.append({'id':sid,'lane':lane,'token':token,'manifest_sha256':digest,'kind':kind,
                            'generation':w.c['generation'],'time':manifest['captured_at'],'snapshot_time':metadata['time'],'tree':metadata['tree']})
            manifests[sid]={k:v for k,v in manifest.items() if k!='files'}
        del listed
    if backfilled:
        # One full seal scan for the cold run, never one scan per admission.
        records=catalog.entries()
        for sid,(lane,native) in live.items():
            record=records.get(sid)
            guards.require(record is not None and record['native']==native and record['repository_id']==repository_ids[lane] and
                           record['lane']==lane and record['projection']==manifests[sid],'Native backfill was not committed to verified catalog')
    result={'generation':w.c['generation'],'repositories':dict(repository_ids),'snapshots':entries,'manifests':manifests,
            'observed_at':observed.isoformat()}
    if reader_out is not None:reader_out[0]=reader
    return result

def confirmed_inventory(inventory,journals,tombstones=()):
    retired={}
    for row in tombstones:
        sid=guards.hex_id(row['id'],64)
        guards.require(sid not in retired and row['generation']==inventory['generation'] and row['lane'] in ('base','binlog'),'Duplicate or foreign tombstone')
        for key in ('manifest_sha256','intent_sha256','receipt_sha256','pre_inventory_sha256','post_inventory_sha256'):guards.hex_id(row[key],64)
        guards.hex_id(row['token'],32);guards.utc(row['forgotten_at']);retired[sid]=row
    for lane in ('base','binlog'):
        rows=[x for x in inventory['snapshots'] if x['lane']==lane];confirmed=journals[lane]['confirmed']
        expected={x['id']:(x['token'],x['manifest_sha256']) for x in confirmed}
        actual={x['id']:(x['token'],x['manifest_sha256']) for x in rows}
        removed={sid:(row['token'],row['manifest_sha256']) for sid,row in retired.items() if row['lane']==lane}
        guards.require(not set(removed)&set(actual) and all(expected.get(sid)==value for sid,value in removed.items()),'Tombstone not bound to exact absent confirmation')
        guards.require(len(expected)==len(confirmed) and {sid:value for sid,value in expected.items() if sid not in removed}==actual,'Unknown or missing acknowledged snapshot; preserve/investigate')
    return True

def inventory_plan(inventory,at):
    entries=inventory['snapshots'];manifests=inventory['manifests'];records=[];logs=[]
    batches=sorted([x for x in entries if x['kind']=='binlog'],key=lambda x:manifests[x['id']]['first_log'])
    guards.require(batches,'No authenticated binlog chain')
    for row in batches:
        manifest=manifests[row['id']];batch=manifest['logs'];guards.checked_logs(batch)
        first=guards.log_number(batch[0]['file']) if batch else None
        guards.require(batch and type(manifest['previous_count']) is int and manifest['previous_count']==first-1 and manifest['first_log']==first and manifest['last_log']==guards.log_number(batch[-1]['file']) and (not logs or first==guards.log_number(logs[-1]['file'])+1),'Binlog manifest range/previous count mismatch')
        logs.extend(batch);records.append({**row,'first_log':manifest['first_log'],'last_log':manifest['last_log']})
    guards.retained_logs(logs);log_index={item['file']:item for item in logs}
    indexed={x['id']:x for x in entries};guards.require(len(indexed)==len(entries),'Duplicate inventory identity')
    for row in entries:
        if row['kind']=='binlog':continue
        manifest=manifests[row['id']];start=manifest['coordinates']
        guards.require(type(start['position']) is int and start['position']>=4,'Invalid base coordinates')
        for key in ('application_sha256','configuration_sha256'):guards.hex_id(manifest[key],64)
        record={**row,'first_log':guards.log_number(start['file'])}
        if row['kind']=='hourly':
            full_id=guards.hex_id(manifest['full_id'],64);full=indexed.get(full_id);guards.require(full and full['kind'] in ('full','pre-update'),'Missing hourly full')
            full_manifest=manifests[full_id]
            guards.require(guards.utc(full['time'])<=guards.utc(row['time']),'Hourly references a future full')
            guards.require(all(manifest[k]==full_manifest[k] for k in ('source','stage_app_sha','application_sha256','configuration_sha256')),'Hourly/full source application mismatch')
            record['full_id']=full_id
        records.append(record)
    plan=guards.retention_candidates(records,inventory['generation'],at)
    first=guards.log_number(logs[0]['file']);cutoff=at-dt.timedelta(days=30)
    dependencies={manifests[r['id']]['full_id'] for r in entries if r['kind']=='hourly' and r['id'] in plan['keep']}
    for row in entries:
        if row['kind']=='binlog':continue
        start=manifests[row['id']]['coordinates']
        if guards.log_number(start['file'])<first:
            guards.require((row['id'] in dependencies or row['id'] in plan['candidates']) and row['kind'] in ('full','pre-update') and guards.utc(row['time'])<cutoff and row['id']!=plan['anchor_id'],'Unavailable recovery base below retained suffix')
        else:
            descriptor=log_index.get(start['file'])
            guards.require(descriptor is not None and start['position']<=descriptor['size'],'Missing or truncated recovery base coordinate')
    return {**plan,**({'cohort':inventory['cohort']} if 'cohort' in inventory else {}),
            'logs':logs,'inventory_sha256':inventory_digest(inventory),'chain_last_file':logs[-1]['file'],'chain_last_position':logs[-1]['size']}

def bounded_plan(inventory,plan,limit=256):
    """One deterministic safe intent, retaining every deferred expired ID.

    Expired bases go first: deferred hourly snapshots keep their full; binlog
    deletion begins only after all deletable bases fit in this intent. The
    remaining binlogs are always an original-numbered prefix, never random IDs.
    Native commands within it remain bounded independently; a later intent
    needs a fresh inventory and all current proof gates again.
    """
    guards.require(type(limit) is int and 0<limit<=MAX_RETENTION_INTENT,'Invalid native intent bound')
    if len(plan['candidates'])<=limit:return dict(plan)
    indexed={row['id']:row for row in inventory['snapshots']};manifests=inventory['manifests']
    eligible=set(plan['candidates']);chosen=[]
    bases=sorted((indexed[sid] for sid in eligible if indexed[sid]['lane']=='base'),
                 key=lambda row:(row['kind']!='hourly',guards.utc(row['time']),row['id']))
    for row in bases:
        if len(chosen)==limit:break
        if row['kind'] in ('full','pre-update') and any(r['kind']=='hourly' and
                manifests[r['id']]['full_id']==row['id'] and r['id'] not in chosen
                for r in inventory['snapshots']):continue
        chosen.append(row['id'])
    if all(row['id'] in chosen for row in bases):
        logs=sorted((indexed[sid] for sid in eligible if indexed[sid]['lane']=='binlog'),
                    key=lambda row:manifests[row['id']]['first_log'])
        chosen.extend(row['id'] for row in logs[:limit-len(chosen)])
    guards.require(chosen,'No safe bounded retention progress')
    return {**plan,'eligible_candidates':sorted(eligible),'candidates':sorted(chosen),
            'keep':sorted(set(plan['keep'])|(eligible-set(chosen)))}

def bind_recovery(inventory,plan,proof):
    try:
        sid=plan['anchor_id'];base=inventory['manifests'][sid];row=next(x for x in inventory['snapshots'] if x['id']==sid)
        full_id=base['full_id'] if row['kind']=='hourly' else sid
        full_row=next(x for x in inventory['snapshots'] if x['id']==full_id)
        guards.require(proof['result']=='PASS' and proof['base_id']==sid and proof['base_manifest_sha256']==row['manifest_sha256'] and proof['full_id']==full_id and proof['full_manifest_sha256']==full_row['manifest_sha256'],'Native recovery anchor identity mismatch')
        guards.require(proof['source']==base['source'] and proof['stage_app_sha']==base['stage_app_sha'] and proof['coordinates']==base['coordinates'],'Native recovery source or coordinates mismatch')
        selected=replay_range(base['coordinates'],proof['stop'],plan['logs'])
        guards.require(type(proof['replayed_logs']) is int and proof['replayed_logs']==len(selected) and proof['verified_binlogs']==selected and isinstance(proof['media']['inventory'],list),'Native recovery binlog bytes or media receipt mismatch')
        guards.require(all(proof[k] is True for k in ('synthetic_order_after_base','synthetic_operation_after_base')),'Native after-base control absent')
        profile=proof.get('profile','point');guards.require(profile in ('point','tip'),'Unknown recovery profile')
        if profile=='tip':
            guards.require(proof['later_order_operation_excluded'] is False and proof['additional_order_operation_present'] is True and proof['stop']=={'file':plan['chain_last_file'],'position':plan['chain_last_position']},'Exact-tip presence proof absent')
        else:guards.require(proof['later_order_operation_excluded'] is True,'Point exclusion proof absent')
        return {'base_id':sid,'manifest_sha256':row['manifest_sha256'],'stop':proof['stop'],'replayed_logs':len(selected),'media_references':len(proof['media']['inventory']),'SQL_reimport_or_replay':False}
    except (KeyError,TypeError,StopIteration) as error:
        raise guards.GuardError('Incomplete native recovery binding') from error

def cached_log_audit(reader,inventory,target):
    """Stream sealed catalog bytes, checking every original ROW/CRC file.

    Full payload verification was required at admission. Native read-data and
    current unfiltered tree equality remain separate compulsory controls.
    """
    import binlog
    target=pathlib.Path(target);plan=inventory_plan(inventory,guards.utc(inventory['cohort']['planned_at']))
    owners={item['file']:(row['id'],item) for row in inventory['snapshots'] if row['lane']=='binlog'
            for item in inventory['manifests'][row['id']]['logs']}
    coordinates={}
    for row in inventory['snapshots']:
        if row['lane']=='base':
            start=inventory['manifests'][row['id']]['coordinates'];coordinates.setdefault(start['file'],[]).append(start)
    events=rows=0
    for item in plan['logs']:
        sid,descriptor=owners[item['file']];guards.require(descriptor==item,'Catalog log descriptor differs')
        raw=reader.binlog_bytes(sid,item['file']);stop={'file':item['file'],'position':len(raw)}
        report=binlog.validate_chain({item['file']:raw},[item],{'file':item['file'],'position':4},stop)
        for start in coordinates.get(item['file'],[]):binlog.validate_chain({item['file']:raw},[item],start,stop)
        path=target/item['file']
        if path.exists() or path.is_symlink():
            guards.require(path.is_file() and not path.is_symlink() and path.stat().st_nlink==1 and sha(path)==item['sha256'],
                           'Existing audited log changed')
        else:
            with open(path,'xb') as output:output.write(raw);output.flush();os.fsync(output.fileno())
            os.chmod(path,0o600)
        events+=report['event_count'];rows+=report['selected_row_events']
    return {'files':len(plan['logs']),'events':events,'row_events':rows,'guard':'strict-mariadb-10.11-row'}

class Inspector:
    def __init__(self,config):
        self.config=config;self.w=Worker(config);self.root=self.w.root/'spool'/('retention-audit-'+uuid.uuid4().hex)
    def recovery_checks(self,inventory,plan):
        if self.w.c.get('retention_readiness_policy','legacy-v1')=='native-v2':
            import retention_restore
            latest=max((row for row in inventory['snapshots'] if row['lane']=='base'),key=lambda row:(guards.utc(row['time']),row['id']))['id']
            checks=[('anchor',retention_restore.RetentionRecovery(self.w,'anchor'),plan,retention_restore.bind_recovery),
                    ('tip',retention_restore.RetentionRecovery(self.w,'tip'),{**plan,'anchor_id':latest},retention_restore.bind_recovery)]
        else:
            recovery=Recovery(self.config,self.w.root/'config/restore-plan.json')
            guards.require(recovery.plan['base_id']==plan['anchor_id'],'Current anchor requires a new separately owned restore control; preserve existing DB')
            checks=[('anchor',recovery,plan,bind_recovery)]
        result={}
        for name,recovery,selected,binder in checks:
            with contextlib.redirect_stdout(io.StringIO()):proof=recovery.verify_existing()
            if self.w.c.get('retention_readiness_policy','legacy-v1')=='native-v2':
                guards.require(proof.get('profile')==name,'Operational audit recovery profile differs')
            binding=binder(inventory,selected,proof)
            for item in proof['verified_binlogs']:
                path=recovery.root/'logs'/item['file']
                guards.require(path.resolve()==path and not path.is_symlink() and path.stat().st_nlink==1 and path.stat().st_size==item['size'] and sha(path)==item['sha256'],'Recovery file differs from audited S3 binlog')
            result[name]=(proof,binding)
        return result
    def run(self):
        import retention_cohort,time
        w=self.w;w.gate();started=now();scan_started=time.monotonic()
        with runtime.lane_lock(w.root/'receipts/retention-audit.lock'):
            self.root.mkdir(mode=0o700);(self.root/'logs').mkdir(mode=0o700)
            runtime.atomic_json(self.root/'intent.json',{'generation':w.c['generation'],'code_sha':w.c['code_sha'],'started_at':now(),'remote_delete':False})
            current_inventory=None
            from retention_native import verified_tombstones
            def audit_journals():
                journals={}
                for lane in ('base','binlog'):
                    guards.require(not (w.root/'receipts'/lane/'pending.json').exists(),'Unknown pending upload; retention audit stopped')
                    journals[lane]=runtime.UploadJournal(w.root/'receipts'/lane,w.c['generation']).state()
                return journals
            if w.c.get('retention_readiness_policy','legacy-v1')=='native-v2':
                current_inventory={}
                with backup_catalog.ArchiveCatalog(w).open_reader() as reader:
                    before=retention_cohort.CohortStore(w).load(reader,current_out=current_inventory)
                    journals=audit_journals()
                    retention_cohort.confirm_observation(w,current_inventory,reader,journals=journals,tombstones=verified_tombstones(w))
                age=(guards.utc(now())-guards.utc(before['cohort']['planned_at'])).total_seconds()
                guards.require(0<=age<=900,'Existing frozen audit cohort expired')
                capture_timing={'critical_seconds':0}
            else:
                before,capture_timing=retention_cohort.CohortStore(w).capture();journals=audit_journals()
                confirmed_inventory(before,journals,verified_tombstones(w))
            repository_ids=before['repositories']
            plan=inventory_plan(before,guards.utc(before['cohort']['planned_at']))
            integrity_report=None
            if w.c.get('retention_readiness_policy','legacy-v1')=='native-v2':
                import integrity
                integrity_report=integrity.ensure(w,before,current_inventory=current_inventory)
            else:
                for lane in ('base','binlog'):w.restic(lane,['--repo',w.c['repositories'][lane],'check','--read-data'])
            with backup_catalog.ArchiveCatalog(w).open_reader() as reader:
                sealed=retention_cohort.CohortStore(w).load(reader);same_inventory(before,sealed)
                row_guard=cached_log_audit(reader,before,self.root/'logs')
            # find batches argv below the native ARG_MAX; SQL output is discarded
            # because this is a checksum audit, never an import/replay stream.
            args=['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','384m','--cpus','0.5','--pids-limit','128','--mount','type=bind,source='+str(self.root/'logs')+',target=/logs,readonly','--entrypoint','sh',DB_IMAGE,'-c',"find /logs -maxdepth 1 -type f -name 'suhoput2-binlog.[0-9][0-9][0-9][0-9][0-9][0-9]' -exec mariadb-binlog --no-defaults --verify-binlog-checksum {} + > /dev/null"]
            w.native.run(args,target=self.root/'checksum-decoded.sql')
            for item in plan['logs']:guards.require(sha(self.root/'logs'/item['file'])==item['sha256'],'Decoded archive changed')
            recoveries=self.recovery_checks(before,plan);proof,binding=recoveries['anchor']
            with backup_catalog.ArchiveCatalog(w).open_reader() as reader:
                after=retention_cohort.CohortStore(w).load(reader);same_inventory(before,after)
            blockers=[] if integrity_report is not None else ['native_delete_executor_disabled','measured_monthly_budget/account_billing_unverified','independent_owner_full_restore_not_run']
            if integrity_report is None and not plan['pre_window_anchor_present']:blockers.append('real_30_day_history_not_present')
            if proof['stop']!={'file':plan['chain_last_file'],'position':plan['chain_last_position']}:blockers.append('verified_restore_stop_precedes_archived_chain_tip')
            receipt={'result':'PASS','operation':'read-only native retention inventory/anchor audit','generation':w.c['generation'],'code_sha':w.c['code_sha'],'repositories':repository_ids,'inventory_sha256':plan['inventory_sha256'],'snapshots':before['snapshots'],'verified_snapshots':len(before['snapshots']),'verified_binlogs':len(plan['logs']),'chain_last_file':plan['chain_last_file'],'anchor_recovery':binding,'keep':plan['keep'],'candidates':plan['candidates'],'pre_window_anchor_present':plan['pre_window_anchor_present'],'history_coverage_verified':False,'apply_allowed':False,'remote_delete_calls':0,'timers_enabled':False,'account_api_requests':'not_measured;native restic calls are not provider counters','blockers':blockers,'completed_at':now()}
            receipt.update(evidence_type='audit',source=w.source,started_at=started,
                           checked_repositories=repository_ids,check_mode=integrity.MODE if integrity_report is not None else 'read-data',binlog_check_mode='native-checksum',
                           readback_snapshots={r['id']:r['manifest_sha256'] for r in before['snapshots']},
                           verified_binlog_count=len(plan['logs']),verified_binlogs=plan['logs'],row_event_guard=row_guard,
                           cohort=before['cohort'],phase_seconds={'scan_seconds':time.monotonic()-scan_started,
                                                                'critical_seconds':capture_timing['critical_seconds']})
            if integrity_report is not None:receipt['full_remote_integrity']=integrity_report
            receipt['readiness_evaluated']=False
            receipt['inventory_mode']='existing-frozen-cohort' if current_inventory is not None else 'new-cohort-capture'
            if 'tip' in recoveries:receipt['tip_recovery']=recoveries['tip'][1]
            runtime.atomic_json(self.root/'receipt.json',receipt)
            from retention_native import publish_evidence
            publish_evidence(w,'audit',receipt,before,started)
            return receipt

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True);args=parser.parse_args()
    try:
        os.nice(10);result=Inspector(args.config).run()
    except Exception as error:result={'result':'FAIL','error_type':type(error).__name__,'remote_delete_calls':0,'apply_allowed':False,'completed_at':now()}
    print(json.dumps(result));return 0 if result['result']=='PASS' else 1
if __name__=='__main__':sys.exit(main())
