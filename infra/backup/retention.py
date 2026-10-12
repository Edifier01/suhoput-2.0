"""Read-only native inventory/anchor audit. No remote deletion or scheduling."""
import argparse,contextlib,datetime as dt,hashlib,io,json,os,pathlib,sys,uuid
import guards,runtime,restic_adapter
from worker import Worker,DB_IMAGE,sha,private_path,now
from restore import Recovery,replay_range

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
        return json.loads(data,object_pairs_hook=runtime.no_duplicates)
    except (ValueError,UnicodeError) as error:
        raise guards.GuardError('Invalid authenticated JSON') from error

def native_inventory(worker,at,repository_ids):
    w=worker;entries=[];manifests={};tokens=set()
    for lane in ('base','binlog'):
        repo=w.c['repositories'][lane];scope=str(w.root/'spool'/(lane+'-payload'))
        run=lambda args:w.restic(lane,['--repo',repo,*args])
        config=decode(run(['cat','config']))
        guards.require(config['version']==2 and config['id']==guards.hex_id(repository_ids[lane],64),'Repository identity changed')
        listed=decode(run(['snapshots','--json']));guards.require(isinstance(listed,list),'Complete snapshot inventory required')
        for row in listed:
            sid=guards.hex_id(row['id'],64);guards.require(sid not in manifests,'Duplicate snapshot across inventory')
            metadata=decode(run(['cat','snapshot',sid]));tags=metadata['tags']
            guards.require(metadata['paths']==[scope] and isinstance(tags,list) and all(isinstance(x,str) for x in tags) and len(tags)==len(set(tags)) and 'task047' in tags,'Unknown snapshot source or tags')
            def tag(prefix):
                values=[x[len(prefix):] for x in tags if x.startswith(prefix)]
                guards.require(len(values)==1,'Ambiguous authenticated tag');return values[0]
            guards.require(tag('generation:')==w.c['generation'],'Foreign generation in repository')
            token=guards.hex_id(tag('token:'),32);digest=guards.hex_id(tag('manifest-sha:'),64)
            guards.require(token not in tokens,'Duplicate upload token');tokens.add(token)
            body=run(['dump',sid,scope+'/manifest.json']);guards.require(hashlib.sha256(body).hexdigest()==digest,'Authenticated manifest digest differs')
            manifest=decode(body);kind=manifest['kind']
            guards.require(manifest['format']==1 and manifest['generation']==w.c['generation'] and manifest['source']==w.source,'Foreign snapshot manifest')
            guards.require(kind in (('full','pre-update','hourly') if lane=='base' else ('binlog',)),'Wrong snapshot lane/kind')
            guards.hex_id(manifest['code_sha'],40)
            captured=guards.utc(manifest['captured_at']);uploaded=guards.utc(metadata['time'])
            guards.require(captured<=uploaded<=at,'Future snapshot or capture timestamp mismatch')
            if lane=='base':guards.require(manifest['stage_app_sha']==w.c['stage_app_sha'],'Unknown stage application')
            entries.append({'id':sid,'lane':lane,'token':token,'manifest_sha256':digest,'kind':kind,
                            'generation':w.c['generation'],'time':manifest['captured_at'],'snapshot_time':metadata['time']})
            manifests[sid]=manifest
    return {'generation':w.c['generation'],'repositories':dict(repository_ids),'snapshots':entries,'manifests':manifests}

def confirmed_inventory(inventory,journals):
    for lane in ('base','binlog'):
        rows=[x for x in inventory['snapshots'] if x['lane']==lane];confirmed=journals[lane]['confirmed']
        expected={x['id']:(x['token'],x['manifest_sha256']) for x in confirmed}
        actual={x['id']:(x['token'],x['manifest_sha256']) for x in rows}
        guards.require(len(expected)==len(confirmed) and expected==actual,'Unknown or missing acknowledged snapshot; preserve/investigate')
    return True

def inventory_plan(inventory,at):
    entries=inventory['snapshots'];manifests=inventory['manifests'];records=[];logs=[]
    batches=sorted([x for x in entries if x['kind']=='binlog'],key=lambda x:manifests[x['id']]['first_log'])
    guards.require(batches,'No authenticated binlog chain')
    for row in batches:
        manifest=manifests[row['id']];batch=manifest['logs'];guards.checked_logs(batch)
        guards.require(batch and manifest['previous_count']==len(logs) and manifest['first_log']==guards.log_number(batch[0]['file']) and manifest['last_log']==guards.log_number(batch[-1]['file']),'Binlog manifest range/previous count mismatch')
        logs.extend(batch);records.append({**row,'first_log':manifest['first_log'],'last_log':manifest['last_log']})
    guards.new_logs([],logs)  # No native pruning exists: complete original prefix required.
    indexed={x['id']:x for x in entries};guards.require(len(indexed)==len(entries),'Duplicate inventory identity')
    for row in entries:
        if row['kind']=='binlog':continue
        manifest=manifests[row['id']];start=manifest['coordinates'];replay_range(start,start,logs)
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
    return {**plan,'logs':logs,'inventory_sha256':inventory_digest(inventory),'chain_last_file':logs[-1]['file'],'chain_last_position':logs[-1]['size']}

def bind_recovery(inventory,plan,proof):
    try:
        sid=plan['anchor_id'];base=inventory['manifests'][sid];row=next(x for x in inventory['snapshots'] if x['id']==sid)
        full_id=base['full_id'] if row['kind']=='hourly' else sid
        full_row=next(x for x in inventory['snapshots'] if x['id']==full_id)
        guards.require(proof['result']=='PASS' and proof['base_id']==sid and proof['base_manifest_sha256']==row['manifest_sha256'] and proof['full_id']==full_id and proof['full_manifest_sha256']==full_row['manifest_sha256'],'Native recovery anchor identity mismatch')
        guards.require(proof['source']==base['source'] and proof['stage_app_sha']==base['stage_app_sha'] and proof['coordinates']==base['coordinates'],'Native recovery source or coordinates mismatch')
        selected=replay_range(base['coordinates'],proof['stop'],plan['logs'])
        guards.require(type(proof['replayed_logs']) is int and proof['replayed_logs']==len(selected) and proof['verified_binlogs']==selected and isinstance(proof['media']['inventory'],list),'Native recovery binlog bytes or media receipt mismatch')
        guards.require(all(proof[k] is True for k in ('synthetic_order_after_base','synthetic_operation_after_base','later_order_operation_excluded')),'Native after-base control absent')
        return {'base_id':sid,'manifest_sha256':row['manifest_sha256'],'stop':proof['stop'],'replayed_logs':len(selected),'media_references':len(proof['media']['inventory']),'SQL_reimport_or_replay':False}
    except (KeyError,TypeError,StopIteration) as error:
        raise guards.GuardError('Incomplete native recovery binding') from error

class Inspector:
    def __init__(self,config):
        self.config=config;self.w=Worker(config);self.root=self.w.root/'spool'/('retention-audit-'+uuid.uuid4().hex)
    def run(self):
        w=self.w;w.gate()
        with runtime.lane_lock(w.root/'receipts/retention-audit.lock'):
            self.root.mkdir(mode=0o700);(self.root/'logs').mkdir(mode=0o700)
            runtime.atomic_json(self.root/'intent.json',{'generation':w.c['generation'],'code_sha':w.c['code_sha'],'started_at':now(),'remote_delete':False})
            repository_ids={lane:runtime.load_json(private_path(w.root/'receipts'/('init-'+lane+'.json')))['repository_id'] for lane in ('base','binlog')}
            before=native_inventory(w,dt.datetime.now(dt.timezone.utc),repository_ids)
            journals={}
            for lane in ('base','binlog'):
                guards.require(not (w.root/'receipts'/lane/'pending.json').exists(),'Unknown pending upload; retention audit stopped')
                journals[lane]=runtime.UploadJournal(w.root/'receipts'/lane,w.c['generation']).state()
            confirmed_inventory(before,journals);plan=inventory_plan(before,dt.datetime.now(dt.timezone.utc))
            for lane in ('base','binlog'):w.restic(lane,['--repo',w.c['repositories'][lane],'check','--read-data'])
            for row in before['snapshots']:
                lane=row['lane'];sid=row['id'];scope=str(w.root/'spool'/(lane+'-payload'))
                adapter=restic_adapter.ResticAdapter(w.c['repositories'][lane],w.c['generation'],scope,runner=lambda args,lane=lane:w.restic(lane,args),verify_archive=lambda sid,manifest,lane=lane:w.verify_archive(lane,sid,manifest))
                adapter.hints[row['token']]=sid;matches=adapter.find(row['token'])
                guards.require(len(matches)==1 and matches[0]['id']==sid and matches[0]['manifest_sha256']==row['manifest_sha256'],'Incomplete authenticated archive readback')
                if lane=='binlog':
                    for item in before['manifests'][sid]['logs']:
                        target=self.root/'logs'/item['file'];guards.require(not target.exists(),'Duplicate archived binlog path')
                        w.restic(lane,['--repo',w.c['repositories'][lane],'dump',sid,scope+'/logs/'+item['file']],target=target)
                        guards.require(target.stat().st_size==item['size'] and sha(target)==item['sha256'] and target.read_bytes()[:4]==b'\xfebin','Captured S3 binlog differs')
            args=['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','384m','--cpus','0.5','--pids-limit','128','--mount','type=bind,source='+str(self.root/'logs')+',target=/logs,readonly','--entrypoint','mariadb-binlog',DB_IMAGE,'--no-defaults','--verify-binlog-checksum',*['/logs/'+x['file'] for x in plan['logs']]]
            w.native.run(args,target=self.root/'checksum-decoded.sql')
            for item in plan['logs']:guards.require(sha(self.root/'logs'/item['file'])==item['sha256'],'Decoded archive changed')
            recovery=Recovery(self.config,w.root/'config/restore-plan.json')
            guards.require(recovery.plan['base_id']==plan['anchor_id'],'Current anchor requires a new separately owned restore control; preserve existing DB')
            with contextlib.redirect_stdout(io.StringIO()):proof=recovery.verify_existing()
            binding=bind_recovery(before,plan,proof)
            for item in proof['verified_binlogs']:
                path=recovery.root/'logs'/item['file']
                guards.require(path.resolve()==path and not path.is_symlink() and path.stat().st_size==item['size'] and sha(path)==item['sha256'],'Recovery file differs from audited S3 binlog')
            after=native_inventory(w,dt.datetime.now(dt.timezone.utc),repository_ids);same_inventory(before,after)
            blockers=['native_delete_executor_disabled','measured_monthly_budget/account_billing_unverified','independent_owner_full_restore_not_run']
            if not plan['pre_window_anchor_present']:blockers.append('real_30_day_history_not_present')
            if proof['stop']!={'file':plan['chain_last_file'],'position':plan['chain_last_position']}:blockers.append('verified_restore_stop_precedes_archived_chain_tip')
            receipt={'result':'PASS','operation':'read-only native retention inventory/anchor audit','generation':w.c['generation'],'code_sha':w.c['code_sha'],'repositories':repository_ids,'inventory_sha256':plan['inventory_sha256'],'snapshots':before['snapshots'],'verified_snapshots':len(before['snapshots']),'verified_binlogs':len(plan['logs']),'chain_last_file':plan['chain_last_file'],'anchor_recovery':binding,'keep':plan['keep'],'candidates':plan['candidates'],'pre_window_anchor_present':plan['pre_window_anchor_present'],'history_coverage_verified':False,'apply_allowed':False,'remote_delete_calls':0,'timers_enabled':False,'account_api_requests':'not_measured;native restic calls are not provider counters','blockers':blockers,'completed_at':now()}
            runtime.atomic_json(self.root/'receipt.json',receipt);runtime.atomic_json(w.root/'receipts/retention-audit.json',receipt);return receipt

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True);args=parser.parse_args()
    try:
        os.nice(10);result=Inspector(args.config).run()
    except Exception as error:result={'result':'FAIL','error_type':type(error).__name__,'remote_delete_calls':0,'apply_allowed':False,'completed_at':now()}
    print(json.dumps(result));return 0 if result['result']=='PASS' else 1
if __name__=='__main__':sys.exit(main())
