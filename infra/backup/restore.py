"""S3-only PITR control into the single new DEC-025 isolated DB/volume.
No source DB/file reads, application bootstrap, remote deletion or auto cleanup.
"""
import os,sys,json,pathlib,hashlib,secrets,time,shutil,re,uuid,datetime as dt
import guards,runtime,dump_records
from worker import Worker,DB_IMAGE,WP_IMAGE,private_path,verify_payload,tree_inventory,sha,now,NativeError
CONTROL='suhoput2-stage-restore-047-db-1';VOLUME='suhoput2-stage-restore-047_db';PROJECT='suhoput2-stage-restore-047'

def objects_absent(native):
    for kind,name in [('container',CONTROL),('volume',VOLUME)]:
        args=['docker',kind,'ls']+(['--all'] if kind=='container' else [])+['--format','{{json .Names}}' if kind=='container' else '{{json .Name}}']
        names=[json.loads(x) for x in native.run(args).splitlines() if x.strip()];guards.require(all(isinstance(x,str) for x in names) and name not in names,'Existing control object; preserve')
    return True

def replay_range(start,stop,logs):
    guards.checked_logs(logs);first=guards.log_number(start['file']);last=guards.log_number(stop['file'])
    guards.require(type(start['position']) is int and type(stop['position']) is int and start['position']>=4 and stop['position']>=4 and first<=last,'Invalid PITR boundaries')
    selected=[x for x in logs if first<=guards.log_number(x['file'])<=last]
    guards.require([guards.log_number(x['file']) for x in selected]==list(range(first,last+1)),'Missing PITR binlog')
    guards.require(start['position']<=selected[0]['size'] and stop['position']<=selected[-1]['size'] and (first!=last or start['position']<=stop['position']),'Truncated or reversed PITR boundary');return selected

def validate_plan(plan,generation):
    guards.require(plan.get('format')==1 and plan.get('generation')==generation,'Restore plan generation mismatch')
    for k in ('base_id','full_id'):guards.hex_id(plan[k],64)
    guards.hex_id(plan['token'],32)
    guards.require(type(plan['expected_order']) is int and type(plan['excluded_order']) is int and plan['expected_order']>0 and plan['excluded_order']>0 and plan['expected_order']!=plan['excluded_order'],'Invalid synthetic order control')
    for k in ('expected_operation','excluded_operation'):guards.require(isinstance(plan[k],str) and re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',plan[k]),'Invalid synthetic operation control')
    return plan

def control_records(data):
    # Validate the entire native dump grammar first; then read only exact IDs,
    # not substring matches in free text or SQL comments.
    catalog=dump_records.records(data)['catalog'];guards.require('id' in catalog.get('wp_wc_orders',[]) and 'operation_id' in catalog.get('wp_suhoput_operations',[]),'Missing native control schema');out={'orders':[],'operations':[]}
    for line in data.splitlines():
        m=re.fullmatch(rb'INSERT INTO `(wp_wc_orders|wp_suhoput_operations)` \((.*?)\) VALUES \((.*)\);',line)
        if not m:continue
        columns=[x.decode() for x in re.findall(rb'`([A-Za-z0-9_]+)`',m[2])];row=dict(zip(columns,dump_records.values(m[3])))
        if m[1]==b'wp_wc_orders':
            guards.require(re.fullmatch(rb'[0-9]+',row['id']) is not None,'Invalid order ID');out['orders'].append(int(row['id']))
        else:out['operations'].append(row['operation_id'].decode('utf8'))
    guards.require(len(out['orders'])==len(set(out['orders'])) and len(out['operations'])==len(set(out['operations'])),'Duplicate base control ID');return out

class Recovery:
    def __init__(self,config,plan):
        self.w=Worker(config);self.plan=validate_plan(runtime.load_json(private_path(plan)),self.w.c['generation']);guards.require(str(plan)==str(self.w.root/'config/restore-plan.json'),'Wrong protected restore plan')
        self.root=self.w.root/'control-restore'/('restore-'+self.plan['token']);self.intent=self.w.root/'receipts/restore-intent.json'
    def snapshot(self,lane,sid,*,existing=False):
        w=self.w;repo=w.c['repositories'][lane];scope=str(w.root/'spool'/(lane+'-payload'));metadata=json.loads(w.restic(lane,['--repo',repo,'cat','snapshot',sid]));tags=metadata['tags']
        guards.require(metadata['paths']==[scope] and isinstance(tags,list) and len(tags)==len(set(tags)) and 'task047' in tags,'Snapshot source path/tags mismatch')
        expected=lambda prefix:[x[len(prefix):] for x in tags if x.startswith(prefix)]
        guards.require(expected('generation:')==[w.c['generation']],'Snapshot generation mismatch');guards.require(len(expected('token:'))==1 and len(expected('manifest-sha:'))==1,'Snapshot identity ambiguity');guards.hex_id(expected('token:')[0],32);digest=guards.hex_id(expected('manifest-sha:')[0],64)
        body=w.restic(lane,['--repo',repo,'dump',sid,scope+'/manifest.json']);guards.require(hashlib.sha256(body).hexdigest()==digest,'Authenticated manifest mismatch');manifest=json.loads(body);guards.require(manifest['generation']==w.c['generation'] and manifest['source']==w.source,'Manifest source mismatch')
        target=self.root/'snapshots'/sid;guards.require(target.resolve()==target and not target.is_symlink(),'Restore target path changed')
        if existing:guards.require(target.is_dir(),'Missing prior restored snapshot')
        else:guards.require(not target.exists(),'Restore target collision');w.restic(lane,['--repo',repo,'restore',sid,'--target',str(target),'--verify'])
        restored=target/scope.lstrip('/');guards.require(sha(restored/'manifest.json')==digest,'Restored manifest mismatch');verify_payload(restored,manifest);return manifest,restored,digest
    def media(self,uploads):
        w=self.w;socket=self.root/'socket';guards.require(socket.resolve()==socket and not socket.is_symlink() and socket.is_dir() and socket.parent==self.root,'Unknown control socket directory')
        # MariaDB entrypoint owns this directory as mysql with mode0700.
        # Only this child path is traversable by root in a cap-drop-ALL reader;
        # its host parent remains root0700, and the socket is mounted read-only
        # into a network-none container. No source/system permissions change.
        os.chmod(socket,0o755)
        script=r"require '/input/media.php';require '/input/database.php';$x=json_decode(stream_get_contents(STDIN),true,16,JSON_THROW_ON_ERROR);mysqli_report(MYSQLI_REPORT_ERROR|MYSQLI_REPORT_STRICT);$c=new mysqli('localhost','root',$x['password'],'suhoput2_stage',3306,'/dbsock/mysqld.sock');try{$c->set_charset('utf8mb4');$q=static function(string $s)use($c):array{$r=$c->query($s);if(!$r instanceof mysqli_result)return [];try{return $r->fetch_all(MYSQLI_ASSOC);}finally{$r->free();}};echo json_encode(SuhoputBackup\databaseMedia($q,'suhoput2_stage','wp_','/uploads'),JSON_THROW_ON_ERROR);}finally{$c->close();}"
        args=['docker','run','--rm','-i','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','256m','--cpus','0.5','--pids-limit','64','--mount','type=bind,source='+str(w.bin)+',target=/input,readonly','--mount','type=bind,source='+str(self.root/'socket')+',target=/dbsock,readonly','--mount','type=bind,source='+str(uploads)+',target=/uploads,readonly','--entrypoint','php',WP_IMAGE,'-d','display_errors=0','-r',script]
        return json.loads(w.native.run(args,data=json.dumps({'password':self.password}).encode()))
    def verified_media(self,uploads,expected):
        result=self.media(uploads);guards.require(result['inventory']==expected,'Restored DB media SHA/bytes/references differ');return result
    def decoder(self,logs,target,*,start=None,stop=None):
        args=['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','256m','--cpus','0.5','--pids-limit','64','--mount','type=bind,source='+str(self.root/'logs')+',target=/logs,readonly','--entrypoint','mariadb-binlog',DB_IMAGE,'--no-defaults','--verify-binlog-checksum']
        if start is not None:args.append('--start-position='+str(start))
        if stop is not None:args.append('--stop-position='+str(stop))
        args.extend('/logs/'+x['file'] for x in logs);self.w.native.run(args,target=target)
    def run(self):
        w=self.w;w.gate();guards.require(not self.intent.exists() and not self.root.exists(),'Existing restore attempt; preserve/investigate, no automatic repeat')
        objects_absent(w.native)
        runtime.atomic_json(self.intent,{'generation':w.c['generation'],'token':self.plan['token'],'started_at':now(),'objects':[CONTROL,VOLUME],'source_mutations':0});self.root.mkdir(mode=0o700);(self.root/'snapshots').mkdir(mode=0o700)
        for lane in ('base','binlog'):w.restic(lane,['--repo',w.c['repositories'][lane],'check','--read-data'])
        base,bpath,bmd=self.snapshot('base',self.plan['base_id']);guards.require(base['kind'] in ('full','pre-update','hourly'),'Wrong base snapshot kind')
        if base['kind']=='hourly':
            guards.require(base['full_id']==self.plan['full_id'],'Hourly prerequisite mismatch');full,fpath,fmd=self.snapshot('base',self.plan['full_id'])
        else:guards.require(self.plan['full_id']==self.plan['base_id'],'Full base identity mismatch');full,fpath,fmd=base,bpath,bmd
        guards.require(full['kind'] in ('full','pre-update') and all(full[k]==base[k] for k in ('generation','source','stage_app_sha','application_sha256','configuration_sha256')),'Full app/config/generation binding mismatch')
        guards.require(w.c['stage_app_sha']==base['stage_app_sha'] and w.c['generation']==base['generation'],'Expected stage application generation mismatch')
        guards.require(w.captured_identity(fpath)=={k:full[k] for k in ('application_sha256','configuration_sha256')},'Full captured application/config bytes differ')
        chain=runtime.load_json(w.root/'receipts/binlog-chain.json');guards.require(chain['generation']==w.c['generation'],'Chain generation mismatch');selected=replay_range(base['coordinates'],self.plan['stop'],chain['logs']);files={};needed={x['file'] for x in selected};(self.root/'logs').mkdir(mode=0o700)
        for row in chain['snapshots']:
            if not any(row['first_log']<=guards.log_number(name)<=row['last_log'] for name in needed):continue
            manifest,path,digest=self.snapshot('binlog',row['id']);guards.require(manifest['kind']=='binlog','Wrong binlog snapshot kind');guards.checked_logs(manifest['logs']);guards.require(digest==row['manifest_sha256'],'Chain snapshot digest mismatch')
            for item in manifest['logs']:
                guards.require(item['file'] not in files,'Duplicate archived binlog');files[item['file']]=item
                if item['file'] in needed:
                    guards.require(item in selected,'Binlog manifest/chain mismatch');source=path/'logs'/item['file'];guards.require(source.stat().st_size==item['size'] and sha(source)==item['sha256'] and source.read_bytes()[:4]==b'\xfebin','Invalid archived binlog');shutil.copyfile(source,self.root/'logs'/item['file']);os.chmod(self.root/'logs'/item['file'],0o600)
        guards.require(needed<=files.keys(),'Incomplete authenticated binlog chain');replay=self.root/'replay.sql';self.decoder(selected,replay,start=base['coordinates']['position'],stop=self.plan['stop']['position'])
        source_inventory=runtime.load_json(bpath/'media.json')['inventory'];records=dump_records.records((bpath/'db.sql').read_bytes());guards.require(w.media(bpath/'uploads',records)==source_inventory,'Recovered base DB/media inventory mismatch')
        # Only now create the previously absent isolated target. All input
        # archives, schemas, chain, decoder and media have been verified first.
        self.password=secrets.token_hex(32)
        with open(self.root/'control.password','x') as stream:stream.write(self.password+'\n');stream.flush();os.fsync(stream.fileno())
        (self.root/'socket').mkdir(mode=0o700);objects_absent(w.native);w.native.run(['docker','volume','create','--label','task047.generation='+w.c['generation'],'--label','task047.restore-token='+self.plan['token'],VOLUME])
        volume=json.loads(w.native.run(['docker','volume','inspect',VOLUME]))[0]
        guards.require(volume['Name']==VOLUME and volume['Labels'].get('task047.generation')==w.c['generation'] and volume['Labels'].get('task047.restore-token')==self.plan['token'],'Unknown control volume identity')
        w.native.run(['docker','run','-d','--name',CONTROL,'--label','com.docker.compose.project='+PROJECT,'--label','com.docker.compose.service=db','--label','task047.generation='+w.c['generation'],'--network','none','--memory','1g','--cpus','0.5','--pids-limit','256','--cap-drop','NET_RAW','--security-opt','no-new-privileges','--env','MARIADB_ROOT_PASSWORD','--mount','type=volume,source='+VOLUME+',target=/var/lib/mysql','--mount','type=bind,source='+str(self.root/'socket')+',target=/run/mysqld',DB_IMAGE,'--skip-networking','--event-scheduler=OFF'],environment={'MARIADB_ROOT_PASSWORD':self.password})
        for attempt in range(100):
            try:
                if w.sql('SELECT 1;',container=CONTROL).strip()==b'1':break
            except NativeError:pass
            time.sleep(0.2)
        else:raise guards.GuardError('Control DB did not start; retained')
        row=json.loads(w.native.run(['docker','inspect',CONTROL]))[0];guards.require(any(m.get('Source')==str(self.root/'socket') and m.get('Destination')=='/run/mysqld' and m.get('Type')=='bind' for m in row['Mounts']),'Existing control socket binding mismatch');guards.require(row['Config']['Image']==DB_IMAGE and row['HostConfig']['NetworkMode']=='none' and all(not x for x in row['NetworkSettings']['Ports'].values()),'Control DB isolation mismatch');guards.require(any(m.get('Name')==VOLUME and m['Destination']=='/var/lib/mysql' for m in row['Mounts']),'Control volume mismatch')
        guards.require(w.sql('SELECT @@event_scheduler,@@skip_networking,@@log_bin;',container=CONTROL).strip()==b'OFF\t1\t0','Unsafe control DB runtime')
        guards.require(w.sql("SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='suhoput2_stage';",container=CONTROL).strip()==b'0','Control schema not empty')
        w.native.run(['docker','exec','-i',CONTROL,'sh','-c','MYSQL_PWD="$MARIADB_ROOT_PASSWORD" exec mariadb -uroot'],data=(bpath/'db.sql').read_bytes())
        expected=self.plan['expected_order'];excluded=self.plan['excluded_order'];operation=self.plan['expected_operation'];excludedop=self.plan['excluded_operation']
        query=f"SELECT COUNT(*) FROM suhoput2_stage.wp_wc_orders WHERE id={expected};SELECT COUNT(*) FROM suhoput2_stage.wp_wc_orders WHERE id={excluded};SELECT COUNT(*) FROM suhoput2_stage.wp_suhoput_operations WHERE operation_id='{operation}';SELECT COUNT(*) FROM suhoput2_stage.wp_suhoput_operations WHERE operation_id='{excludedop}';"
        before_counts=w.sql(query,container=CONTROL).splitlines();guards.require(before_counts==[b'0']*4,'Control records already exist in base; after-base replay not proved');runtime.atomic_json(self.root/'base-imported.json',{'token':self.plan['token'],'generation':w.c['generation'],'base_id':self.plan['base_id'],'base_manifest_sha256':bmd,'before_counts':[int(x) for x in before_counts],'control_id':row['Id']})
        w.native.run(['docker','exec','-i',CONTROL,'sh','-c','MYSQL_PWD="$MARIADB_ROOT_PASSWORD" exec mariadb -uroot'],data=replay.read_bytes())
        counts=w.sql(query,container=CONTROL).splitlines();guards.require(counts==[b'1',b'0',b'1',b'0'],'PITR target/exclusion mismatch');runtime.atomic_json(self.root/'replay-applied.json',{'token':self.plan['token'],'generation':w.c['generation'],'base_id':self.plan['base_id'],'stop':self.plan['stop'],'control_id':row['Id'],'after_counts':[int(x) for x in counts],'replay_sha256':sha(replay)})
        self.before_proof='native imported base counts fourzero before replay'
        return self.verify_result(base,bpath,bmd,full,fpath,fmd,selected)
    def verify_existing(self):
        w=self.w;intent=runtime.load_json(self.intent);guards.require(intent['generation']==w.c['generation'] and intent['token']==self.plan['token'] and self.root.resolve()==self.root and self.root.is_dir(),'Existing recovery scope changed')
        self.password=private_path(self.root/'control.password').read_text().strip();guards.hex_id(self.password,64)
        row=json.loads(w.native.run(['docker','inspect',CONTROL]))[0];volume=json.loads(w.native.run(['docker','volume','inspect',VOLUME]))[0]
        guards.require(row['Config']['Image']==DB_IMAGE and row['Config']['Labels'].get('task047.generation')==w.c['generation'] and row['HostConfig']['NetworkMode']=='none' and all(not x for x in row['NetworkSettings']['Ports'].values()),'Existing control container scope mismatch')
        guards.require(any(m.get('Source')==str(self.root/'socket') and m.get('Destination')=='/run/mysqld' and m.get('Type')=='bind' for m in row['Mounts']),'Existing control socket binding mismatch')
        guards.require(volume['Name']==VOLUME and volume['Labels'].get('task047.restore-token')==self.plan['token'] and volume['Labels'].get('task047.generation')==w.c['generation'] and any(m.get('Name')==VOLUME and m['Destination']=='/var/lib/mysql' for m in row['Mounts']),'Existing control volume identity mismatch')
        guards.require(w.sql('SELECT @@event_scheduler,@@skip_networking,@@log_bin;',container=CONTROL).strip()==b'OFF\t1\t0','Existing control isolation changed')
        base,bpath,bmd=self.snapshot('base',self.plan['base_id'],existing=True);guards.require(base['kind'] in ('full','pre-update','hourly') and base['stage_app_sha']==w.c['stage_app_sha'],'Existing base kind/application mismatch');guards.require((base['kind']=='hourly' and base['full_id']==self.plan['full_id']) or (base['kind'] in ('full','pre-update') and self.plan['full_id']==self.plan['base_id']),'Existing full ID linkage mismatch');full,fpath,fmd=(base,bpath,bmd) if self.plan['full_id']==self.plan['base_id'] else self.snapshot('base',self.plan['full_id'],existing=True)
        guards.require(full['kind'] in ('full','pre-update') and all(full[k]==base[k] for k in ('generation','source','stage_app_sha','application_sha256','configuration_sha256')),'Existing full prerequisite changed');guards.require(w.captured_identity(fpath)=={k:full[k] for k in ('application_sha256','configuration_sha256')},'Existing full application changed')
        expected=self.plan['expected_order'];excluded=self.plan['excluded_order'];op=self.plan['expected_operation'];late=self.plan['excluded_operation'];query=f"SELECT COUNT(*) FROM suhoput2_stage.wp_wc_orders WHERE id={expected};SELECT COUNT(*) FROM suhoput2_stage.wp_wc_orders WHERE id={excluded};SELECT COUNT(*) FROM suhoput2_stage.wp_suhoput_operations WHERE operation_id='{op}';SELECT COUNT(*) FROM suhoput2_stage.wp_suhoput_operations WHERE operation_id='{late}';"
        guards.require(w.sql(query,container=CONTROL).splitlines()==[b'1',b'0',b'1',b'0'],'Existing PITR control counts differ')
        # This path never imports or replays SQL. The original native run reached
        # its PHP mysqli reader after both native count guards; retain its failure.
        # Independently check exact control IDs against authenticated base bytes.
        records=control_records((bpath/'db.sql').read_bytes());guards.require(expected not in records['orders'] and excluded not in records['orders'] and op not in records['operations'] and late not in records['operations'],'After-base evidence absent')
        chain=runtime.load_json(w.root/'receipts/binlog-chain.json');guards.require(chain['generation']==w.c['generation'],'Existing binlog chain generation mismatch');selected=replay_range(base['coordinates'],self.plan['stop'],chain['logs'])
        for item in selected:
            path=self.root/'logs'/item['file'];guards.require(path.is_file() and not path.is_symlink() and path.stat().st_size==item['size'] and sha(path)==item['sha256'],'Existing recovery log changed')
        # Decode again only into a NEW verification file; never apply it to DB.
        self.decoder(selected,self.root/('replay-verified-'+uuid.uuid4().hex+'.sql'),start=base['coordinates']['position'],stop=self.plan['stop']['position'])
        self.before_proof='original native fourzero-before-replay guard passed before PHP socket failure; authenticated base dump control IDs independently absent; existing DB counts1/0/1/0; validation-only resume, SQL writes0'
        return self.verify_result(base,bpath,bmd,full,fpath,fmd,selected)
    def verify_result(self,base,bpath,bmd,full,fpath,fmd,selected):
        w=self.w;source_inventory=runtime.load_json(bpath/'media.json')['inventory']
        restored=self.verified_media(bpath/'uploads',source_inventory)
        negatives={};case='negative-'+uuid.uuid4().hex;negative=self.root/case;negative.mkdir(mode=0o700);missing=negative/'missing-media';corrupt=negative/'corrupt-media';shutil.copytree(bpath/'uploads',missing);shutil.copytree(bpath/'uploads',corrupt)
        candidates=[x for x in source_inventory if 'bytes' in x];guards.require(candidates,'No referenced media negative fixture');thumb=next((x['path'] for x in candidates if '-150x150.' in x['path']),candidates[0]['path']);(missing/thumb).unlink();(corrupt/thumb).write_bytes(b'corrupt synthetic copy')
        for name,path in [('missing_media',missing),('corrupt_media',corrupt)]:
            try:self.verified_media(path,source_inventory)
            except (NativeError,guards.GuardError):negatives[name]='rejected'
            else:raise guards.GuardError('Invalid media accepted')
        last=selected[-1];bad={**last,'file':case+'-truncated.binlog'};shutil.copyfile(self.root/'logs'/last['file'],self.root/'logs'/bad['file'])
        with open(self.root/'logs'/bad['file'],'r+b') as stream:stream.truncate(150)
        try:self.decoder([bad],negative/'negative-replay.sql')
        except NativeError:negatives['truncated_binlog']='rejected'
        else:raise guards.GuardError('Truncated binlog accepted')
        # Positive result remains unchanged by negatives (separate copies only).
        guards.require(self.media(bpath/'uploads')==restored,'Positive restore drift after negatives')
        receipt={'before_replay_control_records_absent':True,'before_replay_proof':getattr(self,'before_proof','native imported base counts fourzero before replay'),'result':'PASS','started_from':'private encrypted S3-B base+binlogs; original source reads=0','source':w.source,'code_sha':w.c['code_sha'],'stage_app_sha':base['stage_app_sha'],'base_id':self.plan['base_id'],'base_manifest_sha256':bmd,'full_id':self.plan['full_id'],'full_manifest_sha256':fmd,'coordinates':base['coordinates'],'stop':self.plan['stop'],'replayed_logs':len(selected),'verified_binlogs':selected,'synthetic_order_after_base':True,'synthetic_operation_after_base':True,'later_order_operation_excluded':True,'media':restored,'negatives':negatives,'control_objects':[CONTROL,VOLUME],'owner_independent_machine':'not_run','timers':'disabled;usage/account tariff prerequisite','completed_at':now()};runtime.atomic_json(w.root/'receipts/restored.json',receipt);print(json.dumps(receipt));return receipt

def main():
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True);parser.add_argument('--plan',required=True);parser.add_argument('--verify-existing',action='store_true');args=parser.parse_args();os.umask(0o077)
    try:
        os.nice(10);recovery=Recovery(args.config,args.plan);recovery.verify_existing() if args.verify_existing else recovery.run();return 0
    except Exception as error:print(json.dumps({'result':'FAIL','error_type':type(error).__name__,'completed_at':now()}));return 1
if __name__=='__main__':sys.exit(main())
