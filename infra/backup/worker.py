"""Protected STAGE-B backup CLI; native retention has a separate intent gate."""
import os,sys,re,json,stat,hashlib,pathlib,subprocess,datetime as dt,uuid,shutil,time,tempfile
import guards,runtime,restic_adapter,dump_records,backup_catalog
UTC=dt.timezone.utc
DB_IMAGE='mariadb:10.11@sha256:7db29378d4fdab73f8123bbc2b48905c90d1a4b00cf848b028f1e81e623257f2'
WP_IMAGE='wordpress:7.1.3-php8.3-apache@sha256:8ecd8d8e374167ea22235acf30f80d1165b82f07ffa5bcef90c1cad8f7be251f'
RESTIC_SHA='20d4142678d0d95ec11a4759def1b73fd9190abc9ca19e4b62d067c0b387e639'
CAPTURE_LIMITS={'hourly':384*1024,'full':192*1024**2,'pre-update':192*1024**2,'binlog':64*1024**2}
CAPTURE_METADATA_LIMITS={'hourly':64*1024,'full':9*1024**2,'pre-update':9*1024**2,'binlog':8*1024}
CAPTURE_MANIFEST_LIMITS={'hourly':64*1024,'full':2*1024**2,'pre-update':2*1024**2,'binlog':2*1024}
PUBLIC_HELPERS=('worker.py','restore.py','retention.py','retention_native.py','retention_cohort.py','maintenance.py','storage.py','readiness_v2.py','integrity.py','retention_restore.py','meter.py','dump_records.py','guards.py','runtime.py','restic_adapter.py','backup_catalog.py','media.php','database.php','owner-kit.php','owner-full.php','budget.py','retention_apply.py','binlog.py')
class NativeError(RuntimeError):
    def __init__(self,phase,diagnostic=None):super().__init__('Native backup operation failed: '+phase)
def now():return dt.datetime.now(UTC).isoformat()
def sha(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()
def validate_config(value):
    guards.require(isinstance(value,dict) and value.get('format')==1,'Invalid worker config')
    c=dict(value);c['source']=guards.source_scope(c['root'],c['schema'],c['generation'])
    c['retention_readiness_policy']=c.get('retention_readiness_policy','legacy-v1')
    guards.require(c['retention_readiness_policy'] in ('legacy-v1','native-v2'),'Unknown retention readiness policy')
    for key in ('code_sha','stage_app_sha'):guards.hex_id(c[key],40)
    for key in ('db_id','wordpress_id','db_environment_sha256','wordpress_environment_sha256'):guards.hex_id(c[key],64)
    guards.require(isinstance(c['region'],str) and re.fullmatch(r'[a-z0-9-]{1,24}',c['region']),'Invalid S3 region')
    c['repositories']={lane:guards.repository_url(c['endpoint'],c['bucket'],lane) for lane in ('base','binlog')}
    return c
def coordinates(data):
    matches=re.findall(rb"-- CHANGE MASTER TO MASTER_LOG_FILE='(suhoput2-binlog\.[0-9]{6})', MASTER_LOG_POS=([0-9]+);",data)
    guards.require(len(matches)==1 and int(matches[0][1])>=4,'Missing or ambiguous dump coordinates')
    file=matches[0][0].decode();guards.log_number(file);return {'file':file,'position':int(matches[0][1])}
def parse_credentials(text):
    out={};allowed={'AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_DEFAULT_REGION'}
    for line in text.splitlines():
        if not line or line.startswith('#'):continue
        guards.require('=' in line,'Env must be data');key,value=line.split('=',1)
        guards.require(key in allowed and key not in out and re.fullmatch(r'[A-Za-z0-9/+=_.-]+',value),'Invalid credential env')
        out[key]=value
    guards.require(set(out)==allowed,'Incomplete credential env');return out

def private_path(path,mode=0o600,uid=0):
    p=pathlib.Path(path);guards.require(p.is_absolute() and '..' not in p.parts,'Canonical private path required')
    for parent in [*reversed(p.parents),p]:guards.require(not parent.is_symlink(),'Private symlink')
    s=p.stat();guards.require(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==uid and stat.S_IMODE(s.st_mode)==mode,'Private file owner/mode mismatch');return p

def tree_inventory(root):
    root=pathlib.Path(root);guards.require(root.is_dir() and not root.is_symlink(),'Invalid capture root');out=[]
    for p in sorted(root.rglob('*')):
        guards.require(not p.is_symlink(),'Capture symlink')
        if p.is_dir():continue
        before=p.stat();guards.require(stat.S_ISREG(before.st_mode) and before.st_nlink==1,'Nonregular capture')
        digest=sha(p);after=p.stat();guards.require((before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_ino,after.st_size,after.st_mtime_ns),'Capture bytes changed')
        out.append({'path':p.relative_to(root).as_posix(),'bytes':after.st_size,'sha256':digest})
    return out
def verify_container(c,service,row):
    source=c['source'];key='db' if service=='db' else 'wordpress';dest='/var/lib/mysql' if key=='db' else '/var/www/html';image=DB_IMAGE if key=='db' else WP_IMAGE
    guards.require(row['Id']==c[key+'_id'] and row['Config']['Image']==image,'Container identity changed')
    labels=row['Config']['Labels'];guards.require(labels.get('com.docker.compose.project')==source['project'] and labels.get('com.docker.compose.service')==service,'Compose scope changed')
    envhash=hashlib.sha256('\0'.join(sorted(row['Config']['Env'])).encode()).hexdigest();guards.require(envhash==c[key+'_environment_sha256'],'Source environment changed')
    mounts=[x for x in row['Mounts'] if x['Destination']==dest];guards.require(len(mounts)==1 and mounts[0]['Type']=='volume' and mounts[0]['Name']==source[key+'_volume'] and mounts[0].get('RW') is True,'Source volume changed')
    guards.require(mounts[0]['Source']=='/var/lib/docker/volumes/'+source[key+'_volume']+'/_data','Unexpected volume location')
    guards.require(all(not value for value in row['NetworkSettings']['Ports'].values()),'Source DB/app published directly')
    return mounts[0]['Source']
def disk_gate(free,spool):
    guards.require(free>=5*1024**3 and spool<2*1024**3,'Backup disk reserve/spool limit exceeded')
def verify_payload(payload,manifest):
    actual=[x for x in tree_inventory(payload) if x['path']!='manifest.json'];guards.require(actual==manifest['files'],'Captured payload changed')
def binlog_watermark(captured_at,current=None):return guards.upload_lag(captured_at,current or dt.datetime.now(UTC))

def protected_directory(path):
    p=pathlib.Path(path);guards.require(p.is_absolute() and p.resolve()==p and p.is_dir() and not p.is_symlink(),'Unsafe protected directory')
    s=p.stat();guards.require(s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700,'Protected directory owner/mode mismatch');return p

class NativeRunner:
    def __init__(self,root):self.root=protected_directory(root)
    def run(self,args,*,data=None,environment=None,timeout=300,target=None):
        guards.require(isinstance(args,list) and args and all(isinstance(x,str) and '\0' not in x for x in args),'Invalid native arguments')
        runid=uuid.uuid4().hex;outpath=pathlib.Path(target) if target else self.root/(runid+'.out');errpath=self.root/(runid+'.err')
        guards.require(not outpath.exists() and not outpath.is_symlink() and outpath.parent.resolve()==outpath.parent,'Native output collision')
        env={'PATH':'/usr/bin:/bin','HOME':str(self.root),'TMPDIR':str(self.root)};env.update(environment or {})
        def limits():
            import resource
            resource.setrlimit(resource.RLIMIT_FSIZE,(256*1024*1024,256*1024*1024))
        with open(outpath,'xb') as out,open(errpath,'xb') as err:
            process=subprocess.Popen(args,stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,stdout=out,stderr=err,env=env,preexec_fn=limits)
            try:process.communicate(data,timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill();process.wait();raise NativeError('timeout')
            out.flush();os.fsync(out.fileno());err.flush();os.fsync(err.fileno())
        if process.returncode!=0:raise NativeError('command')
        guards.require(outpath.stat().st_size<=256*1024*1024,'Native output oversized')
        result=outpath.read_bytes() if target is None else outpath
        # Only this invocation's private transient outputs; never archive data.
        errpath.unlink()
        if target is None:outpath.unlink()
        return result

class Worker:
    def __init__(self,config_file):
        guards.require(os.name=='posix' and os.getuid()==0,'Linux root worker required');os.umask(0o077)
        self.c=validate_config(runtime.load_json(private_path(config_file)));self.stage=pathlib.Path(self.c['root']);self.root=protected_directory(self.stage/'backup');self.bin=protected_directory(self.root/'bin')
        guards.require(str(config_file)==str(self.root/'config/runtime.json'),'Wrong config location')
        for name in ('config','spool','cache','receipts','control-restore'):protected_directory(self.root/name)
        self.credentials=parse_credentials(private_path(self.stage/'.env.backup').read_text());guards.require(self.credentials['AWS_DEFAULT_REGION']==self.c['region'],'S3 region changed')
        self.password=private_path(self.root/'config/recovery.password');guards.hex_id(self.password.read_text().strip(),64)
        self.binary=private_path(self.bin/'restic',0o700);guards.require(sha(self.binary)==RESTIC_SHA,'Restic binary digest mismatch')
        self.native=NativeRunner(self.root/'cache');self.source=self.c['source']
    def source_check(self):
        guards.require(self.stage.resolve()==self.stage and not self.stage.is_symlink(),'Stage root changed')
        rows=json.loads(self.native.run(['docker','inspect',self.source['db_container'],self.source['wordpress_container']]))
        self.db_volume=pathlib.Path(verify_container(self.c,'db',rows[0]));self.wp_volume=pathlib.Path(verify_container(self.c,'wordpress',rows[1]))
        self.wp_mounts=rows[1]['Mounts'];return rows
    def gate(self):
        free=shutil.disk_usage(self.root).free;size=sum(x.stat().st_size for x in (self.root/'spool').rglob('*') if x.is_file());disk_gate(free,size)
        guards.require(self.native.run(['timedatectl','show','--property=NTPSynchronized','--value']).strip()==b'yes','NTP synchronization absent')
    def sql(self,query,*,container=None,target=None):
        return self.native.run(['docker','exec','-i',container or self.source['db_container'],'sh','-c','MYSQL_PWD="$MARIADB_ROOT_PASSWORD" exec mariadb -uroot --batch --raw --skip-column-names'],data=query.encode(),target=target)
    def restic(self,lane,args,*,target=None,timeout=900):
        guards.require(lane in ('base','binlog'),'Wrong repository lane');expected=self.c['repositories'][lane]
        guards.require(len(args)>=3 and args[:2]==['--repo',expected],'Native repository mismatch')
        command=args[2];guards.require(command in ('init','backup','cat','dump','snapshots','check','restore','stats','ls'),'Unsafe restic operation')
        opts=['--password-file',str(self.password),'--cache-dir',str(self.root/'cache'/lane),'-o','s3.bucket-lookup=path','-o','s3.connections=1']
        if command in ('cat','dump','snapshots','check','restore','stats','ls'):opts.append('--no-lock')
        env={**self.credentials,'AWS_REGION':self.c['region']}
        return self.native.run([str(self.binary),*opts,*args],environment=env,timeout=timeout,target=target)
    def retention_forget(self,lane,ids,*,timeout=900):
        """Only the trusted retention executor calls this exact-ID boundary."""
        guards.require(lane in ('base','binlog') and isinstance(ids,list) and 0<len(ids)<=256 and ids==sorted(set(ids)),'Bounded exact snapshot IDs required')
        for sid in ids:guards.hex_id(sid,64)
        opts=['--password-file',str(self.password),'--cache-dir',str(self.root/'cache'/lane),'-o','s3.bucket-lookup=path','-o','s3.connections=1']
        # Restic's native exclusive repository lock serializes the effect.
        return self.native.run([str(self.binary),*opts,'--repo',self.c['repositories'][lane],'forget',*ids],environment={**self.credentials,'AWS_REGION':self.c['region']},timeout=timeout)
    def maintenance_prune(self,lane,*,timeout):
        """Dedicated zero-repack cleanup; only the durable maintenance gate calls it."""
        guards.require(lane in ('base','binlog') and type(timeout) in (int,float) and 0<timeout<=55,'Bounded selected cleanup required')
        # Restic 0.19.1 prune requires at least two backend connections. Other
        # operations retain their existing single-connection limit.
        opts=['--password-file',str(self.password),'--cache-dir',str(self.root/'cache'/lane),'-o','s3.bucket-lookup=path','-o','s3.connections=2']
        return self.native.run([str(self.binary),*opts,'--repo',self.c['repositories'][lane],'prune','--max-repack-size','0','--max-unused=unlimited'],
                               environment={**self.credentials,'AWS_REGION':self.c['region']},timeout=timeout)
    def maintenance_inventory(self,lane,*,repository_id,timeout):
        from storage import repository_receipt
        return repository_receipt(self,lane,repository_id=repository_id,timeout=timeout)
    def maintenance_compact(self,lane,*,timeout):
        """Fixed index rewrite; no snapshot retirement or optional repair flags."""
        guards.require(lane in ('base','binlog') and type(timeout) in (int,float) and 0<timeout<=55,'Bounded selected compaction required')
        opts=['--password-file',str(self.password),'--cache-dir',str(self.root/'cache'/lane),'-o','s3.bucket-lookup=path','-o','s3.connections=2']
        return self.native.run([str(self.binary),*opts,'--repo',self.c['repositories'][lane],'repair','index'],
                               environment={**self.credentials,'AWS_REGION':self.c['region']},timeout=timeout)
    def initialize(self,lane):
        repo=self.c['repositories'][lane];intent=self.root/'receipts'/('init-'+lane+'.json')
        if not intent.exists():
            runtime.atomic_json(intent,{'generation':self.c['generation'],'attempted':True,'prepared_at':now()})
            self.restic(lane,['--repo',repo,'init','--repository-version','2'])
        existing=runtime.load_json(intent);guards.require(existing['generation']==self.c['generation'],'Repository intent generation changed')
        config=json.loads(self.restic(lane,['--repo',repo,'cat','config']));guards.require(config['version']==2,'Repository format mismatch');guards.hex_id(config['id'],64)
        if 'repository_id' in existing:guards.require(existing['repository_id']==config['id'],'Repository identity changed')
        runtime.atomic_json(intent,{**existing,'repository_id':config['id'],'confirmed_at':now()});return {'lane':lane,'initialized':True}
    def schema_catalog(self):
        body=self.sql("SELECT TABLE_NAME,ENGINE,TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA='suhoput2_stage' ORDER BY TABLE_NAME; SELECT 'COLUMN',TABLE_NAME,COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='suhoput2_stage' ORDER BY TABLE_NAME,ORDINAL_POSITION;")
        lines=body.decode().splitlines();tables={};columns={}
        for line in lines:
            parts=line.split('\t')
            if parts[0]=='COLUMN':columns.setdefault(parts[1],[]).append(parts[2])
            else:guards.require(len(parts)==3 and parts[1:] == ['InnoDB','BASE TABLE'],'Nontransactional or unknown source table');tables[parts[0]]=True
        guards.require(tables and set(tables)==set(columns),'Incomplete source schema');return columns
    def dump(self,target,*,safety=False):
        args=['docker','exec',self.source['db_container'],'sh','-c','MYSQL_PWD="$MARIADB_ROOT_PASSWORD" exec mariadb-dump -uroot "$@"','sh','--single-transaction','--hex-blob','--complete-insert','--skip-extended-insert','--routines','--events','--triggers','--databases','suhoput2_stage']
        if not safety:args.append('--master-data=2')
        self.native.run(args,target=target,timeout=300);return target
    def copy_tree(self,source,target):
        before=tree_inventory(source);guards.require(sum(x['bytes'] for x in before)<512*1024*1024,'Capture tree oversized')
        shutil.copytree(source,target)
        for p in target.rglob('*'):os.chmod(p,0o700 if p.is_dir() else 0o600)
        os.chmod(target,0o700);guards.require(before==tree_inventory(target) and before==tree_inventory(source),'Media/code changed while captured');return before
    def media(self,payload,records):
        script="require '/input/media.php';$r=json_decode(stream_get_contents(STDIN),true,64,JSON_THROW_ON_ERROR);echo json_encode(SuhoputBackup\\mediaInventory('/uploads',SuhoputBackup\\mediaReferences($r['posts'],$r['meta'],$r['texts'])),JSON_THROW_ON_ERROR);"
        args=['docker','run','--rm','-i','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','256m','--cpus','0.5','--pids-limit','64','--mount','type=bind,source='+str(self.bin)+',target=/input,readonly','--mount','type=bind,source='+str(payload)+',target=/uploads,readonly','--entrypoint','php',WP_IMAGE,'-d','display_errors=0','-r',script]
        return json.loads(self.native.run(args,data=json.dumps(records).encode()))
    def pending_payload(self,lane):
        pending=self.root/'receipts'/lane/'pending.json'
        if pending.exists():
            value=runtime.load_json(pending);p=pathlib.Path(value['payload']);guards.require(p==self.root/'spool'/(lane+'-payload'),'Pending source scope mismatch');verify_payload(p,runtime.load_json(p/'manifest.json'));return p
    def capture_intent(self,lane,payload):
        path=self.root/'receipts'/('capture-'+lane+'.json');guards.require(path.exists() and (payload/'.capture.json').is_file(),'Capture ownership absent')
        value=runtime.load_json(path);marker=runtime.load_json(payload/'.capture.json')
        guards.require(marker=={k:value[k] for k in ('generation','lane','token')} and value['generation']==self.c['generation'] and value['lane']==lane,'Capture ownership mismatch');guards.hex_id(value['token'],32);return value
    def cleanup_confirmed(self,lane):
        intent=self.root/'receipts'/('cleanup-'+lane+'.json')
        if not intent.exists():return
        value=runtime.load_json(intent)
        if value.get('done'):return
        guards.require(value['generation']==self.c['generation'] and value['lane']==lane,'Cleanup ownership mismatch');guards.hex_id(value['token'],32)
        fixed=self.root/'spool'/(lane+'-payload');archived=self.root/'spool'/('confirmed-'+lane+'-'+value['token'])
        proofs=runtime.UploadJournal(self.root/'receipts'/lane,self.c['generation']).state()['confirmed']
        guards.require(any(x['id']==value['snapshot_id'] and x['manifest_sha256']==value['manifest_sha256'] for x in proofs),'Cleanup needs authenticated confirmation')
        if value['phase']=='prepared':
            guards.require(fixed.exists()!=archived.exists(),'Cleanup collision or missing owned capture');selected=fixed if fixed.exists() else archived
            guards.require(not selected.is_symlink() and selected.resolve()==selected,'Cleanup symlink');verify_payload(selected,runtime.load_json(selected/'manifest.json'));guards.require(sha(selected/'manifest.json')==value['manifest_sha256'] and tree_inventory(selected)==value['files'],'Cleanup manifest/files changed');self.capture_intent(lane,selected)
            if selected==fixed:fixed.rename(archived);runtime.directory_sync(fixed.parent)
            value['phase']='deleting';runtime.atomic_json(intent,value)
        guards.require(value['phase']=='deleting' and not archived.is_symlink() and archived.resolve()==archived,'Cleanup path changed')
        # Resume only deletion of individually recorded/unchanged owned temp bytes.
        # No remote snapshots, safety dumps, failed captures or foreign files.
        expected={x['path']:x for x in value['files']};actual=tree_inventory(archived) if archived.exists() else []
        guards.require(all(x==expected.get(x['path']) for x in actual),'Unknown or changed cleanup byte')
        for item in actual:(archived/item['path']).unlink()
        if archived.exists():
            for directory in sorted((x for x in archived.rglob('*') if x.is_dir()),key=lambda x:len(x.parts),reverse=True):directory.rmdir()
            archived.rmdir();runtime.directory_sync(archived.parent)
        runtime.atomic_json(intent,{**value,'done':True})
    def prepare_payload(self,lane):
        self.cleanup_confirmed(lane);payload=self.root/'spool'/(lane+'-payload')
        if payload.exists():
            capture=self.capture_intent(lane,payload);state=runtime.UploadJournal(self.root/'receipts'/lane,self.c['generation']).state();manifest=payload/'manifest.json';matches=[x for x in state['confirmed'] if manifest.is_file() and x['manifest_sha256']==sha(manifest)]
            if matches:
                guards.require(len(matches)==1,'Ambiguous local confirmation');self.finalize(lane,payload,matches[0]['id']);token=uuid.uuid4().hex
                runtime.atomic_json(self.root/'receipts'/('cleanup-'+lane+'.json'),{'generation':self.c['generation'],'lane':lane,'token':token,'phase':'prepared','snapshot_id':matches[0]['id'],'manifest_sha256':sha(manifest),'files':tree_inventory(payload)})
                self.cleanup_confirmed(lane)
            else:
                guards.require(capture['phase']=='capture' and not (self.root/'receipts'/lane/'pending.json').exists(),'Attempted/unknown upload cannot be replaced')
                failed=self.root/'spool'/('failed-'+lane+'-'+capture['token']);guards.require(not failed.exists(),'Failed capture collision');payload.rename(failed);runtime.directory_sync(payload.parent)
        marker={'generation':self.c['generation'],'lane':lane,'token':uuid.uuid4().hex};runtime.atomic_json(self.root/'receipts'/('capture-'+lane+'.json'),{**marker,'phase':'capture'})
        payload.mkdir(mode=0o700);runtime.atomic_json(payload/'.capture.json',marker);return payload
    def application_identity(self):
        entries={x['path']:x for x in tree_inventory(self.wp_volume) if not x['path'].startswith('wp-content/uploads/')}
        for mount in self.wp_mounts:
            if mount['Type']!='bind':continue
            source=pathlib.Path(mount['Source']);guards.require(source.resolve()==source and source.is_relative_to(self.stage) and mount['RW'] is False,'Unknown app source')
            prefix=pathlib.PurePosixPath(mount['Destination']).relative_to('/var/www/html').as_posix();entries={k:v for k,v in entries.items() if k!=prefix and not k.startswith(prefix+'/')}
            rows=tree_inventory(source) if source.is_dir() else [{'path':'','bytes':source.stat().st_size,'sha256':sha(source)}]
            for row in rows:
                name=prefix+('/'+row['path'] if row['path'] else '');entries[name]={**row,'path':name}
        configuration=[]
        for name in ('.env','infra/staging/compose.yaml','infra/staging/backup.override.yaml','infra/staging/safety.php','infra/staging/proxy.conf'):
            path=self.stage/name;guards.require(path.is_file() and not path.is_symlink(),'Missing app configuration');configuration.append({'path':name,'bytes':path.stat().st_size,'sha256':sha(path)})
        digest=lambda rows:hashlib.sha256(json.dumps(sorted(rows,key=lambda x:x['path']),sort_keys=True,separators=(',',':')).encode()).hexdigest()
        return {'application_sha256':digest([entries[k] for k in sorted(entries)]),'configuration_sha256':digest(configuration)}
    def captured_identity(self,payload):
        entries=[x for x in tree_inventory(payload/'wordpress') if not x['path'].startswith('wp-content/uploads/')];configuration=[]
        for name in ('.env','infra/staging/compose.yaml','infra/staging/backup.override.yaml','infra/staging/safety.php','infra/staging/proxy.conf'):
            path=payload/'configuration'/name;configuration.append({'path':name,'bytes':path.stat().st_size,'sha256':sha(path)})
        digest=lambda rows:hashlib.sha256(json.dumps(sorted(rows,key=lambda x:x['path']),sort_keys=True,separators=(',',':')).encode()).hexdigest()
        return {'application_sha256':digest(entries),'configuration_sha256':digest(configuration)}
    def full_prerequisite(self,identity):
        history=runtime.load_json(self.root/'receipts/full.json');guards.hex_id(history['snapshot_id'],64)
        guards.require(history.get('source')==self.source and history.get('generation')==self.c['generation'] and history.get('stage_app_sha')==self.c['stage_app_sha'] and all(history.get(k)==v for k,v in identity.items()),'Full prerequisite application/generation mismatch')
        proofs=runtime.UploadJournal(self.root/'receipts/base',self.c['generation']).state()['confirmed'];guards.require(any(x['id']==history['snapshot_id'] and x['manifest_sha256']==history['manifest_sha256'] for x in proofs),'Full prerequisite confirmation absent');return history['snapshot_id']
    def verify_archive(self,lane,sid,manifest,*,native_metadata,raw_manifest,reconcile=False):
        # Read back into a new owned root-only directory, including every file;
        # metadata/manifest presence alone cannot acknowledge partial snapshots.
        guards.require(lane in ('base','binlog'),'Wrong archive verification lane');guards.hex_id(sid,64)
        repo=self.c['repositories'][lane]
        config=backup_catalog.decode(self.restic(lane,['--repo',repo,'cat','config']))
        initialization=backup_catalog.decode(backup_catalog.read_file(self.root/'receipts'/('init-'+lane+'.json'),backup_catalog.MAX_RECORD_BYTES))
        guards.require(config['version']==2 and config['id']==guards.hex_id(initialization['repository_id'],64) and
                       initialization['generation']==self.c['generation'],'Native archive repository identity differs')
        scope=str(self.root/'spool'/(lane+'-payload'))
        expected,_,_=backup_catalog.native_identity(native_metadata,sid,scope,self.c['generation'])
        actual=backup_catalog.decode(self.restic(lane,['--repo',repo,'cat','snapshot',sid],timeout=50 if lane=='binlog' else 900))
        actual,_,digest=backup_catalog.native_identity(actual,sid,scope,self.c['generation'])
        guards.require(actual==expected and digest==hashlib.sha256(raw_manifest).hexdigest(),'Actual native archive tree identity mismatch')
        guards.require(backup_catalog.decode(raw_manifest)==manifest,'Native callback manifest differs')
        token=uuid.uuid4().hex;temporary=self.root/'cache'/('verify-'+token);temporary.mkdir(mode=0o700)
        runtime.atomic_json(temporary/'owner.json',{'generation':self.c['generation'],'token':token,'snapshot_id':sid});target=temporary/'archive'
        self.restic(lane,['--repo',self.c['repositories'][lane],'restore',sid,'--target',str(target),'--verify'],timeout=50 if lane=='binlog' else 900)
        restored=restic_adapter.verify_restored_tree(target,scope,manifest,raw_manifest,tree_inventory)
        guards.require(backup_catalog.read_file(restored/'manifest.json',backup_catalog.MAX_RAW_BYTES)==raw_manifest,'Readback raw manifest drift');verify_payload(restored,manifest)
        if lane=='base':
            inventory=self.media(restored/'uploads',dump_records.records((restored/'db.sql').read_bytes()));guards.require(inventory==runtime.load_json(restored/'media.json')['inventory'],'Restored media references/directories differ')
        else:
            for item in manifest['logs']:
                guards.log_number(item['file'])
                self.native.run(['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--cpus','0.5','--memory','384m','--pids-limit','128','--mount','type=bind,source='+str(restored/'logs')+',target=/logs,readonly','--entrypoint','mariadb-binlog',DB_IMAGE,'--no-defaults','--verify-binlog-checksum','/logs/'+item['file']],timeout=20)
        # Admission copies only actual restored, all-file verified bytes. The
        # native header is independently bound to the archive before restore.
        deadline=self.catalog_deadline(lane)
        backup_catalog.ArchiveCatalog(self,deadline=deadline).admit(lane,sid,native_metadata,raw_manifest,restored,reconcile=reconcile,deadline=deadline)
        guards.require(temporary.resolve()==temporary and temporary.parent==self.root/'cache' and not temporary.is_symlink(),'Readback cleanup scope changed');tree_inventory(temporary)
        shutil.rmtree(temporary);runtime.directory_sync(temporary.parent);return True
    def check_capture_budget(self,manifest,payload=None):
        """Bind commissioned raw capture growth before creating upload authority.

        Initial manual calibration predates admission. Once either protected
        report/origin exists, the complete authenticated forecast must load;
        deleting half the pair, expiry or changed expense bytes fail closed.
        Raw bytes are never substituted with native compressed pack sizes.
        """
        report=self.root/'receipts/commissioning-budget.json';origin=self.root/'receipts/commissioning-budget.origin.json'
        if self.c.get('retention_readiness_policy','legacy-v1')!='native-v2':return
        if not any(p.exists() or p.is_symlink() for p in (report,origin)):return
        import budget
        forecast=budget.load_commissioning_budget(self)
        result=self.validate_capture_geometry(manifest,payload,fixed_helpers=forecast.get('capture_policy',{}).get('fixed_helpers'))
        if payload is not None and manifest['kind']!='binlog':
            identity=forecast.get('capture_policy',{}).get('application_identity',{})
            guards.require(set(identity)=={'application_sha256','configuration_sha256'} and
                           all(guards.hex_id(value,64)==manifest.get(key) for key,value in identity.items()),
                           'Commissioned application identity changed; recalibrate before uploading new code')
        return result
    def validate_capture_geometry(self,manifest,payload=None,*,fixed_helpers=None):
        """Pure capture calibration; does not admit a budget or create upload authority."""
        kind=manifest.get('kind');files=manifest.get('files')
        guards.require(kind in CAPTURE_LIMITS and isinstance(files,list),'Unknown commissioned capture kind')
        guards.require(all(type(row.get('bytes')) is int and row['bytes']>=0 for row in files),'Invalid commissioned raw capture size')
        if payload is not None:
            raw=backup_catalog.read_file(payload/'manifest.json',CAPTURE_MANIFEST_LIMITS[kind])
            guards.require(backup_catalog.decode(raw)==manifest,'Commissioned manifest changed during validation')
        else:raw=(json.dumps(manifest,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
        guards.require(sum(row['bytes'] for row in files)+len(raw)<=CAPTURE_LIMITS[kind],
                       'Capture exceeds commissioned raw bound; preserve payload and recalibrate budget')
        guards.require(len(raw)<=CAPTURE_MANIFEST_LIMITS[kind],'Commissioned manifest metadata exceeds bound')
        fixed_config={'configuration/'+name for name in ('.env','infra/staging/compose.yaml',
                      'infra/staging/backup.override.yaml','infra/staging/safety.php','infra/staging/proxy.conf')}
        helper_rows={row['path'].removeprefix('configuration/backup-public/'):row for row in files
                     if str(row.get('path','')).startswith('configuration/backup-public/')}
        if helper_rows or (payload is not None and kind in ('full','pre-update')):
            guards.require(isinstance(fixed_helpers,dict) and set(fixed_helpers)==set(PUBLIC_HELPERS) and
                           set(helper_rows)==set(PUBLIC_HELPERS) and
                           all(set(value)=={'bytes','sha256'} and type(value['bytes']) is int and value['bytes']>=0 and
                               guards.hex_id(value['sha256'],64)==helper_rows[name].get('sha256') and
                               value['bytes']==helper_rows[name]['bytes'] for name,value in fixed_helpers.items()),
                           'Commissioned recovery helper identity changed; recalibrate budget')
        def fixed(row):
            path=str(row.get('path',''))
            return path in fixed_config or (path.startswith('configuration/backup-public/') and path.removeprefix('configuration/backup-public/') in helper_rows) or (path.startswith('wordpress/') and not path.startswith('wordpress/wp-content/uploads/'))
        # Only the captured application's authenticated identity is reusable.
        # Include every other byte: dump, both media copies, public helper
        # configuration, ownership marker and any unexpected extra file.
        dynamic=sum(row['bytes'] for row in files if not fixed(row))
        if kind!='binlog':guards.require(dynamic<=384*1024,'Dynamic base database/media exceeds commissioned bound')
        else:guards.require(len(raw)+sum(row['bytes'] for row in files if not str(row.get('path','')).startswith('logs/'))<=2*1024,
                            'Binlog control bytes exceed commissioned bound')
        # With root-owned files, no xattrs or links and controlled names, each
        # native Linux Node has at most512 fixed JSON bytes, eight UTF8 name
        # bytes after JSON escaping, and72 bytes per possible content ID.
        # Restic's minimum chunk is512KiB. Count every directory, including
        # empty ones; content-only inventories cannot bound native trees.
        metadata=4096;nodes=0
        def add(name,size=0):
            nonlocal metadata,nodes
            encoded=name.encode('utf-8')
            guards.require(len(encoded)<=256 and all(ord(c)>=32 for c in name),'Commissioned capture name exceeds metadata bound')
            metadata+=512+8*len(pathlib.PurePosixPath(name).name.encode('utf-8'))+72*((size+512*1024-1)//(512*1024)+1);nodes+=1
            guards.require(nodes<=16384 and metadata<=CAPTURE_METADATA_LIMITS[kind],'Commissioned native metadata exceeds bound')
        if payload is None:
            add('');add('manifest.json',len(raw))
            for number,row in enumerate(files):add(row.get('path','file-'+str(number)),row['bytes'])
        else:
            guards.require(payload==self.root/'spool'/('binlog-payload' if kind=='binlog' else 'base-payload'),
                           'Commissioned capture path differs')
            if os.name=='posix':
                import pwd,grp
                guards.require(pwd.getpwuid(0).pw_name==grp.getgrgid(0).gr_name=='root','Commissioned native owner name differs')
                ancestor=0
                for path in payload.parents:
                    info=path.lstat()
                    guards.require(stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0 and
                                   not os.listxattr(path,follow_symlinks=False),'Commissioned ancestor metadata differs')
                    ancestor+=512+8*len(path.name.encode('utf-8'))+72
                guards.require(ancestor<=4096,'Commissioned ancestor tree exceeds bound')
            for directory,dirs,names in os.walk(payload,followlinks=False):
                for path in [pathlib.Path(directory),*(pathlib.Path(directory)/name for name in names)]:
                    info=path.lstat();guards.require(not stat.S_ISLNK(info.st_mode) and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)),
                                                   'Commissioned native metadata type differs')
                    if os.name=='posix':guards.require(info.st_uid==info.st_gid==0,'Commissioned native owner differs')
                    if hasattr(os,'listxattr'):guards.require(not os.listxattr(path,follow_symlinks=False),'Commissioned native xattrs exceed model')
                    add('' if path==payload else path.relative_to(payload).as_posix(),info.st_size if stat.S_ISREG(info.st_mode) else 0)
                guards.require(all(not (pathlib.Path(directory)/name).is_symlink() for name in dirs),'Commissioned directory symlink')
        return {'raw_bytes':sum(row['bytes'] for row in files)+len(raw),'manifest_bytes':len(raw),
                'dynamic_base_bytes':dynamic,'native_metadata_bound_bytes':metadata,'node_count':nodes}
    def upload(self,lane,payload):
        from maintenance import require_clear
        require_clear(self)
        deadline=self.catalog_deadline(lane)
        backup_catalog.ArchiveCatalog(self,deadline=deadline).ready(deadline=deadline)
        manifest=runtime.load_json(payload/'manifest.json');verify_payload(payload,manifest)
        self.check_capture_budget(manifest,payload)
        adapter=restic_adapter.ResticAdapter(self.c['repositories'][lane],self.c['generation'],str(payload),runner=lambda args:self.restic(lane,args,timeout=50 if lane=='binlog' else 900),verify_archive=lambda sid,metadata,**proof:self.verify_archive(lane,sid,metadata,**proof))
        capture=self.capture_intent(lane,payload);runtime.atomic_json(self.root/'receipts'/('capture-'+lane+'.json'),{**capture,'phase':'upload'})
        sid=runtime.UploadJournal(self.root/'receipts'/lane,self.c['generation']).upload(payload,sha(payload/'manifest.json'),adapter)
        return sid
    def base(self,kind):
        from maintenance import require_clear
        require_clear(self)
        guards.require(kind in ('full','hourly','pre-update'),'Wrong backup kind');self.source_check();self.gate()
        with runtime.lane_lock(self.root/'receipts/job-base.lock'):
            require_clear(self)
            pending=self.pending_payload('base')
            if pending:return {**self.finalize('base',pending,self.upload('base',pending)),'reconciled':True}
            recovered=self.finish_confirmed('base')
            if recovered:return {**recovered,'reconciled':True}
            identity=self.application_identity();last_full=self.full_prerequisite(identity) if kind=='hourly' else None
            catalog=self.schema_catalog();uploads=self.wp_volume/'wp-content/uploads';media_before=tree_inventory(uploads);payload=self.prepare_payload('base');stamp=now();self.dump(payload/'db.sql');data=dump_records.records((payload/'db.sql').read_bytes());guards.require(data['catalog']==catalog and catalog==self.schema_catalog(),'DDL changed during dump')
            coords=coordinates((payload/'db.sql').read_bytes())
            guards.require(media_before==tree_inventory(uploads),'Uploads changed during DB snapshot');self.copy_tree(uploads,payload/'uploads');inventory=self.media(payload/'uploads',data);runtime.atomic_json(payload/'media.json',{'inventory':inventory,'from_dump':True,'tables':data['tables']})
            if kind in ('full','pre-update'):
                self.copy_tree(self.wp_volume,payload/'wordpress')
                for mount in self.wp_mounts:
                    if mount['Type']=='bind':
                        source=pathlib.Path(mount['Source']);guards.require(source.resolve()==source and source.is_relative_to(self.stage) and mount['RW'] is False,'Unknown application bind mount')
                        relative=pathlib.PurePosixPath(mount['Destination']).relative_to('/var/www/html');target=payload/'wordpress'/relative
                        if source.is_dir():
                            if target.exists():guards.require(not any(target.iterdir()),'Mounted target unexpectedly populated');target.rmdir()
                            target.parent.mkdir(mode=0o700,parents=True,exist_ok=True);self.copy_tree(source,target)
                        else:
                            guards.require(source.is_file() and not source.is_symlink(),'Unknown mounted file');target.parent.mkdir(mode=0o700,parents=True,exist_ok=True);shutil.copyfile(source,target);os.chmod(target,0o600)
                (payload/'configuration').mkdir(mode=0o700)
                for name in ('.env','infra/staging/compose.yaml','infra/staging/backup.override.yaml','infra/staging/safety.php','infra/staging/proxy.conf'):
                    source=self.stage/name;guards.require(source.is_file() and not source.is_symlink(),'Missing full configuration');dest=payload/'configuration'/name;dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True);shutil.copyfile(source,dest);os.chmod(dest,0o600)
                public=payload/'configuration/backup-public';public.mkdir(mode=0o700)
                for name in PUBLIC_HELPERS:
                    source=self.bin/name;guards.require(source.is_file() and not source.is_symlink(),'Missing recovery public helper');shutil.copyfile(source,public/name);os.chmod(public/name,0o600)
            guards.require(media_before==tree_inventory(uploads)==tree_inventory(payload/'uploads'),'Uploads changed during capture')
            if kind in ('full','pre-update'):guards.require(identity==self.captured_identity(payload),'Captured application/configuration differs from baseline')
            guards.require(identity==self.application_identity(),'Application/configuration changed during capture')
            manifest={**identity,'format':1,'generation':self.c['generation'],'code_sha':self.c['code_sha'],'stage_app_sha':self.c['stage_app_sha'],'source':self.source,'kind':kind,'captured_at':stamp,'coordinates':coords,'full_id':last_full,'files':tree_inventory(payload),'components':{'mariadb':'10.11.19','wordpress':'7.1.3','woocommerce':'11.2.0','php':'8.3.35','restic':'0.19.1'}}
            runtime.atomic_json(payload/'manifest.json',manifest);sid=self.upload('base',payload)
            receipt=self.finalize('base',payload,sid);return {**receipt,'files':len(manifest['files']),'media_references':len(inventory),'result':'PASS'}
    def finalize(self,lane,payload,sid):
        guards.require(lane in ('base','binlog') and payload==self.root/'spool'/(lane+'-payload'),'Finalize scope mismatch');guards.hex_id(sid,64)
        manifest=runtime.load_json(payload/'manifest.json');verify_payload(payload,manifest);digest=sha(payload/'manifest.json')
        guards.require(manifest['generation']==self.c['generation'],'Finalize generation mismatch')
        state=runtime.UploadJournal(self.root/'receipts'/lane,self.c['generation']).state()
        proofs=[x for x in state['confirmed'] if x['id']==sid and x['manifest_sha256']==digest and x['captured_at']==manifest['captured_at']]
        guards.require(len(proofs)==1,'Finalize requires authenticated upload journal');proof=proofs[0];guards.hex_id(proof['token'],32);guards.utc(proof['confirmed_at'])
        marker=self.root/'receipts'/lane/'finalized.json'
        if marker.exists():
            old=runtime.load_json(marker)
            if old['snapshot_id']==sid and old['manifest_sha256']==digest:
                guards.require(all((self.root/'receipts'/name).is_file() and sha(self.root/'receipts'/name)==value for name,value in old['domains'].items()),'Finalized receipt drift')
                return {**runtime.load_json(self.root/'receipts'/old['receipt']), '_finalized_now':False}
        receipt={'kind':manifest['kind'],'snapshot_id':sid,'captured_at':manifest['captured_at'],'generation':self.c['generation'],'manifest_sha256':digest,'completed_at':proof['confirmed_at']};domains={}
        if lane=='base':
            guards.require(manifest['kind'] in ('full','hourly','pre-update'),'Unknown base kind');receipt.update(coordinates=manifest['coordinates'],source=manifest.get('source'),stage_app_sha=manifest.get('stage_app_sha'),application_sha256=manifest.get('application_sha256'),configuration_sha256=manifest.get('configuration_sha256'));name='base-'+manifest['kind']+'.json';runtime.atomic_json(self.root/'receipts'/name,receipt);domains[name]=sha(self.root/'receipts'/name)
            if manifest['kind'] in ('full','pre-update'):runtime.atomic_json(self.root/'receipts/full.json',receipt);domains['full.json']=sha(self.root/'receipts/full.json')
        else:
            guards.require(manifest['kind']=='binlog','Unknown binlog kind');path=self.root/'receipts/binlog-chain.json';chain=runtime.load_json(path) if path.exists() else {'generation':self.c['generation'],'logs':[],'snapshots':[],'source_stats':{}};guards.require(chain['generation']==self.c['generation'],'Chain generation mismatch')
            known=chain['logs'];fresh=manifest['logs'];guards.checked_logs(fresh);seen=[x for x in chain['snapshots'] if x['id']==sid]
            if seen:
                guards.require(len(seen)==1 and seen[0]['manifest_sha256']==digest and all(x in known for x in fresh),'Previously finalized chain drift')
            else:
                guards.require(manifest['previous_count']==len(known) and guards.new_logs(known,known+fresh)==fresh,'Chain append gap or overlap')
                chain['logs']=known+fresh;chain['snapshots'].append({'id':sid,'manifest_sha256':digest,'first_log':manifest['first_log'],'last_log':manifest['last_log'],'captured_at':manifest['captured_at']});chain['source_stats'].update(manifest['source_stats'])
            chain.update(last_success_at=manifest['captured_at'],snapshot_id=sid);runtime.atomic_json(path,chain);domains['binlog-chain.json']=sha(path);name='binlog-last.json';runtime.atomic_json(self.root/'receipts'/name,receipt);domains[name]=sha(self.root/'receipts'/name)
        # The final marker is last. Any preceding crash repeats only this local
        # idempotent finalization, never capture/put of the acknowledged intent.
        runtime.atomic_json(marker,{'snapshot_id':sid,'manifest_sha256':digest,'domains':domains,'receipt':name})
        return {**receipt,'_finalized_now':True}
    def finish_confirmed(self,lane):
        payload=self.root/'spool'/(lane+'-payload')
        if not payload.exists():return None
        if (self.root/'receipts'/('capture-'+lane+'.json')).exists() and self.capture_intent(lane,payload)['phase']=='capture':return None
        digest=sha(payload/'manifest.json');state=runtime.UploadJournal(self.root/'receipts'/lane,self.c['generation']).state();matches=[x for x in state['confirmed'] if x['manifest_sha256']==digest]
        guards.require(len(matches)==1,'Existing unconfirmed capture; explicit investigation required')
        receipt=self.finalize(lane,payload,matches[0]['id']);return receipt if receipt['_finalized_now'] else None
    def safety(self):
        self.source_check();self.gate();path=self.root/'spool'/('safety-'+uuid.uuid4().hex);path.mkdir(mode=0o700)
        self.dump(path/'db.sql',safety=True);catalog=self.schema_catalog();guards.require(dump_records.records((path/'db.sql').read_bytes())['catalog']==catalog,'Safety dump catalog mismatch')
        for name in ('.env','infra/staging/compose.yaml'):
            target=path/pathlib.Path(name).name;shutil.copyfile(self.stage/name,target);os.chmod(target,0o600)
        receipt={'captured_at':now(),'kind':'pre-ROW protected local rollback dump/config','files':tree_inventory(path),'source_generation':self.c['generation'],'path':str(path)};runtime.atomic_json(self.root/'receipts/safety.json',receipt);return {'safety_dump':True,'files':len(receipt['files']),'result':'PASS'}
    def catalog_deadline(self,lane):
        # Each catalog acquisition has its own <=5s wait; proof/body work is
        # charged to the original minute deadline, never to that wait budget.
        original=getattr(self,'_binlog_job_deadline',None) if lane=='binlog' else None
        return original if original is not None else float('inf')
    def binlog(self):
        previous=getattr(self,'_binlog_job_deadline',None)
        self._binlog_job_deadline=min(previous,time.monotonic()+55) if previous is not None else time.monotonic()+55
        try:return self._binlog()
        finally:
            if previous is None:del self._binlog_job_deadline
            else:self._binlog_job_deadline=previous
    def _binlog(self):
        from maintenance import require_clear
        from retention_cohort import minute_job
        require_clear(self)
        self.source_check();self.gate()
        with minute_job(self,self._binlog_job_deadline):
            require_clear(self)
            pending=self.pending_payload('binlog')
            if pending:
                sid=self.upload('binlog',pending);receipt=self.finalize('binlog',pending,sid);binlog_watermark(receipt['captured_at']);return {**receipt,'reconciled':True}
            recovered=self.finish_confirmed('binlog')
            if recovered:binlog_watermark(recovered['captured_at']);return {**recovered,'reconciled':True}
            variables=dict(x.split('\t') for x in self.sql("SHOW VARIABLES WHERE Variable_name IN ('log_bin','binlog_format','sync_binlog','innodb_flush_log_at_trx_commit');").decode().splitlines());guards.require(variables=={'binlog_format':'ROW','innodb_flush_log_at_trx_commit':'1','log_bin':'ON','sync_binlog':'1'},'Durable ROW binlog absent')
            self.sql('FLUSH BINARY LOGS;');stamp=now();status=self.sql('SHOW MASTER STATUS;').decode().split('\t');active=status[0];guards.log_number(active)
            listed=[x.split('\t') for x in self.sql('SHOW BINARY LOGS;').decode().splitlines()];closed=[(name,int(size)) for name,size,*_ in listed if name!=active];ledgerpath=self.root/'receipts/binlog-chain.json';chain=runtime.load_json(ledgerpath) if ledgerpath.exists() else {'logs':[],'source_stats':{}};known=chain['logs'];known_map={x['file']:x for x in known};source_stats={}
            available=[]
            for name,size in closed:
                guards.log_number(name);path=self.db_volume/name;guards.require(not path.is_symlink() and path.is_file() and path.stat().st_size==size,'Closed binlog changed');metadata=path.stat();fingerprint=[metadata.st_ino,metadata.st_mtime_ns,metadata.st_ctime_ns];source_stats[name]=fingerprint
                if name in known_map:
                    guards.require(chain['source_stats'].get(name)==fingerprint and known_map[name]['size']==size,'Confirmed closed source changed');available.append(known_map[name])
                else:available.append({'file':name,'size':size,'sha256':sha(path)})
            fresh=guards.new_logs(known,available);guards.require(fresh,'No new closed binlog');payload=self.prepare_payload('binlog');(payload/'logs').mkdir(mode=0o700)
            for item in fresh:
                path=payload/'logs'/item['file'];shutil.copyfile(self.db_volume/item['file'],path);os.chmod(path,0o600);guards.require(path.stat().st_size==item['size'] and sha(path)==item['sha256'],'Binlog copy changed')
                self.native.run(['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--cpus','0.5','--memory','384m','--pids-limit','128','--mount','type=bind,source='+str(payload/'logs')+',target=/logs,readonly','--entrypoint','mariadb-binlog',DB_IMAGE,'--no-defaults','--verify-binlog-checksum','/logs/'+item['file']],timeout=20)
                guards.require(not path.is_symlink() and path.stat().st_size==item['size'] and sha(path)==item['sha256'],'Captured binlog changed during checksum')
                origin=self.db_volume/item['file'];metadata=origin.stat()
                guards.require(not origin.is_symlink() and metadata.st_size==item['size'] and [metadata.st_ino,metadata.st_mtime_ns,metadata.st_ctime_ns]==source_stats[item['file']] and sha(origin)==item['sha256'],'Closed source changed during captured checksum')
            manifest={'format':1,'generation':self.c['generation'],'code_sha':self.c['code_sha'],'source':self.source,'kind':'binlog','captured_at':stamp,'logs':fresh,'source_stats':{x['file']:source_stats[x['file']] for x in fresh},'previous_count':len(known),'first_log':guards.log_number(fresh[0]['file']),'last_log':guards.log_number(fresh[-1]['file']),'active_file':active,'files':tree_inventory(payload)}
            runtime.atomic_json(payload/'manifest.json',manifest);sid=self.upload('binlog',payload);self.finalize('binlog',payload,sid);lag=binlog_watermark(stamp)
            return {'snapshot_id':sid,'closed_files':len(fresh),'lag_seconds':lag,'result':'PASS'}
    def monitor(self):
        import budget,maintenance,integrity
        self.source_check();self.gate();maintenance.require_clear(self)
        forecast=budget.load_commissioning_budget(self)
        full_remote_integrity=integrity.status(self)
        b=runtime.UploadJournal(self.root/'receipts/binlog',self.c['generation']).state()
        guards.require('last_success_at' in b,'No verified minute upload');lag=binlog_watermark(b['last_success_at'])
        base=runtime.UploadJournal(self.root/'receipts/base',self.c['generation']).state()
        full=runtime.load_json(self.root/'receipts/full.json');current=dt.datetime.now(UTC)
        guards.require(full.get('generation')==self.c['generation'],'Full backup generation differs')
        ages={'base':(current-guards.utc(base['last_success_at'])).total_seconds(),
              'full':(current-guards.utc(full['captured_at'])).total_seconds()}
        # Include the bounded 15-minute base job runtime after its scheduled
        # start; the independent minute binlog still has a strict 60s lag gate.
        guards.require(0<=ages['base']<=3600+900 and 0<=ages['full']<=86400+900,'Scheduled base/full backup overdue')
        import storage
        observation=storage.live_observation(self,forecast)
        checked_at=dt.datetime.now(UTC)
        budget.commissioning_live_applicable(forecast,observation,now=checked_at)
        # The remote read can overlap a minute upload. Re-read its atomic
        # journal so a slow monitor cannot report a stale earlier watermark.
        latest=runtime.UploadJournal(self.root/'receipts/binlog',self.c['generation']).state()
        lag=guards.upload_lag(latest['last_success_at'],checked_at)
        storage.publish_live_observation(self,forecast,observation)
        return {'result':'PASS','lag_seconds':lag,'base_age_seconds':ages['base'],'full_age_seconds':ages['full'],
                'full_remote_integrity_completed_at':full_remote_integrity,
                'budget_status':forecast['result'],'projected_monthly_rub':forecast['projected_monthly_rub'],
                'projected_storage_bytes':forecast['projected_storage_bytes'],'budget_valid_until':forecast['valid_until']}

def main():
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True);parser.add_argument('mode',choices=['safety','init-base','init-binlog','full','hourly','pre-update','binlog','monitor']);args=parser.parse_args();start=now();result={'started_at':start,'mode':args.mode}
    try:
        os.nice(10);worker=Worker(args.config)
        if args.mode.startswith('init-'):details=worker.initialize(args.mode[5:])
        elif args.mode=='safety':details=worker.safety()
        elif args.mode=='binlog':details=worker.binlog()
        elif args.mode=='monitor':details=worker.monitor()
        else:details=worker.base(args.mode)
        result.update(details);result['result']='PASS'
    except Exception as e:result['result']='FAIL';result['error_type']=type(e).__name__
    result['finished_at']=now();print(json.dumps(result));return 0 if result['result']=='PASS' else 1
if __name__=='__main__':sys.exit(main())
