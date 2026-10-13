"""Read-only S3 repository object bytes, independent of restic reachability.

ListObjectsV2 includes orphaned packs; it does not include incomplete multipart
uploads or old object versions. Never use this receipt as whole-bucket billing.
"""
import datetime as dt
import hashlib
import hmac
import http.client
import json
import os
import stat
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from urllib.parse import quote, urlsplit
import guards, runtime

PREFIX='suhoput2/stage-b/repositories/'
MAX_XML=2*1024*1024

def list_objects(read, bucket, prefix, *, whole_bucket=False):
    guards.require(prefix=='' if whole_bucket else prefix in (PREFIX+'base/',PREFIX+'binlog/'),'Fixed storage namespace required')
    seen=set();tokens=set();pages=[];size=0;token=None
    indexes={lane:{'object_count':0,'bytes':0} for lane in ('base','binlog') if whole_bucket or prefix==PREFIX+lane+'/'}
    for _ in range(1000):
        query={'list-type':'2','max-keys':'1000','prefix':prefix}
        if token is not None:query['continuation-token']=token
        raw=read(query)
        guards.require(isinstance(raw,bytes) and len(raw)<=MAX_XML and b'<!' not in raw,'Bounded plain S3 XML required')
        try:root=ET.fromstring(raw)
        except ET.ParseError as error:raise guards.GuardError('Invalid S3 listing XML') from error
        for node in root.iter():node.tag=node.tag.rsplit('}',1)[-1]
        def field(node,name):
            rows=node.findall(name);guards.require(len(rows)==1,'S3 listing field missing or duplicate')
            return rows[0].text or ''
        guards.require(root.tag=='ListBucketResult' and field(root,'Name')==bucket and field(root,'Prefix')==prefix and
                       not root.findall('CommonPrefixes'),'S3 listing scope/grouping differs')
        truncated=field(root,'IsTruncated');guards.require(truncated in ('true','false'),'S3 pagination state unknown')
        contents=root.findall('Contents');guards.require(len(contents)<=1000,'Oversized S3 listing page')
        for row in contents:
            key=field(row,'Key');amount=field(row,'Size')
            guards.require(key.startswith(prefix) and key not in seen and amount.isascii() and amount.isdecimal(),
                           'Foreign, duplicate or invalid S3 object')
            seen.add(key);size+=int(amount)
            for lane,metrics in indexes.items():
                index_prefix=PREFIX+lane+'/index/'
                if key.startswith(index_prefix):
                    guards.hex_id(key[len(index_prefix):],64)
                    metrics['object_count']+=1;metrics['bytes']+=int(amount)
        pages.append(hashlib.sha256(raw).hexdigest())
        if truncated=='false':
            return {'physical_bytes':size,'object_count':len(seen),'list_requests':len(pages),'page_sha256':pages,
                    'repository_indexes':indexes,'whole_bucket_billed_storage_verified':False}
        token=field(root,'NextContinuationToken')
        guards.require(token and token not in tokens and len(token)<=4096,'S3 pagination did not advance');tokens.add(token)
    raise guards.GuardError('S3 listing exceeds bounded page count')

class S3Reader:
    """TLS-verified SigV4 GET only; executed in a deadline-bounded subprocess.

    Socket timeouts bound idle reads, not slow continuous responses or DNS.
    The caller must enforce termination outside this process as run_inventory
    does. The local deadline here only avoids starting another expired request.
    """
    def __init__(self,worker,timeout):
        self.w=worker;self.endpoint=urlsplit(worker.c['endpoint']);self.deadline=time.monotonic()+timeout
        guards.repository_url(worker.c['endpoint'],worker.c['bucket'],'base')
    def __call__(self,query):
        remaining=self.deadline-time.monotonic();guards.require(remaining>0,'S3 accounting deadline exceeded')
        stamp=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ');day=stamp[:8];region=self.w.c['region']
        path='/'+quote(self.w.c['bucket'],safe='');encoded='&'.join(quote(k,safe='')+'='+quote(v,safe='') for k,v in sorted(query.items()))
        empty=hashlib.sha256(b'').hexdigest();host=self.endpoint.netloc
        headers={'host':host,'x-amz-content-sha256':empty,'x-amz-date':stamp}
        names=';'.join(sorted(headers));canonical_headers=''.join(k+':'+headers[k]+'\n' for k in sorted(headers))
        request='\n'.join(('GET',path,encoded,canonical_headers,names,empty))
        scope=day+'/'+region+'/s3/aws4_request';string='AWS4-HMAC-SHA256\n'+stamp+'\n'+scope+'\n'+hashlib.sha256(request.encode()).hexdigest()
        key=('AWS4'+self.w.credentials['AWS_SECRET_ACCESS_KEY']).encode()
        for value in (day,region,'s3','aws4_request'):key=hmac.new(key,value.encode(),hashlib.sha256).digest()
        signature=hmac.new(key,string.encode(),hashlib.sha256).hexdigest()
        headers['Authorization']='AWS4-HMAC-SHA256 Credential='+self.w.credentials['AWS_ACCESS_KEY_ID']+'/'+scope+', SignedHeaders='+names+', Signature='+signature
        connection=http.client.HTTPSConnection(self.endpoint.hostname,self.endpoint.port,timeout=min(remaining,10))
        try:
            connection.request('GET',path+'?'+encoded,headers=headers)
            response=connection.getresponse();guards.require(response.status==200,'S3 accounting request rejected')
            raw=response.read(MAX_XML+1)
            guards.require(time.monotonic()<self.deadline and len(raw)<=MAX_XML,'S3 accounting response deadline/size exceeded')
            return raw
        finally:connection.close()

def repository_receipt(worker,lane,*,repository_id,timeout):
    from worker import protected_directory
    guards.require(lane in ('base','binlog') and timeout>0,'Invalid repository accounting scope')
    guards.hex_id(repository_id,64)
    result=run_inventory(worker,lane,timeout)
    indexes=result['repository_indexes'][lane]
    directory=worker.root/'receipts/storage'
    directory.mkdir(mode=0o700,exist_ok=True);protected_directory(directory)
    path=directory/(uuid.uuid4().hex+'.json')
    document={**result,'index_object_count':indexes['object_count'],'index_bytes':indexes['bytes'],
              'format':1,'generation':worker.c['generation'],'code_sha':worker.c['code_sha'],'lane':lane,
              'repository':worker.c['repositories'][lane],'repository_id':repository_id,
              'observed_at':dt.datetime.now(dt.timezone.utc).isoformat(),
              'scope':'current-repository-object-bytes','source':'TLS-verified S3 ListObjectsV2, complete paginated fixed prefix'}
    runtime.atomic_json(path,document)
    return path

def run_inventory(worker,lane,timeout):
    """NativeRunner kills the whole reader even during DNS/headers/slow body."""
    guards.require(lane in ('base','binlog','whole') and 0<timeout<=55,'Bounded repository accounting required')
    raw=worker.native.run([sys.executable,'-B',str(worker.bin/'storage.py'),'--config',
                           str(worker.root/'config/runtime.json'),'--lane',lane],timeout=timeout)
    return json.loads(raw,object_pairs_hook=runtime.no_duplicates)

def live_workload(worker):
    """Current source allocation/media/recent binlog bytes, not a backup.

    The admitted workload model must allow for dump/pack overhead separately.
    Recent binlogs include the active file. This does not claim exact billing.
    """
    raw=worker.sql("SELECT COALESCE(SUM(DATA_LENGTH+INDEX_LENGTH),0) FROM information_schema.TABLES WHERE TABLE_SCHEMA='suhoput2_stage';").strip()
    guards.require(raw.isascii() and raw.isdigit(),'Current database size unavailable')
    uploads=worker.wp_volume/'wp-content/uploads';guards.require(uploads.is_dir() and not uploads.is_symlink(),'Current media directory unavailable')
    media=0;count=0
    for directory,dirs,files in os.walk(uploads,followlinks=False):
        parent=uploads.__class__(directory)
        for name in [*dirs,*files]:
            path=parent/name;metadata=path.lstat();count+=1
            guards.require(count<=100000 and not stat.S_ISLNK(metadata.st_mode),'Unbounded or linked current media')
            if name in files:
                guards.require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink==1,'Invalid current media file')
                media+=metadata.st_size
    cutoff=time.time()-86400;binlogs=0;count=0
    for path in worker.db_volume.glob('suhoput2-binlog.*'):
        if path.name=='suhoput2-binlog.index':continue
        guards.log_number(path.name);metadata=path.lstat();count+=1
        guards.require(count<=100000 and stat.S_ISREG(metadata.st_mode) and metadata.st_nlink==1,'Invalid current source binlog')
        if metadata.st_mtime>=cutoff:binlogs+=metadata.st_size
    return {'database_bytes':int(raw),'media_bytes':media,'binlog_bytes_per_day':binlogs}

def live_observation(worker,forecast,*,timeout=40):
    from worker import private_path, protected_directory, sha
    protected_directory(worker.root/'receipts')
    path=worker.root/'receipts/commissioning-visible.json';sample=None;sampled=None
    interval=forecast.get('visible_interval_seconds',3600)
    guards.require(type(interval) is int and interval in (3600,21600),'Unsupported visible inventory interval')
    binding={'forecast_sha256':document_digest(forecast),'producer_sha256':sha(private_path(worker.bin/'storage.py'))}
    if path.exists() or path.is_symlink():
        value=runtime.load_json(private_path(path));body={k:v for k,v in value.items() if k!='sha256'}
        guards.require(value.get('format')=='protected-visible-list-v1' and value.get('sha256')==document_digest(body),
                       'Cached visible inventory bytes changed')
        age=(dt.datetime.now(dt.timezone.utc)-guards.utc(value['sampled_at'])).total_seconds()
        guards.require(age>=0,'Cached visible inventory clock rollback')
        # Preserve the actual observation clock and leave a minute for the
        # bounded remote call. Budget admission reserves the complete interval
        # of growth; the per-minute workload/lag checks are independent.
        if value['binding']==binding and age<interval-60:sample=value['sample'];sampled=value['sampled_at']
    if sample is None:
        sampled=dt.datetime.now(dt.timezone.utc).isoformat();sample=run_inventory(worker,'whole',timeout)
        body={'format':'protected-visible-list-v1','binding':binding,'sampled_at':sampled,'sample':sample}
        runtime.atomic_json(path,{**body,'sha256':document_digest(body)})
    workload=live_workload(worker)
    return {**sample,'format':'commissioning-live-observation-v3' if interval==21600 else 'commissioning-live-observation-v2','bucket':worker.c['bucket'],
            'scope_sha256':forecast['scope_sha256'],'source':worker.source,'generation':worker.c['generation'],
            'observed_at':dt.datetime.now(dt.timezone.utc).isoformat(),'visible_sampled_at':sampled,
            'visible_interval_seconds':interval,'prefix':'','complete':True,'workload':workload}

def document_digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

def publish_live_observation(worker,forecast,observation):
    from worker import private_path, protected_directory, sha
    protected_directory(worker.root/'receipts')
    runtime.atomic_json(worker.root/'receipts/commissioning-live.json',
                        {'format':'protected-commissioning-live-v1','observation':observation,
                         'observation_sha256':document_digest(observation),'forecast_sha256':document_digest(forecast),
                         'producer_sha256':sha(private_path(worker.bin/'storage.py'))})

def load_live_observation(worker,forecast):
    """Read a protected native observation; caller still checks its ≤120s age."""
    from worker import private_path, protected_directory, sha
    protected_directory(worker.root/'receipts')
    value=runtime.load_json(private_path(worker.root/'receipts/commissioning-live.json'))
    guards.require(value.get('format')=='protected-commissioning-live-v1' and
                   value.get('forecast_sha256')==document_digest(forecast) and
                   value.get('producer_sha256')==sha(private_path(worker.bin/'storage.py')) and
                   value.get('observation_sha256')==document_digest(value.get('observation')),
                   'Current storage observation origin changed')
    return value['observation']

def main():
    import argparse
    from worker import Worker
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True);parser.add_argument('--lane',choices=('base','binlog','whole'),required=True)
    args=parser.parse_args();worker=Worker(args.config)
    whole=args.lane=='whole'
    result=list_objects(S3Reader(worker,55),worker.c['bucket'],'' if whole else PREFIX+args.lane+'/',whole_bucket=whole)
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':main()
