"""Offline actual Selectel JSONL access counters; no credentials or network.

The exported provider byte totals are preserved as measured transport bytes.
They are not silently equated to invoice MB rounding. No CLI-invocation counts,
deduplication of retries, interpolation of unobserved jobs or fabricated zeroes.
"""
import collections, datetime as dt, hashlib, json, uuid
import guards,runtime
FIELDS=frozenset(('container_name','timestamp','server_to_client_bytes','client_to_server_bytes','http_method','status','path'))
METHODS=frozenset(('GET','HEAD','PUT','POST','COPY','DELETE','OPTIONS'))
EXEMPT=frozenset((403,500,501,502,503,504))

def aggregate(rows):
    methods=collections.Counter(r['http_method'] for r in rows)
    billed=[r for r in rows if r['status'] not in EXEMPT]
    return {'http_requests':len(rows),'methods':dict(sorted(methods.items())),
            'status_counts':dict(sorted(collections.Counter(str(r['status']) for r in rows).items())),
            'charge_groups':{'GET':sum(r['http_method'] in ('GET','HEAD') for r in billed),
                             'PUT':sum(r['http_method'] in ('PUT','POST','COPY') for r in billed),'DELETE':0},
            'status_exempt_requests':sum(r['status'] in EXEMPT for r in rows),
            'server_to_client_bytes':sum(r['server_to_client_bytes'] for r in rows),
            'client_to_server_bytes':sum(r['client_to_server_bytes'] for r in rows)}

def access_log(data,*,bucket,windows=None):
    guards.require(isinstance(data,bytes) and 0<len(data)<=128*1024*1024 and isinstance(bucket,str) and bucket,'Bounded native log and exact bucket required')
    windows=windows or {};bounds={}
    for name,row in windows.items():
        guards.require(name in ('binlog','hourly','full','pre_update','check','retention','restore'),'Unknown measured job')
        start=guards.utc(row['started_at']);end=guards.utc(row['completed_at'])
        guards.require(start<end,'Invalid job observation interval')
        # Provider timestamps have second resolution: boundary seconds are
        # included conservatively, never dropped to improve cost figures.
        bounds[name]=(start.replace(microsecond=0),end.replace(microsecond=0))
    rows=[];stamps=[];accounts=set()
    try:
        for line in data.splitlines():
            guards.require(line.strip(),'Empty native log line')
            row=json.loads(line,object_pairs_hook=runtime.no_duplicates)
            guards.require(isinstance(row,dict) and set(row) in (FIELDS,FIELDS|{'account_uuid'}) and row['container_name']==bucket,'Foreign or unknown native log scope/schema')
            if 'account_uuid' in row:
                account=row['account_uuid'];guards.require(isinstance(account,str) and str(uuid.UUID(account)).replace('-','')==account.replace('-',''),'Invalid provider account scope')
                accounts.add(account);guards.require(len(accounts)==1,'Mixed provider account scopes')
            stamp=guards.utc(row['timestamp']);guards.require(row['http_method'] in METHODS,'Unknown native HTTP method')
            guards.require(type(row['status']) is int and 100<=row['status']<=599,'Invalid native response status')
            for key in ('server_to_client_bytes','client_to_server_bytes'):
                guards.require(type(row[key]) is int and 0<=row[key]<=1024**4,'Invalid native byte counter')
            # Provider emits absolute HTTPS URLs for S3/control requests and
            # opaque paths for some panel records. None are executed or echoed.
            guards.require(isinstance(row['path'],str) and 0<len(row['path'])<=16384 and '\x00' not in row['path'] and '\n' not in row['path'] and '\r' not in row['path'],'Invalid native request path')
            rows.append(row);stamps.append(stamp)
    except (ValueError,UnicodeError,KeyError,TypeError) as error:
        raise guards.GuardError('Invalid provider access-log evidence') from error
    guards.require(rows,'Native log rows missing')
    jobs={};memberships=[[] for _ in rows]
    for name,(start,end) in bounds.items():
        selected=[]
        for index,(row,stamp) in enumerate(zip(rows,stamps)):
            if start<=stamp<=end:selected.append(row);memberships[index].append(name)
        jobs[name]={**aggregate(selected),'started_at_utc':start.isoformat(),'completed_at_utc':end.isoformat(),
                    'interval_covered_by_export_rows':min(stamps)<=start and end<=max(stamps)}
    overlap=sum(len(names)>1 for names in memberships)
    return {**aggregate(rows),'result':'NATIVE_COUNTERS_PARSED','file_sha256':hashlib.sha256(data).hexdigest(),
            'source':'Selectel S3 access-log JSONL; seven provider fields; UTC timestamps',
            'first_utc':min(stamps).isoformat(),'last_utc':max(stamps).isoformat(),'jobs':jobs,
            'account_scope_sha256':hashlib.sha256(next(iter(accounts)).encode()).hexdigest() if accounts else None,
            'overlapping_request_lines':overlap,'unattributed_request_lines':sum(not names for names in memberships),
            'isolated_job_measurement':bool(jobs) and overlap==0 and all(j['interval_covered_by_export_rows'] for j in jobs.values()),
            'monthly_projection_verified':False,'invoice_rounding_reconciled':False,
            'billing_rule_source':'https://docs.selectel.ru/s3/about/payment/'}
