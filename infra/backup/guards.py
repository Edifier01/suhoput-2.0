"""Pure backup guards. These checks do not perform or prove external effects."""
import datetime as dt
import pathlib
import re
from urllib.parse import urlsplit

class GuardError(ValueError):
    pass

def require(condition, message='Invalid backup evidence'):
    if not condition:
        raise GuardError(message)

def hex_id(value, length):
    require(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{'+str(length)+r'}', value))
    return value

def source_scope(root, schema, generation):
    require(isinstance(root,str) and re.fullmatch(r'/srv/suhoput2-stage-20[0-9]{6}',root), 'Stage scope required')
    require(schema=='suhoput2_stage', 'Stage schema required')
    hex_id(generation,32)
    project=pathlib.PurePosixPath(root).name
    return {'root':root,'project':project,'schema':schema,'generation':generation,
            'db_container':project+'-db-1','wordpress_container':project+'-wordpress-1',
            'db_volume':project+'_db','wordpress_volume':project+'_wordpress'}

def repository_url(endpoint, bucket, lane):
    require(isinstance(endpoint,str))
    parsed=urlsplit(endpoint)
    require(parsed.scheme=='https' and parsed.hostname and not parsed.username and not parsed.password
            and parsed.path in ('','/') and not parsed.query and not parsed.fragment, 'HTTPS endpoint required')
    require(isinstance(bucket,str) and re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]',bucket))
    require(lane in ('base','binlog'), 'Unknown repository lane')
    return 's3:'+endpoint.rstrip('/')+'/'+bucket+'/suhoput2/stage-b/repositories/'+lane

def media_path(value):
    require(isinstance(value,str) and value and '\x00' not in value and '\\' not in value and ':' not in value)
    p=pathlib.PurePosixPath(value)
    require(not p.is_absolute() and '..' not in p.parts and '.' not in value.split('/')
            and value==str(p) and not value.endswith('/'), 'Unsafe media path')
    return value

def confirm_upload(pending, matches):
    require(len(matches)==1,'Unknown or duplicate upload result')
    actual=matches[0]
    for field in ('token','generation','manifest_sha256'):
        require(actual.get(field)==pending.get(field) and pending.get(field),'Upload identity mismatch')
    hex_id(pending['token'],32);hex_id(pending['generation'],32);hex_id(pending['manifest_sha256'],64)
    return hex_id(actual['id'],64)

def log_number(value):
    require(isinstance(value,str))
    m=re.fullmatch(r'suhoput2-binlog\.([0-9]{6})',value)
    require(m and int(m[1])>0,'Unexpected binlog source')
    return int(m[1])

def checked_logs(logs):
    numbers=[]
    for log in logs:
        number=log_number(log['file']);hex_id(log['sha256'],64)
        require(type(log['size']) is int and log['size']>=4)
        require(not numbers or number>numbers[-1],'Duplicate or unordered logs')
        numbers.append(number)
    return numbers

def new_logs(known, available):
    try:
        known_numbers=checked_logs(known);numbers=checked_logs(available)
        require(not known_numbers or known_numbers==list(range(1,known_numbers[-1]+1)), 'Gap in confirmed chain')
        old={x['file']:x for x in known}
        for item in available:
            if item['file'] in old:
                require(item==old[item['file']],'Confirmed log bytes changed')
        last=known_numbers[-1] if known_numbers else 0
        fresh=[x for x in available if log_number(x['file'])>last]
        if fresh:
            expected=list(range(last+1,log_number(fresh[-1]['file'])+1))
            require([log_number(x['file']) for x in fresh]==expected,'Missing binlog in chain')
        return fresh
    except (KeyError,TypeError) as error:
        raise GuardError('Incomplete log evidence') from error

def utc(value):
    try:
        stamp=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
        require(stamp.tzinfo is not None and stamp.utcoffset()==dt.timedelta(),'UTC required')
        return stamp
    except (ValueError,TypeError,AttributeError) as error:
        raise GuardError('Invalid UTC timestamp') from error

def upload_lag(uploaded, now):
    require(now.utcoffset()==dt.timedelta())
    lag=(now-utc(uploaded)).total_seconds()
    require(0<=lag<=60,'Binlog upload stale or clock rollback')
    return lag

def retention_candidates(snapshots,generation,now):
    """Keep window, preceding anchor, referenced fulls and chain prerequisites.

    A candidate is not permission to delete. Native integrity and a real restore
    of the anchor/chain/media, plus owner access, must precede applying a plan.
    """
    hex_id(generation,32)
    cutoff=now-dt.timedelta(days=30)
    require(now.utcoffset()==dt.timedelta())
    try:
        indexed={}
        for row in snapshots:
            sid=hex_id(row['id'],64)
            require(sid not in indexed and row['generation']==generation and row['kind'] in ('full','pre-update','hourly','binlog'), 'Unknown snapshot; retention stopped')
            require(utc(row['time'])<=now,'Future snapshot or clock rollback')
            indexed[sid]=row
        bases=[x for x in snapshots if x['kind'] in ('full','pre-update','hourly')]
        require(bases,'No recovery base')
        old_bases=[x for x in bases if utc(x['time'])<=cutoff]
        anchor=max(old_bases,key=lambda x:utc(x['time'])) if old_bases else min(bases,key=lambda x:utc(x['time']))
        kept_bases=[x for x in bases if utc(x['time'])>=cutoff or x is anchor]
        keep={x['id'] for x in kept_bases}
        for base in kept_bases:
            if base['kind']=='hourly':
                full=indexed.get(base['full_id'])
                require(full and full['kind'] in ('full','pre-update') and utc(full['time'])<=utc(base['time']), 'Missing full prerequisite')
                keep.add(full['id'])
        first=anchor.get('first_log')
        ranges=[]
        for log in snapshots:
            if log['kind']=='binlog':
                require(type(first) is int and first>0,'Anchor log coordinates missing')
                require(type(log['first_log']) is int and type(log['last_log']) is int and 0<log['first_log']<=log['last_log'])
                if log['last_log']>=first or utc(log['time'])>=cutoff: keep.add(log['id'])
                if log['last_log']>=first: ranges.append((log['first_log'],log['last_log']))
        if ranges:
            ranges.sort()
            require(ranges[0][0]<=first<=ranges[0][1],'Anchor binlog absent')
            for previous,current in zip(ranges,ranges[1:]):
                require(current[0]==previous[1]+1,'Gap or overlap in retained chain')
        return {'anchor_id':anchor['id'],'keep':sorted(keep),'candidates':sorted(set(indexed)-keep),
                'apply_allowed':False,'history_coverage_verified':False,'pre_window_anchor_present':bool(old_bases)}
    except (KeyError,TypeError) as error:
        raise GuardError('Incomplete retention evidence') from error

def authorize_retention(plan,proof,generation):
    # Boolean input flags do not authenticate inventory or prove a restore.
    # No deletion path exists until a native, inventory-bound verifier exists.
    raise GuardError('Native inventory-bound recovery verifier absent; deletion disabled')
