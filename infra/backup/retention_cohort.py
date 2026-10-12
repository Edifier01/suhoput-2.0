"""Protected immutable retention cohort shared by all native proof producers.

The pointer only selects an exclusively published hash-bound document. Native
current listing, admission seals and journals authenticate it on every load;
neither a receipt nor a caller list can create archive provenance.
"""
import contextlib, copy, datetime as dt, time
import backup_catalog, guards, runtime, retention, retention_apply
from worker import private_path, protected_directory, sha

def clock():return dt.datetime.now(dt.timezone.utc)
MAX_CRITICAL_SECONDS=55

@contextlib.contextmanager
def upload_section(worker):
    # Job locks cover capture and domain finalization that happen outside the
    # upload journal lock. All locks are nonblocking and held only briefly.
    with runtime.lane_lock(worker.root/'receipts/job-base.lock'),runtime.lane_lock(worker.root/'receipts/job-binlog.lock'), \
         runtime.lane_lock(worker.root/'receipts/base/lane.lock'),runtime.lane_lock(worker.root/'receipts/binlog/lane.lock'):
        yield

def ready(worker):
    backup_catalog.ArchiveCatalog(worker).ready()
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
            reader=reader.refresh()
            inventory=retention.native_inventory(w,clock(),repository_ids(w),clock,reader=reader)
            confirmed(w,inventory);planned=clock();plan=retention.inventory_plan(inventory,planned)
            compact=retention_apply.compact_authenticated_inventory(inventory,planned)
            captured_seals=seals(reader,inventory);captured_head=copy.deepcopy(reader.head)
            critical=time.monotonic()
            with upload_section(w):
                deadline=time.monotonic()+MAX_CRITICAL_SECONDS
                ready(w);reader=reader.refresh();current=retention.native_inventory(w,clock(),inventory['repositories'],clock,reader=reader,deadline=deadline)
                confirmed(w,current);retention_apply.compatible_inventory(inventory,current,clock())
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
    def load(self,reader):
        reader=reader.refresh();document=self._document();inventory=self._inventory(document,reader)
        current=retention.native_inventory(self.w,clock(),inventory['repositories'],clock,reader=reader)
        confirmed(self.w,current);retention_apply.compatible_inventory(inventory,current,clock())
        return inventory
