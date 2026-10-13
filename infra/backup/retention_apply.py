"""Bounded native retention apply with an injected, protected I/O boundary.

This module cannot establish receipt provenance. The integration must authenticate
inventory and load actual receipts from root-owned protected paths, never user
flags, and serialize apply/reconcile under the same retention lock. IntentStore
prepare() must exclusively create and fsync an immutable intent (including its
parent directory) BEFORE returning. Receipt writer must durably write a root-owned
receipt. An existing intent always disables a subsequent apply, even after success.
No network, credential loading, CLI, scheduling, prune, repair or unlock lives here.
"""
import copy
import contextlib
import datetime as dt
import hashlib
import json
import uuid
from decimal import Decimal, InvalidOperation

import guards
import retention

EVIDENCE_TYPES = frozenset(('audit', 'anchor', 'tip', 'owner', 'budget', 'history'))
NATIVE_V2_POLICY = 'native-v2'
NATIVE_V2_EVIDENCE_TYPES = EVIDENCE_TYPES - {'history'}
MAX_PLAN_AGE_SECONDS = 900
MAX_CANDIDATES = 256
MAX_FORGET_IDS = 256
MAX_INTENT_CANDIDATES = retention.MAX_RETENTION_INTENT
DAILY_BATCH_PROTOCOL = 'daily-batches-v2'
BATCH_PHASE_PROTOCOL = 'bounded-batches-v2'


def evidence_types(plan):
    """The absent policy retains the complete legacy six-receipt contract."""
    if 'readiness_policy' not in plan:
        return EVIDENCE_TYPES
    guards.require(plan['readiness_policy'] == NATIVE_V2_POLICY, 'Unknown native readiness policy')
    return NATIVE_V2_EVIDENCE_TYPES


def _forecast_clock(document, at):
    completed=guards.utc(document['completed_at']);until=guards.utc(document['valid_until'])
    guards.require(completed <= at <= until and (until-completed).total_seconds() <= 31*86400,
                   'Commissioning forecast expired or clock differs')


def _commissioning_budget(document, inventory, source, at):
    """Pure checks after readiness_v2 authenticates the protected real loader.

    This report deliberately has no current cohort, fake history or invoice.
    Configuration and current workload applicability belong to that loader.
    """
    guards.require(document['format']=='commissioning_budget_pass' and document['result']=='PASS' and
                   document['generation']==inventory['generation'] and document['source']==source and
                   document['actual_month_observed'] is False and document['invoice_verified'] is False,
                   'Authentic commissioning forecast binding required')
    for key in ('configuration_sha256','scope_sha256'):guards.hex_id(document[key],64)
    _forecast_clock(document,at)
    cost=document['projected_monthly_rub'];size=document['projected_storage_bytes']
    guards.require(type(cost) in (str,int,float), 'Unknown commissioning cost')
    try:cost=Decimal(str(cost))
    except InvalidOperation as error:raise guards.GuardError('Invalid commissioning cost') from error
    guards.require(cost.is_finite() and 0<=cost<=500 and type(size) is int and 0<=size<=10*1024**3,
                   'Commissioning budget exceeds agreed limits or unknown')


def document_digest(document):
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode()).hexdigest()


def _time(at):
    guards.require(isinstance(at, dt.datetime) and at.utcoffset() == dt.timedelta(),
                   'Explicit UTC evaluation time required')
    return at


def _index(inventory, at):
    guards.hex_id(inventory['generation'], 32)
    guards.require(set(inventory['repositories']) == {'base', 'binlog'}, 'Repository lanes differ')
    for rid in inventory['repositories'].values():
        guards.hex_id(rid, 64)
    rows = {}; tokens = set(); sources = []
    compact = inventory.get('format') == 'authenticated-retention-identities-v1'
    for row in inventory['snapshots']:
        sid = guards.hex_id(row['id'], 64)
        guards.require(sid not in rows and row['generation'] == inventory['generation'],
                       'Duplicate or foreign inventory identity')
        guards.require(row['lane'] in ('base', 'binlog') and row['kind'] in
                       (('full', 'hourly', 'pre-update') if row['lane'] == 'base' else ('binlog',)),
                       'Unknown inventory lane or kind')
        token = guards.hex_id(row['token'], 32)
        guards.require(token not in tokens, 'Duplicate inventory upload token')
        tokens.add(token); guards.hex_id(row['manifest_sha256'], 64)
        guards.require(guards.utc(row['time']) <= guards.utc(row['snapshot_time']) <= at,
                       'Inventory capture/upload clock mismatch')
        source = inventory['source'] if compact else inventory['manifests'][sid]['source']
        guards.require(isinstance(source, dict) and source and
                       source.get('generation') == inventory['generation'],
                       'Authenticated source missing')
        sources.append(source); rows[sid] = row
    guards.require(rows and (compact or set(inventory['manifests']) == set(rows)), 'Manifest inventory differs')
    guards.require(all(source == sources[0] for source in sources), 'Mixed snapshot sources')
    return rows, sources[0]


def compact_authenticated_inventory(inventory, at):
    """Persist every authenticated identity, without duplicating payload lists.

    Native readers verify full manifest bytes against each row's SHA before
    this boundary. That digest binds files, coordinates and dependencies too.
    Current inventories/arrivals still use full manifests for dependency gates.
    """
    _, source = _index(inventory, at)
    return {'format': 'authenticated-retention-identities-v1',
            'generation': inventory['generation'], 'repositories': copy.deepcopy(inventory['repositories']),
            'source': copy.deepcopy(source), 'snapshots': copy.deepcopy(inventory['snapshots'])}


def compatible_inventory(before, after, at, allowed_absent=()):
    """Allow only authenticated arrivals and removal of exact authorized IDs."""
    _time(at)
    try:
        original, source = _index(before, at); current, new_source = _index(after, at)
        guards.require(before['generation'] == after['generation'] and
                       before['repositories'] == after['repositories'] and source == new_source,
                       'Inventory repository, generation or source changed')
        allowed = set(allowed_absent)
        guards.require(allowed <= set(original), 'Unknown allowed absence')
        missing = set(original) - set(current)
        guards.require(missing <= allowed, 'Protected snapshot disappeared')
        for sid in set(original) & set(current):
            full_documents_equal = ('manifests' not in before or 'manifests' not in after or
                                    before['manifests'][sid] == after['manifests'][sid])
            guards.require(original[sid] == current[sid] and full_documents_equal,
                           'Known snapshot or manifest changed')
        return {'absent_ids': sorted(missing), 'arrival_ids': sorted(set(current) - set(original))}
    except (KeyError, TypeError, ValueError) as error:
        raise guards.GuardError('Incomplete authenticated inventory comparison') from error


def protected_dependencies(inventory, candidate_ids, at):
    """Every preserved hourly, including arrivals, protects its authenticated full."""
    try:
        indexed, _ = _index(inventory, at)
        candidates = set(candidate_ids)
        for sid, row in indexed.items():
            if row['kind'] != 'hourly' or sid in candidates:
                continue
            manifest = inventory['manifests'][sid]
            full_id = guards.hex_id(manifest['full_id'], 64)
            full = indexed.get(full_id)
            guards.require(full is not None and full['kind'] in ('full', 'pre-update') and
                           guards.utc(full['time']) <= guards.utc(row['time']),
                           'Preserved hourly has no valid authenticated full')
            full_manifest = inventory['manifests'][full_id]
            guards.require(all(manifest[key] == full_manifest[key] for key in
                               ('source', 'stage_app_sha', 'application_sha256', 'configuration_sha256')),
                           'Preserved hourly/full source or application differs')
            guards.require(full_id not in candidates,
                           'Frozen candidate is required by a preserved hourly arrival')
        # Fulls retained solely for hourly application files are not recovery
        # bases. Every other preserved base, including a new arrival, protects
        # the complete chain starting at its real dump coordinates.
        binlog_candidates=[cid for cid in candidates if cid in indexed and indexed[cid]['lane']=='binlog']
        if not any(row['lane']=='binlog' for row in indexed.values()):
            guards.require(not binlog_candidates,'Candidate binlog chain absent');return True
        plan=retention.inventory_plan(inventory,at)
        descriptors={item['file']:item for item in plan['logs']}
        last_deleted=max((inventory['manifests'][cid]['last_log'] for cid in binlog_candidates),default=0)
        cutoff=at-dt.timedelta(days=30)
        application_only={inventory['manifests'][sid]['full_id'] for sid,row in indexed.items()
                          if row['kind']=='hourly' and sid not in candidates}
        for sid,row in indexed.items():
            if row['lane']!='base' or sid in candidates:continue
            if sid in application_only and row['kind'] in ('full','pre-update') and guards.utc(row['time'])<cutoff and sid!=plan['anchor_id']:continue
            start=inventory['manifests'][sid]['coordinates']
            descriptor=descriptors.get(start['file'])
            guards.require(descriptor is not None and 4<=start['position']<=descriptor['size'],'Preserved recovery base has no available coordinate')
            first=guards.log_number(start['file'])
            guards.require(last_deleted<first,
                           'Frozen binlog candidate is required by a preserved recovery base')
        return True
    except (KeyError, TypeError, ValueError) as error:
        raise guards.GuardError('Incomplete preserved hourly dependency') from error


def _plan(inventory, plan, at):
    _time(at)
    evidence_types(plan)
    indexed, source = _index(inventory, at)
    planned = guards.utc(plan['planned_at'])
    if 'cohort' in inventory:
        cohort=inventory['cohort'];guards.hex_id(cohort['sha256'],64);guards.hex_id(cohort['code_sha'],40)
        guards.require(plan.get('cohort')==cohort and guards.utc(cohort['planned_at'])==planned,
                       'Plan frozen cohort differs')
    guards.require(0 <= (at - planned).total_seconds() <= MAX_PLAN_AGE_SECONDS,
                   'Plan stale or clock rollback')
    protocol=plan.get('batch_protocol')
    guards.require(protocol in (None,DAILY_BATCH_PROTOCOL),'Unknown retention batch protocol')
    limit=MAX_INTENT_CANDIDATES if protocol==DAILY_BATCH_PROTOCOL else MAX_CANDIDATES
    calculated = retention.bounded_plan(inventory, retention.inventory_plan(inventory, planned), limit)
    for key in ('anchor_id', 'keep', 'candidates', 'inventory_sha256',
                'pre_window_anchor_present', 'chain_last_file', 'chain_last_position', 'logs'):
        guards.require(plan[key] == calculated[key], 'Plan differs from authenticated inventory')
    keep = plan['keep']; candidates = plan['candidates']
    guards.require(isinstance(candidates, list) and len(candidates) <= limit and
                   len(candidates) == len(set(candidates)) and not set(candidates) & set(keep),
                   'Unbounded or overlapping candidates')
    cutoff = planned - dt.timedelta(days=30)
    anchor = indexed[plan['anchor_id']]
    first_log = guards.log_number(inventory['manifests'][anchor['id']]['coordinates']['file'])
    for sid in candidates:
        guards.hex_id(sid, 64); row = indexed[sid]
        guards.require(guards.utc(row['time']) < cutoff, 'Candidate not expired')
        if row['lane'] == 'base':
            guards.require(guards.utc(row['time']) < guards.utc(anchor['time']),
                           'Candidate is not below anchor')
        else:
            guards.require(inventory['manifests'][sid]['last_log'] < first_log,
                           'Candidate intersects retained anchor chain')
    return indexed, source, planned


def validate_apply(inventory, plan, evidence, at):
    """Pure gate; missing evidence is always BLOCK for nonempty candidates."""
    try:
        indexed, source, planned = _plan(inventory, plan, at)
        required=evidence_types(plan);v2=required==NATIVE_V2_EVIDENCE_TYPES
        guards.require(set(evidence) == required and
                       set(plan['proof_sha256']) == required,
                       'Complete hash-bound evidence required')
        documents = {}
        for name in sorted(required):
            item = evidence[name]; document = item['document']
            expected = guards.hex_id(plan['proof_sha256'][name], 64)
            guards.require(isinstance(document, dict) and item['sha256'] == expected and
                           document_digest(document) == expected, 'Receipt content hash differs')
            if v2 and name=='budget':
                _commissioning_budget(document,inventory,source,at);documents[name]=document;continue
            guards.require(document['result'] == 'PASS' and document['evidence_type'] == name,
                           'Native completed evidence type/result differs')
            if name == 'tip':
                guards.require(document.get('profile') == 'tip' and
                               document.get('additional_order_operation_present') is True and
                               document.get('later_order_operation_excluded') is False,
                               'Named tip prerequisite requires completed exact-tip presence proof')
            for key, value in [('generation', inventory['generation']),
                               ('repositories', inventory['repositories']), ('source', source),
                               ('inventory_sha256', plan['inventory_sha256'])]:
                guards.require(document[key] == value, 'Evidence inventory/source binding differs')
            if 'cohort' in inventory:
                guards.require(document.get('cohort')==inventory['cohort'] and document.get('code_sha')==inventory['cohort']['code_sha'],
                               'Evidence frozen cohort/version differs')
            started = guards.utc(document['started_at']); completed = guards.utc(document['completed_at'])
            guards.require(started <= completed <= at and completed >= at - dt.timedelta(seconds=MAX_PLAN_AGE_SECONDS),
                           'Evidence clock window differs')
            documents[name] = document
        audit = documents['audit']
        audit_mode=audit['check_mode']
        if v2 and audit_mode=='weekly-read-data-and-verified-admissions':
            import integrity
            integrity.validate_report(audit['full_remote_integrity'],inventory,at)
        else:guards.require(audit_mode=='read-data','Complete native remote byte audit absent')
        guards.require(audit['checked_repositories'] == inventory['repositories'] and
                       audit['binlog_check_mode'] == 'native-checksum' and
                       audit['readback_snapshots'] == {sid: row['manifest_sha256'] for sid, row in indexed.items()} and
                       audit['verified_binlogs'] == plan['logs'], 'Complete native byte/checksum audit absent')
        stop = {'file': plan['chain_last_file'], 'position': plan['chain_last_position']}
        bases = [row for row in indexed.values() if row['lane'] == 'base']
        tip = max(bases, key=lambda row: (guards.utc(row['time']), row['id']))
        for name, sid in [('anchor', plan['anchor_id']), ('tip', tip['id'])]:
            document = documents[name]
            guards.require(document['stop'] == stop and document['started_from'] ==
                           'private encrypted S3-B base+binlogs; original source reads=0',
                           'Recovery is not native or does not reach exact archived tip')
            retention.bind_recovery(inventory, {**plan, 'anchor_id': sid}, document)
        if v2:
            guards.require(plan['pre_window_anchor_present'] is True,'Retained pre-window anchor absent')
        else:
            history = documents['history']
            guards.require(plan['pre_window_anchor_present'] is True and
                           guards.utc(history['observed_from']) <= planned - dt.timedelta(days=30) and
                           guards.utc(history['observed_until']) == planned and
                           history['observation_source'] == 'native-confirmed-upload-journal',
                           'Real 30-day observation and pre-window anchor absent')
            guards.hex_id(history['journal_sha256'], 64)
        owner = documents['owner']
        if owner.get('integrity_check_mode')=='weekly-read-data-and-verified-admissions':
            guards.require(v2,'Legacy owner requires direct remote verification')
            import integrity
            integrity.validate_report(owner['full_remote_integrity'],inventory,at)
        guards.require(all(isinstance(owner[k], str) and owner[k].strip() for k in
                           ('machine_id', 'source_machine_id', 'medium_id')) and
                       owner['machine_id'] != owner['source_machine_id'] and
                       owner['origin'] in ('independent-physical-medium','separately-stored-encrypted-kit') and
                       owner['restore_method'] == 'full-native-database-media' and
                       owner.get('executed_by') == 'owner' and
                       owner.get('bundle_storage_separate') is True and owner.get('password_storage_separate') is True,
                       'Independent full owner restore absent')
        for key in ('recovery_bundle_sha256', 'restore_receipt_sha256'):
            guards.hex_id(owner[key], 64)
        if not v2:
            budget = documents['budget']
            for key in ('provider_usage_sha256', 'account_billing_sha256', 'tariff_sha256'):
                guards.hex_id(budget[key], 64)
            guards.require(guards.utc(budget['measurement_from']) < guards.utc(budget['measurement_until']) <=
                           guards.utc(budget['completed_at']), 'Measured provider interval absent')
            requests = budget['measured_requests']
            guards.require(isinstance(requests, dict) and set(requests) == {'PUT', 'GET', 'DELETE'} and
                           all(type(value) is int and value >= 0 for value in requests.values()),
                           'Measured provider request counters absent')
            guards.require(type(budget['measured_egress_bytes']) is int and budget['measured_egress_bytes'] >= 0,
                           'Measured provider egress absent')
            cost = budget['projected_monthly_rub']; size = budget['projected_storage_bytes']
            guards.require(type(cost) in (int, float) and 0 <= cost <= 500 and
                           type(size) is int and 0 <= size <= 10 * 1024 ** 3,
                           'Account budget projection exceeds agreed limits or unknown')
        return {**({'cohort':copy.deepcopy(inventory['cohort'])} if 'cohort' in inventory else {}),
                **({'readiness_policy':NATIVE_V2_POLICY} if v2 else {}),
                'generation': inventory['generation'], 'repositories': copy.deepcopy(inventory['repositories']),
                'inventory_sha256': plan['inventory_sha256'], 'candidate_ids': list(plan['candidates']),
                'keep_ids': list(plan['keep']), 'anchor_id': plan['anchor_id'],
                'proof_sha256': copy.deepcopy(plan['proof_sha256']), 'source': copy.deepcopy(source)}
    except (KeyError, TypeError, ValueError, StopIteration) as error:
        raise guards.GuardError('Incomplete native apply prerequisites') from error


def current_freshness(plan,evidence,at):
    """Constant-size final clock gate, after all potentially expensive checks."""
    planned=guards.utc(plan['planned_at'])
    guards.require(planned<=at and (at-planned).total_seconds()<=MAX_PLAN_AGE_SECONDS,
                   'Plan expired immediately before effect')
    required=evidence_types(plan)
    guards.require(set(evidence)==required,'Complete native evidence required before effect')
    for name in required:
        document=evidence[name]['document']
        if required==NATIVE_V2_EVIDENCE_TYPES and name=='budget':
            _forecast_clock(document,at);continue
        started=guards.utc(document['started_at']);completed=guards.utc(document['completed_at'])
        guards.require(started<=completed<=at and (at-completed).total_seconds()<=MAX_PLAN_AGE_SECONDS,
                       'Proof expired immediately before effect')


def command_batches(inventory,candidates):
    """One frozen schedule: hourly before full, binlogs in original order."""
    selected=set(candidates);rows=inventory['snapshots'];manifests=inventory['manifests'];result=[]
    for lane in ('base','binlog'):
        ordered=sorted((row for row in rows if row['id'] in selected and row['lane']==lane),
                       key=(lambda row:(row['kind']!='hourly',guards.utc(row['time']),row['id'])) if lane=='base' else
                           (lambda row:manifests[row['id']]['first_log']))
        for start in range(0,len(ordered),MAX_FORGET_IDS):
            result.append({'index':len(result),'lane':lane,'candidate_ids':sorted(row['id'] for row in ordered[start:start+MAX_FORGET_IDS])})
    return result or [{'index':0,'lane':'no-op','candidate_ids':[]}]

def intent_batches(intent):
    """Validate the immutable bounded schedule before any phase/effect use."""
    guards.require(intent.get('phase_protocol')==BATCH_PHASE_PROTOCOL,'Batch intent protocol required')
    candidates=intent['candidate_ids'];batches=intent['batches'];indexed={row['id']:row for row in intent['before_inventory']['snapshots']}
    guards.require(candidates==sorted(set(candidates)) and len(candidates)<=MAX_INTENT_CANDIDATES and isinstance(batches,list) and 1<=len(batches)<=8,'Daily intent bound differs')
    seen=set();binlog_seen=False
    for index,batch in enumerate(batches):
        guards.require(set(batch)=={'index','lane','candidate_ids'} and type(batch['index']) is int and batch['index']==index,'Batch index/schema differs')
        lane=batch['lane'];ids=batch['candidate_ids']
        guards.require(lane in ('base','binlog','no-op') and ids==sorted(set(ids)) and len(ids)<=MAX_FORGET_IDS and not seen.intersection(ids),'Command bound or duplicate identity differs')
        guards.require((lane=='no-op' and not candidates and batches==[{'index':0,'lane':'no-op','candidate_ids':[]}]) or
                       (lane!='no-op' and ids and all(sid in indexed and indexed[sid]['lane']==lane for sid in ids)),'Batch identity/lane differs')
        guards.require(not (binlog_seen and lane=='base'),'Base batch follows binlog retirement')
        binlog_seen=binlog_seen or lane=='binlog';seen.update(ids)
    guards.require(seen==set(candidates),'Batch partition differs from frozen intent');return batches

class Executor:
    """Injected runner(lane, argv) must raise on nonzero or ambiguous exit.

    Store.load()/prepare() and receipt_writer are a protected durability contract.
    Callers must not clear an intent to retry. Reconcile writes observed exact
    absence/presence; a partial receipt never authorizes retry or tombstones.
    """
    def __init__(self, inventory_reader, runner, intent_store, receipt_writer, repository_paths, clock=None, *, effect_section=None, pre_effect=None, phase_section=None, pre_phase=None):
        self.read_inventory = inventory_reader
        self.runner = runner
        self.store = intent_store
        self.write_receipt = receipt_writer
        self.repositories = dict(repository_paths)
        self.clock = clock
        self.effect_section=effect_section;self.pre_effect=pre_effect
        self.phase_section=phase_section;self.pre_phase=pre_phase
        guards.require(set(self.repositories) == {'base', 'binlog'} and
                       all(isinstance(v, str) and v and not v.startswith('-') for v in self.repositories.values()),
                       'Explicit repository paths required')

    def _now(self, previous):
        value = _time(self.clock()) if self.clock is not None else _time(previous)
        guards.require(value >= previous, 'Clock rollback during apply')
        return value

    def _intent(self):
        intent = self.store.load()
        if intent is not None:
            body = {key: value for key, value in intent.items() if key != 'intent_sha256'}
            guards.require(document_digest(body) == intent['intent_sha256'], 'Durable intent altered')
            guards.require(intent['operation'] == 'native-retention-forget' and
                           intent['repository_paths'] == self.repositories, 'Foreign retention intent')
        return intent

    def _observe(self, intent, at):
        try:
            after = self.read_inventory()
            return self._observation(intent,after,at)
        except Exception as error:
            return {'forgotten_ids': None, 'present_candidate_ids': None,
                    'protected_arrival_ids': [], 'post_inventory_sha256': None,
                    'observation_error': type(error).__name__}

    def _observation(self,intent,after,at):
        allowed=intent['candidate_ids']
        if intent.get('phase_protocol') in ('bounded-lanes-v1',BATCH_PHASE_PROTOCOL):allowed=self.store.attempted_ids()
        comparison=compatible_inventory(intent['before_inventory'],after,at,allowed)
        protected_dependencies(after,intent['candidate_ids'],at)
        absent=sorted(set(intent['candidate_ids'])-{row['id'] for row in after['snapshots']})
        return {'forgotten_ids':absent,'present_candidate_ids':sorted(set(intent['candidate_ids'])-set(absent)),
                'protected_arrival_ids':sorted(set(intent['protected_arrival_ids'])|set(comparison['arrival_ids'])),
                'post_inventory_sha256':retention.inventory_digest(after),'observation_error':None}

    def _receipt_value(self, intent, status, at, calls, observed, error=None):
        receipt = {key: copy.deepcopy(intent[key]) for key in
                   ('token', 'generation', 'repositories', 'inventory_sha256', 'candidate_ids',
                    'keep_ids', 'anchor_id', 'proof_sha256', 'source', 'intent_sha256')}
        receipt.update({'operation': 'native-retention-forget', 'result': status,
                        'remote_delete_calls': calls, 'prune_run': False,
                        'error_type': error, 'completed_at': at.isoformat(), **observed})
        if 'cohort' in intent:receipt['cohort']=copy.deepcopy(intent['cohort'])
        if 'readiness_policy' in intent:receipt['readiness_policy']=intent['readiness_policy']
        if intent.get('phase_protocol') in ('bounded-lanes-v1',BATCH_PHASE_PROTOCOL):receipt['phase_witnesses']=self.store.phase_refs()
        return receipt

    def _receipt(self,intent,status,at,calls,observed,error=None):
        receipt=self._receipt_value(intent,status,at,calls,observed,error)
        self.write_receipt(copy.deepcopy(receipt))
        return receipt

    def apply(self, inventory, plan, evidence, at):
        at = self._now(_time(at))
        if plan.get('batch_protocol')==DAILY_BATCH_PROTOCOL:
            guards.require(self.phase_section is not None and callable(getattr(self.store,'phase',None)),'Daily intent requires protected bounded phases')
        existing = self._intent()
        if existing is not None:
            # No new command even when a prior process died before calling restic.
            return self._receipt(existing, 'RECONCILE_REQUIRED', at, 0, self._observe(existing, at))
        try:
            if plan['candidates']:
                binding = validate_apply(inventory, plan, evidence, at)
            else:
                _, source, _ = _plan(inventory, plan, at)
                binding = {'generation': inventory['generation'], 'repositories': copy.deepcopy(inventory['repositories']),
                           'inventory_sha256': plan['inventory_sha256'], 'candidate_ids': [],
                           'keep_ids': list(plan['keep']), 'anchor_id': plan['anchor_id'],
                           'proof_sha256': {}, 'source': copy.deepcopy(source)}
                if 'cohort' in inventory:binding['cohort']=copy.deepcopy(inventory['cohort'])
                if 'readiness_policy' in plan:binding['readiness_policy']=plan['readiness_policy']
        except (KeyError, TypeError, ValueError) as failure:
            raise guards.GuardError('Incomplete retention plan') from failure
        before = self.read_inventory()
        at = self._now(at)
        if plan['candidates']:
            validate_apply(inventory, plan, evidence, at)
        else:
            _plan(inventory, plan, at)
        if self.phase_section is not None:return self._phased(inventory,plan,evidence,binding,before,at)
        # All complete proof validation is outside native upload lane locks.
        if self.effect_section is not None and plan['candidates']:
            validate_apply(inventory,plan,evidence,at)
            at=self._now(at)
        with self.effect_section() if self.effect_section is not None else contextlib.nullcontext():
            if self.effect_section is not None:
                before=self.read_inventory();at=self._now(at)
            if self.pre_effect is not None:self.pre_effect(before)
            return self._effect(inventory,plan,evidence,binding,before,at)

    def _effect(self,inventory,plan,evidence,binding,before,at):
        comparison = compatible_inventory(inventory, before, at)
        protected_dependencies(before, binding['candidate_ids'], at)
        at=self._now(at)
        if plan['candidates']:current_freshness(plan,evidence,at)
        else:_plan(inventory,plan,at)
        body = {**binding, 'operation': 'native-retention-forget', 'token': uuid.uuid4().hex,
                'prepared_at': at.isoformat(), 'before_inventory': compact_authenticated_inventory(before, at),
                'before_inventory_sha256':retention.inventory_digest(before),
                'protected_arrival_ids': comparison['arrival_ids'],
                'repository_paths': self.repositories}
        intent = {**body, 'intent_sha256': document_digest(body)}
        self.store.prepare(copy.deepcopy(intent))
        guards.require(self._intent() == intent, 'Durable intent readback differs')
        calls = 0; error = None; removed = set()
        for lane in ('base', 'binlog'):
            candidates = sorted(sid for sid in intent['candidate_ids']
                                if next(row for row in before['snapshots'] if row['id'] == sid)['lane'] == lane)
            if not candidates:
                continue
            try:
                # Reauthenticate immediately before EACH lane effect. New uploads
                # are protected; candidate identities are frozen in durable intent.
                at = self._now(at)
                guards.require((at - guards.utc(plan['planned_at'])).total_seconds() <= MAX_PLAN_AGE_SECONDS,
                               'Plan expired before lane command')
                # The fresh entry observation under protected upload/job
                # locks already authorized the intent and first lane. Each
                # later fresh observation both confirms the prior exact
                # effect and authorizes the next lane; no duplicate full scan.
                if self.effect_section is not None and calls==0:current=before
                else:
                    current = self.read_inventory();at = self._now(at)
                    comparison=compatible_inventory(before, current, at, removed)
                    guards.require(comparison['absent_ids']==sorted(removed),'Partial or unexpected prior forget effect')
                    protected_dependencies(current, intent['candidate_ids'], at)
                # A slow read (or dependency check) must never turn a fresh
                # pre-read proof into permission for a later expired effect.
                at = self._now(at)
                if self.effect_section is None:validate_apply(inventory, plan, evidence, at)
                at = self._now(at)
                current_freshness(plan,evidence,at)
                calls += 1
                result = self.runner(lane, ['--repo', self.repositories[lane], 'forget', *candidates])
                guards.require(result is None or isinstance(result, bytes), 'Runner must raise on nonzero/ambiguous exit')
                removed.update(candidates)
                at = self._now(at)
                if self.effect_section is None:
                    observed = self._observe(intent, at)
                    guards.require(observed['forgotten_ids'] == sorted(removed),
                                   'Partial or unexpected forget effect')
            except Exception as failure:
                error = type(failure).__name__
                break
        observed = self._observe(intent, at)
        status = 'APPLIED' if error is None and observed['forgotten_ids'] == intent['candidate_ids'] else 'RECONCILE_REQUIRED'
        if not intent['candidate_ids']:
            status = 'NOOP' if observed['forgotten_ids'] is not None else 'RECONCILE_REQUIRED'
            observed['history_coverage_accepted'] = False
        return self._receipt(intent, status, at, calls, observed, error)

    def _publish_phased(self,intent,receipt,at):
        try:
            if callable(getattr(self.write_receipt,'stage',None)):self.write_receipt.stage(receipt)
            with self.phase_section('publication'):
                current=self.read_inventory();at=self._now(at);observed=self._observation(intent,current,at)
                guards.require(observed['post_inventory_sha256']==receipt['post_inventory_sha256'] and
                               observed['forgotten_ids']==receipt['forgotten_ids'],'Final staged native observation changed')
                if self.pre_phase is not None:self.pre_phase(current,intent,observed['forgotten_ids'])
                self.write_receipt(copy.deepcopy(receipt))
            return receipt
        except Exception as failure:
            # A partial promotion remains quarantined. Failure receipt bytes
            # and cleanup are persisted only after every upload lock released.
            receipt={**receipt,'result':'RECONCILE_REQUIRED','error_type':type(failure).__name__}
            self.write_receipt(copy.deepcopy(receipt));return receipt

    def _phased(self,inventory,plan,evidence,binding,before,at):
        comparison=compatible_inventory(inventory,before,at);protected_dependencies(before,binding['candidate_ids'],at)
        body={**binding,'operation':'native-retention-forget','token':uuid.uuid4().hex,'prepared_at':at.isoformat(),
              'before_inventory':compact_authenticated_inventory(before,at),'before_inventory_sha256':retention.inventory_digest(before),
              'protected_arrival_ids':comparison['arrival_ids'],'repository_paths':self.repositories}
        daily=plan.get('batch_protocol')==DAILY_BATCH_PROTOCOL
        if callable(getattr(self.store,'phase',None)):
            body['phase_protocol']=BATCH_PHASE_PROTOCOL if daily else 'bounded-lanes-v1'
            if daily:body['batches']=command_batches(before,binding['candidate_ids'])
        intent={**body,'intent_sha256':document_digest(body)}
        if callable(getattr(self.store,'stage',None)):self.store.stage(intent)
        selected=set(intent['candidate_ids'])
        lane_ids={} if daily else {lane:sorted(row['id'] for row in before['snapshots'] if row['lane']==lane and row['id'] in selected) for lane in ('base','binlog')}
        phases=[(batch['lane'],batch['candidate_ids']) for batch in intent_batches(intent)] if daily else ([(lane,ids) for lane,ids in lane_ids.items() if ids] or [('no-op',[])])
        removed=set();calls=0;error=None;promoted=False
        for index,(lane,ids) in enumerate(phases):
            try:
                with self.phase_section(lane):
                    current=self.read_inventory();at=self._now(at)
                    compared=compatible_inventory(before,current,at,removed)
                    guards.require(compared['absent_ids']==sorted(removed),'Prior exact lane absence differs')
                    protected_dependencies(current,intent['candidate_ids'],at)
                    if self.pre_phase is not None:self.pre_phase(current,intent,sorted(removed))
                    at=self._now(at)
                    if ids:current_freshness(plan,evidence,at)
                    else:_plan(inventory,plan,at)
                    phase_document=self.store.phase_document(lane,current,sorted(removed),at,index=index) if daily else (self.store.phase_document(lane,current,sorted(removed),at) if callable(getattr(self.store,'phase',None)) else None)
                    if not promoted:
                        self.store.prepare(intent);promoted=True
                        guards.require(self._intent()==intent,'Durable phased intent readback differs')
                    if phase_document is not None:self.store.phase(phase_document)
                    at=self._now(at)
                    if ids:
                        current_freshness(plan,evidence,at);calls+=1
                        result=self.runner(lane,['--repo',self.repositories[lane],'forget',*ids])
                        guards.require(result is None or isinstance(result,bytes),'Runner must raise on uncertain result')
                        removed.update(ids)
            except Exception as failure:
                if not promoted:raise
                error=type(failure).__name__;break
        at=self._now(at);observed=self._observe(intent,at)
        status='APPLIED' if error is None and observed['forgotten_ids']==intent['candidate_ids'] else 'RECONCILE_REQUIRED'
        if not intent['candidate_ids']:
            status='NOOP' if observed['forgotten_ids'] is not None else 'RECONCILE_REQUIRED';observed['history_coverage_accepted']=False
        receipt=self._receipt_value(intent,status,at,calls,observed,error)
        if status=='RECONCILE_REQUIRED':self.write_receipt(copy.deepcopy(receipt));return receipt
        return self._publish_phased(intent,receipt,at)

    def reconcile(self, at):
        """Explicit root operation: read only, never repeats a forget command."""
        _time(at); intent = self._intent()
        guards.require(intent is not None, 'No durable retention intent to reconcile')
        observed = self._observe(intent, at)
        status = 'RECONCILED' if observed['forgotten_ids'] is not None else 'RECONCILE_REQUIRED'
        if self.phase_section is not None:
            receipt=self._receipt_value(intent,status,at,0,observed)
            if status=='RECONCILE_REQUIRED':self.write_receipt(copy.deepcopy(receipt));return receipt
            return self._publish_phased(intent,receipt,at)
        return self._receipt(intent, status, at, 0, observed)


def retention_tombstones(intent, receipt):
    """Derive exact acknowledged absences for a protected confirmed journal.

    Integration must atomically add these records to the appropriate lane's
    journal without rewriting confirmed upload rows. Native inventory audits
    accept a confirmed-but-absent ID ONLY with this bound durable receipt; a
    missing candidate with RECONCILE_REQUIRED remains unknown. A retained binlog
    suffix needs its original first_log/previous_count validated against forgotten
    manifests from the intent, not reset to a fabricated zero prefix.
    """
    try:
        body = {key: value for key, value in intent.items() if key != 'intent_sha256'}
        guards.require(document_digest(body) == intent['intent_sha256'], 'Intent hash differs')
        guards.require(receipt['result'] in ('APPLIED', 'RECONCILED') and
                       receipt['operation'] == 'native-retention-forget' and
                       receipt['observation_error'] is None, 'Explicit successful absence receipt required')
        for key in ('token', 'generation', 'repositories', 'inventory_sha256', 'candidate_ids',
                    'keep_ids', 'anchor_id', 'proof_sha256', 'source', 'intent_sha256'):
            guards.require(receipt[key] == intent[key], 'Absence receipt binding differs')
        if 'cohort' in intent:guards.require(receipt.get('cohort')==intent['cohort'],'Absence cohort binding differs')
        absent = receipt['forgotten_ids']; present = receipt['present_candidate_ids']
        guards.require(isinstance(absent, list) and absent == sorted(set(absent)) and
                       set(absent) <= set(intent['candidate_ids']) and
                       present == sorted(set(intent['candidate_ids']) - set(absent)),
                       'Absence receipt identity sets differ')
        guards.require(receipt['result'] != 'APPLIED' or not present, 'Incomplete applied receipt')
        guards.hex_id(receipt['post_inventory_sha256'], 64)
        completed = guards.utc(receipt['completed_at'])
        guards.require(completed >= guards.utc(intent['prepared_at']), 'Absence receipt clock rollback')
        indexed, _ = _index(intent['before_inventory'], completed)
        receipt_sha = document_digest(receipt)
        return [{**{key: indexed[sid][key] for key in ('id', 'lane', 'token', 'manifest_sha256', 'generation')},
                 'forgotten_at': receipt['completed_at'], 'intent_sha256': intent['intent_sha256'],
                 'receipt_sha256': receipt_sha, 'pre_inventory_sha256': intent['inventory_sha256'],
                 'post_inventory_sha256': receipt['post_inventory_sha256']} for sid in absent]
    except (KeyError, TypeError, ValueError) as error:
        raise guards.GuardError('Incomplete retention tombstone binding') from error
