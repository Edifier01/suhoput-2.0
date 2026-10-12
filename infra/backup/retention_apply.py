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
import datetime as dt
import hashlib
import json
import uuid

import guards
import retention

EVIDENCE_TYPES = frozenset(('audit', 'anchor', 'tip', 'owner', 'budget', 'history'))
MAX_PLAN_AGE_SECONDS = 900
MAX_CANDIDATES = 256


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
        return True
    except (KeyError, TypeError, ValueError) as error:
        raise guards.GuardError('Incomplete preserved hourly dependency') from error


def _plan(inventory, plan, at):
    _time(at)
    indexed, source = _index(inventory, at)
    planned = guards.utc(plan['planned_at'])
    guards.require(0 <= (at - planned).total_seconds() <= MAX_PLAN_AGE_SECONDS,
                   'Plan stale or clock rollback')
    calculated = retention.bounded_plan(inventory, retention.inventory_plan(inventory, planned), MAX_CANDIDATES)
    for key in ('anchor_id', 'keep', 'candidates', 'inventory_sha256',
                'pre_window_anchor_present', 'chain_last_file', 'chain_last_position', 'logs'):
        guards.require(plan[key] == calculated[key], 'Plan differs from authenticated inventory')
    keep = plan['keep']; candidates = plan['candidates']
    guards.require(isinstance(candidates, list) and len(candidates) <= MAX_CANDIDATES and
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
        guards.require(set(evidence) == EVIDENCE_TYPES and
                       set(plan['proof_sha256']) == EVIDENCE_TYPES,
                       'Complete hash-bound evidence required')
        documents = {}
        for name in sorted(EVIDENCE_TYPES):
            item = evidence[name]; document = item['document']
            expected = guards.hex_id(plan['proof_sha256'][name], 64)
            guards.require(isinstance(document, dict) and item['sha256'] == expected and
                           document_digest(document) == expected, 'Receipt content hash differs')
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
            started = guards.utc(document['started_at']); completed = guards.utc(document['completed_at'])
            guards.require(started <= completed <= at and completed >= planned - dt.timedelta(seconds=MAX_PLAN_AGE_SECONDS),
                           'Evidence clock window differs')
            documents[name] = document
        audit = documents['audit']
        guards.require(audit['checked_repositories'] == inventory['repositories'] and
                       audit['check_mode'] == 'read-data' and audit['binlog_check_mode'] == 'native-checksum' and
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
        history = documents['history']
        guards.require(plan['pre_window_anchor_present'] is True and
                       guards.utc(history['observed_from']) <= planned - dt.timedelta(days=30) and
                       guards.utc(history['observed_until']) == planned and
                       history['observation_source'] == 'native-confirmed-upload-journal',
                       'Real 30-day observation and pre-window anchor absent')
        guards.hex_id(history['journal_sha256'], 64)
        owner = documents['owner']
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
        return {'generation': inventory['generation'], 'repositories': copy.deepcopy(inventory['repositories']),
                'inventory_sha256': plan['inventory_sha256'], 'candidate_ids': list(plan['candidates']),
                'keep_ids': list(plan['keep']), 'anchor_id': plan['anchor_id'],
                'proof_sha256': copy.deepcopy(plan['proof_sha256']), 'source': copy.deepcopy(source)}
    except (KeyError, TypeError, ValueError, StopIteration) as error:
        raise guards.GuardError('Incomplete native apply prerequisites') from error


class Executor:
    """Injected runner(lane, argv) must raise on nonzero or ambiguous exit.

    Store.load()/prepare() and receipt_writer are a protected durability contract.
    Callers must not clear an intent to retry. Reconcile writes observed exact
    absence/presence; a partial receipt never authorizes retry or tombstones.
    """
    def __init__(self, inventory_reader, runner, intent_store, receipt_writer, repository_paths, clock=None):
        self.read_inventory = inventory_reader
        self.runner = runner
        self.store = intent_store
        self.write_receipt = receipt_writer
        self.repositories = dict(repository_paths)
        self.clock = clock
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
            comparison = compatible_inventory(intent['before_inventory'], after, at, intent['candidate_ids'])
            protected_dependencies(after, intent['candidate_ids'], at)
            absent = sorted(set(intent['candidate_ids']) - {row['id'] for row in after['snapshots']})
            return {'forgotten_ids': absent,
                    'present_candidate_ids': sorted(set(intent['candidate_ids']) - set(absent)),
                    'protected_arrival_ids': sorted(set(intent['protected_arrival_ids']) | set(comparison['arrival_ids'])),
                    'post_inventory_sha256': retention.inventory_digest(after), 'observation_error': None}
        except Exception as error:
            return {'forgotten_ids': None, 'present_candidate_ids': None,
                    'protected_arrival_ids': [], 'post_inventory_sha256': None,
                    'observation_error': type(error).__name__}

    def _receipt(self, intent, status, at, calls, observed, error=None):
        receipt = {key: copy.deepcopy(intent[key]) for key in
                   ('token', 'generation', 'repositories', 'inventory_sha256', 'candidate_ids',
                    'keep_ids', 'anchor_id', 'proof_sha256', 'source', 'intent_sha256')}
        receipt.update({'operation': 'native-retention-forget', 'result': status,
                        'remote_delete_calls': calls, 'prune_run': False,
                        'error_type': error, 'completed_at': at.isoformat(), **observed})
        self.write_receipt(copy.deepcopy(receipt))
        return receipt

    def apply(self, inventory, plan, evidence, at):
        at = self._now(_time(at))
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
        except (KeyError, TypeError, ValueError) as failure:
            raise guards.GuardError('Incomplete retention plan') from failure
        before = self.read_inventory()
        comparison = compatible_inventory(inventory, before, at)
        protected_dependencies(before, binding['candidate_ids'], at)
        body = {**binding, 'operation': 'native-retention-forget', 'token': uuid.uuid4().hex,
                'prepared_at': at.isoformat(), 'before_inventory': compact_authenticated_inventory(before, at),
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
                current = self.read_inventory()
                compatible_inventory(before, current, at, removed)
                protected_dependencies(current, intent['candidate_ids'], at)
                calls += 1
                result = self.runner(lane, ['--repo', self.repositories[lane], 'forget', *candidates])
                guards.require(result is None or isinstance(result, bytes), 'Runner must raise on nonzero/ambiguous exit')
                removed.update(candidates)
                at = self._now(at)
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

    def reconcile(self, at):
        """Explicit root operation: read only, never repeats a forget command."""
        _time(at); intent = self._intent()
        guards.require(intent is not None, 'No durable retention intent to reconcile')
        observed = self._observe(intent, at)
        status = 'RECONCILED' if observed['forgotten_ids'] is not None else 'RECONCILE_REQUIRED'
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
