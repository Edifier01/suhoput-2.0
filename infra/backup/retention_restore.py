"""Isolated operational restore of a frozen native-v2 retention cohort.

This producer proves actual SQL import/replay and stable restored state. Historical
after-base engine controls and independent owner recovery remain separate proofs.
No source database reads, target replacement, automatic SQL retry or deletion.
"""
import datetime as dt
import copy
import hashlib
import json
import os
import pathlib
import re
import secrets
import stat
import time
import uuid
import xml.etree.ElementTree as ET

import backup_catalog
import binlog
import dump_records
import guards
import integrity
import retention
import retention_cohort
import runtime
from restore import Recovery, replay_range
from restic_adapter import verify_restored_tree
from worker import DB_IMAGE, Worker, NativeError, now, private_path, sha, tree_inventory, verify_payload

FORMAT = 'native-retention-restore-plan-v1'
OPERATION = 'native-retention-restore-v1'
STARTED_FROM = 'private encrypted S3-B base+full; sealed verified catalog binlogs; original source reads=0'


def metadata_cache_preflight(worker, repository_id):
    """Prove warm base metadata without hydrating, repairing or admitting cache.

    Manual calibration can call this before initial commissioning. Once either
    protected budget artifact exists, its real authenticated loader must pass
    before any paid LIST/native read. No proof flag persists beyond this call.
    """
    import budget, storage
    w = worker; receipts = w.root / 'receipts'
    budget_paths = [receipts / name for name in ('commissioning-budget.json', 'commissioning-budget.origin.json')]
    if w.c.get('retention_readiness_policy') == 'native-v2' and any(path.exists() or path.is_symlink() for path in budget_paths):
        budget.load_commissioning_budget(w)
    started = dt.datetime.now(dt.timezone.utc); deadline = time.monotonic() + 180
    try:
        repository_id = guards.hex_id(repository_id, 64)
        initialization = runtime.load_json(private_path(receipts / 'init-base.json'))
        guards.require(initialization['repository_id'] == repository_id and initialization['generation'] == w.c['generation'],
                       'Metadata cache repository initialization differs')
        repo = guards.repository_url(w.c['endpoint'], w.c['bucket'], 'base')
        guards.require(w.c['repositories']['base'] == repo, 'Metadata cache repository namespace differs')
        cache = w.root / 'cache' / 'base' / repository_id
        def check_directories(path):
            guards.require(path.is_absolute() and '..' not in path.parts, 'Canonical metadata cache path required')
            for parent in [*reversed(path.parents), path]:
                info = parent.lstat()
                guards.require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not parent.is_symlink(),
                               'Metadata cache directory owner/type/symlink differs')
        check_directories(cache)
        guards.require(private_path(cache / 'version').read_bytes() == b'1', 'Metadata cache version differs')

        def listing():
            indexes = {}; packs = {}; keys = {}; count = 0
            read = storage.S3Reader(w, min(40, max(0, deadline - time.monotonic())))
            prefix = storage.PREFIX + 'base/'
            def observed(query):
                nonlocal count
                guards.require(count < 8 and time.monotonic() < deadline, 'Metadata cache listing request bound exceeded')
                count += 1; raw = read(query)
                guards.require(isinstance(raw, bytes) and len(raw) <= storage.MAX_XML and b'<!' not in raw, 'Bounded plain metadata listing XML required')
                tree = ET.fromstring(raw)
                for node in tree.iter(): node.tag = node.tag.rsplit('}', 1)[-1]
                for row in tree.findall('Contents'):
                    k = row.findall('Key'); s = row.findall('Size')
                    guards.require(len(k) == len(s) == 1 and isinstance(k[0].text, str) and isinstance(s[0].text, str) and
                                   s[0].text.isascii() and s[0].text.isdecimal(), 'Metadata listing fields differ')
                    key = k[0].text; size = int(s[0].text)
                    for kind, output in (('index', indexes), ('data', packs), ('keys', keys)):
                        stem = prefix + kind + '/'
                        if not key.startswith(stem): continue
                        tail = key[len(stem):]; sid = guards.hex_id(tail.split('/')[-1], 64)
                        guards.require(tail == (sid[:2] + '/' + sid if kind == 'data' else sid) and sid not in output,
                                       'Metadata listing object namespace/identity differs')
                        output[sid] = size
                return raw
            proof = storage.list_objects(observed, w.c['bucket'], prefix)
            guards.require(0 < len(indexes) <= 64 and sum(indexes.values()) <= 16 * 1024**2, 'Metadata index count/ciphertext bound exceeded')
            guards.require(len(keys) == 1, 'Metadata cache requires one native unlock key')
            return indexes, packs, keys, proof

        def cached(kind, sid, size):
            guards.require(time.monotonic() < deadline, 'Metadata cache verification deadline exceeded')
            path = cache / kind / sid[:2] / sid; check_directories(path.parent)
            before = path.lstat()
            guards.require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1 and
                           before.st_size == size and 32 < size <= 128 * 1024**2, 'Metadata cache ciphertext file/size differs')
            value = hashlib.sha256()
            fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
            with os.fdopen(fd, 'rb') as stream:
                opened = os.fstat(stream.fileno())
                signature = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink, info.st_uid)
                guards.require(signature(opened) == signature(before), 'Metadata cache ciphertext changed before hash')
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    guards.require(time.monotonic() < deadline, 'Metadata cache verification deadline exceeded'); value.update(block)
                guards.require(signature(os.fstat(stream.fileno())) == signature(before), 'Metadata cache ciphertext changed during hash')
            after = path.lstat(); check_directories(path.parent)
            guards.require(stat.S_ISREG(after.st_mode) and signature(after) == signature(before) and value.hexdigest() == sid,
                           'Metadata cache ciphertext SHA/identity changed')
            return {'id': sid, 'bytes': size, 'sha256': value.hexdigest()}

        indexes, packs, keys, before = listing()
        # Complete every active index check before any native process can load
        # or transparently hydrate an index from a different cache namespace.
        index_seals = [cached('index', sid, size) for sid, size in sorted(indexes.items())]
        guards.require(time.monotonic() < deadline, 'Metadata cache native deadline exceeded')
        config = backup_catalog.decode(w.restic('base', ['--repo', repo, 'cat', 'config'], timeout=min(45, max(0, deadline - time.monotonic()))))
        guards.require(isinstance(config, dict) and config.get('version') == 2 and config.get('id') == repository_id, 'Native metadata cache repository identity differs')
        trees = set(); blobs = 0
        for sid in sorted(indexes):
            guards.require(time.monotonic() < deadline, 'Metadata cache native deadline exceeded')
            raw = w.restic('base', ['--repo', repo, 'cat', 'index', sid], timeout=min(45, deadline - time.monotonic()))
            value = backup_catalog.decode(raw)
            guards.require(isinstance(value, dict) and set(value) == {'packs'} and isinstance(value['packs'], list), 'Native metadata index schema differs')
            seen = set()
            for pack in value['packs']:
                guards.require(isinstance(pack, dict) and set(pack) == {'id', 'blobs'} and isinstance(pack['blobs'], list), 'Native metadata pack schema differs')
                pid = guards.hex_id(pack['id'], 64)
                guards.require(pid not in seen and pid in packs, 'Native metadata pack identity differs'); seen.add(pid)
                for blob in pack['blobs']:
                    guards.require(isinstance(blob, dict) and set(blob) in ({'id', 'type', 'offset', 'length'},
                                   {'id', 'type', 'offset', 'length', 'uncompressed_length'}), 'Native metadata blob schema differs')
                    guards.hex_id(blob['id'], 64)
                    guards.require(blob['type'] in ('data', 'tree') and all(type(blob[k]) is int and 0 <= blob[k] <= 2**32 - 1 for k in ('offset', 'length')) and
                                   blob['length'] > 32 and blob['offset'] + blob['length'] <= packs[pid], 'Native metadata blob type/range differs')
                    if 'uncompressed_length' in blob:
                        guards.require(type(blob['uncompressed_length']) is int and 0 <= blob['uncompressed_length'] <= 2**32 - 1, 'Native metadata blob unpacked length differs')
                    if blob['type'] == 'tree': trees.add(pid)
                    blobs += 1
            cached('index', sid, indexes[sid]); del value, raw
        guards.require(trees, 'Native base metadata tree packs absent')
        tree_seals = [cached('data', sid, packs[sid]) for sid in sorted(trees)]
        after_indexes, after_packs, after_keys, after = listing()
        guards.require(indexes == after_indexes and keys == after_keys and all(after_packs.get(sid) == packs[sid] for sid in trees),
                       'Metadata index/key/tree object listing changed during control')
        for row in index_seals: cached('index', row['id'], row['bytes'])
        for row in tree_seals: cached('data', row['id'], row['bytes'])
        return {'result': 'READ_ONLY_WARM_BASE_METADATA_CONTROL', 'admission': False, 'repository_id': repository_id,
                'source': copy.deepcopy(w.source), 'generation': w.c['generation'], 'code_sha': w.c['code_sha'], 'repository': repo,
                'configuration_sha256': digest({'repository': repo, 'repository_id': repository_id, 'generation': w.c['generation'],
                                               'source': w.source, 'endpoint': w.c['endpoint'], 'bucket': w.c['bucket'], 'code_sha': w.c['code_sha']}),
                'cache_version': 1, 'index_count': len(index_seals), 'index_ciphertext_bytes': sum(row['bytes'] for row in index_seals),
                'active_tree_pack_count': len(tree_seals), 'active_tree_ciphertext_bytes': sum(row['bytes'] for row in tree_seals),
                'typed_blob_entries': blobs, 'index_seals': index_seals, 'tree_pack_seals': tree_seals,
                'before_listing': before, 'after_listing': after, 'started_at': started.isoformat(),
                'completed_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'cache_repair': False, 'restore_calls': 0, 'SQL_calls': 0}
    except guards.GuardError:
        raise
    except (OSError, KeyError, TypeError, ValueError, ET.ParseError) as error:
        raise guards.GuardError('Metadata cache preflight unavailable or malformed; manual calibration required') from error


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def targets(plan):
    guards.require(plan.get('profile') in ('anchor', 'tip'), 'Unknown operational restore profile')
    token = guards.hex_id(plan.get('token'), 32)
    prefix = 'suhoput2-stage-retention-' + plan['profile'] + '-' + token
    return {'control': prefix + '-db', 'volume': prefix + '_db', 'project': prefix}


def validate_plan(plan, inventory, profile):
    try:
        guards.require(set(plan) == {'format', 'profile', 'generation', 'source', 'cohort', 'token', 'base_id', 'full_id', 'stop'} and
                       plan['format'] == FORMAT and plan['profile'] == profile, 'Operational plan fields/profile differ')
        targets(plan)
        guards.require(plan['generation'] == inventory['generation'] and plan['cohort'] == inventory['cohort'], 'Operational plan generation/cohort differs')
        rows = {row['id']: row for row in inventory['snapshots']}
        guards.require(len(rows) == len(inventory['snapshots']), 'Duplicate restore inventory identity')
        for key in ('base_id', 'full_id'):
            sid = guards.hex_id(plan[key], 64)
            guards.require(sid in rows and rows[sid]['lane'] == 'base', 'Foreign restore base identity')
        base = inventory['manifests'][plan['base_id']]; full = inventory['manifests'][plan['full_id']]
        guards.require(base['kind'] in ('hourly', 'full', 'pre-update') and full['kind'] in ('full', 'pre-update') and
                       (base.get('full_id') if base['kind'] == 'hourly' else plan['base_id']) == plan['full_id'], 'Operational full prerequisite differs')
        guards.require(all(base[key] == full[key] for key in ('source', 'generation', 'stage_app_sha', 'application_sha256', 'configuration_sha256')) and
                       base['source'] == plan['source'] and base['generation'] == plan['generation'], 'Operational restore source differs')
        guards.require(set(plan['stop']) == {'file', 'position'} and type(plan['stop']['position']) is int and plan['stop']['position'] >= 4, 'Invalid restore stop')
        guards.log_number(plan['stop']['file'])
        return plan
    except (KeyError, TypeError, ValueError) as error:
        raise guards.GuardError('Malformed operational restore plan') from error


def objects_absent(native, names):
    for kind, name in [('container', names['control']), ('volume', names['volume'])]:
        args = ['docker', kind, 'ls'] + (['--all'] if kind == 'container' else []) + ['--format', '{{json .Names}}' if kind == 'container' else '{{json .Name}}']
        values = [json.loads(line) for line in native.run(args).splitlines() if line.strip()]
        guards.require(all(isinstance(item, str) for item in values) and name not in values, 'Existing operational target; preserve')
    return True


def hydrate_binlogs(reader, inventory, logs, start, stop, target, *, existing=False):
    """Stream independently authenticated files; never import SQL from this helper."""
    guards.require(replay_range(start, stop, logs) == logs, 'Incomplete replay selection')
    owners = {}
    for row in inventory['snapshots']:
        if row['lane'] != 'binlog': continue
        for item in inventory['manifests'][row['id']]['logs']:
            guards.require(item['file'] not in owners, 'Duplicate catalog log owner')
            owners[item['file']] = (row['id'], item)
    target = pathlib.Path(target)
    guards.require(target.is_dir() and not target.is_symlink(), 'Protected replay directory absent')
    guards.require({path.name for path in target.iterdir()} <= {item['file'] for item in logs}, 'Foreign hydrated replay file')
    events = rows = 0; tables = set(); versions = set()
    for item in logs:
        owner = owners.get(item['file'])
        guards.require(owner is not None and owner[1] == item, 'Selected catalog log descriptor missing/different')
        raw = reader.binlog_bytes(owner[0], item['file'])
        first = start if item['file'] == start['file'] else {'file': item['file'], 'position': 4}
        last = stop if item['file'] == stop['file'] else {'file': item['file'], 'position': item['size']}
        checked = binlog.validate_chain({item['file']: raw}, [item], first, last)
        path = target / item['file']
        if existing:
            guards.require(path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1 and
                           path.stat().st_size == len(raw) and sha(path) == item['sha256'], 'Prior hydrated replay bytes differ')
        else:
            with open(path, 'xb') as output: output.write(raw); output.flush(); os.fsync(output.fileno())
            os.chmod(path, 0o600)
        events += checked['event_count']; rows += checked['selected_row_events']
        tables.update(checked['mapped_tables']); versions.update(checked['server_versions'])
    return {'result': 'PASS', 'guard': 'strict-mariadb-10.11-row', 'start': start, 'stop': stop,
            'files': logs, 'event_count': events, 'selected_row_events': rows,
            'mapped_tables': sorted(tables), 'server_versions': sorted(versions)}


def bind_recovery(inventory, plan, proof):
    """Consumer binding; protected origin and fresh cohort are checked separately."""
    try:
        sid = plan['anchor_id']; base = inventory['manifests'][sid]
        indexed = {row['id']: row for row in inventory['snapshots']}; row = indexed[sid]
        full_id = base['full_id'] if row['kind'] == 'hourly' else sid
        guards.require(proof['operation'] == OPERATION and proof['result'] == 'PASS' and proof['profile'] in ('anchor', 'tip') and
                       proof['started_from'] == STARTED_FROM and proof['generation'] == inventory['generation'] and
                       proof['cohort'] == inventory['cohort'] and proof['repositories'] == inventory['repositories'], 'Operational restore scope differs')
        guards.require(proof['base_id'] == sid and proof['base_manifest_sha256'] == row['manifest_sha256'] and
                       proof['full_id'] == full_id and proof['full_manifest_sha256'] == indexed[full_id]['manifest_sha256'] and
                       proof['source'] == base['source'] and proof['stage_app_sha'] == base['stage_app_sha'] and
                       proof['coordinates'] == base['coordinates'], 'Operational restore original base differs')
        stop = {'file': plan['chain_last_file'], 'position': plan['chain_last_position']}
        selected = replay_range(base['coordinates'], stop, plan['logs'])
        guards.require(proof['stop'] == stop and proof['verified_binlogs'] == selected and type(proof['replayed_logs']) is int and
                       proof['replayed_logs'] == len(selected), 'Operational restore replay range differs')
        guards.require(proof['actual_sql_import'] == 'PASS' and proof['native_replay'] == 'PASS' and
                       proof['row_guard']['result'] == 'PASS' and proof['row_guard']['guard'] == 'strict-mariadb-10.11-row' and
                       proof['row_guard']['files'] == selected and proof['row_guard']['start'] == base['coordinates'] and
                       proof['row_guard']['stop'] == stop and isinstance(proof['media']['inventory'], list), 'Operational SQL or media proof absent')
        for key in ('schema_sha256', 'table_rows_sha256', 'replay_sha256', 'base_journal_sha256', 'replay_journal_sha256', 'control_id'):
            guards.hex_id(proof[key], 64)
        guards.hex_id(proof['token'], 32)
        guards.require(proof['control_objects'] == [targets(proof)['control'], targets(proof)['volume']] and
                       proof['source_reads'] == 0 and proof['isolation'] == {'network': 'none', 'event_scheduler': 'OFF', 'skip_networking': True, 'log_bin': False}, 'Operational control isolation differs')
        integrity.validate_report(proof['full_remote_integrity'], inventory, guards.utc(proof['completed_at']))
        return {'base_id': sid, 'manifest_sha256': row['manifest_sha256'], 'stop': stop,
                'replayed_logs': len(selected), 'media_references': len(proof['media']['inventory']), 'SQL_reimport_or_replay': False}
    except (KeyError, TypeError, StopIteration) as error:
        raise guards.GuardError('Incomplete operational recovery binding') from error


class RetentionRecovery(Recovery):
    """Uses only legacy decoder/media helpers, never legacy synthetic controls."""
    def __init__(self, worker, profile='anchor'):
        guards.require(profile in ('anchor', 'tip') and worker.c.get('retention_readiness_policy') == 'native-v2', 'Operational native-v2 restore required')
        self.w = worker; self.profile = profile
        self.plan = runtime.load_json(private_path(worker.root / 'config' / ('retention-restore-' + profile + '.json')))
        names = targets(self.plan)
        self.control = names['control']; self.volume = names['volume']; self.project = names['project']
        self.root = worker.root / 'control-restore' / ('retention-' + profile + '-' + self.plan['token'])
        self.intent = worker.root / 'receipts' / ('retention-restore-' + profile + '-' + self.plan['token'] + '.intent.json')
        self.lock = worker.root / 'receipts' / ('retention-restore-' + profile + '.lock')

    def fresh(self):
        at = guards.utc(now()); planned = guards.utc(self.plan['cohort']['planned_at'])
        guards.require(0 <= (at - planned).total_seconds() <= 900, 'Operational frozen cohort expired')

    def prepare(self, reader):
        current = {}
        self.inventory = retention_cohort.CohortStore(self.w).load(reader, current_out=current)
        validate_plan(self.plan, self.inventory, self.profile); self.fresh()
        guards.require(self.plan['source'] == self.w.source and self.plan['generation'] == self.w.c['generation'], 'Installed restore source differs')
        self.retention_plan = retention.inventory_plan(self.inventory, guards.utc(self.inventory['cohort']['planned_at']))
        expected = self.retention_plan['anchor_id'] if self.profile == 'anchor' else max(
            (row for row in self.inventory['snapshots'] if row['lane'] == 'base'), key=lambda row: (guards.utc(row['time']), row['id']))['id']
        guards.require(self.plan['base_id'] == expected and self.plan['stop'] == {'file': self.retention_plan['chain_last_file'], 'position': self.retention_plan['chain_last_position']}, 'Plan differs from required anchor/tip')
        self.full_remote_integrity = integrity.ensure(self.w, self.inventory, current_inventory=current)
        self.reader = reader

    def snapshot(self, lane, sid, *, existing=False):
        w = self.w; scope = str(w.root / 'spool' / (lane + '-payload'))
        metadata = json.loads(w.restic(lane, ['--repo', w.c['repositories'][lane], 'cat', 'snapshot', sid]))
        native, token, md = backup_catalog.native_identity(metadata, sid, scope, w.c['generation'])
        row = next((item for item in self.inventory['snapshots'] if item['id'] == sid and item['lane'] == lane), None)
        guards.require(row is not None and all(row[key] == value for key, value in
                       [('tree', native['tree']), ('snapshot_time', native['time']), ('token', token), ('manifest_sha256', md)]), 'Native restore identity changed')
        raw = w.restic(lane, ['--repo', w.c['repositories'][lane], 'dump', sid, scope + '/manifest.json'])
        guards.require(hashlib.sha256(raw).hexdigest() == md and raw == self.reader.raw_manifest(sid), 'Native restore original manifest differs')
        manifest = json.loads(raw); target = self.root / 'snapshots' / sid
        guards.require(target.resolve() == target and not target.is_symlink(), 'Operational snapshot path changed')
        if existing: guards.require(target.is_dir(), 'Prior restored snapshot absent')
        else:
            guards.require(not target.exists(), 'Operational snapshot collision')
            w.restic(lane, ['--repo', w.c['repositories'][lane], 'restore', sid, '--target', str(target), '--verify'])
        payload = verify_restored_tree(target, scope, manifest, raw, tree_inventory)
        verify_payload(payload, manifest)
        return manifest, payload, md

    def inputs(self, *, existing=False):
        base, bpath, bmd = self.snapshot('base', self.plan['base_id'], existing=existing)
        full, fpath, fmd = (base, bpath, bmd) if self.plan['base_id'] == self.plan['full_id'] else self.snapshot('base', self.plan['full_id'], existing=existing)
        guards.require(base['stage_app_sha'] == self.w.c['stage_app_sha'] and
                       self.w.captured_identity(fpath) == {key: full[key] for key in ('application_sha256', 'configuration_sha256')}, 'Captured application/configuration differs')
        logs = replay_range(base['coordinates'], self.plan['stop'], self.retention_plan['logs'])
        self.row_guard = hydrate_binlogs(self.reader, self.inventory, logs, base['coordinates'], self.plan['stop'], self.root / 'logs', existing=existing)
        self.base_catalog = dump_records.records((bpath / 'db.sql').read_bytes())
        self.expected_media = runtime.load_json(bpath / 'media.json')['inventory']
        guards.require(self.w.media(bpath / 'uploads', self.base_catalog) == self.expected_media, 'Recovered base media bytes/references differ')
        return base, bpath, bmd, full, fpath, fmd, logs

    def decode(self, logs, start, target):
        # Each archived file ends on a checked transaction boundary. Separate
        # native invocations bound argv; their SQL streams retain exact file order.
        with open(target, 'xb') as output:
            for offset in range(0, len(logs), 1024):
                part = self.root / ('decoded-' + uuid.uuid4().hex + '.sql')
                batch = logs[offset:offset + 1024]
                self.decoder(batch, part, start=start['position'] if offset == 0 else None,
                             stop=self.plan['stop']['position'] if offset + len(batch) == len(logs) else None)
                guards.require(output.tell() + part.stat().st_size <= 256 * 1024 * 1024, 'Operational decoded SQL exceeds bound')
                with open(part, 'rb') as source:
                    while chunk := source.read(1024 * 1024): output.write(chunk)
            output.flush(); os.fsync(output.fileno())
        os.chmod(target, 0o600)

    def sql(self, query):
        return self.w.sql(query, container=self.control)

    def inspect_control(self, expected_id=None):
        row = json.loads(self.w.native.run(['docker', 'inspect', self.control]))[0]
        volume = json.loads(self.w.native.run(['docker', 'volume', 'inspect', self.volume]))[0]
        labels = {'task047.generation': self.w.c['generation'], 'task047.restore-token': self.plan['token']}
        guards.require((expected_id is None or row['Id'] == expected_id) and row['Name'] == '/' + self.control and
                       row['Config']['Image'] == DB_IMAGE and all(row['Config']['Labels'].get(k) == v for k, v in labels.items()) and
                       row['HostConfig']['NetworkMode'] == 'none' and all(not ports for ports in row['NetworkSettings']['Ports'].values()), 'Unknown operational container identity/isolation')
        guards.require(volume['Name'] == self.volume and all(volume['Labels'].get(k) == v for k, v in labels.items()) and
                       any(m.get('Name') == self.volume and m.get('Destination') == '/var/lib/mysql' and m.get('Type') == 'volume' for m in row['Mounts']) and
                       any(m.get('Source') == str(self.root / 'socket') and m.get('Destination') == '/run/mysqld' and m.get('Type') == 'bind' for m in row['Mounts']), 'Unknown operational volume/socket identity')
        guards.hex_id(row['Id'], 64)
        return row

    def ready(self):
        for attempt in range(100):
            try:
                if self.sql('SELECT 1;').strip() == b'1': break
            except NativeError: pass
            time.sleep(.2)
        else: raise guards.GuardError('Operational DB did not start; preserved')
        guards.require(self.sql('SELECT @@event_scheduler,@@skip_networking,@@log_bin;').strip() == b'OFF\t1\t0', 'Unsafe operational DB runtime')

    def state(self):
        body = self.sql("SELECT TABLE_NAME,ENGINE,TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA='suhoput2_stage' ORDER BY TABLE_NAME; SELECT 'COLUMN',TABLE_NAME,COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='suhoput2_stage' ORDER BY TABLE_NAME,ORDINAL_POSITION;")
        tables = set(); columns = {}
        for line in body.decode().splitlines():
            fields = line.split('\t')
            if fields[0] == 'COLUMN':
                guards.require(len(fields) == 3, 'Malformed restored column'); columns.setdefault(fields[1], []).append(fields[2])
            else:
                guards.require(len(fields) == 3 and fields[1:] == ['InnoDB', 'BASE TABLE'] and re.fullmatch(r'[A-Za-z0-9_]+', fields[0]), 'Unknown restored table')
                tables.add(fields[0])
        guards.require(tables and tables == set(columns) and columns == self.base_catalog['catalog'], 'Restored schema catalog differs from authenticated base')
        counts = {}
        for table in sorted(tables):
            value = self.sql('SELECT COUNT(*) FROM suhoput2_stage.`' + table + '`;').strip()
            guards.require(re.fullmatch(rb'[0-9]+', value) is not None, 'Unknown restored row count'); counts[table] = int(value)
        args = ['docker', 'exec', self.control, 'sh', '-c', 'MYSQL_PWD="$MARIADB_ROOT_PASSWORD" exec mariadb-dump -uroot "$@"', 'sh',
                '--single-transaction', '--skip-comments', '--skip-dump-date', '--hex-blob', '--complete-insert', '--skip-extended-insert', '--order-by-primary', '--databases', 'suhoput2_stage']
        schema = self.w.native.run(args + ['--no-data', '--routines', '--events', '--triggers'])
        rows = self.w.native.run(args + ['--no-create-info', '--skip-triggers'])
        return {'schema_sha256': hashlib.sha256(schema).hexdigest(), 'table_rows_sha256': hashlib.sha256(rows).hexdigest(), 'table_counts': counts, 'catalog': columns}

    def journal_binding(self, bmd, control_id):
        return {'plan_sha256': digest(self.plan), 'token': self.plan['token'], 'generation': self.w.c['generation'],
                'control_id': control_id, 'base_id': self.plan['base_id'], 'base_manifest_sha256': bmd, 'stop': self.plan['stop'],
                'replay_sha256': sha(private_path(self.root / 'replay.sql'))}

    def journals(self, bmd, control_id):
        binding = self.journal_binding(bmd, control_id)
        before = runtime.load_json(private_path(self.root / 'base-imported.json'))
        after = runtime.load_json(private_path(self.root / 'replay-applied.json'))
        for journal, phase in [(before, 'base-imported'), (after, 'replay-applied')]:
            guards.require(all(journal.get(key) == value for key, value in binding.items()) and journal.get('phase') == phase and journal.get('native_sql_exit') == 0, 'Operational SQL journal binding differs')
            for key in ('schema_sha256', 'table_rows_sha256'): guards.hex_id(journal['state'][key], 64)
        guards.require(guards.utc(before['completed_at']) <= guards.utc(after['completed_at']), 'Operational SQL journal clock rollback')
        return before, after

    def finish(self, inputs, control_id, *, existing=False):
        base, bpath, bmd, full, fpath, fmd, logs = inputs
        before, after = self.journals(bmd, control_id)
        guards.require(self.state() == after['state'], 'Restored SQL state differs from actual applied replay')
        media = self.verified_media(bpath / 'uploads', self.expected_media)
        self.fresh(); integrity.validate_report(self.full_remote_integrity, self.inventory, guards.utc(now()))
        receipt = {'operation': OPERATION, 'result': 'PASS', 'profile': self.profile, 'token': self.plan['token'],
                   'generation': self.w.c['generation'], 'repositories': self.inventory['repositories'], 'cohort': self.inventory['cohort'],
                   'source': self.w.source, 'stage_app_sha': base['stage_app_sha'], 'started_from': STARTED_FROM, 'source_reads': 0,
                   'base_id': self.plan['base_id'], 'base_manifest_sha256': bmd, 'full_id': self.plan['full_id'], 'full_manifest_sha256': fmd,
                   'coordinates': base['coordinates'], 'stop': self.plan['stop'], 'replayed_logs': len(logs), 'verified_binlogs': logs,
                   'actual_sql_import': 'PASS', 'native_replay': 'PASS', 'row_guard': self.row_guard, 'full_remote_integrity': self.full_remote_integrity,
                   'schema_sha256': after['state']['schema_sha256'], 'table_rows_sha256': after['state']['table_rows_sha256'],
                   'table_counts': after['state']['table_counts'], 'media': media, 'replay_sha256': after['replay_sha256'],
                   'base_journal_sha256': sha(self.root / 'base-imported.json'), 'replay_journal_sha256': sha(self.root / 'replay-applied.json'),
                   'control_id': control_id, 'control_objects': [self.control, self.volume],
                   'isolation': {'network': 'none', 'event_scheduler': 'OFF', 'skip_networking': True, 'log_bin': False},
                   'validation_only': existing, 'SQL_import_replay_calls_this_run': 0 if existing else 2, 'completed_at': now()}
        bind_recovery(self.inventory, {**self.retention_plan, 'anchor_id': self.plan['base_id']}, receipt)
        runtime.atomic_json(self.root / 'completed.json', receipt)
        return receipt

    def stop(self, control_id):
        row = self.inspect_control(control_id)
        if row['State']['Running']: self.w.native.run(['docker', 'stop', '--time', '30', self.control])
        guards.require(not self.inspect_control(control_id)['State']['Running'], 'Operational control remains running')

    def run(self):
        from retention_native import exclusive_json, publish_evidence
        with runtime.lane_lock(self.lock), backup_catalog.ArchiveCatalog(self.w).open_reader() as reader:
            self.w.gate()
            budget_paths = [self.w.root / 'receipts' / name for name in ('commissioning-budget.json', 'commissioning-budget.origin.json')]
            commissioned = self.w.c.get('retention_readiness_policy') == 'native-v2' and any(path.exists() or path.is_symlink() for path in budget_paths)
            if commissioned:
                import budget
                # prepare() may refresh paid native metadata/integrity too.
                budget.load_commissioning_budget(self.w)
            self.prepare(reader)
            if commissioned:
                metadata_cache_preflight(self.w, self.inventory['repositories']['base'])
            guards.require(not self.intent.exists() and not self.intent.is_symlink() and not self.root.exists() and not self.root.is_symlink(), 'Prior operational attempt; preserve/investigate')
            objects_absent(self.w.native, targets(self.plan)); started = now()
            exclusive_json(self.intent, {'plan_sha256': digest(self.plan), 'generation': self.w.c['generation'], 'token': self.plan['token'], 'started_at': started, 'targets': targets(self.plan)})
            self.root.mkdir(mode=0o700)
            for name in ('snapshots', 'logs', 'socket'): (self.root / name).mkdir(mode=0o700)
            inputs = self.inputs(); base, bpath, bmd, *_ = inputs
            self.decode(inputs[-1], base['coordinates'], self.root / 'replay.sql')
            self.password = secrets.token_hex(32)
            fd = os.open(self.root / 'control.password', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as output: output.write(self.password + '\n'); output.flush(); os.fsync(output.fileno())
            self.fresh(); objects_absent(self.w.native, targets(self.plan))
            labels = ['--label', 'task047.generation=' + self.w.c['generation'], '--label', 'task047.restore-token=' + self.plan['token']]
            self.w.native.run(['docker', 'volume', 'create', *labels, self.volume])
            volume = json.loads(self.w.native.run(['docker', 'volume', 'inspect', self.volume]))[0]
            guards.require(volume['Name'] == self.volume and volume['Labels'].get('task047.generation') == self.w.c['generation'] and
                           volume['Labels'].get('task047.restore-token') == self.plan['token'], 'Unknown operational volume before DB start')
            self.w.native.run(['docker', 'run', '-d', '--name', self.control, *labels, '--label', 'com.docker.compose.project=' + self.project,
                '--label', 'com.docker.compose.service=db', '--network', 'none', '--memory', '1g', '--cpus', '0.5', '--pids-limit', '256',
                '--cap-drop', 'NET_RAW', '--security-opt', 'no-new-privileges', '--env', 'MARIADB_ROOT_PASSWORD',
                '--mount', 'type=volume,source=' + self.volume + ',target=/var/lib/mysql', '--mount', 'type=bind,source=' + str(self.root / 'socket') + ',target=/run/mysqld',
                DB_IMAGE, '--skip-networking', '--event-scheduler=OFF'], environment={'MARIADB_ROOT_PASSWORD': self.password})
            row = self.inspect_control(); control_id = row['Id']
            try:
                self.ready()
                guards.require(self.sql("SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='suhoput2_stage';").strip() == b'0', 'Operational schema already exists; no SQL replay')
                command = ['docker', 'exec', '-i', self.control, 'sh', '-c', 'MYSQL_PWD="$MARIADB_ROOT_PASSWORD" exec mariadb -uroot']
                self.fresh(); self.w.native.run(command, data=(bpath / 'db.sql').read_bytes())
                exclusive_json(self.root / 'base-imported.json', {**self.journal_binding(bmd, control_id), 'phase': 'base-imported', 'native_sql_exit': 0, 'state': self.state(), 'completed_at': now()})
                self.fresh(); self.w.native.run(command, data=(self.root / 'replay.sql').read_bytes())
                exclusive_json(self.root / 'replay-applied.json', {**self.journal_binding(bmd, control_id), 'phase': 'replay-applied', 'native_sql_exit': 0, 'state': self.state(), 'completed_at': now()})
                receipt = self.finish(inputs, control_id)
            finally:
                # Only the authenticated ID is stopped; data and uncertain SQL
                # outcomes remain preserved, and no SQL is retried.
                self.stop(control_id)
            return publish_evidence(self.w, self.profile, receipt, self.inventory, started)

    def verify_existing(self):
        from retention_native import publish_evidence
        with runtime.lane_lock(self.lock), backup_catalog.ArchiveCatalog(self.w).open_reader() as reader:
            self.prepare(reader); intent = runtime.load_json(private_path(self.intent))
            guards.require(intent.get('plan_sha256') == digest(self.plan) and intent.get('targets') == targets(self.plan) and
                           self.root.resolve() == self.root and self.root.is_dir(), 'Operational existing intent/path differs')
            # Both journals must exist before restarting even the isolated DB.
            after = runtime.load_json(private_path(self.root / 'replay-applied.json')); control_id = guards.hex_id(after['control_id'], 64)
            self.journals(after['base_manifest_sha256'], control_id)
            row = self.inspect_control(control_id)
            self.password = private_path(self.root / 'control.password').read_text().strip(); guards.hex_id(self.password, 64)
            inputs = self.inputs(existing=True)
            verified = self.root / ('replay-verified-' + uuid.uuid4().hex + '.sql')
            self.decode(inputs[-1], inputs[0]['coordinates'], verified)
            guards.require(sha(verified) == sha(self.root / 'replay.sql'), 'Recreated original replay SQL differs')
            started = now()
            if not row['State']['Running']: self.w.native.run(['docker', 'start', self.control])
            try:
                self.inspect_control(control_id); self.ready(); receipt = self.finish(inputs, control_id, existing=True)
            finally: self.stop(control_id)
            return publish_evidence(self.w, self.profile, receipt, self.inventory, started)


def main():
    import argparse
    parser = argparse.ArgumentParser(); parser.add_argument('--config', required=True)
    parser.add_argument('--profile', choices=['anchor', 'tip'], required=True); parser.add_argument('--verify-existing', action='store_true')
    args = parser.parse_args(); os.umask(0o077)
    try:
        restore = RetentionRecovery(Worker(args.config), args.profile)
        report = restore.verify_existing() if args.verify_existing else restore.run()
        print(json.dumps(report)); return 0
    except Exception as error:
        print(json.dumps({'result': 'FAIL', 'error_type': type(error).__name__, 'completed_at': now()})); return 1


if __name__ == '__main__': raise SystemExit(main())
