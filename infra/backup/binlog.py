"""Pure pre-import guard for archived MariaDB 10.11 ROW bytes.

Format/type/header constants: MariaDB 10.11 sql/log_event.h and log_event.cc,
https://github.com/MariaDB/server/blob/10.11/sql/log_event.h
https://github.com/MariaDB/server/blob/10.11/sql/log_event.cc
CRC writer: sql/log_event_server.cc (FDE in-use bit excluded from CRC).
Unknown, encrypted, compressed, statement-data, XA and DDL events fail closed.
This supplements authenticated descriptor hashes and native mariadb-binlog
--verify-binlog-checksum. It scopes tables and frames replay; it does not decode
all typed row values or execute SQL, nor establish archive provenance/recovery.
"""
import binascii
import copy
import hashlib
import re
import struct

import guards

HEADER = 19
MAGIC = b'\xfebin'
QUERY, STOP, ROTATE, FDE, XID, TABLE_MAP = 2, 3, 4, 15, 16, 19
ROW_V1 = frozenset((23, 24, 25))
ROW_V2 = frozenset((30, 31, 32))
ROWS = ROW_V1 | ROW_V2
ANNOTATE, CHECKPOINT, GTID, GTID_LIST = 160, 161, 162, 163
ALLOWED = frozenset((QUERY, STOP, ROTATE, FDE, XID, TABLE_MAP, ANNOTATE, CHECKPOINT, GTID, GTID_LIST)) | ROWS
POST_HEADERS = {QUERY: 13, STOP: 0, ROTATE: 8, XID: 0, TABLE_MAP: 8,
                23: 8, 24: 8, 25: 8, 30: 10, 31: 10, 32: 10,
                ANNOTATE: 0, CHECKPOINT: 4, GTID: 19, GTID_LIST: 4}
MAX_BYTES = 1024 ** 3
MAX_EVENT_BYTES = 256 * 1024 ** 2


def _need(value, reason):
    guards.require(value, reason)


def _packed(body, offset):
    _need(offset < len(body), 'Truncated packed integer')
    tag = body[offset]; offset += 1
    if tag < 251:
        return tag, offset
    sizes = {252: 2, 253: 3, 254: 8}
    _need(tag in sizes and offset + sizes[tag] <= len(body), 'Invalid packed integer')
    size = sizes[tag]; value = int.from_bytes(body[offset:offset + size], 'little')
    _need(value >= {252: 251, 253: 65536, 254: 16777216}[tag], 'Noncanonical packed integer')
    return value, offset + size


def _name(body, offset):
    _need(offset < len(body), 'Missing table-map identifier')
    length = body[offset]; offset += 1
    _need(0 < length <= 64 and offset + length < len(body) and body[offset + length] == 0,
          'Truncated table-map identifier or terminator')
    raw = body[offset:offset + length]
    _need(re.fullmatch(rb'[A-Za-z0-9_]+', raw) is not None, 'Unsafe table identifier')
    return raw.decode('ascii'), offset + length + 1


def _format(body):
    _need(len(body) >= 57 + GTID_LIST + 1 and struct.unpack_from('<H', body)[0] == 4,
          'Format description must cover MariaDB event headers')
    version_bytes = body[2:52]
    version = version_bytes.split(b'\0', 1)[0]
    _need(re.fullmatch(rb'(?:5\.5\.5-)?10\.11\.[0-9]+-MariaDB[ -~]*', version) is not None,
          'Only MariaDB 10.11 format supported')
    _need(body[56] == HEADER and body[-1] == 1, 'Header19 and native CRC32 required')
    headers = body[57:-1]
    for kind, size in POST_HEADERS.items():
        if kind <= len(headers):
            _need(headers[kind - 1] == size, 'Unsupported event post-header format')
    return version.decode('ascii')


def _table(body, schema, prefix):
    _need(len(body) >= 8, 'Truncated table-map post-header')
    tid = int.from_bytes(body[:6], 'little')
    _need(tid not in (0, 0xffffffff, 0xffffffffffff), 'Invalid table-map ID')
    database, offset = _name(body, 8); table, offset = _name(body, offset)
    _need(database == schema and table.startswith(prefix) and len(table) > len(prefix),
          'Foreign schema or table prefix')
    columns, offset = _packed(body, offset)
    _need(0 < columns <= 4096 and offset + columns <= len(body), 'Invalid table-map column count')
    offset += columns  # Typed value decoding remains the native decoder's job.
    metadata, offset = _packed(body, offset)
    null_bytes = (columns + 7) // 8
    _need(offset + metadata + null_bytes <= len(body), 'Truncated table-map metadata/null bitmap')
    offset += metadata + null_bytes
    # Optional metadata fields are TLVs; never accept an out-of-bounds body.
    while offset < len(body):
        offset += 1
        length, offset = _packed(body, offset)
        _need(offset + length <= len(body), 'Truncated optional table metadata')
        offset += length
    return tid, database + '.' + table, columns


def _rows(body, kind, maps):
    size = 10 if kind in ROW_V2 else 8
    _need(len(body) >= size, 'Truncated row post-header')
    tid = int.from_bytes(body[:6], 'little')
    _need(tid in maps, 'Row event has no current scoped table map')
    flags = struct.unpack_from('<H', body, 6)[0]
    _need(flags & ~15 == 0, 'Unknown row flags')
    offset = 8
    if kind in ROW_V2:
        extra_length = struct.unpack_from('<H', body, 8)[0]
        _need(extra_length >= 2 and 8 + extra_length <= len(body), 'Truncated V2 row extra header')
        # No unknown row extra information is needed by this stage configuration.
        _need(extra_length == 2, 'Unsupported V2 row extra information')
        offset = 8 + extra_length
    columns, offset = _packed(body, offset)
    _need(columns == maps[tid][1], 'Row/table-map column count differs')
    bitmap = (columns + 7) // 8
    count = 2 if kind in (24, 31) else 1
    _need(offset + bitmap * count < len(body), 'Truncated row column bitmap/data')
    for index in range(count):
        bits = body[offset + index * bitmap:offset + (index + 1) * bitmap]
        _need(any(bits) and (columns % 8 == 0 or bits[-1] >> (columns % 8) == 0),
              'Invalid row column bitmap')
    return bool(flags & 1)


def _query_status(status):
    """Closed QUERY status grammar; native decoding emits these as session SQL.

    Numeric encodings below have fixed lengths from log_event.h. Q_TIME_ZONE
    (code5) is interpolated into a quoted SET by log_event_client.cc; its closed
    value grammar excludes quote, backslash, control bytes and SQL punctuation.
    Catalog/invoker/GTID-extra and all unsupported codes fail before import.
    """
    fixed = {0: 4, 1: 8, 3: 4, 4: 6, 7: 2, 8: 2, 128: 3, 129: 8}
    offset = 0; seen = set()
    while offset < len(status):
        code = status[offset]; offset += 1
        _need(code not in seen, 'Duplicate QUERY status variable')
        seen.add(code)
        if code == 5:
            _need(offset < len(status), 'Truncated QUERY time-zone length')
            length = status[offset]; offset += 1
            _need(0 < length <= 64 and offset + length <= len(status), 'Truncated QUERY time-zone value')
            timezone = status[offset:offset + length]
            pattern = rb'(?:SYSTEM|UTC|GMT|[+-](?:0[0-9]|1[0-3]):[0-5][0-9]|[+-]14:00|[A-Za-z][A-Za-z0-9_+-]*(?:/[A-Za-z0-9_+-]+)+)'
            _need(re.fullmatch(pattern, timezone) is not None, 'Unsafe/unsupported QUERY time-zone value')
        else:
            _need(code in fixed, 'Unsupported QUERY status variable')
            length = fixed[code]
            _need(offset + length <= len(status), 'Truncated numeric QUERY status value')
            if code == 3:
                _need(all(value > 0 for value in struct.unpack_from('<HH', status, offset)),
                      'Invalid QUERY auto-increment settings')
        offset += length


def _query(body, schema):
    _need(len(body) >= 14, 'Truncated QUERY post-header')
    database_length = body[8]
    error_code, status_length = struct.unpack_from('<HH', body, 9)
    offset = 13 + status_length
    _need(error_code == 0 and status_length <= 1024 and offset + database_length < len(body) and
          body[offset + database_length] == 0, 'Invalid QUERY status/database bounds')
    _query_status(body[13:offset])
    database = body[offset:offset + database_length]
    _need(database in (b'', schema.encode()), 'Foreign QUERY database')
    statement = body[offset + database_length + 1:]
    match = re.fullmatch(rb'[ \t\r\n]*(BEGIN|COMMIT|ROLLBACK)[ \t\r\n]*;?[ \t\r\n]*',
                         statement, re.I)
    _need(match is not None, 'Statement or DDL event forbidden before import')
    return match[1].upper()


def _parse(raw, filename, schema, prefix):
    _need(raw.startswith(MAGIC) and len(raw) > 4, 'Invalid binlog magic or empty archive')
    offset = 4; maps = {}; tables = set(); events = []; safe = {4}
    transaction = False; version = None
    number = guards.log_number(filename)
    while offset < len(raw):
        _need(len(raw) - offset >= HEADER + 4, 'Truncated event header/footer')
        _, kind, server_id, size, end, flags = struct.unpack_from('<IBIIIH', raw, offset)
        _need(kind in ALLOWED and server_id > 0 and HEADER + 4 <= size <= MAX_EVENT_BYTES and
              offset + size <= len(raw) and end == offset + size, 'Unknown event or invalid event boundary')
        _need(not flags & (0x20 | 0x40 | 0x8000), 'Artificial/relay/skipped-replication event forbidden')
        _need(kind != FDE or offset == 4, 'Repeated format description')
        _need(version is not None or kind == FDE, 'Archive must begin with format description')
        event = raw[offset:end]; body = event[HEADER:-4]
        _need(binascii.crc32(event[:-4]) & 0xffffffff == struct.unpack_from('<I', event, size - 4)[0],
              'Archived event CRC32 differs')
        if kind == FDE:
            _need(not flags & 1, 'Archive is still open')
            version = _format(body)
        elif kind == QUERY:
            statement = _query(body, schema)
            if statement == b'BEGIN':
                _need(not transaction, 'Nested BEGIN')
                transaction = True
            else:
                _need(transaction, 'COMMIT/ROLLBACK without transaction')
                transaction = False; maps.clear()
        elif kind == TABLE_MAP:
            _need(transaction, 'Table map outside transactional ROW group')
            tid, table, columns = _table(body, schema, prefix)
            maps[tid] = (table, columns); tables.add(table)
        elif kind in ROWS:
            _need(transaction, 'ROW event outside transaction')
            if _rows(body, kind, maps):
                maps.clear()
        elif kind == XID:
            _need(len(body) == 8 and transaction, 'Invalid XID or missing transaction')
            transaction = False; maps.clear()
        elif kind == GTID:
            _need(len(body) in (19, 21) and struct.unpack_from('<Q', body)[0] > 0,
                  'Invalid MariaDB GTID structure')
            gtid_flags = body[12]
            _need(not gtid_flags & (1 | 32 | 64 | 128) and gtid_flags & 4 and
                  len(body) == (21 if gtid_flags & 2 else 19), 'Nontransactional/DDL/XA GTID forbidden')
            _need(not transaction, 'GTID interrupts transaction')
            transaction = True; maps.clear()
        elif kind == GTID_LIST:
            _need(not transaction and len(body) >= 4, 'Invalid GTID list')
            count_flags = struct.unpack_from('<I', body)[0]
            _need(count_flags & 0xf0000000 == 0, 'Unsupported GTID list flags')
            count = count_flags & 0x0fffffff
            # MariaDB10.11 get_data_size()/to_packet() uses two ZERO padding
            # bytes for count0, allowing conversion to older slaves' dummy event.
            # log_event.h:3644-3650, log_event_server.cc:3827-3831.
            expected = 6 if count == 0 else 4 + 16 * count
            _need(count < 65536 and len(body) == expected and
                  (count != 0 or body[4:] == b'\0\0'), 'GTID list count/body differs')
        elif kind == CHECKPOINT:
            _need(not transaction and len(body) >= 4, 'Invalid binlog checkpoint')
            length = struct.unpack_from('<I', body)[0]
            _need(length == len(body) - 4, 'Checkpoint filename length differs')
            name = body[4:].decode('ascii')
            _need(guards.log_number(name) <= number, 'Future/foreign checkpoint file')
        elif kind == ROTATE:
            _need(not transaction and len(body) >= 9 and end == len(raw), 'Invalid/unfinished rotation')
            _need(struct.unpack_from('<Q', body)[0] == 4 and
                  guards.log_number(body[8:].decode('ascii')) == number + 1,
                  'Foreign/nonconsecutive rotation target')
        elif kind == STOP:
            _need(not body and not transaction and end == len(raw), 'Invalid/unfinished stop event')
        elif kind == ANNOTATE:
            _need(transaction and body, 'Annotation outside transaction or empty')
        events.append((offset, end, kind))
        if not transaction:
            safe.add(end)
        offset = end
    _need(offset == len(raw) and not transaction, 'Archive ends inside an event/transaction')
    return events, safe, tables, version


def validate_chain(logbytes, descriptors, start, stop, schema='suhoput2_stage', prefix='wp_'):
    """Validate exact selected files before SQL import and return a bytes-free report.

    Full archived files are checked, including bytes outside the replay slice.
    Descriptor files must be exactly the consecutive start..stop range. Replay
    endpoints must be both event and transaction boundaries. Tables are mapped
    afresh per statement/file; native typed row decoding/CRC also runs separately.
    """
    try:
        _need(schema == 'suhoput2_stage' and prefix == 'wp_', 'Only approved stage schema/prefix allowed')
        _need(isinstance(logbytes, dict) and isinstance(descriptors, list) and descriptors,
              'Exact archived byte mapping/descriptors required')
        first = guards.log_number(start['file']); last = guards.log_number(stop['file'])
        _need(type(start['position']) is int and type(stop['position']) is int and
              start['position'] >= 4 and stop['position'] >= 4 and first <= last,
              'Invalid replay coordinates')
        names = [row['file'] for row in descriptors]
        _need([guards.log_number(name) for name in names] == list(range(first, last + 1)) and
              len(names) == len(set(names)) and set(logbytes) == set(names), 'Archive gap/duplicate/unknown bytes')
        _need(sum(len(value) for value in logbytes.values()) <= MAX_BYTES, 'Archived byte guard memory bound exceeded')
        total = 0; selected_rows = 0; tables = set(); versions = set()
        for row in descriptors:
            filename = row['file']; raw = logbytes[filename]
            _need(isinstance(raw, bytes) and type(row['size']) is int and row['size'] == len(raw),
                  'Archived descriptor size/type differs')
            guards.hex_id(row['sha256'], 64)
            _need(hashlib.sha256(raw).hexdigest() == row['sha256'], 'Archived descriptor SHA differs')
            events, safe, mapped, version = _parse(raw, filename, schema, prefix)
            begin = start['position'] if filename == start['file'] else 4
            end = stop['position'] if filename == stop['file'] else len(raw)
            _need(begin in safe and end in safe and begin <= end, 'Replay endpoint splits an event/transaction')
            # A transaction boundary guarantees its table maps are in the slice.
            selected_rows += sum(kind in ROWS for offset, final, kind in events if begin <= offset and final <= end)
            total += len(events); tables.update(mapped); versions.add(version)
        return {'result': 'PASS', 'guard': 'strict-mariadb-10.11-row', 'schema': schema, 'prefix': prefix,
                'start': copy.deepcopy(start), 'stop': copy.deepcopy(stop), 'files': copy.deepcopy(descriptors),
                'event_count': total, 'selected_row_events': selected_rows,
                'mapped_tables': sorted(tables), 'server_versions': sorted(versions)}
    except (KeyError, TypeError, ValueError, UnicodeError, struct.error) as error:
        raise guards.GuardError('Incomplete or malformed archived ROW bytes') from error
