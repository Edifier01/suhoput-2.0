#!/bin/bash
# Real local MariaDB/restic rehearsal with disposable synthetic data.
# No S3, VPS, WordPress bootstrap, external adapters or existing volumes.
# Run only in a new network-none container with an empty /control tmpfs.
set -euo pipefail
trap 'printf "FAIL at line %s\n" "$LINENO" >&2' ERR
umask 077
[ -d /control ]
[ -z "$(find /control -mindepth 1 -print -quit)" ]
printf '%s\n' '20d4142678d0d95ec11a4759def1b73fd9190abc9ca19e4b62d067c0b387e639  /input/restic' | sha256sum -c -
cp /input/restic /control/restic
chmod 0700 /control/restic
export TMPDIR=/control
export RESTIC_CACHE_DIR=/control/cache
export RESTIC_REPOSITORY=/control/repository
export RESTIC_PASSWORD_FILE=/control/password
unset RESTIC_PASSWORD RESTIC_PASSWORD_COMMAND
od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > "$RESTIC_PASSWORD_FILE"
printf '\n' >> "$RESTIC_PASSWORD_FILE"
source_pid=''
restore_pid=''
cleanup() {
    for pid in "$source_pid" "$restore_pid"; do
        if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; fi
    done
}
trap cleanup EXIT
sql() { mariadb --no-defaults --socket="/control/$1.sock" -uroot -N -B; }
ready() {
    local instance=$1
    for attempt in {1..100}; do
        if printf 'SELECT 1;\n' | sql "$instance" > /dev/null 2>&1; then return; fi
        sleep 0.2
    done
    cat "/control/$instance.log" >&2
    return 1
}
mariadb --version
mariadb-binlog --version
/control/restic version
date -u +%Y-%m-%dT%H:%M:%SZ
mkdir /control/source-db /control/restore-db
for instance in source restore; do
    if ! mariadb-install-db --no-defaults --datadir="/control/$instance-db" --skip-test-db \
        --auth-root-authentication-method=normal > "/control/$instance-init.log" 2>&1; then
        cat "/control/$instance-init.log" >&2
        exit 1
    fi
done
# Socket-only root has no password inside this disposable network-none container.
# Never use this setup for a persistent environment.
mariadbd --no-defaults --user=root --datadir=/control/source-db \
    --socket=/control/source.sock --pid-file=/control/source.pid --skip-networking \
    --innodb-buffer-pool-size=32M --event-scheduler=OFF \
    --log-bin=/control/source-db/binlog --server-id=4701 --binlog-format=ROW \
    --sync-binlog=1 --innodb-flush-log-at-trx-commit=1 > /control/source.log 2>&1 &
source_pid=$!
ready source
printf 'SELECT @@version;\n' | sql source
# MariaDB appends -log when this instance has binary logging enabled.
[ "$(printf 'SELECT @@version;\n' | sql source)" = '10.11.19-MariaDB-ubu2204-log' ]
[ "$(printf 'SELECT @@log_bin,@@binlog_format,@@sync_binlog,@@innodb_flush_log_at_trx_commit;\n' | sql source)" = $'1\tROW\t1\t1' ]
mkdir -p /control/payload/uploads/2026/10 /control/payload/binlogs
printf 'synthetic original\n' > /control/payload/uploads/2026/10/item.txt
printf 'synthetic thumbnail\n' > /control/payload/uploads/2026/10/item-thumb.txt
original_sha=$(sha256sum /control/payload/uploads/2026/10/item.txt | cut -d' ' -f1)
thumb_sha=$(sha256sum /control/payload/uploads/2026/10/item-thumb.txt | cut -d' ' -f1)
original_bytes=$(wc -c < /control/payload/uploads/2026/10/item.txt)
thumb_bytes=$(wc -c < /control/payload/uploads/2026/10/item-thumb.txt)
sql source <<SQL
CREATE DATABASE suhoput2_stage;
USE suhoput2_stage;
CREATE TABLE orders (id INT PRIMARY KEY, state VARCHAR(32)) ENGINE=InnoDB;
CREATE TABLE operations (id INT PRIMARY KEY, order_id INT, state VARCHAR(32)) ENGINE=InnoDB;
CREATE TABLE media_refs (path VARCHAR(255) PRIMARY KEY, bytes INT, sha256 CHAR(64)) ENGINE=InnoDB;
INSERT INTO media_refs VALUES ('2026/10/item.txt',$original_bytes,'$original_sha'),
('2026/10/item-thumb.txt',$thumb_bytes,'$thumb_sha');
START TRANSACTION;
INSERT INTO orders VALUES (1,'base');
INSERT INTO operations VALUES (1,1,'base');
COMMIT;
SQL
mariadb-dump --no-defaults --socket=/control/source.sock -uroot --single-transaction \
    --master-data=2 --databases suhoput2_stage > /control/payload/base.sql
read -r base_file base_pos < <(sed -n "s/.*MASTER_LOG_FILE='\([^']*\)', MASTER_LOG_POS=\([0-9]*\).*/\1 \2/p" /control/payload/base.sql)
[ "$base_file" = binlog.000001 ]
[[ "$base_pos" =~ ^[0-9]+$ ]]
sql source <<'SQL'
USE suhoput2_stage;
START TRANSACTION;
INSERT INTO orders VALUES (2,'after-base');
INSERT INTO operations VALUES (2,2,'after-base');
COMMIT;
FLUSH BINARY LOGS;
START TRANSACTION;
UPDATE orders SET state='target' WHERE id=2;
UPDATE operations SET state='target' WHERE id=2;
COMMIT;
SQL
read -r target_file target_pos _ < <(printf 'SHOW MASTER STATUS;\n' | sql source)
[ "$target_file" = binlog.000002 ]
[[ "$target_pos" =~ ^[0-9]+$ ]]
# A later committed transaction must NOT enter the selected recovery point.
sql source <<'SQL'
USE suhoput2_stage;
START TRANSACTION;
INSERT INTO orders VALUES (99,'after-target');
INSERT INTO operations VALUES (99,99,'after-target');
COMMIT;
FLUSH BINARY LOGS;
SQL
[ "$(printf 'SELECT COUNT(*) FROM suhoput2_stage.orders WHERE id=99;\n' | sql source)" = 1 ]
cp /control/source-db/binlog.00000{1,2} /control/payload/binlogs/
for log in /control/payload/binlogs/binlog.00000{1,2}; do
    mariadb-binlog --no-defaults --verify-binlog-checksum "$log" > /dev/null
done
printf '%s %s\n%s %s\n' "$base_file" "$base_pos" "$target_file" "$target_pos" > /control/payload/coordinates
(cd /control/payload; find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
mariadb-admin --no-defaults --socket=/control/source.sock -uroot shutdown
wait "$source_pid"
source_pid=''
/control/restic init > /control/init.log 2>&1
/control/restic backup /control/payload --tag synthetic-local-mariadb > /control/backup.log 2>&1
/control/restic check --read-data > /control/check.log 2>&1
/control/restic restore latest --target /control/restored --verify > /control/restore.log 2>&1
restored=/control/restored/control/payload
(cd "$restored"; sha256sum -c SHA256SUMS)
{
    read -r base_file base_pos
    read -r target_file target_pos
} < "$restored/coordinates"
[ "$base_file" = binlog.000001 ] && [ "$target_file" = binlog.000002 ]
[[ "$base_pos" =~ ^[0-9]+$ ]] && [[ "$target_pos" =~ ^[0-9]+$ ]]
if printf 'SELECT 1;\n' | sql source > /dev/null 2>&1; then
    echo 'FAIL source DB still accessible during recovery' >&2; exit 1
fi
printf '%s\n' 'PASS encrypted local dump/binlog/media archive and byte integrity'
# A second instance, with the original schema name and a separate datadir/socket.
mariadbd --no-defaults --user=root --datadir=/control/restore-db \
    --socket=/control/restore.sock --pid-file=/control/restore.pid --skip-networking \
    --innodb-buffer-pool-size=32M --event-scheduler=OFF --skip-log-bin \
    > /control/restore.log 2>&1 &
restore_pid=$!
ready restore
[ "$(printf "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='suhoput2_stage';\n" | sql restore)" = 0 ]
[ "$(printf 'SELECT @@event_scheduler,@@skip_networking,@@log_bin;\n' | sql restore)" = $'OFF\t1\t0' ]
sql restore < "$restored/base.sql"
[ "$(printf 'SELECT COUNT(*) FROM suhoput2_stage.orders;\n' | sql restore)" = 1 ]
mariadb-binlog --no-defaults --verify-binlog-checksum --start-position="$base_pos" \
    "$restored/binlogs/$base_file" > /control/replay.sql
mariadb-binlog --no-defaults --verify-binlog-checksum --stop-position="$target_pos" \
    "$restored/binlogs/$target_file" >> /control/replay.sql
sql restore < /control/replay.sql
[ "$(printf 'SELECT id,state FROM suhoput2_stage.orders ORDER BY id;\n' | sql restore)" = $'1\tbase\n2\ttarget' ]
[ "$(printf 'SELECT id,order_id,state FROM suhoput2_stage.operations ORDER BY id;\n' | sql restore)" = $'1\t1\tbase\n2\t2\ttarget' ]
[ "$(printf 'SELECT COUNT(*) FROM suhoput2_stage.orders WHERE id=99;\n' | sql restore)" = 0 ]
printf '%s\n' 'PASS base import and ROW replay across two closed logs to committed target; later transaction excluded'
# Enumerate ALL references in the restored synthetic DB, including thumbnail.
printf 'SELECT path,bytes,sha256 FROM suhoput2_stage.media_refs ORDER BY path;\n' | sql restore > /control/references.tsv
[ "$(wc -l < /control/references.tsv)" = 2 ]
verify_media() {
    local path bytes sha actual_sha actual_bytes
    while IFS=$'\t' read -r path bytes sha; do
        [[ "$path" =~ ^2026/10/[a-z-]+\.txt$ ]] || return 1
        [ -f "$restored/uploads/$path" ] || return 1
        actual_sha=$(sha256sum "$restored/uploads/$path" | cut -d' ' -f1)
        actual_bytes=$(wc -c < "$restored/uploads/$path")
        [ "$actual_sha" = "$sha" ] && [ "$actual_bytes" = "$bytes" ] || return 1
    done < /control/references.tsv
}
verify_media
printf '%s\n' 'PASS every restored synthetic DB media reference has matching bytes/SHA, including thumbnail'
mv "$restored/uploads/2026/10/item-thumb.txt" /control/missing-thumb
if verify_media; then echo 'FAIL missing thumbnail accepted' >&2; exit 1; fi
mv /control/missing-thumb "$restored/uploads/2026/10/item-thumb.txt"
printf 'corrupt\n' > "$restored/uploads/2026/10/item-thumb.txt"
if verify_media; then echo 'FAIL corrupt thumbnail accepted' >&2; exit 1; fi
printf '%s\n' 'PASS missing/corrupt referenced thumbnail rejected'
# Truncate only a disposable COPY; native binlog parsing must report an error.
cp "$restored/binlogs/$target_file" /control/corrupt-binlog
truncate -s 150 /control/corrupt-binlog
if mariadb-binlog --no-defaults --verify-binlog-checksum /control/corrupt-binlog > /control/corrupt.out 2> /control/corrupt.err; then
    echo 'FAIL truncated binlog accepted' >&2; exit 1
fi
printf '%s\n' 'PASS truncated binlog rejected by native decoder'
date -u +%Y-%m-%dT%H:%M:%SZ
printf '%s\n' 'RESULT local-mariadb-pitr=PASS synthetic-db-media=PASS s3=not_run stage-backup=not_run wordpress-reference-extraction=not_run owner-restore=not_run'
