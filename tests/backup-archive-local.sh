#!/bin/sh
# Real local archive exercise, synthetic files only. No DB, binlog, S3 or VPS.
# Run in a new network-none container with an empty ephemeral /control tmpfs.
set -eu
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
/control/restic version
date -u +%Y-%m-%dT%H:%M:%SZ
mkdir -p /control/source/uploads
printf '%s\n' '<svg xmlns="http://www.w3.org/2000/svg"><text>synthetic-media</text></svg>' > /control/source/uploads/synthetic.svg
printf '%s\n' '-- Synthetic text fixture, not a MariaDB dump' > /control/source/synthetic.sql
/control/restic init > /control/init.log 2>&1
/control/restic backup /control/source --tag synthetic-local > /control/backup.log 2>&1
/control/restic check --read-data > /control/check.log 2>&1
printf '%s\n' 'PASS local encrypted archive creation and read-data integrity'
/control/restic restore latest --target /control/restored --verify > /control/restore.log 2>&1
cmp /control/source/synthetic.sql /control/restored/control/source/synthetic.sql
cmp /control/source/uploads/synthetic.svg /control/restored/control/source/uploads/synthetic.svg
sha256sum /control/restored/control/source/synthetic.sql /control/restored/control/source/uploads/synthetic.svg
printf '%s\n' 'PASS restore --verify and byte equality of both files'
printf '%s\n' 'deliberately-wrong-test-password' > /control/wrong-password
if /control/restic --password-file /control/wrong-password snapshots > /control/wrong.log 2>&1; then
    printf '%s\n' 'FAIL wrong password accepted' >&2
    exit 1
fi
grep -Eq 'wrong password|no key found' /control/wrong.log
printf '%s\n' 'PASS wrong password denied'
# Corrupt only one pack in this newly created tmpfs repository after restoration.
pack=$(find /control/repository/data -type f -print -quit)
[ -n "$pack" ]
[ "$(wc -c < "$pack")" -gt 1 ]
# Restic writes packs read-only. Permit this deliberate fault only on our own
# ephemeral file; cap-drop ALL correctly prevents overriding its mode.
[ "$(stat -c %u "$pack")" = "$(id -u)" ]
chmod u+w "$pack"
truncate -s 1 "$pack"
if /control/restic check --read-data > /control/corrupt.log 2>&1; then
    printf '%s\n' 'FAIL corrupted pack accepted' >&2
    exit 1
fi
printf '%s\n' 'PASS deliberately corrupted pack rejected by check --read-data'
date -u +%Y-%m-%dT%H:%M:%SZ
printf '%s\n' 'RESULT local-archive=PASS s3=not_run db-restore=not_run binlog-replay=not_run'
