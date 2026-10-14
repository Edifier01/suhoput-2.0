"""Offline, read-only backup evidence checks. No DB/S3 calls or deletion.

Inputs must come from authenticated archives and an independently collected
recovery target. Sequence/hash checks alone do not prove binlog semantics,
common database origin, encryption, scheduling, or a successful restore.
"""
import argparse
import datetime as dt
from decimal import Decimal, DecimalException, InvalidOperation
import hashlib
import json
import pathlib
import re
import stat


class BackupError(ValueError):
    """Fail closed without including paths, file content, or credentials."""


def utc_time(value):
    try:
        result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None or result.utcoffset() != dt.timedelta():
            raise BackupError("UTC timestamp required")
        return result
    except (AttributeError, TypeError, ValueError) as error:
        raise BackupError("Invalid UTC timestamp") from error


def integer(value, minimum=0):
    if type(value) is not int or value < minimum:
        raise BackupError("Invalid nonnegative integer")
    return value


def log_name(value):
    if not isinstance(value, str):
        raise BackupError("Invalid binlog name")
    match = re.fullmatch(r"([A-Za-z0-9_-]+)\.([0-9]{6})", value)
    if not match or int(match[2]) == 0:
        raise BackupError("Invalid binlog name")
    return match[1], int(match[2])


def sha256_value(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise BackupError("Missing or invalid SHA-256")
    return value


def validate_chain(base, target, logs):
    """Validate the ordered byte coverage, not event validity or provenance."""
    try:
        prefix, first = log_name(base["file"])
        target_prefix, last = log_name(target["file"])
        start_position = integer(base["position"], 4)
        stop_position = integer(target["position"], 4)
        if target_prefix != prefix or last < first or (first == last and stop_position < start_position):
            raise BackupError("Target precedes base or has different log prefix")
        seen = set()
        previous = 0
        selected = []
        for item in logs:
            item_prefix, number = log_name(item["file"])
            size = integer(item["size"], 4)
            sha256_value(item["sha256"])
            if item_prefix != prefix or number in seen or number <= previous:
                raise BackupError("Duplicate, unordered, or different-prefix binlog")
            seen.add(number)
            previous = number
            if first <= number <= last:
                selected.append((number, size))
        if len(selected) != last - first + 1:
            raise BackupError("Missing binlog in required chain")
        if start_position > selected[0][1] or stop_position > selected[-1][1]:
            raise BackupError("Coordinate exceeds archived binlog length")
        return {"files": len(selected), "first": base["file"], "last": target["file"],
                "start_position": start_position, "stop_position": stop_position,
                "event_semantics_verified": False}
    except (KeyError, TypeError) as error:
        raise BackupError("Incomplete chain evidence") from error


def check_lag(last_uploaded_closed_at, now):
    if now.tzinfo is None:
        raise BackupError("UTC clock required")
    age = (now - utc_time(last_uploaded_closed_at)).total_seconds()
    if age < 0:
        raise BackupError("Future heartbeat; check clocks")
    if age > 60:
        raise BackupError("Offsite closed-log heartbeat exceeds one minute")
    return age


def relative_path(value):
    if (not isinstance(value, str) or not value or "\\" in value or ":" in value
            or "\x00" in value or value.startswith("/")
            or any(part in ("", ".", "..") for part in value.split("/"))):
        raise BackupError("Unsafe relative archive path")
    return pathlib.PurePosixPath(value)


def checked_file(root, relative):
    path = root
    for index, part in enumerate(relative.parts):
        path = path / part
        try:
            metadata = path.lstat()
        except OSError as error:
            raise BackupError("Restored entry missing or inaccessible") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise BackupError("Symlink not allowed in recovery inventory")
        final = index == len(relative.parts) - 1
        if final:
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise BackupError("Regular independent recovery file required")
        elif not stat.S_ISDIR(metadata.st_mode):
            raise BackupError("Invalid directory in recovery inventory")
    return path


def verify_files(root, files, referenced_media):
    """Read/hash restored files; references must include primary and thumbnails."""
    root = pathlib.Path(root).absolute()
    # Check ancestors as well as leaf; resolve() alone would conceal symlinks.
    for parent in [root, *root.parents]:
        try:
            metadata = parent.lstat()
        except OSError as error:
            raise BackupError("Recovery root inaccessible") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise BackupError("Recovery root must have real directory ancestors")
    known = set()
    total = 0
    try:
        for item in files:
            relative = relative_path(item["path"])
            name = relative.as_posix()
            if name in known:
                raise BackupError("Duplicate inventory path")
            known.add(name)
            expected_size = integer(item["size"])
            expected_sha = sha256_value(item["sha256"])
            path = checked_file(root, relative)
            if path.stat().st_size != expected_size:
                raise BackupError("Restored file size mismatch")
            with path.open("rb") as stream:
                actual_sha = hashlib.file_digest(stream, "sha256").hexdigest()
            if actual_sha != expected_sha:
                raise BackupError("Restored file hash mismatch")
            total += expected_size
        references = set()
        for value in referenced_media:
            relative = relative_path(value)
            if relative.parts[0] != "uploads":
                raise BackupError("Media reference must be inside uploads")
            if relative.as_posix() not in known:
                raise BackupError("Restored database references missing media")
            references.add(relative.as_posix())
        return {"verified_files": len(known), "verified_bytes": total,
                "referenced_media": len(references)}
    except (KeyError, TypeError, OSError) as error:
        raise BackupError("Incomplete or unreadable recovery inventory") from error


def retention_plan(snapshots, now):
    """Preview only. Keep full base before 30d cutoff and all its later data.

    Provenance, archive validity and successful restore remain mandatory before
    any caller could use the IDs. This module cannot authorize deletion.
    """
    cutoff = now - dt.timedelta(days=30)
    records = []
    seen = set()
    try:
        for item in snapshots:
            identifier = sha256_value(item["id"])
            timestamp = utc_time(item["time"])
            kind = item["kind"]
            if identifier in seen or timestamp > now or kind not in ("full", "hourly", "pre-update", "binlog"):
                raise BackupError("Unknown, duplicate or future snapshot")
            seen.add(identifier)
            records.append((timestamp, identifier, kind))
        records.sort()
        full = [record for record in records if record[2] == "full"]
        if not full:
            raise BackupError("Full snapshot required before retention planning")
        older = [record for record in full if record[0] <= cutoff]
        anchor = older[-1] if older else full[0]
        # A new repository keeps every snapshot, even those before its first full.
        expired = [record[1] for record in records if older and record[0] < anchor[0]]
        return {"cutoff": cutoff.isoformat(), "anchor_id": anchor[1], "delete_ids": expired,
                "anchor_before_cutoff": bool(older), "history_coverage_verified": False,
                "apply_allowed": False,
                "prerequisites": "Authenticate origin, verify archives, binlog events and a real restore first"}
    except (KeyError, TypeError) as error:
        raise BackupError("Incomplete snapshot evidence") from error


def decimal_value(value):
    if isinstance(value, bool):
        raise BackupError("Invalid cost input")
    try:
        result = Decimal(str(value))
        if not result.is_finite() or result < 0:
            raise BackupError("Nonnegative finite cost input required")
        return result
    except (ValueError, InvalidOperation) as error:
        raise BackupError("Invalid cost input") from error


def cost_projection(usage, rates, budget_rub, max_gib):
    """Monthly projection from supplied tariff and counters; not provider billing."""
    try:
        storage = decimal_value(usage["storage_gib"])
        egress = decimal_value(usage["egress_gib"])
        cost = storage * decimal_value(rates["storage_rub_gib_month"])
        cost += egress * decimal_value(rates["egress_rub_gib"])
        for operation in ("put", "get", "delete"):
            count = integer(usage[operation + "_requests"])
            cost += Decimal(count) * decimal_value(rates[operation + "_rub_1000"]) / 1000
        budget = decimal_value(budget_rub)
        capacity = decimal_value(max_gib)
        if not budget or not capacity:
            raise BackupError("Positive owner budget and capacity required")
        return {"projected_rub": str(cost.normalize()),
                "over_limit": cost > budget or storage > capacity,
                "provider_billing_verified": False}
    except (KeyError, TypeError) as error:
        raise BackupError("Tariffs or monthly usage inputs missing") from error
    except DecimalException as error:
        raise BackupError("Cost inputs exceed calculable bounds") from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("chain", "files", "retention", "cost"))
    parser.add_argument("evidence", type=pathlib.Path, help="Local JSON, never credentials")
    parser.add_argument("--root", type=pathlib.Path, help="Isolated restored directory for files")
    args = parser.parse_args()
    try:
        evidence = json.loads(args.evidence.read_text(encoding="utf-8-sig"))
        now = dt.datetime.now(dt.timezone.utc)
        if args.command == "chain":
            result = validate_chain(evidence["base"], evidence["target"], evidence["logs"])
            result["lag_seconds"] = check_lag(evidence["last_uploaded_closed_at"], now)
        elif args.command == "files":
            if args.root is None:
                raise BackupError("Recovery root required")
            result = verify_files(args.root, evidence["files"], evidence["referenced_media"])
        elif args.command == "retention":
            result = retention_plan(evidence["snapshots"], now)
        else:
            result = cost_projection(evidence["usage"], evidence["rates"], evidence["budget_rub"], evidence["max_gib"])
        print(json.dumps({"check": args.command, "result": result}, ensure_ascii=True))
        return 1 if result.get("over_limit") else 0
    except (BackupError, KeyError, TypeError, ValueError, OSError):
        print(json.dumps({"check": args.command, "error": "Invalid or insufficient backup evidence"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
