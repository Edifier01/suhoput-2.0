"""Synthetic safety scenarios; these do not exercise S3 or MariaDB."""
import datetime as dt
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

MODULE = pathlib.Path(__file__).resolve().parents[1] / "tools/backup_model.py"
FIXTURES = MODULE.parents[1] / ".cache/backup-model-tests"
FIXTURES.mkdir(parents=True, exist_ok=True)
model = None
if MODULE.exists():
    spec = importlib.util.spec_from_file_location("backup_model", MODULE)
    model = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(model)


def required_symlink(case, link, target):
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        if sys.platform == "win32":
            case.skipTest("Windows disallows creating synthetic symlinks")
        case.fail("Required symlink fixture failed")


class BackupSafety(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(model, "Backup validation implementation is missing")
        self.now = dt.datetime(2026, 10, 11, 17, 0, tzinfo=dt.timezone.utc)

    def logs(self):
        return [{"file": f"suhoput2-bin.{n:06d}", "size": 1000,
                 "sha256": "a" * 64} for n in range(4, 7)]

    def test_chain_covers_base_to_target(self):
        result = model.validate_chain({"file": "suhoput2-bin.000004", "position": 400},
                                      {"file": "suhoput2-bin.000006", "position": 900}, self.logs())
        self.assertEqual(result["files"], 3)

    def test_missing_middle_log_is_fatal(self):
        logs = self.logs()
        del logs[1]
        with self.assertRaises(model.BackupError):
            model.validate_chain({"file": logs[0]["file"], "position": 400},
                                 {"file": logs[-1]["file"], "position": 900}, logs)

    def test_duplicate_reordered_and_changed_generation_are_fatal(self):
        for logs in [self.logs() + [self.logs()[1]], self.logs()[::-1],
                     [self.logs()[0], {**self.logs()[1], "file": "other.000005"}, self.logs()[2]]]:
            with self.subTest(logs=logs), self.assertRaises(model.BackupError):
                model.validate_chain({"file": "suhoput2-bin.000004", "position": 400},
                                     {"file": "suhoput2-bin.000006", "position": 900}, logs)

    def test_bad_positions_and_target_before_base_are_fatal(self):
        for start, end in [(0, 900), (1001, 900), (True, 900), (400, 1001), (800, 700)]:
            with self.subTest(start=start, end=end), self.assertRaises(model.BackupError):
                model.validate_chain({"file": "suhoput2-bin.000004", "position": start},
                                     {"file": "suhoput2-bin.000004", "position": end}, self.logs())

    def test_missing_hash_and_empty_chain_are_fatal(self):
        for logs in [[], [{**self.logs()[0], "sha256": ""}]]:
            with self.assertRaises(model.BackupError):
                model.validate_chain({"file": "suhoput2-bin.000004", "position": 400},
                                     {"file": "suhoput2-bin.000004", "position": 900}, logs)

    def test_heartbeat_lag_future_and_bad_timestamps(self):
        self.assertEqual(model.check_lag("2026-10-11T16:59:10Z", self.now), 50)
        for timestamp in ["2026-10-11T16:58:59Z", "2026-10-11T17:00:01Z",
                          "2026-10-11T16:59:30", "not-a-time"]:
            with self.subTest(timestamp=timestamp), self.assertRaises(model.BackupError):
                model.check_lag(timestamp, self.now)

    def inventory(self, data=b"synthetic media"):
        return [{"path": "uploads/2026/10/sample.bin", "size": len(data),
                 "sha256": hashlib.sha256(data).hexdigest()}]

    def test_restored_content_and_referenced_media(self):
        with tempfile.TemporaryDirectory(dir=FIXTURES) as directory:
            root = pathlib.Path(directory)
            item = root / self.inventory()[0]["path"]
            item.parent.mkdir(parents=True)
            item.write_bytes(b"synthetic media")
            result = model.verify_files(root, self.inventory(), [self.inventory()[0]["path"]])
            self.assertEqual(result["verified_files"], 1)
            self.assertEqual(result["referenced_media"], 1)
            item.write_bytes(b"corrupted media")
            with self.assertRaises(model.BackupError):
                model.verify_files(root, self.inventory(), [self.inventory()[0]["path"]])

    def test_missing_reference_and_file_are_fatal(self):
        with tempfile.TemporaryDirectory(dir=FIXTURES) as directory:
            with self.assertRaises(model.BackupError):
                model.verify_files(pathlib.Path(directory), self.inventory(), [])
            with self.assertRaises(model.BackupError):
                model.verify_files(pathlib.Path(directory), [], ["uploads/missing.jpg"])

    def test_unsafe_paths_duplicates_symlinks_and_symlink_root_are_fatal(self):
        with tempfile.TemporaryDirectory(dir=FIXTURES) as directory:
            root = pathlib.Path(directory)
            for path in ["../outside", "/absolute", "C:/outside", "x\\y", "a/../b", "./a", "a//b"]:
                with self.subTest(path=path), self.assertRaises(model.BackupError):
                    model.verify_files(root, [{**self.inventory()[0], "path": path}], [])
            with self.assertRaises(model.BackupError):
                model.verify_files(root, self.inventory() * 2, [])
            (root / "real").mkdir()
            required_symlink(self, root / "link", root / "real")
            with self.assertRaises(model.BackupError):
                model.verify_files(root / "link", [], [])
            with self.assertRaises(model.BackupError):
                model.verify_files(root, [{**self.inventory()[0], "path": "link/file"}], [])

    def test_actual_content_hash_required_even_when_size_matches(self):
        with tempfile.TemporaryDirectory(dir=FIXTURES) as directory:
            root = pathlib.Path(directory)
            item = root / self.inventory()[0]["path"]
            item.parent.mkdir(parents=True)
            item.write_bytes(b"SYnthetic media")
            with self.assertRaises(model.BackupError):
                model.verify_files(root, self.inventory(), [])

    def snapshots(self):
        return [{"id": str(n) * 64, "time": (self.now - dt.timedelta(days=age)).isoformat(),
                 "kind": kind} for n, age, kind in [(1, 32, "full"), (2, 30.5, "full"),
                                                   (3, 30.25, "binlog"), (4, 29, "hourly"),
                                                   (5, 28, "binlog")]]

    def test_retention_keeps_anchor_and_its_logs(self):
        result = model.retention_plan(self.snapshots(), self.now)
        self.assertEqual(result["delete_ids"], ["1" * 64])
        self.assertEqual(result["anchor_id"], "2" * 64)
        self.assertFalse(result["apply_allowed"])

    def test_unknown_snapshot_future_and_missing_anchor_block_deletion(self):
        for snapshots in [[{**self.snapshots()[0], "kind": "unknown"}],
                          [{**self.snapshots()[0], "time": (self.now + dt.timedelta(days=1)).isoformat()}],
                          [x for x in self.snapshots() if x["kind"] != "full"]]:
            with self.assertRaises(model.BackupError):
                model.retention_plan(snapshots, self.now)

    def test_new_repository_reports_short_history(self):
        result = model.retention_plan([self.snapshots()[3], {**self.snapshots()[4], "kind": "full"}], self.now)
        self.assertFalse(result["anchor_before_cutoff"])
        self.assertFalse(result["history_coverage_verified"])
        self.assertEqual(result["delete_ids"], [])

    def test_old_full_alone_cannot_prove_continuous_30_day_history(self):
        result = model.retention_plan([self.snapshots()[0]], self.now)
        self.assertFalse(result.get("complete_30_day_history", False))
        self.assertEqual(result["delete_ids"], [])

    def test_linux_symlink_fixture_failure_cannot_be_skipped(self):
        with mock.patch.object(pathlib.Path, "symlink_to", side_effect=OSError("fixture unavailable")), \
                mock.patch.object(sys, "platform", "linux"):
            with self.assertRaisesRegex(AssertionError, "Required symlink fixture failed"):
                try:
                    required_symlink(self, pathlib.Path("unused-link"), pathlib.Path("unused-target"))
                except unittest.SkipTest:
                    self.fail("Linux CI silently skipped required symlink check")

    def test_cost_includes_requests_egress_and_storage(self):
        result = model.cost_projection({"storage_gib": 10, "egress_gib": 2,
                                        "put_requests": 43200, "get_requests": 3000, "delete_requests": 1000},
                                       {"storage_rub_gib_month": 5, "egress_rub_gib": 2,
                                        "put_rub_1000": 1, "get_rub_1000": 0.5, "delete_rub_1000": 0.2},
                                       budget_rub=100, max_gib=20)
        self.assertEqual(result["projected_rub"], "98.9")
        self.assertFalse(result["over_limit"])

    def test_missing_tariffs_and_exceeded_limits_are_visible(self):
        usage = {"storage_gib": 10, "egress_gib": 2, "put_requests": 43200,
                 "get_requests": 3000, "delete_requests": 1000}
        rates = {"storage_rub_gib_month": 5, "egress_rub_gib": 2,
                 "put_rub_1000": 1, "get_rub_1000": 0.5, "delete_rub_1000": 0.2}
        with self.assertRaises(model.BackupError):
            model.cost_projection(usage, {}, budget_rub=100, max_gib=20)
        for budget, gib in [(90, 20), (100, 9)]:
            self.assertTrue(model.cost_projection(usage, rates, budget_rub=budget, max_gib=gib)["over_limit"])
        with self.assertRaises(model.BackupError):
            model.cost_projection(usage, {**rates, "put_rub_1000": "NaN"}, budget_rub=100, max_gib=20)

    def test_cost_overflow_returns_controlled_cli_error(self):
        evidence = {"usage": {"storage_gib": "1e999999", "egress_gib": 0, "put_requests": 0,
                              "get_requests": 0, "delete_requests": 0},
                    "rates": {"storage_rub_gib_month": 10, "egress_rub_gib": 0,
                              "put_rub_1000": 0, "get_rub_1000": 0, "delete_rub_1000": 0},
                    "budget_rub": 100, "max_gib": 100}
        with tempfile.TemporaryDirectory(dir=FIXTURES) as directory:
            path = pathlib.Path(directory) / "projection.json"
            path.write_text(json.dumps(evidence), encoding="utf-8")
            result = subprocess.run([sys.executable, str(MODULE), "cost", str(path)],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertTrue(result.stdout.strip(), "CLI returned no controlled error JSON")
            self.assertEqual(json.loads(result.stdout)["error"], "Invalid or insufficient backup evidence")
            self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
