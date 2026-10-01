from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from skilllatch import (
    PolicyError,
    audit_line_to_json,
    evaluate,
    hash_skill_tree,
    load_audit_log,
    make_audit_line,
    verify_audit_log,
    verify_receipt,
)
from skilllatch.core import _sha256

AT = datetime(2026, 10, 1, 12, tzinfo=UTC)
PROJECT = Path(__file__).resolve().parents[1]


class LiveReceipts:
    """Small fixture harness producing real engine receipts."""

    def __init__(self, root: Path):
        self.skill = root / "skill"
        self.skill.mkdir()
        (self.skill / "SKILL.md").write_text("# Test skill\n", encoding="utf-8")
        self.workspace = root / "workspace"
        (self.workspace / "recipes").mkdir(parents=True)
        (self.workspace / "recipes" / "soup.txt").write_text("soup\n", encoding="utf-8")
        (self.workspace / "private.txt").write_text("private\n", encoding="utf-8")
        digest = hash_skill_tree(self.skill)
        self.manifest = {
            "version": 1,
            "skill": {"name": "test-skill", "digest": digest},
            "capabilities": {
                "files": {
                    "read": [{"path": "recipes", "recursive": True}],
                    "write": [],
                },
                "network": [],
                "commands": [],
            },
        }
        self.grant = {
            "version": 2,
            "session_id": "session-1",
            "task_id": "task-1",
            "skill_digest": digest,
            "workspace_id": "test-workspace",
            "issued_at": "2026-10-01T11:00:00Z",
            "expires_at": "2026-10-01T13:00:00Z",
            "capabilities": {
                "files": {
                    "read": [{"path": "recipes/soup.txt", "recursive": False}],
                    "write": [],
                },
                "network": [],
                "commands": [],
            },
        }

    def decide(self, path: str = "recipes/soup.txt") -> dict:
        return evaluate(
            self.skill,
            self.workspace,
            self.manifest,
            self.grant,
            {
                "session_id": "session-1",
                "task_id": "task-1",
                "kind": "file",
                "action": "read",
                "path": path,
            },
            at=AT,
            workspace_id="test-workspace",
        )


def constructed_v1_receipt() -> dict:
    receipt = {
        "version": 1,
        "allowed": True,
        "reason_code": "allowed",
        "reason": "constructed v1 receipt for verification tests",
        "evaluated_at": "2026-10-01T12:00:00Z",
        "skill_digest": "sha256:" + "1" * 64,
        "manifest_hash": "sha256:" + "2" * 64,
        "grant_hash": "sha256:" + "3" * 64,
        "request_hash": "sha256:" + "4" * 64,
    }
    receipt["digest"] = _sha256(receipt)
    return receipt


class VerifyReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.live = LiveReceipts(Path(self.temp.name))

    def assert_code(self, receipt, code) -> None:
        with self.assertRaises(PolicyError) as error:
            verify_receipt(receipt)
        self.assertEqual(error.exception.code, code)

    def test_live_v2_allow_receipt_is_valid(self):
        receipt = self.live.decide()["receipt"]
        outcome = verify_receipt(receipt)
        self.assertEqual(outcome, {"valid": True, "version": 2, "digest": receipt["digest"]})

    def test_live_v2_denial_receipt_is_valid(self):
        receipt = self.live.decide("private.txt")["receipt"]
        outcome = verify_receipt(receipt)
        self.assertEqual(outcome, {"valid": True, "version": 2, "digest": receipt["digest"]})

    def test_constructed_v1_receipt_is_valid(self):
        receipt = constructed_v1_receipt()
        outcome = verify_receipt(receipt)
        self.assertEqual(outcome, {"valid": True, "version": 1, "digest": receipt["digest"]})

    def test_non_dict_is_invalid(self):
        self.assert_code(["not", "a", "receipt"], "invalid_receipt")

    def test_unsupported_versions(self):
        for version in (3, "2"):
            with self.subTest(version=version):
                receipt = self.live.decide()["receipt"]
                receipt["version"] = version
                self.assert_code(receipt, "unsupported_version")

    def test_missing_and_extra_keys_are_invalid(self):
        receipt = self.live.decide()["receipt"]
        del receipt["manifest_hash"]
        self.assert_code(receipt, "invalid_receipt")
        receipt = self.live.decide()["receipt"]
        receipt["surprise"] = True
        self.assert_code(receipt, "invalid_receipt")

    def test_allowed_must_be_boolean(self):
        receipt = self.live.decide()["receipt"]
        receipt["allowed"] = 1
        self.assert_code(receipt, "invalid_receipt")

    def test_skill_digest_must_be_null_or_digest(self):
        receipt = self.live.decide()["receipt"]
        receipt["skill_digest"] = "bogus"
        self.assert_code(receipt, "invalid_receipt")
        receipt = self.live.decide()["receipt"]
        receipt["skill_digest"] = None
        receipt["digest"] = _sha256(
            {key: value for key, value in receipt.items() if key != "digest"}
        )
        self.assertTrue(verify_receipt(receipt)["valid"])

    def test_workspace_binding_must_be_a_known_value(self):
        receipt = self.live.decide()["receipt"]
        receipt["workspace_binding"] = "bogus"
        self.assert_code(receipt, "invalid_receipt")

    def test_v1_receipt_must_not_carry_workspace_fields(self):
        receipt = constructed_v1_receipt()
        receipt["workspace_id"] = "ws"
        self.assert_code(receipt, "invalid_receipt")

    def test_tampered_reason_breaks_the_digest(self):
        receipt = self.live.decide()["receipt"]
        receipt["reason"] = "edited after the fact"
        self.assert_code(receipt, "receipt_digest_mismatch")

    def test_format_valid_wrong_digest_is_a_mismatch(self):
        receipt = self.live.decide()["receipt"]
        receipt["digest"] = "sha256:" + "0" * 64
        self.assert_code(receipt, "receipt_digest_mismatch")

    def test_evaluated_at_must_be_a_real_utc_timestamp(self):
        for value in ("2026-13-01T00:00:00Z", "2026-10-01 12:00:00Z"):
            with self.subTest(value=value):
                receipt = self.live.decide()["receipt"]
                receipt["evaluated_at"] = value
                self.assert_code(receipt, "invalid_receipt")


class AuditLogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        live = LiveReceipts(self.root)
        receipts = [
            live.decide()["receipt"],
            live.decide("private.txt")["receipt"],
            live.decide("recipes/missing.txt")["receipt"],
        ]
        self.lines = []
        for receipt in receipts:
            self.lines.append(
                make_audit_line(
                    receipt,
                    self.lines[-1]["line_digest"] if self.lines else None,
                    len(self.lines) + 1,
                )
            )

    def assert_log_code(self, lines, code) -> None:
        with self.assertRaises(PolicyError) as error:
            verify_audit_log(lines)
        self.assertEqual(error.exception.code, code)

    def test_three_line_chain_verifies(self):
        self.assertEqual(verify_audit_log(self.lines), {"valid": True, "lines": 3})

    def test_make_audit_line_rejects_bad_links(self):
        receipt = self.lines[0]["receipt"]
        with self.assertRaises(PolicyError) as error:
            make_audit_line(receipt, "sha256:" + "0" * 64, 1)
        self.assertEqual(error.exception.code, "invalid_audit_log")
        with self.assertRaises(PolicyError) as error:
            make_audit_line(receipt, "bogus", 2)
        self.assertEqual(error.exception.code, "invalid_audit_log")
        with self.assertRaises(PolicyError) as error:
            make_audit_line(receipt, None, 0)
        self.assertEqual(error.exception.code, "invalid_audit_log")

    def test_empty_and_non_list_logs_are_invalid(self):
        self.assert_log_code([], "invalid_audit_log")
        self.assert_log_code({"line": 1}, "invalid_audit_log")

    def test_renumbered_line_is_invalid(self):
        tampered = copy.deepcopy(self.lines)
        tampered[1]["line"] = 3
        self.assert_log_code(tampered, "invalid_audit_log")

    def test_edited_receipt_breaks_its_own_digest(self):
        tampered = copy.deepcopy(self.lines)
        tampered[1]["receipt"]["reason"] = "edited"
        with self.assertRaises(PolicyError) as error:
            verify_audit_log(tampered)
        self.assertEqual(error.exception.code, "receipt_digest_mismatch")
        self.assertIn("line 2", error.exception.reason)

    def test_edited_prev_digest_breaks_the_chain(self):
        tampered = copy.deepcopy(self.lines)
        tampered[1]["prev_digest"] = "sha256:" + "0" * 64
        self.assert_log_code(tampered, "audit_chain_mismatch")

    def test_replaced_line_digest_breaks_the_chain(self):
        tampered = copy.deepcopy(self.lines)
        tampered[1]["line_digest"] = "sha256:" + "f" * 64
        self.assert_log_code(tampered, "audit_chain_mismatch")

    def test_deleted_middle_line_breaks_the_chain(self):
        tampered = copy.deepcopy(self.lines)
        del tampered[1]
        self.assert_log_code(tampered, "audit_chain_mismatch")

    def test_load_audit_log_round_trip(self):
        path = self.root / "audit.jsonl"
        path.write_text(
            "".join(audit_line_to_json(line) + "\n" for line in self.lines),
            encoding="utf-8",
            newline="\n",
        )
        loaded = load_audit_log(path)
        self.assertEqual(loaded, self.lines)
        self.assertEqual(verify_audit_log(loaded), {"valid": True, "lines": 3})

    def test_load_audit_log_rejects_bad_content(self):
        cases = {
            "blank": audit_line_to_json(self.lines[0]) + "\n\n"
            + audit_line_to_json(self.lines[1]) + "\n",
            "duplicate-key": '{"line": 1, "line": 2}\n',
            "nan": "NaN\n",
        }
        for name, content in cases.items():
            with self.subTest(name=name):
                path = self.root / f"{name}.jsonl"
                path.write_text(content, encoding="utf-8", newline="\n")
                with self.assertRaises(PolicyError) as error:
                    load_audit_log(path)
                self.assertEqual(error.exception.code, "invalid_audit_log")
        with self.assertRaises(PolicyError) as error:
            load_audit_log(self.root / "missing.jsonl")
        self.assertEqual(error.exception.code, "invalid_audit_log")


class CliVerifyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        live = LiveReceipts(self.root)
        self.receipt = live.decide()["receipt"]
        self.lines = []
        for receipt in (
            self.receipt,
            live.decide("private.txt")["receipt"],
            self.receipt,
        ):
            self.lines.append(
                make_audit_line(
                    receipt,
                    self.lines[-1]["line_digest"] if self.lines else None,
                    len(self.lines) + 1,
                )
            )

    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "skilllatch", *arguments],
            cwd=PROJECT,
            capture_output=True,
            text=True,
            check=False,
        )

    def write_receipt(self, name: str, receipt) -> Path:
        path = self.root / name
        path.write_text(json.dumps(receipt), encoding="utf-8")
        return path

    def test_verify_accepts_a_live_receipt(self):
        path = self.write_receipt("receipt.json", self.receipt)
        result = self.run_cli("verify", "--receipt", str(path))
        self.assertEqual(result.returncode, 0, result.stderr)
        outcome = json.loads(result.stdout)
        self.assertTrue(outcome["valid"])
        self.assertEqual(outcome["version"], 2)
        self.assertEqual(outcome["digest"], self.receipt["digest"])

    def test_verify_rejects_a_tampered_receipt(self):
        tampered = copy.deepcopy(self.receipt)
        tampered["reason"] = "edited"
        path = self.write_receipt("tampered.json", tampered)
        result = self.run_cli("verify", "--receipt", str(path))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(json.loads(result.stdout)["reason_code"], "receipt_digest_mismatch")

    def test_verify_rejects_non_json_input(self):
        path = self.root / "not-json.json"
        path.write_text("this is not json", encoding="utf-8")
        result = self.run_cli("verify", "--receipt", str(path))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(json.loads(result.stdout)["valid"])

    def test_verify_without_receipt_argument_is_a_usage_error(self):
        result = self.run_cli("verify")
        self.assertEqual(result.returncode, 64, result.stderr)

    def test_verify_log_accepts_a_chained_log(self):
        path = self.root / "audit.jsonl"
        path.write_text(
            "".join(audit_line_to_json(line) + "\n" for line in self.lines),
            encoding="utf-8",
            newline="\n",
        )
        result = self.run_cli("verify-log", "--log", str(path))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"valid": True, "lines": 3})

    def test_verify_log_rejects_a_tampered_log(self):
        tampered = copy.deepcopy(self.lines)
        tampered[1]["receipt"]["allowed"] = True
        path = self.root / "tampered.jsonl"
        path.write_text(
            "".join(audit_line_to_json(line) + "\n" for line in tampered),
            encoding="utf-8",
            newline="\n",
        )
        result = self.run_cli("verify-log", "--log", str(path))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(json.loads(result.stdout)["valid"])

    def test_no_arguments_is_a_usage_error(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 64, result.stderr)


if __name__ == "__main__":
    unittest.main()
