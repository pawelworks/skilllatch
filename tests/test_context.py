from __future__ import annotations

import copy
import inspect
import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from skilllatch import PolicyError, build_context, evaluate, hash_skill_tree
from skilllatch.context import ATTRIBUTION, SCHEMA
from skilllatch.core import _sha256
from skilllatch.skillspector import load_scan_report

AT = datetime(2026, 10, 1, 12, tzinfo=UTC)
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
CANARY = "CANARY-SECRET-7f3c9e"
FORBIDDEN_KEYS = {"path", "content", "arguments"}


def _all_keys(node):
    keys = set()
    if isinstance(node, dict):
        for key, value in node.items():
            keys.add(key)
            keys |= _all_keys(value)
    elif isinstance(node, list):
        for item in node:
            keys |= _all_keys(item)
    return keys


class BuildContextTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.skill = self.root / "skill"
        self.skill.mkdir()
        (self.skill / "SKILL.md").write_text("# Test skill\n", encoding="utf-8")
        self.workspace = self.root / "workspace"
        (self.workspace / "recipes").mkdir(parents=True)
        (self.workspace / "recipes" / "soup.txt").write_text("soup\n", encoding="utf-8")
        digest = hash_skill_tree(self.skill)
        self.digest = digest
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

    def base_kwargs(self):
        return {
            "session_id": "session-1",
            "task_id": "task-1",
            "workspace_id": "test-workspace",
            "skills": [
                {
                    "digest": self.digest,
                    "source": {"type": "local_dir"},
                    "name": "test-skill",
                },
                {
                    "digest": DIGEST_A,
                    "source": {
                        "type": "mcp",
                        "server_identity": "srv.example",
                        "uri": "mcp://srv.example/skills/remote-skill",
                    },
                },
            ],
            "project_instructions": [
                {"label": "AGENTS.md", "digest": DIGEST_B},
                {"label": "docs/STYLE.md", "digest": DIGEST_C},
            ],
            "tool": {"name": "file", "schema_digest": DIGEST_C},
            "grant_hash": DIGEST_B,
            "at": AT,
        }

    def assert_invalid_context(self, **overrides):
        kwargs = self.base_kwargs()
        kwargs.update(overrides)
        with self.assertRaises(PolicyError) as error:
            build_context(**kwargs)
        self.assertEqual(error.exception.code, "invalid_context")

    def test_determinism_same_inputs_identical_envelope(self):
        first = build_context(**self.base_kwargs())
        second = build_context(**self.base_kwargs())
        self.assertEqual(first, second)

    def test_enumeration_order_does_not_change_the_digest(self):
        kwargs = self.base_kwargs()
        forward = build_context(**kwargs)
        permuted = self.base_kwargs()
        permuted["skills"] = list(reversed(permuted["skills"]))
        permuted["project_instructions"] = list(
            reversed(permuted["project_instructions"])
        )
        backward = build_context(**permuted)
        self.assertEqual(forward["digest"], backward["digest"])
        # Duplicates are preserved, not deduplicated.
        doubled = self.base_kwargs()
        doubled["skills"] = doubled["skills"] + [doubled["skills"][0]]
        envelope = build_context(**doubled)
        self.assertEqual(len(envelope["skills"]), 3)

    def test_digest_recomputes_and_field_flips_break_it(self):
        envelope = build_context(**self.base_kwargs())
        body = {key: value for key, value in envelope.items() if key != "digest"}
        self.assertEqual(_sha256(body), envelope["digest"])
        for field, value in (
            ("session_id", "other-session"),
            ("task_id", "other-task"),
            ("workspace_id", None),
            ("grant_hash", DIGEST_A),
        ):
            flipped = copy.deepcopy(envelope)
            flipped[field] = value
            body = {key: item for key, item in flipped.items() if key != "digest"}
            self.assertNotEqual(_sha256(body), flipped["digest"], field)

    def test_recorded_at_and_schema_constants(self):
        envelope = build_context(**self.base_kwargs())
        self.assertEqual(envelope["schema"], SCHEMA)
        self.assertEqual(envelope["schema"], "skilllatch.context.v1")
        self.assertEqual(envelope["recorded_at"], "2026-10-01T12:00:00Z")

    def test_local_dir_and_mcp_sources_are_accepted(self):
        envelope = build_context(**self.base_kwargs())
        sources = {entry["source"]["type"] for entry in envelope["skills"]}
        self.assertEqual(sources, {"local_dir", "mcp"})

    def test_workspace_id_and_instructions_default_to_absent_shapes(self):
        kwargs = self.base_kwargs()
        kwargs["workspace_id"] = None
        kwargs["project_instructions"] = None
        envelope = build_context(**kwargs)
        self.assertIsNone(envelope["workspace_id"])
        self.assertEqual(envelope["project_instructions"], [])

    def test_bad_sources_and_digests_are_rejected(self):
        base = self.base_kwargs()["skills"][0]
        for bad_source in (
            {"type": "remote"},
            {"type": "mcp", "uri": "mcp://srv/skill"},
            {"type": "mcp", "server_identity": "srv", "uri": "u", "extra": 1},
            {"type": "local_dir", "path": "/etc/skill"},
        ):
            self.assert_invalid_context(skills=[{"digest": DIGEST_A, "source": bad_source}])
        self.assert_invalid_context(
            skills=[{"digest": "not-a-digest", "source": base["source"]}]
        )
        self.assert_invalid_context(skills=[{"source": base["source"]}])
        self.assert_invalid_context(
            skills=[{"digest": DIGEST_A, "source": base["source"], "extra": 1}]
        )
        self.assert_invalid_context(skills="not-a-list")

    def test_attribution_is_constant_and_not_a_parameter(self):
        envelope = build_context(**self.base_kwargs())
        self.assertEqual(envelope["attribution"], ATTRIBUTION)
        self.assertEqual(envelope["attribution"], "unknown")
        self.assertNotIn("attribution", inspect.signature(build_context).parameters)
        kwargs = self.base_kwargs()
        kwargs["attribution"] = "test-skill"
        with self.assertRaises(TypeError):
            build_context(**kwargs)

    def test_validation_of_identity_time_tool_and_grant_hash(self):
        self.assert_invalid_context(session_id="")
        self.assert_invalid_context(session_id="bad\nid")
        self.assert_invalid_context(task_id="")
        self.assert_invalid_context(workspace_id="")
        self.assert_invalid_context(grant_hash="sha256:xyz")
        self.assert_invalid_context(grant_hash=None)
        self.assert_invalid_context(tool={"name": "file"})
        self.assert_invalid_context(
            tool={"name": "file", "schema_digest": DIGEST_A, "extra": 1}
        )
        self.assert_invalid_context(tool={"name": "", "schema_digest": DIGEST_A})
        self.assert_invalid_context(tool={"name": "file", "schema_digest": "nope"})
        kwargs = self.base_kwargs()
        kwargs["at"] = datetime(2026, 10, 1, 12)  # noqa: DTZ001 — intentionally naive clock
        with self.assertRaises(PolicyError) as error:
            build_context(**kwargs)
        self.assertEqual(error.exception.code, "invalid_time")

    def test_no_secret_leakage_from_advisory_metadata(self):
        report = {
            "tool": "skillspector",
            "scan_mode": "static",
            "subject_digest": self.digest,
            "coverage": {"files_scanned": 1, "note": CANARY},
            "extra_metadata": {"token": CANARY},
        }
        report_path = self.root / "report.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        advisory = load_scan_report(report_path, skill_dir=self.skill)
        self.assertIn(CANARY, json.dumps(advisory))  # the full advisory echoes it
        envelope = build_context(**self.base_kwargs(), advisory=advisory)
        encoded = json.dumps(envelope)
        self.assertNotIn(CANARY, encoded)
        self.assertEqual(envelope["advisory"]["report_hash"], advisory["report_hash"])
        self.assertEqual(
            set(envelope["advisory"]),
            {"schema", "scanner", "scan_mode", "digest_match", "report_hash"},
        )
        self.assertFalse(_all_keys(envelope) & FORBIDDEN_KEYS)
        self.assertFalse(_all_keys(envelope) & {"coverage", "metadata", "warnings"})

    def test_advisory_shape_violations(self):
        self.assert_invalid_context(advisory={"schema": "other.v1", "report_hash": DIGEST_A})
        self.assert_invalid_context(
            advisory={"schema": "skilllatch.scan_advisory.v1", "report_hash": "nope"}
        )
        self.assert_invalid_context(advisory="not-a-dict")

    def test_grant_hash_round_trip_from_a_live_receipt(self):
        outcome = evaluate(
            self.skill,
            self.workspace,
            self.manifest,
            self.grant,
            {
                "session_id": "session-1",
                "task_id": "task-1",
                "kind": "file",
                "action": "read",
                "path": "recipes/soup.txt",
            },
            at=AT,
            workspace_id="test-workspace",
        )
        self.assertTrue(outcome["allowed"])
        kwargs = self.base_kwargs()
        kwargs["grant_hash"] = outcome["receipt"]["grant_hash"]
        envelope = build_context(**kwargs)
        self.assertEqual(envelope["grant_hash"], outcome["receipt"]["grant_hash"])


if __name__ == "__main__":
    unittest.main()
