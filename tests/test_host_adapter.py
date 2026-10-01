from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from skilllatch import build_context, hash_skill_tree
from skilllatch.core import _sha256

AT = datetime(2026, 10, 1, 12, tzinfo=UTC)
PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "examples"))

from host_adapter import (
    GatedHost,
    RecordingTool,
    make_command_stub,
    make_fetch_stub,
    make_file_tool,
)


def exploding(name: str) -> RecordingTool:
    def run(arg):
        raise AssertionError(f"{name} tool must never be invoked for a denial")

    return RecordingTool(name, run)


class GatedHostTests(unittest.TestCase):
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
        (self.workspace / "private.txt").write_text("private\n", encoding="utf-8")
        digest = hash_skill_tree(self.skill)
        self.manifest = {
            "version": 1,
            "skill": {"name": "test-skill", "digest": digest},
            "capabilities": {
                "files": {
                    "read": [{"path": "recipes", "recursive": True}],
                    "write": [{"path": "notes", "recursive": True}],
                },
                "network": ["https://recipes.example"],
                "commands": [["git", "status", "--short"]],
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

    def make_host(self, **kwargs):
        options = {"workspace_id": "test-workspace", "clock": lambda: AT}
        options.update(kwargs)
        return GatedHost(
            self.skill, self.workspace, self.manifest, self.grant, **options
        )

    def read_request(self, path="recipes/soup.txt"):
        return {
            "session_id": "session-1",
            "task_id": "task-1",
            "kind": "file",
            "action": "read",
            "path": path,
        }

    def test_allow_dispatches_exactly_once_with_bound_receipt(self):
        host = self.make_host()
        file_tool = make_file_tool(self.workspace)
        fetch = make_fetch_stub()
        host.register_tool("file", file_tool)
        host.register_tool("network", fetch)
        outcome = host.dispatch(self.read_request())
        self.assertTrue(outcome["allowed"])
        self.assertTrue(outcome["dispatched"])
        self.assertIsNone(outcome["error"])
        self.assertEqual(outcome["tool_result"], "soup\n")
        self.assertEqual(len(file_tool.calls), 1)
        self.assertEqual(
            file_tool.calls[0], {"action": "read", "path": "recipes/soup.txt"}
        )
        self.assertEqual(fetch.calls, [])
        receipt = outcome["receipt"]
        body = {key: value for key, value in receipt.items() if key != "digest"}
        self.assertEqual(_sha256(body), receipt["digest"])
        self.assertEqual(receipt["version"], 2)
        self.assertEqual(receipt["workspace_binding"], "pinned")

    def test_denied_file_and_network_requests_never_reach_a_tool(self):
        host = self.make_host()
        file_tool = exploding("file")
        fetch = exploding("network")
        host.register_tool("file", file_tool)
        host.register_tool("network", fetch)
        denied_file = host.dispatch(self.read_request("private.txt"))
        self.assertFalse(denied_file["allowed"])
        self.assertEqual(denied_file["reason_code"], "capability_not_granted")
        self.assertFalse(denied_file["dispatched"])
        self.assertIsNone(denied_file["error"])
        self.assertIsNotNone(denied_file["receipt"])
        denied_network = host.dispatch(
            {
                "session_id": "session-1",
                "task_id": "task-1",
                "kind": "network",
                "url": "https://recipes.example/collect",
            }
        )
        self.assertEqual(denied_network["reason_code"], "capability_not_granted")
        self.assertFalse(denied_network["dispatched"])
        self.assertEqual(file_tool.calls, [])
        self.assertEqual(fetch.calls, [])

    def test_policy_error_is_treated_as_a_denial(self):
        host = self.make_host()
        file_tool = exploding("file")
        host.register_tool("file", file_tool)
        outcome = host.dispatch(
            {
                "session_id": "session-1",
                "task_id": "task-1",
                "kind": "file",
                "action": "read",
                "path": "recipes/soup.txt",
                "extra": float("inf"),
            }
        )
        self.assertFalse(outcome["allowed"])
        self.assertEqual(outcome["reason_code"], "invalid_json_value")
        self.assertIsNone(outcome["receipt"])
        self.assertEqual(outcome["error"], "policy_error")
        self.assertFalse(outcome["dispatched"])
        self.assertEqual(file_tool.calls, [])

    def test_skill_mutation_after_construction_is_denied(self):
        host = self.make_host()
        file_tool = make_file_tool(self.workspace)
        host.register_tool("file", file_tool)
        (self.skill / "SKILL.md").write_text("# Mutated\n", encoding="utf-8")
        outcome = host.dispatch(self.read_request())
        self.assertFalse(outcome["allowed"])
        self.assertEqual(outcome["reason_code"], "skill_digest_mismatch")
        self.assertFalse(outcome["dispatched"])
        self.assertEqual(file_tool.calls, [])

    def test_workspace_pin_is_enforced(self):
        host = self.make_host(workspace_id="other-workspace")
        file_tool = exploding("file")
        host.register_tool("file", file_tool)
        outcome = host.dispatch(self.read_request())
        self.assertFalse(outcome["allowed"])
        self.assertEqual(outcome["reason_code"], "workspace_mismatch")
        self.assertEqual(file_tool.calls, [])

    def test_unregistered_kind_fails_closed(self):
        grant = copy.deepcopy(self.grant)
        grant["capabilities"]["network"] = ["https://recipes.example"]
        host = GatedHost(
            self.skill,
            self.workspace,
            self.manifest,
            grant,
            workspace_id="test-workspace",
            clock=lambda: AT,
        )
        outcome = host.dispatch(
            {
                "session_id": "session-1",
                "task_id": "task-1",
                "kind": "network",
                "url": "https://recipes.example/page",
            }
        )
        self.assertFalse(outcome["allowed"])
        self.assertEqual(outcome["reason_code"], "no_tool_registered")
        self.assertFalse(outcome["dispatched"])
        self.assertIsNone(outcome["error"])
        self.assertIsNotNone(outcome["receipt"])

    def test_manifest_and_grant_are_frozen_at_construction(self):
        manifest = copy.deepcopy(self.manifest)
        grant = copy.deepcopy(self.grant)
        host = GatedHost(
            self.skill,
            self.workspace,
            manifest,
            grant,
            workspace_id="test-workspace",
            clock=lambda: AT,
        )
        file_tool = make_file_tool(self.workspace)
        fetch = exploding("network")
        host.register_tool("file", file_tool)
        host.register_tool("network", fetch)
        manifest["capabilities"]["network"] = ["https://attacker.example"]
        grant["capabilities"]["network"] = ["https://attacker.example"]
        grant["task_id"] = "hijacked"
        allowed = host.dispatch(self.read_request())
        self.assertTrue(allowed["allowed"])
        denied = host.dispatch(
            {
                "session_id": "session-1",
                "task_id": "task-1",
                "kind": "network",
                "url": "https://attacker.example/collect",
            }
        )
        self.assertEqual(denied["reason_code"], "capability_not_granted")
        self.assertEqual(fetch.calls, [])

    def test_command_stub_performs_no_io(self):
        grant = copy.deepcopy(self.grant)
        grant["capabilities"]["commands"] = [["git", "status", "--short"]]
        host = GatedHost(
            self.skill,
            self.workspace,
            self.manifest,
            grant,
            workspace_id="test-workspace",
            clock=lambda: AT,
        )
        stub = make_command_stub()
        host.register_tool("command", stub)
        outcome = host.dispatch(
            {
                "session_id": "session-1",
                "task_id": "task-1",
                "kind": "command",
                "argv": ["git", "status", "--short"],
            }
        )
        self.assertTrue(outcome["dispatched"])
        self.assertEqual(outcome["tool_result"]["stdout"], "ok\n")
        self.assertEqual(stub.calls, [{"argv": ["git", "status", "--short"]}])

    def make_context(self, **overrides):
        options = {
            "session_id": "session-1",
            "task_id": "task-1",
            "workspace_id": "test-workspace",
            "skills": [
                {
                    "digest": self.manifest["skill"]["digest"],
                    "source": {"type": "local_dir"},
                    "name": "test-skill",
                }
            ],
            "project_instructions": [
                {"label": "AGENTS.md", "digest": "sha256:" + "1" * 64}
            ],
            "tool": {"name": "file", "schema_digest": "sha256:" + "2" * 64},
            "grant_hash": "sha256:" + "3" * 64,
            "at": AT,
        }
        options.update(overrides)
        return build_context(**options)

    def test_context_envelope_is_attached_on_allow_and_deny(self):
        context = self.make_context()
        host = self.make_host(context=context)
        host.register_tool("file", make_file_tool(self.workspace))
        allowed = host.dispatch(self.read_request())
        self.assertTrue(allowed["allowed"])
        self.assertEqual(allowed["context"], context)
        denied = host.dispatch(self.read_request("private.txt"))
        self.assertFalse(denied["allowed"])
        self.assertEqual(denied["context"], context)
        errored = host.dispatch({**self.read_request(), "extra": float("inf")})
        self.assertEqual(errored["error"], "policy_error")
        self.assertEqual(errored["context"], context)

    def test_context_is_frozen_against_caller_mutation(self):
        context = self.make_context()
        host = self.make_host(context=context)
        host.register_tool("file", make_file_tool(self.workspace))
        context["session_id"] = "mutated"
        context["skills"].append(
            {"digest": "sha256:" + "9" * 64, "source": {"type": "local_dir"}}
        )
        first = host.dispatch(self.read_request())
        self.assertEqual(first["context"]["session_id"], "session-1")
        self.assertEqual(len(first["context"]["skills"]), 1)
        first["context"]["session_id"] = "mutated-again"
        second = host.dispatch(self.read_request())
        self.assertEqual(second["context"]["session_id"], "session-1")
        self.assertEqual(host.context["session_id"], "session-1")

    def test_per_call_context_overrides_constructor_value(self):
        constructor_context = self.make_context()
        call_context = self.make_context(
            tool={"name": "other-tool", "schema_digest": "sha256:" + "4" * 64}
        )
        host = self.make_host(context=constructor_context)
        host.register_tool("file", make_file_tool(self.workspace))
        overridden = host.dispatch(self.read_request(), context=call_context)
        self.assertEqual(overridden["context"], call_context)
        fallback = host.dispatch(self.read_request())
        self.assertEqual(fallback["context"], constructor_context)
        suppressed = host.dispatch(self.read_request(), context=None)
        self.assertIsNone(suppressed["context"])

    def test_context_defaults_to_none(self):
        host = self.make_host()
        host.register_tool("file", make_file_tool(self.workspace))
        outcome = host.dispatch(self.read_request())
        self.assertIsNone(outcome["context"])
        self.assertIsNone(host.context)

    def test_advisory_behavior_is_unchanged_by_context(self):
        advisory = {
            "schema": "skilllatch.scan_advisory.v1",
            "scanner": "skillspector",
            "report_hash": "sha256:" + "5" * 64,
        }
        context = self.make_context()
        host = self.make_host(advisory=advisory, context=context)
        host.register_tool("file", make_file_tool(self.workspace))
        outcome = host.dispatch(self.read_request())
        self.assertEqual(outcome["advisory"], advisory)
        self.assertEqual(outcome["context"], context)
        advisory["scanner"] = "mutated"
        followup = host.dispatch(self.read_request())
        self.assertEqual(followup["advisory"]["scanner"], "skillspector")


if __name__ == "__main__":
    unittest.main()
