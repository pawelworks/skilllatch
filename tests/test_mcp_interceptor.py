from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from skilllatch import hash_skill_tree
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
from mcp_interceptor import McpStyleInterceptor

TOOL_MAP = {
    "read_recipe": {"kind": "file", "action": "read", "path_from": "path"},
    "write_recipe": {"kind": "file", "action": "write", "path_from": "path"},
    "http_get": {"kind": "network", "url_from": "url"},
    "run_git": {"kind": "command", "argv_from": "argv"},
}


def exploding(name: str) -> RecordingTool:
    def run(arg):
        raise AssertionError(f"{name} tool must never be invoked for a denial")

    return RecordingTool(name, run)


class McpStyleInterceptorTests(unittest.TestCase):
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

    def make_interceptor(self, *, grant=None, tools=None, **kwargs):
        options = {"session_id": "session-1", "task_id": "task-1", "mode": "enforce"}
        options.update(kwargs)
        host = GatedHost(
            self.skill,
            self.workspace,
            self.manifest,
            grant or self.grant,
            workspace_id="test-workspace",
            clock=lambda: AT,
        )
        used_tools = (
            tools
            if tools is not None
            else {
                "file": make_file_tool(self.workspace),
                "network": make_fetch_stub(),
                "command": make_command_stub(),
            }
        )
        for kind, tool in used_tools.items():
            host.register_tool(kind, tool)
        interceptor = McpStyleInterceptor(host, copy.deepcopy(TOOL_MAP), **options)
        return interceptor, used_tools

    def call_message(self, name, arguments=None, **extra):
        params = {"name": name}
        if arguments is not None:
            params["arguments"] = arguments
        message = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 1,
            "params": params,
        }
        message.update(extra)
        return message

    def test_allow_dispatches_once_and_never_mutates_the_message(self):
        interceptor, tools = self.make_interceptor()
        message = self.call_message("read_recipe", {"path": "recipes/soup.txt"})
        before = copy.deepcopy(message)
        verdict = interceptor.handle_message(message)
        self.assertEqual(message, before)
        self.assertEqual(
            set(verdict),
            {"verdict", "severity", "reason_code", "reason", "receipt", "mode"},
        )
        self.assertEqual(verdict["verdict"], "allow")
        self.assertEqual(verdict["severity"], "info")
        self.assertEqual(verdict["reason_code"], "allowed")
        self.assertEqual(verdict["mode"], "enforce")
        receipt = verdict["receipt"]
        self.assertEqual(receipt["version"], 2)
        self.assertEqual(receipt["workspace_binding"], "pinned")
        self.assertEqual(
            tools["file"].calls, [{"action": "read", "path": "recipes/soup.txt"}]
        )
        self.assertEqual(tools["network"].calls, [])
        self.assertEqual(tools["command"].calls, [])

    def test_deny_ungranted_path_never_invokes_a_tool(self):
        interceptor, _ = self.make_interceptor(
            tools={
                "file": exploding("file"),
                "network": exploding("network"),
                "command": exploding("command"),
            }
        )
        verdict = interceptor.handle_message(
            self.call_message("read_recipe", {"path": "private.txt"})
        )
        self.assertEqual(verdict["verdict"], "deny")
        self.assertEqual(verdict["severity"], "error")
        self.assertEqual(verdict["reason_code"], "capability_not_granted")
        self.assertIsNotNone(verdict["receipt"])

    def test_audit_mode_reports_warn_without_blocking(self):
        interceptor, tools = self.make_interceptor(mode="audit")
        verdict = interceptor.handle_message(
            self.call_message("read_recipe", {"path": "private.txt"})
        )
        self.assertEqual(verdict["verdict"], "allow")
        self.assertEqual(verdict["severity"], "warn")
        self.assertEqual(verdict["reason_code"], "capability_not_granted")
        self.assertTrue(
            verdict["reason"].startswith(
                "audit mode: denial reported but not blocked: "
            )
        )
        self.assertIsNotNone(verdict["receipt"])
        self.assertEqual(verdict["mode"], "audit")
        # The wrapped GatedHost still blocks at its own dispatch boundary; a
        # real host in audit mode would forward the call and only log.
        self.assertEqual(tools["file"].calls, [])

    def test_unmapped_tool_denies_in_both_modes(self):
        for mode in ("enforce", "audit"):
            with self.subTest(mode=mode):
                interceptor, tools = self.make_interceptor(mode=mode)
                verdict = interceptor.handle_message(
                    self.call_message("teleport", {"url": "https://recipes.example"})
                )
                self.assertEqual(verdict["verdict"], "deny")
                self.assertEqual(verdict["severity"], "error")
                self.assertEqual(verdict["reason_code"], "unmapped_tool")
                self.assertEqual(
                    verdict["reason"],
                    "no SkillLatch mapping for tool 'teleport'; failing closed",
                )
                self.assertIsNone(verdict["receipt"])
                self.assertEqual(tools["network"].calls, [])

    def test_malformed_messages_deny_in_both_modes(self):
        malformed = [
            "not a dict",
            None,
            ["a", "list"],
            {},
            {"jsonrpc": "2.0", "method": "resources/read", "params": {"name": "x"}},
            self.call_message("read_recipe", {"path": "recipes/soup.txt"}, jsonrpc="1.0"),
            {"jsonrpc": "2.0", "method": "tools/call", "params": "oops"},
            {"jsonrpc": "2.0", "method": "tools/call", "params": {}},
            {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": 5}},
            {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": ""}},
            self.call_message("read_recipe", "not-a-dict"),
            self.call_message("read_recipe", {"wrong_key": 1}),
        ]
        for mode in ("enforce", "audit"):
            interceptor, tools = self.make_interceptor(mode=mode)
            for message in malformed:
                with self.subTest(mode=mode, message=message):
                    verdict = interceptor.handle_message(message)
                    self.assertEqual(verdict["verdict"], "deny")
                    self.assertEqual(verdict["severity"], "error")
                    self.assertEqual(verdict["reason_code"], "invalid_message")
                    self.assertIsNone(verdict["receipt"])
                    self.assertEqual(tools["file"].calls, [])

    def test_policy_error_inputs_deny_in_both_modes(self):
        for mode in ("enforce", "audit"):
            with self.subTest(mode=mode):
                interceptor, tools = self.make_interceptor(mode=mode)
                verdict = interceptor.handle_message(
                    self.call_message("read_recipe", {"path": float("inf")})
                )
                self.assertEqual(verdict["verdict"], "deny")
                self.assertEqual(verdict["severity"], "error")
                self.assertEqual(verdict["reason_code"], "invalid_json_value")
                self.assertEqual(
                    verdict["reason"], "nonfinite numbers are invalid JSON inputs"
                )
                self.assertIsNone(verdict["receipt"])
                self.assertEqual(tools["file"].calls, [])

    def test_identity_comes_from_host_state_only(self):
        interceptor, tools = self.make_interceptor()
        message = self.call_message(
            "read_recipe",
            {
                "path": "recipes/soup.txt",
                "session_id": "attacker-session",
                "task_id": "attacker-task",
            },
        )
        message["params"]["session_id"] = "attacker-session"
        message["params"]["task_id"] = "attacker-task"
        message["_meta"] = {"session_id": "attacker-session"}
        verdict = interceptor.handle_message(message)
        self.assertEqual(verdict["verdict"], "allow")
        expected_request = {
            "session_id": "session-1",
            "task_id": "task-1",
            "kind": "file",
            "action": "read",
            "path": "recipes/soup.txt",
        }
        self.assertEqual(
            verdict["receipt"]["request_hash"], _sha256(expected_request)
        )
        self.assertEqual(len(tools["file"].calls), 1)

        other, other_tools = self.make_interceptor(session_id="other-session")
        replayed = other.handle_message(
            self.call_message("read_recipe", {"path": "recipes/soup.txt"})
        )
        self.assertEqual(replayed["verdict"], "deny")
        self.assertEqual(replayed["reason_code"], "scope_mismatch")
        self.assertEqual(other_tools["file"].calls, [])

    def test_constructor_validation(self):
        host = GatedHost(
            self.skill,
            self.workspace,
            self.manifest,
            self.grant,
            workspace_id="test-workspace",
            clock=lambda: AT,
        )
        identity = {"session_id": "session-1", "task_id": "task-1"}
        bad_maps = [
            "not-a-dict",
            {"": {"kind": "network", "url_from": "url"}},
            {5: {"kind": "network", "url_from": "url"}},
            {"t": "not-a-dict"},
            {"t": {"kind": "portal"}},
            {"t": {"kind": "file", "path_from": "path"}},
            {"t": {"kind": "network", "url_from": "url", "extra": 1}},
            {"t": {"kind": "file", "action": "delete", "path_from": "path"}},
            {"t": {"kind": "network", "url_from": ""}},
            {"t": {"kind": "command"}},
        ]
        for tool_map in bad_maps:
            with self.subTest(tool_map=tool_map), self.assertRaises(ValueError):
                McpStyleInterceptor(host, tool_map, **identity)
        with self.assertRaises(ValueError):
            McpStyleInterceptor(host, copy.deepcopy(TOOL_MAP), mode="permissive", **identity)
        bad_contexts = [
            "not-a-dict",
            {"server_identity": "srv.example"},
            {"server_identity": "", "uri": "mcp://srv/skill"},
            {"server_identity": "srv.example", "uri": ""},
            {"server_identity": "srv\nexample", "uri": "mcp://srv/skill"},
            {"server_identity": "srv", "uri": "u", "extra": 1},
        ]
        for skill_context in bad_contexts:
            with self.subTest(skill_context=skill_context), self.assertRaises(ValueError):
                McpStyleInterceptor(
                    host,
                    copy.deepcopy(TOOL_MAP),
                    skill_context=skill_context,
                    **identity,
                )

    def test_skill_context_is_host_supplied_and_read_only(self):
        skill_context = {
            "server_identity": "srv.example",
            "uri": "mcp://srv.example/skills/test-skill",
        }
        interceptor, _ = self.make_interceptor(skill_context=skill_context)
        self.assertEqual(interceptor.mode, "enforce")
        self.assertEqual(interceptor.skill_context, skill_context)
        skill_context["server_identity"] = "mutated"
        self.assertEqual(
            interceptor.skill_context["server_identity"], "srv.example"
        )
        view = interceptor.skill_context
        view["uri"] = "mutated"
        self.assertEqual(
            interceptor.skill_context["uri"], "mcp://srv.example/skills/test-skill"
        )
        default_interceptor, _ = self.make_interceptor()
        self.assertIsNone(default_interceptor.skill_context)

    def test_network_and_command_tools(self):
        interceptor, tools = self.make_interceptor()
        denied = interceptor.handle_message(
            self.call_message("http_get", {"url": "https://recipes.example/collect"})
        )
        self.assertEqual(denied["verdict"], "deny")
        self.assertEqual(denied["reason_code"], "capability_not_granted")
        self.assertEqual(tools["network"].calls, [])

        widened = copy.deepcopy(self.grant)
        widened["capabilities"]["network"] = ["https://recipes.example"]
        widened["capabilities"]["commands"] = [["git", "status", "--short"]]
        granted, granted_tools = self.make_interceptor(grant=widened)
        fetched = granted.handle_message(
            self.call_message("http_get", {"url": "https://recipes.example/collect"})
        )
        self.assertEqual(fetched["verdict"], "allow")
        self.assertEqual(
            granted_tools["network"].calls,
            [{"url": "https://recipes.example/collect"}],
        )
        ran = granted.handle_message(
            self.call_message("run_git", {"argv": ["git", "status", "--short"]})
        )
        self.assertEqual(ran["verdict"], "allow")
        self.assertEqual(ran["severity"], "info")
        self.assertEqual(
            granted_tools["command"].calls, [{"argv": ["git", "status", "--short"]}]
        )


if __name__ == "__main__":
    unittest.main()
