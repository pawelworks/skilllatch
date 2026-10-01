from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from skilllatch import PolicyError, evaluate, hash_skill_tree, load_json_file

AT = datetime(2026, 10, 1, 12, tzinfo=UTC)
PROJECT = Path(__file__).resolve().parents[1]


class SkillLatchTests(unittest.TestCase):
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
                "network": ["https://recipes.example", "https://example.org:8443"],
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

    def request(self, **kwargs):
        return {"session_id": "session-1", "task_id": "task-1", **kwargs}

    def decide(self, request, *, manifest=None, grant=None, at=AT, workspace_id="test-workspace"):
        return evaluate(
            self.skill,
            self.workspace,
            self.manifest if manifest is None else manifest,
            self.grant if grant is None else grant,
            request,
            at=at,
            workspace_id=workspace_id,
        )

    def legacy_grant(self):
        grant = {key: value for key, value in self.grant.items() if key != "workspace_id"}
        grant["version"] = 1
        return grant

    def test_narrow_file_grant_allows_only_selected_read(self):
        allowed = self.decide(
            self.request(kind="file", action="read", path="recipes/soup.txt")
        )
        self.assertTrue(allowed["allowed"])
        self.assertEqual(allowed["reason_code"], "allowed")
        self.assertEqual(
            allowed["receipt"]["skill_digest"], self.manifest["skill"]["digest"]
        )
        for action, path in (("read", "private.txt"), ("write", "notes/new.txt")):
            with self.subTest(action=action, path=path):
                denied = self.decide(
                    self.request(kind="file", action=action, path=path)
                )
                self.assertEqual(denied["reason_code"], "capability_not_granted")

    def test_grant_may_narrow_recursive_declaration(self):
        grant = copy.deepcopy(self.grant)
        grant["capabilities"]["files"]["read"] = [
            {"path": "recipes", "recursive": True}
        ]
        self.assertTrue(
            self.decide(
                self.request(kind="file", action="read", path="recipes/soup.txt"),
                grant=grant,
            )["allowed"]
        )
        self.assertFalse(
            self.decide(
                self.request(kind="file", action="read", path="private.txt"),
                grant=grant,
            )["allowed"]
        )

    def test_undeclared_grant_fails_closed_even_for_other_request(self):
        grant = copy.deepcopy(self.grant)
        grant["capabilities"]["network"] = ["https://attacker.example"]
        result = self.decide(
            self.request(kind="file", action="read", path="recipes/soup.txt"),
            grant=grant,
        )
        self.assertEqual(result["reason_code"], "grant_exceeds_manifest")

    def test_ungranted_network_and_command_are_denied(self):
        network = self.request(
            kind="network", url="https://attacker.example/collect?secret=placeholder"
        )
        result = self.decide(network)
        self.assertEqual(result["reason_code"], "capability_not_granted")
        self.assertNotIn("placeholder", json.dumps(result))
        command = self.request(kind="command", argv=["git", "status", "--short"])
        self.assertEqual(self.decide(command)["reason_code"], "capability_not_granted")

    def test_network_origin_normalization_and_exact_command(self):
        grant = copy.deepcopy(self.grant)
        grant["capabilities"]["network"] = ["https://RECIPES.example:443"]
        grant["capabilities"]["commands"] = [["git", "status", "--short"]]
        network = self.request(
            kind="network", url="https://recipes.example:443/list?q=tomato"
        )
        self.assertTrue(self.decide(network, grant=grant)["allowed"])
        self.assertFalse(
            self.decide(
                self.request(kind="network", url="https://recipes.example.evil/"),
                grant=grant,
            )["allowed"]
        )
        self.assertFalse(
            self.decide(
                self.request(
                    kind="network", url="https://recipes.example@evil.example/"
                ),
                grant=grant,
            )["allowed"]
        )
        self.assertTrue(
            self.decide(
                self.request(kind="command", argv=["git", "status", "--short"]),
                grant=grant,
            )["allowed"]
        )
        self.assertFalse(
            self.decide(
                self.request(kind="command", argv=["git", "status"]), grant=grant
            )["allowed"]
        )

    def test_skill_mutation_revokes_digest_bound_grant(self):
        (self.skill / "SKILL.md").write_text("# Modified skill\n", encoding="utf-8")
        result = self.decide(
            self.request(kind="file", action="read", path="recipes/soup.txt")
        )
        self.assertEqual(result["reason_code"], "skill_digest_mismatch")

    def test_time_and_scope_are_enforced(self):
        request = self.request(kind="file", action="read", path="recipes/soup.txt")
        self.assertEqual(
            self.decide(request, at=datetime(2026, 10, 1, 13, tzinfo=UTC))[
                "reason_code"
            ],
            "grant_inactive",
        )
        self.assertEqual(
            self.decide({**request, "task_id": "different"})["reason_code"],
            "scope_mismatch",
        )
        grant = copy.deepcopy(self.grant)
        grant["expires_at"] = "2026-10-03T11:00:01Z"
        self.assertEqual(
            self.decide(request, grant=grant)["reason_code"], "invalid_grant_window"
        )
        for malformed in (
            "2026-10-01 11:00:00Z",
            "2026-10-01T11:00Z",
            "2026-10-01T11:00:00+00:00",
        ):
            with self.subTest(malformed=malformed):
                grant = copy.deepcopy(self.grant)
                grant["issued_at"] = malformed
                self.assertEqual(
                    self.decide(request, grant=grant)["reason_code"], "invalid_time"
                )

    def test_v1_grant_without_host_workspace_id_is_allowed_with_binding_none(self):
        result = self.decide(
            self.request(kind="file", action="read", path="recipes/soup.txt"),
            grant=self.legacy_grant(),
            workspace_id=None,
        )
        self.assertTrue(result["allowed"])
        self.assertEqual(result["receipt"]["workspace_binding"], "none")
        self.assertIsNone(result["receipt"]["workspace_id"])

    def test_v1_grant_with_host_workspace_id_is_unpinned(self):
        result = self.decide(
            self.request(kind="file", action="read", path="recipes/soup.txt"),
            grant=self.legacy_grant(),
            workspace_id="test-workspace",
        )
        self.assertTrue(result["allowed"])
        self.assertEqual(result["receipt"]["workspace_binding"], "unpinned")
        self.assertEqual(result["receipt"]["workspace_id"], "test-workspace")

    def test_v2_grant_requires_the_pinned_workspace_id(self):
        request = self.request(kind="file", action="read", path="recipes/soup.txt")
        for host_id in ("other-workspace", None):
            with self.subTest(host_id=host_id):
                result = self.decide(request, workspace_id=host_id)
                self.assertEqual(result["reason_code"], "workspace_mismatch")
                self.assertFalse(result["allowed"])

    def test_v2_grant_replayed_on_second_physical_workspace_is_denied(self):
        second = self.root / "workspace-b"
        (second / "recipes").mkdir(parents=True)
        (second / "recipes" / "soup.txt").write_text("soup\n", encoding="utf-8")
        result = evaluate(
            self.skill,
            second,
            self.manifest,
            self.grant,
            self.request(kind="file", action="read", path="recipes/soup.txt"),
            at=AT,
            workspace_id="workspace-b",
        )
        self.assertEqual(result["reason_code"], "workspace_mismatch")

    def test_grant_version_3_is_unsupported(self):
        grant = copy.deepcopy(self.grant)
        grant["version"] = 3
        result = self.decide(
            self.request(kind="file", action="read", path="recipes/soup.txt"),
            grant=grant,
        )
        self.assertEqual(result["reason_code"], "unsupported_version")

    def test_malformed_host_workspace_id_is_invalid_schema(self):
        result = self.decide(
            self.request(kind="file", action="read", path="recipes/soup.txt"),
            workspace_id="bad\nid",
        )
        self.assertEqual(result["reason_code"], "invalid_schema")

    def test_traversal_absolute_and_windows_aliases_are_denied(self):
        for path in (
            "../private.txt",
            "recipes/../private.txt",
            "/etc/passwd",
            "C:/private.txt",
            "recipes\\soup.txt",
            "recipes//soup.txt",
            "recipes/./soup.txt",
            "recipes/CON.txt",
            "recipes/CONIN$",
            "recipes/CONOUT$.txt",
            "recipes/COM¹.txt",
            "recipes/LPT³",
            "recipes/NUL .txt",
            "recipes/soup.txt.",
        ):
            with self.subTest(path=path):
                result = self.decide(
                    self.request(kind="file", action="read", path=path)
                )
                self.assertEqual(result["reason_code"], "invalid_path")

    def test_symlink_target_is_denied(self):
        link = self.workspace / "recipes" / "linked.txt"
        try:
            link.symlink_to(self.workspace / "private.txt")
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation is not available")
        grant = copy.deepcopy(self.grant)
        grant["capabilities"]["files"]["read"] = [
            {"path": "recipes", "recursive": True}
        ]
        result = self.decide(
            self.request(kind="file", action="read", path="recipes/linked.txt"),
            grant=grant,
        )
        self.assertEqual(result["reason_code"], "unsafe_file_path")

    def test_hard_link_alias_is_denied(self):
        try:
            os.link(
                self.workspace / "private.txt",
                self.workspace / "recipes" / "alias.txt",
            )
        except (OSError, NotImplementedError):
            self.skipTest("hard link creation is not available")
        grant = copy.deepcopy(self.grant)
        grant["capabilities"]["files"]["read"] = [
            {"path": "recipes", "recursive": True}
        ]
        result = self.decide(
            self.request(kind="file", action="read", path="recipes/alias.txt"),
            grant=grant,
        )
        self.assertEqual(result["reason_code"], "unsafe_file_path")

    def test_reparse_point_check_denies_link_path_without_os_privileges(self):
        target = self.workspace / "recipes" / "alias.txt"
        target.write_text("test\n", encoding="utf-8")
        grant = copy.deepcopy(self.grant)
        grant["capabilities"]["files"]["read"] = [
            {"path": "recipes", "recursive": True}
        ]
        from skilllatch import core

        real_check = core._is_reparse_or_symlink
        with patch(
            "skilllatch.core._is_reparse_or_symlink",
            side_effect=lambda path: path == target or real_check(path),
        ):
            result = self.decide(
                self.request(kind="file", action="read", path="recipes/alias.txt"),
                grant=grant,
            )
        self.assertEqual(result["reason_code"], "unsafe_file_path")

    def test_symlink_in_skill_tree_is_rejected(self):
        link = self.skill / "linked.txt"
        try:
            link.symlink_to(self.workspace / "private.txt")
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation is not available")
        with self.assertRaises(PolicyError) as error:
            hash_skill_tree(self.skill)
        self.assertEqual(error.exception.code, "invalid_skill_tree")

    def test_receipt_is_version_2_and_deterministic(self):
        request = self.request(kind="file", action="read", path="recipes/soup.txt")
        one = self.decide(request)
        two = self.decide(copy.deepcopy(request))
        self.assertEqual(one, two)
        self.assertEqual(one["receipt"]["version"], 2)
        self.assertEqual(one["receipt"]["workspace_id"], "test-workspace")
        self.assertEqual(one["receipt"]["workspace_binding"], "pinned")

    def test_receipt_is_deterministic_and_bound_to_request(self):
        request = self.request(kind="file", action="read", path="recipes/soup.txt")
        one = self.decide(request)
        two = self.decide(copy.deepcopy(request))
        self.assertEqual(one, two)
        changed = self.decide({**request, "path": "recipes/other.txt"})
        self.assertNotEqual(one["receipt"]["digest"], changed["receipt"]["digest"])
        self.assertNotEqual(
            one["receipt"]["request_hash"], changed["receipt"]["request_hash"]
        )

    def test_malformed_network_urls_are_denied(self):
        malformed = (
            "http://recipes.example/path",
            "https://recipes.example@evil.example/path",
            "https://recipes.example./path",
            "https://recipes.example%2Fevil.example/path",
            "https://recipes.example:0/path",
            "https://recipes.example/path#fragment",
            "https://",
            "https://faß.de/path",
        )
        for url in malformed:
            with self.subTest(url=url):
                result = self.decide(self.request(kind="network", url=url))
                self.assertEqual(result["reason_code"], "invalid_network_url")

    def test_ascii_punycode_host_is_distinct_from_unicode_host(self):
        manifest = copy.deepcopy(self.manifest)
        grant = copy.deepcopy(self.grant)
        manifest["capabilities"]["network"] = ["https://xn--fa-hia.de"]
        grant["capabilities"]["network"] = ["https://xn--fa-hia.de"]
        allowed = self.decide(
            self.request(kind="network", url="https://xn--fa-hia.de/path"),
            manifest=manifest,
            grant=grant,
        )
        self.assertTrue(allowed["allowed"])
        denied = self.decide(
            self.request(kind="network", url="https://faß.de/path"),
            manifest=manifest,
            grant=grant,
        )
        self.assertEqual(denied["reason_code"], "invalid_network_url")

    def test_nonfinite_json_values_are_rejected_before_receipt_hash(self):
        path = self.root / "nonfinite.json"
        path.write_text('{"nested":{"value":1e400}}', encoding="utf-8")
        with self.assertRaises(PolicyError) as error:
            load_json_file(path)
        self.assertEqual(error.exception.code, "invalid_json_value")
        bad_request = self.request(
            kind="network", url="https://recipes.example", extra={"value": float("inf")}
        )
        with self.assertRaises(PolicyError) as error:
            self.decide(bad_request)
        self.assertEqual(error.exception.code, "invalid_json_value")
        with self.assertRaises(PolicyError) as error:
            self.decide({"kind": "file", 1: "not a JSON key"})
        self.assertEqual(error.exception.code, "invalid_json_value")

    def test_unknown_fields_and_duplicate_json_keys_are_rejected(self):
        request = self.request(
            kind="file", action="read", path="recipes/soup.txt", surprise=True
        )
        self.assertEqual(self.decide(request)["reason_code"], "invalid_schema")
        path = self.root / "duplicates.json"
        path.write_text('{"version":1,"version":2}', encoding="utf-8")
        with self.assertRaises(PolicyError) as error:
            load_json_file(path)
        self.assertEqual(error.exception.code, "duplicate_json_key")


class ExampleCliTests(unittest.TestCase):
    def test_fixture_digest_and_check_exit_codes(self):
        examples = PROJECT / "examples"
        digest = subprocess.run(
            [
                sys.executable,
                "-m",
                "skilllatch",
                "digest",
                "--skill-dir",
                str(examples / "chef-helper"),
            ],
            cwd=PROJECT,
            capture_output=True,
            text=True,
            check=False,
        )
        manifest = load_json_file(examples / "manifest.json")
        self.assertEqual(digest.returncode, 0, digest.stderr)
        self.assertEqual(digest.stdout.strip(), manifest["skill"]["digest"])
        common = [
            sys.executable,
            "-m",
            "skilllatch",
            "check",
            "--skill-dir",
            str(examples / "chef-helper"),
            "--workspace",
            str(examples / "workspace"),
            "--manifest",
            str(examples / "manifest.json"),
            "--grant",
            str(examples / "grant.json"),
            "--at",
            "2026-10-01T12:00:00Z",
            "--workspace-id",
            "chef-demo-workspace",
        ]
        allowed = subprocess.run(
            common + ["--request", str(examples / "allowed-request.json")],
            cwd=PROJECT,
            capture_output=True,
            text=True,
            check=False,
        )
        denied = subprocess.run(
            common + ["--request", str(examples / "denied-request.json")],
            cwd=PROJECT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(allowed.returncode, 0, allowed.stderr)
        self.assertEqual(denied.returncode, 2, denied.stderr)
        self.assertTrue(json.loads(allowed.stdout)["allowed"])
        self.assertEqual(
            json.loads(allowed.stdout)["receipt"]["workspace_binding"], "pinned"
        )
        self.assertEqual(
            json.loads(denied.stdout)["reason_code"], "capability_not_granted"
        )

    def test_pinned_grant_replay_without_workspace_id_is_denied(self):
        examples = PROJECT / "examples"
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "skilllatch",
                "check",
                "--skill-dir",
                str(examples / "chef-helper"),
                "--workspace",
                str(examples / "workspace"),
                "--manifest",
                str(examples / "manifest.json"),
                "--grant",
                str(examples / "grant.json"),
                "--request",
                str(examples / "allowed-request.json"),
                "--at",
                "2026-10-01T12:00:00Z",
            ],
            cwd=PROJECT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(
            json.loads(result.stdout)["reason_code"], "workspace_mismatch"
        )

    def test_usage_and_engine_error_exit_codes_are_distinct(self):
        examples = PROJECT / "examples"
        usage = subprocess.run(
            [sys.executable, "-m", "skilllatch", "check"],
            cwd=PROJECT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(usage.returncode, 64, usage.stderr)
        engine = subprocess.run(
            [
                sys.executable,
                "-m",
                "skilllatch",
                "digest",
                "--skill-dir",
                str(examples / "manifest.json"),
            ],
            cwd=PROJECT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(engine.returncode, 3, engine.stderr)
        self.assertIn("invalid_skill_tree", engine.stderr)

    def test_malformed_json_requests_fail_closed_with_structured_denial(self):
        examples = PROJECT / "examples"
        with tempfile.TemporaryDirectory() as temp:
            for name, content, expected_code in (
                ("large-number", "1" * 5000, "invalid_json_file"),
                ("lone-surrogate", '"\\ud800"', "invalid_json_value"),
            ):
                with self.subTest(name=name):
                    request_file = Path(temp) / f"{name}.json"
                    request_file.write_text(content, encoding="utf-8")
                    result = subprocess.run(
                        [
                            sys.executable,
                            "-m",
                            "skilllatch",
                            "check",
                            "--skill-dir",
                            str(examples / "chef-helper"),
                            "--workspace",
                            str(examples / "workspace"),
                            "--manifest",
                            str(examples / "manifest.json"),
                            "--grant",
                            str(examples / "grant.json"),
                            "--request",
                            str(request_file),
                            "--at",
                            "2026-10-01T12:00:00Z",
                            "--workspace-id",
                            "chef-demo-workspace",
                        ],
                        cwd=PROJECT,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 2, result.stderr)
                    denial = json.loads(result.stdout)
                    self.assertFalse(denial["allowed"])
                    self.assertEqual(denial["reason_code"], expected_code)
                    self.assertIn("digest", denial["receipt"])


if __name__ == "__main__":
    unittest.main()
