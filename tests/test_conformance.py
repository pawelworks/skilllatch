from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from skilllatch import PolicyError, evaluate, hash_skill_tree, load_json_file
from skilllatch.core import REASON_CODES, _parse_time, _sha256

PROJECT = Path(__file__).resolve().parents[1]
FIXTURES = PROJECT / "conformance"

# unsafe_file_path needs symlink/hard-link privileges; unit tests only.
REQUIRED_CODES = REASON_CODES - {"unsafe_file_path"}


def _replace_digest(value, digest):
    if isinstance(value, dict):
        return {key: _replace_digest(item, digest) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_digest(item, digest) for item in value]
    if value == "__SKILL_DIGEST__":
        return digest
    return value


def _stage_tree(root: Path, files: dict[str, str]) -> None:
    for name, content in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content.encode("utf-8"))


class ConformanceTests(unittest.TestCase):
    def run_fixture(self, fixture: dict) -> None:
        if "parse_check" in fixture:
            check = fixture["parse_check"]
            with tempfile.TemporaryDirectory() as temp:
                target = Path(temp) / "input.json"
                target.write_bytes(check["content"].encode("utf-8"))
                with self.assertRaises(PolicyError) as error:
                    load_json_file(target)
            self.assertEqual(error.exception.code, check["expect_reason_code"])
            return
        setup = fixture["setup"]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            skill = root / "skill"
            workspace = root / "workspace"
            if setup["skill_files"] is None:
                digest = "sha256:" + "0" * 64
            else:
                _stage_tree(skill, setup["skill_files"])
                digest = hash_skill_tree(skill)
            if setup["workspace_files"] is None:
                # A regular file, not a directory: exercises invalid_workspace
                # portably, without symlink privileges.
                workspace.write_bytes(b"")
            else:
                _stage_tree(workspace, setup["workspace_files"])
            manifest = _replace_digest(fixture["manifest"], digest)
            grant = _replace_digest(fixture["grant"], digest)
            at = _parse_time(fixture["at"], "at")
            outcomes = [
                evaluate(
                    skill,
                    workspace,
                    manifest,
                    grant,
                    fixture["request"],
                    at=at,
                    workspace_id=fixture["workspace_id"],
                )
                for _ in range(2)
            ]
        self.assertEqual(outcomes[0], outcomes[1])
        expect = fixture["expect"]
        decision, receipt = outcomes[0], outcomes[0]["receipt"]
        self.assertEqual(decision["allowed"], expect["allowed"])
        self.assertEqual(decision["reason_code"], expect["reason_code"])
        body = {key: value for key, value in receipt.items() if key != "digest"}
        self.assertEqual(_sha256(body), receipt["digest"])
        if "expect_digest" in expect:
            self.assertEqual(receipt["digest"], expect["expect_digest"])
        if "workspace_binding" in expect:
            self.assertEqual(receipt["workspace_binding"], expect["workspace_binding"])

    def test_fixtures(self) -> None:
        paths = sorted(FIXTURES.glob("*.json"))
        self.assertTrue(paths, "no conformance fixtures found")
        for path in paths:
            with self.subTest(fixture=path.name):
                self.run_fixture(load_json_file(path))

    def test_reason_code_coverage_is_complete(self) -> None:
        seen: set[str] = set()
        for path in sorted(FIXTURES.glob("*.json")):
            fixture = load_json_file(path)
            if "parse_check" in fixture:
                seen.add(fixture["parse_check"]["expect_reason_code"])
            else:
                seen.add(fixture["expect"]["reason_code"])
        self.assertEqual(seen, REQUIRED_CODES)


if __name__ == "__main__":
    unittest.main()
