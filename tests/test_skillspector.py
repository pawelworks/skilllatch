from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from skilllatch import PolicyError, hash_skill_tree, load_scan_report

PROJECT = Path(__file__).resolve().parents[1]
EXAMPLES = PROJECT / "examples"


class ScanReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.skill = self.root / "skill"
        self.skill.mkdir()
        (self.skill / "SKILL.md").write_text("# Scanned skill\n", encoding="utf-8")
        self.digest = hash_skill_tree(self.skill)

    def write_report(self, report) -> Path:
        path = self.root / "report.json"
        if isinstance(report, str):
            path.write_text(report, encoding="utf-8")
        else:
            path.write_text(json.dumps(report), encoding="utf-8")
        return path

    def test_example_fixture_is_verified_against_example_skill(self):
        report = load_scan_report(EXAMPLES / "skillspector-report.json")
        self.assertEqual(
            report["subject_digest"], hash_skill_tree(EXAMPLES / "chef-helper")
        )
        verified = load_scan_report(
            EXAMPLES / "skillspector-report.json", skill_dir=EXAMPLES / "chef-helper"
        )
        self.assertEqual(verified["schema"], "skilllatch.scan_advisory.v1")
        self.assertTrue(verified["advisory"])
        self.assertEqual(verified["scanner"], "skillspector")
        self.assertEqual(verified["scan_mode"], "static+llm")
        self.assertEqual(
            verified["coverage"],
            {"files_scanned": 1, "files_total": 1, "is_complete": True},
        )
        self.assertTrue(verified["digest_match"])
        self.assertEqual(
            verified["sources"],
            {
                "scanner": "tool",
                "scan_mode": "scan_mode",
                "coverage": "coverage",
                "subject_digest": "subject_digest",
            },
        )
        for key in ("_note", "skill", "risk_assessment", "components", "issues"):
            self.assertIn(key, verified["metadata"])
        self.assertEqual(
            verified["metadata"]["metadata"]["skillspector_version"], "2.12.0"
        )
        for consumed in ("tool", "scan_mode", "subject_digest", "coverage"):
            self.assertNotIn(consumed, verified["metadata"])
        self.assertEqual(verified["warnings"], [])

    def test_report_with_only_unknown_keys_is_preserved_verbatim(self):
        path = self.write_report({"vendor_field": {"nested": [1, 2]}, "other": "x"})
        result = load_scan_report(path)
        self.assertEqual(result["scan_mode"], None)
        self.assertEqual(result["coverage"], {})
        self.assertIsNone(result["subject_digest"])
        self.assertIsNone(result["digest_match"])
        self.assertEqual(result["scanner"], "skillspector")
        self.assertEqual(
            result["metadata"], {"vendor_field": {"nested": [1, 2]}, "other": "x"}
        )
        self.assertEqual(result["warnings"], [])

    def test_alternate_spellings_are_recognized(self):
        path = self.write_report(
            {
                "scanMode": "static",
                "target_digest": self.digest,
                "analysis_coverage": {"files_scanned": 3},
                "scanner": "other-engine",
            }
        )
        result = load_scan_report(path, skill_dir=self.skill)
        self.assertEqual(result["scan_mode"], "static")
        self.assertEqual(result["subject_digest"], self.digest)
        self.assertEqual(result["coverage"], {"files_scanned": 3})
        self.assertEqual(result["scanner"], "other-engine")
        self.assertTrue(result["digest_match"])
        self.assertEqual(
            result["sources"],
            {
                "scanner": "scanner",
                "scan_mode": "scanMode",
                "coverage": "analysis_coverage",
                "subject_digest": "target_digest",
            },
        )

    def test_container_level_fields_are_found(self):
        path = self.write_report(
            {"analysis": {"mode": "deep", "subject_digest": self.digest}}
        )
        result = load_scan_report(path, skill_dir=self.skill)
        self.assertEqual(result["scan_mode"], "deep")
        self.assertTrue(result["digest_match"])
        self.assertEqual(
            result["sources"],
            {"scan_mode": "analysis.mode", "subject_digest": "analysis.subject_digest"},
        )

    def test_exact_case_key_wins_over_case_variant_with_warning(self):
        path = self.write_report({"mode": "static", "Mode": "deep"})
        result = load_scan_report(path)
        self.assertEqual(result["scan_mode"], "static")
        self.assertEqual(result["sources"], {"scan_mode": "mode"})
        self.assertTrue(
            any("case-variant" in warning and "'Mode'" in warning
                for warning in result["warnings"])
        )

    def test_top_level_field_wins_over_container_with_warning(self):
        path = self.write_report(
            {"mode": "static", "analysis": {"mode": "deep"}}
        )
        result = load_scan_report(path)
        self.assertEqual(result["scan_mode"], "static")
        self.assertEqual(result["sources"], {"scan_mode": "mode"})
        self.assertTrue(
            any("top level" in warning and "analysis.mode" in warning
                for warning in result["warnings"])
        )

    def test_non_object_coverage_is_a_warning(self):
        path = self.write_report({"coverage": "not-an-object"})
        result = load_scan_report(path)
        self.assertEqual(result["coverage"], {})
        self.assertEqual(result["sources"], {})
        self.assertIn(
            "coverage is present but not an object; ignoring it", result["warnings"]
        )

    def test_scan_mode_derivation_from_llm_metadata(self):
        for requested, available, expected in (
            (True, True, "static+llm"),
            (True, False, "static-only"),
            (False, False, None),
        ):
            with self.subTest(requested=requested, available=available):
                path = self.write_report(
                    {"metadata": {"llm_requested": requested, "llm_available": available}}
                )
                self.assertEqual(load_scan_report(path)["scan_mode"], expected)

    def test_malformed_and_nonobject_reports_are_rejected(self):
        for content in ('{"tool": "skillspector"', "[1, 2]", '"text"'):
            with self.subTest(content=content):
                with self.assertRaises(PolicyError) as error:
                    load_scan_report(self.write_report(content))
                self.assertEqual(error.exception.code, "invalid_scan_report")

    def test_unreadable_report_is_rejected(self):
        with self.assertRaises(PolicyError) as error:
            load_scan_report(self.root / "missing.json")
        self.assertEqual(error.exception.code, "invalid_scan_report")

    def test_digest_mismatch_fails_closed(self):
        other = self.root / "other"
        other.mkdir()
        (other / "SKILL.md").write_text("# Different\n", encoding="utf-8")
        path = self.write_report({"subject_digest": self.digest})
        with self.assertRaises(PolicyError) as error:
            load_scan_report(path, skill_dir=other)
        self.assertEqual(error.exception.code, "scan_digest_mismatch")
        self.assertEqual(
            error.exception.reason,
            "scan report subject does not match the skill tree",
        )

    def test_no_skill_dir_leaves_digest_match_unknown(self):
        path = self.write_report({"subject_digest": self.digest})
        result = load_scan_report(path)
        self.assertIsNone(result["digest_match"])
        self.assertEqual(result["warnings"], [])

    def test_missing_digest_with_skill_dir_warns(self):
        path = self.write_report({"tool": "skillspector"})
        result = load_scan_report(path, skill_dir=self.skill)
        self.assertIsNone(result["digest_match"])
        self.assertIn("report carries no subject digest", result["warnings"])

    def test_malformed_digest_is_a_warning_not_a_failure(self):
        path = self.write_report({"subject_digest": "md5:abc"})
        result = load_scan_report(path)
        self.assertIsNone(result["subject_digest"])
        self.assertTrue(
            any("malformed subject digest" in warning for warning in result["warnings"])
        )

    def test_non_string_scan_mode_is_a_warning(self):
        path = self.write_report({"scan_mode": 7})
        result = load_scan_report(path)
        self.assertIsNone(result["scan_mode"])
        self.assertTrue(result["warnings"])


if __name__ == "__main__":
    unittest.main()
