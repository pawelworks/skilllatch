"""Schema-vs-fixture checks over a deliberately small JSON Schema subset.

The hand-rolled checker below honors ONLY: ``type`` (single name or list;
``integer`` means ``type(x) is int``, ``boolean`` means ``type(x) is bool``),
``required``, ``additionalProperties`` (only ``false`` is honored: instance
keys must be a subset of ``properties``), ``properties`` (recurse), ``items``
(recurse), and ``oneOf`` (exactly one branch must be error-free). ``const``,
``enum``, ``pattern``, ``minLength``, and ``$ref`` are deliberately IGNORED —
keyword-level validity is the engine's job, and the reference parser in
skilllatch/core.py is authoritative. Consequences, by design:

- conformance fixtures 12/13/15/16/17 carry pattern/const-level invalidity
  (a traversal path, an http URL, an unknown version, a bad timestamp, an
  over-long grant window) that this subset cannot see, so they PASS here;
- fixtures 14 and 18 carry structural invalidity (an unexpected key, a kind
  with missing branch keys) that the subset DOES see, so they are the only
  expected failures.
"""

from __future__ import annotations

import copy
import unittest
from datetime import UTC, datetime
from pathlib import Path

from skilllatch import evaluate, load_json_file

PROJECT = Path(__file__).resolve().parents[1]
SCHEMAS = PROJECT / "schema"
EXAMPLES = PROJECT / "examples"
FIXTURES = PROJECT / "conformance"
DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"
AT = datetime(2026, 10, 1, 12, tzinfo=UTC)

OBJECT_SCHEMAS = ["manifest-v1.json", "grant-v1.json", "grant-v2.json", "receipt-v2.json"]
EXPECTED_FAILURES = {
    "14-deny-invalid-schema.json": {"request"},
    "18-deny-invalid-request.json": {"request"},
}
DIGEST = "sha256:" + "0" * 64


def _type_matches(value, name):
    if name == "integer":
        return type(value) is int
    if name == "boolean":
        return type(value) is bool
    if name == "number":
        return type(value) in (int, float)
    if name == "string":
        return isinstance(value, str)
    if name == "object":
        return isinstance(value, dict)
    if name == "array":
        return isinstance(value, list)
    if name == "null":
        return value is None
    return False


def check_schema(instance, schema, path="$"):
    """Return a list of subset violations for instance under schema."""
    expected = schema.get("type")
    if expected is not None:
        names = [expected] if isinstance(expected, str) else list(expected)
        if not any(_type_matches(instance, name) for name in names):
            return [f"{path}: expected type {names}, got {type(instance).__name__}"]
    violations = []
    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                violations.append(f"{path}: missing required key {key!r}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in instance:
                if key not in properties:
                    violations.append(f"{path}: unexpected key {key!r}")
        for key, subschema in properties.items():
            if key in instance:
                violations.extend(
                    check_schema(instance[key], subschema, f"{path}.{key}")
                )
    if isinstance(instance, list) and "items" in schema:
        for index, item in enumerate(instance):
            violations.extend(
                check_schema(item, schema["items"], f"{path}[{index}]")
            )
    if "oneOf" in schema:
        matching = sum(
            not check_schema(instance, branch, path) for branch in schema["oneOf"]
        )
        if matching != 1:
            violations.append(
                f"{path}: exactly one oneOf branch must match, got {matching}"
            )
    return violations


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


class SchemaSubsetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schemas = {
            name: load_json_file(SCHEMAS / name)
            for name in OBJECT_SCHEMAS + ["request.json"]
        }

    def test_schema_files_are_self_contained_2020_12_objects(self):
        for name, schema in self.schemas.items():
            with self.subTest(schema=name):
                self.assertEqual(schema["$schema"], DRAFT_2020_12)
                self.assertFalse(_all_keys(schema) & {"$id", "$ref", "$defs"})
                if name == "request.json":
                    self.assertIn("oneOf", schema)
                    self.assertEqual(len(schema["oneOf"]), 3)
                    for branch in schema["oneOf"]:
                        self.assertIn("required", branch)
                        self.assertIs(branch["additionalProperties"], False)
                else:
                    self.assertIn("required", schema)
                    self.assertIs(schema["additionalProperties"], False)

    def test_example_documents_satisfy_their_schemas(self):
        manifest = load_json_file(EXAMPLES / "manifest.json")
        grant = load_json_file(EXAMPLES / "grant.json")
        allowed = load_json_file(EXAMPLES / "allowed-request.json")
        denied = load_json_file(EXAMPLES / "denied-request.json")
        cases = [
            ("manifest-v1.json", manifest),
            ("grant-v2.json", grant),
            ("request.json", allowed),
            ("request.json", denied),
        ]
        grant_v1 = copy.deepcopy(grant)
        del grant_v1["workspace_id"]
        grant_v1["version"] = 1
        cases.append(("grant-v1.json", grant_v1))
        for name, document in cases:
            with self.subTest(schema=name, document=document.get("kind", "policy")):
                self.assertEqual(check_schema(document, self.schemas[name]), [])
        # skillspector-report.json is explicitly not covered by any schema:
        # the advisory summary is a tolerant mapping of external scanner
        # output, not a strict SkillLatch wire format.

    def test_conformance_fixtures_match_subset_expectations(self):
        for path in sorted(FIXTURES.glob("*.json")):
            fixture = load_json_file(path)
            if "parse_check" in fixture:
                continue
            with self.subTest(fixture=path.name):
                grant_schema = (
                    "grant-v1.json"
                    if fixture["grant"].get("version") == 1
                    else "grant-v2.json"
                )
                documents = {
                    "manifest": ("manifest-v1.json", fixture["manifest"]),
                    "grant": (grant_schema, fixture["grant"]),
                    "request": ("request.json", fixture["request"]),
                }
                expected = EXPECTED_FAILURES.get(path.name, set())
                for label, (schema_name, document) in documents.items():
                    violations = check_schema(document, self.schemas[schema_name])
                    if label in expected:
                        self.assertTrue(
                            violations, f"{label} should fail the subset here"
                        )
                    else:
                        self.assertEqual(violations, [])

    def test_checker_is_not_vacuous(self):
        manifest = load_json_file(EXAMPLES / "manifest.json")
        broken = copy.deepcopy(manifest)
        broken["extra"] = 1
        self.assertTrue(check_schema(broken, self.schemas["manifest-v1.json"]))
        broken = copy.deepcopy(manifest)
        del broken["skill"]
        self.assertTrue(check_schema(broken, self.schemas["manifest-v1.json"]))
        broken = copy.deepcopy(manifest)
        broken["version"] = "1"
        self.assertTrue(check_schema(broken, self.schemas["manifest-v1.json"]))
        broken = copy.deepcopy(manifest)
        broken["capabilities"]["files"]["read"] = {}
        self.assertTrue(check_schema(broken, self.schemas["manifest-v1.json"]))
        receipt = {
            "version": 2,
            "allowed": True,
            "reason_code": "allowed",
            "reason": "ok",
            "evaluated_at": "2026-10-01T12:00:00Z",
            "skill_digest": 5,
            "workspace_id": None,
            "workspace_binding": "none",
            "manifest_hash": DIGEST,
            "grant_hash": DIGEST,
            "request_hash": DIGEST,
            "digest": DIGEST,
        }
        self.assertTrue(check_schema(receipt, self.schemas["receipt-v2.json"]))

    def test_live_receipts_satisfy_receipt_v2(self):
        manifest = load_json_file(EXAMPLES / "manifest.json")
        grant = load_json_file(EXAMPLES / "grant.json")
        for request_name in ("allowed-request.json", "denied-request.json"):
            request = load_json_file(EXAMPLES / request_name)
            outcome = evaluate(
                EXAMPLES / "chef-helper",
                EXAMPLES / "workspace",
                manifest,
                grant,
                request,
                at=AT,
                workspace_id="chef-demo-workspace",
            )
            with self.subTest(request=request_name):
                self.assertEqual(
                    check_schema(outcome["receipt"], self.schemas["receipt-v2.json"]),
                    [],
                )


if __name__ == "__main__":
    unittest.main()
