"""Byte-exact golden receipts for the examples/ fixtures.

These literals pin the deterministic receipt format: any change to canonical
JSON, receipt fields, or digest computation breaks this file. Regenerate them
only with a deliberate format change AND a SPEC update, never to silence a
failure. Regeneration snippet (run from the repository root):

    import json
    from datetime import UTC, datetime
    from pathlib import Path
    from skilllatch import evaluate, load_json_file

    EXAMPLES = Path("examples")
    AT = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
    manifest = load_json_file(EXAMPLES / "manifest.json")
    grant = load_json_file(EXAMPLES / "grant.json")
    allowed = load_json_file(EXAMPLES / "allowed-request.json")
    denied = load_json_file(EXAMPLES / "denied-request.json")
    for name, (request, workspace_id) in {
        "ALLOW_READ": (allowed, "chef-demo-workspace"),
        "DENY_NETWORK": (denied, "chef-demo-workspace"),
        "DENY_WORKSPACE": (allowed, "laptop-b"),
        "DENY_NO_WORKSPACE": (allowed, None),
    }.items():
        decision = evaluate(
            EXAMPLES / "chef-helper", EXAMPLES / "workspace",
            manifest, grant, request, at=AT, workspace_id=workspace_id,
        )
        print(name, json.dumps(decision["receipt"], indent=4, sort_keys=True))
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime
from pathlib import Path

from skilllatch import evaluate, load_json_file, verify_receipt
from skilllatch.core import _sha256

AT = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
PROJECT = Path(__file__).resolve().parents[1]
EXAMPLES = PROJECT / "examples"

ALLOW_READ = {
    "version": 2,
    "allowed": True,
    "reason_code": "allowed",
    "reason": "request matches the active capability grant",
    "evaluated_at": "2026-10-01T12:00:00Z",
    "skill_digest": "sha256:d9b9ac64610814527c8a51c86dc34bfffa7db2c049b605a14fbcf939e5adc6e9",
    "workspace_id": "chef-demo-workspace",
    "workspace_binding": "pinned",
    "manifest_hash": "sha256:145ea58b2953d3f2a9239811d51cdd340b39df7db5b717702edf42e2fdb5afb8",
    "grant_hash": "sha256:bfa8a8e4e8238d91b7d9d8716a1999e138e0ccf51687a3da8ccd53b2c6207881",
    "request_hash": "sha256:bfcd27dcc277beefbcaa1a103b4f9fec8eb4f8fd04220e8fcce20c116caac72f",
    "digest": "sha256:c2132f3c3ac85496d2f3d12b121ed420e1e62f97b62fa352e264ebd8fa1d6200",
}

DENY_NETWORK = {
    "version": 2,
    "allowed": False,
    "reason_code": "capability_not_granted",
    "reason": "network origin https://attacker.example is not granted",
    "evaluated_at": "2026-10-01T12:00:00Z",
    "skill_digest": "sha256:d9b9ac64610814527c8a51c86dc34bfffa7db2c049b605a14fbcf939e5adc6e9",
    "workspace_id": "chef-demo-workspace",
    "workspace_binding": "pinned",
    "manifest_hash": "sha256:145ea58b2953d3f2a9239811d51cdd340b39df7db5b717702edf42e2fdb5afb8",
    "grant_hash": "sha256:bfa8a8e4e8238d91b7d9d8716a1999e138e0ccf51687a3da8ccd53b2c6207881",
    "request_hash": "sha256:e8f695358dd7dfa818e83697c6a27df4c31820cf453ac4aca67c2e8c53f324c9",
    "digest": "sha256:e0237274fe851ede9436b97233fdc3d962f63eec12583dd8d8f8c524799cb613",
}

DENY_WORKSPACE = {
    "version": 2,
    "allowed": False,
    "reason_code": "workspace_mismatch",
    "reason": "grant is pinned to a different workspace",
    "evaluated_at": "2026-10-01T12:00:00Z",
    "skill_digest": "sha256:d9b9ac64610814527c8a51c86dc34bfffa7db2c049b605a14fbcf939e5adc6e9",
    "workspace_id": "laptop-b",
    "workspace_binding": "pinned",
    "manifest_hash": "sha256:145ea58b2953d3f2a9239811d51cdd340b39df7db5b717702edf42e2fdb5afb8",
    "grant_hash": "sha256:bfa8a8e4e8238d91b7d9d8716a1999e138e0ccf51687a3da8ccd53b2c6207881",
    "request_hash": "sha256:bfcd27dcc277beefbcaa1a103b4f9fec8eb4f8fd04220e8fcce20c116caac72f",
    "digest": "sha256:408c2fa6fa36223128e4eb3aba189d2a7602b273f72b29e3fc30798c2a3879af",
}

DENY_NO_WORKSPACE = {
    "version": 2,
    "allowed": False,
    "reason_code": "workspace_mismatch",
    "reason": "grant is pinned to a different workspace",
    "evaluated_at": "2026-10-01T12:00:00Z",
    "skill_digest": "sha256:d9b9ac64610814527c8a51c86dc34bfffa7db2c049b605a14fbcf939e5adc6e9",
    "workspace_id": None,
    "workspace_binding": "pinned",
    "manifest_hash": "sha256:145ea58b2953d3f2a9239811d51cdd340b39df7db5b717702edf42e2fdb5afb8",
    "grant_hash": "sha256:bfa8a8e4e8238d91b7d9d8716a1999e138e0ccf51687a3da8ccd53b2c6207881",
    "request_hash": "sha256:bfcd27dcc277beefbcaa1a103b4f9fec8eb4f8fd04220e8fcce20c116caac72f",
    "digest": "sha256:312160b4308fb04df1b312aacf8110d079ce2ad3826b380ced64acd4e8d1b631",
}


class GoldenReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = load_json_file(EXAMPLES / "manifest.json")
        cls.grant = load_json_file(EXAMPLES / "grant.json")
        cls.allowed_request = load_json_file(EXAMPLES / "allowed-request.json")
        cls.denied_request = load_json_file(EXAMPLES / "denied-request.json")

    def decide(self, request, workspace_id):
        return evaluate(
            EXAMPLES / "chef-helper",
            EXAMPLES / "workspace",
            self.manifest,
            self.grant,
            request,
            at=AT,
            workspace_id=workspace_id,
        )

    def check(self, request, workspace_id, golden):
        outcomes = [self.decide(request, workspace_id) for _ in range(3)]
        for outcome in outcomes:
            self.assertEqual(outcome["receipt"], golden)
        self.assertTrue(verify_receipt(golden)["valid"])
        body = {key: value for key, value in golden.items() if key != "digest"}
        self.assertEqual(_sha256(body), golden["digest"])

    def test_allow_read(self):
        self.check(self.allowed_request, "chef-demo-workspace", ALLOW_READ)

    def test_deny_network(self):
        self.check(self.denied_request, "chef-demo-workspace", DENY_NETWORK)

    def test_deny_workspace(self):
        self.check(self.allowed_request, "laptop-b", DENY_WORKSPACE)

    def test_deny_no_workspace(self):
        self.check(self.allowed_request, None, DENY_NO_WORKSPACE)


if __name__ == "__main__":
    unittest.main()
