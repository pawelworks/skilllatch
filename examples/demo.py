"""Scripted, narrated, self-checking demo of the reference gated host.

The demo copies the example skill and workspace into a temporary directory so
the repository fixtures stay byte-identical, then walks seven requests through
the gate: one allowed read and six denials. Every step asserts an expected
reason code and that no denied request ever reaches a tool. Exit code is 0
when every expectation holds and 1 otherwise. Tools are simulated; this
demonstrates gate wiring, not production interception.
"""

from __future__ import annotations

import argparse
import copy
import json
import shutil
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = Path(__file__).resolve().parent
for extra in (str(ROOT), str(EXAMPLES)):
    if extra not in sys.path:
        sys.path.insert(0, extra)

from skilllatch import hash_skill_tree, load_json_file, load_scan_report

from host_adapter import (
    GatedHost,
    make_command_stub,
    make_fetch_stub,
    make_file_tool,
)

AT = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
WORKSPACE_ID = "chef-demo-workspace"

_QUIET = False


def say(text: str = "") -> None:
    if not _QUIET:
        print(text)


def show_receipt(receipt: dict | None) -> None:
    if receipt is not None:
        say(json.dumps(receipt, indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    global _QUIET
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--quiet", action="store_true", help="suppress narration")
    args = parser.parse_args(argv)
    _QUIET = args.quiet

    say("SkillLatch gated-host demo (simulated tools; fixed clock 2026-10-01T12:00:00Z)")
    say("All files are staged in a temporary directory; repo fixtures are untouched.")

    with tempfile.TemporaryDirectory() as temp:
        stage = Path(temp)
        skill_dir = stage / "chef-helper"
        workspace = stage / "workspace"
        shutil.copytree(EXAMPLES / "chef-helper", skill_dir)
        shutil.copytree(EXAMPLES / "workspace", workspace)
        manifest = load_json_file(EXAMPLES / "manifest.json")
        grant = load_json_file(EXAMPLES / "grant.json")
        advisory = load_scan_report(
            EXAMPLES / "skillspector-report.json", skill_dir=skill_dir
        )
        assert hash_skill_tree(skill_dir) == manifest["skill"]["digest"]
        say(
            "Advisory scan report attached: "
            f"scanner={advisory['scanner']} mode={advisory['scan_mode']} "
            f"digest_match={advisory['digest_match']} (advisory only)"
        )

        def build_host(workspace_id: str) -> tuple[GatedHost, dict[str, object]]:
            host = GatedHost(
                skill_dir,
                workspace,
                manifest,
                grant,
                workspace_id=workspace_id,
                clock=lambda: AT,
                advisory=advisory,
            )
            tools = {
                "file": make_file_tool(workspace),
                "network": make_fetch_stub(),
                "command": make_command_stub(),
            }
            host.register_tool("file", tools["file"])
            host.register_tool("network", tools["network"])
            host.register_tool("command", tools["command"])
            return host, tools

        host, tools = build_host(WORKSPACE_ID)
        base = {"session_id": "demo-session", "task_id": "soup-question"}
        outcomes: list[dict] = []
        mismatches: list[str] = []

        def step(
            number: int,
            title: str,
            request: dict,
            expected_code: str,
            expected_dispatched: bool,
            actor: GatedHost = host,
        ) -> dict:
            say()
            say(f"Step {number}: {title}")
            say(f"  request: {json.dumps(request, sort_keys=True)}")
            outcome = actor.dispatch(copy.deepcopy(request))
            outcomes.append(outcome)
            say(f"  decision: {outcome['reason_code']} (dispatched={outcome['dispatched']})")
            if outcome["reason_code"] != expected_code or (
                outcome["dispatched"] != expected_dispatched
            ):
                mismatches.append(
                    f"step {number}: expected {expected_code}/dispatched="
                    f"{expected_dispatched}, got {outcome['reason_code']}/"
                    f"dispatched={outcome['dispatched']}"
                )
            return outcome

        first = step(
            1,
            "ALLOW read recipes/soup.txt (granted path, pinned workspace)",
            {**base, "kind": "file", "action": "read", "path": "recipes/soup.txt"},
            "allowed",
            True,
        )
        say("  receipt:")
        show_receipt(first["receipt"])
        say(f"  tool output: {first['tool_result']!r}")
        assert len(tools["network"].calls) == 0
        assert len(tools["command"].calls) == 0

        step(
            2,
            "DENY read private.txt (no capability for this path)",
            {**base, "kind": "file", "action": "read", "path": "private.txt"},
            "capability_not_granted",
            False,
        )
        assert len(tools["file"].calls) == 1  # only step 1 reached the file tool

        step(
            3,
            "DENY fetch https://attacker.example/collect (undeclared egress)",
            {**base, "kind": "network", "url": "https://attacker.example/collect"},
            "capability_not_granted",
            False,
        )

        step(
            4,
            "DENY command ['git', 'status', '--short'] (declared but not granted)",
            {**base, "kind": "command", "argv": ["git", "status", "--short"]},
            "capability_not_granted",
            False,
        )

        step(
            5,
            "DENY task_id 'other-task' (grant is scoped to one task)",
            {
                "session_id": "demo-session",
                "task_id": "other-task",
                "kind": "file",
                "action": "read",
                "path": "recipes/soup.txt",
            },
            "scope_mismatch",
            False,
        )

        skill_file = skill_dir / "SKILL.md"
        original_bytes = skill_file.read_bytes()
        try:
            skill_file.write_bytes(original_bytes + b"\n# mutated after approval\n")
            step(
                6,
                "DENY after SKILL.md was modified (digest no longer matches)",
                {**base, "kind": "file", "action": "read", "path": "recipes/soup.txt"},
                "skill_digest_mismatch",
                False,
            )
        finally:
            skill_file.write_bytes(original_bytes)

        replay_host, replay_tools = build_host("laptop-b")
        step(
            7,
            "DENY grant replayed on another workspace (pinned to chef-demo-workspace)",
            {**base, "kind": "file", "action": "read", "path": "recipes/soup.txt"},
            "workspace_mismatch",
            False,
            actor=replay_host,
        )
        assert len(replay_tools["file"].calls) == 0

    allowed = sum(1 for o in outcomes if o["allowed"] and o["dispatched"])
    denied = sum(1 for o in outcomes if not o["allowed"])
    leaked = sum(1 for o in outcomes if not o["allowed"] and o["dispatched"])
    print(
        f"{len(outcomes)} steps: {allowed} allowed+dispatched, {denied} denied, "
        f"{leaked} denied requests reached a tool"
    )
    if mismatches:
        for mismatch in mismatches:
            print(f"MISMATCH: {mismatch}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
