"""Command line interface for inspecting a skill digest and checking one call."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from .core import (
    PolicyError,
    _decision,
    _parse_time,
    evaluate,
    hash_skill_tree,
    load_json_file,
)
from .receipts import load_audit_log, verify_audit_log, verify_receipt

USAGE_ERROR = 64


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.exit(USAGE_ERROR, f"{self.prog}: error: {message}\n")


def _at(value: str) -> datetime:
    try:
        return _parse_time(value, "--at")
    except PolicyError as exc:
        raise argparse.ArgumentTypeError(
            "--at must be an RFC3339 UTC timestamp"
        ) from exc


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="skilllatch")
    commands = parser.add_subparsers(dest="command", required=True)
    digest = commands.add_parser("digest", help="hash an immutable skill directory")
    digest.add_argument("--skill-dir", required=True, type=Path)
    check = commands.add_parser("check", help="decide one proposed host tool call")
    check.add_argument("--skill-dir", required=True, type=Path)
    check.add_argument("--workspace", required=True, type=Path)
    check.add_argument("--manifest", required=True, type=Path)
    check.add_argument("--grant", required=True, type=Path)
    check.add_argument("--request", required=True, type=Path)
    check.add_argument(
        "--at", type=_at, help="diagnostic clock override; the host must own this value"
    )
    check.add_argument(
        "--workspace-id",
        default=None,
        help="host-observed workspace identity checked against a pinned grant",
    )
    verify = commands.add_parser(
        "verify", help="verify one decision receipt offline"
    )
    verify.add_argument("--receipt", required=True, type=Path)
    verify_log = commands.add_parser(
        "verify-log", help="verify an audit log offline"
    )
    verify_log.add_argument("--log", required=True, type=Path)
    args = parser.parse_args(argv)

    if args.command == "digest":
        try:
            print(hash_skill_tree(args.skill_dir))
            return 0
        except PolicyError as exc:
            print(f"{exc.code}: {exc.reason}", file=sys.stderr)
            return 3

    if args.command == "verify":
        try:
            outcome = verify_receipt(load_json_file(args.receipt))
        except PolicyError as exc:
            outcome = {"valid": False, "reason_code": exc.code, "reason": exc.reason}
        print(json.dumps(outcome, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        return 0 if outcome["valid"] else 2

    if args.command == "verify-log":
        try:
            outcome = verify_audit_log(load_audit_log(args.log))
        except PolicyError as exc:
            outcome = {"valid": False, "reason_code": exc.code, "reason": exc.reason}
        print(json.dumps(outcome, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        return 0 if outcome["valid"] else 2

    when = args.at or datetime.now(UTC)
    inputs: dict[str, object] = {"manifest": None, "grant": None, "request": None}
    try:
        for name in inputs:
            inputs[name] = load_json_file(getattr(args, name))
        result = evaluate(
            args.skill_dir,
            args.workspace,
            inputs["manifest"],
            inputs["grant"],
            inputs["request"],
            at=when,
            workspace_id=args.workspace_id,
        )
    except PolicyError as exc:
        result = _decision(
            False,
            exc.code,
            exc.reason,
            when,
            inputs["manifest"],
            inputs["grant"],
            inputs["request"],
            None,
            args.workspace_id,
            "unpinned" if args.workspace_id is not None else "none",
        )
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    return 0 if result["allowed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
