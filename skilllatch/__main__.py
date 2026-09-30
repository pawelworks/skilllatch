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


def _at(value: str) -> datetime:
    try:
        return _parse_time(value, "--at")
    except PolicyError as exc:
        raise argparse.ArgumentTypeError(
            "--at must be an RFC3339 UTC timestamp"
        ) from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="skilllatch")
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
    args = parser.parse_args(argv)

    if args.command == "digest":
        try:
            print(hash_skill_tree(args.skill_dir))
            return 0
        except PolicyError as exc:
            print(f"{exc.code}: {exc.reason}", file=sys.stderr)
            return 2

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
        )
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    return 0 if result["allowed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
