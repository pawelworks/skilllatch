"""Indicative local timing of evaluate(); not a benchmark claim.

Measures the full decision path over cached in-memory policy inputs against
the repository's example skill and workspace. Every iteration re-runs
evaluate(), which includes a full hash_skill_tree rehash of the skill
directory — that filesystem cost is part of every decision and is never
amortized. Numbers vary with machine, OS, filesystem cache, and Python build.
"""

from __future__ import annotations

import argparse
import platform
import statistics
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = Path(__file__).resolve().parent
for extra in (str(ROOT), str(EXAMPLES)):
    if extra not in sys.path:
        sys.path.insert(0, extra)

from skilllatch import evaluate, load_json_file

AT = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
WORKSPACE_ID = "chef-demo-workspace"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--warmup", type=int, default=200)
    args = parser.parse_args(argv)

    manifest = load_json_file(EXAMPLES / "manifest.json")
    grant = load_json_file(EXAMPLES / "grant.json")
    request = load_json_file(EXAMPLES / "allowed-request.json")

    def run_once() -> None:
        decision = evaluate(
            EXAMPLES / "chef-helper",
            EXAMPLES / "workspace",
            manifest,
            grant,
            request,
            at=AT,
            workspace_id=WORKSPACE_ID,
        )
        if not decision["allowed"]:
            raise SystemExit("benchmark sanity check failed")

    for _ in range(args.warmup):
        run_once()
    deltas: list[float] = []
    for _ in range(args.iterations):
        started = time.perf_counter()
        run_once()
        deltas.append(time.perf_counter() - started)

    micros = [delta * 1_000_000 for delta in deltas]
    print("SkillLatch evaluate() indicative local timing (not a benchmark claim)")
    print(f"python: {sys.version.split()[0]} ({platform.platform()})")
    print(f"iterations: {args.iterations} (warmup {args.warmup})")
    print(f"total_ms: {sum(deltas) * 1000:.1f}")
    print(
        "us_per_decision: "
        f"mean={statistics.fmean(micros):.1f} "
        f"median={statistics.median(micros):.1f} "
        f"min={min(micros):.1f}"
    )
    print(
        "note: every decision re-runs hash_skill_tree over the skill directory; "
        "that filesystem cost is included and never amortized"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
