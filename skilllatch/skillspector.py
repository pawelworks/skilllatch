"""Offline loader for advisory scanner reports (SkillSpector-shaped JSON).

This module reads one local JSON file. It performs no network I/O. SkillLatch
never transmits skill content, scan reports, or secrets to any scanner or
endpoint; attaching a scan report is the host's choice, and the report is
advisory only.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from .core import (
    _DIGEST_RE,
    PolicyError,
    _sha256,
    hash_skill_tree,
    load_json_file,
)

SCAN_REASON_CODES = frozenset({"invalid_scan_report", "scan_digest_mismatch"})

_CONTAINERS = ("subject", "target", "scan", "analysis", "summary")
_SCAN_MODE_KEYS = ("scan_mode", "scanMode", "mode", "analysis_mode")
_COVERAGE_KEYS = (
    "coverage",
    "analysis_coverage",
    "coverage_summary",
    "analysis_completeness",
)
_DIGEST_KEYS = (
    "subject_digest",
    "skill_digest",
    "target_digest",
    "digest",
    "skillTreeDigest",
)
_SCANNER_KEYS = ("tool", "scanner", "tool_name")


def _is_string(value: Any) -> bool:
    return isinstance(value, str)


def _container_value(report: dict[str, Any], container: str) -> tuple[str, Any]:
    """Exact-case container key first, then a case-variant key."""
    if container in report:
        return container, report[container]
    for key, value in report.items():
        if key.lower() == container:
            return key, value
    return container, None


def _search(
    report: dict[str, Any],
    names: tuple[str, ...],
    field: str,
    keep: Callable[[Any], bool] = lambda _: True,
) -> tuple[list[tuple[str, Any]], list[str]]:
    """Collect candidate hits for one field, best precedence first.

    Returns (hits, warnings) where hits are (source path, value) pairs. Top
    level beats containers; exact-case keys beat case variants. Ambiguities
    produce a warning naming the competing keys.
    """
    lowered_names = {name.lower() for name in names}
    exact: list[tuple[str, Any]] = []
    variants: list[tuple[str, Any]] = []
    nested: list[tuple[str, Any]] = []
    for name in names:
        if name in report and keep(report[name]):
            exact.append((name, report[name]))
    for key, value in report.items():
        if key not in names and key.lower() in lowered_names and keep(value):
            variants.append((key, value))
    for container in _CONTAINERS:
        ckey, cvalue = _container_value(report, container)
        if not isinstance(cvalue, dict):
            continue
        for name in names:
            if name in cvalue and keep(cvalue[name]):
                nested.append((f"{ckey}.{name}", cvalue[name]))
        for key, value in cvalue.items():
            if key not in names and key.lower() in lowered_names and keep(value):
                nested.append((f"{ckey}.{key}", value))
    warnings: list[str] = []
    top = exact if exact else variants
    if top:
        if exact and variants:
            warnings.append(
                f"{field} matches both {exact[0][0]!r} and case-variant "
                f"{variants[0][0]!r}; using {exact[0][0]!r}"
            )
        if nested:
            warnings.append(
                f"{field} is present at the top level and in "
                f"{nested[0][0]!r}; using the top-level value"
            )
        return top, warnings
    return nested, warnings


def _derive_scan_mode(report: dict[str, Any]) -> str | None:
    hits, _ = _search(report, ("metadata",), "metadata")
    if not hits or not isinstance(hits[0][1], dict):
        return None
    metadata = hits[0][1]
    lowered = {key.lower(): metadata[key] for key in metadata}
    requested = lowered.get("llm_requested")
    available = lowered.get("llm_available")
    if type(requested) is bool and type(available) is bool:
        if requested and available:
            return "static+llm"
        if requested and not available:
            return "static-only"
    return None


def load_scan_report(report_path: str | Path, *, skill_dir: str | Path | None = None) -> dict[str, Any]:
    """Load one local scanner report into a versioned advisory summary.

    The returned mapping is informational only; it never changes a policy
    decision. When ``skill_dir`` is given and the report carries a well-formed
    subject digest, the digest must match the skill tree or a PolicyError with
    code ``scan_digest_mismatch`` is raised.
    """
    try:
        report = load_json_file(report_path, max_bytes=4 * 1024 * 1024)
    except PolicyError as exc:
        raise PolicyError(
            "invalid_scan_report",
            f"scan report could not be loaded ({exc.code}: {exc.reason})",
        ) from exc
    if not isinstance(report, dict):
        raise PolicyError(
            "invalid_scan_report", "scan report must be a JSON object"
        )

    warnings: list[str] = []
    consumed: set[str] = set()
    sources: dict[str, str] = {}

    def record(field: str, source: str) -> None:
        sources[field] = source
        if "." not in source:
            consumed.add(source)

    scanner = "skillspector"
    hits, found_warnings = _search(report, _SCANNER_KEYS, "scanner", _is_string)
    warnings.extend(found_warnings)
    if hits:
        source, scanner = hits[0]
        record("scanner", source)

    scan_mode: str | None = None
    hits, found_warnings = _search(report, _SCAN_MODE_KEYS, "scan mode")
    warnings.extend(found_warnings)
    if hits:
        source, value = hits[0]
        if isinstance(value, str):
            scan_mode = value
            record("scan_mode", source)
        else:
            warnings.append("scan mode is present but not a string; ignoring it")
    if scan_mode is None:
        scan_mode = _derive_scan_mode(report)

    coverage: dict[str, Any] = {}
    hits, found_warnings = _search(report, _COVERAGE_KEYS, "coverage")
    warnings.extend(found_warnings)
    if hits:
        source, value = hits[0]
        if isinstance(value, dict):
            coverage = value
            record("coverage", source)
        else:
            warnings.append("coverage is present but not an object; ignoring it")

    subject_digest: str | None = None
    hits, found_warnings = _search(report, _DIGEST_KEYS, "subject digest", _is_string)
    warnings.extend(found_warnings)
    if hits:
        source, raw_digest = hits[0]
        if _DIGEST_RE.fullmatch(raw_digest):
            subject_digest = raw_digest
            record("subject_digest", source)
        else:
            warnings.append(
                "report carries a malformed subject digest; treating it as absent"
            )

    digest_match: bool | None = None
    if skill_dir is not None:
        if subject_digest is None:
            warnings.append("report carries no subject digest")
        else:
            if hash_skill_tree(skill_dir) != subject_digest:
                raise PolicyError(
                    "scan_digest_mismatch",
                    "scan report subject does not match the skill tree",
                )
            digest_match = True

    return {
        "schema": "skilllatch.scan_advisory.v1",
        "advisory": True,
        "scanner": scanner,
        "report_hash": _sha256(report),
        "scan_mode": scan_mode,
        "coverage": coverage,
        "subject_digest": subject_digest,
        "digest_match": digest_match,
        "sources": sources,
        "metadata": {key: value for key, value in report.items() if key not in consumed},
        "warnings": warnings,
    }
