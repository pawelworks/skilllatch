"""Offline loader for advisory scanner reports (SkillSpector-shaped JSON).

This module reads one local JSON file. It performs no network I/O. SkillLatch
never transmits skill content, scan reports, or secrets to any scanner or
endpoint; attaching a scan report is the host's choice, and the report is
advisory only.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .core import (
    _DIGEST_RE,
    PolicyError,
    _sha256,
    hash_skill_tree,
    load_json_file,
)

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


def _find_key(
    report: dict[str, Any], names: tuple[str, ...]
) -> tuple[bool, Any, str | None]:
    """Find the first case-insensitive match; top level, then one level deep."""
    lowered = {key.lower(): key for key in report}
    for name in names:
        key = lowered.get(name.lower())
        if key is not None:
            return True, report[key], key
    for container in _CONTAINERS:
        key = lowered.get(container)
        if key is None:
            continue
        nested = report[key]
        if not isinstance(nested, dict):
            continue
        nested_lowered = {nested_key.lower(): nested_key for nested_key in nested}
        for name in names:
            nested_key = nested_lowered.get(name.lower())
            if nested_key is not None:
                return True, nested[nested_key], None
    return False, None, None


def _first_string(
    report: dict[str, Any], names: tuple[str, ...]
) -> tuple[str | None, str | None]:
    """Return the first string-valued candidate and the top-level key used.

    Top-level candidates are tried in order before any container level.
    """
    lowered = {key.lower(): key for key in report}
    for name in names:
        key = lowered.get(name.lower())
        if key is not None and isinstance(report[key], str):
            return report[key], key
    for container in _CONTAINERS:
        key = lowered.get(container)
        if key is None:
            continue
        nested = report[key]
        if not isinstance(nested, dict):
            continue
        nested_lowered = {nested_key.lower(): nested_key for nested_key in nested}
        for name in names:
            nested_key = nested_lowered.get(name.lower())
            if nested_key is not None and isinstance(nested[nested_key], str):
                return nested[nested_key], None
    return None, None


def _derive_scan_mode(report: dict[str, Any]) -> str | None:
    found, metadata, _ = _find_key(report, ("metadata",))
    if not found or not isinstance(metadata, dict):
        return None
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
        report = load_json_file(report_path)
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

    scanner, key = _first_string(report, _SCANNER_KEYS)
    if key is not None:
        consumed.add(key)
    if scanner is None:
        scanner = "skillspector"

    found, value, key = _find_key(report, _SCAN_MODE_KEYS)
    scan_mode: str | None = None
    if found:
        if isinstance(value, str):
            scan_mode = value
            if key is not None:
                consumed.add(key)
        else:
            warnings.append("scan mode is present but not a string; ignoring it")
    if scan_mode is None:
        scan_mode = _derive_scan_mode(report)

    coverage: dict[str, Any] = {}
    for name in _COVERAGE_KEYS:
        found, value, key = _find_key(report, (name,))
        if found and isinstance(value, dict):
            coverage = value
            if key is not None:
                consumed.add(key)
            break

    subject_digest: str | None = None
    raw_digest, key = _first_string(report, _DIGEST_KEYS)
    if raw_digest is not None:
        if _DIGEST_RE.fullmatch(raw_digest):
            subject_digest = raw_digest
            if key is not None:
                consumed.add(key)
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
        "metadata": {key: value for key, value in report.items() if key not in consumed},
        "warnings": warnings,
    }
