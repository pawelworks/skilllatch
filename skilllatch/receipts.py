"""Offline receipt and audit-log verification.

Verification is fully offline: no network, no clock, and no original policy
inputs are needed. It proves internal consistency only — that a receipt's
digest matches its canonical body and that an audit log's hash chain is
unbroken.

The audit log is tamper-EVIDENT, not tamper-proof. There are no signatures
or keys: an attacker who rewrites the whole file can rechain it. The format
deters silent single-record edits and detects edits, gaps, deletions,
truncation, and reordering — nothing more.
"""

from __future__ import annotations

import copy
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .core import (
    _DIGEST_RE,
    _UTC_TIMESTAMP_RE,
    PolicyError,
    _canonical_bytes,
    _sha256,
    _strict_json_loads,
)

AUDIT_SCHEMA = "skilllatch.audit.v1"
RECEIPT_REASON_CODES = frozenset(
    {
        "invalid_receipt",
        "receipt_digest_mismatch",
        "invalid_audit_log",
        "audit_chain_mismatch",
    }
)

_V1_KEYS = {
    "version",
    "allowed",
    "reason_code",
    "reason",
    "evaluated_at",
    "skill_digest",
    "manifest_hash",
    "grant_hash",
    "request_hash",
    "digest",
}
_V2_KEYS = _V1_KEYS | {"workspace_id", "workspace_binding"}
_BINDINGS = ("pinned", "unpinned", "none")


def verify_receipt(receipt: Any) -> dict[str, Any]:
    """Check one receipt's shape and self-consistency; fully offline."""
    if not isinstance(receipt, dict):
        raise PolicyError("invalid_receipt", "receipt must be a JSON object")
    version = receipt.get("version")
    if type(version) is not int or version not in (1, 2):
        raise PolicyError(
            "unsupported_version", "receipt version must be one of: 1, 2"
        )
    expected = _V1_KEYS if version == 1 else _V2_KEYS
    keys = set(receipt)
    if keys != expected:
        detail = []
        if expected - keys:
            detail.append(f"missing: {', '.join(sorted(expected - keys))}")
        if keys - expected:
            detail.append(f"extra: {', '.join(sorted(keys - expected))}")
        raise PolicyError(
            "invalid_receipt", f"receipt keys mismatch ({'; '.join(detail)})"
        )
    try:
        _canonical_bytes(receipt)
    except PolicyError as exc:
        raise PolicyError(
            "invalid_receipt", f"receipt is not canonical JSON ({exc.reason})"
        ) from exc
    if type(receipt["allowed"]) is not bool:
        raise PolicyError("invalid_receipt", "receipt allowed must be boolean")
    for label in ("reason_code", "reason"):
        if not isinstance(receipt[label], str) or not receipt[label]:
            raise PolicyError(
                "invalid_receipt", f"receipt {label} must be a nonempty string"
            )
    if any(ord(c) < 32 or ord(c) == 127 for c in receipt["reason_code"]):
        raise PolicyError(
            "invalid_receipt",
            "receipt reason_code must not contain control characters",
        )
    evaluated_at = receipt["evaluated_at"]
    if not isinstance(evaluated_at, str) or not _UTC_TIMESTAMP_RE.fullmatch(
        evaluated_at
    ):
        raise PolicyError(
            "invalid_receipt",
            "receipt evaluated_at must use YYYY-MM-DDTHH:MM:SS[.fraction]Z",
        )
    try:
        datetime.fromisoformat(evaluated_at)
    except ValueError as exc:
        raise PolicyError(
            "invalid_receipt", "receipt evaluated_at is not a valid timestamp"
        ) from exc
    skill_digest = receipt["skill_digest"]
    if skill_digest is not None and (
        not isinstance(skill_digest, str) or not _DIGEST_RE.fullmatch(skill_digest)
    ):
        raise PolicyError(
            "invalid_receipt",
            "receipt skill_digest must be null or a sha256: digest",
        )
    if version == 2:
        if receipt["workspace_binding"] not in _BINDINGS:
            raise PolicyError(
                "invalid_receipt",
                "receipt workspace_binding must be pinned, unpinned, or none",
            )
        workspace_id = receipt["workspace_id"]
        if workspace_id is not None and not isinstance(workspace_id, str):
            raise PolicyError(
                "invalid_receipt", "receipt workspace_id must be null or a string"
            )
    for label in ("manifest_hash", "grant_hash", "request_hash", "digest"):
        value = receipt[label]
        if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
            raise PolicyError(
                "invalid_receipt", f"receipt {label} must be a sha256: digest"
            )
    body = {key: value for key, value in receipt.items() if key != "digest"}
    if _sha256(body) != receipt["digest"]:
        raise PolicyError(
            "receipt_digest_mismatch", "receipt digest does not match its contents"
        )
    return {"valid": True, "version": version, "digest": receipt["digest"]}


def make_audit_line(receipt: Any, prev_digest: Any, line_number: Any) -> dict[str, Any]:
    """Chain a verified receipt onto the previous line's digest."""
    verify_receipt(receipt)
    if type(line_number) is not int or line_number < 1:
        raise PolicyError(
            "invalid_audit_log", "audit line number must be a positive integer"
        )
    if line_number == 1:
        if prev_digest is not None:
            raise PolicyError(
                "invalid_audit_log", "audit line 1 must not have a previous digest"
            )
    elif not isinstance(prev_digest, str) or not _DIGEST_RE.fullmatch(prev_digest):
        raise PolicyError(
            "invalid_audit_log",
            f"audit line {line_number} needs the previous line digest",
        )
    body = copy.deepcopy(receipt)
    return {
        "line": line_number,
        "receipt": body,
        "prev_digest": prev_digest,
        "line_digest": _sha256(
            {"line": line_number, "prev_digest": prev_digest, "receipt": body}
        ),
    }


def verify_audit_log(lines: Any) -> dict[str, Any]:
    """Verify an audit log's hash chain, numbering, and receipts."""
    if not isinstance(lines, list) or not lines:
        raise PolicyError("invalid_audit_log", "audit log must be a nonempty array")
    previous: str | None = None
    for index, line in enumerate(lines, start=1):
        if not isinstance(line, dict) or set(line) != {
            "line",
            "receipt",
            "prev_digest",
            "line_digest",
        }:
            raise PolicyError(
                "invalid_audit_log",
                f"line {index}: audit line must have exactly: "
                "line, line_digest, prev_digest, receipt",
            )
        if line["prev_digest"] != previous:
            raise PolicyError(
                "audit_chain_mismatch",
                f"line {index}: previous digest does not match the chain",
            )
        if type(line["line"]) is not int or line["line"] != index:
            raise PolicyError(
                "invalid_audit_log",
                f"line {index}: line number gap or renumbering",
            )
        try:
            verify_receipt(line["receipt"])
        except PolicyError as exc:
            raise PolicyError(exc.code, f"line {index}: {exc.reason}") from exc
        if not isinstance(line["line_digest"], str) or not _DIGEST_RE.fullmatch(
            line["line_digest"]
        ):
            raise PolicyError(
                "invalid_audit_log",
                f"line {index}: line_digest must be a sha256: digest",
            )
        body = {
            "line": line["line"],
            "prev_digest": line["prev_digest"],
            "receipt": line["receipt"],
        }
        if _sha256(body) != line["line_digest"]:
            raise PolicyError(
                "audit_chain_mismatch",
                f"line {index}: line digest does not match its contents",
            )
        previous = line["line_digest"]
    return {"valid": True, "lines": len(lines)}


def load_audit_log(path: str | Path) -> list[dict[str, Any]]:
    """Read a JSONL audit log with the same strictness as load_json_file."""
    try:
        with open(path, "r", encoding="utf-8") as stream:
            text = stream.read()
    except (OSError, UnicodeError) as exc:
        raise PolicyError(
            "invalid_audit_log", f"cannot read audit log from {path}"
        ) from exc
    raw_lines = text.split("\n")
    if raw_lines and raw_lines[-1] == "":
        raw_lines.pop()  # tolerate one trailing newline
    lines: list[dict[str, Any]] = []
    for number, raw in enumerate(raw_lines, start=1):
        content = raw.rstrip("\r")
        if not content.strip():
            raise PolicyError(
                "invalid_audit_log", f"line {number}: blank line in audit log"
            )
        try:
            value = _strict_json_loads(content)
            _canonical_bytes(value)
        except PolicyError as exc:
            raise PolicyError(
                "invalid_audit_log",
                f"line {number}: invalid JSON ({exc.code}: {exc.reason})",
            ) from exc
        except (ValueError, RecursionError) as exc:
            raise PolicyError(
                "invalid_audit_log", f"line {number}: invalid JSON"
            ) from exc
        lines.append(value)
    return lines


def audit_line_to_json(line: dict[str, Any]) -> str:
    """Serialize one audit line as canonical compact JSON, no trailing newline."""
    return json.dumps(line, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
