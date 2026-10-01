"""Host-originated context provenance envelope (skilllatch.context.v1).

Records which instruction artifacts a trusted host observed as active when a
tool was requested. It does NOT claim those artifacts caused the request:
attribution is the constant 'unknown'. The envelope contains digests and
labels only — never file paths, instruction text, tool arguments, or
secrets. It is a provenance record, not a decision; policy outcomes live in
the v2 receipt. Stdlib only.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .core import _DIGEST_RE, PolicyError, _canonical_bytes, _sha256, _utc_time

SCHEMA = "skilllatch.context.v1"
ATTRIBUTION = "unknown"

_ADVISORY_SCHEMA = "skilllatch.scan_advisory.v1"


def _invalid(reason: str) -> PolicyError:
    return PolicyError("invalid_context", reason)


def _safe_string(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise _invalid(
            f"{label} must be a nonempty string without control characters"
        )
    return value


def _digest_value(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise _invalid(f"{label} must be a sha256: digest")
    return value


def _skill_source(value: Any) -> dict[str, Any]:
    # Sources carry identity only; a path, URI payload, or instruction text
    # would break the envelope's digests-and-labels-only rule.
    if not isinstance(value, dict):
        raise _invalid("skill source must be an object")
    if set(value) == {"type"} and value["type"] == "local_dir":
        return {"type": "local_dir"}
    if set(value) == {"type", "server_identity", "uri"} and value["type"] == "mcp":
        return {
            "type": "mcp",
            "server_identity": _safe_string(
                value["server_identity"], "server identity"
            ),
            "uri": _safe_string(value["uri"], "skill URI"),
        }
    raise _invalid(
        "skill source must be exactly {'type': 'local_dir'} or an mcp source "
        "with server_identity and uri"
    )


def _skill_entry(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _invalid("skill entries must be objects")
    keys = set(value)
    if not {"digest", "source"} <= keys or not keys <= {"digest", "source", "name"}:
        raise _invalid(
            "skill entries must have exactly digest and source, plus optional name"
        )
    entry: dict[str, Any] = {
        "digest": _digest_value(value["digest"], "skill digest"),
        "source": _skill_source(value["source"]),
    }
    if "name" in value:
        entry["name"] = _safe_string(value["name"], "skill name")
    return entry


def _instruction_entry(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"label", "digest"}:
        raise _invalid(
            "project instruction entries must have exactly: digest, label"
        )
    return {
        "label": _safe_string(value["label"], "project instruction label"),
        "digest": _digest_value(value["digest"], "project instruction digest"),
    }


def _reduce_advisory(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or value.get("schema") != _ADVISORY_SCHEMA:
        raise _invalid("advisory must be a skilllatch.scan_advisory.v1 summary")
    report_hash = _digest_value(value.get("report_hash"), "advisory report_hash")
    scanner = value.get("scanner")
    if not isinstance(scanner, str) or not scanner:
        raise _invalid("advisory scanner must be a nonempty string")
    scan_mode = value.get("scan_mode")
    if scan_mode is not None and not isinstance(scan_mode, str):
        raise _invalid("advisory scan_mode must be null or a string")
    digest_match = value.get("digest_match")
    if digest_match is not None and type(digest_match) is not bool:
        raise _invalid("advisory digest_match must be null or boolean")
    # The full advisory's metadata echoes arbitrary report content; the
    # envelope stores digests and labels only.
    return {
        "schema": _ADVISORY_SCHEMA,
        "scanner": scanner,
        "scan_mode": scan_mode,
        "digest_match": digest_match,
        "report_hash": report_hash,
    }


def build_context(
    *,
    session_id: str,
    task_id: str,
    workspace_id: str | None = None,
    skills: list[Any],
    project_instructions: list[Any] | None = None,
    tool: dict[str, Any],
    advisory: dict[str, Any] | None = None,
    grant_hash: str,
    at: datetime | None = None,
) -> dict[str, Any]:
    """Build one context provenance envelope (skilllatch.context.v1).

    ``skills`` lists the instruction artifacts the host observed as active:
    each entry carries a content digest and a source (``local_dir`` or an MCP
    server identity plus skill URI). ``project_instructions`` carries a label
    and digest per active instruction artifact. ``tool`` carries the tool
    name and the digest of the schema the host invoked. ``advisory`` accepts
    a full skilllatch.scan_advisory.v1 summary and stores only its reduced
    identity. ``grant_hash`` is obtainable from a v2 receipt's ``grant_hash``;
    this module never touches grant content. Every shape violation raises
    ``PolicyError("invalid_context", ...)``; a clock violation keeps core's
    ``invalid_time``.
    """
    when = _utc_time(at)
    if workspace_id is not None:
        workspace_id = _safe_string(workspace_id, "workspace_id")
    if not isinstance(skills, list):
        raise _invalid("skills must be an array")
    skill_entries = [_skill_entry(entry) for entry in skills]
    # Duplicates are preserved; sorting only fixes enumeration order so a
    # fixed clock and the same input sets always yield an identical digest.
    skill_entries.sort(key=lambda entry: (entry["digest"], _canonical_bytes(entry["source"])))
    instructions = [
        _instruction_entry(entry) for entry in (project_instructions or [])
    ]
    instructions.sort(key=lambda entry: (entry["label"], entry["digest"]))
    if not isinstance(tool, dict) or set(tool) != {"name", "schema_digest"}:
        raise _invalid("tool must have exactly: name, schema_digest")
    tool_entry = {
        "name": _safe_string(tool["name"], "tool name"),
        "schema_digest": _digest_value(tool["schema_digest"], "tool schema_digest"),
    }
    envelope = {
        "schema": SCHEMA,
        "recorded_at": when.isoformat().replace("+00:00", "Z"),
        "session_id": _safe_string(session_id, "session_id"),
        "task_id": _safe_string(task_id, "task_id"),
        "workspace_id": workspace_id,
        "skills": skill_entries,
        "project_instructions": instructions,
        "tool": tool_entry,
        "advisory": _reduce_advisory(advisory),
        "grant_hash": _digest_value(grant_hash, "grant_hash"),
        # Presence of instructions does not establish they caused the
        # request, so attribution is a constant, never a parameter.
        "attribution": ATTRIBUTION,
    }
    envelope["digest"] = _sha256(envelope)
    return envelope
