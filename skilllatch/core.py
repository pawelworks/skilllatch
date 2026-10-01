"""Pure policy decisions. This module never invokes the requested tool call.

The trusted host must own the skill snapshot, policy inputs, clock, request
metadata, and the actual tool invocation. Checking a request here does not
intercept calls made through other paths or remove filesystem race conditions.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_UTC_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_WINDOWS_DEVICE_RE = re.compile(
    r"^(?:con|prn|aux|nul|conin\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³])$",
    re.IGNORECASE,
)
_MAX_GRANT_LIFETIME = timedelta(hours=24)
_FILE_ACTIONS = ("read", "write")


class PolicyError(ValueError):
    """An input cannot be safely interpreted as a SkillLatch policy."""

    def __init__(self, code: str, reason: str):
        super().__init__(reason)
        self.code = code
        self.reason = reason


def _canonical_bytes(value: Any) -> bytes:
    def validate(item: Any) -> None:
        if item is None or type(item) in (bool, int):
            return
        if type(item) is str:
            item.encode("utf-8")
            return
        if type(item) is float:
            if not math.isfinite(item):
                raise PolicyError(
                    "invalid_json_value", "nonfinite numbers are invalid JSON inputs"
                )
            return
        if type(item) is list:
            for child in item:
                validate(child)
            return
        if type(item) is dict:
            for key, child in item.items():
                if type(key) is not str:
                    raise PolicyError(
                        "invalid_json_value", "JSON object keys must be strings"
                    )
                key.encode("utf-8")
                validate(child)
            return
        raise PolicyError("invalid_json_value", "input must contain JSON values")

    try:
        validate(value)
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except PolicyError:
        raise
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise PolicyError(
            "invalid_json_value", "input must contain JSON values"
        ) from exc


def _sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError("duplicate_json_key", f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _finite_float(raw: str) -> float:
    value = float(raw)
    if not math.isfinite(value):
        raise PolicyError(
            "invalid_json_value", "nonfinite numbers are invalid JSON inputs"
        )
    return value


def load_json_file(path: str | Path) -> Any:
    """Read strict UTF-8 JSON, rejecting duplicate object keys and NaN values."""
    try:
        with open(path, "r", encoding="utf-8") as stream:
            value = json.load(
                stream,
                object_pairs_hook=_unique_object,
                parse_float=_finite_float,
                parse_constant=lambda _: (_ for _ in ()).throw(
                    PolicyError(
                        "invalid_json_value", "NaN and Infinity are invalid JSON"
                    )
                ),
            )
        _canonical_bytes(value)
        return value
    except PolicyError:
        raise
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        ValueError,
        RecursionError,
    ) as exc:
        raise PolicyError(
            "invalid_json_file", f"cannot read valid JSON from {path}"
        ) from exc


def _object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise PolicyError(
            "invalid_schema", f"{label} must have exactly: {', '.join(sorted(keys))}"
        )
    return value


def _string(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise PolicyError(
            "invalid_schema",
            f"{label} must be a nonempty string without control characters",
        )
    return value


def _version(value: Any, allowed: set[int], label: str) -> None:
    if type(value) is not int or value not in allowed:
        raise PolicyError(
            "unsupported_version",
            f"{label} version must be one of: {', '.join(map(str, sorted(allowed)))}",
        )


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise PolicyError("invalid_schema", f"{label} must be a sha256: digest")
    return value


def _relative_path(value: Any, label: str) -> tuple[str, ...]:
    path = _string(value, label)
    if path.startswith("/") or any(char in path for char in '\\:*?<>|"'):
        raise PolicyError("invalid_path", f"{label} must be a portable relative path")
    parts = tuple(path.split("/"))
    if any(
        part in ("", ".", "..")
        or part.endswith((" ", "."))
        or _WINDOWS_DEVICE_RE.fullmatch(part.split(".", 1)[0].rstrip(" "))
        for part in parts
    ):
        raise PolicyError(
            "invalid_path", f"{label} contains a forbidden path component"
        )
    return parts


def _file_rule(value: Any) -> tuple[tuple[str, ...], bool]:
    rule = _object(value, {"path", "recursive"}, "file rule")
    recursive = rule["recursive"]
    if type(recursive) is not bool:
        raise PolicyError("invalid_schema", "file rule recursive must be boolean")
    return _relative_path(rule["path"], "file rule path"), recursive


def _origin(value: Any, *, declaration: bool) -> str:
    raw = _string(value, "network origin" if declaration else "network URL")
    if raw != raw.strip() or "\\" in raw:
        raise PolicyError(
            "invalid_network_url", "network URL contains forbidden characters"
        )
    try:
        parsed = urlsplit(raw)
        port = parsed.port
        host = parsed.hostname
    except ValueError as exc:
        raise PolicyError(
            "invalid_network_url", "network URL has an invalid host or port"
        ) from exc
    if parsed.scheme != "https" or not parsed.netloc or not host:
        raise PolicyError(
            "invalid_network_url", "network URL must use HTTPS and contain a host"
        )
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise PolicyError(
            "invalid_network_url",
            "network URL must not contain credentials or a fragment",
        )
    if declaration and (parsed.path or "?" in raw or "#" in raw):
        raise PolicyError(
            "invalid_network_url", "declared network capability must be an origin only"
        )
    if not declaration and parsed.path.startswith("//"):
        raise PolicyError(
            "invalid_network_url", "network URL path must not start with //"
        )
    if host.endswith(".") or "%" in host:
        raise PolicyError("invalid_network_url", "network host must not end with a dot")
    try:
        ascii_host = host.encode("ascii").decode("ascii").lower()
    except UnicodeError as exc:
        raise PolicyError(
            "invalid_network_url", "network host must be ASCII; use punycode"
        ) from exc
    if not ascii_host or any(c.isspace() for c in ascii_host) or port == 0:
        raise PolicyError("invalid_network_url", "network host is invalid")
    if ":" in ascii_host:
        try:
            ipaddress.IPv6Address(ascii_host)
        except ValueError as exc:
            raise PolicyError(
                "invalid_network_url", "network IPv6 host is invalid"
            ) from exc
        ascii_host = f"[{ascii_host}]"
    elif len(ascii_host) > 253 or any(
        not _DNS_LABEL_RE.fullmatch(label) for label in ascii_host.split(".")
    ):
        raise PolicyError("invalid_network_url", "network host is invalid")
    if port == 443:
        port = None
    return f"https://{ascii_host}" + (f":{port}" if port is not None else "")


def _argv(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise PolicyError("invalid_schema", "command argv must be a nonempty array")
    return tuple(_string(part, "command argument") for part in value)


def _capabilities(value: Any) -> dict[str, Any]:
    caps = _object(value, {"files", "network", "commands"}, "capabilities")
    files = _object(caps["files"], set(_FILE_ACTIONS), "files capabilities")
    normalized: dict[str, Any] = {"files": {}, "network": set(), "commands": set()}
    for action in _FILE_ACTIONS:
        if not isinstance(files[action], list):
            raise PolicyError("invalid_schema", f"files.{action} must be an array")
        normalized["files"][action] = {_file_rule(rule) for rule in files[action]}
    if not isinstance(caps["network"], list) or not isinstance(caps["commands"], list):
        raise PolicyError("invalid_schema", "network and commands must be arrays")
    normalized["network"] = {
        _origin(origin, declaration=True) for origin in caps["network"]
    }
    normalized["commands"] = {_argv(command) for command in caps["commands"]}
    return normalized


def _parse_time(value: Any, label: str) -> datetime:
    raw = _string(value, label)
    if not _UTC_TIMESTAMP_RE.fullmatch(raw):
        raise PolicyError(
            "invalid_time", f"{label} must use YYYY-MM-DDTHH:MM:SS[.fraction]Z"
        )
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise PolicyError("invalid_time", f"{label} is not a valid timestamp") from exc
    return parsed


def _parse_manifest(value: Any) -> tuple[str, dict[str, Any]]:
    manifest = _object(value, {"version", "skill", "capabilities"}, "manifest")
    _version(manifest["version"], {1}, "manifest")
    skill = _object(manifest["skill"], {"name", "digest"}, "manifest skill")
    _string(skill["name"], "skill name")
    return _digest(skill["digest"], "skill digest"), _capabilities(
        manifest["capabilities"]
    )


def _parse_grant(
    value: Any,
) -> tuple[str, str, str, str | None, datetime, datetime, dict[str, Any]]:
    if not isinstance(value, dict):
        raise PolicyError(
            "invalid_schema",
            "grant must have exactly: capabilities, expires_at, issued_at, "
            "session_id, skill_digest, task_id, version",
        )
    common = {
        "version",
        "session_id",
        "task_id",
        "skill_digest",
        "issued_at",
        "expires_at",
        "capabilities",
    }
    _version(value.get("version"), {1, 2}, "grant")
    if value["version"] == 1:
        grant = _object(value, common, "grant")
        workspace_id: str | None = None
    else:
        grant = _object(value, common | {"workspace_id"}, "grant")
        workspace_id = _string(grant["workspace_id"], "workspace_id")
    issued = _parse_time(grant["issued_at"], "issued_at")
    expires = _parse_time(grant["expires_at"], "expires_at")
    if expires <= issued or expires - issued > _MAX_GRANT_LIFETIME:
        raise PolicyError(
            "invalid_grant_window",
            "grant lifetime must be positive and at most 24 hours",
        )
    return (
        _string(grant["session_id"], "session_id"),
        _string(grant["task_id"], "task_id"),
        _digest(grant["skill_digest"], "grant skill_digest"),
        workspace_id,
        issued,
        expires,
        _capabilities(grant["capabilities"]),
    )


def _is_reparse_or_symlink(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def hash_skill_tree(skill_dir: str | Path) -> str:
    """Hash all regular files in a skill tree, rejecting links and special files."""
    root = Path(skill_dir)
    try:
        if _is_reparse_or_symlink(root) or not root.is_dir():
            raise PolicyError(
                "invalid_skill_tree", "skill directory must be a real directory"
            )
        inventory: list[dict[str, Any]] = []

        def on_walk_error(error: OSError) -> None:
            raise error

        for current, directories, files in os.walk(
            root, topdown=True, followlinks=False, onerror=on_walk_error
        ):
            directories.sort()
            files.sort()
            current_path = Path(current)
            for name in directories:
                child = current_path / name
                if _is_reparse_or_symlink(child) or not child.is_dir():
                    raise PolicyError(
                        "invalid_skill_tree",
                        "skill tree contains a link or special directory",
                    )
            for name in files:
                child = current_path / name
                if _is_reparse_or_symlink(child) or not child.is_file():
                    raise PolicyError(
                        "invalid_skill_tree",
                        "skill tree contains a link or special file",
                    )
                relative = child.relative_to(root).as_posix()
                _relative_path(relative, "skill file path")
                content_hash = hashlib.sha256()
                size = 0
                flags = (
                    os.O_RDONLY
                    | getattr(os, "O_BINARY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                descriptor = os.open(child, flags)
                with os.fdopen(descriptor, "rb") as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                        raise PolicyError(
                            "invalid_skill_tree", "skill tree contains a special file"
                        )
                    while chunk := stream.read(1024 * 1024):
                        content_hash.update(chunk)
                        size += len(chunk)
                inventory.append(
                    {"path": relative, "size": size, "sha256": content_hash.hexdigest()}
                )
        inventory.sort(key=lambda item: item["path"])
        return _sha256({"schema": "skilllatch.tree.v1", "files": inventory})
    except PolicyError:
        raise
    except OSError as exc:
        raise PolicyError(
            "invalid_skill_tree", "skill directory could not be read safely"
        ) from exc


def _within_rule(path: tuple[str, ...], rule: tuple[tuple[str, ...], bool]) -> bool:
    base, recursive = rule
    return path == base or (
        recursive and len(path) > len(base) and path[: len(base)] == base
    )


def _grant_rule_within_declaration(
    grant_rule: tuple[tuple[str, ...], bool],
    declared_rule: tuple[tuple[str, ...], bool],
) -> bool:
    grant_path, grant_recursive = grant_rule
    declared_path, declared_recursive = declared_rule
    if grant_path == declared_path:
        return declared_recursive or not grant_recursive
    return (
        declared_recursive
        and len(grant_path) > len(declared_path)
        and grant_path[: len(declared_path)] == declared_path
    )


def _grant_is_subset(grant: dict[str, Any], declared: dict[str, Any]) -> bool:
    for action in _FILE_ACTIONS:
        if not all(
            any(
                _grant_rule_within_declaration(rule, parent)
                for parent in declared["files"][action]
            )
            for rule in grant["files"][action]
        ):
            return False
    return (
        grant["network"] <= declared["network"]
        and grant["commands"] <= declared["commands"]
    )


def _safe_workspace_path(workspace: str | Path, path: tuple[str, ...]) -> None:
    root = Path(workspace)
    try:
        if _is_reparse_or_symlink(root) or not root.is_dir():
            raise PolicyError("invalid_workspace", "workspace must be a real directory")
        resolved_root = root.resolve(strict=True)
        current = root
        for part in path:
            current = current / part
            try:
                linked = _is_reparse_or_symlink(current)
            except FileNotFoundError:
                continue
            if linked:
                raise PolicyError(
                    "unsafe_file_path",
                    "file path passes through a link or reparse point",
                )
        resolved_target = current.resolve(strict=False)
        if not resolved_target.is_relative_to(resolved_root):
            raise PolicyError("unsafe_file_path", "file path escapes workspace")
        try:
            if current.is_file() and current.lstat().st_nlink != 1:
                raise PolicyError(
                    "unsafe_file_path", "file has multiple hard links"
                )
        except PolicyError:
            raise
        except OSError as exc:
            raise PolicyError(
                "unsafe_file_path", "file path could not be checked safely"
            ) from exc
    except PolicyError:
        raise
    except OSError as exc:
        raise PolicyError(
            "unsafe_file_path", "file path could not be checked safely"
        ) from exc


def _request(value: Any, workspace: str | Path) -> tuple[str, str, str, Any]:
    if not isinstance(value, dict):
        raise PolicyError("invalid_request", "request must be an object")
    kind = value.get("kind")
    common = {"session_id", "task_id", "kind"}
    if kind == "file":
        req = _object(value, common | {"action", "path"}, "file request")
        action = req["action"]
        if action not in _FILE_ACTIONS:
            raise PolicyError("invalid_request", "file action must be read or write")
        path = _relative_path(req["path"], "request path")
        _safe_workspace_path(workspace, path)
        target: Any = (action, path)
    elif kind == "network":
        req = _object(value, common | {"url"}, "network request")
        target = _origin(req["url"], declaration=False)
    elif kind == "command":
        req = _object(value, common | {"argv"}, "command request")
        target = _argv(req["argv"])
    else:
        raise PolicyError(
            "invalid_request", "request kind must be file, network, or command"
        )
    return (
        _string(req["session_id"], "request session_id"),
        _string(req["task_id"], "request task_id"),
        kind,
        target,
    )


def _utc_time(at: datetime | None) -> datetime:
    when = datetime.now(UTC) if at is None else at
    if not isinstance(when, datetime) or when.tzinfo is None:
        raise PolicyError("invalid_time", "evaluation time must include a timezone")
    return when.astimezone(UTC)


def _decision(
    allowed: bool,
    code: str,
    reason: str,
    when: datetime,
    manifest: Any,
    grant: Any,
    request: Any,
    skill_digest: str | None,
    workspace_id: str | None = None,
    workspace_binding: str = "none",
) -> dict[str, Any]:
    receipt = {
        "version": 2,
        "allowed": allowed,
        "reason_code": code,
        "reason": reason,
        "evaluated_at": when.isoformat().replace("+00:00", "Z"),
        "skill_digest": skill_digest,
        "workspace_id": workspace_id,
        "workspace_binding": workspace_binding,
        "manifest_hash": _sha256(manifest),
        "grant_hash": _sha256(grant),
        "request_hash": _sha256(request),
    }
    receipt["digest"] = _sha256(receipt)
    return {
        "allowed": allowed,
        "reason_code": code,
        "reason": reason,
        "receipt": receipt,
    }


def evaluate(
    skill_dir: str | Path,
    workspace: str | Path,
    manifest: Any,
    grant: Any,
    request: Any,
    *,
    at: datetime | None = None,
    workspace_id: str | None = None,
) -> dict[str, Any]:
    """Decide one host-supplied tool call; never execute it.

    IMPORTANT: library callers must treat a raised PolicyError as a denial.
    Malformed direct Python values (non-JSON values, nonfinite floats) and an
    invalid clock RAISE PolicyError instead of returning a denial receipt.
    Valid JSON-shaped inputs always produce an allow/deny decision receipt.

    All mutable inputs and the clock must be supplied by a trusted host. An
    allow decision is valid only for the exact request and skill snapshot in
    the receipt, and only if the host gates the actual invocation.

    ``workspace_id`` is the host-observed identity of the active workspace.
    A version 2 grant pins one workspace identity; evaluating it against a
    different (or missing) host value denies with ``workspace_mismatch``.
    """
    # Direct callers may pass Python objects instead of parsed JSON. Reject
    # nonfinite floats and other non-JSON values before constructing a receipt.
    for value in (manifest, grant, request):
        _canonical_bytes(value)
    when = _utc_time(at)
    skill_digest: str | None = None
    grant_workspace_id: str | None = None
    try:
        if workspace_id is not None:
            _string(workspace_id, "workspace_id")
        skill_digest = hash_skill_tree(skill_dir)
        manifest_digest, declared = _parse_manifest(manifest)
        (
            session_id,
            task_id,
            grant_digest,
            grant_workspace_id,
            issued,
            expires,
            granted,
        ) = _parse_grant(grant)
        req_session, req_task, kind, target = _request(request, workspace)
        if skill_digest != manifest_digest or skill_digest != grant_digest:
            raise PolicyError(
                "skill_digest_mismatch",
                "skill bytes do not match both manifest and grant",
            )
        if not _grant_is_subset(granted, declared):
            raise PolicyError(
                "grant_exceeds_manifest", "grant contains an undeclared capability"
            )
        if not issued <= when < expires:
            raise PolicyError(
                "grant_inactive", "grant is not active at evaluation time"
            )
        if session_id != req_session or task_id != req_task:
            raise PolicyError(
                "scope_mismatch", "request session or task does not match grant"
            )
        if grant_workspace_id is not None and grant_workspace_id != workspace_id:
            raise PolicyError(
                "workspace_mismatch", "grant is pinned to a different workspace"
            )
        if kind == "file":
            action, path = target
            if not any(_within_rule(path, rule) for rule in granted["files"][action]):
                raise PolicyError(
                    "capability_not_granted",
                    f"file {action} is not granted for this path",
                )
        elif kind == "network":
            if target not in granted["network"]:
                raise PolicyError(
                    "capability_not_granted", f"network origin {target} is not granted"
                )
        elif target not in granted["commands"]:
            raise PolicyError(
                "capability_not_granted", "exact command argv is not granted"
            )
    except PolicyError as exc:
        if grant_workspace_id is not None:
            binding = "pinned"
        elif workspace_id is not None:
            binding = "unpinned"
        else:
            binding = "none"
        return _decision(
            False,
            exc.code,
            exc.reason,
            when,
            manifest,
            grant,
            request,
            skill_digest,
            workspace_id,
            binding,
        )
    binding = (
        "pinned"
        if grant_workspace_id is not None
        else ("unpinned" if workspace_id is not None else "none")
    )
    return _decision(
        True,
        "allowed",
        "request matches the active capability grant",
        when,
        manifest,
        grant,
        request,
        skill_digest,
        workspace_id,
        binding,
    )
