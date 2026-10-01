"""Illustrative validator-style interceptor for MCP-shaped tools/call messages.

Illustrative example informed by the draft MCP Interceptors proposal
(SEP-2624). It implements no MCP transport, speaks no JSON-RPC on the wire,
and is not an implementation of that draft or of the MCP Skills extension.
The interceptor accepts one already-parsed JSON-RPC-shaped request message
for method 'tools/call', maps the tool name onto a SkillLatch request through
a host-supplied mapping, and asks the wrapped GatedHost for a decision. It is
a validator only: it never mutates the message and never synthesizes a
response message. Session, task, and workspace identity come from host-side
state (constructor arguments and the wrapped host), never from message
content. Skill identity (server identity and skill URI) is host-observed
context recorded for the context envelope, not read from the message.
Fail-closed by default, mirroring the draft's posture: an unmapped tool name
or a malformed message is denied with reason code 'unmapped_tool' or
'invalid_message'. This example deliberately does not implement the draft's
failOpen option and does not use priorityHint. Mode 'audit' reports a policy
denial without blocking (verdict 'allow', severity 'warn'), while
structurally invalid messages, unmapped tools, and PolicyError inputs deny in
every mode. The wrapped GatedHost still enforces the decision at its own
dispatch boundary, so in this example an audited denial is reported as
allow+warn but the simulated tool is not invoked; a real host in audit mode
would forward the call and only log the warning. Tools are simulated; this
demonstrates gate wiring, not production interception.
"""

from __future__ import annotations

import copy
from typing import Any

from host_adapter import GatedHost

_KIND_KEYS = {
    "file": {"kind", "action", "path_from"},
    "network": {"kind", "url_from"},
    "command": {"kind", "argv_from"},
}
_EXTRACTOR = {"file": "path_from", "network": "url_from", "command": "argv_from"}
_REQUEST_FIELD = {"file": "path", "network": "url", "command": "argv"}


def _validate_tool_map(tool_map: Any) -> dict[str, dict[str, str]]:
    if not isinstance(tool_map, dict):
        # ValueError, not TypeError: register_tool's style in host_adapter.py.
        raise ValueError("tool_map must be a dict of tool name to mapping")  # noqa: TRY004
    validated: dict[str, dict[str, str]] = {}
    for name, entry in tool_map.items():
        if not isinstance(name, str) or not name:
            raise ValueError("tool_map names must be nonempty strings")
        if not isinstance(entry, dict):
            raise ValueError(f"mapping for tool {name!r} must be a dict")  # noqa: TRY004
        kind = entry.get("kind")
        if kind not in _KIND_KEYS:
            raise ValueError(f"mapping for tool {name!r} has an unknown kind")
        if set(entry) != _KIND_KEYS[kind]:
            raise ValueError(
                f"mapping for tool {name!r} must have exactly: "
                + ", ".join(sorted(_KIND_KEYS[kind]))
            )
        if kind == "file" and entry["action"] not in ("read", "write"):
            raise ValueError(
                f"mapping for tool {name!r} must use action read or write"
            )
        extractor = _EXTRACTOR[kind]
        if not isinstance(entry[extractor], str) or not entry[extractor]:
            raise ValueError(
                f"mapping for tool {name!r} needs a nonempty {extractor} key"
            )
        validated[name] = dict(entry)
    return validated


def _validate_skill_context(skill_context: Any) -> dict[str, str] | None:
    if skill_context is None:
        return None
    if not isinstance(skill_context, dict) or set(skill_context) != {
        "server_identity",
        "uri",
    }:
        raise ValueError(
            "skill_context must have exactly: server_identity, uri"
        )
    for label in ("server_identity", "uri"):
        value = skill_context[label]
        if (
            not isinstance(value, str)
            or not value
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
        ):
            raise ValueError(
                f"skill_context {label} must be a nonempty string "
                "without control characters"
            )
    return dict(skill_context)


class McpStyleInterceptor:
    """Validator-style interceptor wrapping a GatedHost for tools/call messages."""

    def __init__(
        self,
        host: GatedHost,
        tool_map: Any,
        *,
        session_id: str,
        task_id: str,
        mode: str = "enforce",
        skill_context: dict[str, str] | None = None,
    ):
        if mode not in ("enforce", "audit"):
            raise ValueError("mode must be enforce or audit")
        self._host = host
        self._tool_map = _validate_tool_map(tool_map)
        self._session_id = session_id
        self._task_id = task_id
        self._mode = mode
        self._skill_context = _validate_skill_context(skill_context)

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def skill_context(self) -> dict[str, str] | None:
        return copy.deepcopy(self._skill_context)

    def _verdict(
        self,
        verdict: str,
        severity: str,
        reason_code: str,
        reason: str,
        receipt: dict[str, Any] | None,
    ) -> dict[str, Any]:
        return {
            "verdict": verdict,
            "severity": severity,
            "reason_code": reason_code,
            "reason": reason,
            "receipt": receipt,
            "mode": self._mode,
        }

    def _deny(self, reason_code: str, reason: str) -> dict[str, Any]:
        return self._verdict("deny", "error", reason_code, reason, None)

    def _extract_call(self, message: Any) -> tuple[str, dict[str, Any]] | None:
        if not isinstance(message, dict):
            return None
        if "jsonrpc" in message and message["jsonrpc"] != "2.0":
            return None
        if message.get("method") != "tools/call":
            return None
        params = message.get("params")
        if not isinstance(params, dict):
            return None
        name = params.get("name")
        if not isinstance(name, str) or not name:
            return None
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            return None
        return name, arguments

    def handle_message(self, message: Any) -> dict[str, Any]:
        """Validate one tools/call message; never mutates it, never raises."""
        try:
            extracted = self._extract_call(message)
            if extracted is None:
                return self._deny(
                    "invalid_message", "message is not a well-formed tools/call request"
                )
            name, arguments = extracted
            mapping = self._tool_map.get(name)
            if mapping is None:
                return self._deny(
                    "unmapped_tool",
                    f"no SkillLatch mapping for tool {name!r}; failing closed",
                )
            extractor = mapping[_EXTRACTOR[mapping["kind"]]]
            if extractor not in arguments:
                return self._deny(
                    "invalid_message",
                    f"arguments for tool {name!r} lack required key {extractor!r}",
                )
            # A present-but-wrong-typed value flows through so SkillLatch
            # denies with its own receipt.
            request: dict[str, Any] = {
                "session_id": self._session_id,
                "task_id": self._task_id,
                "kind": mapping["kind"],
                _REQUEST_FIELD[mapping["kind"]]: arguments[extractor],
            }
            if mapping["kind"] == "file":
                request["action"] = mapping["action"]
            outcome = self._host.dispatch(request)
        except Exception as exc:  # noqa: BLE001 — fail-closed contract: handle_message never raises
            return self._deny("invalid_message", f"message could not be processed: {exc}")

        if outcome["error"] == "policy_error":
            # PolicyError inputs deny in every mode; no receipt exists.
            return self._verdict(
                "deny", "error", outcome["reason_code"], outcome["reason"], None
            )
        if outcome["allowed"]:
            return self._verdict(
                "allow", "info", "allowed", outcome["reason"], outcome["receipt"]
            )
        if self._mode == "audit":
            return self._verdict(
                "allow",
                "warn",
                outcome["reason_code"],
                "audit mode: denial reported but not blocked: " + outcome["reason"],
                outcome["receipt"],
            )
        return self._verdict(
            "deny",
            "error",
            outcome["reason_code"],
            outcome["reason"],
            outcome["receipt"],
        )
