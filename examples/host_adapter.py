"""Reference gated host. Tools are simulated; this demonstrates gate wiring, not production interception."""

from __future__ import annotations

import copy
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from skilllatch import PolicyError, evaluate

# Sentinel for "no per-call context override": dispatch falls back to the
# constructor-supplied envelope. A caller can still pass context=None to
# suppress it for one call.
_DEFAULT = object()


class RecordingTool:
    """A named callable that records a deep copy of every call's argument."""

    def __init__(self, name: str, fn: Callable[[dict[str, Any]], Any]):
        self.name = name
        self._fn = fn
        self.calls: list[dict[str, Any]] = []

    def __call__(self, arg: dict[str, Any]) -> Any:
        self.calls.append(copy.deepcopy(arg))
        return self._fn(arg)


def make_file_tool(workspace: str | Path) -> RecordingTool:
    """Real reads and writes of workspace-relative files under ``workspace``."""
    root = Path(workspace)

    def run(arg: dict[str, Any]) -> str:
        target = root / arg["path"]
        if arg["action"] == "read":
            return target.read_text(encoding="utf-8")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(arg.get("content", ""), encoding="utf-8")
        return "written"

    return RecordingTool("file", run)


def make_fetch_stub(payload: bytes = b"demo") -> RecordingTool:
    """Simulated network fetch. Performs no I/O of any kind."""

    def run(arg: dict[str, Any]) -> dict[str, Any]:
        return {"url": arg["url"], "status": 200, "body": payload.decode("utf-8")}

    return RecordingTool("fetch-stub", run)


def make_command_stub(stdout: str = "ok\n") -> RecordingTool:
    """Simulated command runner. Never spawns a subprocess."""

    def run(arg: dict[str, Any]) -> dict[str, Any]:
        return {"argv": list(arg["argv"]), "exit_code": 0, "stdout": stdout}

    return RecordingTool("command-stub", run)


class GatedHost:
    """Minimal host that checks every request with SkillLatch before dispatch."""

    def __init__(
        self,
        skill_dir: str | Path,
        workspace: str | Path,
        manifest: Any,
        grant: Any,
        *,
        workspace_id: str | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        advisory: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ):
        self._skill_dir = Path(skill_dir)
        self._workspace = Path(workspace)
        self._manifest = copy.deepcopy(manifest)
        self._grant = copy.deepcopy(grant)
        self._advisory = copy.deepcopy(advisory)
        self._context = copy.deepcopy(context)
        self._workspace_id = workspace_id
        self._clock = clock
        self._tools: dict[str, RecordingTool] = {}

    @property
    def advisory(self) -> dict[str, Any] | None:
        return copy.deepcopy(self._advisory)

    @property
    def context(self) -> dict[str, Any] | None:
        return copy.deepcopy(self._context)

    def register_tool(self, kind: str, tool: RecordingTool) -> None:
        if kind not in ("file", "network", "command"):
            raise ValueError(f"unknown tool kind: {kind}")
        self._tools[kind] = tool

    def dispatch(
        self, request: dict[str, Any], *, context: Any = _DEFAULT
    ) -> dict[str, Any]:
        """Decide ``request`` and invoke the registered tool only when allowed."""
        # Freeze the caller's dict: the same deep copy feeds both evaluate()
        # and tool-arg building, closing the plain-dict mutation window
        # between check and use.
        request = copy.deepcopy(request)
        # The context envelope is stored opaquely: validation is
        # build_context's job, exactly as advisory validation lives in
        # load_scan_report. A per-call override falls back to the
        # constructor value.
        active_context = (
            self.context if context is _DEFAULT else copy.deepcopy(context)
        )
        try:
            decision = evaluate(
                self._skill_dir,
                self._workspace,
                self._manifest,
                self._grant,
                request,
                at=self._clock(),
                workspace_id=self._workspace_id,
            )
        except PolicyError as exc:
            return {
                "allowed": False,
                "reason_code": exc.code,
                "reason": exc.reason,
                "receipt": None,
                "dispatched": False,
                "tool_result": None,
                "error": "policy_error",
                "advisory": self.advisory,
                "context": active_context,
            }
        if not decision["allowed"]:
            return {
                "allowed": False,
                "reason_code": decision["reason_code"],
                "reason": decision["reason"],
                "receipt": decision["receipt"],
                "dispatched": False,
                "tool_result": None,
                "error": None,
                "advisory": self.advisory,
                "context": active_context,
            }
        kind = request["kind"]
        tool = self._tools.get(kind)
        if tool is None:
            return {
                "allowed": False,
                "reason_code": "no_tool_registered",
                "reason": f"no tool is registered for kind {kind!r}; failing closed",
                "receipt": decision["receipt"],
                "dispatched": False,
                "tool_result": None,
                "error": None,
                "advisory": self.advisory,
                "context": active_context,
            }
        if kind == "file":
            arg = {"action": request["action"], "path": request["path"]}
        elif kind == "network":
            arg = {"url": request["url"]}
        else:
            arg = {"argv": list(request["argv"])}
        result = tool(arg)
        return {
            "allowed": True,
            "reason_code": "allowed",
            "reason": decision["reason"],
            "receipt": decision["receipt"],
            "dispatched": True,
            "tool_result": result,
            "error": None,
            "advisory": self.advisory,
            "context": active_context,
        }
