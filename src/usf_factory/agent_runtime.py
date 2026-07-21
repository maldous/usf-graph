"""Agent Runtime Protocol (build task §9 / review P0-5).

A bounded **tool broker** exposes a small set of vetted operations over a
packet's disposable workspace, and a **tool-call loop** drives a model through
them under strict turn/time budgets, requiring a structured result. Arbitrary
shell is never a tool; every tool validates its own inputs and scope.

The loop is model-agnostic: it takes an async ``chat(messages, tools)`` callable
so it can be driven by any provider adapter (OpenAI-compatible, Ollama) or a
deterministic fake in tests. Provider invocation is billable and gated by the
caller.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Packet
from .sandbox import parse_unified_diff_paths, scan_secrets, validate_patch_scope

MAX_READ_LINES = 400
MAX_SEARCH_RESULTS = 50
MAX_FILE_BYTES = 4_000_000  # per-file read/search cap
MAX_PATCH_BYTES = 2_000_000  # apply_*_patch payload cap
MAX_WRITE_BYTES = 2_000_000  # write_new_file content cap
MAX_QUERY_CHARS = 512  # search query cap

# Broker tool -> the packet tool-profile entry that must permit it. finish_packet
# is unlisted: a worker must always be able to return a structured result.
_TOOL_REQUIREMENT = {
    "read_file_range": "read_file",
    "list_directory": "list_paths",
    "search_repository": "read_file",
    "apply_patch": "write_patch",
    "apply_unified_patch": "write_patch",
    "write_new_file": "edit_file",
    "run_validation_profile": "run_focused_tests",
}

# chat(messages, tools) -> {"content": str, "tool_calls": [{"id","name","arguments"}]}
ChatFn = Callable[[list[dict[str, Any]], list[dict[str, Any]]], Awaitable[dict[str, Any]]]


@dataclass
class ToolBroker:
    """Bounded, scope-checked tools over a packet workspace.

    When ``mutating`` is True the write tools ACTUALLY edit files in the workspace
    (confined to the packet write scope); the orchestrator later derives the exact
    diff from git. When False (shadow), writes are validated but not applied.
    """

    workspace: Path
    packet: Packet
    mutating: bool = False
    validation_runner: Any = None  # Callable[[str, Path], tuple[bool, str]] | None
    # Egress recheck at the tool boundary (defense in depth behind the scheduler):
    # when False, tools that would return repository file CONTENT to the provider
    # (read_file_range, search_repository) are refused.
    source_content_allowed: bool = True
    finished: dict[str, Any] | None = field(default=None, init=False)
    edits: int = field(default=0, init=False)

    # ---- tool schema advertised to the model ---------------------------- #

    def tool_specs(self) -> list[dict[str, Any]]:
        specs = [
            _spec(
                "read_file_range",
                "Read a bounded line range of a file in scope.",
                {"path": _str, "start": _int, "end": _int},
                ["path"],
            ),
            _spec(
                "list_directory",
                "List entries of a directory in the workspace.",
                {"path": _str},
                ["path"],
            ),
            _spec(
                "search_repository",
                "Search file contents (bounded results).",
                {"query": _str},
                ["query"],
            ),
        ]
        if self.mutating:
            specs += [
                _spec(
                    "apply_unified_patch",
                    "Apply a unified diff limited to the write scope.",
                    {"patch": _str},
                    ["patch"],
                ),
                _spec(
                    "write_new_file",
                    "Create/overwrite a file within the write scope.",
                    {"path": _str, "content": _str},
                    ["path", "content"],
                ),
                _spec(
                    "run_validation_profile",
                    "Run a named deterministic validation profile.",
                    {"name": _str},
                    ["name"],
                ),
            ]
        else:
            specs.append(
                _spec(
                    "apply_patch",
                    "Propose (validate only; not applied) a unified diff.",
                    {"patch": _str},
                    ["patch"],
                )
            )
        specs.append(
            _spec(
                "finish_packet",
                "Finish with a structured result. A read-only packet MUST include "
                "findings and criteria_results (durable analysis evidence).",
                {
                    "status": {
                        "type": "string",
                        "enum": ["COMPLETED", "FAILED", "HUMAN_DECISION_REQUIRED"],
                    },
                    "findings": {"type": "array", "items": _str},
                    "criteria_results": {"type": "object"},
                    "uncertainties": {"type": "array", "items": _str},
                },
                ["status"],
            )
        )
        # Only advertise tools the packet's tool profile permits (fail closed).
        return [s for s in specs if self._permitted(s["function"]["name"])]

    def _permitted(self, tool: str) -> bool:
        """True iff the packet tool profile permits this broker tool."""
        req = _TOOL_REQUIREMENT.get(tool)
        return req is None or req in set(self.packet.permitted_tools)

    # ---- dispatch -------------------------------------------------------- #

    def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        handler = {
            "read_file_range": self._read_file_range,
            "list_directory": self._list_directory,
            "search_repository": self._search_repository,
            "apply_patch": self._apply_patch,
            "apply_unified_patch": self._apply_unified_patch,
            "write_new_file": self._write_new_file,
            "run_validation_profile": self._run_validation_profile,
            "finish_packet": self._finish_packet,
        }.get(name)
        if handler is None:
            return {"error": f"unknown tool: {name}"}
        if not self._permitted(name):
            return {"error": f"tool not permitted by packet tool profile: {name}"}
        try:
            return handler(arguments)
        except Exception as exc:
            return {"error": f"{type(exc).__name__}: {exc}"}

    def _scope(self) -> set[str]:
        """The exact files the model may see (read + write scope)."""
        return set(self.packet.read_paths) | set(self.packet.write_paths)

    def _scope_dirs(self) -> set[str]:
        """Directories that are ancestors of an in-scope file (listable)."""
        from pathlib import PurePosixPath

        dirs = {"."}
        for rel in self._scope():
            parent = PurePosixPath(rel).parent
            while True:
                dirs.add(str(parent))
                if str(parent) in (".", ""):
                    break
                parent = parent.parent
        return dirs

    def _resolve(self, rel: str) -> Path:
        """Confine a relative path to the workspace. Rejects absolute paths,
        ``..``, and EVERY symlink component (lstat walk) — so neither a
        sibling-prefix escape, an external symlink, nor an inside-workspace
        symlink alias can reach a file other than the declared scoped path.
        Real-path containment is kept as a second, independent check."""
        if rel.startswith("/") or ".." in Path(rel).parts:
            raise PermissionError(f"illegal path: {rel}")
        cur = self.workspace
        for part in Path(rel).parts:
            cur = cur / part
            if cur.is_symlink():  # lstat: refuses symlinks even to in-workspace targets
                raise PermissionError(f"symlink component refused: {rel}")
        ws = self.workspace.resolve()
        target = (self.workspace / rel).resolve()
        try:
            target.relative_to(ws)  # ValueError if outside the workspace
        except ValueError as exc:
            raise PermissionError(f"path escapes workspace: {rel}") from exc
        return self.workspace / rel

    def _read_file_range(self, args: dict[str, Any]) -> dict[str, Any]:
        path = str(args["path"])
        # Fail closed: an empty scope grants NO reads (bounded-context promise).
        if path not in self._scope():
            return {"error": f"path not in packet scope: {path}"}
        if not self.source_content_allowed:
            return {"error": "source content egress to this provider is not permitted by policy"}
        target = self._resolve(path)  # rejects every symlink component
        if not target.is_file():
            return {"error": "not a regular file in scope"}
        if target.stat().st_size > MAX_FILE_BYTES:
            return {"error": f"file exceeds the read cap ({MAX_FILE_BYTES} bytes)"}
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(1, int(args.get("start", 1)))
        end = min(len(lines), int(args.get("end", start + MAX_READ_LINES - 1)))
        end = min(end, start + MAX_READ_LINES - 1)
        return {"path": path, "start": start, "end": end, "lines": lines[start - 1 : end]}

    def _list_directory(self, args: dict[str, Any]) -> dict[str, Any]:
        from pathlib import PurePosixPath

        rel = str(args.get("path", "."))
        if rel not in self._scope_dirs():
            return {"error": f"directory not in packet scope: {rel}"}
        target = self._resolve(rel)
        if not target.is_dir():
            return {"error": "not a directory"}
        scope = self._scope()
        scope_dirs = self._scope_dirs()
        # Only reveal entries that are themselves in scope or are scoped ancestors;
        # never .git or unrelated files.
        entries = []
        for p in sorted(target.iterdir()):
            if p.name == ".git":
                continue
            child = str(PurePosixPath(rel) / p.name) if rel != "." else p.name
            if child in scope or child in scope_dirs:
                entries.append(p.name)
        return {"entries": entries[:MAX_SEARCH_RESULTS]}

    def _search_repository(self, args: dict[str, Any]) -> dict[str, Any]:
        # Search ONLY in-scope files (never the whole clone, never .git). A hit
        # confirms content presence, so this is a content oracle: it is refused
        # when source content may not egress to this provider.
        query = str(args["query"])
        if not self.source_content_allowed:
            return {"error": "source content egress to this provider is not permitted by policy"}
        if len(query) > MAX_QUERY_CHARS:
            return {"error": f"query exceeds {MAX_QUERY_CHARS} chars"}
        hits: list[dict[str, Any]] = []
        for rel in sorted(self._scope()):
            if len(hits) >= MAX_SEARCH_RESULTS:
                break
            try:
                target = self._resolve(rel)
            except PermissionError:
                continue
            if not target.is_file() or target.stat().st_size > MAX_FILE_BYTES:
                continue
            for i, line in enumerate(
                target.read_text(encoding="utf-8", errors="replace").splitlines(), 1
            ):
                if query in line:
                    hits.append({"path": rel, "line": i})
                    break
        return {"hits": hits}

    def _apply_patch(self, args: dict[str, Any]) -> dict[str, Any]:
        """Shadow mode: validate the diff against scope but do NOT apply it."""
        patch = str(args["patch"])
        if len(patch) > MAX_PATCH_BYTES:
            return {"accepted": False, "error": f"patch exceeds {MAX_PATCH_BYTES} bytes"}
        violations = validate_patch_scope(patch, self.packet.write_paths)
        leaks = scan_secrets(patch)
        if violations or leaks:
            return {"accepted": False, "violations": violations + leaks}
        return {"accepted": True, "changed_paths": parse_unified_diff_paths(patch)}

    def _apply_unified_patch(self, args: dict[str, Any]) -> dict[str, Any]:
        """Mutating mode: validate scope, then apply the diff to the workspace via git."""
        import subprocess

        patch = str(args["patch"])
        if len(patch) > MAX_PATCH_BYTES:
            return {"accepted": False, "error": f"patch exceeds {MAX_PATCH_BYTES} bytes"}
        violations = validate_patch_scope(patch, self.packet.write_paths)
        leaks = scan_secrets(patch)
        if violations or leaks:
            return {"accepted": False, "violations": violations + leaks}
        chk = subprocess.run(
            ["git", "-C", str(self.workspace), "apply", "--check", "-"],
            input=patch,
            capture_output=True,
            text=True,
        )
        if chk.returncode != 0:
            return {
                "accepted": False,
                "error": "patch does not apply",
                "detail": chk.stderr.strip()[:200],
            }
        appl = subprocess.run(
            ["git", "-C", str(self.workspace), "apply", "--index", "-"],
            input=patch,
            capture_output=True,
            text=True,
        )
        if appl.returncode != 0:  # never assume the real apply matched the dry check
            return {
                "accepted": False,
                "error": "patch apply failed after check",
                "detail": appl.stderr.strip()[:200],
            }
        self.edits += 1
        return {"accepted": True, "changed_paths": parse_unified_diff_paths(patch)}

    def _write_new_file(self, args: dict[str, Any]) -> dict[str, Any]:
        path = str(args["path"])
        if path not in set(self.packet.write_paths):
            return {"accepted": False, "error": f"path not in write scope: {path}"}
        target = self._resolve(path)  # rejects symlink components => no alias writes
        content = str(args.get("content", ""))
        if len(content) > MAX_WRITE_BYTES:
            return {"accepted": False, "error": f"content exceeds {MAX_WRITE_BYTES} bytes"}
        leaks = scan_secrets(content)
        if leaks:
            return {"accepted": False, "violations": leaks}
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        self.edits += 1
        return {"accepted": True, "path": path}

    def _run_validation_profile(self, args: dict[str, Any]) -> dict[str, Any]:
        name = str(args["name"])
        if self.validation_runner is None:
            return {"error": "no validation runner configured"}
        passed, detail = self.validation_runner(name, self.workspace)
        return {"profile": name, "passed": passed, "detail": detail}

    def _finish_packet(self, args: dict[str, Any]) -> dict[str, Any]:
        self.finished = dict(args)
        return {"ok": True}


@dataclass
class ToolLoopResult:
    finished: dict[str, Any] | None
    turns: int
    transcript_digest: str
    stopped_reason: str
    # Per-turn attribution facts as REPORTED by the provider (actual routed
    # model, token usage). Empty entries mean the provider reported nothing —
    # attribution is then explicitly unverified, never assumed.
    turn_meta: list[dict[str, Any]] = field(default_factory=list)


class GenericToolLoop:
    """Drives a model through the tool broker under a turn budget."""

    SYSTEM = (
        "You are a USF factory worker in an isolated workspace. Use the provided "
        "tools to inspect files and propose a unified diff limited to the write "
        "scope. You may NOT access the network, read secrets, or write outside "
        "scope. When done, call finish_packet with a structured result."
    )

    def __init__(self, chat: ChatFn, max_turns: int = 12) -> None:
        self._chat = chat
        self.max_turns = max_turns

    async def run(self, packet: Packet, broker: ToolBroker) -> ToolLoopResult:
        from .canonical import content_digest

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": self.SYSTEM},
            {
                "role": "user",
                "content": f"PACKET:\n{packet.objective}\nwrite_paths={packet.write_paths}",
            },
        ]
        tools = broker.tool_specs()
        turns = 0
        reason = "max_turns"
        turn_meta: list[dict[str, Any]] = []
        while turns < self.max_turns:
            turns += 1
            reply = await self._chat(messages, tools)
            turn_meta.append(
                {
                    "actual_model": reply.get("actual_model"),
                    "usage": dict(reply.get("usage") or {}),
                }
            )
            content = reply.get("content") or ""
            tool_calls = reply.get("tool_calls") or []
            messages.append({"role": "assistant", "content": content, "tool_calls": tool_calls})
            if not tool_calls:
                reason = "no_tool_call"
                break
            for call in tool_calls:
                result = broker.dispatch(call.get("name", ""), call.get("arguments", {}) or {})
                messages.append(
                    {"role": "tool", "tool_call_id": call.get("id", ""), "content": result}
                )
            if broker.finished is not None:
                reason = "finished"
                break
        return ToolLoopResult(
            finished=broker.finished,
            turns=turns,
            transcript_digest=content_digest({"messages": messages}),
            stopped_reason=reason,
            turn_meta=turn_meta,
        )


# --------------------------------------------------------------------------- #
# Tiny JSON-schema helpers.
# --------------------------------------------------------------------------- #

_str = {"type": "string"}
_int = {"type": "integer"}


def _spec(
    name: str, description: str, props: dict[str, Any], required: list[str]
) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": props,
                "required": required,
                "additionalProperties": False,
            },
        },
    }
