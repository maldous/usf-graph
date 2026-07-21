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
                "Finish with a structured result.",
                {
                    "status": {
                        "type": "string",
                        "enum": ["COMPLETED", "FAILED", "HUMAN_DECISION_REQUIRED"],
                    },
                    "uncertainties": {"type": "array", "items": _str},
                },
                ["status"],
            )
        )
        return specs

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
        try:
            return handler(arguments)
        except Exception as exc:
            return {"error": f"{type(exc).__name__}: {exc}"}

    def _resolve(self, rel: str) -> Path:
        target = (self.workspace / rel).resolve()
        # Confine to the workspace (defense in depth alongside the OS sandbox).
        if not str(target).startswith(str(self.workspace.resolve())):
            raise PermissionError(f"path escapes workspace: {rel}")
        return target

    def _read_file_range(self, args: dict[str, Any]) -> dict[str, Any]:
        path = str(args["path"])
        allowed = set(self.packet.read_paths) | set(self.packet.write_paths)
        if allowed and path not in allowed:
            return {"error": f"path not in packet scope: {path}"}
        target = self._resolve(path)
        if not target.is_file():
            return {"error": "not a file"}
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(1, int(args.get("start", 1)))
        end = min(len(lines), int(args.get("end", start + MAX_READ_LINES - 1)))
        end = min(end, start + MAX_READ_LINES - 1)
        return {"path": path, "start": start, "end": end, "lines": lines[start - 1 : end]}

    def _list_directory(self, args: dict[str, Any]) -> dict[str, Any]:
        target = self._resolve(str(args.get("path", ".")))
        if not target.is_dir():
            return {"error": "not a directory"}
        return {"entries": sorted(p.name for p in target.iterdir())[:MAX_SEARCH_RESULTS]}

    def _search_repository(self, args: dict[str, Any]) -> dict[str, Any]:
        query = str(args["query"])
        hits: list[dict[str, Any]] = []
        for p in sorted(self.workspace.rglob("*")):
            if len(hits) >= MAX_SEARCH_RESULTS or not p.is_file():
                continue
            try:
                for i, line in enumerate(
                    p.read_text(encoding="utf-8", errors="replace").splitlines(), 1
                ):
                    if query in line:
                        hits.append({"path": str(p.relative_to(self.workspace)), "line": i})
                        break
            except OSError:
                continue
        return {"hits": hits}

    def _apply_patch(self, args: dict[str, Any]) -> dict[str, Any]:
        """Shadow mode: validate the diff against scope but do NOT apply it."""
        patch = str(args["patch"])
        violations = validate_patch_scope(patch, self.packet.write_paths)
        leaks = scan_secrets(patch)
        if violations or leaks:
            return {"accepted": False, "violations": violations + leaks}
        return {"accepted": True, "changed_paths": parse_unified_diff_paths(patch)}

    def _apply_unified_patch(self, args: dict[str, Any]) -> dict[str, Any]:
        """Mutating mode: validate scope, then apply the diff to the workspace via git."""
        import subprocess

        patch = str(args["patch"])
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
        subprocess.run(
            ["git", "-C", str(self.workspace), "apply", "--index", "-"],
            input=patch,
            capture_output=True,
            text=True,
        )
        self.edits += 1
        return {"accepted": True, "changed_paths": parse_unified_diff_paths(patch)}

    def _write_new_file(self, args: dict[str, Any]) -> dict[str, Any]:
        path = str(args["path"])
        if path not in set(self.packet.write_paths):
            return {"accepted": False, "error": f"path not in write scope: {path}"}
        target = self._resolve(path)
        content = str(args.get("content", ""))
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
        while turns < self.max_turns:
            turns += 1
            reply = await self._chat(messages, tools)
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
