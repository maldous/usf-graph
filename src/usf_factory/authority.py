"""USF authority boundary — a deterministic, read-only MCP STDIO client.

The factory (not an AI model) talks to the USF MCP server via newline-delimited
JSON-RPC 2.0 over stdio. The server is tools-only; an empty resources list is
expected and not used.

Safety
------
* Read-only by default: only the read-only tool wrappers are exposed. No
  mutation or publication method is exposed in this safe runtime.
* ``query`` refuses SPARQL containing mutation keywords (defense in depth; the
  server also refuses mutation on the read path).
* The server sources ``/usf/.env`` itself; the factory never sees Stardog
  credentials.
"""

from __future__ import annotations

import json
import queue
import re
import subprocess
import threading
from dataclasses import dataclass
from typing import Any

from .errors import AuthorityError
from .paths import USF_MCP_COMMAND

# Read-only tools the factory relies on (build task §3).
READ_ONLY_TOOLS = (
    "usf_health",
    "usf_bootstrap",
    "usf_query",
    "usf_layout_context",
    "usf_artifact_describe",
    "usf_artifact_verify",
    "usf_contract_project",
    "usf_work_plan",
)

_MUTATION_SPARQL = re.compile(
    r"\b(INSERT|DELETE|DROP|CLEAR|LOAD|CREATE|ADD|MOVE|COPY|WITH)\b", re.IGNORECASE
)

_PROTOCOL_VERSION = "2024-11-05"


@dataclass
class ToolCallResult:
    ok: bool
    content: list[dict[str, Any]]
    is_error: bool = False
    raw: dict[str, Any] | None = None

    def text(self) -> str:
        parts = []
        for item in self.content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(str(item.get("text", "")))
        return "\n".join(parts)

    def json(self) -> Any:
        """Best-effort parse of the first text block as JSON."""
        txt = self.text().strip()
        if not txt:
            return None
        try:
            return json.loads(txt)
        except json.JSONDecodeError:
            return None


class UsfAuthorityClient:
    """A minimal, robust MCP stdio JSON-RPC client (read-only wrappers only)."""

    def __init__(self, command: str | None = None, *, startup_timeout: float = 30.0) -> None:
        self._command = command or USF_MCP_COMMAND
        self._startup_timeout = startup_timeout
        self._proc: subprocess.Popen[bytes] | None = None
        self._id = 0
        self._inbox: queue.Queue[dict[str, Any]] = queue.Queue()
        self._stderr_tail: list[str] = []
        self._reader: threading.Thread | None = None
        self._stderr_thread: threading.Thread | None = None
        self._tools: list[str] = []
        self._started = False

    # ---- lifecycle ------------------------------------------------------ #

    def start(self) -> None:
        if self._started:
            return
        try:
            self._proc = subprocess.Popen(
                ["bash", "-lc", self._command],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
            )
        except OSError as exc:
            raise AuthorityError(f"failed to launch USF MCP server: {exc}") from exc

        self._reader = threading.Thread(target=self._read_stdout, daemon=True)
        self._reader.start()
        self._stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self._stderr_thread.start()

        self._handshake()
        self._started = True

    def close(self) -> None:
        if self._proc is None:
            return
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        except Exception:
            pass
        finally:
            self._proc = None
            self._started = False

    def __enter__(self) -> UsfAuthorityClient:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---- io threads ----------------------------------------------------- #

    def _read_stdout(self) -> None:
        assert self._proc and self._proc.stdout
        for raw in self._proc.stdout:
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(msg, dict):
                self._inbox.put(msg)

    def _read_stderr(self) -> None:
        assert self._proc and self._proc.stderr
        for raw in self._proc.stderr:
            line = raw.decode("utf-8", errors="replace").rstrip()
            if line:
                self._stderr_tail.append(line)
                if len(self._stderr_tail) > 50:
                    self._stderr_tail = self._stderr_tail[-50:]

    # ---- jsonrpc -------------------------------------------------------- #

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def _send(self, msg: dict[str, Any]) -> None:
        if not self._proc or not self._proc.stdin:
            raise AuthorityError("USF MCP server not started")
        data = (json.dumps(msg) + "\n").encode("utf-8")
        try:
            self._proc.stdin.write(data)
            self._proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise AuthorityError(f"USF MCP server pipe error: {exc}") from exc

    def _request(
        self, method: str, params: dict[str, Any] | None = None, timeout: float | None = None
    ) -> dict[str, Any]:
        req_id = self._next_id()
        self._send({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}})
        deadline = timeout if timeout is not None else self._startup_timeout
        # Drain messages until we see our response id.
        import time as _time

        end = _time.monotonic() + deadline
        while True:
            remaining = end - _time.monotonic()
            if remaining <= 0:
                raise AuthorityError(
                    f"timeout waiting for '{method}' response; "
                    f"stderr tail: {self._stderr_summary()}"
                )
            try:
                msg = self._inbox.get(timeout=min(remaining, 1.0))
            except queue.Empty:
                if self._proc and self._proc.poll() is not None:
                    raise AuthorityError(
                        f"USF MCP server exited (code {self._proc.returncode}); "
                        f"stderr tail: {self._stderr_summary()}"
                    ) from None
                continue
            if msg.get("id") == req_id:
                if "error" in msg:
                    err = msg["error"]
                    raise AuthorityError(f"MCP error for {method}: {err.get('message', err)}")
                return msg.get("result", {})
            # else: notification or a different id — ignore.

    def _notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def _handshake(self) -> None:
        result = self._request(
            "initialize",
            {
                "protocolVersion": _PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "usf-factory", "version": "0.1.0"},
            },
        )
        self._server_info = result.get("serverInfo", {})
        self._notify("notifications/initialized")

    def _stderr_summary(self) -> str:
        from . import secrets

        return secrets.redact(" | ".join(self._stderr_tail[-5:]))

    # ---- tools ---------------------------------------------------------- #

    def list_tools(self) -> list[str]:
        result = self._request("tools/list")
        tools = result.get("tools", [])
        self._tools = [t.get("name", "") for t in tools if isinstance(t, dict)]
        return self._tools

    def list_resources(self) -> list[dict[str, Any]]:
        """Resources are expected to be empty for this tools-only server."""
        try:
            result = self._request("resources/list", timeout=10)
        except AuthorityError:
            return []
        return result.get("resources", [])

    def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None, timeout: float = 60.0
    ) -> ToolCallResult:
        if name not in READ_ONLY_TOOLS:
            raise AuthorityError(f"tool '{name}' is not in the read-only allowlist")
        result = self._request(
            "tools/call", {"name": name, "arguments": arguments or {}}, timeout=timeout
        )
        content = result.get("content", []) if isinstance(result, dict) else []
        is_error = bool(result.get("isError")) if isinstance(result, dict) else False
        return ToolCallResult(ok=not is_error, content=content, is_error=is_error, raw=result)

    # ---- read-only convenience wrappers --------------------------------- #

    def health(self) -> ToolCallResult:
        return self.call_tool("usf_health", timeout=30)

    def bootstrap(self, arguments: dict[str, Any] | None = None) -> ToolCallResult:
        return self.call_tool("usf_bootstrap", arguments or {}, timeout=120)

    def query(self, sparql: str, limit: int | None = None) -> ToolCallResult:
        if _MUTATION_SPARQL.search(sparql):
            raise AuthorityError("mutation SPARQL refused on the read-only path")
        # The server's usf_query tool takes a `sparql` argument. Callers should
        # include a LIMIT clause; we append one only if wholly absent.
        query = sparql
        if limit is not None and " limit " not in sparql.lower():
            query = f"{sparql.rstrip()} LIMIT {int(limit)}"
        return self.call_tool("usf_query", {"sparql": query}, timeout=60)

    def layout_context(self, arguments: dict[str, Any] | None = None) -> ToolCallResult:
        return self.call_tool("usf_layout_context", arguments or {})

    def artifact_describe(self, arguments: dict[str, Any]) -> ToolCallResult:
        return self.call_tool("usf_artifact_describe", arguments)

    def artifact_verify(self, arguments: dict[str, Any]) -> ToolCallResult:
        return self.call_tool("usf_artifact_verify", arguments)

    def contract_project(self, arguments: dict[str, Any] | None = None) -> ToolCallResult:
        return self.call_tool("usf_contract_project", arguments or {})

    def work_plan(self, arguments: dict[str, Any] | None = None) -> ToolCallResult:
        return self.call_tool("usf_work_plan", arguments or {})
