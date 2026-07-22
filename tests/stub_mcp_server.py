#!/usr/bin/env python3
"""A minimal stub USF MCP server for contract tests.

Speaks newline-delimited JSON-RPC 2.0 over stdio, exposing the read-only tools
plus a mutation tool (usf_evidence_admit) that the client must refuse to call.
"""

from __future__ import annotations

import json
import sys

TOOLS = [
    {"name": "usf_health", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "usf_bootstrap", "inputSchema": {"type": "object", "properties": {}}},
    {
        "name": "usf_query",
        "inputSchema": {"type": "object", "properties": {"sparql": {"type": "string"}}},
    },
    {"name": "usf_layout_context", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "usf_artifact_describe", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "usf_artifact_verify", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "usf_contract_project", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "usf_work_plan", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "usf_evidence_admit", "inputSchema": {"type": "object", "properties": {}}},  # mutation
]


def _send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _text(obj):
    return {"content": [{"type": "text", "text": json.dumps(obj)}]}


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        method = msg.get("method")
        mid = msg.get("id")
        if method == "initialize":
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "serverInfo": {"name": "stub", "version": "0"},
                        "capabilities": {"tools": {}},
                    },
                }
            )
        elif method == "notifications/initialized":
            pass  # notification, no response
        elif method == "tools/list":
            _send({"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}})
        elif method == "resources/list":
            _send({"jsonrpc": "2.0", "id": mid, "result": {"resources": []}})
        elif method == "tools/call":
            name = msg["params"]["name"]
            if name == "usf_health":
                _send(
                    {
                        "jsonrpc": "2.0",
                        "id": mid,
                        "result": _text({"ok": True, "database": "USF", "triples": 42}),
                    }
                )
            elif name == "usf_bootstrap":
                _send(
                    {
                        "jsonrpc": "2.0",
                        "id": mid,
                        "result": _text(
                            {
                                "authority": {
                                    "digest": "sha256:stub",
                                    "triples": 42,
                                    "coveredGraphCount": 3,
                                },
                                "openGaps": [],
                                "proofObligations": [],
                                "validationObligations": [],
                                "evidenceResults": [],
                            }
                        ),
                    }
                )
            elif name == "usf_query":
                _send({"jsonrpc": "2.0", "id": mid, "result": _text({"rows": []})})
            elif name == "usf_work_plan":
                offset = int(msg["params"].get("arguments", {}).get("offset", 0))
                _send(
                    {
                        "jsonrpc": "2.0",
                        "id": mid,
                        "result": _text(
                            {
                                "schemaVersion": 1,
                                "authorityDigest": "sha256:stub",
                                "contract": "urn:usf:semanticcontract:test",
                                "offset": offset,
                                "gaps": [],
                                "truncated": False,
                                "nextOffset": None,
                            }
                        ),
                    }
                )
            else:
                _send({"jsonrpc": "2.0", "id": mid, "result": _text({"echo": name})})
        else:
            if mid is not None:
                _send(
                    {
                        "jsonrpc": "2.0",
                        "id": mid,
                        "error": {"code": -32601, "message": "method not found"},
                    }
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
