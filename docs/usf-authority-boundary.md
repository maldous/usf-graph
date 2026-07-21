# USF authority boundary

The factory reads current USF semantic state **only** through the USF MCP
boundary. It never infers semantic truth from repository graph files.

## The client

`usf_factory.authority.UsfAuthorityClient` is a deterministic, **read-only** MCP
STDIO client speaking newline-delimited JSON-RPC 2.0. It launches the server via:

```bash
bash -lc 'set -a; [ -f /usf/.env ] && . /usf/.env; set +a; \
  exec /usr/local/bin/node /usf/processes/semantic-assurance/semantic-authority-mcp.mjs'
```

(overridable via `USF_FACTORY_MCP_COMMAND`). The server sources `/usf/.env`
itself, so the factory never sees Stardog credentials.

## Read-only allowlist

Only these tools are exposed as callable wrappers:

```
usf_health  usf_bootstrap  usf_query  usf_layout_context
usf_artifact_describe  usf_artifact_verify  usf_contract_project  usf_work_plan
```

The live server also offers mutation tools (`usf_evidence_admit`,
`usf_materialise`, `usf_validation_record`, `usf_proof_evaluate`, `usf_layout_plan`,
`usf_layout_validate`). These are **not** in the allowlist and `call_tool`
rejects them. `query()` additionally refuses SPARQL containing mutation keywords.

The server is tools-only; an **empty resources list is expected** and never used
as a substitute for the tools above.

## Deterministic snapshot

`snapshots.compile_snapshot` — run by the factory, not a model — assembles an
immutable, content-addressed `SemanticSnapshot` from:

| Field | Source |
| --- | --- |
| `authority_digest` | `usf_bootstrap` → `authority.digest` |
| `triple_count`, `graph_count` | `authority.triples`, `authority.coveredGraphCount` |
| `unresolved_obligations` | `openGaps` + `proofObligations` + `validationObligations` |
| `admitted_evidence` | `evidenceResults` (bounded, never a full transcript) |
| `repository_head`, `working_tree_digest` | read-only git inspection of `/usf` |
| `goal_digest`, `checkpoint_digest`, `ledger_digest` | file digests (if present) |
| `mcp_tools`, `health_ok` | `tools/list`, `usf_health` |

`captured_at` is metadata and **excluded from identity**, so re-snapshotting
identical state yields the same `snapshot_id` (the basis of replay).

## Why the factory compiles the snapshot

Per DESIGN Phase 4, letting a model "compile the bootstrap" caused tool-selection
failures, divergent interpretation of the empty resources list, repeated large
transcripts, and authority facts depending on model output. The factory compiles
the facts deterministically and hands AI a **compact projection** only.

## Verifying live health

```bash
usf-factory usf health       # tools, resources (empty), triples, ok
usf-factory usf bootstrap    # compact authority digest + obligation counts
usf-factory cycle snapshot   # full deterministic snapshot
```
