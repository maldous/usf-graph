# Security & isolation

The factory is **safe by default**. This document describes the isolation
boundaries, secret handling, sandboxing, and egress controls, and how each is
enforced deterministically (never by trusting a model).

## Isolation from /usf

- The factory **never writes to /usf** and never registers a worktree under
  `/usf/.git/worktrees`.
- Reads of `/usf` use `git --no-optional-locks` so git never takes the index
  lock or rewrites `/usf/.git`.
- A factory-owned **bare mirror** is created once with
  `git clone --mirror --no-hardlinks --no-local` (so it shares no objects or
  alternates with `/usf`). All disposable clones are made from the **mirror**,
  never from `/usf`.
- Disposable clones have their remotes removed, so a worker cannot fetch or push.

Enforced in `isolation.py`; verified in
`tests/test_contract.py::test_git_mirror_isolation_no_usf_writes` and the e2e
suite (which asserts `/usf` HEAD and status are unchanged).

## Semantic authority boundary

- Current semantic state is read **only** through the USF MCP boundary
  (`authority.py`), exposing a read-only allowlist of tools. Mutation tools the
  server offers (e.g. `usf_evidence_admit`) are **not callable** through the
  client.
- Mutation SPARQL is refused before it reaches the server.
- Repository graph files are **never** treated as semantic authority.
- Stardog is never mutated. Publication is a gated, disabled interface.

## Secrets

- Credentials live in `/root/.env` — root-owned, **mode 0600**, outside the repo.
- Only an **exact allowlist** of canonical model-provider variables is stored
  (`secrets.ALIAS_TABLE`). Stardog and unrelated service credentials are
  excluded (`secrets.EXCLUDED_VARS`).
- Values are **never** printed, logged, committed, or stored in SQLite. Every
  data structure that touches credentials exposes names only (`Normalization`
  has a value-free `__repr__`).
- A global `Redactor` scrubs known secret values and token-shaped strings from
  any log/report/event payload (`context.log_event` redacts recursively).
- `STARDOG_TOKEN` is never copied; the factory relies on `/usf/.env` (loaded by
  the MCP server itself).

## Sandbox enforcement (never trust the model)

`sandbox.py` inspects what a worker actually produced/attempted:

- **Patch scope**: a unified diff may only touch allowed write paths — never
  absolute paths, `..` escapes, `/usf`, or the secret file.
- **Secret leakage**: patches referencing the secret file or containing
  token-shaped strings are rejected.
- **Command allowlist**: only vetted local/read commands; `git push`, `remote`,
  `fetch`, network tools (`curl`/`wget`), and destructive commands are denied.

A worker result that violates scope or leaks a secret is turned into a
`SCOPE_VIOLATION` failure (see `workers.AiWorker`, `result_validation`), verified
across `tests/test_sandbox_results.py` and `tests/test_adversarial.py`.

## Data egress

- `config/data-egress-policy.yaml` maps data classifications to allowed provider
  privacy classes.
- Source-code egress is **disabled by default**. Private source may only go to
  `local_only` (and, when `--allow-source-egress` is set, `first_party_cli`).
- The scheduler enforces egress in hard eligibility; an external provider is
  ineligible for a private-source packet unless egress is explicitly enabled.

## Protected actions (all disabled by default)

`config/safety.yaml` gates: paid inference, source egress, main-branch
integration, push/PR, Stardog publication, risk acceptance, terminal completion.
`context.require_gate` fails closed. The **learning engine may never change these**
— it writes only `model_task_scores`.

## Prompt-injection resistance

Repository content cannot induce unsafe behavior because enforcement is external
to the model: tool/command/path allowlists, patch-scope validation, secret
scanning, and network-less disposable clones. A malicious instruction embedded in
a file cannot exfiltrate secrets or write outside scope.
