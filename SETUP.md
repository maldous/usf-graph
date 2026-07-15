# Standalone setup

## Requirements

- Linux with Node.js 22 or later.
- Access to a dedicated Stardog database through the official JavaScript SDK.
- For the isolation proof: a Debian-compatible chroot whose root is the parent directory of this repository, plus `sudo` and `chroot`.
- Python 3.11 or later with the exact dependencies in `pyproject.toml` for RDF/SHACL and representative Parquet proof cases.

No Stardog CLI or local Stardog server is required. No cloud object-storage account is required.

## Credentials and local payloads

From the repository root:

```bash
cp .env.example .env
```

Set `STARDOG_SERVER`, `STARDOG_DATABASE`, and either `STARDOG_TOKEN` or `STARDOG_USERNAME` plus `STARDOG_PASSWORD`. Set `USF_CAS_ROOT` to an operator-owned directory outside this repository, such as `/var/lib/usf-cas` inside the chroot. `.env` and CAS bytes are ignored and must never be committed.

The default architecture does not create a GCS bucket, link a billing account, or upload a payload. A managed backend is out of scope until separately modelled and proved.

## Local compiler

```bash
npm ci --prefix tools/compiler
npm --prefix tools/compiler run check
npm --prefix tools/compiler test
tools/validation/validate-materialisation.mjs schemas
```

To publish registered authored model changes:

```bash
tools/compiler/bin/publish-authority.sh
```

The publisher performs local checks and tests, asserts database options, replaces only registered named graphs inside the compiler transaction, runs SHACL/integrity/contamination/derivation gates, commits only after complete success, verifies live state, and checks source/live drift.

## Chroot

The host-side entry helper derives the chroot root from its own repository location:

```bash
sudo tools/chroot/enter.sh
```

Inside the chroot:

```bash
/usf/tools/chroot/bootstrap.sh
/usf/tools/chroot/verify-isolation.sh
```

Bootstrap installs pinned Node, Python dependencies, compiler dependencies, agent CLIs, and token-free MCP wiring. The repository and `.env` are already available at `/usf`; no parent repository or census is mounted. `verify-isolation.sh` checks the locally owned graph/compiler/agent surface and fails if a parent path is visible.

## Agent gateway

The project MCP configuration launches `tools/compiler/src/mcp.js`. Its bounded operations include health/query/bootstrap, layout context/plan/validation/application, artifact description/verification, contract packet projection, and semantic-gap work projection. Direct RDF mutation through MCP is refused. Coordinator mutations are realised as registered authored source and published by the compiler transaction.

AI agents should request `usf_contract_project` for the relevant active contract. The returned packet contains the live authority digest, semantic identifiers, states, objective, claims/nonclaims, authorised actions/paths/formats, acceptance and validation obligations, result requirements, and fail-closed stop conditions.
