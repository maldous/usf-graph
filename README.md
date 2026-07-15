# Universal Service Foundation semantic graph

This repository is a standalone, semantic-first USF authority workspace. Validated state in Stardog is the sole semantic authority; the authored `graph/` source, compiler, schemas, code, ADRs, reports, and tickets have their distinct lifecycle roles and do not independently establish truth.

The repository owns everything needed to evolve and realise its model: registered RDF source, a transactional Stardog compiler, a bounded agent gateway, an operator-local content-addressed payload adapter, proof and validation tools, agent directives and skill, and a chroot isolation harness. It has no runtime dependency on a parent repository.

## Layout

- `graph/` — registered authored, observed, derived, rule, and SHACL source.
- `tools/compiler/` — official-SDK compiler and bounded MCP gateway.
- `tools/collectors/` — evidence and local-CAS collectors.
- `tools/proof/` — deterministic proof algorithms.
- `tools/validation/` — local and live validators.
- `schemas/` — durable JSON representation schemas.
- `decisions/` — rationale records; never semantic authority.
- `realisations/` — absent until a specific accepted decision authorises local code.

Runtime evidence, proof output, validation output, logs, binaries, Parquet datasets, local Stardog stores, generated projections, and CAS objects do not belong in Git.

## Start

1. Copy `.env.example` to `.env` and provide the Stardog endpoint/database plus token or username/password. Keep `USF_CAS_ROOT` outside this repository.
2. Install the frozen compiler dependencies with `npm ci --prefix tools/compiler`.
3. Run `npm --prefix tools/compiler run check` and `npm --prefix tools/compiler test`.
4. Publish an authorised graph change with `tools/compiler/bin/publish-authority.sh`. It checks, tests, validates, compiles in one transaction, verifies live state, and checks drift.

Agents use the `usf` MCP gateway and must call the single bounded bootstrap exactly once per task. Before creating or changing paths or formats, retrieve the active materialisation context or an AI task packet from Stardog. See [SETUP.md](SETUP.md) for chroot and operational details.

## Payload storage

The default payload backend is an operator-owned local content-addressed directory outside Git. Managed object storage, GCS buckets, billing linkage, and uploads are not configured or selected. Any future paid or managed backend requires its own semantic decision, evidence, proof, contract activation, and validation.
