# Repository and external artefact materialisation

## Status

Accepted as a rationale record for `urn:usf:realisationdecision:repositoryexternalartefactmaterialisation`.
This ADR is not semantic authority and cannot activate a contract or authorise a path.

## Context

USF needs a standalone repository whose durable source and external payloads remain distinct from its validated semantic control plane. AI agents must be able to retrieve bounded, current, digest-bound realisation and validation instructions without treating a ticket, projection, source file, or report as truth.

## Decision

Use Stardog as the semantic control plane. Use the owner-oriented Git layout selected by the active contract: `tools/` for owned executables, `schemas/` for durable representation definitions, `decisions/` for rationale records, and `realisations/` only when an accepted decision selects local code.

Large or runtime payloads use immutable content addressing. The default backend is an operator-owned local filesystem outside Git. No GCS bucket, cloud billing linkage, or paid managed object store is selected. OCI remains only an authorised representation hypothesis for a future distributable bundle; it is not provisioned by this decision.

Repository writes are applied only from bounded plans carrying the live authority digest, exact content and prior-state digests, authorised path roles, artefact families, representation formats, and file modes. Agents realise and validate from bounded contract packets regenerated from current Stardog state.

## Consequences

The repository is independently usable with its own graph source, compiler, credentials boundary, agent skill, schemas, collectors, proof algorithm, validator, and chroot isolation harness. Runtime evidence, logs, reports, Parquet data, binaries, and local CAS objects remain outside Git. A changed authority digest invalidates outstanding plans and agent packets.

## Validation

The binding validation obligation is `urn:usf:validationobligation:repositoryexternalartefactmaterialisation`. Representative positive and planted-negative cases cover deterministic materialisation, rollback, digest verification, bounded packets, path portability, source isolation, transaction rollback, retention, and supersession.

## Nonclaims

This record does not claim proof-cockpit completion, production execution, Java cross-engine parity, paid object storage, external payload authority, or that an ADR can establish semantic truth.
