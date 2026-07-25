# Adversarial counterexample harness (review artefact, not an authorised gate)

Preserved from the semantic-authority readiness review of merged `main`
`1637909fe21a64834b034dc1593543c5dd8adec5`, live authority
`sha256:19b46fa43cf6cddebc53fa213569a38d762905b7e16c0082ec9c3b33b94bf45d`
(40 graphs, 107 005 triples, `authority:drift mismatched: []`).

## Status and non-claims

- This directory is **not** semantic authority and **not** part of the canonical
  gate. `assurance/semantic-model-compilation/test-runner.mjs` discovers only
  `*.test.mjs`, so nothing here executes in `npm test`.
- `validation-satisfaction-counterexamples.py` is Python. The active
  repository-materialisation contract's `authorisedFormats` does **not** include
  a Python representation format, so this file is preserved on a branch for
  review continuity and **must not be merged to `main`** until either the
  contract authorises the format or the harness is reimplemented as tracked
  `*.test.mjs` regressions. Recorded as an open question, not a silent
  exception.
- Findings must be re-derived, not trusted from `run-53-cases.txt`. A green
  result here proves nothing about authority; a `DEFECT` result is a claim to be
  reproduced against the canonical Stardog validate-and-rollback path.

## Contents

| File | Purpose |
|---|---|
| `validation-satisfaction-counterexamples.py` | 58 counterexample fixtures over the full dataset, validated with pyshacl/rdflib (second engine). Each case declares `mustReject`; a case that must be rejected but conforms is reported as `DEFECT`. |
| `semantic-coverage-inventory.mjs` | Machine-generated class/predicate/shape/controlled-vocabulary coverage inventory over tracked source. |
| `run-53-cases.txt` | Observed outcome of the 53-case run at the baseline above: 32 `EXPECTED`, 21 `DEFECT`, 0 harness errors. |

The five `CV-*` cross-family cases (contradictory controlled values) were added
after that run and all five reported `DEFECT`, giving 58 cases and 26 accepted
malformed states in total.

## Running it

```sh
# read-only; parses tracked source, mutates nothing, contacts no endpoint
USF_ROOT=/path/to/worktree \
USF_RESULTS=/tmp/adversarial-results.json \
  .venv/bin/python assurance/adversarial/validation-satisfaction-counterexamples.py [CASE-ID ...]

USF_ROOT=/path/to/worktree node assurance/adversarial/semantic-coverage-inventory.mjs
```

Requires the tracked local SHACL dependency set
(`assurance/semantic-model-compilation/local-shacl-dependencies.json`):
CPython 3.11.2, pyshacl 0.40.0, rdflib 7.6.0, PyYAML 6.0.3.

## Harness caveats that affect interpretation

- Validation is scoped with pyshacl `focus_nodes`, so only the fixture's own
  nodes and any real node it names are validated. Violations focused elsewhere
  are not counted.
- Fixture IRIs must be hyphen-free and carry `usf:canonicalName`, or
  `urn:usf:shacl:IriHyphenShape` and the canonical-name shape fire and mask the
  case under test. `n()` handles both.
- `sh:sparql` constraints containing `SERVICE` cannot be evaluated locally.
- **Cases EV-02 to EV-08 are rejected incidentally**, by `EvidenceResultShape`
  on the fixture's own evidence node, not by the validation satisfaction
  contract. `EV-11` and `EV-12` isolate that contract by citing real,
  fully conformant live nodes; both conform, which is the actual finding.
