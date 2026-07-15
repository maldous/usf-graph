import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import test from 'node:test';

const root = resolve(import.meta.dirname, '../../..');
const shared = readFileSync(resolve(root, 'AGENTS.md'), 'utf8');
const claude = readFileSync(resolve(root, 'CLAUDE.md'), 'utf8');
const codex = readFileSync(resolve(root, 'CODEX.md'), 'utf8');
const normalized = (value) => value.split('\n').map((line) => line.trimStart()).join('\n');
const accepted = `Semantics establish truth.      (Model)
    Truth demands evidence.         (Evidence)
    Evidence warrants proof.        (Proof)
    Proof warrants constraints.     (Contract)
    Contracts authorise code.       (Realisation)
    Code produces evidence.         (Validation)`;
const rejected = `Requirements establish code.    (Ticket)
    Code demands features.          (Toolchain)
    Features warrant proof.         (Testing)
    Proof specifies evidence.       (Reports)
    Evidence shapes truth.           (Review)
    Truth fulfils semantics.        (Documentation)`;

test('shared policy uniquely states accepted and rejected lifecycle sequences', () => {
  const acceptedPattern = /Semantics establish truth\.[ \t]+\(Model\)\nTruth demands evidence\.[ \t]+\(Evidence\)\nEvidence warrants proof\.[ \t]+\(Proof\)\nProof warrants constraints\.[ \t]+\(Contract\)\nContracts authorise code\.[ \t]+\(Realisation\)\nCode produces evidence\.[ \t]+\(Validation\)/g;
  const rejectedPattern = /Requirements establish code\.[ \t]+\(Ticket\)\nCode demands features\.[ \t]+\(Toolchain\)\nFeatures warrant proof\.[ \t]+\(Testing\)\nProof specifies evidence\.[ \t]+\(Reports\)\nEvidence shapes truth\.[ \t]+\(Review\)\nTruth fulfils semantics\.[ \t]+\(Documentation\)/g;
  assert.equal(normalized(shared).match(acceptedPattern)?.length || 0, 1);
  assert.equal(normalized(shared).match(rejectedPattern)?.length || 0, 1);
  assert.match(shared, /Reject the build-first inversion:/);
  assert.equal(claude.includes(accepted) || claude.includes(rejected), false);
  assert.equal(codex.includes(accepted) || codex.includes(rejected), false);
});

test('shared policy names sole authority and separates non-authority roles', () => {
  assert.match(shared, /Validated semantic state in Stardog is the sole USF semantic authority/);
  assert.doesNotMatch(shared, /semantic definitions\s*>\s*ADRs\s*>\s*validators/);
  for (const role of ['Model', 'Evidence', 'Proof', 'Contract', 'ADR', 'Realisation', 'Toolchain', 'Code', 'Validation', 'Report', 'Ticket']) assert.match(shared, new RegExp(`\\b${role}\\b`));
});
