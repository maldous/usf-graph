import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import test from 'node:test';

const root = resolve(import.meta.dirname, '../../..');
const shared = readFileSync(resolve(root, 'AGENTS.md'), 'utf8');
const claude = readFileSync(resolve(root, 'CLAUDE.md'), 'utf8');
const codex = readFileSync(resolve(root, 'CODEX.md'), 'utf8');
const goal = readFileSync(resolve(root, 'GOAL.md'), 'utf8');
const mcp = JSON.parse(readFileSync(resolve(root, '.mcp.json'), 'utf8'));
const chrootBootstrap = readFileSync(resolve(root, 'tools/chroot/bootstrap.sh'), 'utf8');
const agentVerifier = readFileSync(resolve(root, 'tools/chroot/verify-agents.sh'), 'utf8');
const normalized = (value) => value.split('\n').map((line) => line.trimStart()).join('\n');
const accepted = `Semantics establish truth.      (Model)
    Truth demands evidence.         (Evidence)
    Evidence warrants proof.        (Proof)
    Proof warrants constraints.     (Contract)
    Contracts authorise code.       (Realisation)
    Code produces evidence.         (Validation)`;
const rejected = `Requests establish code.        (External work record)
    Code demands features.          (Toolchain)
    Features warrant proof.         (Testing)
    Proof specifies evidence.       (Reports)
    Evidence shapes truth.           (Review)
    Truth fulfils semantics.        (Documentation)`;

test('shared policy uniquely states accepted and rejected lifecycle sequences', () => {
  const acceptedPattern = /Semantics establish truth\.[ \t]+\(Model\)\nTruth demands evidence\.[ \t]+\(Evidence\)\nEvidence warrants proof\.[ \t]+\(Proof\)\nProof warrants constraints\.[ \t]+\(Contract\)\nContracts authorise code\.[ \t]+\(Realisation\)\nCode produces evidence\.[ \t]+\(Validation\)/g;
  const rejectedPattern = /Requests establish code\.[ \t]+\(External work record\)\nCode demands features\.[ \t]+\(Toolchain\)\nFeatures warrant proof\.[ \t]+\(Testing\)\nProof specifies evidence\.[ \t]+\(Reports\)\nEvidence shapes truth\.[ \t]+\(Review\)\nTruth fulfils semantics\.[ \t]+\(Documentation\)/g;
  assert.equal(normalized(shared).match(acceptedPattern)?.length || 0, 1);
  assert.equal(normalized(shared).match(rejectedPattern)?.length || 0, 1);
  assert.match(shared, /Reject the build-first inversion:/);
  assert.equal(claude.includes(accepted) || claude.includes(rejected), false);
  assert.equal(codex.includes(accepted) || codex.includes(rejected), false);
});

test('shared policy names sole authority and separates non-authority roles', () => {
  assert.match(shared, /Validated semantic state in Stardog is the sole USF semantic authority/);
  assert.doesNotMatch(shared, /semantic definitions\s*>\s*ADRs\s*>\s*validators/);
  for (const role of ['Model', 'Evidence', 'Proof', 'Contract', 'ADR', 'Realisation', 'Toolchain', 'Code', 'Validation', 'Report', 'External work record']) assert.match(shared, new RegExp(`\\b${role}\\b`));
});

test('product shims defer to the durable directive and checkpoint', () => {
  for (const shim of [claude, codex]) {
    assert.match(shim, /`GOAL\.md`/);
    assert.match(shim, /latest verified\s+programme checkpoint/);
    assert.match(shim, /cannot override `GOAL\.md` or\s+validated live semantic authority/);
  }
  assert.match(goal, /A Claude session reads `CLAUDE\.md`; a Codex session reads `CODEX\.md`/);
  assert.match(goal, /## Agent Continuation and Handoff/);
  assert.match(goal, /## Usage-Limit Safe Stop/);
});

test('durable directive preserves remedial terminal and external-work boundaries', () => {
  assert.match(goal, /USF_HERMETIC_SUITE_DELIVERY_COMPLETE/);
  assert.match(goal, /USF_HERMETIC_SUITE_DELIVERY_BLOCKED_IRRECOVERABLY/);
  assert.doesNotMatch(goal, /USF_INITIAL_SUITE_REALISATION_COMPLETE/);
  assert.match(goal, /External work trackers are never programme memory/);
  assert.match(goal, /No external work-tracker identifier may enter/);
});

test('default agent wiring does not make an external work tracker mandatory', () => {
  assert.equal(Object.keys(mcp.mcpServers).some((name) => /work.?tracker/i.test(name)), false);
  assert.doesNotMatch(chrootBootstrap, /work.?tracker.*(?:api.?key|mcp)|enabledMcpjsonServers[^\n]*work.?tracker/i);
  assert.doesNotMatch(agentVerifier, /work.?tracker.*(?:api.?key|mcp)/i);
});
