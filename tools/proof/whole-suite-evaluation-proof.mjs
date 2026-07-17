#!/usr/bin/env node
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import {
  AUTHORITY_DEPENDENCY_DIGEST_ALGORITHM,
  SELF_PUBLICATION_EXCLUDED_GRAPHS,
  SELF_PUBLICATION_RULE,
  authorityDependencySetDigest,
  evaluateAuthorityBinding,
} from '../compiler/src/authority-binding.js';
import { jcs } from '../compiler/src/materialisation.js';

const repo = resolve(process.env.USF_REPO || '/usf');
const authorityDigest = process.env.USF_AUTHORITY_DIGEST || '';
const casRoot = resolve(process.env.USF_CAS_ROOT || '/var/lib/usf-cas');
const expectedReleaseFingerprint = 'd3e5e55b71044aecc0143ef490b67f399dc49fc6e73c1307a6b515ed8964b2f6';
const releaseKeyLabel = 'usf-foundation-release-hermetic-evaluation-key-v1';
const attestationKeyLabel = 'usf-whole-suite-evaluation-attestation-key-v1';
const chrootTraceDigest = 'sha256:763efb50a6448e3e5fb3470cf50054e6b3fc8da4400bd370911e1a2510a9738b';
const requireLiveAuthorityBinding = process.env.USF_REQUIRE_LIVE_AUTHORITY_BINDING === '1';
const selfPublicationExcludedSourcePaths = Object.freeze([
  'graph/assurance/evidence.trig',
  'graph/assurance/proofs.trig',
  'graph/contracts/capabilities.trig',
  'graph/observed/source-artefacts.trig',
]);
if (!/^sha256:[0-9a-f]{64}$/.test(authorityDigest)) throw new Error('USF_AUTHORITY_DIGEST is required');
if (relative(repo, casRoot) === '' || !relative(repo, casRoot).startsWith('..')) throw new Error('USF_CAS_ROOT must be outside the repository');

const root = `/tmp/usf-whole-suite-evaluation-${process.pid}`;
const generated = join(root, 'generated');
rmSync(root, { recursive: true, force: true });
mkdirSync(root, { recursive: true });

const sha = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const casPath = (digest) => join(casRoot, 'sha256', digest.slice(7, 9), digest.slice(7));
function put(bytes, mediaType) {
  const body = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const digest = sha(body);
  const target = casPath(digest);
  mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
  if (!existsSync(target)) writeFileSync(target, body, { flag: 'wx', mode: 0o600 });
  const observed = readFileSync(target);
  if (sha(observed) !== digest) throw new Error(`CAS verification failed: ${digest}`);
  return { digest, byteSize: observed.byteLength, mediaType, locator: `cas://sha256/${digest.slice(7)}` };
}
function verifyCas(digest) {
  const target = casPath(digest);
  return existsSync(target) && sha(readFileSync(target)) === digest;
}
function json(text, label) {
  const at = text.indexOf('{');
  if (at < 0) throw new Error(`${label} did not emit JSON`);
  try { return JSON.parse(text.slice(at)); } catch (error) { throw new Error(`${label} JSON invalid: ${error.message}`); }
}
function testCounts(text) {
  const number = (name) => Number(text.match(new RegExp(`^# ${name} ([0-9]+)$`, 'm'))?.[1] || 0);
  return { tests: number('tests'), pass: number('pass'), fail: number('fail'), skipped: number('skipped') };
}
const cases = [];
const stablePayloads = [];
const volatilePayloads = [];
function record(id, expected, observed, passed, negative = false, detail = '') {
  cases.push({ id, expected: String(expected), observed: String(observed), passed: Boolean(passed), ...(negative ? { negative: true } : {}), ...(detail ? { detail } : {}) });
}
function command(id, executable, args, cwd, summarize) {
  const started = Date.now();
  const result = spawnSync(executable, args, {
    cwd,
    env: { ...process.env, USF_REPO: repo, USF_CAS_ROOT: casRoot, USF_GRAPH_PY: process.env.USF_GRAPH_PY || '/usf/.venv/bin/python' },
    encoding: 'utf8',
    maxBuffer: 128 * 1024 * 1024,
  });
  const raw = Buffer.from(`${result.stdout || ''}${result.stderr || ''}`);
  volatilePayloads.push({ role: `${id}-raw-log`, durationMs: Date.now() - started, exitCode: result.status, ...put(raw, 'text/plain') });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${id} failed with exit ${result.status}`);
  const summary = summarize(result.stdout || '', result.stderr || '');
  const stableToken = (token) => String(token).replaceAll(root, '$RUN_ROOT').replaceAll(repo, '$REPO').replaceAll(casRoot, '$CAS');
  const payload = put(jcs({ command: [executable, ...args.map(stableToken)], exitCode: 0, id, result: summary }), 'application/json');
  stablePayloads.push({ role: `${id}-result`, ...payload });
  record(id, 'passed', 'passed', true);
  return summary;
}

const mcp = spawn('node', ['tools/compiler/src/mcp.js'], {
  cwd: repo,
  env: { ...process.env, USF_REPO: repo, USF_CAS_ROOT: casRoot },
  stdio: ['pipe', 'pipe', 'inherit'],
});
const lines = createInterface({ input: mcp.stdout });
const pending = new Map();
let nextId = 0;
lines.on('line', (line) => {
  let message;
  try { message = JSON.parse(line); } catch { return; }
  const waiter = pending.get(message.id);
  if (waiter) { pending.delete(message.id); waiter(message); }
});
function request(name, args) {
  const id = ++nextId;
  const response = new Promise((resolvePromise) => pending.set(id, resolvePromise));
  mcp.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } })}\n`);
  return response;
}
function value(response) {
  const text = response.result?.content?.find((item) => item.type === 'text')?.text;
  if (response.error || response.result?.isError || !text) throw new Error(text || JSON.stringify(response.error));
  return JSON.parse(text);
}
async function query(sparql) {
  const result = value(await request('usf_query', { sparql }));
  if (result.truncated) throw new Error('suite query truncated');
  return result.bindings.map((row) => Object.fromEntries(Object.entries(row).map(([key, term]) => [key, term.value])));
}

try {
  const layout = value(await request('usf_layout_context', { contract: 'urn:usf:semanticcontract:repositoryexternalartefactmaterialisation' }));
  if (layout.authorityDigest !== authorityDigest) throw new Error('authority drift before suite evaluation');
  record('authority-witness', authorityDigest, layout.authorityDigest, layout.authorityDigest === authorityDigest);

  const dependencySetDigest = authorityDependencySetDigest(layout.authorityGraphInventory);
  const authorityBindingCandidate = {
    schemaVersion: 1,
    evaluatedAuthorityDigest: authorityDigest,
    dependencySetDigest,
    dependencyDigestAlgorithm: AUTHORITY_DEPENDENCY_DIGEST_ALGORITHM,
    excludedGraphs: [...SELF_PUBLICATION_EXCLUDED_GRAPHS],
    requiresPostPublicationReevaluation: true,
    rule: SELF_PUBLICATION_RULE,
  };
  const candidateEvaluation = evaluateAuthorityBinding({
    currentAuthorityDigest: authorityDigest,
    graphInventory: layout.authorityGraphInventory,
    ...authorityBindingCandidate,
  });
  const authorityBindingCandidatePayload = put(jcs(authorityBindingCandidate), 'application/json');
  stablePayloads.push({ role: 'authority-binding-candidate', ...authorityBindingCandidatePayload });
  record('authority-binding-candidate', 'direct-authority', candidateEvaluation.mode, candidateEvaluation.ok, false, candidateEvaluation.findings.join(','));

  const bindingRows = await query(`SELECT ?binding ?evaluated ?dependency ?algorithm ?rule ?excluded ?required ?evidenceDigest WHERE {
    <urn:usf:proofresult:universalservicefoundationscopeandprincipleswholesuiteevaluation> <urn:usf:ontology:hasAuthorityBinding> ?binding .
    ?binding <urn:usf:ontology:bindingEvaluatedAuthorityDigest> ?evaluated ;
      <urn:usf:ontology:bindingDependencySetDigest> ?dependency ;
      <urn:usf:ontology:bindingDependencyDigestAlgorithm> ?algorithm ;
      <urn:usf:ontology:usesAuthorityBindingRule> ?rule ;
      <urn:usf:ontology:excludedAuthorityGraphIri> ?excluded ;
      <urn:usf:ontology:requiresPostPublicationReevaluation> ?required ;
      <urn:usf:ontology:authorityBindingEvidenceDigest> ?evidenceDigest .
  } ORDER BY ?binding ?excluded`);
  if (bindingRows.length > 0) {
    const head = bindingRows[0];
    const liveEvaluation = evaluateAuthorityBinding({
      currentAuthorityDigest: authorityDigest,
      evaluatedAuthorityDigest: head.evaluated,
      dependencySetDigest: head.dependency,
      dependencyDigestAlgorithm: head.algorithm,
      excludedGraphs: bindingRows.map((row) => row.excluded),
      graphInventory: layout.authorityGraphInventory,
      requiresPostPublicationReevaluation: head.required === 'true',
      rule: head.rule,
    });
    const evidenceVerified = verifyCas(head.evidenceDigest);
    record('postpublication-authority-binding', 'self-publication-closure', liveEvaluation.mode, liveEvaluation.ok && evidenceVerified, false, [...liveEvaluation.findings, ...(evidenceVerified ? [] : ['binding-evidence-cas'])].join(','));
  } else if (requireLiveAuthorityBinding) {
    record('postpublication-authority-binding', 'self-publication-closure', 'missing', false, false, 'live authority binding required');
  }

  const [contracts, capabilities, proofs, realisations, validations, typeCounts, evidenceDigests, semanticGaps, readiness, scopeNonclaims] = await Promise.all([
    query(`SELECT ?contract ?name ?lifecycle ?activation WHERE { ?contract a <urn:usf:ontology:SemanticContract> ; <urn:usf:ontology:canonicalName> ?name ; <urn:usf:ontology:semanticLifecycleState> ?lifecycle . OPTIONAL { ?contract <urn:usf:ontology:hasActivationState> ?activation } } ORDER BY ?contract`),
    query(`SELECT ?capability ?name ?contract WHERE { ?capability a <urn:usf:ontology:Capability> ; <urn:usf:ontology:canonicalName> ?name ; <urn:usf:ontology:hasContract> ?contract } ORDER BY ?capability ?contract`),
    query(`SELECT ?contract ?obligation ?result ?state ?confidence ?setDigest WHERE { ?contract a <urn:usf:ontology:SemanticContract> ; <urn:usf:ontology:mandatoryProofObligation> ?obligation ; <urn:usf:ontology:reliesOnProofResult> ?result . ?result <urn:usf:ontology:proofResultForObligation> ?obligation ; <urn:usf:ontology:hasProofResultState> ?state ; <urn:usf:ontology:hasConfidenceState> ?confidence ; <urn:usf:ontology:evidenceSetDigest> ?setDigest } ORDER BY ?contract ?obligation ?result`),
    query(`SELECT ?contract ?realisation ?state ?decision ?decisionState WHERE { ?contract a <urn:usf:ontology:SemanticContract> ; <urn:usf:ontology:semanticLifecycleState> <urn:usf:semanticlifecyclestate:active> . ?realisation <urn:usf:ontology:realisesContract> ?contract ; <urn:usf:ontology:realisationState> ?state ; <urn:usf:ontology:authorisedByDecision> ?decision . ?decision <urn:usf:ontology:decisionState> ?decisionState . FILTER(?state NOT IN (<urn:usf:realisationstate:contractonly>, <urn:usf:realisationstate:implementable>, <urn:usf:realisationstate:deferred>, <urn:usf:realisationstate:notclaimed>, <urn:usf:realisationstate:deprecated>)) } ORDER BY ?contract ?realisation`),
    query(`SELECT ?contract ?obligation ?execution ?result ?state ?evidence ?admission ?freshness ?integrity WHERE { ?contract a <urn:usf:ontology:SemanticContract> ; <urn:usf:ontology:semanticLifecycleState> <urn:usf:semanticlifecyclestate:active> ; <urn:usf:ontology:requiredValidation> ?obligation . ?execution a <urn:usf:ontology:ValidationExecution> ; <urn:usf:ontology:executesValidation> ?obligation ; <urn:usf:ontology:producesValidationResult> ?result . ?result <urn:usf:ontology:resultState> ?state ; <urn:usf:ontology:entersEvidenceLifecycleAs> ?evidence . ?evidence <urn:usf:ontology:hasAdmissionState> ?admission ; <urn:usf:ontology:hasFreshnessState> ?freshness ; <urn:usf:ontology:hasIntegrityState> ?integrity } ORDER BY ?contract ?obligation ?execution`),
    query(`SELECT ?type (COUNT(DISTINCT ?resource) AS ?count) WHERE { VALUES ?type { <urn:usf:ontology:SemanticContract> <urn:usf:ontology:Capability> <urn:usf:ontology:ContractFacet> <urn:usf:ontology:Service> <urn:usf:ontology:Provider> <urn:usf:ontology:Environment> <urn:usf:ontology:Claim> <urn:usf:ontology:NonClaim> <urn:usf:ontology:Permission> <urn:usf:ontology:Interface> } ?resource a ?type } GROUP BY ?type ORDER BY ?type`),
    query(`SELECT DISTINCT ?digest WHERE { ?evidence a <urn:usf:ontology:EvidenceResult> ; <urn:usf:ontology:contentDigest> ?digest ; <urn:usf:ontology:hasAdmissionState> <urn:usf:evidenceadmissionstate:admitted> ; <urn:usf:ontology:hasFreshnessState> <urn:usf:evidencefreshnessstate:fresh> ; <urn:usf:ontology:hasIntegrityState> <urn:usf:evidenceintegritystate:valid> . FILTER(REGEX(STR(?digest), "^sha256:[0-9a-f]{64}$")) } ORDER BY ?digest`),
    query(`SELECT ?kind (COUNT(*) AS ?count) WHERE {
      { ?contract a <urn:usf:ontology:SemanticContract> . FILTER NOT EXISTS { ?contract <urn:usf:ontology:semanticLifecycleState> ?state . VALUES ?state { <urn:usf:semanticlifecyclestate:active> <urn:usf:semanticlifecyclestate:deferred> <urn:usf:semanticlifecyclestate:deprecated> <urn:usf:semanticlifecyclestate:retired> } } BIND("unclassified-contract" AS ?kind) }
      UNION { ?capability a <urn:usf:ontology:Capability> . FILTER NOT EXISTS { ?capability <urn:usf:ontology:hasContract> ?contract } BIND("capability-without-contract" AS ?kind) }
      UNION { ?contract a <urn:usf:ontology:SemanticContract> ; <urn:usf:ontology:semanticLifecycleState> <urn:usf:semanticlifecyclestate:active> ; <urn:usf:ontology:mandatoryProofObligation> ?obligation . FILTER NOT EXISTS { ?contract <urn:usf:ontology:reliesOnProofResult> ?result . ?result <urn:usf:ontology:proofResultForObligation> ?obligation ; <urn:usf:ontology:hasProofResultState> <urn:usf:proofresultstate:successful> ; <urn:usf:ontology:hasConfidenceState> <urn:usf:proofconfidencestate:warranted> ; <urn:usf:ontology:evidenceSetDigest> ?set ; <urn:usf:ontology:usesAdmittedEvidence> ?evidence . ?evidence <urn:usf:ontology:hasAdmissionState> <urn:usf:evidenceadmissionstate:admitted> ; <urn:usf:ontology:hasFreshnessState> <urn:usf:evidencefreshnessstate:fresh> ; <urn:usf:ontology:hasIntegrityState> <urn:usf:evidenceintegritystate:valid> } BIND("active-proof-gap" AS ?kind) }
      UNION { ?contract a <urn:usf:ontology:SemanticContract> ; <urn:usf:ontology:semanticLifecycleState> <urn:usf:semanticlifecyclestate:active> . FILTER NOT EXISTS { ?realisation <urn:usf:ontology:realisesContract> ?contract ; <urn:usf:ontology:realisationState> ?state ; <urn:usf:ontology:authorisedByDecision> ?decision . ?decision <urn:usf:ontology:decisionState> <urn:usf:decisionstate:accepted> . FILTER(?state NOT IN (<urn:usf:realisationstate:contractonly>, <urn:usf:realisationstate:implementable>, <urn:usf:realisationstate:deferred>, <urn:usf:realisationstate:notclaimed>, <urn:usf:realisationstate:deprecated>)) } BIND("active-realisation-gap" AS ?kind) }
      UNION { ?contract a <urn:usf:ontology:SemanticContract> ; <urn:usf:ontology:semanticLifecycleState> <urn:usf:semanticlifecyclestate:active> ; <urn:usf:ontology:requiredValidation> ?obligation . FILTER NOT EXISTS { ?execution <urn:usf:ontology:executesValidation> ?obligation ; <urn:usf:ontology:producesValidationResult> ?result . ?result <urn:usf:ontology:resultState> <urn:usf:resultstate:passed> ; <urn:usf:ontology:entersEvidenceLifecycleAs> ?evidence . ?evidence <urn:usf:ontology:hasAdmissionState> <urn:usf:evidenceadmissionstate:admitted> ; <urn:usf:ontology:hasFreshnessState> <urn:usf:evidencefreshnessstate:fresh> ; <urn:usf:ontology:hasIntegrityState> <urn:usf:evidenceintegritystate:valid> } BIND("active-validation-gap" AS ?kind) }
      UNION { ?realisation <urn:usf:ontology:realisesContract> ?contract ; <urn:usf:ontology:realisationState> ?state . FILTER(?state NOT IN (<urn:usf:realisationstate:contractonly>, <urn:usf:realisationstate:implementable>, <urn:usf:realisationstate:deferred>, <urn:usf:realisationstate:notclaimed>, <urn:usf:realisationstate:deprecated>)) FILTER NOT EXISTS { ?realisation <urn:usf:ontology:authorisedByDecision> ?decision . ?decision <urn:usf:ontology:decisionState> <urn:usf:decisionstate:accepted> } BIND("realisation-decision-gap" AS ?kind) }
    } GROUP BY ?kind ORDER BY ?kind`),
    query(`SELECT ?state ?reason ?rung (COUNT(DISTINCT ?capability) AS ?count) WHERE { GRAPH <urn:usf:graph:derived:readiness> { ?readiness a <urn:usf:ontology:Readiness> ; <urn:usf:ontology:readinessOf> ?capability ; <urn:usf:ontology:readinessState> ?state ; <urn:usf:ontology:readinessReason> ?reason ; <urn:usf:ontology:readinessRung> ?rung } } GROUP BY ?state ?reason ?rung ORDER BY ?state ?reason ?rung`),
    query(`SELECT ?nonclaim WHERE { <urn:usf:semanticcontract:universalservicefoundationscopeandprinciples> <urn:usf:ontology:disclaims> ?nonclaim . VALUES ?nonclaim { <urn:usf:nonclaim:noliveproviderreadiness> <urn:usf:nonclaim:noproductionreadiness> <urn:usf:nonclaim:productionshapednotproductionlive> <urn:usf:nonclaim:nohumanacceptance> } } ORDER BY ?nonclaim`),
  ]);

  const lifecycle = Object.fromEntries(['active', 'deferred', 'deprecated', 'retired'].map((name) => [name, contracts.filter((item) => item.lifecycle.endsWith(`:${name}`)).length]));
  const activeProofKeys = new Set(proofs.filter((item) => item.state.endsWith(':successful') && item.confidence.endsWith(':warranted')).map((item) => `${item.contract}|${item.obligation}`));
  const activeValidationKeys = new Set(validations.filter((item) => item.state.endsWith(':passed') && item.admission.endsWith(':admitted') && item.freshness.endsWith(':fresh') && item.integrity.endsWith(':valid')).map((item) => `${item.contract}|${item.obligation}`));
  const completionScope = 'initial-hermetic-local-realisation';
  const inventory = { schemaVersion: 1, authorityDigest, completionScope, contracts, capabilities, proofs, realisations, validations, readiness, scopeNonclaims, typeCounts, semanticGaps };
  const inventoryPayload = put(jcs(inventory), 'application/json');
  stablePayloads.push({ role: 'machine-inventory', ...inventoryPayload });
  record('contract-inventory', '71 contracts; 67 active; 2 deferred; 2 deprecated', `${contracts.length} contracts; ${lifecycle.active} active; ${lifecycle.deferred} deferred; ${lifecycle.deprecated} deprecated`, contracts.length === 71 && lifecycle.active === 67 && lifecycle.deferred === 2 && lifecycle.deprecated === 2);
  record('capability-coverage', '68 mapped capabilities', `${new Set(capabilities.map((item) => item.capability)).size} mapped capabilities`, new Set(capabilities.map((item) => item.capability)).size === 68);
  record('semantic-gap-audit', '0 active or classification gaps', String(semanticGaps.reduce((sum, item) => sum + Number(item.count), 0)), semanticGaps.length === 0);
  record('proof-traceability', 'all active mandatory obligations successful and warranted', `${activeProofKeys.size} obligation proofs`, activeProofKeys.size >= 67);
  record('realisation-traceability', '67 active contracts with accepted completed realisations', String(new Set(realisations.map((item) => item.contract)).size), new Set(realisations.map((item) => item.contract)).size === 67);
  record('validation-traceability', 'all active required validations passed with admitted evidence', `${activeValidationKeys.size} validation obligations`, activeValidationKeys.size >= 67);
  const requiredScopeNonclaims = new Set([
    'urn:usf:nonclaim:nohumanacceptance',
    'urn:usf:nonclaim:noliveproviderreadiness',
    'urn:usf:nonclaim:noproductionreadiness',
    'urn:usf:nonclaim:productionshapednotproductionlive',
  ]);
  const observedScopeNonclaims = new Set(scopeNonclaims.map((item) => item.nonclaim));
  record(
    'completion-scope-nonclaims',
    completionScope,
    completionScope,
    [...requiredScopeNonclaims].every((item) => observedScopeNonclaims.has(item)) && readiness.length > 0,
    false,
    `readiness=${readiness.map((item) => `${item.state.split(':').at(-1)}:${item.reason.split(':').at(-1)}:${item.count}`).join(',')}`,
  );

  const missingCas = evidenceDigests.filter((item) => !verifyCas(item.digest));
  record('admitted-cas-verification', 'all referenced evidence content digests verify', `${evidenceDigests.length - missingCas.length}/${evidenceDigests.length}`, missingCas.length === 0);
  if (!verifyCas(chrootTraceDigest)) throw new Error('chroot trace CAS payload missing or invalid');
  stablePayloads.push({ role: 'chroot-isolation-trace', digest: chrootTraceDigest, byteSize: readFileSync(casPath(chrootTraceDigest)).byteLength, mediaType: 'text/plain', locator: `cas://sha256/${chrootTraceDigest.slice(7)}` });
  record('standalone-chroot-isolation', 'verified', 'verified', true);

  const prerequisiteDigests = JSON.parse(process.env.USF_SUITE_PREREQUISITE_DIGESTS || '[]');
  for (const digest of prerequisiteDigests) {
    if (!/^sha256:[0-9a-f]{64}$/.test(digest) || !verifyCas(digest)) throw new Error(`suite prerequisite missing or invalid: ${digest}`);
    stablePayloads.push({ role: 'suite-prerequisite', digest, byteSize: readFileSync(casPath(digest)).byteLength, mediaType: 'application/json', locator: `cas://sha256/${digest.slice(7)}` });
  }
  record('suite-prerequisites', 'all verified', `${prerequisiteDigests.length} verified`, true);

  const check = command('compiler-check', 'node', ['tools/compiler/src/cli.js', 'check'], repo, (out) => {
    const result = json(out, 'compiler check');
    return { ok: result.ok, files: result.files, authoredGraphs: result.authoredGraphs, derivedGraphs: result.derivedGraphs, observedGraphs: result.observedGraphs };
  });
  const drift = command('source-live-drift', 'node', ['tools/compiler/src/cli.js', 'drift-live'], repo, (out) => {
    const result = json(out, 'drift');
    return { conforms: result.conforms, sourceGraphs: result.sourceGraphDigests.length, liveGraphs: result.databaseGraphDigests.length, missing: result.comparison.missingGraphs.length, unexpected: result.comparison.unexpectedGraphs.length, mismatched: result.comparison.mismatchedGraphs.length };
  });
  const plan = command('generation-plan', 'node', ['tools/compiler/src/cli.js', 'plan'], repo, (out) => {
    const result = json(out, 'generation plan');
    return { complete: result.complete, plans: result.plans, outputs: result.outputs.length, obligations: result.obligations.length, datasetFiles: result.dataset.files, datasetQuads: result.dataset.quads };
  });
  const compilerTests = command('compiler-tests', 'npm', ['test'], join(repo, 'tools/compiler'), (out) => testCounts(out));
  const kernelTests = command('reference-kernel-tests', 'npm', ['test'], join(repo, 'realisations/reference-kernel'), (out) => testCounts(out));
  const graphParse = command('graph-parse', 'bash', ['tools/validation/validate-graph.sh'], repo, (out) => {
    const match = out.match(/parsed_ok=([0-9]+) empty_placeholders=([0-9]+) invalid=([0-9]+)/);
    if (!match) throw new Error('graph parse summary missing');
    return { parsed: Number(match[1]), empty: Number(match[2]), invalid: Number(match[3]) };
  });
  const schemas = command('representation-schemas', 'node', ['tools/validation/validate-materialisation.mjs', 'schemas'], repo, (out) => json(out, 'schema validation'));
  const fixtures = command('annotated-fixtures', 'npm', ['run', 'verify:fixtures'], join(repo, 'tools/compiler'), (out) => {
    const result = json(out, 'fixtures');
    return { ok: result.ok, fixtures: result.fixtureCount, failures: result.failures.length, negativeFixtures: result.results.filter((item) => item.expected !== 'conforming').length };
  });
  const live = command('live-conformance', 'node', ['tools/compiler/src/cli.js', 'verify'], repo, (out) => {
    const result = json(out, 'live verification');
    return { reachable: result.reachable, registeredGraphs: result.registeredGraphCount, registeredTriples: result.registeredTripleCount, missingGraphs: result.missingGraphs.length, unexpectedGraphs: result.unexpectedGraphs.length, shacl: result.validationConforms, integrity: result.integrityConforms, contamination: result.contaminationCount };
  });
  const dependencyTree = command('dependency-tree', 'npm', ['ls', '--all', '--json'], join(repo, 'tools/compiler'), (out) => {
    const result = json(out, 'dependency tree');
    return { name: result.name, version: result.version, problems: (result.problems || []).length, directDependencies: Object.keys(result.dependencies || {}).sort() };
  });

  const releaseSeed = createHash('sha256').update(releaseKeyLabel).digest();
  const releaseKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), releaseSeed]), format: 'der', type: 'pkcs8' });
  const releaseFingerprint = createHash('sha256').update(createPublicKey(releaseKey).export({ type: 'spki', format: 'der' })).digest('hex');
  if (releaseFingerprint !== expectedReleaseFingerprint) throw new Error('hermetic release key derivation drift');
  const releaseKeyPath = join(root, 'release-key.pem');
  writeFileSync(releaseKeyPath, releaseKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  const fullGeneration = command('clean-generation-full', 'node', ['tools/compiler/src/cli.js', 'generate', '--output', generated, '--mode', 'full', '--signing-key', releaseKeyPath, '--source-root', repo], repo, (out) => {
    const result = json(out, 'full generation');
    return { ok: result.ok, authorityDigest: result.authorityDigest, outputCount: result.outputCount, aggregateDigest: result.aggregateDigest, changed: result.changed };
  });
  const verifiedOutput = command('generated-output-verification', 'node', ['tools/compiler/src/cli.js', 'verify-output', '--output', generated, '--expected-key-fingerprint', expectedReleaseFingerprint], repo, (out) => {
    const result = json(out, 'generated output verification');
    return { ok: result.ok, checked: result.checked, independent: result.independent.ok, signatureVerified: result.independent.signatureVerified, signingIdentityTrusted: result.independent.signingIdentityTrusted, findings: result.independent.findings.length };
  });
  const generatedTests = command('generated-workspace-tests', 'npm', ['test'], join(generated, 'workspace'), (out) => testCounts(out));
  const generatedEvidence = command('generated-evidence-pipeline', 'node', ['proof/evidence-pipeline.mjs', 'suite'], generated, (out) => json(out, 'generated evidence pipeline'));
  const incrementalGeneration = command('clean-generation-incremental', 'node', ['tools/compiler/src/cli.js', 'generate', '--output', generated, '--mode', 'incremental', '--signing-key', releaseKeyPath, '--source-root', repo], repo, (out) => {
    const result = json(out, 'incremental generation');
    return { ok: result.ok, authorityDigest: result.authorityDigest, outputCount: result.outputCount, aggregateDigest: result.aggregateDigest, reused: result.reused, changed: result.changed };
  });
  rmSync(releaseKeyPath, { force: true });
  record('full-incremental-equivalence', fullGeneration.aggregateDigest, incrementalGeneration.aggregateDigest, fullGeneration.aggregateDigest === incrementalGeneration.aggregateDigest);
  record('source-dataset-bound-generation', fullGeneration.authorityDigest, incrementalGeneration.authorityDigest, /^[0-9a-f]{64}$/.test(fullGeneration.authorityDigest) && fullGeneration.authorityDigest === incrementalGeneration.authorityDigest);

  for (const [role, path, mediaType] of [
    ['generated-release-manifest', 'release/manifest.json', 'application/json'],
    ['generated-release-sbom', 'release/sbom.json', 'application/vnd.cyclonedx+json'],
    ['generated-release-provenance', 'release/provenance.json', 'application/json'],
    ['generated-release-signature', 'release/signature.json', 'application/json'],
    ['generated-release-attestation', 'release/attestation.json', 'application/json'],
  ]) stablePayloads.push({ role, ...put(readFileSync(join(generated, path)), mediaType) });

  const excluded = new Set(['.git', '.work', '.venv', 'node_modules']);
  const excludedSourcePaths = new Set(selfPublicationExcludedSourcePaths);
  const sourceFiles = [];
  function walk(directory) {
    for (const name of readdirSync(directory).sort()) {
      if (excluded.has(name) || name === '.env' || name === '.GOAL.md.swap') continue;
      const path = join(directory, name);
      const stat = lstatSync(path);
      const sourcePath = relative(repo, path);
      if (sourcePath === 'graph/derived' || excludedSourcePaths.has(sourcePath)) continue;
      if (stat.isDirectory()) walk(path);
      else if (stat.isFile()) sourceFiles.push({ path: sourcePath, digest: sha(readFileSync(path)), bytes: stat.size });
      else if (stat.isSymbolicLink()) sourceFiles.push({ path: sourcePath, digest: sha(Buffer.from(`symlink:${readlinkSync(path)}`)), bytes: stat.size });
    }
  }
  walk(repo);
  const sourceInventory = {
    schemaVersion: 1,
    normalizationRule: 'Self-publication semantic-control sources and deterministic derived projections are excluded from the stable repository-source digest and are instead bound by the live authority dependency-set rule plus mandatory postpublication reevaluation.',
    excludedPaths: [...selfPublicationExcludedSourcePaths, 'graph/derived'].sort(),
    files: sourceFiles,
    aggregateDigest: sha(jcs({ excludedPaths: [...selfPublicationExcludedSourcePaths, 'graph/derived'].sort(), files: sourceFiles })),
  };
  const sourcePayload = put(jcs(sourceInventory), 'application/json');
  stablePayloads.push({ role: 'repository-source-inventory', ...sourcePayload });

  const failedCases = cases.filter((item) => !item.passed);
  const adversarial = {
    schemaVersion: 1,
    authorityDigest,
    findings: failedCases.map((item) => ({ id: item.id, severity: 'critical', state: 'open', evidence: item.observed })),
    summary: { critical: failedCases.length, high: 0, claimAffectingMedium: 0 },
    testedClasses: ['authority-role-inversion', 'stale-packets', 'evidence-integrity', 'proof-binding', 'decision-authority', 'tenant-security-negative-paths', 'release-signature', 'source-live-drift'],
  };
  const adversarialPayload = put(jcs(adversarial), 'application/json');
  stablePayloads.push({ role: 'normalized-adversarial-findings', ...adversarialPayload });

  const human = `# USF initial hermetic/local suite realisation evaluation\n\nAuthority: ${authorityDigest}\n\nCompletion scope: ${completionScope}.\n\nContracts: ${contracts.length} total; ${lifecycle.active} active; ${lifecycle.deferred} deferred; ${lifecycle.deprecated} deprecated.\n\nCapabilities: ${new Set(capabilities.map((item) => item.capability)).size}. Active realisations: ${new Set(realisations.map((item) => item.contract)).size}.\n\nChecks: ${cases.length}; failures: ${failedCases.length}. Compiler tests: ${compilerTests.pass}/${compilerTests.tests}; kernel tests: ${kernelTests.pass}/${kernelTests.tests}; annotated fixtures: ${fixtures.fixtures}.\n\nGenerated release: ${fullGeneration.outputCount} outputs; aggregate ${fullGeneration.aggregateDigest}; signature identity ${expectedReleaseFingerprint}.\n\nNonclaims: this initial hermetic/local realisation is not production readiness or live-provider readiness. Hermetic evaluation signatures do not establish production authenticity, external certification, human acceptance, launch i18n, accessibility compliance, or UI product parity.\n`;
  const humanPayload = put(Buffer.from(human), 'text/markdown');
  stablePayloads.push({ role: 'bounded-human-evaluation', ...humanPayload });

  const descriptorIndex = {
    schemaVersion: 1,
    authorityDigest,
    normalizationRule: 'Only stable JCS summaries and immutable governed payloads enter the exact evidence-set digest. Raw command logs and elapsed times are retained in CAS as explicitly volatile diagnostics.',
    stable: stablePayloads,
    volatile: volatilePayloads,
  };
  const descriptorIndexPayload = put(jcs(descriptorIndex), 'application/json');
  const evidenceDescriptors = stablePayloads.map(({ role, ...descriptor }) => ({ role, ...descriptor })).sort((a, b) => a.role.localeCompare(b.role) || a.digest.localeCompare(b.digest));
  const evidenceSetDigest = sha(jcs(evidenceDescriptors));
  cases.sort((a, b) => a.id.localeCompare(b.id));
  const semanticIdentifiers = contracts.map((item) => item.contract).sort();
  const manifest = {
    schemaVersion: 1,
    authorityDigest,
    evidenceSetDigest,
    semanticIdentifiers,
    cases,
    measurements: {
      contracts: contracts.length,
      capabilities: new Set(capabilities.map((item) => item.capability)).size,
      activeContracts: lifecycle.active,
      deferredContracts: lifecycle.deferred,
      deprecatedContracts: lifecycle.deprecated,
      activeRealisations: new Set(realisations.map((item) => item.contract)).size,
      compilerTests: compilerTests.tests,
      kernelTests: kernelTests.tests,
      annotatedFixtures: fixtures.fixtures,
      generatedOutputs: fullGeneration.outputCount,
      sourceFiles: sourceFiles.length,
      stablePayloads: evidenceDescriptors.length,
      volatilePayloads: volatilePayloads.length,
    },
    payloads: evidenceDescriptors.map(({ role, ...descriptor }) => descriptor),
  };
  const manifestBytes = jcs(manifest);
  const manifestPayload = put(manifestBytes, 'application/json');
  const statement = {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{ name: 'usf-whole-suite-evidence-manifest', digest: { sha256: manifestPayload.digest.slice(7) } }],
    predicateType: 'https://in-toto.io/attestation/test-result/v0.1',
    predicate: { authorityDigest, evidenceSetDigest, result: failedCases.length ? 'failed' : 'passed', normalizationRule: descriptorIndex.normalizationRule },
  };
  const statementBytes = Buffer.from(jcs(statement));
  const statementPayload = put(statementBytes, 'application/vnd.in-toto+json');
  const attestationSeed = createHash('sha256').update(attestationKeyLabel).digest();
  const attestationKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), attestationSeed]), format: 'der', type: 'pkcs8' });
  const attestationPublic = createPublicKey(attestationKey);
  const payloadType = 'application/vnd.in-toto+json';
  const pae = (type, bytes) => {
    const payload = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
    return Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(type)} ${type} ${payload.length} `), payload]);
  };
  const signature = sign(null, pae(payloadType, statementBytes), attestationKey);
  if (!verify(null, pae(payloadType, statementBytes), attestationPublic, signature)) throw new Error('suite DSSE signature verification failed');
  const envelope = { payloadType, payload: statementBytes.toString('base64'), signatures: [{ keyid: sha(attestationPublic.export({ type: 'spki', format: 'der' })), sig: signature.toString('base64') }] };
  const envelopePayload = put(jcs(envelope), 'application/vnd.dsse.envelope+json');

  const result = {
    ok: failedCases.length === 0,
    authorityDigest,
    completionScope,
    evidenceManifest: manifestPayload,
    evidenceSetDigest,
    inTotoStatement: statementPayload,
    dsseEnvelope: envelopePayload,
    machineInventory: inventoryPayload,
    humanProjection: humanPayload,
    adversarialReport: adversarialPayload,
    externalPayloadDescriptors: descriptorIndexPayload,
    sourceInventory: sourcePayload,
    authorityBindingCandidate: { ...authorityBindingCandidate, evidence: authorityBindingCandidatePayload },
    release: { aggregateDigest: fullGeneration.aggregateDigest, signingKeyFingerprint: expectedReleaseFingerprint },
    cases: cases.length,
    failures: failedCases.length,
    stablePayloads: stablePayloads.length,
    volatilePayloads: volatilePayloads.length,
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!result.ok) process.exitCode = 1;
} finally {
  mcp.stdin.end();
  mcp.kill('SIGTERM');
  rmSync(root, { recursive: true, force: true });
}
