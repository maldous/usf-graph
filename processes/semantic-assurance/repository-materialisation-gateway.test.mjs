import assert from 'node:assert/strict';
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';

import { DataFactory, Parser, Store } from 'n3';

import {
  ACTION_STATES, applyLayoutPlan, AUTHORITY_MOVED_CODE, createLayoutPlan, digest, GAP_DISPOSITIONS,
  layoutContext, materialisationInternals, realisationVerdict, REALISATION_STATE_FAILURE_CODES,
  refuseLifecycleMutation, planWork, projectContract, sourceDigest, stableAuthorityRead,
  validateLayoutPlan, verifyArtifact,
} from './repository-materialisation-gateway.mjs';

const { namedNode } = DataFactory;
const contract = 'urn:usf:semanticcontract:repositoryexternalartefactmaterialisation';
const family = 'urn:usf:artefactfamily:compiler';
const format = 'urn:usf:representationformat:ecmascriptmodule';
const role = 'urn:usf:pathrole:compilersource';
const compilerContract = 'urn:usf:semanticcontract:compilersemanticenforcement';
const compilerDecision = 'urn:usf:realisationdecision:semanticmodelcompilationrealisation';
const authorityDecision = 'urn:usf:realisationdecision:semanticauthoritycontrolselection';

const roots = [];
test.after(() => roots.forEach((root) => rmSync(root, { recursive: true, force: true })));

function binding(value) { return { value }; }
function defaultContractRows() {
  return [{
    canonicalName: binding('repositoryexternalartefactmaterialisation'),
    lifecycle: binding('urn:usf:semanticlifecyclestate:active'),
    activation: binding('urn:usf:contractactivationstate:active'),
    proof: binding('urn:usf:proofresult:repositoryexternalartefactmaterialisation'),
    proofState: binding('urn:usf:proofresultstate:successful'),
    decision: binding('urn:usf:realisationdecision:repositoryexternalartefactmaterialisation'),
    decisionState: binding('urn:usf:decisionstate:accepted'),
    authorisedRepository: binding('usf'),
    authorisedPath: binding('capabilities/semantic-model-compilation'),
  }];
}
function complementaryCompilerRows(effectiveDecisions = [compilerDecision]) {
  const base = {
    canonicalName: binding('compilersemanticenforcement'),
    lifecycle: binding('urn:usf:semanticlifecyclestate:active'),
    activation: binding('urn:usf:contractactivationstate:active'),
    proof: binding('urn:usf:proofresult:compilersemanticenforcement'),
    proofState: binding('urn:usf:proofresultstate:successful'),
    decisionState: binding('urn:usf:decisionstate:accepted'),
    authorisedRepository: binding('maldous/usf-graph'),
  };
  const rows = [
    { ...base, decision: binding(compilerDecision), authorisedPath: binding('package.json') },
    { ...base, decision: binding(authorityDecision), authorisedPath: binding('provider-bindings/stardog') },
  ];
  if (effectiveDecisions.length === 0) return rows;
  return rows.flatMap((row) => effectiveDecisions.map((effective) => ({
    ...row,
    effectiveDecision: binding(effective),
  })));
}
const validationObligation = 'urn:usf:validationobligation:repositoryexternalartefactmaterialisation';
// The fake's authority witness is one graph with one triple. The witness total
// is the inventory sum, not the client's size() reading, so that one triple fixes
// the digest a satisfying result has to bind to be current.
const witnessDigest = 'sha256:a28dfd4cb3960f9078f558caf098cb215aabad01c74593035ccab63acaf90e76';

function defaultApplicabilityRows(state = 'urn:usf:validationapplicabilitystate:required', extra = {}) {
  return [{
    state: binding(state),
    reason: binding('Validation is required: this contract binds an explicit ValidationObligation.'),
    ...extra,
  }];
}
// Live state after the applicability migration: validation is required and the
// obligation is reserved, so nothing is satisfied and nothing is executable.
function defaultValidationObligationRows(activation = 'urn:usf:validationactivationstate:reserved', extra = {}) {
  return [{ id: binding(validationObligation), activation: binding(activation), ...extra }];
}
function satisfyingResultRow({
  result = 'urn:usf:validationresult:materialisation',
  boundObligation = validationObligation,
  resultState = 'urn:usf:resultstate:passed',
  boundAuthority = witnessDigest,
  boundHead = 'a'.repeat(40),
  ...rest
} = {}) {
  return {
    satisfaction: binding(result),
    ...(boundObligation === null ? {} : { boundObligation: binding(boundObligation) }),
    ...(resultState === null ? {} : { resultState: binding(resultState) }),
    ...(boundAuthority === null ? {} : { boundAuthority: binding(boundAuthority) }),
    ...(boundHead === null ? {} : { boundHead: binding(boundHead) }),
    ...rest,
  };
}

function fakeClient({
  descriptor,
  contractRows = defaultContractRows(),
  applicabilityRows = defaultApplicabilityRows(),
  validationObligationRows = defaultValidationObligationRows(),
  proofGapRows = [],
} = {}) {
  return {
    size: async () => 10,
    construct: async () => '<urn:s> <urn:p> "materialisation" .\n',
    select: async (query) => {
      if (query.includes('COUNT(*) AS ?count')) return [{ count: binding('1') }];
      if (query.includes('SELECT DISTINCT ?g')) return [{ g: binding('urn:g') }];
      if (query.includes('?canonicalName ?lifecycle')) return contractRows;
      if (query.includes('<urn:usf:ontology:hasValidationApplicability> ?state')) return applicabilityRows;
      if (query.includes('a <urn:usf:ontology:ValidationObligation>')) return validationObligationRows;
      if (query.includes('<urn:usf:ontology:mandatoryProofObligation> ?subject')) return proofGapRows;
      if (query.includes('a <urn:usf:ontology:PathRole>')) return [{ role: binding(role), canonicalName: binding('compilersource'), parent: binding('capabilities/semantic-model-compilation'), onDemand: binding('true') }];
      if (query.includes('a <urn:usf:ontology:ArtefactFamily>')) return [{ family: binding(family), familyName: binding('compiler'), storage: binding('urn:usf:storageclass:gittrackedsource'), pathRole: binding(role), format: binding(format), namingPattern: binding('^[A-Za-z0-9._-]+$') }];
      if (query.includes('ExternalPayloadDescriptor')) return descriptor ? [Object.fromEntries(Object.entries(descriptor).map(([key, item]) => [key, binding(item)]))] : [];
      return [];
    },
  };
}

test('semantic authority explicitly selects the compiler decision and exact graph repository', () => {
  const bindings = new Store(new Parser({ format: 'application/trig' }).parse(
    readFileSync(new URL('../../semantic-model/realisation/bindings.trig', import.meta.url), 'utf8'),
  ));
  const predicate = namedNode('urn:usf:ontology:effectiveRealisationDecision');
  assert.deepEqual(
    bindings.getObjects(namedNode(compilerContract), predicate, null).map(({ value }) => value),
    [compilerDecision],
  );
  for (const decision of [compilerDecision, authorityDecision]) {
    assert.deepEqual(
      bindings.getObjects(
        namedNode(decision),
        namedNode('urn:usf:ontology:authorisesRepository'),
        null,
      ).map(({ value }) => value),
      ['maldous/usf-graph'],
    );
  }

  const ontology = new Store(new Parser({ format: 'text/turtle' }).parse(
    readFileSync(new URL('../../semantic-model/ontology.ttl', import.meta.url), 'utf8'),
  ));
  const property = namedNode('urn:usf:ontology:effectiveRealisationDecision');
  for (const type of [
    'http://www.w3.org/2002/07/owl#ObjectProperty',
    'http://www.w3.org/2002/07/owl#FunctionalProperty',
  ]) {
    assert.equal(ontology.has(
      property,
      namedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type'),
      namedNode(type),
      null,
    ), true);
  }
  assert.equal(ontology.has(
    property,
    namedNode('http://www.w3.org/2000/01/rdf-schema#domain'),
    namedNode('urn:usf:ontology:SemanticContract'),
    null,
  ), true);
  assert.equal(ontology.has(
    property,
    namedNode('http://www.w3.org/2000/01/rdf-schema#range'),
    namedNode('urn:usf:ontology:RealisationDecision'),
    null,
  ), true);
});

test('layout context is live-digest-bound and exposes active proof and authorised paths', async () => {
  const context = await layoutContext({ client: fakeClient() });
  assert.match(context.authorityDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(context.authorityDigestAlgorithm, 'sha256-rdfc10-graph-inventory-v2');
  assert.deepEqual(context.authorityGraphInventory, [{
    graph: 'urn:g',
    sha256: context.authorityGraphInventory[0].sha256,
    triples: 1,
  }]);
  assert.match(context.authorityGraphInventory[0].sha256, /^sha256:[0-9a-f]{64}$/);
  assert.equal(context.contract.activationState, 'urn:usf:contractactivationstate:active');
  assert.equal(context.contract.proofResultState, 'urn:usf:proofresultstate:successful');
  assert.equal(context.acceptedDecisionCount, 1);
  assert.equal(context.decisionResolution, 'unique-accepted');
  assert.deepEqual(context.authorisedRepositories, ['usf']);
  assert.deepEqual(context.authorisedPaths, ['capabilities/semantic-model-compilation']);
});

// --- authored-model closure ------------------------------------------------
// The projections above can only fail closed if the model actually carries an
// explicit applicability state for every governed contract. These read the
// authored source directly, so a contract added later without one fails here.
const ONT = 'urn:usf:ontology:';
const VAS = 'urn:usf:validationapplicabilitystate:';
const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';

function authoredModel() {
  const store = new Store();
  for (const file of ['contracts/capabilities.trig', 'contracts/materialisation.trig']) {
    store.addQuads(new Parser({ format: 'application/trig' }).parse(
      readFileSync(new URL(`../../semantic-model/${file}`, import.meta.url), 'utf8'),
    ));
  }
  for (const file of ['ontology.ttl', 'vocabulary.ttl']) {
    store.addQuads(new Parser({ format: 'text/turtle' }).parse(
      readFileSync(new URL(`../../semantic-model/${file}`, import.meta.url), 'utf8'),
    ));
  }
  return store;
}

test('the validation applicability vocabulary is a closed five-state set bound to contracts', () => {
  const model = authoredModel();
  const declared = model
    .getSubjects(namedNode(RDF_TYPE), namedNode(`${ONT}ValidationApplicabilityState`), null)
    .map(({ value }) => value)
    .sort();
  assert.deepEqual(declared, [
    `${VAS}conditional`, `${VAS}notrequired`, `${VAS}required`, `${VAS}reserved`, `${VAS}unresolved`,
  ]);
  const property = namedNode(`${ONT}hasValidationApplicability`);
  for (const type of ['http://www.w3.org/2002/07/owl#ObjectProperty', 'http://www.w3.org/2002/07/owl#FunctionalProperty']) {
    assert.equal(model.has(property, namedNode(RDF_TYPE), namedNode(type), null), true, type);
  }
  assert.deepEqual(
    model.getObjects(property, namedNode('http://www.w3.org/2000/01/rdf-schema#domain'), null).map(({ value }) => value),
    [`${ONT}SemanticContract`],
  );
  assert.deepEqual(
    model.getObjects(property, namedNode('http://www.w3.org/2000/01/rdf-schema#range'), null).map(({ value }) => value),
    [`${ONT}ValidationApplicabilityState`],
  );
});

test('every authored semantic contract declares exactly one applicability state with a stated basis', () => {
  const model = authoredModel();
  const contracts = [...new Set(model
    .getSubjects(namedNode(RDF_TYPE), namedNode(`${ONT}SemanticContract`), null)
    .map(({ value }) => value))];
  assert.ok(contracts.length >= 64, `expected the full contract set, saw ${contracts.length}`);
  for (const contract of contracts) {
    const states = model.getObjects(namedNode(contract), namedNode(`${ONT}hasValidationApplicability`), null).map(({ value }) => value);
    assert.equal(states.length, 1, `${contract} must declare exactly one applicability state`);
    assert.ok(states[0].startsWith(VAS), `${contract} applicability must come from the closed vocabulary`);
    assert.ok(
      model.getObjects(namedNode(contract), namedNode(`${ONT}validationApplicabilityReason`), null).length >= 1,
      `${contract} must state the basis of its applicability`,
    );
  }
});

test('the applicability migration promoted no contract to an exemption or an unearned conclusion', () => {
  const model = authoredModel();
  const contracts = [...new Set(model
    .getSubjects(namedNode(RDF_TYPE), namedNode(`${ONT}SemanticContract`), null)
    .map(({ value }) => value))];
  const byState = new Map();
  for (const contract of contracts) {
    const [state] = model.getObjects(namedNode(contract), namedNode(`${ONT}hasValidationApplicability`), null).map(({ value }) => value);
    byState.set(state, [...(byState.get(state) || []), contract]);
  }
  // Nothing may be migrated to exemption, and nothing may claim a conditional
  // or reserved determination that no authored condition supports.
  assert.deepEqual(byState.get(`${VAS}notrequired`), undefined);
  assert.deepEqual(byState.get(`${VAS}conditional`), undefined);
  assert.deepEqual(byState.get(`${VAS}reserved`), undefined);

  for (const contract of byState.get(`${VAS}unresolved`) || []) {
    const node = namedNode(contract);
    // Unresolved must stay unresolved: no bound obligation, no exemption
    // authority, and never on a contract whose activation implies it was proven.
    assert.deepEqual(model.getObjects(node, namedNode(`${ONT}requiredValidation`), null), []);
    assert.deepEqual(model.getObjects(node, namedNode(`${ONT}validationApplicabilityAuthority`), null), []);
    assert.deepEqual(
      model.getObjects(node, namedNode(`${ONT}hasActivationState`), null).map(({ value }) => value),
      ['urn:usf:contractactivationstate:proofblocked'],
      `${contract} is unresolved, so it must not be an active contract`,
    );
  }
  for (const contract of byState.get(`${VAS}required`) || []) {
    assert.ok(
      model.getObjects(namedNode(contract), namedNode(`${ONT}requiredValidation`), null).length >= 1,
      `${contract} declares required applicability so it must bind an obligation`,
    );
  }
  assert.equal((byState.get(`${VAS}required`) || []).length, 3);
  assert.equal((byState.get(`${VAS}unresolved`) || []).length, contracts.length - 3);
});

// usf:SemanticContract is a superclass of several descriptive classes, so under
// the reasoning schema "every SemanticContract" is not "every governed
// contract". The applicability requirement is keyed on governance marks, and
// this pins both halves of that boundary.
test('the governed-contract discriminator selects every governed contract and no descriptive subclass', () => {
  const model = authoredModel();
  const marks = ['hasActivationState', 'mandatoryProofObligation', 'requiredValidation', 'declaresFacet'];
  const contracts = [...new Set(model
    .getSubjects(namedNode(RDF_TYPE), namedNode(`${ONT}SemanticContract`), null)
    .map(({ value }) => value))];
  for (const contract of contracts) {
    assert.ok(
      marks.some((mark) => model.getObjects(namedNode(contract), namedNode(`${ONT}${mark}`), null).length > 0),
      `${contract} must carry a governance mark, otherwise the applicability requirement cannot reach it`,
    );
  }
  const descriptive = model
    .getSubjects(namedNode('http://www.w3.org/2000/01/rdf-schema#subClassOf'), namedNode(`${ONT}SemanticContract`), null)
    .map(({ value }) => value)
    .sort();
  assert.deepEqual(descriptive, [
    `${ONT}AccessibilityProfile`, `${ONT}ArtefactPlan`, `${ONT}AutomationWorkflowContract`,
    `${ONT}CompatibilityContract`, `${ONT}LocalisationProfile`, `${ONT}RendererContract`,
    `${ONT}UISemanticModel`, `${ONT}ViewModel`,
  ]);

  // Both enforcement layers must key on the same four marks, or one of them
  // would demand a lifecycle answer from a view model while the other did not.
  const shapes = readFileSync(new URL('../../semantic-model/shapes/lifecycle.ttl', import.meta.url), 'utf8');
  const integrity = readFileSync(new URL('../../semantic-model/rules/integrity.rq', import.meta.url), 'utf8');
  for (const mark of marks) {
    assert.ok(shapes.includes(`<urn:usf:ontology:${mark}> ?governedMark`), `shape must key on ${mark}`);
    assert.ok(integrity.includes(`usf:${mark} ?governedMark`), `integrity rule must key on ${mark}`);
  }
});

test('the rule layer carries a whole-dataset violation for every applicability and satisfaction leak', () => {
  const integrity = readFileSync(new URL('../../semantic-model/rules/integrity.rq', import.meta.url), 'utf8');
  for (const [code, discriminator] of [
    ['contractvalidationapplicabilityundeclared', 'FILTER NOT EXISTS { ?subject usf:hasValidationApplicability ?applicability }'],
    ['validationobligationoutsidecontractapplicability', 'usf:validationForContract ?validationContract'],
    ['validationsatisfactionwithoutcurrentidentitybinding', 'usf:validationEvaluatedSourceHead ?claimedHead'],
    ['reservedvalidationobligationsatisfied', 'urn:usf:validationactivationstate:blocked'],
    ['evidencefreshnessaxisdivergence', 'usf:hasFreshness ?legacyFreshness ; usf:hasFreshnessState ?lifecycleFreshness'],
  ]) {
    assert.ok(integrity.includes(`BIND("${code}" AS ?violation)`), `integrity rule must bind ${code}`);
    assert.ok(integrity.includes(discriminator), `integrity rule ${code} must retain its discriminating pattern`);
  }
});

test('readiness cannot reach ready past an unsatisfied, blocked or unresolved validation state', () => {
  const readiness = readFileSync(new URL('../../semantic-model/rules/readiness.rq', import.meta.url), 'utf8');
  for (const term of ['?validationUnsatisfied', '?validationBlocked', '?validationApplicabilityUnresolved']) {
    assert.ok(readiness.includes(`AS ${term}`), `readiness must derive ${term}`);
  }
  // Each new term must sit inside the precedence chain before its ready and
  // degraded tail, otherwise it could never change the outcome it exists to
  // change. Existing negative states keep priority, so a contract that is
  // already notready stays notready with its original, more specific reason.
  assert.ok(readiness.includes('?validationBlocked || ?validationUnsatisfied, rds:notready'));
  assert.ok(readiness.includes('?validationApplicabilityUnresolved, rds:unknown'));
  assert.ok(readiness.indexOf('?missingBlocking, rds:notready') < readiness.indexOf('?validationBlocked || ?validationUnsatisfied, rds:notready'));
  assert.ok(readiness.indexOf('?validationApplicabilityUnresolved, rds:unknown') < readiness.indexOf('?missingAdvisory, rds:degraded'));
  for (const reason of ['rr:validationunsatisfied', 'rr:validationblocked', 'rr:validationapplicabilityunresolved']) {
    assert.ok(readiness.includes(reason), `readiness must report ${reason}`);
  }
  const vocabulary = readFileSync(new URL('../../semantic-model/vocabulary.ttl', import.meta.url), 'utf8');
  for (const reason of ['validationunsatisfied', 'validationblocked', 'validationapplicabilityunresolved']) {
    assert.ok(vocabulary.includes(`rr:${reason} a usf:ReadinessReason`), `${reason} must be a declared readiness reason`);
  }
});

test('explicit effective decision selects one of multiple complementary accepted decisions', async () => {
  const context = await layoutContext({
    client: fakeClient({ contractRows: complementaryCompilerRows() }),
  }, { contract: compilerContract });
  assert.equal(context.acceptedDecisionCount, 2);
  assert.equal(context.effectiveDecisionCount, 1);
  assert.equal(context.decisionResolution, 'explicit');
  assert.equal(context.contract.decision, compilerDecision);
  assert.equal(context.contract.authorisedRepository, 'maldous/usf-graph');
  assert.deepEqual(context.authorisedRepositories, ['maldous/usf-graph']);
  assert.deepEqual(context.authorisedPaths, ['package.json']);
  const packet = await projectContract({
    client: fakeClient({ contractRows: complementaryCompilerRows() }),
  }, { contract: compilerContract });
  assert.deepEqual(packet.authorisedRepositories, ['maldous/usf-graph']);
  assert.deepEqual(packet.authorisedPaths, ['package.json']);
  assert.ok(packet.authorisedActions.length > 0);
});

test('multiple accepted decisions fail closed without exactly one valid effective marker', async () => {
  for (const [rows, expectedResolution] of [
    [complementaryCompilerRows([]), 'missing-effective-decision'],
    [complementaryCompilerRows([compilerDecision, authorityDecision]), 'multiple-effective-decisions'],
    [complementaryCompilerRows(['urn:usf:realisationdecision:notforcontract']), 'invalid-effective-decision'],
  ]) {
    const client = fakeClient({ contractRows: rows });
    const context = await layoutContext({ client }, { contract: compilerContract });
    assert.equal(context.decisionResolution, expectedResolution);
    assert.equal(context.contract.decision, null);
    assert.deepEqual(context.authorisedRepositories, []);
    assert.deepEqual(context.authorisedPaths, []);
    const packet = await projectContract({ client }, { contract: compilerContract });
    assert.deepEqual(packet.authorisedActions, []);
    assert.deepEqual(packet.authorisedRepositories, []);
    assert.deepEqual(packet.authorisedPaths, []);
  }
});

test('layout context rejects a truncated materialisation-rule projection', async () => {
  const client = fakeClient();
  const select = client.select;
  client.select = async (query) => query.includes('COUNT(*) AS ?count')
    ? [{ count: binding('2') }]
    : select(query);
  await assert.rejects(() => layoutContext({ client }), /rule projection is incomplete/);
});

test('plans require one accepted decision, its authorised paths, and an exact plan digest', async () => {
  const content = 'export const value = 1;\n';
  const operation = { action: 'write-file', artefactFamily: family, content, contentDigest: digest(content), contentEncoding: 'utf8', index: 0, path: 'capabilities/semantic-model-compilation/value.mjs', pathRole: role, representationFormat: format };
  const plan = await createLayoutPlan({ client: fakeClient() }, { contract, operations: [operation] });

  const missingDigest = structuredClone(plan);
  delete missingDigest.planDigest;
  assert.ok((await validateLayoutPlan({ client: fakeClient() }, missingDigest)).failures.some((finding) => finding.code === 'plan-digest'));

  const draftRows = defaultContractRows();
  draftRows[0].decisionState = binding('urn:usf:decisionstate:draft');
  assert.ok((await validateLayoutPlan({ client: fakeClient({ contractRows: draftRows }) }, plan)).failures.some((finding) => finding.code === 'plan-decision-not-uniquely-accepted'));

  const pathlessRows = defaultContractRows();
  delete pathlessRows[0].authorisedPath;
  assert.ok((await validateLayoutPlan({ client: fakeClient({ contractRows: pathlessRows }) }, plan)).failures.some((finding) => finding.code === 'operation-decision-path'));

  const second = { ...defaultContractRows()[0], decision: binding('urn:usf:realisationdecision:other') };
  assert.ok((await validateLayoutPlan({ client: fakeClient({ contractRows: [...defaultContractRows(), second] }) }, plan)).failures.some((finding) => finding.code === 'plan-decision-not-uniquely-accepted'));
});

test('layout plan validates exact content, path role, family, format, digest and authority', async () => {
  const ctx = { client: fakeClient() };
  const content = 'export const value = 1;\n';
  const operations = [{ action: 'write-file', artefactFamily: family, content, contentDigest: digest(content), contentEncoding: 'utf8', index: 0, path: 'capabilities/semantic-model-compilation/value.mjs', pathRole: role, representationFormat: format }];
  const plan = await createLayoutPlan(ctx, { contract, operations });
  assert.equal((await validateLayoutPlan(ctx, plan)).ok, true);
  const tampered = structuredClone(plan);
  tampered.operations[0].content = 'different';
  const validation = await validateLayoutPlan(ctx, tampered);
  assert.equal(validation.ok, false);
  assert.ok(validation.failures.some((finding) => finding.code === 'operation-content-mismatch'));
});

test('contract projection reports each validation obligation with its activation and satisfaction state', async () => {
  const packet = await projectContract({ client: fakeClient() }, { contract });
  assert.deepEqual(packet.validationObligations, [{
    id: validationObligation,
    activation: 'urn:usf:validationactivationstate:reserved',
    satisfactionCurrent: false,
    recordedSatisfactionCount: 0,
  }]);
  assert.ok(packet.semanticIdentifiers.includes(validationObligation));
});

// The boundary that keeps the model honest in both directions: a reserved
// obligation must not withdraw realisation authority that an accepted decision
// and a successful proof already granted, and must not be reported as satisfied.
test('reserved validation withholds the validated claim without withdrawing realisation authority', async () => {
  const packet = await projectContract({ client: fakeClient() }, { contract });
  assert.equal(packet.actionState, 'PROCEED');
  assert.deepEqual(packet.actionStateReasons, []);
  assert.ok(packet.authorisedActions.length > 0);
  assert.equal(packet.validationActionState, 'RESERVED_NO_ACTION');
  assert.equal(packet.validationSatisfied, false);
  assert.deepEqual(packet.validationGaps.map((gap) => gap.code), ['validation-obligation-reserved']);
  assert.ok(packet.stopConditions.includes('validationSatisfied is false and the task would claim validation'));
});

test('an activated but unsatisfied validation obligation blocks realisation authority', async () => {
  const client = fakeClient({ validationObligationRows: defaultValidationObligationRows('urn:usf:validationactivationstate:activated') });
  const packet = await projectContract({ client }, { contract });
  assert.equal(packet.actionState, 'BLOCK');
  assert.deepEqual(packet.actionStateReasons, ['missing-current-passing-validation']);
  assert.deepEqual(packet.authorisedActions, []);
  assert.deepEqual(packet.authorisedPaths, []);
  assert.equal(packet.validationActionState, 'PROCEED');
  assert.equal(packet.validationSatisfied, false);
});

test('a fully bound current satisfaction is the only state that reports validation satisfied', async () => {
  const client = fakeClient({
    validationObligationRows: [{
      ...defaultValidationObligationRows('urn:usf:validationactivationstate:activated')[0],
      ...satisfyingResultRow(),
    }],
  });
  const packet = await projectContract({ client }, { contract });
  assert.equal(packet.validationSatisfied, true);
  assert.equal(packet.validationObligations[0].satisfactionCurrent, true);
  assert.deepEqual(packet.validationGaps, []);
  assert.equal(packet.actionState, 'PROCEED');
  const plan = await planWork({ client }, { contract });
  assert.equal(plan.gapCount, 0);
  assert.equal(plan.actionState, 'PROCEED');
  assert.equal(plan.validationSatisfied, true);
  assert.equal(plan.completionClaim, false);
});

// Adversarial matrix. Each row is the smallest state that could previously have
// been read as "validation is fine", paired with the state the factory must now
// resolve to. None of them may reach PROCEED.
const adversarialCases = [
  {
    name: 'no applicability statement at all',
    client: { applicabilityRows: [] },
    gap: 'validation-applicability-unresolved',
    actionState: 'UNRESOLVED_FAIL_CLOSED',
    validationActionState: 'UNRESOLVED_FAIL_CLOSED',
  },
  {
    name: 'explicitly unresolved applicability',
    client: { applicabilityRows: defaultApplicabilityRows('urn:usf:validationapplicabilitystate:unresolved') },
    gap: 'validation-applicability-unresolved',
    actionState: 'UNRESOLVED_FAIL_CLOSED',
    validationActionState: 'UNRESOLVED_FAIL_CLOSED',
  },
  {
    name: 'conditional applicability with no structured condition',
    client: { applicabilityRows: defaultApplicabilityRows('urn:usf:validationapplicabilitystate:conditional'), validationObligationRows: [] },
    gap: 'validation-applicability-conditional-unevaluated',
    actionState: 'UNRESOLVED_FAIL_CLOSED',
    validationActionState: 'UNRESOLVED_FAIL_CLOSED',
  },
  {
    name: 'exemption claimed without proof authority',
    client: { applicabilityRows: defaultApplicabilityRows('urn:usf:validationapplicabilitystate:notrequired'), validationObligationRows: [] },
    gap: 'validation-exemption-unwarranted',
    actionState: 'BLOCK',
    validationActionState: 'UNRESOLVED_FAIL_CLOSED',
  },
  {
    name: 'exemption cited against an unsuccessful proof result',
    client: {
      applicabilityRows: defaultApplicabilityRows('urn:usf:validationapplicabilitystate:notrequired', {
        authority: binding('urn:usf:proofresult:other'),
        authorityState: binding('urn:usf:proofresultstate:failed'),
      }),
      validationObligationRows: [],
    },
    gap: 'validation-exemption-unwarranted',
    actionState: 'BLOCK',
    validationActionState: 'UNRESOLVED_FAIL_CLOSED',
  },
  {
    name: 'obligation with no activation state',
    client: { validationObligationRows: [{ id: binding(validationObligation) }] },
    gap: 'validation-obligation-activation-unresolved',
    actionState: 'UNRESOLVED_FAIL_CLOSED',
    validationActionState: 'UNRESOLVED_FAIL_CLOSED',
  },
  {
    name: 'obligation with an unknown activation state',
    client: { validationObligationRows: defaultValidationObligationRows('urn:usf:validationactivationstate:invented') },
    gap: 'validation-obligation-activation-unresolved',
    actionState: 'UNRESOLVED_FAIL_CLOSED',
    validationActionState: 'UNRESOLVED_FAIL_CLOSED',
  },
  {
    name: 'blocked obligation',
    client: { validationObligationRows: defaultValidationObligationRows('urn:usf:validationactivationstate:blocked') },
    gap: 'validation-obligation-blocked',
    actionState: 'BLOCK',
    validationActionState: 'BLOCK',
  },
  {
    name: 'required applicability binding no obligation',
    client: { validationObligationRows: [] },
    gap: null,
    actionState: 'PROCEED',
    validationActionState: 'UNRESOLVED_FAIL_CLOSED',
  },
  {
    name: 'satisfying result bound to a different obligation',
    client: {
      validationObligationRows: [{
        ...defaultValidationObligationRows('urn:usf:validationactivationstate:activated')[0],
        ...satisfyingResultRow({ boundObligation: 'urn:usf:validationobligation:sibling' }),
      }],
    },
    gap: 'validation-satisfaction-not-current',
    actionState: 'BLOCK',
    validationActionState: 'PROCEED',
  },
  {
    name: 'satisfying result bound to a superseded authority digest',
    client: {
      validationObligationRows: [{
        ...defaultValidationObligationRows('urn:usf:validationactivationstate:activated')[0],
        ...satisfyingResultRow({ boundAuthority: `sha256:${'0'.repeat(64)}` }),
      }],
    },
    gap: 'validation-satisfaction-not-current',
    actionState: 'BLOCK',
    validationActionState: 'PROCEED',
  },
  {
    name: 'satisfying result with no bound authority digest',
    client: {
      validationObligationRows: [{
        ...defaultValidationObligationRows('urn:usf:validationactivationstate:activated')[0],
        ...satisfyingResultRow({ boundAuthority: null }),
      }],
    },
    gap: 'validation-satisfaction-not-current',
    actionState: 'BLOCK',
    validationActionState: 'PROCEED',
  },
  {
    name: 'satisfying result with no bound source head',
    client: {
      validationObligationRows: [{
        ...defaultValidationObligationRows('urn:usf:validationactivationstate:activated')[0],
        ...satisfyingResultRow({ boundHead: null }),
      }],
    },
    gap: 'validation-satisfaction-not-current',
    actionState: 'BLOCK',
    validationActionState: 'PROCEED',
  },
  {
    name: 'satisfying result that did not pass',
    client: {
      validationObligationRows: [{
        ...defaultValidationObligationRows('urn:usf:validationactivationstate:activated')[0],
        ...satisfyingResultRow({ resultState: 'urn:usf:resultstate:failed' }),
      }],
    },
    gap: 'validation-satisfaction-not-current',
    actionState: 'BLOCK',
    validationActionState: 'PROCEED',
  },
  {
    name: 'satisfying result carrying an invalidation condition',
    client: {
      validationObligationRows: [{
        ...defaultValidationObligationRows('urn:usf:validationactivationstate:activated')[0],
        ...satisfyingResultRow({ invalidation: binding('urn:usf:validationinvalidationcondition:evidencestale') }),
      }],
    },
    gap: 'validation-satisfaction-not-current',
    actionState: 'BLOCK',
    validationActionState: 'PROCEED',
  },
  {
    name: 'satisfying result already superseded',
    client: {
      validationObligationRows: [{
        ...defaultValidationObligationRows('urn:usf:validationactivationstate:activated')[0],
        ...satisfyingResultRow({ superseded: binding('urn:usf:validationresult:successor') }),
      }],
    },
    gap: 'validation-satisfaction-not-current',
    actionState: 'BLOCK',
    validationActionState: 'PROCEED',
  },
];

test('adversarial validation states never authorise action and never report satisfaction', async () => {
  for (const item of adversarialCases) {
    const client = fakeClient(item.client);
    const packet = await projectContract({ client }, { contract });
    assert.equal(packet.validationSatisfied, false, item.name);
    assert.equal(packet.actionState, item.actionState, item.name);
    assert.equal(packet.validationActionState, item.validationActionState, item.name);
    if (item.actionState !== 'PROCEED') assert.deepEqual(packet.authorisedActions, [], item.name);
    const plan = await planWork({ client }, { contract });
    assert.equal(plan.validationSatisfied, false, item.name);
    assert.equal(plan.completionClaim, false, item.name);
    if (item.gap === null) {
      assert.equal(plan.gapCount, 0, item.name);
    } else {
      assert.ok(plan.gaps.some((gap) => gap.type === item.gap), `${item.name}: expected gap ${item.gap}`);
      assert.notEqual(plan.actionState, 'PROCEED', item.name);
    }
  }
});

// --- R6: applicability-level reserved, distinct from activation-level reserved -
// "reserved" names two different axes and they must never be conflated:
//   applicability reserved -> whether validation is in scope is deliberately deferred
//   activation   reserved -> the obligation exists but is not yet executable
// The applicability-level state has no live instance. These cases prove the code
// path is correct without authoring one, because inventing an instance to satisfy
// coverage is the defect this model exists to prevent.
test('applicability-level reserved resolves to RESERVED_NO_ACTION on its own axis', async () => {
  const client = fakeClient({
    applicabilityRows: defaultApplicabilityRows('urn:usf:validationapplicabilitystate:reserved'),
    // Reserved applicability still binds its obligations; give it an activated
    // one so the outcome cannot be attributed to activation-level reservation.
    validationObligationRows: defaultValidationObligationRows('urn:usf:validationactivationstate:activated'),
  });
  const packet = await projectContract({ client }, { contract });
  assert.equal(packet.validationApplicability.state, 'urn:usf:validationapplicabilitystate:reserved');
  assert.equal(packet.validationActionState, 'RESERVED_NO_ACTION');
  assert.equal(packet.validationSatisfied, false);
  assert.equal(GAP_DISPOSITIONS['validation-applicability-reserved'], 'RESERVED_NO_ACTION');

  const plan = await planWork({ client }, { contract });
  const applicabilityGap = plan.gaps.find((gap) => gap.type === 'validation-applicability-reserved');
  assert.ok(applicabilityGap, 'applicability-level reserved must emit its own gap');
  assert.equal(applicabilityGap.disposition, 'RESERVED_NO_ACTION');
  // Its subject is the contract, not an obligation: the deferral is a
  // contract-level determination.
  assert.equal(applicabilityGap.subject, contract);
  assert.equal(plan.validationSatisfied, false);
  assert.equal(plan.completionClaim, false);
  assert.notEqual(plan.actionState, 'PROCEED');
});

test('the two reserved axes are distinct codes on distinct subjects and cannot be confused', async () => {
  // Both axes reserved: each contributes its own code, on its own subject. The
  // obligation is reserved in both runs, so the only variable is applicability.
  const applicabilityReserved = await planWork({
    client: fakeClient({
      applicabilityRows: defaultApplicabilityRows('urn:usf:validationapplicabilitystate:reserved'),
    }),
  }, { contract });
  const activationReserved = await planWork({ client: fakeClient() }, { contract });

  const codes = (plan) => plan.gaps.map((gap) => gap.type).sort();
  assert.deepEqual(codes(applicabilityReserved), ['validation-applicability-reserved', 'validation-obligation-reserved']);
  assert.deepEqual(codes(activationReserved), ['validation-obligation-reserved']);
  // The applicability axis adds exactly one conclusion and changes nothing else.
  assert.deepEqual(
    codes(applicabilityReserved).filter((code) => !codes(activationReserved).includes(code)),
    ['validation-applicability-reserved'],
  );
  // Distinct IRIs, distinct gap codes, distinct subjects — and neither leaks the
  // other's conclusion.
  assert.equal(applicabilityReserved.validationApplicability, 'urn:usf:validationapplicabilitystate:reserved');
  assert.equal(activationReserved.validationApplicability, 'urn:usf:validationapplicabilitystate:required');
  const subjectOf = (plan, type) => plan.gaps.find((gap) => gap.type === type).subject;
  assert.equal(subjectOf(applicabilityReserved, 'validation-applicability-reserved'), contract);
  assert.equal(subjectOf(applicabilityReserved, 'validation-obligation-reserved'), validationObligation);
  assert.equal(subjectOf(activationReserved, 'validation-obligation-reserved'), validationObligation);
  // Both are validation-scoped, so neither withdraws realisation authority, and
  // neither reports satisfaction.
  for (const plan of [applicabilityReserved, activationReserved]) {
    assert.equal(plan.actionState, 'RESERVED_NO_ACTION');
    assert.equal(plan.validationSatisfied, false);
  }
});

test('reserved applicability that binds no obligation is unresolved, not reserved', async () => {
  // Reserved asserts validation is in scope; with nothing bound there is nothing
  // to defer, so the conclusion is withheld rather than downgraded.
  const client = fakeClient({
    applicabilityRows: defaultApplicabilityRows('urn:usf:validationapplicabilitystate:reserved'),
    validationObligationRows: [],
  });
  const packet = await projectContract({ client }, { contract });
  assert.equal(packet.validationActionState, 'RESERVED_NO_ACTION');
  assert.equal(packet.validationSatisfied, false);
  const plan = await planWork({ client }, { contract });
  assert.deepEqual(plan.gaps.map((gap) => gap.type), ['validation-applicability-reserved']);
  assert.notEqual(plan.actionState, 'PROCEED');
});

test('the current authored model contains no applicability-level reserved instance', () => {
  // Hermetic equivalent of a live census: the authored contract graphs are the
  // source of live authority and are drift-verified identical to it. Coverage of
  // the reserved branch above therefore proves the code path without inventing a
  // live instance.
  const model = authoredModel();
  const reserved = model
    .getSubjects(namedNode(`${ONT}hasValidationApplicability`), namedNode(`${VAS}reserved`), null)
    .map(({ value }) => value);
  assert.deepEqual(reserved, []);
  // ...and the state remains declared, so the branch is reachable vocabulary
  // rather than a dead code path.
  assert.equal(model.has(namedNode(`${VAS}reserved`), namedNode(RDF_TYPE), namedNode(`${ONT}ValidationApplicabilityState`), null), true);
  // The activation-level reserved state, by contrast, does have instances.
  assert.ok(model.getSubjects(
    namedNode(`${ONT}hasValidationActivationState`),
    namedNode('urn:usf:validationactivationstate:reserved'),
    null,
  ).length >= 3);
});

test('work planning refuses a contract declaring more than one applicability state', async () => {
  const client = fakeClient({
    applicabilityRows: [
      ...defaultApplicabilityRows('urn:usf:validationapplicabilitystate:required'),
      ...defaultApplicabilityRows('urn:usf:validationapplicabilitystate:notrequired'),
    ],
  });
  await assert.rejects(() => planWork({ client }, { contract }), /more than one validation applicability state/);
});

test('every work-plan gap code declares a factory disposition and none of them is PROCEED', () => {
  const codes = Object.keys(GAP_DISPOSITIONS);
  assert.ok(codes.length > 0);
  for (const code of codes) {
    assert.ok(['BLOCK', 'RESERVED_NO_ACTION', 'UNRESOLVED_FAIL_CLOSED'].includes(GAP_DISPOSITIONS[code]), code);
  }
});

test('work-plan pagination reports the whole disposition census, so a page cannot hide a blocked state', async () => {
  const proofGapRows = Array.from({ length: 60 }, (_, index) => ({ subject: binding(`urn:usf:proofobligation:p${index}`) }));
  const client = fakeClient({
    proofGapRows,
    validationObligationRows: defaultValidationObligationRows('urn:usf:validationactivationstate:blocked'),
  });
  const first = await planWork({ client }, { contract });
  assert.equal(first.gapCount, 61);
  assert.equal(first.gaps.length, 50);
  assert.equal(first.truncated, true);
  assert.equal(first.nextOffset, 50);
  assert.equal(first.dispositionCounts.BLOCK, 61);
  assert.equal(first.actionState, 'BLOCK');

  const second = await planWork({ client }, { contract, offset: 50 });
  assert.equal(second.gaps.length, 11);
  assert.equal(second.truncated, false);
  assert.equal(second.nextOffset, null);
  // The census and the state are identical on every page: pagination cannot
  // turn a blocked contract into an empty, apparently clean plan.
  assert.deepEqual(second.dispositionCounts, first.dispositionCounts);
  assert.equal(second.actionState, 'BLOCK');
  assert.equal(second.gapCount, 61);
});

test('work planning fails closed when live authority changes while the plan is built', async () => {
  const client = fakeClient();
  let calls = 0;
  const construct = client.construct;
  client.construct = async (...args) => {
    calls += 1;
    return calls > 1 ? '<urn:s> <urn:p> "drifted" .\n' : construct(...args);
  };
  await assert.rejects(() => planWork({ client }, { contract }), /live authority changed/);
});

test("proof-blocked contract projection is available but grants no materialisation authority", async () => {
  const packet = await projectContract({ client: fakeClient({ contractRows: [{
    canonicalName: binding("compilersemanticenforcement"),
    lifecycle: binding("urn:usf:semanticlifecyclestate:planned"),
    activation: binding("urn:usf:contractactivationstate:proofblocked"),
  }] }) }, { contract: "urn:usf:semanticcontract:compilersemanticenforcement" });
  assert.equal(packet.contractState.proof, null);
  assert.equal(packet.contractState.decision, null);
  assert.deepEqual(packet.authorisedActions, []);
  assert.deepEqual(packet.authorisedPaths, []);
  assert.deepEqual(packet.authorisedFormats, []);
});

test('model-incomplete contract projection is available with null lifecycle and activation and no authority grants', async () => {
  const packet = await projectContract({ client: fakeClient({ contractRows: [{
    canonicalName: binding('universalservicefoundationscopeandprinciples'),
  }] }) }, { contract: 'urn:usf:semanticcontract:universalservicefoundationscopeandprinciples' });
  assert.equal(packet.contractState.lifecycle, null);
  assert.equal(packet.contractState.activation, null);
  assert.equal(packet.contractState.proof, null);
  assert.equal(packet.contractState.decision, null);
  assert.deepEqual(packet.authorisedActions, []);
  assert.deepEqual(packet.authorisedPaths, []);
  assert.deepEqual(packet.authorisedFormats, []);
});

// --- one authoritative realisation verdict, consumed by every plan surface ----
// Before this, projectContract computed a validation-aware realisation state while
// createLayoutPlan / validateLayoutPlan / applyLayoutPlan judged only activation,
// proof and decision from layoutContext. An activated-but-unsatisfied validation
// obligation therefore produced actionState=BLOCK in the projection while
// usf_layout_plan still succeeded and coordinator apply remained reachable. These
// cases call the plan tools DIRECTLY, so they prove the bypass is closed rather
// than that the projection happens to agree.

const planOperation = () => {
  const content = 'export const value = 1;\n';
  return {
    action: 'write-file', artefactFamily: family, content, contentDigest: digest(content),
    contentEncoding: 'utf8', index: 0, path: 'capabilities/semantic-model-compilation/value.mjs',
    pathRole: role, representationFormat: format,
  };
};

// A plan minted while the contract did authorise realisation, replayed against a
// client that no longer does. Nothing about the plan itself is malformed.
async function goodPlan() {
  return createLayoutPlan({ client: fakeClient() }, { contract, operations: [planOperation()] });
}

const nonProceedClients = [
  {
    name: 'activated but unsatisfied validation',
    client: () => fakeClient({ validationObligationRows: defaultValidationObligationRows('urn:usf:validationactivationstate:activated') }),
    expected: ACTION_STATES.block,
    reason: 'missing-current-passing-validation',
  },
  {
    name: 'blocked validation obligation',
    client: () => fakeClient({ validationObligationRows: defaultValidationObligationRows('urn:usf:validationactivationstate:blocked') }),
    expected: ACTION_STATES.block,
    reason: 'validation-obligation-blocked',
  },
  {
    name: 'absent applicability',
    client: () => fakeClient({ applicabilityRows: [] }),
    expected: ACTION_STATES.unresolved,
    reason: 'validation-applicability-unresolved',
  },
  {
    name: 'explicitly unresolved applicability',
    client: () => fakeClient({ applicabilityRows: defaultApplicabilityRows('urn:usf:validationapplicabilitystate:unresolved') }),
    expected: ACTION_STATES.unresolved,
    reason: 'validation-applicability-unresolved',
  },
  {
    name: 'obligation activation unknown',
    client: () => fakeClient({ validationObligationRows: defaultValidationObligationRows('urn:usf:validationactivationstate:invented') }),
    expected: ACTION_STATES.unresolved,
    reason: 'validation-obligation-activation-unresolved',
  },
  {
    name: 'missing semantic lifecycle',
    client: () => {
      const rows = defaultContractRows();
      delete rows[0].lifecycle;
      return fakeClient({ contractRows: rows });
    },
    expected: ACTION_STATES.unresolved,
    reason: 'contract-lifecycle-unresolved',
  },
  {
    name: 'non-active semantic lifecycle',
    client: () => {
      const rows = defaultContractRows();
      rows[0].lifecycle = binding('urn:usf:semanticlifecyclestate:retired');
      return fakeClient({ contractRows: rows });
    },
    expected: ACTION_STATES.block,
    reason: 'contract-lifecycle-not-active',
  },
  {
    name: 'unsuccessful proof result',
    client: () => {
      const rows = defaultContractRows();
      rows[0].proofState = binding('urn:usf:proofresultstate:failed');
      return fakeClient({ contractRows: rows });
    },
    expected: ACTION_STATES.block,
    reason: 'contract-proof-not-successful',
  },
  {
    name: 'absent proof result',
    client: () => {
      const rows = defaultContractRows();
      delete rows[0].proof;
      delete rows[0].proofState;
      return fakeClient({ contractRows: rows });
    },
    expected: ACTION_STATES.unresolved,
    reason: 'contract-proof-result-unresolved',
  },
  {
    name: 'no accepted decision',
    client: () => {
      const rows = defaultContractRows();
      rows[0].decisionState = binding('urn:usf:decisionstate:draft');
      return fakeClient({ contractRows: rows });
    },
    expected: ACTION_STATES.unresolved,
    reason: 'decision-no-accepted-decision',
  },
];

test('the shared realisation verdict resolves every non-PROCEED state with its reason', async () => {
  for (const item of nonProceedClients) {
    const verdict = await realisationVerdict({ client: item.client() }, { contract });
    assert.equal(verdict.actionState, item.expected, item.name);
    assert.ok(verdict.actionStateReasons.includes(item.reason), `${item.name}: expected reason ${item.reason}, saw ${verdict.actionStateReasons.join(',')}`);
    assert.equal(verdict.stateFailureCode, REALISATION_STATE_FAILURE_CODES[item.expected], item.name);
  }
});

test('a non-PROCEED realisation state cannot create, validate or apply a plan', async () => {
  const plan = await goodPlan();
  for (const item of nonProceedClients) {
    // create
    await assert.rejects(
      () => createLayoutPlan({ client: item.client() }, { contract, operations: [planOperation()] }),
      new RegExp(REALISATION_STATE_FAILURE_CODES[item.expected]),
      `create: ${item.name}`,
    );
    // validate — a stable code, the state, and the reasons
    const validation = await validateLayoutPlan({ client: item.client() }, plan);
    assert.equal(validation.ok, false, `validate: ${item.name}`);
    assert.equal(validation.realisationActionState, item.expected, `validate state: ${item.name}`);
    const stateFailure = validation.failures.find((failure) => failure.code === REALISATION_STATE_FAILURE_CODES[item.expected]);
    assert.ok(stateFailure, `validate code: ${item.name}`);
    assert.ok(stateFailure.reasons.includes(item.reason), `validate reason: ${item.name}`);
    // apply — refused, and never applied, even with coordinator authority
    const applied = await applyLayoutPlan(
      { client: item.client(), coordinator: true, repositoryRoot: '/usf' },
      { plan, apply: true },
    );
    assert.equal(applied.applied, false, `apply: ${item.name}`);
    assert.equal(applied.realisationActionState, item.expected, `apply state: ${item.name}`);
    assert.equal(applied.stateFailureCode, REALISATION_STATE_FAILURE_CODES[item.expected], `apply code: ${item.name}`);
  }
});

test('ambiguous scalar contract conclusions fail closed instead of taking the first row', async () => {
  const cases = [
    ['canonical name', 'canonicalName', binding('somethingelse')],
    ['semantic lifecycle state', 'lifecycle', binding('urn:usf:semanticlifecyclestate:retired')],
    ['activation state', 'activation', binding('urn:usf:contractactivationstate:proofblocked')],
    ['proof result', 'proof', binding('urn:usf:proofresult:other')],
    ['proof result state', 'proofState', binding('urn:usf:proofresultstate:failed')],
  ];
  for (const [label, key, contradictory] of cases) {
    const rows = [...defaultContractRows(), { ...defaultContractRows()[0], [key]: contradictory }];
    const client = fakeClient({ contractRows: rows });
    await assert.rejects(() => realisationVerdict({ client }, { contract }), new RegExp(`ambiguous ${label}`), label);
    // The ambiguity must stop the plan surfaces too, not just the verdict.
    await assert.rejects(() => createLayoutPlan({ client }, { contract, operations: [planOperation()] }), new RegExp(`ambiguous ${label}`), `create: ${label}`);
    await assert.rejects(() => projectContract({ client }, { contract }), new RegExp(`ambiguous ${label}`), `project: ${label}`);
  }
});

test('an unknown gap code has no disposition and cannot silently authorise anything', () => {
  for (const code of Object.keys(GAP_DISPOSITIONS)) {
    assert.notEqual(GAP_DISPOSITIONS[code], ACTION_STATES.proceed, code);
  }
  assert.equal(GAP_DISPOSITIONS['validation-obligation-invented'], undefined);
  assert.deepEqual(Object.keys(REALISATION_STATE_FAILURE_CODES).sort(), [
    ACTION_STATES.block, ACTION_STATES.reserved, ACTION_STATES.unresolved,
  ].sort());
});

// The intended state of the live materialisation contract: validation is required
// and its obligation is reserved, so realisation authority stands while the
// validated claim is withheld. A dry-run must complete and claim nothing.
test('the reserved-validation contract stays PROCEED and dry-runs without a validation claim', async () => {
  const ctx = { client: fakeClient() };
  const verdict = await realisationVerdict(ctx, { contract });
  assert.equal(verdict.actionState, ACTION_STATES.proceed);
  assert.deepEqual(verdict.actionStateReasons, []);
  assert.equal(verdict.validation.validationActionState, ACTION_STATES.reserved);
  assert.equal(verdict.validation.validationSatisfied, false);

  const plan = await createLayoutPlan(ctx, { contract, operations: [planOperation()] });
  const validation = await validateLayoutPlan(ctx, plan);
  assert.equal(validation.ok, true);
  assert.equal(validation.realisationActionState, ACTION_STATES.proceed);
  assert.equal(validation.validationSatisfied, false, 'a passing plan must still make no validation claim');

  const dryRun = await applyLayoutPlan(ctx, { plan, apply: false });
  assert.equal(dryRun.applied, false);
  assert.equal(dryRun.dryRun, true);
  assert.equal(dryRun.validation.ok, true);
  assert.equal(dryRun.validation.validationSatisfied, false);

  const packet = await projectContract(ctx, { contract });
  assert.equal(packet.actionState, ACTION_STATES.proceed);
  assert.equal(packet.validationActionState, ACTION_STATES.reserved);
  assert.equal(packet.validationSatisfied, false);
});

// --- authority movement: every window between reads and writes -----------------
// A verdict is a statement about ONE authority state. Reading the witness
// concurrently with the semantic queries proved nothing, and apply re-read nothing
// at all, so a plan could be authorised against one state and written against
// another. These cases move authority in each window and require every one to fail
// closed — and every mutating case to prove exact rollback of paths, bytes, types
// and modes.

// A client whose graph content changes after a chosen number of witness reads, so
// authority moves at a precise point in the sequence.
function movingClient({ moveAfterWitnessReads = 1, ...options } = {}) {
  const base = fakeClient(options);
  let witnessReads = 0;
  let moved = false;
  return {
    ...base,
    // The witness reads the graph list then constructs each graph, so counting
    // construct calls counts witness reads.
    construct: async () => {
      witnessReads += 1;
      if (witnessReads > moveAfterWitnessReads) moved = true;
      return moved ? '<urn:s> <urn:p> "moved" .\n' : '<urn:s> <urn:p> "materialisation" .\n';
    },
    select: async (query) => base.select(query),
    get movedYet() { return moved; },
  };
}

// A client that moves authority when a chosen semantic query is issued, so the move
// lands between the opening witness and that query, or between two queries.
function movingOnQueryClient(trigger, options = {}) {
  const base = fakeClient(options);
  let moved = false;
  return {
    ...base,
    construct: async () => (moved ? '<urn:s> <urn:p> "moved" .\n' : '<urn:s> <urn:p> "materialisation" .\n'),
    select: async (query) => {
      const rows = await base.select(query);
      if (query.includes(trigger)) moved = true;
      return rows;
    },
  };
}

const writeOperation = (content = 'export const value = 1;\n', index = 0, path = 'capabilities/semantic-model-compilation/value.mjs') => ({
  action: 'write-file', artefactFamily: family, content, contentDigest: digest(content),
  contentEncoding: 'utf8', index, path, pathRole: role, representationFormat: format,
});

test('stableAuthorityRead brackets the read and rejects any movement inside it', async () => {
  const still = fakeClient();
  const { witness, value } = await stableAuthorityRead(still, 'test read', async () => 'result');
  assert.equal(value, 'result');
  assert.match(witness.digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(witness.graphCount, 1);
  assert.equal(witness.triples, 1);

  // Moving between the opening and closing witness must be rejected, and the
  // rejection must name the phase.
  await assert.rejects(
    () => stableAuthorityRead(movingClient({ moveAfterWitnessReads: 1 }), 'test read', async () => 'result'),
    (error) => error.message.includes(AUTHORITY_MOVED_CODE) && error.message.includes('test read'),
  );
});

test('authority moving between the opening witness and the contract queries fails closed', async () => {
  // The move lands as the contract row query is issued: the opening witness saw one
  // state, the semantic read saw another.
  const client = movingOnQueryClient('?canonicalName ?lifecycle');
  await assert.rejects(() => realisationVerdict({ client }, { contract }), new RegExp(AUTHORITY_MOVED_CODE));
  await assert.rejects(() => layoutContext({ client: movingOnQueryClient('?canonicalName ?lifecycle') }), new RegExp(AUTHORITY_MOVED_CODE));
});

test('authority moving between the contract and validation queries fails closed', async () => {
  // The validation scope is read after the contract rows but inside the same
  // bracket, so a move here is caught by the closing witness.
  const client = movingOnQueryClient('<urn:usf:ontology:hasValidationApplicability> ?state');
  await assert.rejects(() => realisationVerdict({ client }, { contract }), new RegExp(AUTHORITY_MOVED_CODE));
});

test('authority moving after the verdict but before plan validation fails closed', async () => {
  const verdict = await realisationVerdict({ client: fakeClient() }, { contract });
  // A fresh client at a different authority state: the plan and verdict digests no
  // longer describe live authority, so validation cannot pass.
  const moved = movingClient({ moveAfterWitnessReads: 0 });
  const validation = await validateLayoutPlan({ client: moved }, {
    schemaVersion: 1,
    authorityDigest: verdict.context.authorityDigest,
    contract,
    operations: [writeOperation()],
    planDigest: 'sha256:0',
  });
  assert.equal(validation.ok, false);
  assert.ok(validation.failures.some((failure) => failure.code === 'plan-authority-digest'));
});

test('projection queries after the verdict are proven against the verdict witness', async () => {
  // The three projection queries run after the bracket closes, so their own closing
  // witness must still equal the verdict witness exactly.
  const client = movingOnQueryClient('<urn:usf:ontology:asserts>');
  await assert.rejects(() => projectContract({ client }, { contract }), new RegExp(AUTHORITY_MOVED_CODE));
});

test('authority moving immediately before the first apply operation refuses to touch the filesystem', async () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-apply-premove-'));
  roots.push(root);
  const plan = await createLayoutPlan({ client: fakeClient() }, { contract, operations: [writeOperation()] });
  // Witness reads on this client: verdict open (1) and close (2) — validation
  // consumes the passed verdict and re-reads nothing — then pre-apply (3). Move
  // authority exactly at the pre-apply read.
  const client = movingClient({ moveAfterWitnessReads: 2 });
  await assert.rejects(
    () => applyLayoutPlan({ client, coordinator: true, repositoryRoot: root }, { plan, apply: true }),
    new RegExp(AUTHORITY_MOVED_CODE),
  );
  // Nothing was written: the refusal happened before the first mutation.
  assert.equal(existsSync(join(root, 'capabilities/semantic-model-compilation/value.mjs')), false);
  assert.deepEqual(readdirSync(root), []);
});

test('authority moving after the final operation rolls the plan back exactly and never reports applied', async () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-apply-postmove-'));
  roots.push(root);
  // Pre-existing state the rollback must restore byte-for-byte, with its own mode.
  const existingDirectory = join(root, 'capabilities/semantic-model-compilation');
  mkdirSync(existingDirectory, { recursive: true });
  const existingPath = join(existingDirectory, 'existing.mjs');
  const existingBytes = 'export const existing = true;\n';
  writeFileSync(existingPath, existingBytes, { mode: 0o640 });
  const beforeBytes = readFileSync(existingPath);
  const beforeMode = statSync(existingPath).mode & 0o7777;
  const beforeTree = readdirSync(existingDirectory).sort();

  const operations = [
    writeOperation('export const created = 1;\n', 0, 'capabilities/semantic-model-compilation/created.mjs'),
    { ...writeOperation('export const existing = false;\n', 1, 'capabilities/semantic-model-compilation/existing.mjs'), sourceDigest: digest(existingBytes) },
  ];
  const plan = await createLayoutPlan({ client: fakeClient() }, { contract, operations });

  // Witness reads: verdict open (1), verdict close (2), pre-apply (3) — all stable,
  // so the writes happen — then the post-apply check (4) observes the move.
  const client = movingClient({ moveAfterWitnessReads: 3 });
  await assert.rejects(
    () => applyLayoutPlan({ client, coordinator: true, repositoryRoot: root }, { plan, apply: true }),
    (error) => {
      // The stable code survives, and rollback failures would be preserved through
      // AggregateError rather than replacing the primary error.
      const message = error instanceof AggregateError ? error.errors.map((item) => item.message).join(' ') : error.message;
      return message.includes(AUTHORITY_MOVED_CODE);
    },
  );

  // Exact rollback: the created path is gone, the overwritten path is byte- and
  // mode-identical, the directory contains exactly what it did, and types match.
  assert.equal(existsSync(join(existingDirectory, 'created.mjs')), false, 'created path must be removed');
  assert.deepEqual(readFileSync(existingPath), beforeBytes, 'overwritten bytes must be restored');
  assert.equal(statSync(existingPath).mode & 0o7777, beforeMode, 'mode must be restored');
  assert.equal(statSync(existingPath).isFile(), true, 'type must be restored');
  assert.deepEqual(readdirSync(existingDirectory).sort(), beforeTree, 'directory contents must be restored');
});

test('a stable authority applies the same plan and reports applied', async () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-apply-stable-'));
  roots.push(root);
  const ctx = { client: fakeClient(), coordinator: true, repositoryRoot: root };
  const plan = await createLayoutPlan(ctx, { contract, operations: [writeOperation()] });
  const applied = await applyLayoutPlan(ctx, { plan, apply: true });
  assert.equal(applied.applied, true);
  assert.equal(
    readFileSync(join(root, 'capabilities/semantic-model-compilation/value.mjs'), 'utf8'),
    'export const value = 1;\n',
  );
});

test('materialiser defaults to dry-run and apply is coordinator-only and idempotent', async () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-materialise-'));
  try {
    const ctx = { client: fakeClient(), repositoryRoot: root, coordinator: true };
    const content = 'export const value = 1;\n';
    const plan = await createLayoutPlan(ctx, { operations: [{ action: 'write-file', artefactFamily: family, content, contentDigest: digest(content), contentEncoding: 'utf8', index: 0, path: 'capabilities/semantic-model-compilation/value.mjs', pathRole: role, representationFormat: format }] });
    assert.equal((await applyLayoutPlan(ctx, { plan })).dryRun, true);
    assert.equal((await applyLayoutPlan(ctx, { plan, apply: true })).applied, true);
    assert.equal(readFileSync(join(root, 'capabilities/semantic-model-compilation/value.mjs'), 'utf8'), content);
    assert.equal((await applyLayoutPlan(ctx, { plan, apply: true })).applied, true);
    await assert.rejects(() => applyLayoutPlan({ ...ctx, coordinator: false }, { plan, apply: true }), /coordinator-only/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('materialiser replaces only an exact prior digest and rolls the plan back on failure', async () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-materialise-rollback-'));
  try {
    const ctx = { client: fakeClient(), repositoryRoot: root, coordinator: true };
    const existing = join(root, 'capabilities/semantic-model-compilation/existing.js');
    mkdirSync(join(root, 'capabilities/semantic-model-compilation'), { recursive: true });
    writeFileSync(existing, 'prior\n');
    const replacement = 'replacement\n';
    const plan = await createLayoutPlan(ctx, { operations: [
      { action: 'write-file', artefactFamily: family, content: 'new\n', contentDigest: digest('new\n'), contentEncoding: 'utf8', index: 0, path: 'capabilities/semantic-model-compilation/new.js', pathRole: role, representationFormat: format },
      { action: 'write-file', artefactFamily: family, content: replacement, contentDigest: digest(replacement), contentEncoding: 'utf8', index: 1, path: 'capabilities/semantic-model-compilation/existing.js', pathRole: role, representationFormat: format, sourceDigest: digest('prior\n') },
    ] });
    writeFileSync(existing, 'concurrent-change\n');
    await assert.rejects(() => applyLayoutPlan(ctx, { plan, apply: true }), /source digest mismatch/);
    assert.equal(existsSync(join(root, 'capabilities/semantic-model-compilation/new.js')), false);
    assert.equal(readFileSync(existing, 'utf8'), 'concurrent-change\n');
    writeFileSync(existing, 'prior\n');
    assert.equal((await applyLayoutPlan(ctx, { plan, apply: true })).applied, true);
    assert.equal(readFileSync(existing, 'utf8'), replacement);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('delete rollback restores exact file and directory types, bytes, and modes after a later failure', async () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-materialise-delete-mode-'));
  try {
    const ctx = { client: fakeClient(), repositoryRoot: root, coordinator: true };
    const source = join(root, 'capabilities/semantic-model-compilation/mode.js');
    const directory = join(root, 'capabilities/semantic-model-compilation/mode-directory');
    const blocker = join(root, 'capabilities/semantic-model-compilation/blocker.js');
    mkdirSync(join(root, 'capabilities/semantic-model-compilation'), { recursive: true });
    mkdirSync(directory, { mode: 0o711 });
    writeFileSync(source, 'exact prior bytes\n', { mode: 0o640 });
    writeFileSync(blocker, 'concurrent bytes\n');
    chmodSync(source, 0o640);
    chmodSync(directory, 0o711);
    const plan = await createLayoutPlan(ctx, { operations: [
      { action: 'delete-path', index: 0, path: 'capabilities/semantic-model-compilation/mode.js', pathRole: role, sourceDigest: sourceDigest(source) },
      { action: 'delete-path', index: 1, path: 'capabilities/semantic-model-compilation/mode-directory', pathRole: role, sourceDigest: sourceDigest(directory) },
      {
        action: 'write-file', artefactFamily: family, content: 'replacement\n', contentDigest: digest('replacement\n'),
        contentEncoding: 'utf8', index: 2, path: 'capabilities/semantic-model-compilation/blocker.js', pathRole: role,
        representationFormat: format, sourceDigest: digest('stale bytes\n'),
      },
    ] });
    await assert.rejects(() => applyLayoutPlan(ctx, { plan, apply: true }), /source digest mismatch/);
    assert.equal(lstatSync(source).isFile(), true);
    assert.equal(readFileSync(source, 'utf8'), 'exact prior bytes\n');
    assert.equal(lstatSync(source).mode & 0o7777, 0o640);
    assert.equal(lstatSync(directory).isDirectory(), true);
    assert.equal(lstatSync(directory).mode & 0o7777, 0o711);
    assert.equal(readFileSync(blocker, 'utf8'), 'concurrent bytes\n');
  } finally { rmSync(root, { recursive: true, force: true }); }
});


// The hermetic test runtime forbids symlink creation entirely (Node
// --permission grants no global fs.write), and its snapshot builder rejects
// symbolic links, so the traversal attack is structurally excluded there.
// Assert that stronger runtime guarantee explicitly when fixture symlinks
// cannot exist; otherwise exercise the gateway rejection directly.
function fixtureSymlink(target, path) {
  try {
    symlinkSync(target, path, 'dir');
    return true;
  } catch (error) {
    if (error.code !== 'ERR_ACCESS_DENIED' || !process.permission) throw error;
    assert.equal(process.permission.has('fs.write'), false);
    return false;
  }
}

test('materialiser rejects symbolic-link traversal for repository and CAS paths', async () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-materialise-symlink-'));
  const outside = mkdtempSync(join(tmpdir(), 'usf-materialise-outside-'));
  try {
    mkdirSync(join(root, 'capabilities'), { recursive: true });
    if (!fixtureSymlink(outside, join(root, 'capabilities/semantic-model-compilation'))) return;
    const ctx = { client: fakeClient(), repositoryRoot: root, coordinator: true };
    const content = 'export const escaped = true;\n';
    const plan = await createLayoutPlan(ctx, { operations: [{
      action: 'write-file', artefactFamily: family, content, contentDigest: digest(content),
      contentEncoding: 'utf8', index: 0, path: 'capabilities/semantic-model-compilation/escaped.js',
      pathRole: role, representationFormat: format,
    }] });
    await assert.rejects(() => applyLayoutPlan(ctx, { plan, apply: true }), /traverses a symbolic link/);
    assert.equal(existsSync(join(outside, 'src/escaped.js')), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});

test('rollback failures preserve the primary error and every undo error', () => {
  const primary = new Error('primary');
  assert.throws(
    () => materialisationInternals.rethrowWithRollback(primary, [() => { throw new Error('undo'); }]),
    (error) => error instanceof AggregateError
      && error.errors[0] === primary
      && error.errors[1].message === 'undo'
      && error.cause === primary,
  );
});

test('bounded plans may reference exact write bytes from the operator-local CAS', async () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-materialise-cas-'));
  const casRoot = mkdtempSync(join(tmpdir(), 'usf-materialise-content-'));
  try {
    const content = Buffer.alloc(70_000, 7);
    const contentDigest = digest(content);
    const hex = contentDigest.slice(7);
    const stored = join(casRoot, 'sha256', hex.slice(0, 2), hex);
    mkdirSync(join(casRoot, 'sha256', hex.slice(0, 2)), { recursive: true });
    writeFileSync(stored, content);
    const ctx = { client: fakeClient(), repositoryRoot: root, coordinator: true, casRoot };
    const plan = await createLayoutPlan(ctx, { operations: [{
      action: 'write-file', artefactFamily: family, contentDigest,
      contentLocator: `cas://sha256/${hex}`, fileMode: '0644', index: 0,
      path: 'capabilities/semantic-model-compilation/large.js', pathRole: role, representationFormat: format,
    }] });
    assert.ok(Buffer.byteLength(JSON.stringify(plan)) < 65_536);
    assert.equal((await applyLayoutPlan(ctx, { plan, apply: true })).applied, true);
    assert.deepEqual(readFileSync(join(root, 'capabilities/semantic-model-compilation/large.js')), content);
    writeFileSync(stored, 'tampered');
    const otherRoot = mkdtempSync(join(tmpdir(), 'usf-materialise-content-tamper-'));
    try {
      await assert.rejects(() => applyLayoutPlan({ ...ctx, repositoryRoot: otherRoot }, { plan, apply: true }), /content digest mismatch/);
    } finally { rmSync(otherRoot, { recursive: true, force: true }); }
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(casRoot, { recursive: true, force: true });
  }
});

test('move and delete operations require exact source digests', async () => {
  const ctx = { client: fakeClient() };
  const bad = await createLayoutPlan(ctx, { operations: [{ action: 'move-path', index: 0, path: 'capabilities/semantic-model-compilation/next', pathRole: role, sourcePath: 'compiler' }] }).catch((error) => error);
  assert.match(bad.message, /operation-source-digest/);
});

test('plans reject root-role descendants, forbidden segments and family naming violations', async () => {
  const rootRole = 'urn:usf:pathrole:repositoryroot';
  const rootFamily = 'urn:usf:artefactfamily:repositorydocumentation';
  const rootFormat = 'urn:usf:representationformat:markdown';
  const client = fakeClient();
  const originalSelect = client.select;
  client.select = async (query) => {
    if (query.includes('COUNT(*) AS ?count')) return [{ count: binding('1') }];
    if (query.includes('a <urn:usf:ontology:PathRole>')) return [{ role: binding(rootRole), canonicalName: binding('repositoryroot'), parent: binding('.'), onDemand: binding('true') }];
    if (query.includes('a <urn:usf:ontology:ArtefactFamily>')) return [{ family: binding(rootFamily), familyName: binding('repositorydocumentation'), storage: binding('urn:usf:storageclass:gittrackedsource'), pathRole: binding(rootRole), format: binding(rootFormat), namingPattern: binding('^[A-Za-z0-9._-]+$') }];
    return originalSelect(query);
  };
  const make = (path) => createLayoutPlan({ client }, { operations: [{ action: 'write-file', artefactFamily: rootFamily, content: '# x\n', contentDigest: digest('# x\n'), contentEncoding: 'utf8', index: 0, path, pathRole: rootRole, representationFormat: rootFormat }] });
  await assert.rejects(() => make('docs/README.md'), /operation-root-descendant/);
  await assert.rejects(() => make('v2/README.md'), /operation-path/);
  await assert.rejects(() => make('bad name.md'), /operation-filename/);
});

test('operator-local CAS verification checks Stardog digest and byte size', async () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-cas-'));
  try {
    const bytes = Buffer.from('immutable evidence');
    const contentDigest = digest(bytes);
    const hex = contentDigest.slice(7);
    const path = join(root, 'sha256', hex.slice(0, 2), hex);
    mkdirSync(join(root, 'sha256', hex.slice(0, 2)), { recursive: true });
    writeFileSync(path, bytes);
    const descriptor = {
      id: 'urn:usf:externalpayloaddescriptor:test', family, format,
      mediaType: 'application/octet-stream', byteSize: String(bytes.length),
      locator: `cas://sha256/${hex}`, artifactType: 'urn:usf:artefacttype:test',
      storageClass: 'urn:usf:storageclass:contentaddressedobjectstorage',
    };
    const result = await verifyArtifact({ client: fakeClient({ descriptor }), casRoot: root }, { digest: contentDigest });
    assert.equal(result.verified, true);
    const external = join(root, 'external-object');
    writeFileSync(external, bytes);
    unlinkSync(path);
    if (fixtureSymlink(external, path)) {
      const symlinked = await verifyArtifact({ client: fakeClient({ descriptor }), casRoot: root }, { digest: contentDigest });
      assert.equal(symlinked.verified, false);
      assert.equal(symlinked.code, 'artifact-not-regular-file');
      unlinkSync(path);
    }
    writeFileSync(path, 'mutated');
    assert.equal((await verifyArtifact({ client: fakeClient({ descriptor }), casRoot: root }, { digest: contentDigest })).verified, false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('direct lifecycle mutation is always refused at the agent MCP boundary', () => {
  assert.throws(() => refuseLifecycleMutation('usf.evidence.admit'), /compiler.*single transaction/);
});

test('source digests distinguish exact file and deterministic tree state', () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-source-digest-'));
  try {
    writeFileSync(join(root, 'a'), 'one');
    const first = sourceDigest(root);
    writeFileSync(join(root, 'a'), 'two');
    assert.notEqual(sourceDigest(root), first);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
