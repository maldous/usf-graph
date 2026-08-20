import assert from 'node:assert/strict';
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';

import { DataFactory, Parser, Store } from 'n3';

import { canonicalInventoryGraphDigest } from '../../capabilities/semantic-model-compilation/compiler.mjs';
import { censusFamilies, familyRegistry } from '../../assurance/permutation-closure/family-census.mjs';

import {
  ACTION_STATES, applyLayoutPlan, AUTHORITY_MOVED_CODE, createLayoutPlan, digest, GAP_DISPOSITIONS,
  layoutContext, materialisationInternals, realisationVerdict, REALISATION_STATE_FAILURE_CODES,
  refuseLifecycleMutation, planWork, projectContract, sourceDigest, stableAuthorityRead,
  validateLayoutPlan, verifyArtifact,
} from './repository-materialisation-gateway.mjs';

// Preterminal gateway behaviour is asserted under an EXPLICIT V1 owner.
// The owner boundary refuses when it cannot observe ownership, so a test that
// omitted the observer would be asserting against UNRESOLVED, not against V1.
// Ownership is DECLARED by every test. There is deliberately no shared default
// that means V1: that would recreate the implicit "V1 test universe" the native
// V2 transition exists to remove.
//
// BAU_TERMINAL_OWNER is the terminal native V2 owner and is what
// ownership-irrelevant assertions run under -- the state the system will
// actually be in. BAU_TERMINAL_OWNER is an exceptional, named fixture used
// ONLY by tests whose scenario is genuinely pre-terminal V1 behaviour, and it
// is retired together with V1.
const BAU_TERMINAL_OWNER = async () => ({
  ownership_state: 'V2_TERMINAL_OWNER',
  authority_digest: `sha256:${'a'.repeat(64)}`,
  observation_identity_digest: `sha256:${'1'.repeat(64)}`,
  // A terminal observation carries the complete native validation-currentness
  // head. It is the execution scope's anchor, so an incomplete head must fail
  // closed rather than yield a scope with no current warrant.
  validation_currentness: {
    state: 'CURRENT',
    digest: `sha256:${'2'.repeat(64)}`,
    proof_result_digest: `sha256:${'3'.repeat(64)}`,
    evidence_set_digest: `sha256:${'4'.repeat(64)}`,
    semantic_scope_digest: `sha256:${'5'.repeat(64)}`,
    admission_receipt_digest: `sha256:${'6'.repeat(64)}`,
    source: 'HANDOVER_GENESIS',
  },
});
const V1_TRANSITION_OWNER = async () => ({ ownership_state: 'V1_OWNER' });


const { namedNode } = DataFactory;
const contract = 'urn:usf:semanticcontract:repositoryexternalartefactmaterialisation';
const family = 'urn:usf:artefactfamily:compiler';
const format = 'urn:usf:representationformat:ecmascriptmodule';
const jsonFormat = 'urn:usf:representationformat:json';
const markdownFormat = 'urn:usf:representationformat:markdown';
const role = 'urn:usf:pathrole:compilersource';
const compilerContract = 'urn:usf:semanticcontract:compilersemanticenforcement';
const compilerDecision = 'urn:usf:realisationdecision:semanticmodelcompilationrealisation';
const authorityDecision = 'urn:usf:realisationdecision:semanticauthoritycontrolselection';
const materialisationDecision = 'urn:usf:realisationdecision:repositoryexternalartefactmaterialisation';
const decisionFormatPredicate = 'urn:usf:ontology:authorisesRepresentationFormat';

const roots = [];
test.after(() => roots.forEach((root) => rmSync(root, { recursive: true, force: true })));

function binding(value) { return { value }; }
async function git(root, args, options = {}) {
  const { execFileSync } = await import('node:child_process');
  return execFileSync('git', ['-C', root, ...args], {
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...options,
  }).trim();
}

async function initialiseRepository(root) {
  await git(root, ['init', '-q']);
  await git(root, ['config', 'user.name', 'USF Test']);
  await git(root, ['config', 'user.email', 'usf-test@example.invalid']);
  writeFileSync(join(root, 'README.md'), 'authority-conflict predecessor\n');
  await git(root, ['add', 'README.md']);
  await git(root, ['commit', '-q', '-m', 'predecessor']);
  return { head: await git(root, ['rev-parse', 'HEAD']), tree: await git(root, ['rev-parse', 'HEAD^{tree}']) };
}

async function successorTreeForWrite(root, path, content) {
  const temporary = mkdtempSync(join(tmpdir(), 'usf-test-index-'));
  const indexPath = join(temporary, 'index');
  const target = join(root, path);
  const env = { ...process.env, GIT_INDEX_FILE: indexPath };
  try {
    mkdirSync(join(target, '..'), { recursive: true });
    writeFileSync(target, content);
    await git(root, ['read-tree', 'HEAD'], { env });
    await git(root, ['add', '-A', '--', '.'], { env });
    return await git(root, ['write-tree'], { env });
  } finally {
    rmSync(join(root, path.split('/')[0]), { recursive: true, force: true });
    rmSync(temporary, { recursive: true, force: true });
  }
}
function materialisationRule(representationFormat = format) {
  return {
    family: binding(family),
    familyName: binding('compiler'),
    storage: binding('urn:usf:storageclass:gittrackedsource'),
    pathRole: binding(role),
    format: binding(representationFormat),
    namingPattern: binding('^[A-Za-z0-9._-]+$'),
  };
}
function defaultContractRows() {
  return [{
    canonicalName: binding('repositoryexternalartefactmaterialisation'),
    lifecycle: binding('urn:usf:semanticlifecyclestate:active'),
    activation: binding('urn:usf:contractactivationstate:active'),
    proof: binding('urn:usf:proofresult:repositoryexternalartefactmaterialisation'),
    proofState: binding('urn:usf:proofresultstate:successful'),
    decision: binding(materialisationDecision),
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
const AUTHORITY_NQUADS = '<urn:s> <urn:p> "materialisation" .\n';
const authorityGraphDependencyDigest = (await canonicalInventoryGraphDigest('urn:g', AUTHORITY_NQUADS)).sha256;
const validationDependency = () => materialisationInternals
  .validationNonPublicationDependencyDigest([{
    dependencySha256: authorityGraphDependencyDigest,
    graph: 'urn:g',
    triples: 1,
  }]);

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

const durableFamilyValidations = Object.freeze([
  {
    id: 'urn:usf:validationobligation:operationexpectedoutcomeerrorclass',
    family: 'urn:usf:permutationfamily:operationexpectedoutcomeerrorclass',
  },
  {
    id: 'urn:usf:validationobligation:resourceactionretentionstatelegalholdstate',
    family: 'urn:usf:permutationfamily:resourceactionretentionstatelegalholdstate',
  },
  {
    id: 'urn:usf:validationobligation:scheduledjobactionroleserviceidentityenvironmentclass',
    family: 'urn:usf:permutationfamily:scheduledjobactionroleserviceidentityenvironmentclass',
  },
]);

function durableFamilyValidationRows({ conditionMatched = true, satisfaction = null } = {}) {
  return durableFamilyValidations.flatMap(({ id, family }) => [family, 'urn:usf:artefact:permutationfamilysource'].map((evidence) => ({
    id: binding(id),
    activation: binding('urn:usf:validationactivationstate:activated'),
    definition: binding(`read-only analysis objective for ${family}`),
    activationReason: binding(`live defect condition for ${family}`),
    target: binding(family),
    defectEvidence: binding(evidence),
    ownerPath: binding('semantic-model/permutation/families.trig'),
    ...(conditionMatched ? { conditionMatched: binding('true') } : {}),
    ...(satisfaction ? {
      ...satisfaction,
      satisfaction: binding(`${id}:result`),
      boundObligation: binding(id),
    } : {}),
  })));
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

const validationClosure = Object.freeze({
  result: 'urn:usf:validationresult:materialisation',
  binding: 'urn:usf:validationauthoritybinding:materialisation',
  producer: 'urn:usf:validationproducer:materialisation',
  admissionPath: 'urn:usf:evidenceadmissionpath:materialisation',
  evaluation: 'urn:usf:validationevaluation:materialisation',
  execution: 'urn:usf:validationexecution:materialisation',
  evidence: 'urn:usf:validationevidence:materialisation',
  priorAuthority: `sha256:${'76'.repeat(32)}`,
  evaluatedAuthority: `sha256:${'77'.repeat(32)}`,
  executionReceipt: `sha256:${'88'.repeat(32)}`,
  evaluationReceipt: `sha256:${'99'.repeat(32)}`,
  dependency: validationDependency(),
  algorithm: 'sha256-rdfc10-nonpublication-graph-inventory-v1',
  release: 'urn:usf:validationproducerrelease:materialisation-v1',
  repository: 'maldous/usf-graph',
  head: 'a'.repeat(40),
  tree: 'b'.repeat(40),
  scope: `sha256:${'cc'.repeat(32)}`,
});

function selfPublicationClosureRow(overrides = {}) {
  const row = {
    ...satisfyingResultRow({ result: validationClosure.result, boundAuthority: validationClosure.evaluatedAuthority }),
    binding: binding(validationClosure.binding),
    bindingResult: binding(validationClosure.result),
    bindingRule: binding('urn:usf:authoritybindingrule:validationnonpublicationdependencyclosure'),
    reevaluationRequired: binding('true'),
    reevaluationState: binding('urn:usf:resultstate:passed'),
    stageOneEvaluated: binding(validationClosure.priorAuthority),
    stageOneSettled: binding(validationClosure.evaluatedAuthority),
    nonPublicationDependency: binding(validationClosure.dependency),
    dependencyAlgorithm: binding(validationClosure.algorithm),
    reevaluationDependency: binding(validationClosure.dependency),
    bindingExecutionReceipt: binding(validationClosure.executionReceipt),
    bindingEvaluationReceipt: binding(validationClosure.evaluationReceipt),
    bindingProducer: binding(validationClosure.producer),
    bindingAdmissionPath: binding(validationClosure.admissionPath),
    bindingProducerRelease: binding(validationClosure.release),
    bindingRepository: binding(validationClosure.repository),
    bindingSourceHead: binding(validationClosure.head),
    bindingSourceTree: binding(validationClosure.tree),
    bindingSourceScope: binding(validationClosure.scope),
    evaluation: binding(validationClosure.evaluation),
    evaluationReceipt: binding(validationClosure.evaluationReceipt),
    execution: binding(validationClosure.execution),
    executionReceipt: binding(validationClosure.executionReceipt),
    executionProducer: binding(validationClosure.producer),
    executionAdmissionPath: binding(validationClosure.admissionPath),
    evidence: binding(validationClosure.evidence),
    evidenceType: binding('true'),
    evidenceExecution: binding(validationClosure.execution),
    evidenceAdmissionPath: binding(validationClosure.admissionPath),
    producerRelease: binding(validationClosure.release),
    producerRepository: binding(validationClosure.repository),
    producerSourceHead: binding(validationClosure.head),
    producerSourceTree: binding(validationClosure.tree),
    producerSourceScope: binding(validationClosure.scope),
    admissionProducer: binding(validationClosure.producer),
    admissionRepository: binding(validationClosure.repository),
    admissionSourceHead: binding(validationClosure.head),
    admissionSourceTree: binding(validationClosure.tree),
    admissionSourceScope: binding(validationClosure.scope),
  };
  return { ...row, ...overrides };
}

const crossValidationClosure = Object.freeze({
  ...validationClosure,
  admissionRepository: 'maldous/usf-graph',
  admissionHead: 'c'.repeat(40),
  admissionTree: 'd'.repeat(40),
  admissionScope: `sha256:${'ab'.repeat(32)}`,
  producerRepository: 'maldous/usf-factory',
  settledAuthority: `sha256:${'78'.repeat(32)}`,
  reevaluation: 'urn:usf:postpublicationreevaluation:materialisation',
  reevaluationExecutionReceipt: `sha256:${'12'.repeat(32)}`,
  reevaluationEvaluationReceipt: `sha256:${'13'.repeat(32)}`,
});
const crossProducerPaths = Object.freeze(['src/usf_factory/provider_plane_runtime.py',
  'tests/test_v3_provider_refresh_authority.py']);
const crossAdmissionPaths = Object.freeze(['processes/semantic-assurance/semantic-authority-publication.mjs',
  'semantic-model/assurance/evidence.trig']);

function crossRepositorySelfPublicationClosureRow(overrides = {}) {
  const row = {
    ...satisfyingResultRow({
      result: crossValidationClosure.result,
      boundAuthority: crossValidationClosure.priorAuthority,
      boundHead: crossValidationClosure.head,
    }),
    binding: binding(crossValidationClosure.binding),
    bindingResult: binding(crossValidationClosure.result),
    bindingRule: binding('urn:usf:authoritybindingrule:validationcrossrepositorynonpublicationclosure'),
    reevaluationRequired: binding('true'),
    reevaluationState: binding('urn:usf:resultstate:passed'),
    stageOneEvaluated: binding(crossValidationClosure.evaluatedAuthority),
    stageOneSettled: binding(crossValidationClosure.settledAuthority),
    nonPublicationDependency: binding(crossValidationClosure.dependency),
    dependencyAlgorithm: binding(crossValidationClosure.algorithm),
    reevaluationDependency: binding(crossValidationClosure.dependency),
    bindingExecutionReceipt: binding(crossValidationClosure.executionReceipt),
    bindingEvaluationReceipt: binding(crossValidationClosure.evaluationReceipt),
    bindingProducer: binding(crossValidationClosure.producer),
    bindingAdmissionPath: binding(crossValidationClosure.admissionPath),
    bindingProducerRelease: binding(crossValidationClosure.release),
    bindingProducerRepository: binding(crossValidationClosure.producerRepository),
    bindingProducerSourceHead: binding(crossValidationClosure.head),
    bindingProducerSourceTree: binding(crossValidationClosure.tree),
    bindingProducerSourceScope: binding(crossValidationClosure.scope),
    bindingAdmissionRepository: binding(crossValidationClosure.admissionRepository),
    bindingAdmissionSourceHead: binding(crossValidationClosure.admissionHead),
    bindingAdmissionSourceTree: binding(crossValidationClosure.admissionTree),
    bindingAdmissionSourceScope: binding(crossValidationClosure.admissionScope),
    bindingReevaluation: binding(crossValidationClosure.reevaluation),
    reevaluatesValidationResult: binding(crossValidationClosure.result),
    reevaluationAuthority: binding(crossValidationClosure.settledAuthority),
    reevaluationResultState: binding('urn:usf:resultstate:passed'),
    reevaluationExecutionReceipt: binding(crossValidationClosure.reevaluationExecutionReceipt),
    reevaluationEvaluationReceipt: binding(crossValidationClosure.reevaluationEvaluationReceipt),
    evaluation: binding(crossValidationClosure.evaluation),
    evaluationReceipt: binding(crossValidationClosure.evaluationReceipt),
    execution: binding(crossValidationClosure.execution),
    executionReceipt: binding(crossValidationClosure.executionReceipt),
    executionProducer: binding(crossValidationClosure.producer),
    executionAdmissionPath: binding(crossValidationClosure.admissionPath),
    evidence: binding(crossValidationClosure.evidence),
    evidenceType: binding('true'),
    evidenceExecution: binding(crossValidationClosure.execution),
    evidenceAdmissionPath: binding(crossValidationClosure.admissionPath),
    producerRelease: binding(crossValidationClosure.release),
    producerRepository: binding(crossValidationClosure.producerRepository),
    producerSourceHead: binding(crossValidationClosure.head),
    producerSourceTree: binding(crossValidationClosure.tree),
    producerSourceScope: binding(crossValidationClosure.scope),
    admissionProducer: binding(crossValidationClosure.producer),
    admissionRepository: binding(crossValidationClosure.admissionRepository),
    admissionSourceHead: binding(crossValidationClosure.admissionHead),
    admissionSourceTree: binding(crossValidationClosure.admissionTree),
    admissionSourceScope: binding(crossValidationClosure.admissionScope),
  };
  return { ...row, ...overrides };
}

function crossRepositoryPathRows({ omit = null } = {}) {
  const groups = [
    ['bindingProducerSourcePath', crossProducerPaths],
    ['producerSourcePath', crossProducerPaths],
    ['bindingAdmissionSourcePath', crossAdmissionPaths],
    ['admissionSourcePath', crossAdmissionPaths],
  ];
  return groups.flatMap(([field, paths]) => paths.map((path, index) => ({
    field: binding(field),
    id: binding(validationObligation),
    path: binding(path),
    satisfaction: binding(crossValidationClosure.result),
    omitted: omit === `${field}:${index}`,
  }))).filter((row) => !row.omitted).map(({ omitted, ...row }) => row);
}

// A complete, agreeing currentness chain. Every gateway test that is not about
// currentness needs one, because PROCEED now requires the positive conclusion
// and not merely a successful historical result.
const CURRENT_ALGORITHM = 'urn:usf:proofalgorithm:repositorymaterialisationcontrolplane';
const CURRENT_VERSION = 'urn:usf:proofalgorithmversion:current';
const CURRENT_SOURCE_DIGEST = `sha256:${'11'.repeat(32)}`;
const CURRENT_IMPLEMENTATION = `sha256:${'22'.repeat(32)}`;
const CURRENT_DEPENDENCY = `sha256:${'33'.repeat(32)}`;
const DEPENDENCY_ALGORITHM = 'sha256-rdfc10-nonpublication-graph-inventory-v1';
const CURRENT_RESULT = 'urn:usf:proofresult:repositorymaterialisationcontrolplane';

function defaultCurrentness(overrides = {}) {
  const base = {
    mandatory: [{ obligation: binding('urn:usf:proofobligation:repositoryexternalartefactmaterialisation') }],
    result: [{
      result: binding(CURRENT_RESULT),
      state: binding('urn:usf:proofresultstate:successful'),
      obligation: binding('urn:usf:proofobligation:repositoryexternalartefactmaterialisation'),
      proof: binding('urn:usf:proof:repositorymaterialisationcontrolplane'),
      algorithm: binding(CURRENT_ALGORITHM),
      algorithmVersion: binding(CURRENT_VERSION),
      evidenceSetDigest: binding(`sha256:${'44'.repeat(32)}`),
      implementationDigest: binding(CURRENT_IMPLEMENTATION),
      dependencyDigest: binding(CURRENT_DEPENDENCY),
      dependencyAlgorithm: binding(DEPENDENCY_ALGORITHM),
      binding: binding('urn:usf:proofauthoritybinding:repositorymaterialisationcontrolplane'),
      evidence: binding('urn:usf:evidenceresult:repositorymaterialisationcontrolplane'),
    }],
    evidence: [{
      result: binding(CURRENT_RESULT),
      evidence: binding('urn:usf:evidenceresult:repositorymaterialisationcontrolplane'),
      admission: binding('urn:usf:evidenceadmissionstate:admitted'),
      freshness: binding('urn:usf:evidencefreshnessstate:fresh'),
      integrity: binding('urn:usf:evidenceintegritystate:valid'),
      withinScope: binding('true'),
      validUntil: binding('2099-01-01T00:00:00Z'),
      contentDigest: binding(`sha256:${'55'.repeat(32)}`),
    }],
    algorithm: [{
      result: binding(CURRENT_RESULT),
      algorithm: binding(CURRENT_ALGORITHM),
      sourceDigest: binding(CURRENT_SOURCE_DIGEST),
      currentSourceDigest: binding(CURRENT_SOURCE_DIGEST),
      currentVersion: binding(CURRENT_VERSION),
      currentImplementation: binding(CURRENT_IMPLEMENTATION),
      currentDependency: binding(CURRENT_DEPENDENCY),
      currentDependencyAlgorithm: binding(DEPENDENCY_ALGORITHM),
    }],
    binding: [{
      result: binding(CURRENT_RESULT),
      binding: binding('urn:usf:proofauthoritybinding:repositorymaterialisationcontrolplane'),
      rule: binding('urn:usf:authoritybindingrule:selfpublicationclosure'),
      requiresReevaluation: binding('true'),
      reevaluationState: binding('urn:usf:proofreevaluationstate:successful'),
      evaluatedDigest: binding(`sha256:${'66'.repeat(32)}`),
      settledDigest: binding(witnessDigest),
      reevaluationDependency: binding(CURRENT_DEPENDENCY),
      bindingDependency: binding(CURRENT_DEPENDENCY),
      bindingDependencyAlgorithm: binding(DEPENDENCY_ALGORITHM),
    }],
  };
  return { ...base, ...overrides };
}

function pluralCurrentness() {
  const base = defaultCurrentness();
  const result = 'urn:usf:proofresult:factoryproviderv3implementation';
  const obligation = 'urn:usf:proofobligation:factoryproviderv3implementation';
  const algorithm = 'urn:usf:proofalgorithm:factoryproviderv3implementation';
  const evidence = 'urn:usf:evidenceresult:factoryproviderv3implementation';
  const authorityBinding = 'urn:usf:proofauthoritybinding:factoryproviderv3implementation';
  return {
    mandatory: [...base.mandatory, { obligation: binding(obligation) }],
    result: [...base.result, {
      ...base.result[0],
      result: binding(result),
      obligation: binding(obligation),
      proof: binding('urn:usf:proof:factoryproviderv3implementation'),
      algorithm: binding(algorithm),
      evidence: binding(evidence),
      binding: binding(authorityBinding),
    }],
    evidence: [...base.evidence, {
      ...base.evidence[0],
      result: binding(result),
      evidence: binding(evidence),
    }],
    algorithm: [...base.algorithm, {
      ...base.algorithm[0],
      result: binding(result),
      algorithm: binding(algorithm),
    }],
    binding: [...base.binding, {
      ...base.binding[0],
      result: binding(result),
      binding: binding(authorityBinding),
    }],
  };
}

function fakeClient({
  descriptor,
  contractRows = defaultContractRows(),
  decisionFormatRows = [{ format: binding(format) }],
  decisionFormatCountRows = null,
  ruleRows = [materialisationRule()],
  applicabilityRows = defaultApplicabilityRows(),
  validationObligationRows = defaultValidationObligationRows(),
  validationEvidenceRows = [],
  validationPathRows = [],
  proofGapRows = [],
  currentness = defaultCurrentness(),
  authorityNQuads = AUTHORITY_NQUADS,
  authorityConflictSurfaceRows = [],
  authorityConflictResolutionRows = [],
  authorityConflictSetRows = [],
  queries = [],
} = {}) {
  return {
    size: async () => 10,
    construct: async () => authorityNQuads,
    select: async (query) => {
      queries.push(query);
      if (query.includes('SELECT DISTINCT ?surfaceContract ?authorisedPath ?authorisedFormat')) return authorityConflictSurfaceRows;
      if (query.includes('SELECT ?resolution ?conflict ?resolutionState ?decisionState')) return authorityConflictResolutionRows;
      if (query.includes('SELECT ?resolution ?kind ?item')) return authorityConflictSetRows;
      if (query.includes(`<${decisionFormatPredicate}>`)) {
        if (query.includes('COUNT(DISTINCT ?format) AS ?count')) {
          return decisionFormatCountRows ?? [{ count: binding(String(decisionFormatRows.length)) }];
        }
        return decisionFormatRows;
      }
      if (query.includes('COUNT(*) AS ?count')) return [{ count: binding(String(ruleRows.length)) }];
      if (query.includes('SELECT DISTINCT ?g')) return [{ g: binding('urn:g') }];
      if (query.includes('?canonicalName ?lifecycle')) return contractRows;
      if (query.includes('<urn:usf:ontology:hasValidationApplicability> ?state')) return applicabilityRows;
      if (query.includes('BIND("bindingSourcePath" AS ?field)')) return validationPathRows;
      if (query.includes('?evidence a <urn:usf:ontology:ValidationEvidence>')) return validationEvidenceRows;
      if (query.includes('a <urn:usf:ontology:ValidationObligation>')) return validationObligationRows;
      if (query.includes('<urn:usf:ontology:mandatoryProofObligation> ?subject')) return proofGapRows;
      if (query.includes('<urn:usf:ontology:mandatoryProofObligation> ?obligation')) return currentness.mandatory;
      if (query.includes('?implementationDigest ?dependencyDigest')) return currentness.result;
      if (query.includes('?evidence ?admission ?freshness')) return currentness.evidence;
      if (query.includes('?currentSourceDigest ?currentVersion')) return currentness.algorithm;
      if (query.includes('?requiresReevaluation ?reevaluationState')) return currentness.binding;
      if (query.includes('a <urn:usf:ontology:PathRole>')) return [{ role: binding(role), canonicalName: binding('compilersource'), parent: binding('capabilities/semantic-model-compilation'), onDemand: binding('true') }];
      if (query.includes('a <urn:usf:ontology:ArtefactFamily>')) return ruleRows;
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
  const context = await layoutContext({ client: fakeClient(), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER });
  assert.match(context.authorityDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(context.authorityDigestAlgorithm, 'sha256-rdfc10-graph-inventory-v2');
  assert.deepEqual(context.authorityGraphInventory, [{
    dependencySha256: context.authorityGraphInventory[0].dependencySha256,
    graph: 'urn:g',
    sha256: context.authorityGraphInventory[0].sha256,
    triples: 1,
  }]);
  assert.match(context.authorityGraphInventory[0].sha256, /^sha256:[0-9a-f]{64}$/);
  assert.match(context.authorityGraphInventory[0].dependencySha256, /^sha256:[0-9a-f]{64}$/);
  assert.equal(context.contract.activationState, 'urn:usf:contractactivationstate:active');
  assert.equal(context.contract.proofResultState, 'urn:usf:proofresultstate:successful');
  assert.equal(context.acceptedDecisionCount, 1);
  assert.equal(context.decisionResolution, 'unique-accepted');
  assert.deepEqual(context.authorisedRepositories, ['usf']);
  assert.deepEqual(context.authorisedPaths, ['capabilities/semantic-model-compilation']);
  assert.deepEqual(context.authorisedFormats, [format]);
});

test('contract packet projects the selected decision exact representation-format set', async () => {
  const packet = await projectContract({
    client: fakeClient({
      decisionFormatRows: [{ format: binding(jsonFormat) }, { format: binding(format) }],
    }), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
  assert.deepEqual(packet.authorisedFormats, [format, jsonFormat]);
});

test('contract packet projects an exact two-proof two-obligation conjunction without collapsing it', async () => {
  const currentness = pluralCurrentness();
  const contractRows = currentness.result.map((item) => ({
    ...defaultContractRows()[0],
    proof: item.result,
    proofState: item.state,
  }));
  const packet = await projectContract({
    client: fakeClient({ contractRows, currentness }), observeGraphRuntimeOwnership: V1_TRANSITION_OWNER }, { contract });
  assert.equal(packet.actionState, ACTION_STATES.proceed);
  assert.equal(packet.proofCurrentness.state, 'CURRENT');
  assert.equal(packet.proofCurrentness.proofResults.length, 2);
  assert.equal(packet.proofCurrentness.mandatoryObligations.length, 2);
  assert.equal(packet.proofCurrentness.obligationProofResults.length, 2);
  assert.equal(packet.proofCurrentness.perProof.length, 2);
  assert.deepEqual(
    packet.proofCurrentness.proofResults,
    packet.proofCurrentness.perProof.map((item) => item.proofResult),
  );
  assert.ok(packet.proofCurrentness.proofResults.includes(packet.executionScope.currentProofIri));
  assert.equal(
    packet.executionScope.scopeCore.obligationIri,
    packet.proofCurrentness.obligationProofResults[0].obligation,
  );
});

test('global materialisation-rule formats do not leak into decision authority', async () => {
  const client = fakeClient({
    ruleRows: [materialisationRule(), materialisationRule(markdownFormat)],
  });
  const packet = await projectContract({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
  assert.deepEqual(packet.authorisedFormats, [format]);

  const content = '# globally valid rule, decision-denied format\n';
  await assert.rejects(
    () => createLayoutPlan({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, {
      contract,
      operations: [{
        action: 'write-file',
        artefactFamily: family,
        content,
        contentDigest: digest(content),
        contentEncoding: 'utf8',
        index: 0,
        path: 'capabilities/semantic-model-compilation/value.md',
        pathRole: role,
        representationFormat: markdownFormat,
      }],
    }),
    /operation-decision-representation-format/,
  );
});

test('formats authorised by another accepted decision do not leak into the selected decision', async () => {
  const client = fakeClient({ contractRows: complementaryCompilerRows() });
  const select = client.select;
  const formatQueries = [];
  client.select = async (query) => {
    if (!query.includes(`<${decisionFormatPredicate}>`)) return select(query);
    formatQueries.push(query);
    if (query.includes(`<${compilerDecision}>`)) {
      return query.includes('COUNT(DISTINCT ?format) AS ?count')
        ? [{ count: binding('1') }]
        : [{ format: binding(format) }];
    }
    return query.includes('COUNT(DISTINCT ?format) AS ?count')
      ? [{ count: binding('2') }]
      : [{ format: binding(format) }, { format: binding(markdownFormat) }];
  };

  const context = await layoutContext({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract: compilerContract });
  assert.deepEqual(context.authorisedFormats, [format]);
  assert.equal(formatQueries.length, 2);
  assert.ok(formatQueries.every((query) => query.includes(`<${compilerDecision}>`)));
  assert.ok(formatQueries.every((query) => !query.includes(`<${authorityDecision}>`)));
});

test('a decision with authorised paths and zero representation formats fails closed', async () => {
  await assert.rejects(
    () => layoutContext({
      client: fakeClient({ decisionFormatRows: [] }), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }),
    /authorises source paths but no representation formats/,
  );
});

test('decision representation-format count and row mismatch fails closed', async () => {
  await assert.rejects(
    () => layoutContext({
      client: fakeClient({
        decisionFormatCountRows: [{ count: binding('2') }],
        decisionFormatRows: [{ format: binding(format) }],
      }), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }),
    /representation-format projection is incomplete/,
  );
});

test('more than 256 decision representation formats fails closed', async () => {
  const decisionFormatRows = Array.from({ length: 256 }, (_, index) => ({
    format: binding(`urn:usf:representationformat:test${index}`),
  }));
  await assert.rejects(
    () => layoutContext({
      client: fakeClient({
        decisionFormatCountRows: [{ count: binding('257') }],
        decisionFormatRows,
      }), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }),
    /representation-format projection exceeds 256 items/,
  );
});

test('decision format count and bounded rows are queried after decision resolution without a path join', async () => {
  const client = fakeClient();
  const select = client.select;
  const queries = [];
  client.select = async (query) => {
    queries.push(query);
    return select(query);
  };

  await layoutContext({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER });
  const contractQueryIndex = queries.findIndex((query) => query.includes('?canonicalName ?lifecycle'));
  const formatQueryIndexes = queries
    .map((query, index) => ({ query, index }))
    .filter(({ query }) => query.includes(`<${decisionFormatPredicate}>`));
  assert.equal(formatQueryIndexes.length, 2);
  assert.ok(formatQueryIndexes.every(({ index }) => index > contractQueryIndex));
  assert.ok(formatQueryIndexes.every(({ query }) => query.includes(`<${materialisationDecision}>`)));
  assert.ok(formatQueryIndexes.every(({ query }) => !query.includes('authorisesSourcePath')));
  assert.equal(formatQueryIndexes.filter(({ query }) => query.includes('COUNT(DISTINCT ?format)')).length, 1);
  assert.equal(formatQueryIndexes.filter(({ query }) => query.includes('SELECT DISTINCT ?format')).length, 1);
  assert.ok(formatQueryIndexes.some(({ query }) => query.includes('LIMIT 256')));
  assert.ok(!queries[contractQueryIndex].includes(decisionFormatPredicate));
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

test('authored model contains exactly three durable family validation obligations and one owner artefact', () => {
  const model = authoredModel();
  const activated = namedNode('urn:usf:validationactivationstate:activated');
  const obligationFor = namedNode(`${ONT}obligationFor`);
  const derivedFrom = namedNode(`${ONT}derivedFrom`);
  const expectedIds = durableFamilyValidations.map(({ id }) => id).sort();
  const obligations = model
    .getSubjects(namedNode(`${ONT}hasValidationActivationState`), activated, null)
    .filter((subject) => expectedIds.includes(subject.value))
    .map(({ value }) => value)
    .sort();
  assert.deepEqual(obligations, expectedIds);
  for (const { id, family } of durableFamilyValidations) {
    const subject = namedNode(id);
    assert.deepEqual(model.getObjects(subject, obligationFor, null).map(({ value }) => value), [family]);
    assert.equal(model.has(subject, derivedFrom, namedNode(family), null), true);
    assert.equal(model.has(subject, namedNode(`${ONT}validationForContract`), namedNode(contract), null), true);
  }
  const ownerArtefacts = model
    .getSubjects(namedNode(`${ONT}canonicalPath`), DataFactory.literal('semantic-model/permutation/families.trig'), null)
    .map(({ value }) => value);
  assert.deepEqual(ownerArtefacts, ['urn:usf:artefact:permutationfamilysource']);
  const changedSources = [
    readFileSync(new URL('../../semantic-model/contracts/materialisation.trig', import.meta.url), 'utf8'),
    readFileSync(new URL('./repository-materialisation-gateway.mjs', import.meta.url), 'utf8'),
  ].join('\n');
  assert.ok(!changedSources.includes('validationSubject'));
  assert.ok(!changedSources.includes('family-model-review-observations.tsv'));
});

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

test('applicability admits the exact current checkpoint validation and no exemption or unearned conclusion', () => {
  const model = authoredModel();
  const contracts = [...new Set(model
    .getSubjects(namedNode(RDF_TYPE), namedNode(`${ONT}SemanticContract`), null)
    .map(({ value }) => value))];
  const byState = new Map();
  for (const contract of contracts) {
    const [state] = model.getObjects(namedNode(contract), namedNode(`${ONT}hasValidationApplicability`), null).map(({ value }) => value);
    byState.set(state, [...(byState.get(state) || []), contract]);
  }
  // Nothing may be migrated to exemption, reservation or an unresolved
  // conditional. The checkpoint validation is required only after its exact
  // decision, proof and validation have been made effective together.
  assert.deepEqual(byState.get(`${VAS}notrequired`), undefined);
  assert.deepEqual(byState.get(`${VAS}reserved`), undefined);
  assert.deepEqual(byState.get(`${VAS}conditional`), undefined);

  const backup = namedNode('urn:usf:semanticcontract:backupandrestore');
  const condition = namedNode('urn:usf:validationapplicabilitycondition:backupandrestoreeventhistorycheckpointpruningbecomeseffective');
  assert.deepEqual(model.getObjects(backup, namedNode(`${ONT}validationApplicabilityCondition`), null), []);
  assert.deepEqual(model.getObjects(condition, namedNode(RDF_TYPE), null), []);
  assert.deepEqual(
    model.getObjects(backup, namedNode(`${ONT}requiredValidation`), null).map(({ value }) => value),
    ['urn:usf:validationobligation:backupandrestoreeventhistorycheckpointpruning'],
  );
  assert.deepEqual(
    model.getObjects(backup, namedNode(`${ONT}hasActivationState`), null).map(({ value }) => value),
    ['urn:usf:contractactivationstate:active'],
  );
  assert.deepEqual(
    model.getObjects(backup, namedNode(`${ONT}effectiveRealisationDecision`), null).map(({ value }) => value),
    ['urn:usf:realisationdecision:backupandrestoreeventhistorycheckpointpruning'],
  );
  assert.deepEqual(
    model.getObjects(backup, namedNode(`${ONT}reliesOnProofResult`), null).map(({ value }) => value),
    ['urn:usf:proofresult:eventhistorycheckpointpruning'],
  );

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
  assert.equal((byState.get(`${VAS}required`) || []).length, 7);
  assert.equal((byState.get(`${VAS}unresolved`) || []).length, contracts.length - 7);
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
    client: fakeClient({ contractRows: complementaryCompilerRows() }), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract: compilerContract });
  assert.equal(context.acceptedDecisionCount, 2);
  assert.equal(context.effectiveDecisionCount, 1);
  assert.equal(context.decisionResolution, 'explicit');
  assert.equal(context.contract.decision, compilerDecision);
  assert.equal(context.contract.authorisedRepository, 'maldous/usf-graph');
  assert.deepEqual(context.authorisedRepositories, ['maldous/usf-graph']);
  assert.deepEqual(context.authorisedPaths, ['package.json']);
  const packet = await projectContract({
    client: fakeClient({ contractRows: complementaryCompilerRows() }), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract: compilerContract });
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
    const context = await layoutContext({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract: compilerContract });
    assert.equal(context.decisionResolution, expectedResolution);
    assert.equal(context.contract.decision, null);
    assert.deepEqual(context.authorisedRepositories, []);
    assert.deepEqual(context.authorisedPaths, []);
    const packet = await projectContract({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract: compilerContract });
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
  await assert.rejects(() => layoutContext({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }), /rule projection is incomplete/);
});

test('plans require one accepted decision, its authorised paths, and an exact plan digest', async () => {
  const content = 'export const value = 1;\n';
  const operation = { action: 'write-file', artefactFamily: family, content, contentDigest: digest(content), contentEncoding: 'utf8', index: 0, path: 'capabilities/semantic-model-compilation/value.mjs', pathRole: role, representationFormat: format };
  const plan = await createLayoutPlan({ client: fakeClient(), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract, operations: [operation] });

  const missingDigest = structuredClone(plan);
  delete missingDigest.planDigest;
  assert.ok((await validateLayoutPlan({ client: fakeClient(), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, missingDigest)).failures.some((finding) => finding.code === 'plan-digest'));

  const draftRows = defaultContractRows();
  draftRows[0].decisionState = binding('urn:usf:decisionstate:draft');
  assert.ok((await validateLayoutPlan({ client: fakeClient({ contractRows: draftRows }), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, plan)).failures.some((finding) => finding.code === 'plan-decision-not-uniquely-accepted'));

  const pathlessRows = defaultContractRows();
  delete pathlessRows[0].authorisedPath;
  assert.ok((await validateLayoutPlan({ client: fakeClient({ contractRows: pathlessRows }), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, plan)).failures.some((finding) => finding.code === 'operation-decision-path'));

  const second = { ...defaultContractRows()[0], decision: binding('urn:usf:realisationdecision:other') };
  assert.ok((await validateLayoutPlan({ client: fakeClient({ contractRows: [...defaultContractRows(), second] }), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, plan)).failures.some((finding) => finding.code === 'plan-decision-not-uniquely-accepted'));
});

test('layout plan validates exact content, path role, family, format, digest and authority', async () => {
  const ctx = { client: fakeClient(), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER };
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
  const packet = await projectContract({ client: fakeClient(), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
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
  const packet = await projectContract({ client: fakeClient(), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
  assert.equal(packet.actionState, 'PROCEED');
  assert.deepEqual(packet.actionStateReasons, []);
  assert.ok(packet.authorisedActions.length > 0);
  assert.equal(packet.validationActionState, 'RESERVED_NO_ACTION');
  assert.equal(packet.validationSatisfied, false);
  assert.deepEqual(packet.validationGaps.map((gap) => gap.code), ['validation-obligation-reserved']);
  assert.ok(packet.stopConditions.includes('validationSatisfied is false and the task would claim validation'));
});

test('an activated unsatisfied validation obligation projects only the exact read-only remediation scope', async () => {
  const client = fakeClient({ validationObligationRows: defaultValidationObligationRows('urn:usf:validationactivationstate:activated') });
  const packet = await projectContract({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
  assert.equal(packet.schemaVersion, 3);
  assert.equal(packet.actionState, 'PROCEED');
  assert.deepEqual(packet.actionStateReasons, ['missing-current-passing-validation']);
  assert.deepEqual(packet.authorisedActions, []);
  assert.deepEqual(packet.authorisedPaths, []);
  assert.equal(packet.validationActionState, 'PROCEED');
  assert.equal(packet.validationSatisfied, false);
  assert.equal(packet.executionScope.scopeCore.modeIri, 'urn:usf:executionscopemode:readonlysemanticvalidation');
  assert.equal(packet.executionScope.scopeCore.repositoryMutationPermitted, false);
  assert.equal(packet.executionScope.scopeCore.maximumRepositoryWrites, 0);
  assert.deepEqual(packet.executionScope.scopeCore.writePaths, []);
});

test('exact live family defects produce exactly three bounded read-only work rows', async () => {
  const queries = [];
  const plan = await planWork({ client: fakeClient({
    validationObligationRows: durableFamilyValidationRows(),
    queries,
  }), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
  assert.equal(plan.actionState, 'BLOCK');
  assert.equal(plan.gapCount, 3);
  assert.deepEqual(plan.gaps.map((item) => item.subject), durableFamilyValidations.map(({ id }) => id).sort());
  for (const item of plan.gaps) {
    const expected = durableFamilyValidations.find(({ id }) => id === item.subject);
    assert.equal(item.type, 'missing-current-passing-validation');
    assert.equal(item.disposition, 'BLOCK');
    assert.equal(item.taskClass, 'semantic-planning');
    assert.equal(item.remediationKind, 'ANALYSIS_ONLY');
    assert.equal(item.repository, 'maldous/usf-graph');
    assert.equal(item.materialisationOwnerPath, 'semantic-model/permutation/families.trig');
    assert.equal(item.familySubject, expected.family);
    assert.equal(item.sourceArtefact, 'urn:usf:artefact:permutationfamilysource');
    assert.equal(item.defectCondition, `live defect condition for ${expected.family}`);
    assert.equal(item.analysisObjective, `read-only analysis objective for ${expected.family}`);
    assert.ok(item.defectEvidence.includes(expected.family));
    assert.ok(item.subjects.includes(expected.family));
    assert.ok(item.subjects.includes('urn:usf:artefact:permutationfamilysource'));
    assert.deepEqual(item.decisionIds, ['urn:usf:realisationdecision:repositoryarchitectureandnaming']);
  }
  const validationQuery = queries.find((query) => query.includes('a <urn:usf:ontology:ValidationObligation>'));
  assert.ok(validationQuery);
  for (const { id } of durableFamilyValidations) {
    assert.ok(validationQuery.includes(`BIND(<${id}> AS ?id)`));
    assert.ok(!validationQuery.includes(`FILTER(?id = <${id}>)`));
  }
});

test('corrected source conditions stop remediation scheduling but remain blocked without current results', async () => {
  const plan = await planWork({ client: fakeClient({
    validationObligationRows: durableFamilyValidationRows({ conditionMatched: false }),
  }), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
  assert.equal(plan.actionState, 'BLOCK');
  assert.equal(plan.validationSatisfied, false);
  assert.equal(plan.gapCount, 3);
  assert.ok(plan.gaps.every((item) => item.type === 'missing-current-passing-validation'));
  assert.ok(plan.gaps.every((item) => item.remediationKind === undefined));
});

test('a minimal corrected family with a current passing result produces no work row', async () => {
  const current = satisfyingResultRow();
  const plan = await planWork({ client: fakeClient({
    validationObligationRows: durableFamilyValidationRows({ conditionMatched: false, satisfaction: current }),
  }), observeGraphRuntimeOwnership: V1_TRANSITION_OWNER }, { contract });
  assert.equal(plan.gapCount, 0);
  assert.equal(plan.validationSatisfied, true);
});

test('reintroducing exact faulty triples adds bounded remediation metadata without changing fail-closed satisfaction', async () => {
  const corrected = await planWork({ client: fakeClient({
    validationObligationRows: durableFamilyValidationRows({ conditionMatched: false }),
  }), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
  const reintroduced = await planWork({ client: fakeClient({
    validationObligationRows: durableFamilyValidationRows(),
  }), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
  assert.equal(corrected.gapCount, 3);
  assert.ok(corrected.gaps.every((item) => item.remediationKind === undefined));
  assert.equal(reintroduced.gapCount, 3);
  assert.ok(reintroduced.gaps.every((item) => item.remediationKind === 'ANALYSIS_ONLY'));
  assert.ok(reintroduced.gaps.every((item) => item.disposition === 'BLOCK'));
});

test('a corrected source condition with stale satisfaction remains blocked', async () => {
  const stale = satisfyingResultRow({ boundAuthority: `sha256:${'44'.repeat(32)}` });
  const plan = await planWork({ client: fakeClient({
    validationObligationRows: durableFamilyValidationRows({ conditionMatched: false, satisfaction: stale }),
  }), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
  assert.equal(plan.actionState, 'BLOCK');
  assert.equal(plan.gapCount, 3);
  assert.ok(plan.gaps.every((item) => item.type === 'validation-satisfaction-not-current'));
  assert.ok(plan.gaps.every((item) => item.remediationKind === undefined));
});

test('stale passing results do not satisfy durable family obligations at changed authority', async () => {
  const stale = satisfyingResultRow({ boundAuthority: `sha256:${'44'.repeat(32)}` });
  const plan = await planWork({ client: fakeClient({
    validationObligationRows: durableFamilyValidationRows({ satisfaction: stale }),
  }), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
  assert.equal(plan.gapCount, 3);
  assert.ok(plan.gaps.every((item) => item.type === 'validation-satisfaction-not-current'));
  assert.ok(plan.gaps.every((item) => item.materialisationOwnerPath === 'semantic-model/permutation/families.trig'));
});

test('durable validation work planning rejects a substituted family binding', async () => {
  const rows = durableFamilyValidationRows();
  rows[0] = { ...rows[0], target: binding('urn:usf:permutationfamily:unrelated') };
  await assert.rejects(
    () => planWork({ client: fakeClient({ validationObligationRows: rows }), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract }),
    /has no exact family target/,
  );
});

test('durable family validation query contains exactly the three family-specific live patterns', async () => {
  const client = fakeClient({ validationObligationRows: durableFamilyValidationRows() });
  const select = client.select;
  const queries = [];
  client.select = async (query) => { queries.push(query); return select(query); };
  await planWork({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
  const query = queries.find((item) => item.includes('?conditionMatched'));
  assert.ok(query);
  for (const { id, family } of durableFamilyValidations) {
    assert.ok(query.includes(`<${id}>`));
    assert.ok(query.includes(`<${family}>`));
  }
  assert.ok(query.includes('ValidationFailureCode'));
  assert.ok(query.includes('permutationapplicabilityrule:datamodels'));
  assert.ok(query.includes('permutationapplicabilityrule:workflows'));
  assert.ok(!query.includes('family-model-review-observations.tsv'));
});

test('a fully bound current satisfaction is the only state that reports validation satisfied', async () => {
  const client = fakeClient({
    validationObligationRows: [{
      ...defaultValidationObligationRows('urn:usf:validationactivationstate:activated')[0],
      ...satisfyingResultRow(),
    }],
  });
  const packet = await projectContract({ client, observeGraphRuntimeOwnership: V1_TRANSITION_OWNER }, { contract });
  assert.equal(packet.validationSatisfied, true);
  assert.equal(packet.validationObligations[0].satisfactionCurrent, true);
  assert.deepEqual(packet.validationGaps, []);
  assert.equal(packet.actionState, 'PROCEED');
  const plan = await planWork({ client, observeGraphRuntimeOwnership: V1_TRANSITION_OWNER }, { contract });
  assert.equal(plan.gapCount, 0);
  assert.equal(plan.actionState, 'PROCEED');
  assert.equal(plan.validationSatisfied, true);
  assert.equal(plan.completionClaim, false);
});

test('complete validation self-publication closure is current after its authority transition', async () => {
  const client = fakeClient({
    validationObligationRows: [{
      ...defaultValidationObligationRows('urn:usf:validationactivationstate:activated')[0],
      ...selfPublicationClosureRow(),
    }],
  });
  const packet = await projectContract({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
  assert.equal(packet.validationObligations[0].satisfactionCurrent, true);
  assert.equal(packet.validationSatisfied, true);
  assert.deepEqual(packet.validationGaps, []);
  assert.equal(packet.actionState, 'PROCEED');
});

test('cross-repository validation closure keeps Factory production and Graph admission identities independent', async () => {
  const client = fakeClient({
    validationObligationRows: [{
      ...defaultValidationObligationRows('urn:usf:validationactivationstate:activated')[0],
      ...crossRepositorySelfPublicationClosureRow(),
    }],
    validationPathRows: crossRepositoryPathRows(),
  });
  const packet = await projectContract({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
  assert.equal(packet.validationObligations[0].satisfactionCurrent, true);
  assert.equal(packet.validationSatisfied, true);
  assert.deepEqual(packet.validationGaps, []);
  assert.equal(packet.actionState, 'PROCEED');
});

test('cross-repository validation closure accepts its exact result in a shared plural reevaluation', async () => {
  const client = fakeClient({
    validationObligationRows: [{
      ...defaultValidationObligationRows('urn:usf:validationactivationstate:activated')[0],
      ...crossRepositorySelfPublicationClosureRow({
        reevaluatesValidationResult: binding(crossValidationClosure.result),
      }),
    }, {
      ...defaultValidationObligationRows('urn:usf:validationactivationstate:activated')[0],
      ...crossRepositorySelfPublicationClosureRow({
        reevaluatesValidationResult: binding('urn:usf:validationresult:eventhistorycheckpointpruning'),
      }),
    }],
    validationPathRows: crossRepositoryPathRows(),
  });
  const packet = await projectContract({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
  assert.equal(packet.validationObligations[0].satisfactionCurrent, true);
  assert.equal(packet.validationSatisfied, true);
  assert.deepEqual(packet.validationGaps, []);
  assert.equal(packet.actionState, 'PROCEED');
});

test('D2 validation evidence is projected independently of the bounded scalar closure', async () => {
  const scalar = crossRepositorySelfPublicationClosureRow();
  const evidence = Object.fromEntries(
    ['evidence', 'evidenceType', 'evidenceExecution', 'evidenceAdmissionPath']
      .map((field) => [field, scalar[field]]),
  );
  for (const field of Object.keys(evidence)) delete scalar[field];
  const queries = [];
  const client = fakeClient({
    validationObligationRows: [{
      ...defaultValidationObligationRows('urn:usf:validationactivationstate:activated')[0],
      ...scalar,
    }],
    validationEvidenceRows: [{
      id: binding(validationObligation),
      satisfaction: binding(crossValidationClosure.result),
      ...evidence,
    }],
    validationPathRows: crossRepositoryPathRows(),
    queries,
  });
  const packet = await projectContract({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
  assert.equal(packet.validationSatisfied, true);
  const scalarQuery = queries.find((query) => query.includes('?conditionMatched'));
  const evidenceQuery = queries.find(
    (query) => query.includes('?evidence a <urn:usf:ontology:ValidationEvidence>'),
  );
  assert.ok(scalarQuery);
  assert.ok(evidenceQuery);
  assert.ok(evidenceQuery.includes('?satisfaction <urn:usf:ontology:usesAdmittedValidationEvidence> ?evidence'));
  assert.equal(scalarQuery.includes('?evidence a <urn:usf:ontology:ValidationEvidence>'), false);
  assert.ok(scalarQuery.includes('LIMIT 257'));
  assert.ok(evidenceQuery.includes('LIMIT 257'));
});

test('D2 validation currentness accepts supporting evidence beside its exact validation evidence', async () => {
  const scalar = crossRepositorySelfPublicationClosureRow();
  for (const field of ['evidence', 'evidenceType', 'evidenceExecution', 'evidenceAdmissionPath']) delete scalar[field];
  const validationEvidenceRows = ['validation', 'evaluation', 'decision'].map((name, index) => ({
    id: binding(validationObligation),
    satisfaction: binding(crossValidationClosure.result),
    evidence: binding(`urn:usf:evidenceresult:${name}`),
    ...(index === 0 ? {
      evidenceType: binding('true'),
      evidenceExecution: binding(crossValidationClosure.execution),
      evidenceAdmissionPath: binding(crossValidationClosure.admissionPath),
    } : {}),
  }));
  const packet = await projectContract({ client: fakeClient({
    validationObligationRows: [{
      ...defaultValidationObligationRows('urn:usf:validationactivationstate:activated')[0],
      ...scalar,
    }],
    validationEvidenceRows,
    validationPathRows: crossRepositoryPathRows(),
  }), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
  assert.equal(packet.validationObligations[0].satisfactionCurrent, true);
  assert.equal(packet.validationSatisfied, true);
  assert.deepEqual(packet.validationGaps, []);
  assert.equal(packet.actionState, 'PROCEED');
});

test('D2 validation currentness rejects a plural evidence set with a substituted execution', async () => {
  const scalar = crossRepositorySelfPublicationClosureRow();
  for (const field of ['evidence', 'evidenceType', 'evidenceExecution', 'evidenceAdmissionPath']) delete scalar[field];
  const validationEvidenceRows = ['validation', 'evaluation', 'decision'].map((name, index) => ({
    id: binding(validationObligation),
    satisfaction: binding(crossValidationClosure.result),
    evidence: binding(`urn:usf:evidenceresult:${name}`),
    ...(index < 2 ? {
      evidenceType: binding('true'),
      evidenceExecution: binding(index === 1
        ? 'urn:usf:validationexecution:substituted'
        : crossValidationClosure.execution),
      evidenceAdmissionPath: binding(crossValidationClosure.admissionPath),
    } : {}),
  }));
  const packet = await projectContract({ client: fakeClient({
    validationObligationRows: [{
      ...defaultValidationObligationRows('urn:usf:validationactivationstate:activated')[0],
      ...scalar,
    }],
    validationEvidenceRows,
    validationPathRows: crossRepositoryPathRows(),
  }), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
  assert.equal(packet.validationObligations[0].satisfactionCurrent, false);
  assert.equal(packet.validationSatisfied, false);
  assert.deepEqual(packet.validationGaps.map((item) => item.code), ['validation-satisfaction-not-current']);
  assert.equal(packet.actionState, 'BLOCK');
});

test('D2 validation subprojections preserve their declared cardinality limits', async () => {
  const scalar = {
    ...defaultValidationObligationRows('urn:usf:validationactivationstate:activated')[0],
    ...crossRepositorySelfPublicationClosureRow(),
  };
  const path = {
    id: binding(validationObligation),
    satisfaction: binding(crossValidationClosure.result),
    field: binding('bindingProducerSourcePath'),
    path: binding(crossProducerPaths[0]),
  };
  for (const item of [
    {
      options: { validationObligationRows: Array.from({ length: 257 }, () => scalar) },
      expected: /validation obligation projection exceeds 256 rows/,
    },
    {
      options: {
        validationObligationRows: [scalar],
        validationEvidenceRows: Array.from({ length: 257 }, () => ({
          id: binding(validationObligation),
          satisfaction: binding(crossValidationClosure.result),
          evidence: binding(crossValidationClosure.evidence),
          evidenceType: binding('true'),
          evidenceExecution: binding(crossValidationClosure.execution),
          evidenceAdmissionPath: binding(crossValidationClosure.admissionPath),
        })),
      },
      expected: /validation evidence projection exceeds 256 rows/,
    },
    {
      options: {
        validationObligationRows: [scalar],
        validationPathRows: Array.from({ length: 1025 }, () => path),
      },
      expected: /validation self-publication source path projection exceeds 1024 rows/,
    },
  ]) {
    await assert.rejects(
      () => projectContract({ client: fakeClient(item.options), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract }),
      item.expected,
    );
  }
});

test('cross-repository validation closure rejects scalar, reevaluation and exact-path-set substitutions', async () => {
  const cases = [
    {
      name: 'repository identities collapsed',
      row: { bindingAdmissionRepository: binding(crossValidationClosure.producerRepository) },
    },
    {
      name: 'producer source head substituted',
      row: { bindingProducerSourceHead: binding('f'.repeat(40)) },
    },
    {
      name: 'admission scope substituted',
      row: { bindingAdmissionSourceScope: binding(`sha256:${'ef'.repeat(32)}`) },
    },
    {
      name: 'reevaluation targets another validation result',
      row: { reevaluatesValidationResult: binding('urn:usf:validationresult:substituted') },
    },
    {
      name: 'reevaluation receipt absent',
      row: { reevaluationExecutionReceipt: undefined },
    },
    {
      name: 'legacy shared binding mixed into split identity',
      row: { bindingRepository: binding(crossValidationClosure.producerRepository) },
    },
    {
      name: 'producer binding path omitted',
      paths: { omit: 'bindingProducerSourcePath:1' },
    },
    {
      name: 'admission resource path omitted',
      paths: { omit: 'admissionSourcePath:0' },
    },
  ];
  for (const item of cases) {
    const row = crossRepositorySelfPublicationClosureRow(item.row || {});
    if (item.row && Object.hasOwn(item.row, 'reevaluationExecutionReceipt')
        && item.row.reevaluationExecutionReceipt === undefined) delete row.reevaluationExecutionReceipt;
    const client = fakeClient({
      validationObligationRows: [{
        ...defaultValidationObligationRows('urn:usf:validationactivationstate:activated')[0],
        ...row,
      }],
      validationPathRows: crossRepositoryPathRows(item.paths),
    });
    const packet = await projectContract({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
    assert.equal(packet.validationSatisfied, false, item.name);
    assert.equal(packet.validationObligations[0].satisfactionCurrent, false, item.name);
    assert.equal(packet.actionState, 'BLOCK', item.name);
    assert.deepEqual(packet.validationGaps.map((gap) => gap.code),
      ['validation-satisfaction-not-current'], item.name);
  }
});

test('validation non-publication closure rejects unrelated authority drift', async () => {
  const client = fakeClient({
    authorityNQuads: '<urn:s> <urn:p> "unrelated-drift" .\n',
    validationObligationRows: [{
      ...defaultValidationObligationRows('urn:usf:validationactivationstate:activated')[0],
      ...selfPublicationClosureRow(),
    }],
  });
  const packet = await projectContract({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
  assert.equal(packet.validationObligations[0].satisfactionCurrent, false);
  assert.equal(packet.validationSatisfied, false);
  assert.equal(packet.actionState, 'BLOCK');
  assert.equal(packet.executionScope, null);
  assert.equal(packet.semanticIdentifiers.some((item) => item.startsWith('urn:usf:contractexecutionscope:')), false);
  assert.deepEqual(packet.validationGaps.map((gap) => gap.code), ['validation-satisfaction-not-current']);
});

const selfPublicationClosureAdversarialCases = [
  {
    name: 'missing immutable execution receipt',
    mutate: { executionReceipt: undefined },
  },
  {
    name: 'mismatched reevaluation dependency set',
    mutate: { reevaluationDependency: binding(`sha256:${'dd'.repeat(32)}`) },
  },
  {
    name: 'wrong non-publication dependency algorithm',
    mutate: { dependencyAlgorithm: binding('sha256:invented') },
  },
  {
    name: 'failed post-publication reevaluation',
    mutate: { reevaluationState: binding('urn:usf:resultstate:failed') },
  },
  {
    name: 'validation producer substitution',
    mutate: { executionProducer: binding('urn:usf:validationproducer:substituted') },
  },
];

test('incomplete or substituted validation self-publication closures fail currentness', async () => {
  for (const item of selfPublicationClosureAdversarialCases) {
    const row = selfPublicationClosureRow(item.mutate);
    if (item.mutate.executionReceipt === undefined) delete row.executionReceipt;
    const client = fakeClient({
      validationObligationRows: [{
        ...defaultValidationObligationRows('urn:usf:validationactivationstate:activated')[0],
        ...row,
      }],
    });
    const packet = await projectContract({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
    assert.equal(packet.validationSatisfied, false, item.name);
    assert.equal(packet.validationObligations[0].satisfactionCurrent, false, item.name);
    assert.equal(packet.actionState, 'BLOCK', item.name);
    assert.equal(packet.executionScope, null, item.name);
    assert.deepEqual(packet.validationGaps.map((gap) => gap.code), ['validation-satisfaction-not-current'], item.name);
  }
});

test('ambiguous validation self-publication authority bindings fail currentness', async () => {
  const first = selfPublicationClosureRow();
  const second = selfPublicationClosureRow({
    binding: binding('urn:usf:validationauthoritybinding:ambiguous'),
    bindingResult: binding(validationClosure.result),
  });
  const activation = defaultValidationObligationRows('urn:usf:validationactivationstate:activated')[0];
  const client = fakeClient({
    validationObligationRows: [{ ...activation, ...first }, { ...activation, ...second }],
  });
  const packet = await projectContract({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
  assert.equal(packet.validationSatisfied, false);
  assert.equal(packet.validationObligations[0].satisfactionCurrent, false);
  assert.equal(packet.actionState, 'BLOCK');
  assert.deepEqual(packet.validationGaps.map((gap) => gap.code), ['validation-satisfaction-not-current']);
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
    const packet = await projectContract({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
    assert.equal(packet.validationSatisfied, false, item.name);
    assert.equal(packet.actionState, item.actionState, item.name);
    assert.equal(packet.validationActionState, item.validationActionState, item.name);
    if (item.actionState !== 'PROCEED') assert.deepEqual(packet.authorisedActions, [], item.name);
    const plan = await planWork({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
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
  const packet = await projectContract({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
  assert.equal(packet.validationApplicability.state, 'urn:usf:validationapplicabilitystate:reserved');
  assert.equal(packet.validationActionState, 'RESERVED_NO_ACTION');
  assert.equal(packet.validationSatisfied, false);
  assert.equal(GAP_DISPOSITIONS['validation-applicability-reserved'], 'RESERVED_NO_ACTION');

  const plan = await planWork({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
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
    }), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
  const activationReserved = await planWork({ client: fakeClient(), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });

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
  const packet = await projectContract({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
  assert.equal(packet.validationActionState, 'RESERVED_NO_ACTION');
  assert.equal(packet.validationSatisfied, false);
  const plan = await planWork({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
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
  await assert.rejects(() => planWork({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract }), /more than one validation applicability state/);
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
  const first = await planWork({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
  assert.equal(first.gapCount, 61);
  assert.equal(first.gaps.length, 50);
  assert.equal(first.truncated, true);
  assert.equal(first.nextOffset, 50);
  assert.equal(first.dispositionCounts.BLOCK, 61);
  assert.equal(first.actionState, 'BLOCK');

  const second = await planWork({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract, offset: 50 });
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
  await assert.rejects(() => planWork({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract }), /live authority changed/);
});

test("proof-blocked contract projection is available but grants no materialisation authority", async () => {
  const packet = await projectContract({ client: fakeClient({ contractRows: [{
    canonicalName: binding("compilersemanticenforcement"),
    lifecycle: binding("urn:usf:semanticlifecyclestate:planned"),
    activation: binding("urn:usf:contractactivationstate:proofblocked"),
  }] }), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract: "urn:usf:semanticcontract:compilersemanticenforcement" });
  assert.equal(packet.contractState.proof, null);
  assert.equal(packet.contractState.decision, null);
  assert.deepEqual(packet.authorisedActions, []);
  assert.deepEqual(packet.authorisedPaths, []);
  assert.deepEqual(packet.authorisedFormats, []);
});

test('model-incomplete contract projection is available with null lifecycle and activation and no authority grants', async () => {
  const packet = await projectContract({ client: fakeClient({ contractRows: [{
    canonicalName: binding('universalservicefoundationscopeandprinciples'),
  }] }), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract: 'urn:usf:semanticcontract:universalservicefoundationscopeandprinciples' });
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
  return createLayoutPlan({ client: fakeClient(), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract, operations: [planOperation()] });
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
    const verdict = await realisationVerdict({ client: item.client(), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
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
      () => createLayoutPlan({ client: item.client(), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract, operations: [planOperation()] }),
      new RegExp(REALISATION_STATE_FAILURE_CODES[item.expected]),
      `create: ${item.name}`,
    );
    // validate — a stable code, the state, and the reasons
    const validation = await validateLayoutPlan({ client: item.client(), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, plan);
    assert.equal(validation.ok, false, `validate: ${item.name}`);
    assert.equal(validation.realisationActionState, item.expected, `validate state: ${item.name}`);
    const stateFailure = validation.failures.find((failure) => failure.code === REALISATION_STATE_FAILURE_CODES[item.expected]);
    assert.ok(stateFailure, `validate code: ${item.name}`);
    assert.ok(stateFailure.reasons.includes(item.reason), `validate reason: ${item.name}`);
    // apply — refused, and never applied, even with coordinator authority
    const applied = await applyLayoutPlan(
      { client: item.client(), coordinator: true, repositoryRoot: '/usf', observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER },
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
  ];
  for (const [label, key, contradictory] of cases) {
    const rows = [...defaultContractRows(), { ...defaultContractRows()[0], [key]: contradictory }];
    const client = fakeClient({ contractRows: rows });
    await assert.rejects(() => realisationVerdict({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract }), new RegExp(`ambiguous ${label}`), label);
    // The ambiguity must stop the plan surfaces too, not just the verdict.
    await assert.rejects(() => createLayoutPlan({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract, operations: [planOperation()] }), new RegExp(`ambiguous ${label}`), `create: ${label}`);
    await assert.rejects(() => projectContract({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract }), new RegExp(`ambiguous ${label}`), `project: ${label}`);
  }
});

test('distinct relied-on proof results are plural, while contradictory state for one result is ambiguous', async () => {
  const result = defaultContractRows()[0].proof;
  const rows = [
    ...defaultContractRows(),
    { ...defaultContractRows()[0], proof: result, proofState: binding('urn:usf:proofresultstate:failed') },
  ];
  await assert.rejects(
    () => projectContract({ client: fakeClient({ contractRows: rows }), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract }),
    /proof result .* has ambiguous state/,
  );
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
  const ctx = { client: fakeClient(), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER };
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
  await assert.rejects(() => realisationVerdict({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract }), new RegExp(AUTHORITY_MOVED_CODE));
  await assert.rejects(() => layoutContext({ client: movingOnQueryClient('?canonicalName ?lifecycle'), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }), new RegExp(AUTHORITY_MOVED_CODE));
});

test('authority moving between the contract and validation queries fails closed', async () => {
  // The validation scope is read after the contract rows but inside the same
  // bracket, so a move here is caught by the closing witness.
  const client = movingOnQueryClient('<urn:usf:ontology:hasValidationApplicability> ?state');
  await assert.rejects(() => realisationVerdict({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract }), new RegExp(AUTHORITY_MOVED_CODE));
});

test('authority moving after the verdict but before plan validation fails closed', async () => {
  const verdict = await realisationVerdict({ client: fakeClient(), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
  // A fresh client at a different authority state: the plan and verdict digests no
  // longer describe live authority, so validation cannot pass.
  const moved = movingClient({ moveAfterWitnessReads: 0 });
  const validation = await validateLayoutPlan({ client: moved, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, {
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
  await assert.rejects(() => projectContract({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract }), new RegExp(AUTHORITY_MOVED_CODE));
});

test('authority moving immediately before the first apply operation refuses to touch the filesystem', async () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-apply-premove-'));
  roots.push(root);
  const plan = await createLayoutPlan({ client: fakeClient(), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract, operations: [writeOperation()] });
  // Witness reads on this client: verdict open (1) and close (2) — validation
  // consumes the passed verdict and re-reads nothing — then pre-apply (3). Move
  // authority exactly at the pre-apply read.
  const client = movingClient({ moveAfterWitnessReads: 2 });
  await assert.rejects(
    () => applyLayoutPlan({ client, coordinator: true, repositoryRoot: root, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { plan, apply: true }),
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
  const plan = await createLayoutPlan({ client: fakeClient(), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract, operations });

  // Witness reads: verdict open (1), verdict close (2), pre-apply (3) — all stable,
  // so the writes happen — then the post-apply check (4) observes the move.
  const client = movingClient({ moveAfterWitnessReads: 3 });
  await assert.rejects(
    () => applyLayoutPlan({ client, coordinator: true, repositoryRoot: root, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { plan, apply: true }),
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
  const ctx = { client: fakeClient(), coordinator: true, repositoryRoot: root, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER };
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
    const ctx = { client: fakeClient(), repositoryRoot: root, coordinator: true, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER };
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
    const ctx = { client: fakeClient(), repositoryRoot: root, coordinator: true, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER };
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
    const ctx = { client: fakeClient(), repositoryRoot: root, coordinator: true, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER };
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
    const ctx = { client: fakeClient(), repositoryRoot: root, coordinator: true, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER };
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
    const ctx = { client: fakeClient(), repositoryRoot: root, coordinator: true, casRoot, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER };
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
  const ctx = { client: fakeClient(), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER };
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
  const make = (path) => createLayoutPlan({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { operations: [{ action: 'write-file', artefactFamily: rootFamily, content: '# x\n', contentDigest: digest('# x\n'), contentEncoding: 'utf8', index: 0, path, pathRole: rootRole, representationFormat: rootFormat }] });
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
    const result = await verifyArtifact({ client: fakeClient({ descriptor }), casRoot: root, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { digest: contentDigest });
    assert.equal(result.verified, true);
    const external = join(root, 'external-object');
    writeFileSync(external, bytes);
    unlinkSync(path);
    if (fixtureSymlink(external, path)) {
      const symlinked = await verifyArtifact({ client: fakeClient({ descriptor }), casRoot: root, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { digest: contentDigest });
      assert.equal(symlinked.verified, false);
      assert.equal(symlinked.code, 'artifact-not-regular-file');
      unlinkSync(path);
    }
    writeFileSync(path, 'mutated');
    assert.equal((await verifyArtifact({ client: fakeClient({ descriptor }), casRoot: root, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { digest: contentDigest })).verified, false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('direct lifecycle mutation is always refused at the agent MCP boundary', () => {
  assert.throws(() => refuseLifecycleMutation('usf.evidence.admit'), /compiler.*single transaction/);
});

function exactAuthorityConflictFixture({
  conflictAuthorityDigest = witnessDigest,
  consumptionAuthorityDigest = witnessDigest,
} = {}) {
  const candidateDigest = `sha256:${'a1'.repeat(32)}`;
  const sourcePaths = Object.freeze([
    'semantic-model/assurance/evidence.trig',
    'semantic-model/assurance/proofs.trig',
    'semantic-model/realisation/bindings.trig',
  ]);
  const obligations = Object.freeze(durableFamilyValidations.map((item) => item.id).sort());
  const operation = Object.freeze({
    action: 'write-file',
    artefactFamily: family,
    content: 'exact correction\n',
    contentDigest: digest('exact correction\n'),
    contentEncoding: 'utf8',
    index: 0,
    path: 'semantic-model/ontology.ttl',
    pathRole: role,
    representationFormat: format,
    sourceDigest: `sha256:${'b2'.repeat(32)}`,
  });
  const bindingValue = materialisationInternals.normaliseAuthorityConflictBinding({
    schemaVersion: 2,
    candidateDigest,
    conflictAuthorityDigest,
    consumptionAuthorityDigest,
    ownerAuthorityDomain: 'urn:usf:capabilityowner:semanticmodelcompilation',
    predecessorSourceHead: 'c'.repeat(40),
    predecessorSourceTree: 'd'.repeat(40),
    repository: 'maldous/usf-graph',
    requestedEffects: [
      'urn:usf:obligationeffect:repositorymutation',
      'urn:usf:obligationeffect:validationproducersourceauthorisation',
    ],
    sourcePaths,
    sourceScopeDigest: digest(JSON.stringify(sourcePaths)),
    successorSourceTree: 'e'.repeat(40),
    validationObligations: obligations,
  }, [operation]);
  const conflict = 'urn:usf:authorityconflict:exactsemanticcorrection';
  const resolution = Object.freeze({
    id: 'urn:usf:authorityconflictresolution:exactsemanticcorrection',
    conflict,
    resolutionState: 'urn:usf:semanticcorrectiondecisionstate:accepted',
    decisionState: 'urn:usf:semanticcorrectiondecisionstate:accepted',
    reviewState: 'urn:usf:semanticadequacyreviewstate:accepted',
    reviewAuthorityDigest: conflictAuthorityDigest,
    reviewInventoryDigest: candidateDigest,
    proofState: 'urn:usf:proofresultstate:successful',
    proofSubject: conflict,
    ownerState: 'active',
    ownerAuthorityDomain: bindingValue.ownerAuthorityDomain,
    ownerRepository: bindingValue.repository,
    ownerEnvelopeState: 'urn:usf:resultstate:passed',
    ownerSourcePaths: sourcePaths,
    authorityDigest: conflictAuthorityDigest,
    repository: bindingValue.repository,
    operationDigest: bindingValue.operationDigest,
    candidateDigest,
    predecessorSourceHead: bindingValue.predecessorSourceHead,
    predecessorSourceTree: bindingValue.predecessorSourceTree,
    successorSourceTree: bindingValue.successorSourceTree,
    sourceScopeDigest: bindingValue.sourceScopeDigest,
    sourcePaths,
    contracts: [compilerContract, contract].sort(),
    requestedActions: bindingValue.requestedActions,
    requestedPaths: bindingValue.requestedPaths,
    requestedFormats: bindingValue.requestedFormats,
    requestedEffects: bindingValue.requestedEffects,
    validationObligations: obligations,
  });
  return {
    authorityDigest: consumptionAuthorityDigest,
    targetContract: contract,
    baseActionState: ACTION_STATES.block,
    baseActionStateReasons: obligations.map(() => 'missing-current-passing-validation'),
    baseValidationGaps: obligations.map((subject) => ({ code: 'missing-current-passing-validation', subject })),
    applicableContracts: [compilerContract],
    authoritySurfaces: [{ contract: compilerContract, authorisedPaths: ['semantic-model'], authorisedFormats: [format] }],
    binding: bindingValue,
    resolutions: [resolution],
  };
}

function authorityConflictClient(normalised, ownerSourcePaths) {
  const resolution = 'urn:usf:authorityconflictresolution:exactsemanticcorrection';
  const conflict = 'urn:usf:authorityconflict:exactsemanticcorrection';
  const scalar = {
    resolution, conflict,
    resolutionState: 'urn:usf:semanticcorrectiondecisionstate:accepted',
    decisionState: 'urn:usf:semanticcorrectiondecisionstate:accepted',
    review: 'urn:usf:semanticadequacyreview:exactsemanticcorrection',
    reviewState: 'urn:usf:semanticadequacyreviewstate:accepted',
    reviewAuthorityDigest: witnessDigest,
    reviewInventoryDigest: normalised.candidateDigest,
    proofResult: 'urn:usf:proofresult:exactsemanticcorrection',
    proofState: 'urn:usf:proofresultstate:successful', proofSubject: conflict,
    ownerAssignment: 'urn:usf:ownerassignment:semanticmodelcompilation:matthewaldous',
    ownerState: 'active', ownerAuthorityDomain: normalised.ownerAuthorityDomain,
    ownerRepository: normalised.repository, ownerEnvelopeState: 'urn:usf:resultstate:passed',
    authorityDigest: witnessDigest, repository: normalised.repository,
    operationDigest: normalised.operationDigest, candidateDigest: normalised.candidateDigest,
    predecessorSourceHead: normalised.predecessorSourceHead,
    predecessorSourceTree: normalised.predecessorSourceTree,
    successorSourceTree: normalised.successorSourceTree,
    sourceScopeDigest: normalised.sourceScopeDigest,
  };
  const scalarRows = [Object.fromEntries(Object.entries(scalar).map(([key, item]) => [key, binding(item)]))];
  const setRows = [
    ...[compilerContract, contract].map((item) => ['contract', item]),
    ...normalised.requestedActions.map((item) => ['action', item]),
    ...normalised.requestedPaths.map((item) => ['path', item]),
    ...normalised.requestedFormats.map((item) => ['format', item]),
    ...normalised.requestedEffects.map((item) => ['effect', item]),
    ...normalised.sourcePaths.map((item) => ['sourcePath', item]),
    ...normalised.validationObligations.map((item) => ['validationObligation', item]),
    ...ownerSourcePaths.map((item) => ['ownerSourcePath', item]),
  ].map(([kind, item]) => ({ resolution: binding(resolution), kind: binding(kind), item: binding(item) }));
  return fakeClient({
    validationObligationRows: durableFamilyValidationRows(),
    authorityConflictSurfaceRows: [{
      surfaceContract: binding(compilerContract),
      authorisedPath: binding('capabilities/semantic-model-compilation'),
      authorisedFormat: binding(format),
      surfaceObligation: binding('urn:usf:proofobligation:repositoryexternalartefactmaterialisation'),
    }],
    authorityConflictResolutionRows: scalarRows,
    authorityConflictSetRows: setRows,
  });
}

test('authority-conflict resolution is exact, fail-closed and non-replayable', () => {
  const evaluate = materialisationInternals.evaluateAuthorityConflictResolution;
  const control = exactAuthorityConflictFixture();
  assert.equal(evaluate(control).actionState, ACTION_STATES.proceed);

  const mutateResolution = (changes) => {
    const candidate = exactAuthorityConflictFixture();
    candidate.resolutions = [{ ...candidate.resolutions[0], ...changes }];
    return candidate;
  };
  const mutateBinding = (changes) => {
    const candidate = exactAuthorityConflictFixture();
    candidate.binding = { ...candidate.binding, ...changes };
    return candidate;
  };
  const adversaries = [
    mutateResolution({ contracts: [contract] }),
    mutateResolution({ contracts: [compilerContract, contract, 'urn:usf:semanticcontract:unrelated'].sort() }),
    mutateResolution({ authorityDigest: `sha256:${'01'.repeat(32)}` }),
    mutateResolution({ reviewAuthorityDigest: `sha256:${'02'.repeat(32)}` }),
    mutateBinding({ conflictAuthorityDigest: `sha256:${'06'.repeat(32)}` }),
    mutateBinding({ consumptionAuthorityDigest: `sha256:${'07'.repeat(32)}` }),
    mutateResolution({ candidateDigest: `sha256:${'03'.repeat(32)}` }),
    mutateResolution({ successorSourceTree: '1'.repeat(40) }),
    mutateResolution({ sourceScopeDigest: `sha256:${'04'.repeat(32)}` }),
    mutateResolution({ requestedPaths: ['semantic-model', ...control.binding.requestedPaths] }),
    mutateResolution({ requestedEffects: [...control.binding.requestedEffects, 'urn:usf:obligationeffect:providercontact'] }),
    mutateResolution({ reviewState: null }),
    mutateResolution({ reviewState: 'urn:usf:semanticadequacyreviewstate:rejected' }),
    mutateResolution({ proofState: null }),
    mutateResolution({ proofState: 'urn:usf:proofresultstate:failed' }),
    mutateResolution({ proofSubject: 'urn:usf:authorityconflict:other' }),
    mutateResolution({ ownerAuthorityDomain: 'urn:usf:capabilityowner:providerconfigurationplane' }),
    mutateResolution({ ownerEnvelopeState: 'urn:usf:resultstate:failed' }),
    mutateResolution({ resolutionState: 'urn:usf:semanticcorrectiondecisionstate:superseded' }),
    mutateResolution({ operationDigest: `sha256:${'05'.repeat(32)}` }),
    { ...exactAuthorityConflictFixture(), baseActionState: ACTION_STATES.proceed, baseActionStateReasons: [] },
    mutateResolution({ resolutionState: 'urn:usf:semanticcorrectiondecisionstate:unknown' }),
  ];
  for (const [index, adversary] of adversaries.entries()) {
    assert.equal(evaluate(adversary).actionState, ACTION_STATES.block, `adversary ${index + 1}`);
  }

  const replayOperation = structuredClone(control.binding);
  assert.throws(() => materialisationInternals.normaliseAuthorityConflictBinding({
    schemaVersion: 2,
    candidateDigest: replayOperation.candidateDigest,
    conflictAuthorityDigest: replayOperation.conflictAuthorityDigest,
    consumptionAuthorityDigest: replayOperation.consumptionAuthorityDigest,
    ownerAuthorityDomain: replayOperation.ownerAuthorityDomain,
    predecessorSourceHead: replayOperation.predecessorSourceHead,
    predecessorSourceTree: replayOperation.predecessorSourceTree,
    repository: replayOperation.repository,
    requestedEffects: replayOperation.requestedEffects,
    sourcePaths: replayOperation.sourcePaths,
    sourceScopeDigest: replayOperation.sourceScopeDigest,
    successorSourceTree: replayOperation.successorSourceTree,
    validationObligations: replayOperation.validationObligations,
  }, [{
    action: 'write-file', artefactFamily: family, content: 'exact correction\n',
    contentDigest: digest('exact correction\n'), contentEncoding: 'utf8', index: 0,
    path: 'semantic-model/ontology.ttl', pathRole: role, representationFormat: format,
  }]), /source preimage/);
});

test('an exact D0 resolution remains consumable after its governed D1/D2 admission', () => {
  const d0 = `sha256:${'11'.repeat(32)}`;
  const d2 = `sha256:${'22'.repeat(32)}`;
  const admitted = exactAuthorityConflictFixture({
    conflictAuthorityDigest: d0,
    consumptionAuthorityDigest: d2,
  });
  assert.equal(admitted.resolutions[0].authorityDigest, d0);
  assert.equal(admitted.resolutions[0].reviewAuthorityDigest, d0);
  assert.equal(admitted.authorityDigest, d2);
  assert.equal(
    materialisationInternals.evaluateAuthorityConflictResolution(admitted).actionState,
    ACTION_STATES.proceed,
  );

  const stalePlan = {
    ...admitted,
    authorityDigest: `sha256:${'33'.repeat(32)}`,
  };
  assert.equal(
    materialisationInternals.evaluateAuthorityConflictResolution(stalePlan).actionState,
    ACTION_STATES.block,
  );
});

test('the canonical gateway consumes one exact live conflict resolution and no implicit precedence', async () => {
  // The semantic-assurance profile intentionally proves that read-only
  // validation loads without child-process authority. The full hermetic profile
  // grants that authority and exercises the coordinator's real Git boundary.
  if (process.env.USF_EXPECTED_CHILD_PROCESS_PERMISSION === 'denied') {
    assert.equal(process.env.USF_HERMETIC_TEST_MODE, '1');
    return;
  }
  const root = mkdtempSync(join(tmpdir(), 'usf-authority-conflict-apply-'));
  roots.push(root);
  const predecessor = await initialiseRepository(root);
  const content = 'exact correction\n';
  const operation = {
    action: 'write-file', artefactFamily: family, content,
    contentDigest: digest(content), contentEncoding: 'utf8', index: 0,
    path: 'capabilities/semantic-model-compilation/value.mjs', pathRole: role,
    representationFormat: format, sourceDigest: `sha256:${'b2'.repeat(32)}`,
  };
  const sourcePaths = [
    'semantic-model/assurance/evidence.trig',
    'semantic-model/assurance/proofs.trig',
    'semantic-model/realisation/bindings.trig',
  ];
  const validationObligations = durableFamilyValidations.map((item) => item.id).sort();
  const rawBinding = {
    schemaVersion: 2,
    candidateDigest: `sha256:${'a1'.repeat(32)}`,
    conflictAuthorityDigest: witnessDigest,
    consumptionAuthorityDigest: witnessDigest,
    ownerAuthorityDomain: 'urn:usf:capabilityowner:semanticmodelcompilation',
    predecessorSourceHead: predecessor.head, predecessorSourceTree: predecessor.tree,
    repository: 'maldous/usf-graph',
    requestedEffects: [
      'urn:usf:obligationeffect:repositorymutation',
      'urn:usf:obligationeffect:validationproducersourceauthorisation',
    ],
    sourcePaths, sourceScopeDigest: digest(JSON.stringify(sourcePaths)),
    successorSourceTree: await successorTreeForWrite(root, operation.path, content), validationObligations,
  };
  const normalised = materialisationInternals.normaliseAuthorityConflictBinding(rawBinding, [operation]);
  const client = authorityConflictClient(normalised, sourcePaths);
  await assert.rejects(
    () => createLayoutPlan({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract, operations: [operation] }),
    /plan-realisation-blocked/,
  );
  const plan = await createLayoutPlan({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, {
    contract, operations: [operation], authorityConflictBinding: rawBinding,
  });
  assert.equal(plan.authorityConflictBinding.candidateDigest, normalised.candidateDigest);
  assert.equal((await validateLayoutPlan({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, plan)).ok, true);
  assert.equal((await applyLayoutPlan({ client, coordinator: true, repositoryRoot: root, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { plan, apply: true })).applied, true);
  await assert.rejects(
    () => applyLayoutPlan({ client, coordinator: true, repositoryRoot: root, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { plan, apply: true }),
    /authority-conflict predecessor worktree is not exact and clean|authority-conflict resolution is single-use/,
  );
});

test('an exact directory-only authority-conflict resolution cannot report replay success', async () => {
  if (process.env.USF_EXPECTED_CHILD_PROCESS_PERMISSION === 'denied') {
    assert.equal(process.env.USF_HERMETIC_TEST_MODE, '1');
    return;
  }
  const root = mkdtempSync(join(tmpdir(), 'usf-authority-conflict-directory-'));
  roots.push(root);
  const predecessor = await initialiseRepository(root);
  const operation = {
    action: 'create-directory', artefactFamily: family, index: 0,
    path: 'capabilities/semantic-model-compilation', pathRole: role,
    representationFormat: format,
  };
  const sourcePaths = [
    'semantic-model/assurance/evidence.trig',
    'semantic-model/assurance/proofs.trig',
    'semantic-model/realisation/bindings.trig',
  ];
  const rawBinding = {
    schemaVersion: 2,
    candidateDigest: `sha256:${'a1'.repeat(32)}`,
    conflictAuthorityDigest: witnessDigest,
    consumptionAuthorityDigest: witnessDigest,
    ownerAuthorityDomain: 'urn:usf:capabilityowner:semanticmodelcompilation',
    predecessorSourceHead: predecessor.head,
    predecessorSourceTree: predecessor.tree,
    repository: 'maldous/usf-graph',
    requestedEffects: [
      'urn:usf:obligationeffect:repositorymutation',
      'urn:usf:obligationeffect:validationproducersourceauthorisation',
    ],
    sourcePaths,
    sourceScopeDigest: digest(JSON.stringify(sourcePaths)),
    successorSourceTree: predecessor.tree,
    validationObligations: durableFamilyValidations.map((item) => item.id).sort(),
  };
  const normalised = materialisationInternals.normaliseAuthorityConflictBinding(rawBinding, [operation]);
  const client = authorityConflictClient(normalised, sourcePaths);
  const plan = await createLayoutPlan({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, {
    contract, operations: [operation], authorityConflictBinding: rawBinding,
  });
  assert.equal((await applyLayoutPlan({ client, coordinator: true, repositoryRoot: root, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { plan, apply: true })).applied, true);
  await assert.rejects(
    () => applyLayoutPlan({ client, coordinator: true, repositoryRoot: root, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { plan, apply: true }),
    /authority-conflict resolution is single-use/,
  );
});

test('bounded authority capture is complete for the exact canonical family registry', () => {
  const scope = JSON.parse(readFileSync(new URL(
    '../../assurance/permutation-closure/authority-capture-scope.json',
    import.meta.url,
  ), 'utf8'));
  const projectedClasses = new Set(scope.projectedClassIris);
  const projectedPredicates = new Set(scope.projectedPredicateIris);
  const requiredClasses = new Set();
  const requiredPredicates = new Set();
  for (const closure of familyRegistry.classClosures.values()) {
    for (const classIri of closure.memberClassIris) requiredClasses.add(classIri);
  }
  for (const selector of familyRegistry.selectors.values()) {
    requiredClasses.add(selector.subjectClassIri);
    requiredClasses.add(selector.terminalClassIri);
    for (const step of selector.steps) requiredPredicates.add(step.predicateIri);
  }
  for (const familyRecord of censusFamilies) requiredClasses.add(familyRecord.subjectClassIri);
  const missingClasses = [...requiredClasses].filter((iri) => !projectedClasses.has(iri)).sort();
  const missingPredicates = [...requiredPredicates].filter((iri) => !projectedPredicates.has(iri)).sort();
  assert.deepEqual(missingClasses, []);
  assert.deepEqual(missingPredicates, []);
  assert.equal(scope.projectedClassIris.length, 377);
  assert.equal(scope.projectedPredicateIris.length, 221);
  assert.deepEqual(scope.projectedClassIris, [...projectedClasses].sort());
  assert.deepEqual(scope.projectedPredicateIris, [...projectedPredicates].sort());
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

test('implementation work grant projection permits only exact existing-file candidate work and DENY always wins', async () => {
  if (process.env.USF_EXPECTED_CHILD_PROCESS_PERMISSION === 'denied') {
    assert.equal(process.env.USF_HERMETIC_TEST_MODE, '1');
    return;
  }
  const root = mkdtempSync(join(tmpdir(), 'usf-implementation-work-grant-'));
  roots.push(root);
  const predecessor = await initialiseRepository(root);
  const paths = ['README.md'];
  const allowedActions = [
    'urn:usf:implementationworkaction:candidateexistingfileedit',
    'urn:usf:implementationworkaction:candidatesigningandprotection',
    'urn:usf:implementationworkaction:casclosure',
    'urn:usf:implementationworkaction:compilationandbuild',
    'urn:usf:implementationworkaction:evidencegeneration',
    'urn:usf:implementationworkaction:independentreview',
    'urn:usf:implementationworkaction:isolatedreadonlyrehearsal',
    'urn:usf:implementationworkaction:tests',
  ];
  const deniedEffects = [
    'urn:usf:implementationworkeffect:a0capture',
    'urn:usf:implementationworkeffect:authoritymutation',
    'urn:usf:implementationworkeffect:businesssemanticscopeexpansion',
    'urn:usf:implementationworkeffect:deployment',
    'urn:usf:implementationworkeffect:implicitpathwidening',
    'urn:usf:implementationworkeffect:learnedexecution',
    'urn:usf:implementationworkeffect:productionwrite',
    'urn:usf:implementationworkeffect:providercontact',
    'urn:usf:implementationworkeffect:pruning',
    'urn:usf:implementationworkeffect:semanticpublication',
    'urn:usf:implementationworkeffect:v2activation',
  ];
  const grantCandidateDigest = `sha256:${'9'.repeat(64)}`;
  const graphScope = {
    predecessorCommit: predecessor.head, predecessorTree: predecessor.tree, repository: 'maldous/usf-graph',
    sourcePaths: paths, sourceScopeDigest: digest(JSON.stringify(paths)),
  };
  const grant = {
    allowedActions, authorityDigest: `sha256:${'a'.repeat(64)}`, deniedEffects,
    evidenceSetDigest: `sha256:${'b'.repeat(64)}`, expiresAt: '2026-08-20T00:00:00Z',
    grantCandidateDigest, grantIri: `urn:usf:implementationworkgrant:${grantCandidateDigest.slice(7)}`,
    issuedAt: '2026-08-16T00:00:00Z', nonce: '00000000-0000-4000-8000-000000000009',
    nonPublicationDependencySetDigest: `sha256:${'e'.repeat(64)}`,
    purpose: 'urn:usf:implementationworkpurpose:v2nativehandover',
    repositories: [{
      predecessorCommit: '3'.repeat(40), predecessorTree: '4'.repeat(40), repository: 'maldous/usf-factory',
      sourcePaths: ['src/usf_factory/activation.py'],
      sourceScopeDigest: digest(JSON.stringify(['src/usf_factory/activation.py'])),
    }, graphScope],
    state: 'urn:usf:implementationworkgrantstate:reserved', transactionState: 'reserved',
  };
  const operation = { action: 'write-file', path: paths[0], sourceDigest: sourceDigest(join(root, paths[0])) };
  const verdict = materialisationInternals.evaluateImplementationWorkGrantProjection({
    grant, nonPublicationDependencySetDigest: grant.nonPublicationDependencySetDigest, repository: graphScope.repository,
    predecessorCommit: graphScope.predecessorCommit, predecessorTree: graphScope.predecessorTree,
    operations: [operation], observedAt: '2026-08-16T01:00:00Z', repositoryRoot: root,
  });
  assert.equal(verdict.actionState, ACTION_STATES.proceed);
  for (const mutation of [
    { nonPublicationDependencySetDigest: `sha256:${'d'.repeat(64)}` },
    { operations: [{ ...operation, action: 'delete-path' }] },
    { operations: [{ ...operation, path: 'unreviewed.mjs' }] },
    { operations: [{ ...operation, path: 'absent.mjs' }] },
    { predecessorTree: '5'.repeat(40) },
    { observedAt: '2026-08-21T00:00:00Z' },
  ]) {
    assert.equal(materialisationInternals.evaluateImplementationWorkGrantProjection({
      grant, nonPublicationDependencySetDigest: grant.nonPublicationDependencySetDigest, repository: graphScope.repository,
      predecessorCommit: graphScope.predecessorCommit, predecessorTree: graphScope.predecessorTree,
      operations: [operation], observedAt: '2026-08-16T01:00:00Z', repositoryRoot: root, ...mutation,
    }).actionState, ACTION_STATES.block);
  }
  assert.throws(() => materialisationInternals.normaliseImplementationWorkGrantProjection({
    ...grant, deniedEffects: deniedEffects.slice(1),
  }), /ALLOW or DENY/);
  assert.throws(() => materialisationInternals.normaliseImplementationWorkGrantProjection({
    ...grant, nonce: '------------------------------------',
  }), /identity is invalid/);
});

test('production plan create, validate and apply consume one exact live implementation work grant', async () => {
  if (process.env.USF_EXPECTED_CHILD_PROCESS_PERMISSION === 'denied') {
    assert.equal(process.env.USF_HERMETIC_TEST_MODE, '1');
    return;
  }
  const root = mkdtempSync(join(tmpdir(), 'usf-implementation-work-plan-'));
  roots.push(root);
  await initialiseRepository(root);
  const path = 'capabilities/semantic-model-compilation/value.mjs';
  mkdirSync(join(root, 'capabilities/semantic-model-compilation'), { recursive: true });
  writeFileSync(join(root, path), 'export const value = 0;\n');
  await git(root, ['add', path]);
  await git(root, ['commit', '-q', '-m', 'exact implementation predecessor']);
  const predecessorCommit = await git(root, ['rev-parse', 'HEAD']);
  const predecessorTree = await git(root, ['rev-parse', 'HEAD^{tree}']);
  const client = fakeClient({
    validationObligationRows: defaultValidationObligationRows('urn:usf:validationactivationstate:activated'),
  });
  const authority = await layoutContext({ client, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER });
  const nonPublicationDependencySetDigest = materialisationInternals
    .validationNonPublicationDependencyDigest(authority.authorityGraphInventory);
  const grantCandidateDigest = `sha256:${'9'.repeat(64)}`;
  const grant = {
    allowedActions: [
      'urn:usf:implementationworkaction:candidateexistingfileedit',
      'urn:usf:implementationworkaction:candidatesigningandprotection',
      'urn:usf:implementationworkaction:casclosure',
      'urn:usf:implementationworkaction:compilationandbuild',
      'urn:usf:implementationworkaction:evidencegeneration',
      'urn:usf:implementationworkaction:independentreview',
      'urn:usf:implementationworkaction:isolatedreadonlyrehearsal',
      'urn:usf:implementationworkaction:tests',
    ],
    authorityDigest: authority.authorityDigest,
    deniedEffects: [
      'urn:usf:implementationworkeffect:a0capture',
      'urn:usf:implementationworkeffect:authoritymutation',
      'urn:usf:implementationworkeffect:businesssemanticscopeexpansion',
      'urn:usf:implementationworkeffect:deployment',
      'urn:usf:implementationworkeffect:implicitpathwidening',
      'urn:usf:implementationworkeffect:learnedexecution',
      'urn:usf:implementationworkeffect:productionwrite',
      'urn:usf:implementationworkeffect:providercontact',
      'urn:usf:implementationworkeffect:pruning',
      'urn:usf:implementationworkeffect:semanticpublication',
      'urn:usf:implementationworkeffect:v2activation',
    ],
    evidenceSetDigest: `sha256:${'b'.repeat(64)}`,
    expiresAt: '2026-08-20T00:00:00Z',
    grantCandidateDigest,
    grantIri: `urn:usf:implementationworkgrant:${grantCandidateDigest.slice(7)}`,
    issuedAt: '2026-08-16T00:00:00Z',
    nonPublicationDependencySetDigest,
    nonce: '00000000-0000-4000-8000-000000000009',
    purpose: 'urn:usf:implementationworkpurpose:v2nativehandover',
    repositories: [{
      predecessorCommit: '3'.repeat(40), predecessorTree: '4'.repeat(40), repository: 'maldous/usf-factory',
      sourcePaths: ['src/usf_factory/activation.py'],
      sourceScopeDigest: digest(JSON.stringify(['src/usf_factory/activation.py'])),
    }, {
      predecessorCommit, predecessorTree, repository: 'maldous/usf-graph',
      sourcePaths: [path], sourceScopeDigest: digest(JSON.stringify([path])),
    }],
    state: 'urn:usf:implementationworkgrantstate:reserved',
    transactionState: 'reserved',
  };
  const readImplementationWorkGrantAuthorityState = async (_client, iri, options) => {
    assert.equal(iri, grant.grantIri);
    assert.equal(options.nonPublicationDependencySetDigest, nonPublicationDependencySetDigest);
    assert.equal(options.requireReservedTransaction, true);
    return grant;
  };
  const select = client.select;
  client.select = async (query) => query.includes('a <urn:usf:ontology:ImplementationWorkGrant>')
    ? [{ grant: binding(grant.grantIri) }]
    : select(query);
  const content = 'export const value = 1;\n';
  const operations = [{
    ...writeOperation(content, 0, path),
    sourceDigest: sourceDigest(join(root, path)),
  }];
  const ctx = {
    client,
    coordinator: true,
    observedAt: '2026-08-16T01:00:00Z',
    observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER,
    readImplementationWorkGrantAuthorityState,
    repositoryRoot: root,
  };
  const plan = await createLayoutPlan(ctx, {
    contract,
    operations,
  });
  assert.equal(plan.implementationWorkGrantBinding.grantCandidateDigest, grantCandidateDigest);
  assert.equal((await validateLayoutPlan(ctx, plan)).ok, true);
  assert.equal((await applyLayoutPlan(ctx, { plan, apply: true })).applied, true);
  assert.equal(readFileSync(join(root, path), 'utf8'), content);
  const replay = await applyLayoutPlan(ctx, { plan, apply: true });
  assert.equal(replay.applied, false);
  assert.equal(replay.realisationActionState, ACTION_STATES.block);
});

// ---------------------------------------------------------------------------
// GRAPH-17 native V2 owner boundary.
//
// Preterminal behaviour is proven byte-identical by every test above, which
// runs with no ownership observer and therefore under V1_OWNER. These tests
// prove the other two owners: that terminal V2 derives the COMPLETE work-plan
// semantics from native state without consulting the V1 proof lifecycle at all,
// and that a pending handover fails closed instead of borrowing V1's answer.
// ---------------------------------------------------------------------------

const ownerBoundary = await import('./repository-materialisation-gateway.mjs');

const terminalOwner = (state = 'CURRENT', authority = witnessDigest) => ({
  observeGraphRuntimeOwnership: async () => ({
    ownership_state: 'V2_TERMINAL_OWNER',
    authority_digest: authority,
    observation_identity_digest: `sha256:${'1'.repeat(64)}`,
    // A terminal observation carries the COMPLETE native currentness head: it is
    // the execution scope's anchor, so an incomplete head must fail closed.
    validation_currentness: {
      state,
      digest: `sha256:${'2'.repeat(64)}`,
      proof_result_digest: `sha256:${'3'.repeat(64)}`,
      evidence_set_digest: `sha256:${'4'.repeat(64)}`,
      semantic_scope_digest: `sha256:${'5'.repeat(64)}`,
      admission_receipt_digest: `sha256:${'6'.repeat(64)}`,
      source: 'HANDOVER_GENESIS',
    },
  }),
});
const pendingOwner = () => ({
  observeGraphRuntimeOwnership: async () => ({
    ownership_state: 'V2_HANDOVER_PENDING',
    observation_identity_digest: `sha256:${'2'.repeat(64)}`,
  }),
});
// Only proof-currentness reads the algorithm binding, so its absence from the
// issued SPARQL is a mechanical proof that the V1 resolver was never called.
const V1_CURRENTNESS_MARKER = 'usesProofAlgorithm';

test('terminal V2 projects a contract execution scope anchored on the native currentness head', async () => {
  const queries = [];
  const packet = await projectContract({
    client: fakeClient({ validationObligationRows: durableFamilyValidationRows({ conditionMatched: false, satisfaction: satisfyingResultRow() }), queries }),
    ...terminalOwner() }, { contract });
  // projectContract is a required consumer AND a live MCP tool. Before this it
  // threw unconditionally after the handover, through a chain of V1-shaped
  // invariants, because no terminal test exercised it.
  assert.ok(packet.executionScope, 'terminal V2 must still project an execution scope');
  const core = packet.executionScope.scopeCore;
  // The anchor is the native validation-currentness head, not a V1 proof result.
  assert.ok(core.prepublicationProofIri.startsWith('urn:usf:v2nativevalidationcurrentness:'),
    'terminal scope must anchor on the native currentness head');
  assert.ok(!queries.some((query) => query.includes('usesProofAlgorithm')),
    'terminal V2 must not issue the V1 proof-currentness algorithm read');
  // Obligations are contract facts and survive the handover; only proof results go.
  assert.ok(core.obligationIri.length > 0, 'terminal scope must still name its obligation');
  assert.deepEqual(packet.proofCurrentness.perProof, []);
  assert.deepEqual(packet.proofCurrentness.proofResults, []);
  assert.ok(packet.proofCurrentness.mandatoryObligations.length > 0,
    'terminal V2 keeps the exact mandatory obligation set');
});

test('terminal V2 refuses an execution scope when the native currentness head is incomplete', async () => {
  // Missing or invalid current data fails closed: it must never fall back to a
  // V1 proof anchor, and never emit a scope with no current warrant.
  const incomplete = () => ({
    observeGraphRuntimeOwnership: async () => ({
      ownership_state: 'V2_TERMINAL_OWNER',
      authority_digest: `sha256:${'a'.repeat(64)}`,
      observation_identity_digest: `sha256:${'1'.repeat(64)}`,
      validation_currentness: { state: 'CURRENT' },
    }),
  });
  await assert.rejects(
    () => projectContract({
      client: fakeClient({ validationObligationRows: durableFamilyValidationRows({ conditionMatched: false, satisfaction: satisfyingResultRow() }) }),
      ...incomplete() }, { contract }),
    /native validation-currentness head/,
  );
});

test('terminal V2 derives the work plan from native currentness and never reads V1 proof currentness', async () => {
  const queries = [];
  const plan = await planWork({
    client: fakeClient({ validationObligationRows: durableFamilyValidationRows({ conditionMatched: false, satisfaction: satisfyingResultRow() }), queries }),
    ...terminalOwner() }, { contract });
  assert.equal(plan.proofCurrentness.state, 'CURRENT');
  assert.deepEqual(plan.proofCurrentness.reasons, []);
  assert.equal(plan.actionState, 'PROCEED');
  assert.equal(plan.gapCount, 0);
  assert.equal(plan.validationSatisfied, true);
  assert.ok(!queries.some((query) => query.includes(V1_CURRENTNESS_MARKER)),
    'terminal V2 must not issue the V1 proof-currentness algorithm read');
});

test('terminal V2 with a stale native validation head blocks on the declared currentness code', async () => {
  const queries = [];
  const plan = await planWork({
    client: fakeClient({ validationObligationRows: durableFamilyValidationRows({ conditionMatched: false, satisfaction: satisfyingResultRow() }), queries }),
    ...terminalOwner('STALE_BLOCK') }, { contract });
  assert.equal(plan.proofCurrentness.state, 'STALE_BLOCK');
  assert.deepEqual(plan.proofCurrentness.reasons, ['proof-authority-binding-stale']);
  assert.equal(plan.actionState, 'BLOCK');
  // A stale head withdraws every satisfaction at once, so validation is not
  // satisfied and the gap census reports it rather than staying silent.
  assert.equal(plan.validationSatisfied, false);
  assert.ok(plan.gapCount > 0);
  assert.ok(!queries.some((query) => query.includes(V1_CURRENTNESS_MARKER)));
});

test('a pending handover fails closed instead of borrowing the outgoing V1 conclusion', async () => {
  const queries = [];
  const plan = await planWork({
    client: fakeClient({ validationObligationRows: durableFamilyValidationRows({ conditionMatched: false, satisfaction: satisfyingResultRow() }), queries }),
    ...pendingOwner() }, { contract });
  assert.equal(plan.proofCurrentness.state, 'UNRESOLVED_FAIL_CLOSED');
  assert.deepEqual(plan.proofCurrentness.reasons, ['proof-currentness-unresolved']);
  assert.equal(plan.actionState, 'UNRESOLVED_FAIL_CLOSED');
  assert.equal(plan.validationSatisfied, false);
  assert.ok(!queries.some((query) => query.includes(V1_CURRENTNESS_MARKER)));
});

test('a satisfaction bound to a different authority is not current under terminal V2', async () => {
  const plan = await planWork({
    client: fakeClient({ validationObligationRows: durableFamilyValidationRows({ conditionMatched: false, satisfaction: satisfyingResultRow() }) }),
    ...terminalOwner('CURRENT', `sha256:${'9'.repeat(64)}`) }, { contract });
  assert.equal(plan.validationSatisfied, false);
  assert.equal(plan.actionState, 'BLOCK');
});

test('the public work-plan contract is byte-shape identical under every owner', async () => {
  const rows = () => durableFamilyValidationRows({ conditionMatched: false, satisfaction: satisfyingResultRow() });
  const owners = [{}, terminalOwner(), terminalOwner('STALE_BLOCK'), pendingOwner()];
  const baseline = Object.keys(await planWork({ client: fakeClient({ validationObligationRows: rows() }), observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract })).sort();
  for (const owner of owners) {
    const plan = await planWork({ client: fakeClient({ validationObligationRows: rows() }), ...owner, observeGraphRuntimeOwnership: BAU_TERMINAL_OWNER }, { contract });
    assert.deepEqual(Object.keys(plan).sort(), baseline, 'work-plan key set must not drift');
    assert.equal(plan.schemaVersion, 2);
    assert.ok(Object.values(ownerBoundary.ACTION_STATES).includes(plan.actionState));
    assert.deepEqual(Object.keys(plan.dispositionCounts).sort(), Object.values(ownerBoundary.ACTION_STATES).slice().sort());
    assert.deepEqual(Object.keys(plan.proofCurrentness).sort(), ['reasons', 'state', 'stateIri']);
    for (const gap of plan.gaps) {
      assert.ok(Object.hasOwn(ownerBoundary.GAP_DISPOSITIONS, gap.type), `gap code outside the declared vocabulary: ${gap.type}`);
    }
  }
  // The declared vocabulary itself must not grow: eighteen codes, four states.
  assert.equal(Object.keys(ownerBoundary.GAP_DISPOSITIONS).length, 18);
  assert.equal(Object.keys(ownerBoundary.ACTION_STATES).length, 4);
});

test('an unknown ownership state is refused rather than defaulted', async () => {
  await assert.rejects(() => planWork({
    client: fakeClient({}),
    observeGraphRuntimeOwnership: async () => ({ ownership_state: 'SOMETHING_ELSE' }),
  }, { contract }), /not a closed state/);
});

test('terminal ownership without a validation currentness state is refused', async () => {
  await assert.rejects(() => planWork({
    client: fakeClient({}),
    observeGraphRuntimeOwnership: async () => ({ ownership_state: 'V2_TERMINAL_OWNER', authority_digest: witnessDigest }),
  }, { contract }), /carries no validation currentness state/);
});
