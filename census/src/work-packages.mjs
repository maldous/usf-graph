import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJson, compareBy, sha256, sortUnique } from './canonical.mjs';

const censusRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const baselineMembershipPath = path.join(censusRoot, 'src', 'baseline', 'package-membership.jsonl');

const outcomeDefinitions = Object.freeze({
  'semantic-authority': 'Define and govern the canonical semantic language, policy, and contract authority.',
  'interface-workflows': 'Realise canonical interface, event, interaction, and workflow contracts.',
  'semantic-derivation': 'Produce integrity-protected semantic derivations and projections.',
  'canonical-generation': 'Generate canonical artifacts and human projections from governed semantics.',
  'implementation-realisation': 'Realise implementation obligations against semantic and contract authority.',
  'runtime-materialisation': 'Materialise runtime, provider, configuration, and clean-room support outcomes.',
  'proof-evidence': 'Produce proof obligations, evidence collection, ingestion, and readiness outcomes.',
  validation: 'Validate semantics, artifacts, fixtures, defects, and behavioural equivalence.',
  'retained-assets': 'Retain integrity-protected static inputs required by canonical outputs.',
  'closed-disposition': 'Remove or exclude noncanonical artifacts after reference and absence closure.'
});

const layerOutcomes = new Map([
  ['ontology', 'semantic-authority'], ['vocabulary', 'semantic-authority'], ['taxonomy', 'semantic-authority'],
  ['claims-nonclaims', 'semantic-authority'], ['contracts', 'semantic-authority'], ['policy', 'semantic-authority'],
  ['constraints-permissions', 'semantic-authority'], ['interfaces-events-workflows', 'interface-workflows'],
  ['derivation-integrity', 'semantic-derivation'], ['artifact-output-plans', 'canonical-generation'],
  ['generation-renderer-contracts', 'canonical-generation'], ['requirements-projections', 'canonical-generation'],
  ['implementation-obligations', 'implementation-realisation'], ['data-configuration-lifecycle', 'runtime-materialisation'],
  ['provider-service-realisation', 'runtime-materialisation'], ['materialisation-contracts', 'runtime-materialisation'],
  ['self-hosting-clean-room-support', 'runtime-materialisation'], ['proof-obligations', 'proof-evidence'],
  ['evidence-requirements', 'proof-evidence'], ['collector-normaliser-ingestion-contracts', 'proof-evidence'],
  ['readiness-consequences', 'proof-evidence'], ['validation-tests-fixtures-defects', 'validation'],
  ['equivalence-rules', 'validation'], ['execution-agent-constraints', 'validation']
]);

function readJsonl(target) {
  const text = fs.readFileSync(target, 'utf8');
  if (text.length > 0 && !text.endsWith('\n')) throw new Error(`${target} lacks final newline`);
  return text.split('\n').filter(Boolean).map((line) => JSON.parse(line));
}

export function readBaselinePackageMembership(target = baselineMembershipPath) {
  const records = readJsonl(target);
  if (records.length === 0) throw new Error('baseline package lineage is empty');
  return records;
}

function pathFamily(repoPath) {
  const parts = String(repoPath).split('/');
  if (parts.length === 1) return 'repository-root';
  if (parts[0] === 'v2' && parts.length >= 3) return parts.slice(0, 3).join('/');
  if (['apps', 'packages', 'services', 'capabilities', 'adapters', 'docs', 'artifacts', 'tools'].includes(parts[0]) && parts.length >= 2) return parts.slice(0, 2).join('/');
  return parts[0];
}

function outcomeFor({ canonicalArtifacts, currentArtifacts }) {
  let outcome;
  if (canonicalArtifacts.length === 0) outcome = 'artifact-plan-closure';
  const kinds = new Set(canonicalArtifacts.map((record) => record.artifactKind));
  if (!outcome && kinds.has('static-retained-asset')) outcome = 'retained-assets';
  if (!outcome && kinds.has('validator-test')) outcome = 'validation';
  if (!outcome && (kinds.has('proof-executable') || kinds.has('evidence-output') || kinds.has('evidence-collector-schema'))) outcome = 'proof-evidence';
  if (!outcome && kinds.has('source-module')) outcome = 'implementation-realisation';
  if (!outcome && [...kinds].some((kind) => /runtime|deployment|materialisation|support/.test(kind))) outcome = 'runtime-materialisation';
  const layers = sortUnique(canonicalArtifacts.flatMap((record) => record.requiredSemanticLayers));
  if (!outcome) for (const layer of layers) if (layerOutcomes.has(layer)) { outcome = layerOutcomes.get(layer); break; }
  if (!outcome && currentArtifacts.some((record) => record.artifactFamily === 'documentation-assets')) outcome = 'canonical-generation';
  if (!outcome) outcome = 'canonical-generation';
  const families = sortUnique(currentArtifacts.map((record) => record.artifactFamily));
  const pathFamilies = sortUnique(currentArtifacts.map((record) => pathFamily(record.path)));
  // Until graph authority assigns a canonical ArtefactPlan, the bounded path
  // family is the only defensible architectural execution boundary. Splitting
  // the same unresolved module into implementation, verification and evidence
  // packages manufactures bidirectional prerequisites from ordinary imports.
  // Co-own the unresolved path family instead; no edge is mechanically
  // softened and no canonical output or disposition is invented.
  if (outcome === 'artifact-plan-closure') {
    return `${outcome}:${pathFamilies.join('+') || 'graph-defined'}`;
  }
  return `${outcome}:${families.join('+') || 'graph-defined'}:${pathFamilies.join('+') || 'graph-defined'}`;
}

function ensureUnique(records, key, label) {
  const seen = new Set();
  for (const record of records) {
    const value = typeof key === 'function' ? key(record) : record[key];
    if (seen.has(value)) throw new Error(`duplicate ${label}: ${value}`);
    seen.add(value);
  }
}

function complexityFor(packageState, mappingsByArtifact) {
  const drivers = [];
  const evidence = [];
  const add = (driver, measure, value, reason) => {
    if (drivers.includes(driver)) return;
    drivers.push(driver);
    evidence.push({ driver, measure, value, reason });
  };
  const layerCount = packageState.requiredSemanticLayers.size;
  const canonicalOutcomeCount = packageState.canonicalArtifactKeys.size;
  const gateCount = packageState.equivalenceGates.size;
  const responsibilityCount = packageState.productionResponsibilities.size;
  const families = new Set([...packageState.artifactKeys].map((key) => packageState.artifactByKey.get(key)?.artifactFamily).filter(Boolean));
  const mappings = [...packageState.artifactKeys].map((key) => mappingsByArtifact.get(key)).filter(Boolean);
  const ambiguousMappings = mappings.filter((mapping) => mapping.ambiguities.length > 0 || mapping.conflicts.length > 0).length;
  const reuseRiskCount = [...packageState.reuseActions.values()].filter((entry) => !['adopt', 'none'].includes(entry.action)).length;
  if (layerCount > 1) add('semantic-depth', 'required-semantic-layer-count', layerCount, 'The outcome crosses multiple governed semantic layers.');
  add('canonical-outcome-count', 'canonical-outcome-count', canonicalOutcomeCount, canonicalOutcomeCount > 1 ? 'Multiple canonical outputs must close as one architectural outcome.' : 'The package has an explicit bounded canonical or no-output outcome.');
  if ([...packageState.canonicalArtifacts.values()].some((record) => record.artifactKind === 'source-module')) add('algorithmic-complexity', 'algorithmic-contract-presence', true, 'Executable source realization requires behavioural contract logic.');
  if ([...packageState.artifactKeys].some((key) => packageState.artifactByKey.get(key)?.artifactFamily === 'implementation')) add('framework-coupling', 'implementation-family-presence', true, 'Implementation ownership carries framework integration constraints.');
  if ([...packageState.canonicalArtifacts.values()].some((record) => record.materialisationContract !== null)) add('external-ecosystem', 'materialisation-contract-presence', true, 'The outcome depends on a separately verified external materialisation.');
  if (responsibilityCount > 1) add('generator-renderer-count', 'production-responsibility-count', responsibilityCount, 'The outcome coordinates multiple production responsibilities.');
  if (gateCount > 1) add('proof-equivalence-complexity', 'proof-equivalence-gate-count', gateCount, 'Multiple independent gates must pass before replacement closure.');
  if (reuseRiskCount > 0) add('migration-reuse-risk', 'nontrivial-reuse-action-count', reuseRiskCount, 'Reuse actions require wrapping, rewriting, templating, or replacement.');
  if (families.size > 1) add('cross-domain-coordination', 'artifact-family-count', families.size, 'The outcome crosses artifact ownership domains.');
  if (ambiguousMappings > 0) add('ambiguous-behaviour', 'ambiguous-mapping-count', ambiguousMappings, 'Mapping ambiguity requires architectural review before execution.');
  drivers.sort();
  evidence.sort(compareBy(['driver', 'measure']));
  const level = drivers.length >= 8 ? 'programme' : drivers.length >= 6 ? 'large' : drivers.length >= 3 ? 'medium' : 'small';
  return { level, drivers, evidence };
}

function packageState(outcome, artifactByKey) {
  return {
    outcome,
    artifactByKey,
    artifactKeys: new Set(),
    missingEntirelyKeys: new Set(),
    canonicalArtifactKeys: new Set(),
    replacementGroupKeys: new Set(),
    reuseActions: new Map(),
    equivalenceGates: new Map(),
    canonicalArtifacts: new Map(),
    requiredSemanticLayers: new Set(),
    semanticInputs: new Set(),
    productionResponsibilities: new Set()
  };
}

function workPackageKey(outcome) {
  return `work-package-${sha256(`architectural-outcome\0${outcome}`).slice(0, 20)}`;
}

function addGate(state, gate, sourceKey, gateClass) {
  const gateKey = typeof gate === 'string' ? gate : gate.gateKey;
  if (!gateKey) throw new Error(`equivalence gate lacks identity: ${sourceKey}`);
  const current = state.equivalenceGates.get(gateKey);
  const mechanism = typeof gate === 'string' ? null : gate.mechanism ?? null;
  if (current && current.mechanism !== mechanism && mechanism !== null) throw new Error(`conflicting equivalence gate: ${gateKey}`);
  state.equivalenceGates.set(gateKey, { gateKey, mechanism: current?.mechanism ?? mechanism, gateClass, sources: sortUnique([...(current?.sources ?? []), sourceKey]) });
}

function normaliseArguments(first, rest) {
  if (!Array.isArray(first)) return first;
  const [mappings, missingEntirely, canonicalArtifacts, replacementGroups, baselinePackages] = rest;
  return { artifacts: first, mappings, missingEntirely, canonicalArtifacts, replacementGroups, baselinePackages };
}

export function buildWorkPackages(first, ...rest) {
  const {
    artifacts,
    mappings,
    missingEntirely,
    canonicalArtifacts,
    replacementGroups,
    baselinePackages = readBaselinePackageMembership()
  } = normaliseArguments(first, rest);
  for (const [label, records] of Object.entries({ artifacts, mappings, missingEntirely, canonicalArtifacts, replacementGroups, baselinePackages })) {
    if (!Array.isArray(records)) throw new Error(`${label} must be an array`);
  }
  ensureUnique(artifacts, 'artifactKey', 'artifact key');
  ensureUnique(missingEntirely, 'missingKey', 'missing-entirely key');
  ensureUnique(canonicalArtifacts, 'canonicalArtifactKey', 'canonical artifact key');
  ensureUnique(replacementGroups, 'groupKey', 'replacement group key');
  ensureUnique(baselinePackages, 'key', 'baseline package key');
  const artifactByKey = new Map(artifacts.map((record) => [record.artifactKey, record]));
  const canonicalByKey = new Map(canonicalArtifacts.map((record) => [record.canonicalArtifactKey, record]));
  const mappingByArtifact = new Map(mappings.map((record) => [record.artifactKey, record]));
  if (mappingByArtifact.size !== artifacts.length || artifacts.some((record) => !mappingByArtifact.has(record.artifactKey))) throw new Error('artifact mapping ownership is not closed');
  const states = new Map();
  const artifactOwners = new Map();
  const canonicalOwners = new Map();
  const replacementOwners = new Map();
  const reuseOwners = new Map();
  const gateOwners = new Map();
  const semanticLayerOwners = new Map();
  const semanticLayerArtifactOwners = new Map();
  const requiredCanonicalLayers = new Set(canonicalArtifacts.flatMap((record) => record.requiredSemanticLayers));
  for (const artifact of canonicalArtifacts) {
    if (!Array.isArray(artifact.ownedSemanticLayers)) throw new Error(`canonical artifact lacks explicit semantic layer ownership: ${artifact.canonicalArtifactKey}`);
    for (const layer of artifact.ownedSemanticLayers) {
      if (!artifact.requiredSemanticLayers.includes(layer)) throw new Error(`canonical artifact owns an undeclared semantic layer: ${artifact.canonicalArtifactKey}:${layer}`);
      const existing = semanticLayerArtifactOwners.get(layer);
      if (existing) throw new Error(`semantic layer has multiple canonical artifact owners: ${layer}:${existing}:${artifact.canonicalArtifactKey}`);
      semanticLayerArtifactOwners.set(layer, artifact.canonicalArtifactKey);
    }
  }
  const missingCanonicalLayerOwners = [...requiredCanonicalLayers].filter((layer) => !semanticLayerArtifactOwners.has(layer)).sort();
  if (missingCanonicalLayerOwners.length) throw new Error(`semantic layer lacks canonical artifact owner: ${missingCanonicalLayerOwners.join(',')}`);
  const stateFor = (outcome) => {
    if (!states.has(outcome)) states.set(outcome, packageState(outcome, artifactByKey));
    return states.get(outcome);
  };
  for (const replacement of [...replacementGroups].sort(compareBy(['groupKey']))) {
    const current = replacement.currentArtifacts.map((key) => artifactByKey.get(key));
    const canonical = replacement.canonicalArtifacts.map((key) => canonicalByKey.get(key));
    if (current.some((record) => !record) || canonical.some((record) => !record)) throw new Error(`replacement references missing artifact: ${replacement.groupKey}`);
    const outcome = outcomeFor({ canonicalArtifacts: canonical, currentArtifacts: current });
    const owner = workPackageKey(outcome);
    const state = stateFor(outcome);
    state.replacementGroupKeys.add(replacement.groupKey);
    replacementOwners.set(replacement.groupKey, owner);
    for (const artifact of current) {
      if (artifactOwners.has(artifact.artifactKey)) throw new Error(`artifact has multiple replacement owners: ${artifact.artifactKey}`);
      artifactOwners.set(artifact.artifactKey, owner);
      state.artifactKeys.add(artifact.artifactKey);
    }
    for (const artifact of canonical) {
      if (canonicalOwners.has(artifact.canonicalArtifactKey)) throw new Error(`canonical artifact has multiple replacement owners: ${artifact.canonicalArtifactKey}`);
      canonicalOwners.set(artifact.canonicalArtifactKey, owner);
      state.canonicalArtifactKeys.add(artifact.canonicalArtifactKey);
      state.canonicalArtifacts.set(artifact.canonicalArtifactKey, artifact);
      artifact.requiredSemanticLayers.forEach((value) => state.requiredSemanticLayers.add(value));
      for (const layer of artifact.ownedSemanticLayers) {
        semanticLayerOwners.set(layer, owner);
      }
      artifact.semanticInputs.forEach((value) => state.semanticInputs.add(value));
      artifact.productionResponsibilities.forEach((value) => state.productionResponsibilities.add(value));
      for (const gate of artifact.equivalenceContract.gates ?? []) addGate(state, gate, artifact.canonicalArtifactKey, 'equivalence');
      for (const gate of artifact.acceptanceGates ?? []) addGate(state, gate, artifact.canonicalArtifactKey, 'acceptance');
    }
    replacement.reuseActions.forEach((action, index) => {
      const reuseActionKey = `${replacement.groupKey}:reuse:${index}`;
      state.reuseActions.set(reuseActionKey, { reuseActionKey, replacementGroupKey: replacement.groupKey, action });
      reuseOwners.set(reuseActionKey, owner);
    });
    for (const gate of replacement.equivalenceGates) addGate(state, gate, replacement.groupKey, 'equivalence');
    for (const gate of replacement.proofEvidenceGates) addGate(state, gate, replacement.groupKey, 'proof');
  }
  if (artifactOwners.size !== artifacts.length) throw new Error('artifact primary ownership is not closed');
  if (canonicalOwners.size !== canonicalArtifacts.length) throw new Error('canonical artifact primary ownership is not closed');
  if (replacementOwners.size !== replacementGroups.length) throw new Error('replacement group primary ownership is not closed');
  const gapOwners = new Map();
  for (const gap of missingEntirely) {
    const owner = artifactOwners.get(gap.artifactKey);
    if (!owner) throw new Error(`missing-entirely record lacks artifact owner: ${gap.missingKey}`);
    gapOwners.set(gap.missingKey, owner);
    const state = [...states.values()].find((candidate) => workPackageKey(candidate.outcome) === owner);
    state.missingEntirelyKeys.add(gap.missingKey);
    gap.requiredSemanticLayers.forEach((value) => state.requiredSemanticLayers.add(value));
  }
  const workPackages = [...states.values()].map((state) => {
    const key = workPackageKey(state.outcome);
    const complexity = complexityFor(state, mappingByArtifact);
    const primaryOwnership = {
      artifactKeys: [...state.artifactKeys].sort(),
      missingEntirelyKeys: [...state.missingEntirelyKeys].sort(),
      canonicalArtifactKeys: [...state.canonicalArtifactKeys].sort(),
      replacementGroupKeys: [...state.replacementGroupKeys].sort(),
      reuseActionKeys: [...state.reuseActions.keys()].sort(),
      equivalenceGateKeys: [...state.equivalenceGates.keys()].sort()
    };
    return {
      key,
      title: `${state.outcome.split(':')[0].split('-').map((word) => word[0].toUpperCase() + word.slice(1)).join(' ')} — ${state.outcome.split(':').slice(1).join(' / ')}`,
      architecturalOutcome: outcomeDefinitions[state.outcome.split(':')[0]] ?? 'Resolve a bounded path/family outcome from explicit graph authority without inventing canonical targets or dispositions.',
      outcomeClass: state.outcome,
      primaryOwnership,
      artifactKeys: primaryOwnership.artifactKeys,
      missingEntirelyKeys: primaryOwnership.missingEntirelyKeys,
      canonicalArtifactKeys: primaryOwnership.canonicalArtifactKeys,
      replacementGroupKeys: primaryOwnership.replacementGroupKeys,
      reuseActions: [...state.reuseActions.values()].sort(compareBy(['reuseActionKey'])),
      equivalenceGates: [...state.equivalenceGates.values()].sort(compareBy(['gateKey'])),
      semanticInputs: [...state.semanticInputs].sort(),
      ownedSemanticLayers: [...semanticLayerOwners].filter(([, owner]) => owner === key).map(([layer]) => layer).sort(),
      requiredSemanticLayers: [...state.requiredSemanticLayers].sort(),
      productionResponsibilities: [...state.productionResponsibilities].sort(),
      acceptanceCriteria: [
        { criterionKey: `${key}:ownership`, requirement: 'Every scoped entity has this package as its sole primary owner.', evidence: [`ownership-index:${key}:${sha256(canonicalJson(primaryOwnership))}`] },
        { criterionKey: `${key}:equivalence`, requirement: 'Every scoped equivalence and proof gate passes before replacement or removal.', evidence: primaryOwnership.equivalenceGateKeys.length ? primaryOwnership.equivalenceGateKeys : [`closed-no-gate-disposition:${key}`] },
        { criterionKey: `${key}:canonical-outcome`, requirement: 'Canonical outputs and closed no-output dispositions satisfy their production contracts.', evidence: primaryOwnership.canonicalArtifactKeys.length ? primaryOwnership.canonicalArtifactKeys : primaryOwnership.replacementGroupKeys }
      ],
      complexity: complexity.level,
      complexityDrivers: complexity.drivers,
      complexityEvidence: complexity.evidence,
      safeParallelism: { boundary: state.outcome, sharedInputs: [...state.semanticInputs].sort(), coordinationRule: 'Parallel execution is safe only when shared semantic inputs and canonical target paths remain unchanged.' },
      confidence: (() => {
        const ownedMappings = [...state.artifactKeys].map((artifactKey) => mappingByArtifact.get(artifactKey)).filter(Boolean);
        const score = ownedMappings.length ? Math.min(...ownedMappings.map((mapping) => mapping.mappingConfidence?.score ?? 0.1)) : 0.1;
        return { level: score >= 0.9 ? 'high' : score >= 0.5 ? 'medium' : 'low', score, reasons: score >= 0.9 ? ['exact-machine-verifiable-input'] : ['unmet-graph-authority'] };
      })(),
      reviewStatus: 'machine-reviewed'
    };
  }).sort(compareBy(['key']));
  ensureUnique(workPackages, 'key', 'work package key');
  const ownership = {
    artifacts: [...artifactOwners].map(([ownedKey, primaryWorkPackage]) => ({ ownedKey, primaryWorkPackage })).sort(compareBy(['ownedKey'])),
    missingEntirely: [...gapOwners].map(([ownedKey, primaryWorkPackage]) => ({ ownedKey, primaryWorkPackage })).sort(compareBy(['ownedKey'])),
    canonicalArtifacts: [...canonicalOwners].map(([ownedKey, primaryWorkPackage]) => ({ ownedKey, primaryWorkPackage })).sort(compareBy(['ownedKey'])),
    semanticLayers: [...semanticLayerOwners].map(([ownedKey, primaryWorkPackage]) => ({ ownedKey, primaryWorkPackage })).sort(compareBy(['ownedKey'])),
    replacementGroups: [...replacementOwners].map(([ownedKey, primaryWorkPackage]) => ({ ownedKey, primaryWorkPackage })).sort(compareBy(['ownedKey'])),
    reuseActions: [...reuseOwners].map(([ownedKey, primaryWorkPackage]) => ({ ownedKey, primaryWorkPackage })).sort(compareBy(['ownedKey'])),
    equivalenceGates: workPackages.flatMap((record) => record.equivalenceGates.map((gate) => ({ ownedKey: gate.gateKey, primaryWorkPackage: record.key }))).sort(compareBy(['ownedKey']))
  };
  for (const record of ownership.equivalenceGates) {
    if (gateOwners.has(record.ownedKey)) throw new Error(`equivalence gate has multiple primary owners: ${record.ownedKey}`);
    gateOwners.set(record.ownedKey, record.primaryWorkPackage);
  }
  validateWorkPackageOwnership(workPackages, ownership);
  const workPackageLineage = buildWorkPackageLineage({ baselinePackages, workPackages, artifacts });
  return { workPackages, workPackageLineage, ownership };
}

export function validateWorkPackageOwnership(workPackages, ownership) {
  const packageKeys = new Set(workPackages.map((record) => record.key));
  const packageByKey = new Map(workPackages.map((record) => [record.key, record]));
  const ownershipFields = {
    artifacts: 'artifactKeys',
    missingEntirely: 'missingEntirelyKeys',
    canonicalArtifacts: 'canonicalArtifactKeys',
    semanticLayers: 'ownedSemanticLayers',
    replacementGroups: 'replacementGroupKeys',
    reuseActions: 'reuseActions',
    equivalenceGates: 'equivalenceGates'
  };
  for (const [kind, records] of Object.entries(ownership)) {
    ensureUnique(records, 'ownedKey', `${kind} ownership`);
    for (const record of records) {
      if (!packageKeys.has(record.primaryWorkPackage)) throw new Error(`${kind} owner is not a work package: ${record.ownedKey}`);
      const owned = packageByKey.get(record.primaryWorkPackage)[ownershipFields[kind]];
      const declared = owned.some((entry) => (typeof entry === 'string' ? entry : entry.reuseActionKey ?? entry.gateKey) === record.ownedKey);
      if (!declared) throw new Error(`${kind} owner does not declare scoped identity: ${record.ownedKey}`);
    }
  }
  for (const record of workPackages) {
    if (typeof record.outcomeClass !== 'string' || !record.outcomeClass.includes(':')) throw new Error(`invalid bounded architectural outcome: ${record.key}`);
    if (record.complexityEvidence.some((item) => /(?:byte|line|row|file)-?count|byte-?size/i.test(item.measure))) throw new Error(`forbidden sizing evidence: ${record.key}`);
    if (record.complexityDrivers.length !== record.complexityEvidence.length) throw new Error(`complexity evidence is incomplete: ${record.key}`);
  }
}

export function buildWorkPackageLineage({ baselinePackages, workPackages, artifacts }) {
  const ownerByArtifact = new Map(workPackages.flatMap((record) => record.artifactKeys.map((key) => [key, record.key])));
  const artifactByRow = new Map(artifacts.map((record) => [`${record.universe}:${record.path}`, record.artifactKey]));
  const successorsByBaseline = new Map();
  const unmatchedByBaseline = new Map();
  for (const baseline of baselinePackages) {
    const successors = new Set();
    const unmatched = [];
    for (const row of baseline.affectedRows) {
      if (row.startsWith('semantic-layer:')) {
        const layer = row.slice('semantic-layer:'.length);
        const owners = workPackages.filter((record) => record.ownedSemanticLayers.includes(layer)).map((record) => record.key);
        if (owners.length > 1) throw new Error(`semantic layer has multiple primary owners: ${layer}`);
        if (owners.length === 1) successors.add(owners[0]);
        else unmatched.push(row);
      } else {
        const artifactKey = artifactByRow.get(row);
        const owner = artifactKey ? ownerByArtifact.get(artifactKey) : null;
        if (owner) successors.add(owner);
        else unmatched.push(row);
      }
    }
    successorsByBaseline.set(baseline.key, [...successors].sort());
    unmatchedByBaseline.set(baseline.key, unmatched.sort());
  }
  const predecessorCount = new Map();
  for (const successors of successorsByBaseline.values()) for (const successor of successors) predecessorCount.set(successor, (predecessorCount.get(successor) ?? 0) + 1);
  const lineage = baselinePackages.map((baseline) => {
    const successors = successorsByBaseline.get(baseline.key);
    const disposition = successors.length === 0 ? 'retired-invalid-bucket' : successors.length > 1 ? 'split-successors' : predecessorCount.get(successors[0]) > 1 ? 'merged-successor' : 'retained-successor';
    return {
      baselinePackageKey: baseline.key,
      disposition,
      successorWorkPackageKeys: successors,
      matchedArchitecturalOutcomes: workPackages.filter((record) => successors.includes(record.key)).map((record) => record.outcomeClass).sort(),
      baselineCanonicalOutcome: baseline.canonicalOutcome,
      lineageEvidence: {
        affectedArtifactMembership: baseline.affectedRows.filter((row) => artifactByRow.has(row)).sort(),
        affectedSemanticLayers: baseline.affectedRows.filter((row) => row.startsWith('semantic-layer:')).map((row) => row.slice('semantic-layer:'.length)).sort(),
        unmatchedBaselineRows: unmatchedByBaseline.get(baseline.key)
      },
      reviewStatus: 'machine-reviewed'
    };
  }).sort(compareBy(['baselinePackageKey']));
  ensureUnique(lineage, 'baselinePackageKey', 'baseline package lineage');
  if (lineage.length !== baselinePackages.length) throw new Error('baseline package lineage is incomplete');
  return lineage;
}

export const workPackageInternals = { outcomeFor, complexityFor, layerOutcomes };
