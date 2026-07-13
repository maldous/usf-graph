import { compareBy, readJsonl, sha256, sortUnique } from './canonical.mjs';
import { validateDependency } from './contract.mjs';
import { prerequisiteDependencySatisfactionStatus, dependencyEvidenceFamilies, dependencyKeyFor, dependencyResolutionBasis } from './dependency-resolution.mjs';

function ownerMaps(packages) {
  const maps = { artifacts: new Map(), canonical: new Map(), layers: new Map(), gates: new Map() };
  for (const pkg of packages) {
    for (const key of pkg.artifactKeys ?? []) maps.artifacts.set(key, pkg.key);
    for (const key of pkg.canonicalArtifactKeys ?? []) maps.canonical.set(key, pkg.key);
    for (const key of pkg.ownedSemanticLayers ?? []) {
      if (maps.layers.has(key)) throw new Error(`semantic layer has multiple package owners: ${key}:${maps.layers.get(key)}:${pkg.key}`);
      maps.layers.set(key, pkg.key);
    }
    for (const gate of pkg.equivalenceGates ?? []) maps.gates.set(gate.gateKey ?? gate, pkg.key);
  }
  return maps;
}

function addCandidate(candidates, source, prerequisite, dependencyType, evidence, status = 'required-prerequisite') {
  if (!source || !prerequisite || source === prerequisite) return;
  const key = `${source}\0${prerequisite}`;
  const candidate = candidates.get(key) ?? {
    source, prerequisite, dependencyType, status,
    reasonCode: dependencyType,
    semanticEvidence: [], artifactEvidence: [], repositoryRelationshipEvidence: [],
    proofEquivalenceEvidence: [], migrationEvidence: [],
    confidence: { level: 'medium', score: 0.7, reasons: ['machine-observed-direct-evidence'] },
    reviewStatus: 'machine-reviewed'
  };
  if (candidate.status === 'coordination' && status === 'required-prerequisite') candidate.status = 'required-prerequisite';
  if (evidence.semantic) candidate.semanticEvidence.push(evidence.semantic);
  if (evidence.artifact) candidate.artifactEvidence.push(evidence.artifact);
  if (evidence.relationship) candidate.repositoryRelationshipEvidence.push(evidence.relationship);
  if (evidence.proof) candidate.proofEquivalenceEvidence.push(evidence.proof);
  if (evidence.migration) candidate.migrationEvidence.push(evidence.migration);
  candidates.set(key, candidate);
}

function relationshipDependencyStatus(relation, sourceArtifact) {
  const keyPath = relation.attributes?.keyPath ?? '';
  // Aggregation selectors and path aliases declare compilation scope or name
  // resolution. They coordinate the configuration with the selected artefact;
  // they do not make the selected implementation a prerequisite for authoring
  // the configuration. Inheritance (`extends`) and executable imports remain
  // required prerequisites. This classification comes from the structural JSON pointer and
  // is therefore not cycle-driven dependency softening.
  if (relation.extractionMethod === 'json-pointer' &&
      /^(?:include|exclude)(?:\.|$)|^compilerOptions[.]paths(?:\.|$)/.test(keyPath)) {
    return 'coordination';
  }
  if (/^markdown-/.test(relation.extractionMethod)) return 'coordination';
  if (relation.extractionMethod === 'json-pointer' && relation.relationshipType === 'references' &&
      ['documentation-assets', 'repository-governance'].includes(sourceArtifact?.artifactFamily)) {
    return 'coordination';
  }
  return 'required-prerequisite';
}

function reachable(edges, start, goal, excluded) {
  const queue = [start];
  const seen = new Set();
  while (queue.length) {
    const item = queue.shift();
    if (item === goal) return true;
    if (seen.has(item)) continue;
    seen.add(item);
    for (const edge of edges) if (edge !== excluded && edge.source === item && !seen.has(edge.prerequisite)) queue.push(edge.prerequisite);
  }
  return false;
}

function hasCycle(edges) {
  const nodes = sortUnique(edges.flatMap((edge) => [edge.source, edge.prerequisite]));
  const visiting = new Set();
  const visited = new Set();
  const prerequisites = new Map(nodes.map((node) => [node, []]));
  for (const edge of edges) prerequisites.get(edge.source).push(edge.prerequisite);
  function visit(node) {
    if (visiting.has(node)) return true;
    if (visited.has(node)) return false;
    visiting.add(node);
    for (const next of prerequisites.get(node)) if (visit(next)) return true;
    visiting.delete(node);
    visited.add(node);
    return false;
  }
  return nodes.some(visit);
}

function cycleComponents(edges) {
  const nodes = sortUnique(edges.flatMap((edge) => [edge.source, edge.prerequisite]));
  const adjacency = new Map(nodes.map((node) => [node, []]));
  for (const edge of edges) adjacency.get(edge.source).push(edge.prerequisite);
  let index = 0;
  const indexes = new Map();
  const lowlinks = new Map();
  const stack = [];
  const onStack = new Set();
  const components = [];
  const visit = (node) => {
    indexes.set(node, index);
    lowlinks.set(node, index);
    index += 1;
    stack.push(node);
    onStack.add(node);
    for (const next of adjacency.get(node)) {
      if (!indexes.has(next)) {
        visit(next);
        lowlinks.set(node, Math.min(lowlinks.get(node), lowlinks.get(next)));
      } else if (onStack.has(next)) lowlinks.set(node, Math.min(lowlinks.get(node), indexes.get(next)));
    }
    if (lowlinks.get(node) !== indexes.get(node)) return;
    const component = [];
    let item;
    do {
      item = stack.pop();
      onStack.delete(item);
      component.push(item);
    } while (item !== node);
    const selfCycle = component.length === 1 && adjacency.get(component[0]).includes(component[0]);
    if (component.length > 1 || selfCycle) components.push(component.sort());
  };
  nodes.forEach((node) => { if (!indexes.has(node)) visit(node); });
  return components.sort((left, right) => left[0].localeCompare(right[0]));
}

function transitiveReduction(edges) {
  const kept = [];
  const removed = [];
  for (const edge of edges.slice().sort(compareBy(['source', 'prerequisite']))) {
    const others = [...kept, ...edges.filter((candidate) => candidate !== edge && !kept.includes(candidate))];
    if (reachable(others, edge.source, edge.prerequisite, edge)) removed.push(edge);
    else kept.push(edge);
  }
  return { kept, removed };
}

function graphMetrics(packages, prerequisites) {
  const incoming = new Map(packages.map((pkg) => [pkg.key, []]));
  const outgoing = new Map(packages.map((pkg) => [pkg.key, []]));
  for (const edge of prerequisites) {
    incoming.get(edge.source).push(edge.prerequisite);
    outgoing.get(edge.prerequisite).push(edge.source);
  }
  const indegree = new Map([...incoming].map(([key, values]) => [key, values.length]));
  let frontier = [...indegree].filter(([, count]) => count === 0).map(([key]) => key).sort();
  const waves = [];
  const distance = new Map(frontier.map((key) => [key, 1]));
  let visited = 0;
  while (frontier.length) {
    waves.push(frontier);
    const next = [];
    for (const key of frontier) {
      visited += 1;
      for (const target of outgoing.get(key)) {
        distance.set(target, Math.max(distance.get(target) ?? 1, (distance.get(key) ?? 1) + 1));
        indegree.set(target, indegree.get(target) - 1);
        if (indegree.get(target) === 0) next.push(target);
      }
    }
    frontier = next.sort();
  }
  if (visited !== packages.length) return { criticalPathLength: 0, parallelWaveCount: 0, waves: [] };
  return { criticalPathLength: Math.max(0, ...distance.values()), parallelWaveCount: waves.length, waves };
}

function baselineLineage(packages, dependencies, workPackageLineage) {
  const old = readJsonl(new URL('./baseline/dependencies.jsonl', import.meta.url));
  const successors = new Map();
  for (const lineage of workPackageLineage ?? []) successors.set(lineage.baselinePackageKey, lineage.successorWorkPackageKeys);
  const direct = new Set(dependencies.map((edge) => `${edge.source}\0${edge.prerequisite}`));
  return old.map((edge) => {
    const sources = sortUnique(successors.get(edge.workPackage) ?? []);
    const prerequisites = sortUnique(successors.get(edge.dependsOn) ?? []);
    const retained = sources.some((source) => prerequisites.some((prerequisite) => direct.has(`${source}\0${prerequisite}`)));
    return {
      baselineSource: edge.workPackage,
      baselinePrerequisite: edge.dependsOn,
      successorSources: sources,
      successorPrerequisites: prerequisites,
      disposition: retained ? 'retained-with-evidence' : sources.length && prerequisites.length ? 'represented-indirectly' : 'removed-unsupported',
      reason: retained ? 'successor direct edge has architectural evidence' : 'family-Cartesian baseline relationship is not a direct architectural prerequisite'
    };
  }).sort(compareBy(['baselineSource', 'baselinePrerequisite']));
}

function evaluatePrerequisiteSatisfaction(record, { packageByKey, owners, artifactByPath, relationshipByHash, retainedPrerequisiteKeys, prerequisiteCycleCount }) {
  const exactEvidence = record.repositoryRelationshipEvidence ?? [];
  let currentRelationshipHashCount = 0;
  let structurallyProvenRelationshipHashCount = 0;
  let directionMatchedRelationshipHashCount = 0;
  let currentPrerequisiteArtifactHashCount = 0;
  const currentPrerequisiteArtifacts = new Set();
  for (const evidence of exactEvidence) {
    const matches = relationshipByHash.get(evidence) ?? [];
    if (matches.length !== 1) continue;
    currentRelationshipHashCount += 1;
    const relation = matches[0];
    const resolvedStructural = relation.resolved === true && relation.targetKind === 'artifact' && relation.evidenceKind === 'structurally-proven';
    if (resolvedStructural) structurallyProvenRelationshipHashCount += 1;
    const sourceArtifact = artifactByPath.get(relation.source);
    const prerequisiteArtifact = artifactByPath.get(relation.target);
    if (resolvedStructural && owners.artifacts.get(sourceArtifact?.artifactKey) === record.source && owners.artifacts.get(prerequisiteArtifact?.artifactKey) === record.prerequisite) directionMatchedRelationshipHashCount += 1;
    if (prerequisiteArtifact && prerequisiteArtifact.sourceState !== 'deleted' && /^[a-f0-9]{64}$/.test(prerequisiteArtifact.contentDigest ?? '')) {
      currentPrerequisiteArtifactHashCount += 1;
      currentPrerequisiteArtifacts.add(prerequisiteArtifact.artifactKey);
    }
  }
  const edgeKey = `${record.source}\0${record.prerequisite}`;
  const basis = {
    exactEvidenceHashCount: exactEvidence.length,
    currentRelationshipHashCount,
    structurallyProvenRelationshipHashCount,
    directionMatchedRelationshipHashCount,
    currentPrerequisiteArtifactHashCount,
    currentPrerequisiteArtifactCount: currentPrerequisiteArtifacts.size,
    sourceEndpointExists: packageByKey.has(record.source),
    prerequisiteEndpointExists: packageByKey.has(record.prerequisite),
    edgeSurvivedTransitiveReduction: retainedPrerequisiteKeys.has(edgeKey),
    requiredPrerequisiteGraphAcyclic: prerequisiteCycleCount === 0,
  };
  return { satisfactionBasis: basis, satisfactionStatus: prerequisiteDependencySatisfactionStatus(basis) };
}

function resolveRetainedDependencies({ dependencies, packages, artifacts, canonicalArtifacts, replacementGroups, relationships, prerequisiteCycleCount, retainedPrerequisiteKeys }) {
  if (prerequisiteCycleCount !== 0) throw new Error('dependency resolution requires an acyclic required-prerequisite graph');
  const packageByKey = new Map(packages.map((record) => [record.key, record]));
  const owners = ownerMaps(packages);
  const artifactByPath = new Map(artifacts.map((record) => [record.path, record]));
  const relationshipByHash = new Map();
  for (const relation of relationships) {
    const key = sha256(`${relation.source}\0${relation.relationshipType}\0${relation.target}`);
    if (!relationshipByHash.has(key)) relationshipByHash.set(key, []);
    relationshipByHash.get(key).push(relation);
  }
  const canonicalByKey = new Map(canonicalArtifacts.map((record) => [record.canonicalArtifactKey, record]));
  const replacementByKey = new Map(replacementGroups.map((record) => [record.groupKey, record]));
  for (const record of dependencies) {
    if (!packageByKey.has(record.source) || !packageByKey.has(record.prerequisite) || record.source === record.prerequisite) throw new Error(`dependency resolution endpoint invalid: ${record.source}:${record.prerequisite}`);
    if (record.reviewStatus !== 'machine-reviewed' || dependencyEvidenceFamilies(record).length === 0) throw new Error(`dependency resolution evidence invalid: ${record.source}:${record.prerequisite}`);
    for (const evidence of record.repositoryRelationshipEvidence) {
      const matches = relationshipByHash.get(evidence) ?? [];
      const valid = matches.some((relation) => {
        const sourceArtifact = artifactByPath.get(relation.source);
        const prerequisiteArtifact = artifactByPath.get(relation.target);
        return relation.resolved === true && relation.targetKind === 'artifact' && relation.evidenceKind === 'structurally-proven' &&
          owners.artifacts.get(sourceArtifact?.artifactKey) === record.source && owners.artifacts.get(prerequisiteArtifact?.artifactKey) === record.prerequisite;
      });
      if (!valid) throw new Error(`dependency relationship evidence does not prove direction and ownership: ${evidence}`);
    }
    for (const layer of record.semanticEvidence) {
      if (!packageByKey.get(record.source).requiredSemanticLayers?.includes(layer) || owners.layers.get(layer) !== record.prerequisite) throw new Error(`dependency semantic evidence does not prove direction and ownership: ${layer}`);
    }
    for (const evidence of record.artifactEvidence) {
      const canonicalKey = [...canonicalByKey.keys()].find((key) => evidence.startsWith(`${key}:`));
      const dependencyPath = canonicalKey ? evidence.slice(canonicalKey.length + 1) : null;
      const dependencyArtifact = dependencyPath ? artifactByPath.get(dependencyPath) : null;
      if (!canonicalKey || owners.canonical.get(canonicalKey) !== record.source || !canonicalByKey.get(canonicalKey).artifactDependencies.includes(dependencyPath) || owners.artifacts.get(dependencyArtifact?.artifactKey) !== record.prerequisite) throw new Error(`dependency artifact evidence does not prove direction and ownership: ${evidence}`);
    }
    for (const evidence of record.proofEquivalenceEvidence) if (owners.gates.get(evidence) !== record.prerequisite) throw new Error(`dependency proof evidence does not prove prerequisite ownership: ${evidence}`);
    for (const evidence of record.migrationEvidence) {
      const group = replacementByKey.get(evidence);
      const groupPackages = sortUnique([...(group?.currentArtifacts ?? []).map((key) => owners.artifacts.get(key)), ...(group?.canonicalArtifacts ?? []).map((key) => owners.canonical.get(key))].filter(Boolean));
      if (!group || groupPackages[0] !== record.prerequisite || !groupPackages.slice(1).includes(record.source)) throw new Error(`dependency migration evidence does not prove ordering: ${evidence}`);
    }
  }
  return dependencies.map((record) => {
    const resolved = { ...record, dependencyKey: dependencyKeyFor(record), resolutionStatus: 'resolved-retained' };
    resolved.resolutionBasis = dependencyResolutionBasis(resolved);
    if (resolved.status === 'required-prerequisite') {
      Object.assign(resolved, evaluatePrerequisiteSatisfaction(resolved, { packageByKey, owners, artifactByPath, relationshipByHash, retainedPrerequisiteKeys, prerequisiteCycleCount }));
      if (resolved.satisfactionStatus !== 'satisfied') throw new Error(`required prerequisite is not satisfied: ${resolved.source}:${resolved.prerequisite}`);
    }
    validateDependency(resolved);
    return resolved;
  });
}

export function buildDependencyGraph(packages, artifacts, canonicalArtifacts, replacementGroups, relationships, workPackageLineage = []) {
  const owners = ownerMaps(packages);
  const artifactByPath = new Map(artifacts.map((artifact) => [artifact.path, artifact]));
  const candidates = new Map();
  for (const relation of relationships) {
    if (!relation.resolved || relation.targetKind !== 'artifact') continue;
    const sourceArtifact = artifactByPath.get(relation.source);
    const targetArtifact = artifactByPath.get(relation.target);
    const source = sourceArtifact && owners.artifacts.get(sourceArtifact.artifactKey);
    const prerequisite = targetArtifact && owners.artifacts.get(targetArtifact.artifactKey);
    addCandidate(candidates, source, prerequisite, 'canonical-artifact-input', { relationship: sha256(`${relation.source}\0${relation.relationshipType}\0${relation.target}`) }, relationshipDependencyStatus(relation, sourceArtifact));
  }
  for (const artifact of canonicalArtifacts) {
    const source = owners.canonical.get(artifact.canonicalArtifactKey);
    for (const dependency of artifact.artifactDependencies ?? []) {
      const targetArtifact = artifactByPath.get(dependency);
      addCandidate(candidates, source, targetArtifact && owners.artifacts.get(targetArtifact.artifactKey), 'canonical-artifact-input', { artifact: `${artifact.canonicalArtifactKey}:${dependency}` });
    }
    for (const layer of artifact.requiredSemanticLayers ?? []) {
      addCandidate(candidates, source, owners.layers.get(layer), 'semantic-language-prerequisite', { semantic: layer });
    }
  }
  for (const group of replacementGroups) {
    const packageKeys = sortUnique([...group.currentArtifacts.map((key) => owners.artifacts.get(key)), ...group.canonicalArtifacts.map((key) => owners.canonical.get(key))].filter(Boolean));
    for (let index = 1; index < packageKeys.length; index += 1) addCandidate(candidates, packageKeys[index], packageKeys[0], 'replacement-migration-ordering', { migration: group.groupKey }, 'coordination');
  }
  let dependencies = [...candidates.values()].map((record) => ({
    ...record,
    semanticEvidence: sortUnique(record.semanticEvidence), artifactEvidence: sortUnique(record.artifactEvidence),
    repositoryRelationshipEvidence: sortUnique(record.repositoryRelationshipEvidence), proofEquivalenceEvidence: sortUnique(record.proofEquivalenceEvidence),
    migrationEvidence: sortUnique(record.migrationEvidence)
  }));
  const prerequisites = dependencies.filter((record) => record.status === 'required-prerequisite');
  const cycles = cycleComponents(prerequisites);
  const reduced = cycles.length ? { kept: prerequisites, removed: [] } : transitiveReduction(prerequisites);
  const keptKeys = new Set(reduced.kept.map((edge) => `${edge.source}\0${edge.prerequisite}`));
  dependencies = dependencies.filter((edge) => edge.status === 'coordination' || keptKeys.has(`${edge.source}\0${edge.prerequisite}`)).sort(compareBy(['status', 'source', 'prerequisite']));
  dependencies = resolveRetainedDependencies({ dependencies, packages, artifacts, canonicalArtifacts, replacementGroups, relationships, prerequisiteCycleCount: cycles.length, retainedPrerequisiteKeys: keptKeys });
  const requiredPrerequisites = dependencies.filter((edge) => edge.status === 'required-prerequisite');
  const metrics = graphMetrics(packages, requiredPrerequisites);
  const resolvedPrerequisiteRelationshipCount = requiredPrerequisites.filter((edge) => edge.resolutionStatus === 'resolved-retained').length;
  const satisfiedPrerequisiteRelationshipCount = requiredPrerequisites.filter((edge) => edge.satisfactionStatus === 'satisfied').length;
  return {
    dependencies,
    lineage: baselineLineage(packages, dependencies, workPackageLineage),
    metrics: {
      ...metrics,
      requiredPrerequisiteRelationshipCount: requiredPrerequisites.length,
      resolvedPrerequisiteRelationshipCount,
      satisfiedPrerequisiteRelationshipCount,
      blockingRelationshipCount: 0,
      activeBlockingRelationshipCount: requiredPrerequisites.length - satisfiedPrerequisiteRelationshipCount,
      coordinationRelationshipCount: dependencies.filter((edge) => edge.status === 'coordination').length,
      transitiveLinksRemoved: reduced.removed.length,
      familyOnlyLinkCount: 0,
      untypedLinkCount: 0,
      unsupportedEvidenceCount: 0,
      requiredPrerequisiteCycleCount: cycles.length,
      requiredPrerequisiteCycleComponents: cycles,
      unreviewedParallelismReductionCount: cycles.length
    }
  };
}

export const dependencyGraphInternals = { cycleComponents, evaluatePrerequisiteSatisfaction, graphMetrics, hasCycle, ownerMaps, relationshipDependencyStatus, transitiveReduction };
