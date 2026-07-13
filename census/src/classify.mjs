import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJson, compareBy, readJsonl, sortUnique, writeJsonlAtomic } from './canonical.mjs';
import { censusRoot } from './constants.mjs';
import { assertUnique, validateArtifact } from './contract.mjs';

const familyOrder = [
  'repository-governance',
  'automation',
  'implementation',
  'runtime-topology',
  'machine-semantics',
  'verification',
  'proof-evidence',
  'documentation-assets',
  'v2-support'
];

const familyIssueOutcome = {
  'repository-governance': 'repository composition, commands, workspaces, and dependency policy',
  automation: 'CI, runner, and repository automation',
  implementation: 'application, package, adapter, and executable product behavior',
  'runtime-topology': 'runtime topology, deployment, container, and configuration',
  'machine-semantics': 'machine semantics, schemas, contracts, and interface projections',
  verification: 'tests, validators, fixtures, and adversarial checks',
  'proof-evidence': 'proof executables, collectors, evidence, and assurance outputs',
  'documentation-assets': 'documentation, runbooks, reports, requirements, and static assets',
  'v2-support': 'V2 support, provisioning, and execution assets'
};

const reviewedOverridePath = path.join(censusRoot, 'src', 'reviewed-overrides.jsonl');
const reviewedOverrides = fs.existsSync(reviewedOverridePath)
  ? new Map(readJsonl(reviewedOverridePath).map((entry) => [`${entry.universe}\0${entry.path}\0${entry.contentDigest}`, entry.patch]))
  : new Map();

function allMembers() {
  return ['repository-universe.jsonl', 'v2-graph-universe.jsonl', 'v2-compiler-universe.jsonl', 'v2-support-universe.jsonl']
    .flatMap((file) => readJsonl(path.join(censusRoot, file)));
}

export function familyFor(member) {
  const lower = member.path.toLowerCase();
  if (member.universe === 'v2-support-provisioning') return 'v2-support';
  if (member.universe === 'v2-graph-authority') {
    if (lower.includes('/fixtures/') || lower.includes('/shapes') || lower.includes('/rules/') || lower.includes('/execution/validators')) return 'verification';
    if (lower.includes('/assurance/') || lower.includes('/derived/evidence')) return 'proof-evidence';
    return 'machine-semantics';
  }
  if (member.universe === 'v2-compiler-implementation') {
    if (lower.includes('/test/')) return 'verification';
    if (lower.endsWith('/package.json') || lower.endsWith('/package-lock.json') || lower.includes('/node_modules/.package-lock')) return 'repository-governance';
    return 'implementation';
  }
  if (/^\.github\/|\/(?:workflows?|ci|hooks?)\//.test(lower) || /(?:^|\/)(?:jenkinsfile|gitlab-ci|azure-pipelines)/.test(lower)) return 'automation';
  if (/^(?:evidence|artifacts)\//.test(lower) || /(?:^|\/)(?:proof|proofs|evidence|collector|assurance)(?:\/|[-_.])/.test(lower)) return 'proof-evidence';
  if (lower === 'license' || /^docs\//.test(lower) || member.formatKind.startsWith('document-') || member.formatKind.startsWith('image-') || ['font', 'opaque-binary', 'archive'].includes(member.formatKind)) return 'documentation-assets';
  if (/^(?:test|tests|e2e|tools\/validate)/.test(lower) || /(?:^|\/)(?:test|tests|fixtures?|defects?|validator|validation)(?:\/|[-_.])/.test(lower) || /\.(?:test|spec)\.[^.]+$/.test(lower)) return 'verification';
  if (/^spec\//.test(lower) || /\.(?:schema\.json|ttl|trig|rq|sparql|graphql|proto|openapi\.ya?ml|asyncapi\.ya?ml)$/.test(lower)) return 'machine-semantics';
  if (/^(?:infra|config|deploy|docker|k8s|terraform)\//.test(lower) || /(?:compose|dockerfile|caddyfile|prometheus|grafana|loki|tempo|otel|environment|migration)/.test(lower)) return 'runtime-topology';
  if (/^(?:apps|packages|adapters|services)\//.test(lower) || /\/(?:src|lib)\//.test(lower) || /\.(?:js|mjs|cjs|ts|tsx|jsx|py|go|rs|java|swift|kt|c|cpp)$/.test(lower)) return 'implementation';
  return 'repository-governance';
}

function authorityFor(member, family) {
  const lower = member.path.toLowerCase();
  if (member.sourceState === 'ignored-materialised') return 'transient';
  if (lower.endsWith('.gitkeep')) return 'transient';
  if (member.universe === 'v2-graph-authority') {
    if (lower.includes('/fixtures/')) return 'test';
    if (lower.includes('/derived/')) return 'projection';
    if (family === 'proof-evidence') return lower.includes('evidence') ? 'evidence' : 'proof';
    return 'normative';
  }
  return {
    automation: 'operational',
    'documentation-assets': lower.includes('report') ? 'humanprojection' : 'humanprojection',
    implementation: 'implementation',
    'machine-semantics': 'normative',
    'proof-evidence': lower.includes('evidence') || lower.startsWith('artifacts/') ? 'evidence' : 'proof',
    'repository-governance': lower.endsWith('.json') || lower.startsWith('.') ? 'configuration' : 'operational',
    'runtime-topology': 'configuration',
    'v2-support': lower.endsWith('.gitkeep') ? 'transient' : 'operational',
    verification: 'test'
  }[family];
}

function dispositionFor(member, family) {
  const lower = member.path.toLowerCase();
  if (lower.endsWith('.gitkeep')) return { output: 'remove', responsibility: ['none'], generator: null, equivalence: 'none', reuse: 'none', coverage: 'notrequired' };
  if (member.sourceState === 'ignored-materialised') return { output: 'materialise', responsibility: ['package-manager'], generator: 'package-manager', equivalence: 'normalised', reuse: 'none', coverage: 'notrequired' };
  if (member.universe === 'v2-graph-authority') {
    if (lower.includes('/derived/')) return { output: 'derive', responsibility: ['generator'], generator: 'semantic-derivation-engine', equivalence: 'normalised', reuse: 'replace', coverage: 'partial' };
    if (lower.includes('/fixtures/')) return { output: 'generate', responsibility: ['generator'], generator: 'conformance-fixture-renderer', equivalence: 'behavioural', reuse: 'template', coverage: 'partial' };
    return { output: 'retain', responsibility: ['human-authoring'], generator: null, equivalence: 'exact', reuse: 'adopt', coverage: 'partial' };
  }
  if (member.universe === 'v2-compiler-implementation') {
    if (family === 'repository-governance') return { output: lower.endsWith('package-lock.json') ? 'materialise' : 'retain', responsibility: [lower.endsWith('package-lock.json') ? 'package-manager' : 'human-authoring'], generator: lower.endsWith('package-lock.json') ? 'package-manager' : null, equivalence: 'exact', reuse: 'adopt', coverage: 'partial' };
    return { output: 'retain', responsibility: ['human-authoring'], generator: null, equivalence: family === 'verification' ? 'behavioural' : 'behavioural', reuse: 'adopt', coverage: 'partial' };
  }
  if (family === 'proof-evidence' && (/^artifacts\//.test(lower) || /machine-runs|\.claude\/runs/.test(lower))) return { output: 'exclude', responsibility: ['none'], generator: null, equivalence: 'evidential', reuse: 'none', coverage: 'notrequired' };
  if (family === 'documentation-assets' && member.binary) return { output: 'retain', responsibility: ['asset-copier'], generator: 'asset-copier', equivalence: 'exact', reuse: 'adopt', coverage: 'partial' };
  const plans = {
    automation: ['generate', 'renderer', 'automation-renderer', 'behavioural', 'template', 'identityonly'],
    'documentation-assets': ['generate', 'renderer', 'documentation-renderer', 'normalised', 'template', 'partial'],
    implementation: ['generate', 'generator', 'implementation-generator', 'behavioural', 'rewrite', 'identityonly'],
    'machine-semantics': ['derive', 'generator', 'semantic-projection-generator', 'normalised', 'replace', 'partial'],
    'proof-evidence': ['collect', 'collector', 'evidence-collector', 'evidential', 'wrap', 'identityonly'],
    'repository-governance': [lower.endsWith('lock.yaml') || lower.endsWith('package-lock.json') ? 'materialise' : 'generate', lower.includes('lock') ? 'package-manager' : 'template', lower.includes('lock') ? 'package-manager' : 'repository-template-renderer', 'normalised', 'template', 'partial'],
    'runtime-topology': ['generate', 'renderer', 'runtime-topology-renderer', 'behavioural', 'template', 'identityonly'],
    verification: ['generate', 'generator', 'verification-generator', 'behavioural', 'template', 'identityonly'],
    'v2-support': ['retain', 'environment-bootstrap', null, 'behavioural', 'wrap', 'partial']
  };
  const [output, responsibility, generator, equivalence, reuse, coverage] = plans[family];
  return { output, responsibility: [responsibility], generator, equivalence, reuse, coverage };
}

function gapsFor(family, coverage) {
  if (coverage === 'complete' || coverage === 'notrequired') return { gaps: [], layers: [] };
  const map = {
    automation: { gaps: ['missingconstraint', 'missingrenderer', 'missingequivalence'], layers: ['constraints-permissions', 'generation-renderer-contracts', 'equivalence-rules'] },
    'documentation-assets': { gaps: ['missingartifactplan', 'missingrenderer'], layers: ['artifact-output-plans', 'requirements-projections', 'generation-renderer-contracts'] },
    implementation: { gaps: ['missingimplementation', 'missingartifactplan', 'missinggenerator'], layers: ['implementation-obligations', 'artifact-output-plans', 'generation-renderer-contracts'] },
    'machine-semantics': { gaps: ['missingderivation', 'missinggenerator'], layers: ['derivation-integrity', 'artifact-output-plans', 'generation-renderer-contracts'] },
    'proof-evidence': { gaps: ['missingobligation', 'missingcollector', 'missingingestion'], layers: ['proof-obligations', 'evidence-requirements', 'collector-normaliser-ingestion-contracts'] },
    'repository-governance': { gaps: ['missingpolicy', 'missingartifactplan'], layers: ['policy', 'artifact-output-plans', 'generation-renderer-contracts'] },
    'runtime-topology': { gaps: ['missingrelationship', 'missingmaterialisation', 'missingequivalence'], layers: ['provider-service-realisation', 'materialisation-contracts', 'equivalence-rules'] },
    verification: { gaps: ['missingobligation', 'missingfixture', 'missinggenerator'], layers: ['validation-tests-fixtures-defects', 'proof-obligations', 'generation-renderer-contracts'] },
    'v2-support': { gaps: ['missingselfhosting', 'missingmaterialisation', 'missingequivalence'], layers: ['self-hosting-clean-room-support', 'materialisation-contracts', 'equivalence-rules'] }
  };
  return map[family];
}

function riskFor(member, family, coverage) {
  const risks = [];
  if (member.binary) risks.push('binary-static-asset-uncertainty');
  if (member.sourceState === 'ignored-materialised') risks.push('external-ecosystem-dependency');
  if (family === 'implementation') risks.push('framework-coupled-implementation');
  if (family === 'proof-evidence') risks.push('run-specific-evidence');
  if (family === 'v2-support' || family === 'runtime-topology') risks.push('provisioning-boundary');
  if (coverage === 'identityonly') risks.push('missing-behavioural-specification');
  if (coverage === 'partial') risks.push('semantic-ambiguity');
  return sortUnique(risks.length ? risks : ['ambiguous-current-authority']);
}

function sizeFor(member) {
  if (member.byteSize < 1024) return 'trivial';
  if (member.byteSize < 20000) return 'small';
  if (member.byteSize < 100000) return 'medium';
  if (member.byteSize < 1000000) return 'large';
  return 'programme';
}

export function classifyMemberBase(member) {
  const family = familyFor(member);
  const disposition = dispositionFor(member, family);
  const { gaps, layers } = gapsFor(family, disposition.coverage);
  const deterministic = member.universe !== 'repository-output' || family !== 'repository-governance' || member.formatKind !== 'plain-text';
  const record = {
    path: member.path,
    universe: member.universe,
    sourceState: member.sourceState,
    contentDigest: member.contentDigest,
    mediaType: member.mediaType,
    fileMode: member.fileMode,
    formatKind: member.formatKind,
    artifactFamily: family,
    authorityStatus: authorityFor(member, family),
    canonicalOutputRequirement: disposition.output,
    productionResponsibility: disposition.responsibility,
    expectedGenerator: disposition.generator,
    equivalenceClass: disposition.equivalence,
    reuseStrategy: disposition.reuse,
    v2ConceptCoverage: disposition.coverage,
    gapClassification: gaps,
    requiredSemanticLayers: layers,
    implementationSize: sizeFor(member),
    confidence: {
      level: deterministic ? 'high' : 'medium',
      score: deterministic ? 0.95 : 0.7,
      reasons: [deterministic ? 'machine-verifiable-primary-role' : 'content-role-requires-review']
    },
    riskDrivers: riskFor(member, family, disposition.coverage),
    reasonCodes: [member.universe === 'v2-graph-authority' ? 'graph-authority' : member.sourceState === 'ignored-materialised' ? 'external-materialisation' : 'primary-responsibility'],
    primaryOwner: family
  };
  validateArtifact(record);
  return record;
}

export function classifyMember(member) {
  const base = classifyMemberBase(member);
  const patch = reviewedOverrides.get(`${member.universe}\0${member.path}\0${member.contentDigest}`);
  if (!patch) return base;
  const reviewed = { ...base, ...patch };
  validateArtifact(reviewed);
  if (reviewed.artifactFamily !== base.artifactFamily || reviewed.primaryOwner !== base.primaryOwner) {
    throw new Error(`reviewed override changed primary ownership: ${member.path}`);
  }
  return reviewed;
}

export function createAssignments(members = allMembers()) {
  const groups = Object.fromEntries(familyOrder.map((family) => [family, []]));
  for (const member of members) groups[familyFor(member)].push(member);
  for (const family of familyOrder) {
    const directory = path.join(censusRoot, '.work', family);
    fs.mkdirSync(directory, { recursive: true });
    const manifest = {
      assignment: family,
      outcome: familyIssueOutcome[family],
      memberCount: groups[family].length,
      members: groups[family].sort(compareBy(['path']))
    };
    fs.writeFileSync(path.join(directory, 'assignment.json'), canonicalJson(manifest));
  }
  return Object.fromEntries(familyOrder.map((family) => [family, groups[family].length]));
}

export function classifyMembers(members) {
  const records = members.map(classifyMember).sort(compareBy(['universe', 'path']));
  assertUnique(records, (record) => `${record.universe}\0${record.path}`);
  return records;
}

export function classifyAssignment(manifestPath, outputPath) {
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const records = manifest.members.map(classifyMember).sort(compareBy(['path']));
  if (records.some((record) => record.artifactFamily !== manifest.assignment)) throw new Error(`assignment drift for ${manifest.assignment}`);
  assertUnique(records, 'path');
  writeJsonlAtomic(outputPath, records);
  return records;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const counts = createAssignments();
  process.stdout.write(`${JSON.stringify(counts)}\n`);
}
