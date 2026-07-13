import { compareBy, sha256 } from './canonical.mjs';
import { assertUnique, validateConfidence } from './contract.mjs';

const families = ['automation', 'documentation-assets', 'implementation', 'machine-semantics', 'proof-evidence', 'repository-governance', 'runtime-topology', 'v2-support', 'verification'];

function add(score, evidence, family, points, reason, source) {
  score[family] += points;
  evidence.push({ family, points, reason, source });
}

function contentScores(member, parsed, relations, inventory) {
  const score = Object.fromEntries(families.map((family) => [family, 0]));
  const evidence = [];
  const syntax = parsed.syntaxKind;
  const declarationKinds = new Set(parsed.declarations.map((entry) => entry.kind));
  const declarationIdentifiers = parsed.declarations.map((entry) => String(entry.identifier ?? '').toLowerCase());
  const executableOwnerIdentifiers = parsed.declarations.filter((entry) => ['async-function', 'class', 'export', 'function', 'method'].includes(entry.kind)).map((entry) => String(entry.identifier ?? '').toLowerCase());
  const relationTypes = new Set(relations.map((entry) => entry.relationshipType));
  if (['rdf-turtle', 'rdf-trig', 'sparql', 'graphql', 'json-schema'].includes(syntax) || [...declarationKinds].some((kind) => /^(?:semantic-resource|schema-contract|shacl-node-shape|owl-(?:class|object-property|datatype-property)|sparql-operation|graphql-(?:operation|type))$/.test(kind))) add(score, evidence, 'machine-semantics', 8, 'parsed semantic structure', parsed.parserImplementation);
  if (syntax === 'workflow-yaml' || [...declarationKinds].some((kind) => /^(?:workflow|workflow-job|automation-trigger)$/.test(kind)) || relationTypes.has('uses-action') || relationTypes.has('triggers')) add(score, evidence, 'automation', 8, 'parsed workflow execution structure', parsed.parserImplementation);
  if (['compose-yaml', 'dockerfile', 'sql'].includes(syntax) || [...declarationKinds].some((kind) => /^(?:service|container|migration|table|volume|port|runtime)$/.test(kind)) || relationTypes.has('persists-to') || relationTypes.has('health-checks')) add(score, evidence, 'runtime-topology', 7, 'parsed runtime or data topology', parsed.parserImplementation);
  const fixtureStructure = parsed.pathContext === 'fixture-or-test' && declarationIdentifiers.some((identifier) => /(?:^|[.:-])(?:expected|fixture|invalid|valid)(?:$|[.:-])/.test(identifier));
  const testFrameworkImport = parsed.relationships.some((entry) => entry.targetKind === 'package' && /^(?:node:)?(?:test|assert)$/.test(entry.target));
  if (fixtureStructure || testFrameworkImport || executableOwnerIdentifiers.some((identifier) => /test|assert|validator|fixture|defect/.test(identifier)) || [...declarationKinds].some((kind) => /^(?:test|fixture|validator|assertion|defect)$/.test(kind)) || relationTypes.has('tests') || relationTypes.has('validates') || relationTypes.has('uses-fixture')) add(score, evidence, 'verification', 9, 'parsed validation role', parsed.parserImplementation);
  if (executableOwnerIdentifiers.some((identifier) => /proof|evidence|collector|ingest|attestation/.test(identifier)) || [...declarationKinds].some((kind) => /^(?:proof|evidence|collector|ingestion|attestation)$/.test(kind)) || relationTypes.has('proves') || relationTypes.has('collects') || relationTypes.has('ingests')) add(score, evidence, 'proof-evidence', 9, 'parsed proof or evidence role', parsed.parserImplementation);
  if (['javascript-typescript', 'python'].includes(syntax) && declarationKinds.size > 0) add(score, evidence, 'implementation', 6, 'parsed executable implementation structure', parsed.parserImplementation);
  if (inventory && ['package-manifest', 'dependency-record', 'keyed-map'].includes(inventory.inventoryKind)) add(score, evidence, 'repository-governance', 6, 'parsed repository inventory role', inventory.inventoryKind);
  if (['make', 'configuration'].includes(syntax) || [...declarationKinds].some((kind) => /command|workspace|package|configuration/.test(kind))) add(score, evidence, 'repository-governance', 5, 'parsed command or configuration role', parsed.parserImplementation);
  if (declarationKinds.has('dependency-declaration')) add(score, evidence, 'repository-governance', 6, 'parsed dependency materialisation declaration', parsed.parserImplementation);
  if (member.byteSize <= 1 && syntax === 'plain-text' && declarationKinds.size === 0) add(score, evidence, 'repository-governance', 4, 'empty textual source placeholder disposition', member.contentDigest);
  if (syntax === 'plain-text' && declarationKinds.has('prose-line')) add(score, evidence, 'documentation-assets', 4, 'parsed prose content', parsed.parserImplementation);
  if (['markdown', 'html', 'svg', 'binary'].includes(syntax) || member.mediaType.startsWith('image/') || member.mediaType.startsWith('font/')) add(score, evidence, 'documentation-assets', 5, 'document or static media structure', member.mediaType);
  if (member.universe === 'v2-support-provisioning' && (relationTypes.has('materialises') || relationTypes.has('configures') || ['shell', 'configuration'].includes(syntax))) add(score, evidence, 'v2-support', 7, 'support materialisation behavior in support universe', parsed.parserImplementation);
  if (member.universe === 'v2-graph-authority') add(score, evidence, 'machine-semantics', 3, 'normative graph authority membership', member.universe);
  if (member.universe === 'v2-compiler-implementation' && ['javascript-typescript', 'structured-json'].includes(syntax)) add(score, evidence, 'implementation', 3, 'compiler implementation membership plus parsed source', member.universe);
  const lower = member.path.toLowerCase();
  if (/test|fixture|validator|defect/.test(lower)) add(score, evidence, 'verification', 1, 'supporting path signal', member.path);
  if (/proof|evidence|collector/.test(lower)) add(score, evidence, 'proof-evidence', 1, 'supporting path signal', member.path);
  if (/docs?\//.test(lower)) add(score, evidence, 'documentation-assets', 1, 'supporting path signal', member.path);
  if (/workflow|\.github/.test(lower)) add(score, evidence, 'automation', 1, 'supporting path signal', member.path);
  return { score, evidence };
}

function confidenceFromScores(sorted, evidence) {
  const first = sorted[0];
  const second = sorted[1];
  const nonPathEvidence = evidence.filter((entry) => entry.reason !== 'supporting path signal' && entry.family === first[0]);
  const margin = first[1] - second[1];
  if (first[1] <= 1 || nonPathEvidence.length === 0) return { level: 'low', score: 0.35, reasons: ['content-role-requires-review'] };
  if (margin < 3) return { level: 'medium', score: 0.68, reasons: ['content-signature', 'cross-family-ownership'] };
  return { level: 'high', score: Math.min(0.98, 0.78 + margin / 40), reasons: ['content-signature', 'content-role-score'] };
}

function authorityStatus(member, family, parsed) {
  if (member.sourceState === 'deleted' || member.path.endsWith('.gitkeep')) return 'transient';
  if (member.universe === 'v2-graph-authority') return member.path.includes('/derived/') ? 'projection' : member.path.includes('/fixtures/') ? 'test' : 'normative';
  if (family === 'implementation') return 'implementation';
  if (family === 'verification') return 'test';
  if (family === 'proof-evidence') return parsed.syntaxKind.includes('json') ? 'evidence' : 'proof';
  if (family === 'machine-semantics') return 'normative';
  if (family === 'documentation-assets') return 'humanprojection';
  if (family === 'runtime-topology' || family === 'repository-governance') return 'configuration';
  return 'operational';
}

export function classifyArtifacts(members, parserResults, relationships, inventories) {
  const parserByPath = new Map(parserResults.map((parsed) => [parsed.path, parsed]));
  const relationsByPath = new Map();
  for (const relation of relationships) {
    if (!relationsByPath.has(relation.source)) relationsByPath.set(relation.source, []);
    relationsByPath.get(relation.source).push(relation);
  }
  const inventoryByPath = new Map(inventories.map((record) => [record.path, record]));
  const records = [];
  for (const member of members) {
    const parsed = parserByPath.get(member.path);
    if (!parsed) throw new Error(`missing parser result for ${member.path}`);
    const relations = relationsByPath.get(member.path) ?? [];
    const { score, evidence } = contentScores(member, parsed, relations, inventoryByPath.get(member.path));
    const sorted = Object.entries(score).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    const machineProposal = sorted[0][0];
    const finalOwner = machineProposal;
    if (!families.includes(finalOwner)) throw new Error(`invalid reviewed family: ${member.path}`);
    const familyConfidence = confidenceFromScores(sorted, evidence);
    validateConfidence(familyConfidence);
    const relationshipConfidence = relations.length === 0
      ? { level: 'medium', score: 0.7, reasons: ['no-structural-relationships-observed'] }
      : { level: relations.some((entry) => entry.confidence.level === 'low') ? 'medium' : 'high', score: Math.min(...relations.map((entry) => entry.confidence.score)), reasons: ['structural-parser-evidence'] };
    validateConfidence(relationshipConfidence);
    records.push({
      artifactKey: sha256(`${member.universe}\0${member.path}`),
      path: member.path,
      universe: member.universe,
      sourceState: member.sourceState,
      contentDigest: member.contentDigest,
      mediaType: member.mediaType,
      fileMode: member.fileMode,
      formatKind: member.formatKind,
      syntaxKind: parsed.syntaxKind,
      parserImplementation: parsed.parserImplementation,
      machineFamilyProposal: machineProposal,
      artifactFamily: finalOwner,
      familyScores: score,
      ownershipEvidence: evidence.filter((entry) => entry.family === finalOwner),
      authorityStatus: authorityStatus(member, finalOwner, parsed),
      formatConfidence: parsed.confidence,
      relationshipConfidence,
      familyConfidence,
      mappingConfidence: { level: 'low', score: 0, reasons: ['mapping-stage-required'] },
      coverageConfidence: { level: 'low', score: 0, reasons: ['mapping-stage-required'] },
      reviewStatus: 'machine-reviewed',
      reviewEvidence: []
    });
  }
  records.sort(compareBy(['universe', 'path']));
  assertUnique(records, (record) => `${record.universe}\0${record.path}`);
  return records;
}

export function familyReviewCandidates(records) {
  return records.filter((record) => record.familyConfidence.level !== 'high' || record.ownershipEvidence.some((entry) => entry.reason === 'supporting path signal'))
    .map((record) => ({ artifactKey: record.artifactKey, path: record.path, universe: record.universe, proposedOwner: record.machineFamilyProposal, confidence: record.familyConfidence, evidence: record.ownershipEvidence }))
    .sort((a, b) => a.confidence.score - b.confidence.score || a.path.localeCompare(b.path));
}
