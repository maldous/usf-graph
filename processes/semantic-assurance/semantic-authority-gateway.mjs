import { createHash } from 'node:crypto';

import { canonicalGraphDigest } from '../../capabilities/semantic-model-compilation/compiler.mjs';
import {
  MATERIALISATION_CONTRACT,
  createMaterialisationPlan,
  materialisePlan,
  validateMaterialisationPlan,
} from '../../capabilities/repository-external-artefact-materialisation/materialisation-plan.mjs';

const ACCEPTED = 'urn:usf:decisionstate:accepted';
const CONTRACT_REFERENCE = /^(?:urn:usf:[a-z0-9:._-]+|[a-z][a-z0-9]*)$/;
const value = (row, key) => row[key]?.value ?? null;

export function semanticAuthorityInventoryDigest(inventory, triples) {
  if (!Array.isArray(inventory) || !Number.isSafeInteger(triples) || triples < 0) {
    throw new Error('semantic authority witness inventory and triple count are required');
  }
  const body = inventory.map((record) => {
    if (typeof record?.graph !== 'string' || typeof record?.sha256 !== 'string' || !Number.isSafeInteger(record?.triples) || record.triples < 0) {
      throw new Error('semantic authority witness contains an invalid graph record');
    }
    const graphDigest = record.sha256.startsWith('sha256:') ? record.sha256.slice(7) : record.sha256;
    if (!/^[0-9a-f]{64}$/.test(graphDigest)) throw new Error('semantic authority graph digest is invalid');
    return `${record.graph}=${graphDigest}:${record.triples}`;
  }).sort().join('\n');
  return `sha256:${createHash('sha256').update(`${body}\ntotal=${triples}`).digest('hex')}`;
}

export async function readSemanticAuthorityWitness(client) {
  if (!client || typeof client.connectivity !== 'function' || typeof client.select !== 'function' || typeof client.construct !== 'function') {
    throw new Error('semantic authority witness requires connectivity, select and construct operations');
  }
  const [rawTriples, rows] = await Promise.all([
    client.connectivity(),
    client.select('SELECT DISTINCT ?g WHERE { GRAPH ?g { ?s ?p ?o } } ORDER BY ?g'),
  ]);
  const triples = Number(rawTriples);
  if (!Number.isSafeInteger(triples) || triples < 0 || !Array.isArray(rows)) throw new Error('semantic authority witness response is invalid');
  const graphs = rows.map((row) => value(row, 'g'));
  if (graphs.some((graph) => typeof graph !== 'string' || graph.length === 0) || new Set(graphs).size !== graphs.length) {
    throw new Error('semantic authority witness graph inventory is invalid');
  }
  graphs.sort();
  const inventory = [];
  for (const graph of graphs) {
    const content = await client.construct(`CONSTRUCT { ?s ?p ?o } WHERE { GRAPH <${graph}> { ?s ?p ?o } }`, 'application/n-quads');
    const record = await canonicalGraphDigest(content);
    if (record.triples > 0) inventory.push({ graph, ...record });
  }
  return Object.freeze({
    algorithm: 'sha256-rdfc10-graph-inventory-v2',
    digest: semanticAuthorityInventoryDigest(inventory, triples),
    inventory: Object.freeze(inventory),
    triples,
  });
}

const MATERIALISATION_RULE_WHERE = `
  ?family a <urn:usf:ontology:ArtefactFamily> ;
          <urn:usf:ontology:canonicalName> ?familyName ;
          <urn:usf:ontology:usesMaterialisationRule> ?rule .
  ?rule <urn:usf:ontology:usesStorageClass> ?storage ;
        <urn:usf:ontology:usesRepresentationFormat> ?format ;
        <urn:usf:ontology:usesNamingRule> ?naming .
  ?naming <urn:usf:ontology:filenamePattern> ?namingPattern .
  OPTIONAL { ?rule <urn:usf:ontology:usesPathRole> ?pathRole }
  FILTER NOT EXISTS { ?family <urn:usf:ontology:semanticAdequacyDisposition> ?familyDisposition . FILTER(?familyDisposition != <urn:usf:semanticadequacydisposition:independentlywarrantedretained>) }
  FILTER NOT EXISTS { ?rule <urn:usf:ontology:semanticAdequacyDisposition> ?ruleDisposition . FILTER(?ruleDisposition != <urn:usf:semanticadequacydisposition:independentlywarrantedretained>) }
  FILTER NOT EXISTS { ?naming <urn:usf:ontology:semanticAdequacyDisposition> ?namingDisposition . FILTER(?namingDisposition != <urn:usf:semanticadequacydisposition:independentlywarrantedretained>) }
`;

function authorityDigest(witness) {
  const digest = witness?.digest || witness?.authorityDigest;
  if (typeof digest !== 'string') throw new Error('authority witness is missing its digest');
  return digest.startsWith('sha256:') ? digest : `sha256:${digest}`;
}

async function resolveContract(client, reference) {
  if (!CONTRACT_REFERENCE.test(reference || '')) throw new Error('invalid semantic contract reference');
  if (reference.startsWith('urn:')) return reference;
  const rows = await client.select(`SELECT ?contract WHERE { ?contract a <urn:usf:ontology:SemanticContract> ; <urn:usf:ontology:canonicalName> "${reference}" } LIMIT 2`);
  if (rows.length !== 1) throw new Error('semantic contract reference must resolve exactly once');
  return value(rows[0], 'contract');
}

export function createSemanticAuthorityGateway({ client, readAuthorityWitness }) {
  if (!client || typeof client.select !== 'function') throw new Error('semantic authority client is required');
  if (typeof readAuthorityWitness !== 'function') throw new Error('authority witness reader is required');

  async function layoutContext(contractReference = MATERIALISATION_CONTRACT) {
    const contract = await resolveContract(client, contractReference);
    const [witness, contractRows, roleRows, ruleRows, ruleCountRows] = await Promise.all([
      readAuthorityWitness(client),
      client.select(`SELECT ?canonicalName ?lifecycle ?activation ?proof ?proofState ?decision ?decisionState ?authorisedPath WHERE {
        <${contract}> <urn:usf:ontology:canonicalName> ?canonicalName .
        OPTIONAL { <${contract}> <urn:usf:ontology:semanticLifecycleState> ?lifecycle }
        OPTIONAL { <${contract}> <urn:usf:ontology:hasActivationState> ?activation }
        OPTIONAL { <${contract}> <urn:usf:ontology:reliesOnProofResult> ?proof . ?proof <urn:usf:ontology:hasProofResultState> ?proofState . }
        OPTIONAL { ?realisation <urn:usf:ontology:realisesContract> <${contract}> ; <urn:usf:ontology:authorisedByDecision> ?decision . ?decision <urn:usf:ontology:decisionState> ?decisionState . OPTIONAL { ?decision <urn:usf:ontology:authorisesSourcePath> ?authorisedPath } }
      } ORDER BY ?authorisedPath LIMIT 256`),
      client.select('SELECT ?role ?canonicalName ?parent ?onDemand WHERE { ?role a <urn:usf:ontology:PathRole> ; <urn:usf:ontology:canonicalName> ?canonicalName ; <urn:usf:ontology:authorisedParentPath> ?parent ; <urn:usf:ontology:materialisesOnDemand> ?onDemand . FILTER NOT EXISTS { ?role <urn:usf:ontology:semanticAdequacyDisposition> ?disposition . FILTER(?disposition != <urn:usf:semanticadequacydisposition:independentlywarrantedretained>) } } ORDER BY ?canonicalName LIMIT 256'),
      client.select(`SELECT ?family ?familyName ?storage ?pathRole ?format ?namingPattern WHERE { ${MATERIALISATION_RULE_WHERE} } ORDER BY ?familyName ?format LIMIT 512`),
      client.select(`SELECT (COUNT(*) AS ?count) WHERE { ${MATERIALISATION_RULE_WHERE} }`),
    ]);
    if (contractRows.length === 0) throw new Error('semantic contract does not exist in current authority');
    const expectedRuleCount = Number(value(ruleCountRows[0], 'count'));
    if (ruleCountRows.length !== 1 || !Number.isSafeInteger(expectedRuleCount) || expectedRuleCount !== ruleRows.length) {
      throw new Error('materialisation rule projection is incomplete');
    }
    const observedDigest = authorityDigest(witness);
    if (client.expectedAuthorityDigest && client.expectedAuthorityDigest !== observedDigest) throw new Error('observed semantic authority digest differs from configured digest');
    const decisions = new Map();
    for (const row of contractRows) {
      const id = value(row, 'decision');
      if (!id) continue;
      const state = value(row, 'decisionState');
      const decision = decisions.get(id) || { id, state, authorisedPaths: new Set() };
      if (decision.state !== state) throw new Error('realisation decision has inconsistent state');
      const path = value(row, 'authorisedPath');
      if (path) decision.authorisedPaths.add(path);
      decisions.set(id, decision);
    }
    const accepted = [...decisions.values()].filter((decision) => decision.state === ACCEPTED);
    const selected = accepted.length === 1 ? accepted[0] : null;
    const head = contractRows[0];
    return {
      schemaVersion: 1,
      authorityDigest: observedDigest,
      authorityDigestAlgorithm: witness.algorithm || 'sha256-rdfc10-graph-inventory-v2',
      authorityGraphInventory: witness.inventory || [],
      contract: {
        id: contract,
        canonicalName: value(head, 'canonicalName'),
        lifecycleState: value(head, 'lifecycle'),
        activationState: value(head, 'activation'),
        proofResult: value(head, 'proof'),
        proofResultState: value(head, 'proofState'),
        decision: selected?.id ?? null,
        decisionState: selected?.state ?? null,
      },
      acceptedDecisionCount: accepted.length,
      authorisedPaths: selected ? [...selected.authorisedPaths].sort() : [],
      pathRoles: roleRows.map((row) => ({ id: value(row, 'role'), canonicalName: value(row, 'canonicalName'), parent: value(row, 'parent'), onDemand: value(row, 'onDemand') === 'true' })),
      materialisationRuleCount: expectedRuleCount,
      rules: ruleRows.map((row) => ({ family: value(row, 'family'), familyName: value(row, 'familyName'), storageClass: value(row, 'storage'), pathRole: value(row, 'pathRole'), representationFormat: value(row, 'format'), namingPattern: value(row, 'namingPattern') })),
    };
  }

  return Object.freeze({
    layoutContext,

    async createPlan({ contract = MATERIALISATION_CONTRACT, operations }) {
      return createMaterialisationPlan(await layoutContext(contract), operations, contract);
    },

    async validatePlan(plan) {
      return validateMaterialisationPlan(await layoutContext(plan?.contract), plan);
    },

    async materialise({ plan, repositoryRoot, casRoot, apply = false, coordinator = false }) {
      if (apply && coordinator !== true) throw new Error('materialisation apply requires explicit coordinator authority');
      return materialisePlan({ authority: await layoutContext(plan?.contract), plan, repositoryRoot, casRoot, apply });
    },

    async health() {
      const [triples, witness] = await Promise.all([client.connectivity(), readAuthorityWitness(client)]);
      const observedDigest = authorityDigest(witness);
      if (client.expectedAuthorityDigest && client.expectedAuthorityDigest !== observedDigest) throw new Error('observed semantic authority digest differs from configured digest');
      return { triples, authorityDigest: observedDigest };
    },
  });
}
