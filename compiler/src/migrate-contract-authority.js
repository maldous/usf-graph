import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DataFactory, Parser, Store, Writer } from 'n3';

const { namedNode, literal, quad } = DataFactory;
const HERE = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(HERE, '..', '..', '..', '..');
const GRAPH_DIR = join(REPOSITORY_ROOT, 'v2/usf/graph');
const CONTRACT_DIR = join(REPOSITORY_ROOT, 'spec/instances/semantic-contract');
const CENSUS_ARTIFACTS = join(REPOSITORY_ROOT, 'v2/usf/census/artifacts.jsonl');
const OUTPUT = join(GRAPH_DIR, 'contracts/semantic-depth.trig');
const GRAPH = namedNode('urn:usf:graph:semanticdepth');
const RDF_TYPE = namedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type');
const USF = 'urn:usf:ontology:';
const p = (local) => namedNode(`${USF}${local}`);
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const canonical = (value) => value.toLowerCase().replace(/[^a-z0-9]/g, '');

const reviewedOverrides = new Map([
]);

const REQUIRED_UI_NONCLAIMS = Object.freeze([
  'urn:usf:nonclaim:nohumanacceptance',
  'urn:usf:nonclaim:nouiproductparity',
  'urn:usf:nonclaim:noaccessibilitycompliance',
  'urn:usf:nonclaim:nolaunchi18n',
]);

const lifecycleOverrides = new Map([
  ['semantic-contract.alerting-incident-management-on-call-status-page', {
    successor: 'observabilitybuiltinalertingandincidents',
    statement: 'This deprecated contract is retained as source-lineage identity only. Its canonical successor is the observability built-in alerting and incidents contract, so none of its facets is a generation obligation.',
  }],
]);

function parseJsonl(path) {
  return readFileSync(path, 'utf8').split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
}

function one(store, subject, predicate, label) {
  const values = store.getObjects(subject, predicate, null);
  if (values.length !== 1) throw new Error(`${label} requires exactly one value for ${subject.value}; observed ${values.length}`);
  return values[0];
}

function sanitiseStatement(value) {
  const statement = value
    .replace(/fresh USF proof pending USF-[0-9]+(?:\/USF-[0-9]+)*/gi, 'fresh proof remains pending')
    .trim();
  if (/linear[.]app|github[.]com|gitlab[.]com|refs\/heads|commitSha|branchName|issueId|projectId|ADR-[0-9]|USF-[0-9]/i.test(statement)) {
    throw new Error('semantic statement contains forbidden external coordination metadata');
  }
  return statement;
}

const capabilityStore = new Store(new Parser({ format: 'application/trig' }).parse(
  readFileSync(join(GRAPH_DIR, 'contracts/capabilities.trig'), 'utf8'),
));
const uiAuthorityStore = new Store();
for (const relative of [
  'claims.ttl', 'contracts/interfaces.trig', 'contracts/policies.trig', 'contracts/experience.trig',
  'contracts/ui.trig', 'realisation/renderers.trig',
]) {
  const format = relative.endsWith('.ttl') ? 'text/turtle' : 'application/trig';
  uiAuthorityStore.addQuads(new Parser({ format }).parse(readFileSync(join(GRAPH_DIR, relative), 'utf8')));
}

function uiFacetAuthority(contract, _facet) {
  const capabilities = capabilityStore.getSubjects(p('hasContract'), contract, null);
  if (capabilities.length !== 1) throw new Error(`UI facet requires exactly one capability for ${contract.value}`);
  const capability = capabilities[0];
  const exposure = one(uiAuthorityStore, capability, p('uiExposure'), 'capability UI exposure').value;
  const models = uiAuthorityStore.getObjects(capability, p('hasUISemanticModel'), null);
  const capabilityName = one(capabilityStore, capability, p('canonicalName'), 'capability canonicalName').value;
  if (exposure !== 'urn:usf:uiexposureclass:uiexposed') {
    if (models.length !== 0) throw new Error(`non-UI-exposed capability has a UI semantic model: ${capability.value}`);
    const posture = exposure.split(':').at(-1);
    const rationale = posture === 'apionly'
      ? `The ${capabilityName} capability is explicitly API-only; no human-rendered surface, component, action, journey, consent prompt, or renderer input is authorised. Any UI requires a deliberate exposure amendment.`
      : posture === 'internal'
        ? `The ${capabilityName} capability is explicitly internal; no product or operator UI is authorised. Any UI requires a deliberate exposure amendment.`
        : `The ${capabilityName} capability is explicitly not exposed; no product or operator UI is authorised. Any UI requires a deliberate exposure amendment.`;
    return { status: 'notapplicable', statement: rationale, nonclaims: REQUIRED_UI_NONCLAIMS };
  }
  if (models.length !== 1) throw new Error(`UI-exposed capability requires exactly one UI semantic model: ${capability.value}`);
  const model = models[0];
  for (const [property, label] of [
    ['hasJourney', 'journey'], ['hasViewModel', 'view model'], ['hasSurface', 'surface'],
    ['hasAccessibilityProfile', 'accessibility profile'], ['hasLocalisationProfile', 'localisation profile'],
    ['rendererContract', 'renderer contract'],
  ]) if (uiAuthorityStore.getObjects(model, p(property), null).length === 0) {
    throw new Error(`UI semantic model lacks ${label}: ${model.value}`);
  }
  for (const surface of uiAuthorityStore.getObjects(model, p('hasSurface'), null)) {
    if (uiAuthorityStore.getObjects(surface, p('uiRequiresPermission'), null).length === 0) throw new Error(`UI surface lacks permission authority: ${surface.value}`);
    const kinds = uiAuthorityStore.getObjects(surface, p('surfaceKind'), null).map((term) => term.value);
    if (uiAuthorityStore.getQuads(surface, RDF_TYPE, namedNode(`${USF}Form`), null).length > 0 && uiAuthorityStore.getObjects(surface, p('submitsOperation'), null).length !== 1) {
      throw new Error(`UI form requires exactly one submit operation: ${surface.value}`);
    }
    if (kinds.includes('urn:usf:surfacekind:queryview')) {
      const viewModel = one(uiAuthorityStore, surface, p('rendersViewModel'), 'query surface view model');
      if (uiAuthorityStore.getObjects(viewModel, p('loadsOperation'), null).length === 0 || uiAuthorityStore.getObjects(viewModel, p('bindsInterface'), null).length === 0) {
        throw new Error(`UI query view lacks exact operation or interface authority: ${surface.value}`);
      }
    }
  }
  return {
    status: 'complete',
    statement: `The ${capabilityName} capability has one framework-neutral UI semantic model with explicit surfaces, view models, components, journeys, permissions, accessibility, localisation, and target-specific renderer contracts. This semantic closure disclaims product parity, human acceptance, accessibility compliance, and launch-language readiness.`,
    nonclaims: REQUIRED_UI_NONCLAIMS,
  };
}
const contractsByName = new Map();
for (const row of capabilityStore.getQuads(null, RDF_TYPE, namedNode(`${USF}SemanticContract`), null)) {
  contractsByName.set(one(capabilityStore, row.subject, p('canonicalName'), 'contract canonicalName').value, row.subject);
}
const artifactsByPath = new Map(parseJsonl(CENSUS_ARTIFACTS).map((row) => [row.path, row]));
const documents = readdirSync(CONTRACT_DIR).filter((file) => file.endsWith('.json')).sort()
  .map((file) => ({ file, sourcePath: `spec/instances/semantic-contract/${file}`, document: JSON.parse(readFileSync(join(CONTRACT_DIR, file), 'utf8')) }));

if (documents.length !== 67 || contractsByName.size !== 67) {
  throw new Error(`contract migration requires 67 source and 67 target contracts; observed ${documents.length}/${contractsByName.size}`);
}

const quads = [];
const boundBindings = [];
const deprecatedBindings = [];
let artefactPlanCount = 0;
let facetCount = 0;
let overrideCount = 0;
let semanticBindingCount = 0;
for (const { sourcePath, document } of documents) {
  const expectedId = `semantic-contract.${document.capability}`;
  if (document.id !== expectedId) throw new Error(`source contract identity mismatch: ${sourcePath}`);
  const contractName = canonical(document.capability);
  const contract = contractsByName.get(contractName);
  if (!contract) throw new Error(`no explicit target contract selected for ${sourcePath}`);
  const artifact = artifactsByPath.get(sourcePath);
  if (!artifact || artifact.contentDigest !== sha256(readFileSync(join(REPOSITORY_ROOT, sourcePath)))) {
    throw new Error(`current census digest mismatch for ${sourcePath}`);
  }
  const facets = capabilityStore.getObjects(contract, p('declaresFacet'), null);
  const facetsByKind = new Map(facets.map((facet) => {
    const kind = one(capabilityStore, facet, p('facetKind'), 'facet kind').value.split(':').at(-1);
    return [kind, facet];
  }));
  if (facetsByKind.size !== 10 || Object.keys(document.facets).length !== 10) throw new Error(`contract facet cardinality mismatch: ${sourcePath}`);

  const bindingName = `${contractName}semanticsource`;
  const binding = namedNode(`urn:usf:sourcesemanticbinding:${bindingName}`);
  const source = namedNode(`urn:usf:sourceartefact:s${artifact.artifactKey}`);
  quads.push(
    quad(binding, RDF_TYPE, namedNode(`${USF}SourceSemanticBinding`), GRAPH),
    quad(binding, p('canonicalName'), literal(bindingName), GRAPH),
    quad(binding, p('sourceBindingSource'), source, GRAPH),
    quad(binding, p('sourceBindingTarget'), contract, GRAPH),
    quad(binding, p('sourceBindingContentDigest'), literal(artifact.contentDigest), GRAPH),
    quad(binding, p('sourceBindingPath'), literal(sourcePath), GRAPH),
    quad(binding, p('sourceBindingEquivalenceKind'), namedNode('urn:usf:equivalencekind:structural'), GRAPH),
    quad(contract, p('semanticLifecycleState'), namedNode(`urn:usf:semanticlifecyclestate:${canonical(document.lifecycleState)}`), GRAPH),
  );
  boundBindings.push(binding);

  const lifecycleOverride = lifecycleOverrides.get(document.id);
  if (lifecycleOverride) {
    const successor = contractsByName.get(lifecycleOverride.successor);
    if (!successor || canonical(document.lifecycleState) !== 'deprecated') throw new Error(`invalid reviewed lifecycle override: ${sourcePath}`);
    quads.push(quad(contract, p('supersededBy'), successor, GRAPH));
    deprecatedBindings.push(binding);
  } else {
    const outputName = `semanticcontract${contractName}`;
    const plan = namedNode(`urn:usf:artefactplan:${outputName}`);
    const artefact = namedNode(`urn:usf:artefact:${outputName}`);
    const pathRule = namedNode(`urn:usf:pathrule:${outputName}`);
    const outputPath = `contracts/semantic/${contractName}.json`;
    quads.push(
      quad(namedNode('urn:usf:repository:foundation'), p('hasArtefactPlan'), plan, GRAPH),
      quad(plan, RDF_TYPE, namedNode(`${USF}ArtefactPlan`), GRAPH),
      quad(plan, p('canonicalName'), literal(outputName), GRAPH),
      quad(plan, p('ownedByRepository'), namedNode('urn:usf:repository:foundation'), GRAPH),
      quad(plan, p('plansArtefact'), artefact, GRAPH),
      quad(plan, p('plansSemanticResource'), contract, GRAPH),
      quad(artefact, RDF_TYPE, namedNode(`${USF}Artefact`), GRAPH),
      quad(artefact, p('canonicalName'), literal(outputName), GRAPH),
      quad(artefact, p('artefactKind'), namedNode('urn:usf:artefactkind:contract'), GRAPH),
      quad(artefact, p('canonicalPath'), literal(outputPath), GRAPH),
      quad(artefact, p('governedByPathRule'), pathRule, GRAPH),
      quad(artefact, p('generatedByComponent'), namedNode('urn:usf:generator:semanticcontract'), GRAPH),
      quad(pathRule, RDF_TYPE, namedNode(`${USF}PathRule`), GRAPH),
      quad(pathRule, p('canonicalName'), literal(outputName), GRAPH),
      quad(pathRule, p('pathPattern'), literal(outputPath), GRAPH),
      quad(binding, p('sourceBindingArtefactPlan'), plan, GRAPH),
      quad(binding, p('sourceBindingEquivalenceRule'), namedNode('urn:usf:equivalencerule:semanticcontractprojection'), GRAPH),
      quad(binding, p('sourceBindingTarget'), plan, GRAPH),
      quad(binding, p('sourceBindingTarget'), artefact, GRAPH),
    );
    artefactPlanCount += 1;
  }

  let overridden = Boolean(lifecycleOverride);
  for (const [sourceKind, sourceFacet] of Object.entries(document.facets)) {
    const kind = sourceKind === 'uiSemanticDefinition' ? 'uisemantics' : canonical(sourceKind);
    const facet = facetsByKind.get(kind);
    if (!facet) throw new Error(`no explicit target facet selected for ${sourcePath}#${sourceKind}`);
    const override = lifecycleOverride
      ? {
          status: 'notapplicable',
          statement: lifecycleOverride.statement,
          nonclaims: sourceKind === 'uiSemanticDefinition' ? REQUIRED_UI_NONCLAIMS : [],
        }
      : sourceKind === 'uiSemanticDefinition'
        ? uiFacetAuthority(contract, facet)
        : reviewedOverrides.get(`${document.id}#${sourceKind}`);
    if (override) { overridden = true; overrideCount += 1; }
    const status = override?.status ?? canonical(sourceFacet.status);
    const statement = sanitiseStatement(override?.statement ?? sourceFacet.description ?? '');
    if (!statement) throw new Error(`identity-only source facet requires a reviewed override: ${sourcePath}#${sourceKind}`);
    if (!['complete', 'gap', 'notapplicable'].includes(status)) throw new Error(`unsupported facet status ${status}: ${sourcePath}#${sourceKind}`);
    quads.push(
      quad(binding, p('sourceBindingTarget'), facet, GRAPH),
      quad(facet, p('facetStatus'), namedNode(`urn:usf:facetstatus:${status}`), GRAPH),
      quad(facet, p('facetStatement'), literal(statement), GRAPH),
    );
    for (const nonclaim of override?.nonclaims ?? []) quads.push(quad(contract, p('disclaims'), namedNode(nonclaim), GRAPH));
    facetCount += 1;
  }
  if (!overridden) {
    quads.push(quad(binding, p('sourceBindingEquivalenceKind'), namedNode('urn:usf:equivalencekind:semantic'), GRAPH));
    semanticBindingCount += 1;
  }
}

const policy = namedNode('urn:usf:sourcedispositionpolicy:semanticcontractsource');
quads.push(
  quad(policy, RDF_TYPE, namedNode(`${USF}SourceDispositionPolicy`), GRAPH),
  quad(policy, p('canonicalName'), literal('semanticcontractsource'), GRAPH),
  quad(policy, p('policyDispositionKind'), namedNode('urn:usf:dispositionkind:retireafterequivalence'), GRAPH),
  quad(policy, p('policyDispositionBasis'), namedNode('urn:usf:dispositionbasis:explicitplanlink'), GRAPH),
  quad(policy, p('policyDispositionBasis'), namedNode('urn:usf:dispositionbasis:exactsemanticbinding'), GRAPH),
  quad(policy, p('policyDispositionBasis'), namedNode('urn:usf:dispositionbasis:independentintegrityobservation'), GRAPH),
  quad(policy, p('policyDecisionState'), namedNode('urn:usf:dispositiondecisionstate:accepted'), GRAPH),
  quad(policy, p('policyOutputMode'), namedNode('urn:usf:dispositionoutputmode:canonicaloutput'), GRAPH),
  quad(policy, p('policyPrecedence'), literal(40), GRAPH),
  quad(policy, p('policyGenerationInputRole'), namedNode('urn:usf:generationinputrole:equivalencesubject'), GRAPH),
  quad(policy, p('isDefaultDispositionPolicy'), literal(false), GRAPH),
  quad(policy, p('isActiveDispositionPolicy'), literal(true), GRAPH),
  quad(policy, p('decisionRationale'), literal('Each selected source is joined through an exact authored identity, path, and content-digest binding to its contract, facets, and source-specific canonical output plan. It remains an equivalence subject until the graph-generated contract projection passes semantic equivalence.'), GRAPH),
);
const deprecatedBindingNames = new Set(deprecatedBindings.map((binding) => binding.value));
for (const binding of boundBindings.filter((item) => !deprecatedBindingNames.has(item.value)).sort((a, b) => a.value.localeCompare(b.value))) {
  quads.push(quad(policy, p('policyMatchesSourceBinding'), binding, GRAPH));
}

const deprecatedPolicy = namedNode('urn:usf:sourcedispositionpolicy:deprecatedsemanticcontractsource');
quads.push(
  quad(deprecatedPolicy, RDF_TYPE, namedNode(`${USF}SourceDispositionPolicy`), GRAPH),
  quad(deprecatedPolicy, p('canonicalName'), literal('deprecatedsemanticcontractsource'), GRAPH),
  quad(deprecatedPolicy, p('policyDispositionKind'), namedNode('urn:usf:dispositionkind:excludenoncanonical'), GRAPH),
  quad(deprecatedPolicy, p('policyDispositionBasis'), namedNode('urn:usf:dispositionbasis:exactsemanticbinding'), GRAPH),
  quad(deprecatedPolicy, p('policyDispositionBasis'), namedNode('urn:usf:dispositionbasis:independentintegrityobservation'), GRAPH),
  quad(deprecatedPolicy, p('policyDecisionState'), namedNode('urn:usf:dispositiondecisionstate:accepted'), GRAPH),
  quad(deprecatedPolicy, p('policyOutputMode'), namedNode('urn:usf:dispositionoutputmode:nooutput'), GRAPH),
  quad(deprecatedPolicy, p('policyPrecedence'), literal(40), GRAPH),
  quad(deprecatedPolicy, p('policyGenerationInputRole'), namedNode('urn:usf:generationinputrole:equivalencesubject'), GRAPH),
  quad(deprecatedPolicy, p('isDefaultDispositionPolicy'), literal(false), GRAPH),
  quad(deprecatedPolicy, p('isActiveDispositionPolicy'), literal(true), GRAPH),
  quad(deprecatedPolicy, p('decisionRationale'), literal('The exact bound source declares a deprecated contract with an authored canonical successor. It is retained for lineage and excluded from semantic generation inputs.'), GRAPH),
);
for (const binding of deprecatedBindings.sort((a, b) => a.value.localeCompare(b.value))) {
  quads.push(quad(deprecatedPolicy, p('policyMatchesSourceBinding'), binding, GRAPH));
}

const writer = new Writer({ format: 'application/trig' });
writer.addQuads(quads);
const output = await new Promise((resolveOutput, reject) => writer.end((error, value) => error ? reject(error) : resolveOutput(value)));
mkdirSync(dirname(OUTPUT), { recursive: true });
writeFileSync(OUTPUT, output, 'utf8');
process.stdout.write(`${JSON.stringify({ output: 'v2/usf/graph/contracts/semantic-depth.trig', contracts: documents.length, facets: facetCount, bindings: documents.length, artefactPlans: artefactPlanCount, semanticBindings: semanticBindingCount, reviewedFacetOverrides: overrideCount, reviewedLifecycleOverrides: lifecycleOverrides.size, triples: quads.length, sha256: sha256(output) })}\n`);
