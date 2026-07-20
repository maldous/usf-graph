import { createHash } from 'node:crypto';
import { lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import N3 from 'n3';
import YAML from 'yaml';
import { universeProofInternals } from './universe-proof.mjs';

const RDF = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#';
const RDFS = 'http://www.w3.org/2000/01/rdf-schema#';
const OWL = 'http://www.w3.org/2002/07/owl#';
const XSD = 'http://www.w3.org/2001/XMLSchema#';
const O = 'urn:usf:ontology:';
const TYPE = `${RDF}type`;
const DOMAIN = `${RDFS}domain`;
const RANGE = `${RDFS}range`;
const SUBCLASS = `${RDFS}subClassOf`;
const SUBPROPERTY = `${RDFS}subPropertyOf`;
const INVERSE = `${OWL}inverseOf`;
const CONTROLLED_VALUE = `${O}ControlledValue`;
const STANDARD_CLASS = `${O}standardDefinesSemanticClass`;
const STANDARD_PROPERTY = `${O}standardDefinesSemanticProperty`;
const PERMUTATION_GRAPH = 'urn:usf:graph:permutation-families';
const FIXTURE_PATH = 'semantic-model/fixtures/conforming/universal-service-foundation.trig';
const RESERVED = 'urn:usf:termusagestate:reservedfuturescope';
const ZERO_BY_DESIGN = 'urn:usf:termusagestate:zeroinstancebydesign';
const FAMILY_REVIEW_CLASS = `${O}PermutationFamilySignatureReview`;
const FAMILY_REVIEW_WARRANTED = 'urn:usf:permutationfamilymodelreviewdisposition:warranted';
const TERM_REVIEW_CLASS = `${O}SemanticTermPermutationReview`;
const REVIEW_COVERAGE_CLASS = `${O}PermutationReviewCoverage`;
const FAMILY_CANDIDATE_CLASS = `${O}PermutationFamilyCandidate`;
const TERM_SET_ALGORITHM = 'semantic-input-term-key-set-v1';
const FAMILY_SIGNATURE_ALGORITHM = 'family-record-canonical-json-sha256-v1';
const SHA256 = /^sha256:[0-9a-f]{64}$/u;
const CLASS_KINDS = new Set([`${OWL}Class`, `${RDFS}Class`]);
const PROPERTY_KINDS = new Set([
  `${OWL}AnnotationProperty`, `${OWL}AsymmetricProperty`, `${OWL}DatatypeProperty`,
  `${OWL}DeprecatedProperty`, `${OWL}FunctionalProperty`, `${OWL}InverseFunctionalProperty`,
  `${OWL}IrreflexiveProperty`, `${OWL}ObjectProperty`, `${OWL}ReflexiveProperty`,
  `${OWL}SymmetricProperty`, `${OWL}TransitiveProperty`, `${RDF}Property`,
]);
const compare = (left, right) => (left < right ? -1 : left > right ? 1 : 0);
const uniqueSorted = (values) => [...new Set(values)].sort(compare);

function normalise(value) {
  if (Array.isArray(value)) return value.map(normalise);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value)
    .sort(compare).map((key) => [key, normalise(value[key])]));
  return value;
}
const canonicalJson = (value) => JSON.stringify(normalise(value));
const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const digest = (value) => sha256(canonicalJson(value));

export class UniversalSemanticCoverageProofError extends Error {
  constructor(code, message, details = {}) {
    super(`${code}: ${message}`);
    this.name = 'UniversalSemanticCoverageProofError';
    this.code = code;
    this.details = details;
  }
}
const fail = (code, message, details) => {
  throw new UniversalSemanticCoverageProofError(code, message, details);
};

function contained(root, target) {
  const value = relative(root, target);
  return value !== '' && value !== '..' && !value.startsWith(`..${sep}`);
}

function verifyAuthorityInput(root, pathArgument, expectedDigest, code) {
  if (typeof pathArgument !== 'string' || !pathArgument || pathArgument.startsWith('/')) {
    fail(code, 'authority input path is invalid');
  }
  const path = resolve(root, pathArgument);
  if (!contained(root, path)) fail(code, 'authority input path escapes repository');
  let stat;
  let canonicalPath;
  try {
    stat = lstatSync(path);
    canonicalPath = realpathSync(path);
  } catch (error) {
    fail(code, 'authority input is absent or cannot be rebound', { causeCode: error?.code, path: pathArgument });
  }
  if (!stat.isFile() || stat.isSymbolicLink() || !contained(root, canonicalPath)) {
    fail(code, 'authority input is not a canonical regular file');
  }
  const bytes = readFileSync(path);
  if (sha256(bytes) !== expectedDigest || sha256(readFileSync(path)) !== expectedDigest) {
    fail(code, 'authority input bytes or rebind digest differ');
  }
  let value;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch {
    fail(code, 'authority input is not JSON');
  }
  return { path: pathArgument, value };
}

function reconstructAuthorityVerification(root, authorityBinding, packetPath, projectionPath) {
  const packet = verifyAuthorityInput(
    root,
    packetPath,
    authorityBinding.authorityPacketDigest,
    'UNIVERSAL_PROOF_AUTHORITY_PACKET_INVALID',
  );
  const projection = verifyAuthorityInput(
    root,
    projectionPath,
    authorityBinding.authorityProjectionDigest,
    'UNIVERSAL_PROOF_AUTHORITY_PROJECTION_INVALID',
  );
  if (packet.value?.recordKind !== 'USF_PERMUTATION_AUTHORITY_INPUT_PACKET'
    || packet.value?.packetSchemaVersion !== 1
    || packet.value?.authorityDigest !== authorityBinding.authorityDigest) {
    fail('UNIVERSAL_PROOF_AUTHORITY_PACKET_INVALID', 'packet identity is invalid');
  }
  if (projection.value?.recordKind !== 'USF_PERMUTATION_AUTHORITY_PROJECTION'
    || projection.value?.schemaVersion !== 1
    || projection.value?.authorityDigest !== authorityBinding.authorityDigest
    || projection.value?.basePacketDigest !== authorityBinding.authorityPacketDigest
    || projection.value?.projectionMethod !== 'BOUNDED_USF_MCP_SELECT'
    || !Array.isArray(projection.value?.triples)
    || !Array.isArray(projection.value?.projectedClassIris)
    || !Array.isArray(projection.value?.projectedPredicateIris)) {
    fail('UNIVERSAL_PROOF_AUTHORITY_PROJECTION_INVALID', 'projection identity is invalid');
  }
  const core = {
    authorityDigest: authorityBinding.authorityDigest,
    authorityPacket: {
      contentDigest: authorityBinding.authorityPacketDigest,
      path: packet.path,
      recordKind: packet.value.recordKind,
      schemaVersion: packet.value.packetSchemaVersion,
    },
    authorityProjection: {
      basePacketDigest: projection.value.basePacketDigest,
      contentDigest: authorityBinding.authorityProjectionDigest,
      path: projection.path,
      projectedClassCount: uniqueSorted(projection.value.projectedClassIris).length,
      projectedPredicateCount: uniqueSorted(projection.value.projectedPredicateIris).length,
      recordKind: projection.value.recordKind,
      schemaVersion: projection.value.schemaVersion,
      tripleCount: projection.value.triples.length,
    },
    fullAuthorityTermParityState: 'NOT_PROVEN_BY_BOUNDED_PROJECTION',
    recordKind: 'USF_VERIFIED_BOUNDED_UNIVERSAL_AUTHORITY_INPUT',
    schemaVersion: 1,
  };
  return { ...core, verificationDigest: digest(core) };
}

function canonicalTerm(term, sourcePath) {
  if (term.termType === 'NamedNode') return { termType: 'NamedNode', value: term.value };
  if (term.termType === 'BlankNode') return { termType: 'BlankNode', value: `${sourcePath}#${term.value}` };
  if (term.termType === 'Literal') return {
    datatypeIri: term.datatype?.value || `${XSD}string`,
    language: term.language || '',
    termType: 'Literal',
    value: term.value,
  };
  if (term.termType === 'DefaultGraph') return { termType: 'DefaultGraph', value: '' };
  fail('UNIVERSAL_PROOF_RDF_TERM_UNSUPPORTED', term.termType);
}

function readSource(root, entry) {
  const modelRoot = join(root, 'semantic-model');
  if (!entry || typeof entry.file !== 'string' || typeof entry.graph !== 'string'
    || !/\.(?:ttl|trig)$/u.test(entry.file) || entry.file.startsWith('/')
    || entry.file.split('/').some((part) => ['', '.', '..'].includes(part))) {
    fail('UNIVERSAL_PROOF_MANIFEST_ENTRY_INVALID', 'invalid semantic source entry', { entry });
  }
  const path = resolve(modelRoot, entry.file);
  if (!contained(root, path)) fail('UNIVERSAL_PROOF_MANIFEST_PATH_ESCAPE', entry.file);
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || !contained(root, realpathSync(path))) {
    fail('UNIVERSAL_PROOF_SOURCE_NOT_REGULAR', entry.file);
  }
  const bytes = readFileSync(path);
  let quads;
  try {
    quads = new N3.Parser({
      blankNodePrefix: `_:s${sha256(entry.file).slice(7)}_`,
      format: entry.file.endsWith('.trig') ? 'application/trig' : 'text/turtle',
    }).parse(bytes.toString('utf8'));
  } catch (error) {
    fail('UNIVERSAL_PROOF_RDF_PARSE_FAILED', error.message, { path: entry.file });
  }
  if (sha256(bytes) !== sha256(readFileSync(path))) fail('UNIVERSAL_PROOF_SOURCE_MUTATED', entry.file);
  const sourceCore = {
    contentDigest: sha256(bytes),
    declaredGraphIri: entry.graph,
    manifestGroup: entry.manifestGroup,
    path: `semantic-model/${entry.file}`,
  };
  const source = { ...sourceCore, sourceRecordDigest: digest(sourceCore) };
  return {
    records: quads.map((quad) => {
      const core = {
        graphIri: quad.graph.termType === 'DefaultGraph' ? entry.graph : quad.graph.value,
        manifestGroup: entry.manifestGroup,
        object: canonicalTerm(quad.object, source.path),
        predicateIri: quad.predicate.value,
        sourceRecordDigest: source.sourceRecordDigest,
        subject: canonicalTerm(quad.subject, source.path),
      };
      return { ...core, occurrenceDigest: digest(core), sourcePath: source.path };
    }),
    source,
  };
}

function sparqlTerms(source) {
  let stripped = '';
  let index = 0;
  let quote = null;
  let triple = false;
  let escaped = false;
  let iri = false;
  while (index < source.length) {
    const character = source[index];
    if (iri) {
      stripped += character;
      index += 1;
      if (character === '>') iri = false;
      continue;
    }
    if (quote !== null) {
      if (escaped) {
        escaped = false;
        stripped += ' ';
        index += 1;
      } else if (character === '\\') {
        escaped = true;
        stripped += ' ';
        index += 1;
      } else if (triple && source.slice(index, index + 3) === quote.repeat(3)) {
        stripped += '   ';
        index += 3;
        quote = null;
        triple = false;
      } else if (!triple && character === quote) {
        stripped += ' ';
        index += 1;
        quote = null;
      } else {
        stripped += character === '\n' ? '\n' : ' ';
        index += 1;
      }
      continue;
    }
    if (character === '<') {
      iri = true;
      stripped += character;
      index += 1;
      continue;
    }
    if (character === '#') {
      const end = source.indexOf('\n', index);
      if (end === -1) {
        stripped += ' '.repeat(source.length - index);
        break;
      }
      stripped += `${' '.repeat(end - index)}\n`;
      index = end + 1;
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
      triple = source.slice(index, index + 3) === character.repeat(3);
      stripped += triple ? '   ' : ' ';
      index += triple ? 3 : 1;
      continue;
    }
    stripped += character;
    index += 1;
  }
  const prefixes = new Map([...stripped.matchAll(/\bPREFIX\s+([A-Za-z][A-Za-z0-9_-]*):\s*<([^>]+)>/giu)]
    .map((match) => [match[1], match[2]]));
  const iris = new Set([...stripped.matchAll(/<([^<>\s]+)>/gu)].map((match) => match[1]));
  for (const match of stripped.matchAll(/\b([A-Za-z][A-Za-z0-9_-]*):([A-Za-z_][A-Za-z0-9._~-]*)/gu)) {
    if (prefixes.has(match[1])) iris.add(`${prefixes.get(match[1])}${match[2]}`);
  }
  return uniqueSorted(iris);
}

function readRules(root, manifest) {
  const sources = [];
  const dependencies = [];
  for (const entry of [...(manifest.rules ?? [])].sort((a, b) => compare(a.file, b.file))) {
    if (!entry || typeof entry.file !== 'string' || !entry.file.endsWith('.rq')
      || entry.file.startsWith('/') || entry.file.split('/').some((part) => ['', '.', '..'].includes(part))) {
      fail('UNIVERSAL_PROOF_RULE_ENTRY_INVALID', 'invalid rule entry', { entry });
    }
    const path = resolve(root, 'semantic-model', entry.file);
    if (!contained(root, path)) fail('UNIVERSAL_PROOF_MANIFEST_PATH_ESCAPE', entry.file);
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || !contained(root, realpathSync(path))) {
      fail('UNIVERSAL_PROOF_SOURCE_NOT_REGULAR', entry.file);
    }
    const bytes = readFileSync(path);
    if (sha256(bytes) !== sha256(readFileSync(path))) fail('UNIVERSAL_PROOF_SOURCE_MUTATED', entry.file);
    const core = {
      contentDigest: sha256(bytes),
      declaredGraphIri: entry.output,
      manifestGroup: 'rules',
      path: `semantic-model/${entry.file}`,
    };
    const source = { ...core, sourceRecordDigest: digest(core) };
    sources.push(source);
    for (const dependencyIri of sparqlTerms(bytes.toString('utf8'))) dependencies.push({
      dependencyIri,
      sourcePath: source.path,
      sourceRecordDigest: source.sourceRecordDigest,
    });
  }
  return { dependencies, sources };
}

function loadDataset(repositoryRoot) {
  const root = realpathSync(repositoryRoot);
  const manifest = YAML.parse(readFileSync(join(root, 'semantic-model/manifest.yaml'), 'utf8'));
  if (manifest?.version !== 1) fail('UNIVERSAL_PROOF_MANIFEST_INVALID', 'manifest version is unsupported');
  const entries = ['definitionGraphs', 'authoredGraphs', 'reviewGraphs', 'derivedGraphs', 'shapeGraphs'].flatMap((manifestGroup) => (
    (manifest[manifestGroup] ?? []).map((entry) => ({ ...entry, manifestGroup }))
  )).sort((a, b) => compare(`${a.file}\0${a.graph}`, `${b.file}\0${b.graph}`));
  const identities = entries.map(({ file, graph }) => `${file}\0${graph}`);
  if (new Set(identities).size !== identities.length) {
    fail('UNIVERSAL_PROOF_MANIFEST_ENTRY_DUPLICATE', 'duplicate source identity');
  }
  const sourceRecords = [];
  const records = [];
  for (const entry of entries) {
    const loaded = readSource(root, entry);
    sourceRecords.push(loaded.source);
    records.push(...loaded.records);
  }
  const rules = readRules(root, manifest);
  sourceRecords.push(...rules.sources);
  const fixtureEntry = {
    file: FIXTURE_PATH.slice('semantic-model/'.length),
    graph: 'urn:usf:graph:foundation-conformance-fixture',
    manifestGroup: 'conformanceFixture',
  };
  const fixture = readSource(root, fixtureEntry);
  sourceRecords.push(fixture.source);
  records.push(...fixture.records);
  records.sort((a, b) => compare(a.occurrenceDigest, b.occurrenceDigest));
  const duplicates = records.filter((record, index) => index > 0
    && record.occurrenceDigest === records[index - 1].occurrenceDigest);
  const canonicalRecords = records.filter((record, index) => index === 0
    || record.occurrenceDigest !== records[index - 1].occurrenceDigest);
  sourceRecords.sort((a, b) => compare(canonicalJson(a), canonicalJson(b)));
  return {
    duplicates,
    records: canonicalRecords,
    root,
    ruleDependencyRecords: rules.dependencies,
    sourceRecords,
  };
}

function objectIndex(records) {
  const index = new Map();
  for (const record of records) {
    if (record.subject.termType !== 'NamedNode' || record.object.termType !== 'NamedNode') continue;
    const key = `${record.subject.value}\0${record.predicateIri}`;
    if (!index.has(key)) index.set(key, []);
    index.get(key).push(record.object.value);
  }
  return new Map([...index].map(([key, values]) => [key, uniqueSorted(values)]));
}
const values = (index, subject, predicate) => index.get(`${subject}\0${predicate}`) ?? [];

function literalIndex(records) {
  const index = new Map();
  for (const record of records) {
    if (record.subject.termType !== 'NamedNode' || record.object.termType !== 'Literal') continue;
    const key = `${record.subject.value}\0${record.predicateIri}`;
    if (!index.has(key)) index.set(key, []);
    index.get(key).push({
      datatypeIri: record.object.datatypeIri,
      language: record.object.language,
      value: record.object.value,
    });
  }
  return new Map([...index].map(([key, items]) => [key, items
    .sort((a, b) => compare(canonicalJson(a), canonicalJson(b)))
    .filter((item, index_) => index_ === 0
      || canonicalJson(item) !== canonicalJson(items[index_ - 1]))]));
}
const literalStrings = (index, subject, predicate) => (
  index.get(`${subject}\0${predicate}`) ?? []
).map(({ value }) => value);

function explicitTypes(records) {
  const index = new Map();
  for (const record of records) {
    if (record.predicateIri !== TYPE || record.subject.termType !== 'NamedNode'
      || record.object.termType !== 'NamedNode') continue;
    if (!index.has(record.subject.value)) index.set(record.subject.value, []);
    index.get(record.subject.value).push(record.object.value);
  }
  return new Map([...index].map(([key, items]) => [key, uniqueSorted(items)]));
}

function occurrenceIndexes(records) {
  const index = {
    class: { derived: new Map(), fixture: new Map(), model: new Map() },
    individualObject: { derived: new Map(), fixture: new Map(), model: new Map() },
    individualSubject: { derived: new Map(), fixture: new Map(), model: new Map() },
    property: { derived: new Map(), fixture: new Map(), model: new Map() },
  };
  const add = (map, key, record) => {
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(record);
  };
  for (const record of records) {
    const plane = record.manifestGroup === 'conformanceFixture' ? 'fixture'
      : record.manifestGroup === 'derivedGraphs' ? 'derived' : 'model';
    add(index.property[plane], record.predicateIri, record);
    if (record.subject.termType === 'NamedNode') add(index.individualSubject[plane], record.subject.value, record);
    if (record.object.termType === 'NamedNode') add(index.individualObject[plane], record.object.value, record);
    if (record.predicateIri === TYPE && record.object.termType === 'NamedNode') {
      add(index.class[plane], record.object.value, record);
    }
  }
  return index;
}

function individualSummary(index, iri) {
  const records = (plane) => [
    ...(index.individualSubject[plane].get(iri) ?? []),
    ...(index.individualObject[plane].get(iri) ?? []),
  ];
  const digests = (plane) => uniqueSorted(records(plane).map(({ occurrenceDigest }) => occurrenceDigest));
  const model = digests('model');
  const derived = digests('derived');
  const fixture = digests('fixture');
  return {
    activeOccurrenceCount: model.length,
    activeOccurrenceSetDigest: digest(model),
    derivedOccurrenceCount: derived.length,
    derivedOccurrenceSetDigest: digest(derived),
    fixtureOccurrenceCount: fixture.length,
    fixtureOccurrenceSetDigest: digest(fixture),
    sourcePaths: uniqueSorted(['model', 'derived', 'fixture'].flatMap((plane) => (
      records(plane).map(({ sourcePath }) => sourcePath)
    ))),
  };
}

function occurrenceSummary(index, iri, kind, typeIndex) {
  const model = index[kind].model.get(iri) ?? [];
  const derived = index[kind].derived.get(iri) ?? [];
  const fixture = index[kind].fixture.get(iri) ?? [];
  const all = [...model, ...derived, ...fixture];
  return {
    activeGraphIris: uniqueSorted(model.map(({ graphIri }) => graphIri)),
    activeOccurrenceCount: model.length,
    activeOccurrenceSetDigest: digest(model.map(({ occurrenceDigest }) => occurrenceDigest).sort(compare)),
    derivedGraphIris: uniqueSorted(derived.map(({ graphIri }) => graphIri)),
    derivedOccurrenceCount: derived.length,
    derivedOccurrenceSetDigest: digest(derived.map(({ occurrenceDigest }) => occurrenceDigest).sort(compare)),
    endpointObjectClassIris: kind === 'property' ? uniqueSorted(all.flatMap(({ object }) => (
      object.termType === 'NamedNode' ? typeIndex.get(object.value) ?? [] : []
    ))) : [],
    endpointSubjectClassIris: kind === 'property' ? uniqueSorted(all.flatMap(({ subject }) => (
      subject.termType === 'NamedNode' ? typeIndex.get(subject.value) ?? [] : []
    ))) : [],
    fixtureGraphIris: uniqueSorted(fixture.map(({ graphIri }) => graphIri)),
    fixtureOccurrenceCount: fixture.length,
    fixtureOccurrenceSetDigest: digest(fixture.map(({ occurrenceDigest }) => occurrenceDigest).sort(compare)),
    sourcePaths: uniqueSorted(all.map(({ sourcePath }) => sourcePath)),
  };
}

function classAncestors(records) {
  const parents = new Map();
  for (const record of records) {
    if (record.predicateIri !== SUBCLASS || record.subject.termType !== 'NamedNode'
      || record.object.termType !== 'NamedNode') continue;
    if (!parents.has(record.subject.value)) parents.set(record.subject.value, new Set());
    parents.get(record.subject.value).add(record.object.value);
  }
  const memo = new Map();
  const visit = (iri, path = new Set()) => {
    if (memo.has(iri)) return memo.get(iri);
    if (path.has(iri)) fail('UNIVERSAL_PROOF_CLASS_HIERARCHY_CYCLE', iri);
    const result = new Set(parents.get(iri) ?? []);
    const next = new Set(path).add(iri);
    for (const parent of [...result]) for (const ancestor of visit(parent, next)) result.add(ancestor);
    memo.set(iri, result);
    return result;
  };
  return (iri) => uniqueSorted(visit(iri));
}

function reconstructRelationshipSignatures(records, typeIndex) {
  const grouped = new Map();
  for (const record of records) {
    const core = {
      direction: 'OUTBOUND',
      objectClassIris: record.object.termType === 'NamedNode'
        ? uniqueSorted(typeIndex.get(record.object.value) ?? []) : [],
      objectDatatypeIri: record.object.termType === 'Literal' ? record.object.datatypeIri : null,
      objectTermKind: record.object.termType,
      predicateIri: record.predicateIri,
      subjectClassIris: record.subject.termType === 'NamedNode'
        ? uniqueSorted(typeIndex.get(record.subject.value) ?? []) : [],
      subjectTermKind: record.subject.termType,
    };
    const key = canonicalJson(core);
    if (!grouped.has(key)) grouped.set(key, { core, records: [] });
    grouped.get(key).records.push(record);
  }
  return [...grouped.values()].map(({ core, records: occurrences }) => {
    const occurrenceDigests = uniqueSorted(occurrences.map(({ occurrenceDigest }) => occurrenceDigest));
    const signatureIdentityDigest = digest(core);
    const record = {
      ...core,
      activeGraphIris: uniqueSorted(occurrences.map(({ graphIri }) => graphIri)),
      activeOccurrenceCount: occurrenceDigests.length,
      activeOccurrenceSetDigest: digest(occurrenceDigests),
      relationshipSignatureIri: `urn:usf:relationshipsignature:${signatureIdentityDigest.slice(7)}`,
      signatureIdentityDigest,
      sourcePaths: uniqueSorted(occurrences.map(({ sourcePath }) => sourcePath)),
    };
    return { ...record, relationshipSignatureDigest: digest(record) };
  }).sort((a, b) => compare(a.relationshipSignatureIri, b.relationshipSignatureIri));
}

function reconstructValidatorDependencies(shapeRecords, ruleDependencyRecords, terms) {
  const kinds = new Map();
  for (const term of terms) {
    if (!kinds.has(term.iri)) kinds.set(term.iri, []);
    kinds.get(term.iri).push(term.termKind);
  }
  const records = [];
  const add = (iri, role, sourcePath, sourceRecordDigest) => {
    for (const termKind of kinds.get(iri) ?? []) {
      const core = { iri, role, sourcePath, sourceRecordDigest, termKey: `${termKind}\0${iri}` };
      records.push({ ...core, dependencyDigest: digest(core) });
    }
  };
  for (const record of shapeRecords) {
    add(record.predicateIri, 'SHAPE_PREDICATE', record.sourcePath, record.sourceRecordDigest);
    for (const term of [record.subject, record.object]) {
      if (term.termType === 'NamedNode') add(term.value, 'SHAPE_TERM', record.sourcePath, record.sourceRecordDigest);
    }
  }
  for (const record of ruleDependencyRecords) {
    add(record.dependencyIri, 'RULE_TERM', record.sourcePath, record.sourceRecordDigest);
  }
  records.sort((a, b) => compare(canonicalJson(a), canonicalJson(b)));
  const unique = records.filter((record, index) => index === 0
    || record.dependencyDigest !== records[index - 1].dependencyDigest);
  return {
    records: unique,
    setDigest: digest(unique),
    termKeys: uniqueSorted(unique.map(({ termKey }) => termKey)),
  };
}

function reconstructInventory(dataset, authorityBinding, authorityInputVerification, analyzerSourceDigest) {
  const semanticRecords = dataset.records.filter(({ manifestGroup }) => [
    'authoredGraphs', 'definitionGraphs',
  ].includes(manifestGroup));
  const shapeRecords = dataset.records.filter(({ manifestGroup }) => manifestGroup === 'shapeGraphs');
  const occurrenceRecords = dataset.records.filter(({ manifestGroup }) => [
    'authoredGraphs', 'conformanceFixture', 'definitionGraphs', 'derivedGraphs',
  ].includes(manifestGroup));
  const valueIndex = objectIndex(semanticRecords);
  const typeIndex = explicitTypes(semanticRecords);
  const occurrences = occurrenceIndexes(occurrenceRecords);
  const declaredClasses = uniqueSorted(semanticRecords.filter(({ predicateIri, object }) => (
    predicateIri === TYPE && object.termType === 'NamedNode' && CLASS_KINDS.has(object.value)
  )).map(({ subject }) => subject.termType === 'NamedNode' ? subject.value : null).filter(Boolean));
  const declaredProperties = uniqueSorted(semanticRecords.filter(({ predicateIri, object }) => (
    predicateIri === TYPE && object.termType === 'NamedNode' && PROPERTY_KINDS.has(object.value)
  )).map(({ subject }) => subject.termType === 'NamedNode' ? subject.value : null).filter(Boolean));
  const classBindings = semanticRecords.filter(({ predicateIri, subject, object }) => (
    predicateIri === STANDARD_CLASS && subject.termType === 'NamedNode' && object.termType === 'NamedNode'
  )).map(({ subject, object }) => ({ standardIri: subject.value, termIri: object.value }))
    .sort((a, b) => compare(canonicalJson(a), canonicalJson(b)));
  const propertyBindings = semanticRecords.filter(({ predicateIri, subject, object }) => (
    predicateIri === STANDARD_PROPERTY && subject.termType === 'NamedNode' && object.termType === 'NamedNode'
  )).map(({ subject, object }) => ({ standardIri: subject.value, termIri: object.value }))
    .sort((a, b) => compare(canonicalJson(a), canonicalJson(b)));
  const externalClasses = uniqueSorted(classBindings.map(({ termIri }) => termIri));
  const externalProperties = uniqueSorted(propertyBindings.map(({ termIri }) => termIri));
  const referencedClasses = uniqueSorted(semanticRecords.flatMap((record) => {
    if (record.object.termType !== 'NamedNode') return [];
    return record.predicateIri === TYPE || [DOMAIN, RANGE, SUBCLASS].includes(record.predicateIri)
      ? [record.object.value] : [];
  }));
  const referencedProperties = uniqueSorted(semanticRecords.flatMap(({ predicateIri, subject, object }) => (
    [SUBPROPERTY, INVERSE].includes(predicateIri)
      ? [subject, object].filter(({ termType }) => termType === 'NamedNode').map(({ value }) => value)
      : []
  )));
  const usedProperties = uniqueSorted(semanticRecords.map(({ predicateIri }) => predicateIri));
  const classIris = uniqueSorted([...declaredClasses, ...referencedClasses, ...externalClasses]);
  const propertyIris = uniqueSorted([
    ...declaredProperties, ...externalProperties, ...referencedProperties, ...usedProperties,
  ]);
  const classes = classIris.map((iri) => {
    const declarationKindIris = values(valueIndex, iri, TYPE).filter((value) => CLASS_KINDS.has(value));
    const core = {
      ...occurrenceSummary(occurrences, iri, 'class', typeIndex),
      declarationKindIris,
      declarationState: declarationKindIris.length ? 'DECLARED'
        : externalClasses.includes(iri) ? 'EXTERNAL_STANDARD_BINDING' : 'USED_BUT_UNDECLARED',
      directParentIris: values(valueIndex, iri, SUBCLASS),
      iri,
      standardBindingIris: uniqueSorted(classBindings.filter(({ termIri }) => termIri === iri)
        .map(({ standardIri }) => standardIri)),
      termKey: `class\0${iri}`,
      termKind: 'class',
      termUsageStateIris: values(valueIndex, iri, `${O}termUsageState`),
    };
    return { ...core, recordDigest: digest(core) };
  });
  const properties = propertyIris.map((iri) => {
    const declarationKindIris = values(valueIndex, iri, TYPE).filter((value) => PROPERTY_KINDS.has(value));
    const core = {
      ...occurrenceSummary(occurrences, iri, 'property', typeIndex),
      declarationKindIris,
      declarationState: declarationKindIris.length ? 'DECLARED'
        : externalProperties.includes(iri) ? 'EXTERNAL_STANDARD_BINDING' : 'USED_BUT_UNDECLARED',
      declaredDomainIris: values(valueIndex, iri, DOMAIN),
      declaredRangeIris: values(valueIndex, iri, RANGE),
      iri,
      standardBindingIris: uniqueSorted(propertyBindings.filter(({ termIri }) => termIri === iri)
        .map(({ standardIri }) => standardIri)),
      termKey: `property\0${iri}`,
      termKind: 'property',
      termUsageStateIris: values(valueIndex, iri, `${O}termUsageState`),
    };
    return { ...core, recordDigest: digest(core) };
  });
  const ancestors = classAncestors(semanticRecords);
  const classSet = new Set(classIris);
  const propertySet = new Set(propertyIris);
  const namedIris = uniqueSorted(semanticRecords.flatMap(({ subject, object }) => [subject, object]
    .filter(({ termType }) => termType === 'NamedNode').map(({ value }) => value)));
  const individualIris = namedIris.filter((iri) => !classSet.has(iri) && !propertySet.has(iri));
  const individuals = individualIris.map((iri) => {
    const explicitTypeIris = uniqueSorted(typeIndex.get(iri) ?? []);
    const controlledValueTypeIris = explicitTypeIris.filter((typeIri) => (
      typeIri === CONTROLLED_VALUE || ancestors(typeIri).includes(CONTROLLED_VALUE)
    ));
    const core = {
      ...individualSummary(occurrences, iri),
      controlledValue: controlledValueTypeIris.length > 0,
      controlledValueTypeIris,
      explicitTypeIris,
      iri,
      termKey: `individual\0${iri}`,
      termKind: 'individual',
      termUsageStateIris: values(valueIndex, iri, `${O}termUsageState`),
    };
    return { ...core, recordDigest: digest(core) };
  });
  const terms = [...classes, ...properties, ...individuals].sort((a, b) => compare(a.termKey, b.termKey));
  const relationshipCategories = properties.map((property) => {
    const core = {
      activeGraphIris: property.activeGraphIris,
      activeOccurrenceCount: property.activeOccurrenceCount,
      activeOccurrenceSetDigest: property.activeOccurrenceSetDigest,
      declarationKindIris: property.declarationKindIris,
      declarationState: property.declarationState,
      declaredDomainIris: property.declaredDomainIris,
      declaredRangeIris: property.declaredRangeIris,
      endpointObjectClassIris: property.endpointObjectClassIris,
      endpointSubjectClassIris: property.endpointSubjectClassIris,
      derivedOccurrenceCount: property.derivedOccurrenceCount,
      derivedOccurrenceSetDigest: property.derivedOccurrenceSetDigest,
      fixtureOccurrenceCount: property.fixtureOccurrenceCount,
      predicateIri: property.iri,
      relationshipKey: `relationship\0${property.iri}`,
    };
    return { ...core, relationshipCategoryDigest: digest(core) };
  });
  const byIriKinds = new Map();
  for (const term of terms) {
    if (!byIriKinds.has(term.iri)) byIriKinds.set(term.iri, []);
    byIriKinds.get(term.iri).push(term.termKind);
  }
  const mechanism = new Set();
  for (const record of semanticRecords.filter(({ graphIri }) => graphIri === PERMUTATION_GRAPH)) {
    if (record.predicateIri.startsWith(O)) mechanism.add(`property\0${record.predicateIri}`);
    if (record.predicateIri === TYPE && record.object.termType === 'NamedNode'
      && record.object.value.startsWith(O)) mechanism.add(`class\0${record.object.value}`);
    for (const term of [record.subject, record.object]) {
      if (term.termType !== 'NamedNode') continue;
      for (const kind of byIriKinds.get(term.value) ?? []) mechanism.add(`${kind}\0${term.value}`);
    }
  }
  const known = new Set(terms.map(({ termKey }) => termKey));
  const mechanismDependencyTermKeys = uniqueSorted([...mechanism].filter((key) => known.has(key)));
  const relationshipSignatures = reconstructRelationshipSignatures(semanticRecords, typeIndex);
  const validationDependencies = reconstructValidatorDependencies(
    shapeRecords,
    dataset.ruleDependencyRecords,
    terms,
  );
  const sourceRecords = dataset.sourceRecords.filter(({ manifestGroup }) => [
    'authoredGraphs', 'definitionGraphs',
  ].includes(manifestGroup));
  const validationSourceRecords = dataset.sourceRecords.filter(({ manifestGroup }) => (
    ['rules', 'shapeGraphs'].includes(manifestGroup)
  ));
  const sourceSetDigest = digest(sourceRecords);
  const core = {
    authorityBinding,
    authorityInputVerification,
    classCount: classes.length,
    classes,
    controlledValueCount: individuals.filter(({ controlledValue }) => controlledValue).length,
    controlledValueSetDigest: digest(individuals.filter(({ controlledValue }) => controlledValue)
      .map(({ recordDigest }) => recordDigest)),
    duplicateOccurrenceCount: dataset.duplicates.filter(({ manifestGroup }) => (
      manifestGroup !== 'reviewGraphs'
    )).length,
    duplicateOccurrenceSetDigest: digest(uniqueSorted(dataset.duplicates
      .filter(({ manifestGroup }) => manifestGroup !== 'reviewGraphs')
      .map(({ occurrenceDigest }) => occurrenceDigest))),
    externalStandardBindings: { classes: classBindings, properties: propertyBindings },
    fixtureSourceDigest: dataset.sourceRecords.find(({ path }) => path === FIXTURE_PATH)?.contentDigest ?? null,
    inventoryAlgorithmSourceDigest: analyzerSourceDigest,
    individualCount: individuals.length,
    individuals,
    mechanismDependencyTermKeys,
    propertyCount: properties.length,
    properties,
    recordKind: 'USF_UNIVERSAL_SEMANTIC_OCCURRENCE_INVENTORY',
    relationshipCategories,
    relationshipCategoryCount: relationshipCategories.length,
    relationshipCategorySetDigest: digest(relationshipCategories.map(({ relationshipCategoryDigest }) => relationshipCategoryDigest)),
    relationshipSignatureCount: relationshipSignatures.length,
    relationshipSignatures,
    relationshipSignatureSetDigest: digest(relationshipSignatures.map(({ relationshipSignatureDigest }) => relationshipSignatureDigest)),
    schemaVersion: 4,
    excludedSourceGroups: ['conformanceFixture', 'derivedGraphs', 'reviewGraphs', 'rules', 'shapeGraphs'],
    semanticInputSourceSetDigest: sourceSetDigest,
    sourceRecords,
    sourceSetDigest,
    termCount: terms.length,
    termKeySetDigest: digest(terms.map(({ termKey }) => termKey)),
    terms,
    undeclaredClassIris: classIris.filter((iri) => !declaredClasses.includes(iri) && !externalClasses.includes(iri)),
    undeclaredPredicateIris: propertyIris.filter((iri) => !declaredProperties.includes(iri)
      && !externalProperties.includes(iri)),
    validationDependencyCount: validationDependencies.records.length,
    validationDependencyRecords: validationDependencies.records,
    validationDependencySetDigest: validationDependencies.setDigest,
    validationDependencyTermKeys: validationDependencies.termKeys,
    validationSourceRecords,
    validationSourceSetDigest: digest(validationSourceRecords),
  };
  return { ...core, inventoryDigest: digest(core) };
}

function directFamilySignatures(dataset, candidateRegistry) {
  const records = dataset.records.filter(({ manifestGroup }) => [
    'authoredGraphs', 'definitionGraphs',
  ].includes(manifestGroup));
  const index = objectIndex(records);
  const literals = new Map();
  for (const record of records) {
    if (record.subject.termType !== 'NamedNode' || record.object.termType !== 'Literal') continue;
    const key = `${record.subject.value}\0${record.predicateIri}`;
    if (!literals.has(key)) literals.set(key, []);
    literals.get(key).push(record.object.value);
  }
  const literalValues = (subject, predicate) => uniqueSorted(literals.get(`${subject}\0${predicate}`) ?? []);
  const familyIris = uniqueSorted(records.filter(({ predicateIri, object }) => (
    predicateIri === TYPE && object.termType === 'NamedNode' && object.value === `${O}PermutationFamily`
  )).map(({ subject }) => subject.value));
  const signatures = candidateRegistry.families.map((family) => {
    const registration = values(index, family.familyIri, `${O}familySubjectRegistration`);
    const rule = values(index, family.familyIri, `${O}familyApplicabilityRule`);
    const bindingIris = values(index, family.familyIri, `${O}hasFamilyDimensionBinding`);
    const directBindings = bindingIris.map((bindingIri) => ({
      bindingIri,
      dimensionIris: values(index, bindingIri, `${O}bindsDimension`),
      positions: literalValues(bindingIri, `${O}dimensionPosition`).map(Number),
    })).sort((a, b) => a.positions[0] - b.positions[0]);
    const candidateBindings = family.orderedBindings.map(({ bindingIri, dimensionIri, position }) => ({
      bindingIri, dimensionIris: [dimensionIri], positions: [position],
    }));
    const closure = family.subjectClassClosure;
    const direct = {
      applicabilityRuleIris: rule,
      bindingRecords: directBindings,
      canonicalNames: literalValues(family.familyIri, `${O}canonicalName`),
      familyIri: family.familyIri,
      planeIris: registration.flatMap((iri) => values(index, iri, `${O}registeredFamilyPlane`)),
      registrationIris: registration,
      subjectClassIris: registration.flatMap((iri) => values(index, iri, `${O}registeredSubjectClass`)),
      subjectClosureIris: registration.flatMap((iri) => values(index, iri, `${O}subjectClassClosure`)),
    };
    const candidate = {
      applicabilityRuleIris: [family.ruleIri],
      bindingRecords: candidateBindings,
      canonicalNames: [family.canonicalName],
      familyIri: family.familyIri,
      planeIris: [family.planeIri],
      registrationIris: [family.registrationIri],
      subjectClassIris: [family.subjectClassIri],
      subjectClosureIris: [closure.closureIri],
    };
    return { candidate, direct, familyIri: family.familyIri, match: canonicalJson(candidate) === canonicalJson(direct) };
  });
  return {
    candidateFamilyIris: candidateRegistry.families.map(({ familyIri }) => familyIri).sort(compare),
    familyIris,
    signatures,
  };
}

function independentlyReconstructExactFamilyRegistry(repositoryRoot, analyzerSourceDigest) {
  const metaModel = universeProofInternals.loadIndependentMetaModel(repositoryRoot);
  const closureByDigest = new Map(metaModel.classClosures.closures
    .map((closure) => [closure.digest, closure]));
  const closureRecord = (closureDigest) => {
    const closure = closureByDigest.get(closureDigest);
    if (!closure) fail('UNIVERSAL_PROOF_AXIS_CLOSURE_ABSENT', closureDigest);
    return {
      closureDigest: closure.digest,
      closureIri: closure.iri,
      memberClassIris: closure.memberClassIris,
      rootClassIri: closure.rootClassIri,
    };
  };
  const selectorRecord = (selectorIri) => {
    if (selectorIri === null) return null;
    const selector = metaModel.selectors.get(selectorIri);
    if (!selector) fail('UNIVERSAL_PROOF_PATH_SELECTOR_ABSENT', selectorIri);
    return {
      digest: selector.digest,
      iri: selector.selectorIri,
      steps: selector.steps.map(({ directionIri, index, predicateIri }) => ({
        directionIri, index, predicateIri,
      })),
      subjectClassClosure: closureRecord(selector.subjectClassClosureDigest),
      terminalClassClosure: closureRecord(selector.terminalClassClosureDigest),
    };
  };
  const ruleSelectorIris = (clause, result = new Set()) => {
    if (clause?.selectorIri) result.add(clause.selectorIri);
    for (const operand of clause?.operands ?? []) ruleSelectorIris(operand.clause, result);
    return result;
  };
  const exactRecords = new Map(metaModel.familyRegistry.registryRecord.families
    .map((record) => [record.familyIri, record]));
  const dimensionsByIri = new Map();
  const families = metaModel.familyRegistry.families.map((family) => {
    const rule = metaModel.rules.get(family.ruleIri);
    if (!rule) fail('UNIVERSAL_PROOF_APPLICABILITY_RULE_ABSENT', family.ruleIri);
    const orderedBindings = family.dimensions.map((binding) => {
      const record = {
        axisClassClosures: binding.axisClassClosureDigests.map(closureRecord),
        bindingIri: binding.bindingIri,
        derivationPredicateIris: binding.derivationPredicateIris,
        dimensionIri: binding.dimensionIri,
        key: binding.key,
        position: binding.position,
        selector: selectorRecord(binding.valueSelectorIri),
        sourceIri: binding.sourceIri,
        sourceKind: binding.sourceKind,
        sourceScopeIri: binding.sourceScopeIri,
        valueDerivationRootIri: binding.valueDerivationRootIri,
        valueSourceDigest: binding.valueSourceDigest,
      };
      const dimension = {
        axisClassClosures: record.axisClassClosures,
        derivationPredicateIris: record.derivationPredicateIris,
        iri: record.dimensionIri,
        key: record.key,
        selector: record.selector,
        sourceIri: record.sourceIri,
        sourceKind: record.sourceKind,
        sourceScopeIri: record.sourceScopeIri,
        valueDerivationRootIri: record.valueDerivationRootIri,
        valueSourceDigest: record.valueSourceDigest,
      };
      const prior = dimensionsByIri.get(dimension.iri);
      if (prior && canonicalJson(prior) !== canonicalJson(dimension)) {
        fail('UNIVERSAL_PROOF_AXIS_DEFINITION_CONFLICT', dimension.iri);
      }
      dimensionsByIri.set(dimension.iri, dimension);
      return record;
    });
    const exactRecord = exactRecords.get(family.familyIri);
    if (!exactRecord) fail('UNIVERSAL_PROOF_FAMILY_IDENTITY_SUBSTITUTION', family.familyIri);
    return {
      applicabilitySelectors: uniqueSorted([...ruleSelectorIris(rule.rootClause)])
        .map(selectorRecord),
      canonicalName: family.canonicalName,
      familyIri: family.familyIri,
      familyRecordDigest: digest(exactRecord),
      orderedBindings,
      planeIri: family.planeIri,
      registrationIri: family.registrationIri,
      ruleDigest: family.ruleDigest,
      ruleIri: family.ruleIri,
      subjectClassClosure: closureRecord(family.subjectClassClosureDigest),
      subjectClassIri: family.subjectClassIri,
    };
  }).sort((left, right) => compare(left.familyIri, right.familyIri));
  const dimensions = [...dimensionsByIri.values()].sort((left, right) => compare(left.iri, right.iri));
  const core = {
    dimensionCount: dimensions.length,
    dimensions,
    families,
    familyCount: families.length,
    productionRegistryDigest: metaModel.familyRegistry.registryDigest,
    projectionAlgorithmSourceDigest: analyzerSourceDigest,
    recordKind: 'USF_UNIVERSAL_EXACT_FAMILY_REGISTRY_PROJECTION',
    schemaVersion: 4,
  };
  return { ...core, registryDigest: digest(core) };
}

function familyRegistryMismatchCode(actual, expected) {
  const identity = (registry) => registry.families.map(({ canonicalName, familyIri }) => ({
    canonicalName, familyIri,
  }));
  if (canonicalJson(identity(actual)) !== canonicalJson(identity(expected))) {
    return 'UNIVERSAL_PROOF_FAMILY_IDENTITY_SUBSTITUTION';
  }
  const expectedByIri = new Map(expected.families.map((family) => [family.familyIri, family]));
  for (const family of actual.families) {
    const warranted = expectedByIri.get(family.familyIri);
    const select = (value, fields) => Object.fromEntries(fields.map((field) => [field, value[field]]));
    if (canonicalJson(select(family, ['planeIri', 'registrationIri', 'subjectClassClosure', 'subjectClassIri']))
      !== canonicalJson(select(warranted, ['planeIri', 'registrationIri', 'subjectClassClosure', 'subjectClassIri']))) {
      return 'UNIVERSAL_PROOF_SUBJECT_SUBSTITUTION';
    }
    if (canonicalJson(select(family, ['ruleDigest', 'ruleIri']))
      !== canonicalJson(select(warranted, ['ruleDigest', 'ruleIri']))
      || canonicalJson(family.applicabilitySelectors.map(({ iri }) => iri))
        !== canonicalJson(warranted.applicabilitySelectors.map(({ iri }) => iri))) {
      return 'UNIVERSAL_PROOF_APPLICABILITY_SUBSTITUTION';
    }
    const bindingIdentity = (item) => item.orderedBindings.map(({ bindingIri, position }) => ({
      bindingIri, position,
    }));
    if (canonicalJson(bindingIdentity(family)) !== canonicalJson(bindingIdentity(warranted))) {
      return 'UNIVERSAL_PROOF_BINDING_SUBSTITUTION';
    }
    const axis = (item) => item.orderedBindings.map(({ axisClassClosures, dimensionIri, key }) => ({
      axisClassClosures, dimensionIri, key,
    }));
    if (canonicalJson(axis(family)) !== canonicalJson(axis(warranted))) {
      return 'UNIVERSAL_PROOF_AXIS_SUBSTITUTION';
    }
    const derivation = (item) => item.orderedBindings.map(({
      derivationPredicateIris, sourceIri, sourceKind, sourceScopeIri,
      valueDerivationRootIri, valueSourceDigest,
    }) => ({
      derivationPredicateIris, sourceIri, sourceKind, sourceScopeIri,
      valueDerivationRootIri, valueSourceDigest,
    }));
    if (canonicalJson(derivation(family)) !== canonicalJson(derivation(warranted))) {
      return 'UNIVERSAL_PROOF_DERIVATION_SUBSTITUTION';
    }
    if (canonicalJson(family.orderedBindings.map(({ selector }) => selector))
      !== canonicalJson(warranted.orderedBindings.map(({ selector }) => selector))
      || canonicalJson(family.applicabilitySelectors) !== canonicalJson(warranted.applicabilitySelectors)) {
      return 'UNIVERSAL_PROOF_PATH_SUBSTITUTION';
    }
    if (family.familyRecordDigest !== warranted.familyRecordDigest) {
      return 'UNIVERSAL_PROOF_FAMILY_IDENTITY_SUBSTITUTION';
    }
  }
  return 'UNIVERSAL_PROOF_REGISTRY_RECONSTRUCTION_MISMATCH';
}

function compact(value) {
  return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== null));
}

function reconstructReviewProjection(dataset, inventory, registry, analyzerSourceDigest) {
  const allTypes = explicitTypes(dataset.records);
  const reviewClassIris = new Set([
    TERM_REVIEW_CLASS, REVIEW_COVERAGE_CLASS, FAMILY_REVIEW_CLASS, FAMILY_CANDIDATE_CLASS,
  ]);
  const reviewResourceIris = uniqueSorted([...allTypes.entries()]
    .filter(([, typeIris]) => typeIris.some((typeIri) => reviewClassIris.has(typeIri)))
    .map(([iri]) => iri));
  const invalidReviewResourcePlanes = reviewResourceIris.flatMap((iri) => {
    const planes = uniqueSorted(dataset.records.filter(({ subject }) => (
      subject.termType === 'NamedNode' && subject.value === iri
    )).map(({ manifestGroup }) => manifestGroup));
    return canonicalJson(planes) === canonicalJson(['reviewGraphs']) ? [] : [{ iri, planes }];
  });
  if (invalidReviewResourcePlanes.length) {
    fail('UNIVERSAL_PROOF_REVIEW_RESOURCE_PLANE_INVALID',
      'review resources must be isolated in registered review graphs', { invalidReviewResourcePlanes });
  }
  const records = dataset.records.filter(({ manifestGroup }) => manifestGroup === 'reviewGraphs');
  const objects = objectIndex(records);
  const literals = literalIndex(records);
  const types = explicitTypes(records);
  const typed = (classIri) => uniqueSorted([...types.entries()]
    .filter(([, typeIris]) => typeIris.includes(classIri)).map(([iri]) => iri));
  const sourcePlanes = (iri) => uniqueSorted(records.filter(({ subject }) => (
    subject.termType === 'NamedNode' && subject.value === iri
  )).map(({ manifestGroup }) => manifestGroup));
  const objectsFor = (iri, name) => values(objects, iri, `${O}${name}`);
  const literalsFor = (iri, name) => literalStrings(literals, iri, `${O}${name}`);
  const termReviews = typed(TERM_REVIEW_CLASS).map((reviewIri) => {
    const core = {
      authorityDigests: literalsFor(reviewIri, 'termPermutationAuthorityDigest'),
      axisBindingIris: objectsFor(reviewIri, 'termPermutationAxisBinding'),
      familyCandidateStateIris: objectsFor(reviewIri, 'termPermutationFamilyCandidateState'),
      inventoryDigests: literalsFor(reviewIri, 'termPermutationInventoryDigest'),
      participationIris: objectsFor(reviewIri, 'termPermutationParticipation'),
      reasonCodes: literalsFor(reviewIri, 'termPermutationReasonCode'),
      reviewDigests: literalsFor(reviewIri, 'termPermutationReviewDigest'),
      reviewIri,
      reviewedTermIris: objectsFor(reviewIri, 'reviewedSemanticTerm'),
      sourcePlanes: sourcePlanes(reviewIri),
      statedSourcePlanes: literalsFor(reviewIri, 'termPermutationSourcePlane'),
    };
    return { ...core, projectionRecordDigest: digest(core) };
  }).sort((a, b) => compare(a.reviewIri, b.reviewIri));
  const familySignatureReviews = typed(FAMILY_REVIEW_CLASS).map((reviewIri) => {
    const core = {
      applicabilityRuleIris: objectsFor(reviewIri, 'reviewedFamilyApplicabilityRule'),
      authorityDigests: literalsFor(reviewIri, 'familySignatureReviewAuthorityDigest'),
      dimensionBindingIris: objectsFor(reviewIri, 'reviewedFamilyDimensionBinding'),
      dispositionIris: objectsFor(reviewIri, 'familySignatureReviewDisposition'),
      familyIris: objectsFor(reviewIri, 'reviewedPermutationFamily'),
      registryDigests: literalsFor(reviewIri, 'familySignatureReviewRegistryDigest'),
      reviewDigests: literalsFor(reviewIri, 'familySignatureReviewDigest'),
      reviewIri,
      signatureDigests: literalsFor(reviewIri, 'reviewedFamilySignatureDigest'),
      sourcePlanes: sourcePlanes(reviewIri),
      subjectRegistrationIris: objectsFor(reviewIri, 'reviewedFamilySubjectRegistration'),
    };
    return { ...core, projectionRecordDigest: digest(core) };
  }).sort((a, b) => compare(a.reviewIri, b.reviewIri));
  const coverages = typed(REVIEW_COVERAGE_CLASS).map((coverageIri) => {
    const core = {
      authorityDigests: literalsFor(coverageIri, 'permutationReviewAuthorityDigest'),
      coverageDigests: literalsFor(coverageIri, 'permutationReviewDigest'),
      coverageIri,
      expectedFamilyIris: objectsFor(coverageIri, 'permutationReviewExpectedFamily'),
      expectedTermIris: objectsFor(coverageIri, 'permutationReviewExpectedTerm'),
      familyRegistryDigests: literalsFor(coverageIri, 'permutationReviewFamilyRegistryDigest'),
      familySignatureAlgorithms: literalsFor(coverageIri, 'permutationReviewFamilySignatureAlgorithm'),
      familySignatureReviewIris: objectsFor(coverageIri, 'permutationReviewFamilySignatureReview'),
      inventoryDigests: literalsFor(coverageIri, 'permutationReviewInventoryDigest'),
      sourcePlanes: sourcePlanes(coverageIri),
      termReviewIris: objectsFor(coverageIri, 'permutationReviewTermReview'),
      termSetAlgorithms: literalsFor(coverageIri, 'permutationReviewTermSetAlgorithm'),
    };
    return { ...core, projectionRecordDigest: digest(core) };
  }).sort((a, b) => compare(a.coverageIri, b.coverageIri));
  const familyCandidates = typed(FAMILY_CANDIDATE_CLASS).map((candidateIri) => {
    const core = { candidateIri, sourcePlanes: sourcePlanes(candidateIri) };
    return { ...core, projectionRecordDigest: digest(core) };
  });
  const semanticSourceRecords = dataset.sourceRecords.filter(({ manifestGroup }) => [
    'authoredGraphs', 'definitionGraphs',
  ].includes(manifestGroup));
  const reviewSourceRecords = dataset.sourceRecords.filter(({ manifestGroup }) => (
    manifestGroup === 'reviewGraphs'
  ));
  const core = {
    authorityDigest: inventory.authorityBinding.authorityDigest,
    coverageCount: coverages.length,
    coverages,
    familyCandidateCount: familyCandidates.length,
    familyCandidates,
    familyRegistryDigest: registry.registryDigest,
    familySignatureReviewCount: familySignatureReviews.length,
    familySignatureReviews,
    inventoryDigest: inventory.inventoryDigest,
    recordKind: 'USF_UNIVERSAL_REVIEW_PROJECTION',
    projectionAlgorithmSourceDigest: analyzerSourceDigest,
    reviewSourceCount: reviewSourceRecords.length,
    reviewSourceRecords,
    reviewSourceSetDigest: digest(reviewSourceRecords),
    schemaVersion: 2,
    semanticInputSourceSetDigest: digest(semanticSourceRecords),
    termReviewCount: termReviews.length,
    termReviews,
  };
  return { ...core, reviewProjectionDigest: digest(core) };
}

function reconstructAnalysis(inventory, registry, reviewProjection) {
  const witnesses = [];
  const add = (core) => {
    const record = compact({ inventoryDigest: inventory.inventoryDigest, registryDigest: registry.registryDigest, schemaVersion: 2, ...core });
    witnesses.push({ ...record, witnessDigest: digest(record) });
  };
  const matchingIndividuals = (classIris) => {
    const classSet = new Set(classIris);
    return inventory.individuals.filter(({ explicitTypeIris }) => (
      explicitTypeIris.some((iri) => classSet.has(iri))
    ));
  };
  for (const family of registry.families) {
    add({ bindingPosition: null, closureDigest: family.subjectClassClosure.closureDigest,
      closureIri: family.subjectClassClosure.closureIri, familyIri: family.familyIri,
      familyRecordDigest: family.familyRecordDigest, ownerIri: family.registrationIri,
      role: 'EXACT_FAMILY_SUBJECT_ROOT', termKey: `class\0${family.subjectClassIri}` });
    for (const classIri of family.subjectClassClosure.memberClassIris) add({ bindingPosition: null,
      closureDigest: family.subjectClassClosure.closureDigest, closureIri: family.subjectClassClosure.closureIri,
      familyIri: family.familyIri, familyRecordDigest: family.familyRecordDigest, ownerIri: family.registrationIri,
      role: 'EXPLICIT_SUBJECT_CLOSURE_MEMBER', termKey: `class\0${classIri}` });
    for (const individual of matchingIndividuals(family.subjectClassClosure.memberClassIris)) add({
      bindingPosition: null, closureDigest: family.subjectClassClosure.closureDigest,
      closureIri: family.subjectClassClosure.closureIri, familyIri: family.familyIri,
      familyRecordDigest: family.familyRecordDigest, ownerIri: family.registrationIri,
      role: 'EXACT_FAMILY_SUBJECT_INSTANCE_CLASSIFICATION', termKey: individual.termKey,
    });
    for (const binding of family.orderedBindings) {
      for (const closure of binding.axisClassClosures) {
        for (const classIri of closure.memberClassIris) add({
          bindingPosition: binding.position, closureDigest: closure.closureDigest, closureIri: closure.closureIri,
          familyIri: family.familyIri, familyRecordDigest: family.familyRecordDigest, ownerIri: binding.dimensionIri,
          role: 'EXPLICIT_AXIS_CLOSURE_MEMBER', termKey: `class\0${classIri}` });
        for (const individual of matchingIndividuals(closure.memberClassIris)) add({
          bindingPosition: binding.position, closureDigest: closure.closureDigest,
          closureIri: closure.closureIri, familyIri: family.familyIri,
          familyRecordDigest: family.familyRecordDigest, ownerIri: binding.dimensionIri,
          role: 'FINITE_AXIS_VALUE_CLASSIFICATION', termKey: individual.termKey,
        });
      }
      for (const step of binding.selector?.steps ?? []) add({ bindingPosition: binding.position,
        directionIri: step.directionIri, familyIri: family.familyIri, familyRecordDigest: family.familyRecordDigest,
        ownerIri: binding.selector.iri, predicateIri: step.predicateIri, role: 'EXACT_DIMENSION_SELECTOR_STEP',
        selectorDigest: binding.selector.digest, stepIndex: step.index, termKey: `property\0${step.predicateIri}` });
      for (const predicateIri of binding.derivationPredicateIris) add({ bindingPosition: binding.position,
        familyIri: family.familyIri, familyRecordDigest: family.familyRecordDigest,
        ownerIri: binding.valueDerivationRootIri ?? binding.sourceIri, predicateIri,
        role: 'EXACT_VALUE_DERIVATION_PREDICATE', termKey: `property\0${predicateIri}` });
    }
    for (const selector of family.applicabilitySelectors) for (const step of selector.steps) add({
      bindingPosition: null, directionIri: step.directionIri, familyIri: family.familyIri,
      familyRecordDigest: family.familyRecordDigest, ownerIri: selector.iri, predicateIri: step.predicateIri,
      role: 'EXACT_APPLICABILITY_SELECTOR_STEP', selectorDigest: selector.digest, stepIndex: step.index,
      termKey: `property\0${step.predicateIri}` });
  }
  for (const termKey of inventory.mechanismDependencyTermKeys) add({ bindingPosition: null, familyIri: null,
    familyRecordDigest: null, ownerIri: PERMUTATION_GRAPH, role: 'PERMUTATION_META_MODEL_DEPENDENCY', termKey });
  for (const termKey of inventory.validationDependencyTermKeys) add({ bindingPosition: null, familyIri: null,
    familyRecordDigest: null, ownerIri: 'urn:usf:graph:validation-dependencies',
    role: 'VALIDATOR_DEPENDENCY', termKey });
  witnesses.sort((a, b) => compare(canonicalJson(a), canonicalJson(b)));
  const byTerm = new Map();
  for (const witness of witnesses) {
    if (!byTerm.has(witness.termKey)) byTerm.set(witness.termKey, []);
    byTerm.get(witness.termKey).push(witness);
  }
  const termsByIri = new Map();
  for (const term of inventory.terms) {
    if (!termsByIri.has(term.iri)) termsByIri.set(term.iri, []);
    termsByIri.get(term.iri).push(term);
  }
  if ([...termsByIri.values()].some((items) => items.length !== 1)) {
    fail('UNIVERSAL_PROOF_TERM_IDENTITY_AMBIGUOUS', 'review identity cannot distinguish term kinds');
  }
  const sourceGroupByPath = new Map(inventory.sourceRecords
    .map(({ manifestGroup, path }) => [path, manifestGroup]));
  const termReviewsByIri = new Map();
  const invalidTermReviewIris = [];
  const orphanTermReviewIris = [];
  for (const review of reviewProjection.termReviews) {
    if (review.reviewedTermIris.length !== 1 || review.authorityDigests.length !== 1
      || review.axisBindingIris.length !== 1 || review.familyCandidateStateIris.length !== 1
      || review.inventoryDigests.length !== 1 || review.participationIris.length !== 1
      || review.reasonCodes.length !== 1 || review.reviewDigests.length !== 1
      || review.statedSourcePlanes.length !== 1) {
      invalidTermReviewIris.push(review.reviewIri);
      continue;
    }
    const core = {
      authorityDigest: review.authorityDigests[0],
      axisBindingIri: review.axisBindingIris[0],
      familyCandidateStateIri: review.familyCandidateStateIris[0],
      inventoryDigest: review.inventoryDigests[0],
      participationIri: review.participationIris[0],
      reasonCode: review.reasonCodes[0],
      reviewedTermIri: review.reviewedTermIris[0],
      sourcePlane: review.statedSourcePlanes[0],
    };
    if (core.authorityDigest !== inventory.authorityBinding.authorityDigest
      || core.inventoryDigest !== inventory.inventoryDigest
      || review.reviewDigests[0] !== digest(core)) {
      invalidTermReviewIris.push(review.reviewIri);
      continue;
    }
    const terms = termsByIri.get(core.reviewedTermIri) ?? [];
    if (terms.length === 0) {
      orphanTermReviewIris.push(review.reviewIri);
      continue;
    }
    const expectedPlane = uniqueSorted(terms[0].sourcePaths
      .map((path) => sourceGroupByPath.get(path)).filter(Boolean)).join('+');
    if (core.sourcePlane !== expectedPlane) {
      invalidTermReviewIris.push(review.reviewIri);
      continue;
    }
    if (!termReviewsByIri.has(core.reviewedTermIri)) termReviewsByIri.set(core.reviewedTermIri, []);
    termReviewsByIri.get(core.reviewedTermIri).push({
      ...core, reviewDigest: review.reviewDigests[0], reviewIri: review.reviewIri,
    });
  }
  const termDispositions = [];
  const dispositionGaps = [];
  for (const term of inventory.terms) {
    const owned = byTerm.get(term.termKey) ?? [];
    const exact = owned.filter(({ role }) => ![
      'PERMUTATION_META_MODEL_DEPENDENCY', 'VALIDATOR_DEPENDENCY',
    ].includes(role));
    const mechanism = owned.filter(({ role }) => role === 'PERMUTATION_META_MODEL_DEPENDENCY');
    const validator = owned.filter(({ role }) => role === 'VALIDATOR_DEPENDENCY');
    const reviews = termReviewsByIri.get(term.iri) ?? [];
    const review = reviews.length === 1 ? reviews[0] : null;
    let disposition;
    let reasonCode;
    let reviewClosureState = reviews.length === 1 ? 'CURRENT' : reviews.length > 1 ? 'DUPLICATE' : 'MISSING';
    if (exact.length) [disposition, reasonCode] = ['EXACT_CLOSURE_PARTICIPATION', 'UNIVERSAL_EXACT_WITNESS_PRESENT'];
    else if (mechanism.length) [disposition, reasonCode] = ['STRUCTURAL_META_MODEL_DEPENDENCY', 'UNIVERSAL_META_MODEL_DEPENDENCY_EXPLICIT'];
    else if (term.termUsageStateIris.includes(RESERVED) && term.activeOccurrenceCount === 0
      && term.fixtureOccurrenceCount === 0) [disposition, reasonCode] = ['RESERVED_WITH_EXPLICIT_STATE', 'UNIVERSAL_RESERVED_SCOPE_EXPLICIT'];
    else if (term.termUsageStateIris.includes(ZERO_BY_DESIGN) && term.activeOccurrenceCount === 0
      && term.fixtureOccurrenceCount === 0) [disposition, reasonCode] = ['ZERO_INSTANCE_WITH_EXPLICIT_STATE', 'UNIVERSAL_ZERO_INSTANCE_BY_DESIGN_EXPLICIT'];
    else [disposition, reasonCode] = ['AUTHORITY_REVIEW_REQUIRED', validator.length
      ? 'UNIVERSAL_VALIDATOR_DEPENDENCY_UNDISPOSITIONED'
      : term.termKind === 'class' ? 'UNIVERSAL_ACTIVE_CLASS_UNDISPOSITIONED'
        : term.termKind === 'individual' ? 'UNIVERSAL_ACTIVE_INDIVIDUAL_UNDISPOSITIONED'
          : term.declarationKindIris.includes(`${OWL}ObjectProperty`)
            ? 'UNIVERSAL_ACTIVE_RELATIONSHIP_UNCOVERED' : 'UNIVERSAL_ACTIVE_PROPERTY_UNDISPOSITIONED'];
    if (review) {
      const nonAxis = review.participationIri
        === 'urn:usf:permutationparticipationclassification:metadataprovenancenonaxis'
        && review.axisBindingIri === 'urn:usf:permutationaxisbindingclassification:notanaxis'
        && ['urn:usf:permutationfamilycandidateclassification:notafamilycandidate',
          'urn:usf:permutationfamilycandidateclassification:rejected'].includes(review.familyCandidateStateIri);
      const existingAxis = [
        'urn:usf:permutationparticipationclassification:operationalaxis',
        'urn:usf:permutationparticipationclassification:assuranceaxis',
        'urn:usf:permutationparticipationclassification:structuralselector',
        'urn:usf:permutationparticipationclassification:lifecyclederivationinput',
      ].includes(review.participationIri)
        && review.axisBindingIri === 'urn:usf:permutationaxisbindingclassification:existingaxis'
        && ['urn:usf:permutationfamilycandidateclassification:notafamilycandidate',
          'urn:usf:permutationfamilycandidateclassification:rejected'].includes(review.familyCandidateStateIri)
        && exact.length > 0;
      const open = review.participationIri
        === 'urn:usf:permutationparticipationclassification:authoritydecisionrequired'
        || review.axisBindingIri === 'urn:usf:permutationaxisbindingclassification:unregisteredcontrolledaxis'
        || review.familyCandidateStateIri === 'urn:usf:permutationfamilycandidateclassification:authorityreviewrequired';
      if (nonAxis && exact.length > 0) {
        disposition = 'AUTHORITY_REVIEW_REQUIRED';
        reasonCode = 'UNIVERSAL_TERM_REVIEW_CONTRADICTS_EXACT_COVERAGE';
        reviewClosureState = 'CONFLICT';
      } else if (nonAxis) {
        disposition = 'AUTHORITY_REVIEWED_NON_AXIS';
        reasonCode = review.reasonCode;
      } else if (existingAxis) {
        disposition = 'AUTHORITY_REVIEWED_EXACT_PARTICIPATION';
        reasonCode = review.reasonCode;
      } else if (open) {
        disposition = 'AUTHORITY_REVIEW_REQUIRED';
        reasonCode = review.reasonCode;
      } else {
        disposition = 'AUTHORITY_REVIEW_REQUIRED';
        reasonCode = 'UNIVERSAL_TERM_REVIEW_SEMANTIC_COMBINATION_INVALID';
        reviewClosureState = 'CONFLICT';
      }
    }
    const gapDigest = disposition === 'AUTHORITY_REVIEW_REQUIRED' ? digest({ reasonCode, termKey: term.termKey }) : null;
    const core = { authorityDigest: inventory.authorityBinding.authorityDigest, disposition,
      gapIri: gapDigest ? `urn:usf:universalsemanticgap:${gapDigest.slice(7)}` : null,
      inventoryDigest: inventory.inventoryDigest, reasonCode, reviewClosureState,
      reviewDecisionDigest: review?.reviewDigest ?? null,
      reviewDecisionIri: review?.reviewIri ?? null, schemaVersion: 3, termKey: term.termKey,
      witnessDigests: owned.map(({ witnessDigest }) => witnessDigest).sort(compare) };
    termDispositions.push({ ...core, dispositionDigest: digest(core) });
    if (gapDigest) dispositionGaps.push({ code: reasonCode, gapIri: core.gapIri, termIri: term.iri, termKind: term.termKind });
    if (reviews.length === 0) dispositionGaps.push({
      code: 'UNIVERSAL_TERM_REVIEW_MISSING', termIri: term.iri, termKind: term.termKind,
    });
    if (reviews.length > 1) dispositionGaps.push({
      code: 'UNIVERSAL_TERM_REVIEW_DUPLICATE', reviewCount: reviews.length,
      termIri: term.iri, termKind: term.termKind,
    });
  }
  for (const reviewIri of uniqueSorted(invalidTermReviewIris)) dispositionGaps.push({
    code: 'UNIVERSAL_TERM_REVIEW_STALE_OR_INVALID', reviewIri,
  });
  for (const reviewIri of uniqueSorted(orphanTermReviewIris)) dispositionGaps.push({
    code: 'UNIVERSAL_TERM_REVIEW_ORPHAN', reviewIri,
  });
  const signatureWitnessBuffer = [];
  const matchSelector = (family, selector, role) => {
    if (selector.steps.length !== 1) return;
    const step = selector.steps[0];
    const subjectMembers = new Set(selector.subjectClassClosure.memberClassIris);
    const terminalMembers = new Set(selector.terminalClassClosure.memberClassIris);
    for (const signature of inventory.relationshipSignatures) {
      if (signature.predicateIri !== step.predicateIri || signature.objectTermKind !== 'NamedNode') continue;
      const outbound = step.directionIri === 'urn:usf:permutationpathdirection:outbound';
      const inbound = step.directionIri === 'urn:usf:permutationpathdirection:inbound';
      if (!outbound && !inbound) continue;
      const subjectMatch = (outbound ? signature.subjectClassIris : signature.objectClassIris)
        .some((iri) => subjectMembers.has(iri));
      const terminalMatch = (outbound ? signature.objectClassIris : signature.subjectClassIris)
        .some((iri) => terminalMembers.has(iri));
      if (!subjectMatch || !terminalMatch) continue;
      const core = {
        familyIri: family.familyIri, familyRecordDigest: family.familyRecordDigest,
        relationshipSignatureDigest: signature.relationshipSignatureDigest,
        relationshipSignatureIri: signature.relationshipSignatureIri, role,
        selectorDigest: selector.digest, selectorIri: selector.iri,
        stepDirectionIri: step.directionIri, stepIndex: step.index,
      };
      signatureWitnessBuffer.push({ ...core, witnessDigest: digest(core) });
    }
  };
  for (const family of registry.families) {
    for (const binding of family.orderedBindings) {
      if (binding.selector) matchSelector(family, binding.selector, 'EXACT_SINGLE_STEP_DIMENSION_SELECTOR');
    }
    for (const selector of family.applicabilitySelectors) {
      matchSelector(family, selector, 'EXACT_SINGLE_STEP_APPLICABILITY_SELECTOR');
    }
  }
  signatureWitnessBuffer.sort((a, b) => compare(canonicalJson(a), canonicalJson(b)));
  const relationshipSignatureWitnesses = signatureWitnessBuffer.filter((record, index) => index === 0
    || record.witnessDigest !== signatureWitnessBuffer[index - 1].witnessDigest);
  const signatureWitnessByIri = new Map();
  for (const record of relationshipSignatureWitnesses) {
    if (!signatureWitnessByIri.has(record.relationshipSignatureIri)) {
      signatureWitnessByIri.set(record.relationshipSignatureIri, []);
    }
    signatureWitnessByIri.get(record.relationshipSignatureIri).push(record);
  }
  const relationshipSignatureDispositions = [];
  const relationshipSignatureGaps = [];
  for (const signature of inventory.relationshipSignatures) {
    const owned = signatureWitnessByIri.get(signature.relationshipSignatureIri) ?? [];
    const reasonCode = owned.length
      ? 'UNIVERSAL_RELATIONSHIP_SIGNATURE_EXACT_SELECTOR_WITNESS'
      : 'UNIVERSAL_RELATIONSHIP_SIGNATURE_UNDISPOSITIONED';
    const core = {
      authorityDigest: inventory.authorityBinding.authorityDigest,
      disposition: owned.length ? 'EXACT_FAMILY_COVERAGE' : 'AUTHORITY_REVIEW_REQUIRED',
      inventoryDigest: inventory.inventoryDigest, reasonCode,
      relationshipSignatureDigest: signature.relationshipSignatureDigest,
      relationshipSignatureIri: signature.relationshipSignatureIri, schemaVersion: 1,
      witnessDigests: owned.map(({ witnessDigest }) => witnessDigest).sort(compare),
    };
    relationshipSignatureDispositions.push({ ...core, dispositionDigest: digest(core) });
    if (!owned.length) relationshipSignatureGaps.push({
      code: reasonCode, predicateIri: signature.predicateIri,
      relationshipSignatureIri: signature.relationshipSignatureIri,
    });
  }
  const atomicCandidates = [];
  const atomicGaps = [];
  for (const signature of inventory.relationshipSignatures) {
    if ((signatureWitnessByIri.get(signature.relationshipSignatureIri) ?? []).length
      || signature.activeOccurrenceCount === 0) continue;
    const namedObject = signature.objectTermKind === 'NamedNode';
    const literalObject = signature.objectTermKind === 'Literal';
    if (signature.subjectClassIris.length !== 1
      || (namedObject && signature.objectClassIris.length !== 1)
      || (literalObject && !signature.objectDatatypeIri)
      || (!namedObject && !literalObject)) {
      atomicGaps.push({ code: 'UNIVERSAL_ATOMIC_CANDIDATE_ENDPOINT_AMBIGUOUS',
        objectClassIris: signature.objectClassIris, objectDatatypeIri: signature.objectDatatypeIri,
        predicateIri: signature.predicateIri, relationshipSignatureIri: signature.relationshipSignatureIri,
        subjectClassIris: signature.subjectClassIris });
      continue;
    }
    const core = { authorityDigest: inventory.authorityBinding.authorityDigest,
      candidateKind: namedObject ? 'OBJECT_RELATIONSHIP' : 'DATATYPE_RELATIONSHIP',
      classification: 'AUTHORITY_REVIEW_REQUIRED', directionIri: 'urn:usf:permutationpathdirection:outbound',
      inventoryDigest: inventory.inventoryDigest, predicateIri: signature.predicateIri,
      reasonCode: 'UNIVERSAL_RELATIONSHIP_SIGNATURE_UNDISPOSITIONED',
      relationshipSignatureDigest: signature.relationshipSignatureDigest,
      relationshipSignatureIri: signature.relationshipSignatureIri, schemaVersion: 2,
      subjectClassIri: signature.subjectClassIris[0],
      terminalClassIri: namedObject ? signature.objectClassIris[0] : null,
      terminalDatatypeIri: literalObject ? signature.objectDatatypeIri : null };
    const candidateDigest = digest(core);
    atomicCandidates.push({ ...core, candidateDigest,
      candidateIri: `urn:usf:permutationfamilycandidate:${candidateDigest.slice(7)}`,
      recordKind: 'USF_ATOMIC_PERMUTATION_FAMILY_CANDIDATE' });
  }
  atomicCandidates.sort((a, b) => compare(a.candidateIri, b.candidateIri));
  atomicGaps.sort((a, b) => compare(canonicalJson(a), canonicalJson(b)));
  const knownFamilies = new Set(registry.families.map(({ familyIri }) => familyIri));
  const orphanFamilyReviewIris = reviewProjection.familySignatureReviews.filter(({ familyIris }) => (
    familyIris.length !== 1 || !knownFamilies.has(familyIris[0])
  )).map(({ reviewIri }) => reviewIri);
  let familySignatureDriftCount = 0;
  const familyRows = registry.families.map((family) => {
    const related = reviewProjection.familySignatureReviews.filter(({ familyIris }) => (
      familyIris.length === 1 && familyIris[0] === family.familyIri
    ));
    const exactReviews = related.filter((review) => {
      const core = {
        applicabilityRuleIri: family.ruleIri,
        authorityDigest: inventory.authorityBinding.authorityDigest,
        dimensionBindingIris: family.orderedBindings.map(({ bindingIri }) => bindingIri).sort(compare),
        dispositionIri: FAMILY_REVIEW_WARRANTED, familyIri: family.familyIri,
        registryDigest: registry.registryDigest, signatureDigest: family.familyRecordDigest,
        subjectRegistrationIri: family.registrationIri,
      };
      const match = canonicalJson(review.applicabilityRuleIris) === canonicalJson([core.applicabilityRuleIri])
        && canonicalJson(review.authorityDigests) === canonicalJson([core.authorityDigest])
        && canonicalJson(review.dimensionBindingIris) === canonicalJson(core.dimensionBindingIris)
        && canonicalJson(review.dispositionIris) === canonicalJson([core.dispositionIri])
        && canonicalJson(review.registryDigests) === canonicalJson([core.registryDigest])
        && canonicalJson(review.signatureDigests) === canonicalJson([core.signatureDigest])
        && canonicalJson(review.subjectRegistrationIris) === canonicalJson([core.subjectRegistrationIri])
        && canonicalJson(review.reviewDigests) === canonicalJson([digest(core)]);
      if (!match) familySignatureDriftCount += 1;
      return match;
    });
    const reviewState = related.length === 0 ? 'REVIEW_MISSING'
      : related.length > 1 ? 'REVIEW_DUPLICATE'
        : exactReviews.length === 1 ? 'REVIEW_CURRENT' : 'REVIEW_STALE_OR_INVALID';
    return {
      acceptedReviewIri: reviewState === 'REVIEW_CURRENT' ? exactReviews[0].reviewIri : null,
      expectedFamilyRecordDigest: family.familyRecordDigest,
      familyIri: family.familyIri,
      relatedReviewCount: related.length,
      reviewState,
    };
  });
  const registeredFamilyModelReview = {
    duplicateReviewCount: familyRows.filter(({ reviewState }) => reviewState === 'REVIEW_DUPLICATE').length,
    exactReviewCount: familyRows.filter(({ reviewState }) => reviewState === 'REVIEW_CURRENT').length,
    missingReviewCount: familyRows.filter(({ reviewState }) => reviewState === 'REVIEW_MISSING').length,
    orphanReviewCount: orphanFamilyReviewIris.length,
    orphanReviewIris: orphanFamilyReviewIris,
    reviewClassIri: FAMILY_REVIEW_CLASS,
    reviewSetDigest: digest(familyRows),
    rows: familyRows,
    signatureDriftCount: familySignatureDriftCount,
    staleOrInvalidReviewCount: familyRows.filter(({ reviewState }) => (
      reviewState === 'REVIEW_STALE_OR_INVALID'
    )).length,
    warrantedDispositionIri: FAMILY_REVIEW_WARRANTED,
  };
  const expectedTermIris = uniqueSorted(inventory.terms.map(({ iri }) => iri));
  const expectedFamilyIris = registry.families.map(({ familyIri }) => familyIri).sort(compare);
  const currentCoverage = reviewProjection.coverages.filter((coverage) => (
    canonicalJson(coverage.authorityDigests) === canonicalJson([inventory.authorityBinding.authorityDigest])
      && canonicalJson(coverage.inventoryDigests) === canonicalJson([inventory.inventoryDigest])
      && canonicalJson(coverage.familyRegistryDigests) === canonicalJson([registry.registryDigest])
  ));
  const exactTermReviews = expectedTermIris.map((iri) => termReviewsByIri.get(iri) ?? []);
  const exactFamilyReviews = familyRows.map(({ acceptedReviewIri }) => acceptedReviewIri);
  const exactCoverage = currentCoverage.filter((coverage) => {
    const core = {
      authorityDigest: inventory.authorityBinding.authorityDigest,
      expectedFamilyIris,
      expectedTermIris,
      familyRegistryDigest: registry.registryDigest,
      familySignatureAlgorithm: FAMILY_SIGNATURE_ALGORITHM,
      familySignatureReviewIris: exactFamilyReviews.filter(Boolean).sort(compare),
      inventoryDigest: inventory.inventoryDigest,
      termReviewIris: exactTermReviews.flatMap((reviews) => (
        reviews.map(({ reviewIri }) => reviewIri)
      )).sort(compare),
      termSetAlgorithm: TERM_SET_ALGORITHM,
    };
    return exactTermReviews.every((reviews) => reviews.length === 1)
      && exactFamilyReviews.every(Boolean)
      && canonicalJson(coverage.expectedFamilyIris) === canonicalJson(expectedFamilyIris)
      && canonicalJson(coverage.expectedTermIris) === canonicalJson(expectedTermIris)
      && canonicalJson(coverage.familySignatureAlgorithms) === canonicalJson([FAMILY_SIGNATURE_ALGORITHM])
      && canonicalJson(coverage.familySignatureReviewIris) === canonicalJson(core.familySignatureReviewIris)
      && canonicalJson(coverage.termReviewIris) === canonicalJson(core.termReviewIris)
      && canonicalJson(coverage.termSetAlgorithms) === canonicalJson([TERM_SET_ALGORITHM])
      && canonicalJson(coverage.coverageDigests) === canonicalJson([digest(core)]);
  });
  const orphanCoverageIris = reviewProjection.coverages.filter((coverage) => (
    !currentCoverage.includes(coverage)
  )).map(({ coverageIri }) => coverageIri).sort(compare);
  const registeredReviewCoverage = {
    acceptedCoverageIri: exactCoverage.length === 1 ? exactCoverage[0].coverageIri : null,
    coverageState: exactCoverage.length === 1 ? 'COVERAGE_CURRENT'
      : exactCoverage.length > 1 ? 'COVERAGE_DUPLICATE'
        : currentCoverage.length > 0 ? 'COVERAGE_STALE_OR_INVALID' : 'COVERAGE_MISSING',
    currentCoverageCount: currentCoverage.length,
    expectedFamilyCount: expectedFamilyIris.length,
    expectedFamilySetDigest: digest(expectedFamilyIris),
    expectedTermCount: expectedTermIris.length,
    expectedTermSetDigest: digest(expectedTermIris),
    orphanCoverageCount: orphanCoverageIris.length,
    orphanCoverageIris,
  };
  const familyReviewGaps = familyRows.flatMap(({ familyIri, reviewState }) => (
    reviewState === 'REVIEW_CURRENT' ? [] : [{
      code: `UNIVERSAL_REGISTERED_FAMILY_${reviewState}`, familyIri,
    }]
  )).concat(orphanFamilyReviewIris.map((reviewIri) => ({
    code: 'UNIVERSAL_REGISTERED_FAMILY_REVIEW_ORPHAN', reviewIri,
  })));
  const coverageGaps = [
    ...(registeredReviewCoverage.coverageState === 'COVERAGE_CURRENT' ? [] : [{
      code: `UNIVERSAL_REVIEW_${registeredReviewCoverage.coverageState}`,
    }]),
    ...orphanCoverageIris.map((coverageIri) => ({
      code: 'UNIVERSAL_REVIEW_COVERAGE_ORPHAN', coverageIri,
    })),
  ];
  const gaps = [
    ...(inventory.authorityInputVerification.fullAuthorityTermParityState === 'PROVEN_EQUAL'
      ? [] : [{ code: 'UNIVERSAL_LIVE_AUTHORITY_FULL_TERM_PARITY_UNPROVEN' }]),
    ...inventory.undeclaredClassIris.map((termIri) => ({ code: 'UNIVERSAL_ACTIVE_CLASS_UNDECLARED', termIri })),
    ...inventory.undeclaredPredicateIris.map((predicateIri) => ({ code: 'UNIVERSAL_ACTIVE_RELATIONSHIP_UNDECLARED', predicateIri })),
    ...dispositionGaps, ...relationshipSignatureGaps, ...atomicGaps,
    ...atomicCandidates.map(({ candidateIri, predicateIri, relationshipSignatureIri }) => ({
      candidateIri, code: 'UNIVERSAL_CANDIDATE_MODEL_NOT_AUTHORITY',
      predicateIri, relationshipSignatureIri,
    })),
    ...familyReviewGaps, ...coverageGaps,
  ].sort((a, b) => compare(canonicalJson(a), canonicalJson(b)));
  const termDispositionPartition = Object.fromEntries([
    'AUTHORITY_REVIEW_REQUIRED', 'AUTHORITY_REVIEWED_EXACT_PARTICIPATION',
    'AUTHORITY_REVIEWED_NON_AXIS', 'EXACT_CLOSURE_PARTICIPATION',
    'RESERVED_WITH_EXPLICIT_STATE', 'STRUCTURAL_META_MODEL_DEPENDENCY',
    'ZERO_INSTANCE_WITH_EXPLICIT_STATE',
  ].map((state) => [state, termDispositions.filter(({ disposition }) => disposition === state).length]));
  const relationshipSignatureDispositionPartition = Object.fromEntries([
    'AUTHORITY_REVIEW_REQUIRED', 'EXACT_FAMILY_COVERAGE',
  ].map((state) => [state, relationshipSignatureDispositions
    .filter(({ disposition }) => disposition === state).length]));
  return {
    atomicCandidates,
    gaps,
    registeredFamilyModelReview,
    registeredReviewCoverage,
    relationshipSignatureDispositionPartition,
    relationshipSignatureDispositions,
    relationshipSignatureWitnesses,
    termDispositionPartition,
    termDispositions,
    witnesses,
  };
}

function verifyInternalDigest(record, field, code) {
  const value = record?.[field];
  if (!SHA256.test(value ?? '')) fail(code, `${field} is absent`);
  const core = { ...record };
  delete core[field];
  if (digest(core) !== value) fail(code, `${field} does not bind the record`);
}

export function proveUniversalSemanticCoverage({
  algorithmSourceDigest,
  analysis,
  authorityBinding,
  authorityInputRoot,
  authorityPacketPath,
  authorityProjectionPath,
  foundationAssessment,
  foundationProof,
  inventory,
  reviewProjection,
  registry,
  repositoryRoot,
}) {
  if (![authorityBinding?.authorityDigest, authorityBinding?.authorityPacketDigest,
    authorityBinding?.authorityProjectionDigest, algorithmSourceDigest].every((value) => SHA256.test(value ?? ''))) {
    fail('UNIVERSAL_PROOF_AUTHORITY_BINDING_INVALID', 'exact authority and algorithm digests are required');
  }
  verifyInternalDigest(inventory, 'inventoryDigest', 'UNIVERSAL_PROOF_INVENTORY_DIGEST_MISMATCH');
  verifyInternalDigest(registry, 'registryDigest', 'UNIVERSAL_PROOF_REGISTRY_DIGEST_MISMATCH');
  verifyInternalDigest(reviewProjection, 'reviewProjectionDigest',
    'UNIVERSAL_PROOF_REVIEW_PROJECTION_DIGEST_MISMATCH');
  verifyInternalDigest(analysis, 'analysisDigest', 'UNIVERSAL_PROOF_ANALYSIS_DIGEST_MISMATCH');
  verifyInternalDigest(foundationAssessment, 'assessmentDigest', 'UNIVERSAL_PROOF_FOUNDATION_DIGEST_MISMATCH');
  verifyInternalDigest(foundationProof, 'proofDigest', 'UNIVERSAL_PROOF_FOUNDATION_DIGEST_MISMATCH');
  if (canonicalJson(inventory.authorityBinding) !== canonicalJson(authorityBinding)
    || canonicalJson(foundationAssessment.baselineAuthorityBinding) !== canonicalJson(authorityBinding)
    || canonicalJson(foundationProof.baselineAuthorityBinding) !== canonicalJson(authorityBinding)
    || analysis.authorityDigest !== authorityBinding.authorityDigest
    || analysis.foundationAssessmentDigest !== foundationAssessment.assessmentDigest
    || analysis.foundationProofDigest !== foundationProof.proofDigest
    || analysis.reviewProjectionDigest !== reviewProjection.reviewProjectionDigest) {
    fail('UNIVERSAL_PROOF_AUTHORITY_BINDING_MISMATCH', 'candidate inputs do not share one authority/foundation binding');
  }
  const authorityInputVerification = reconstructAuthorityVerification(
    realpathSync(authorityInputRoot ?? repositoryRoot),
    authorityBinding,
    authorityPacketPath,
    authorityProjectionPath,
  );
  if (canonicalJson(authorityInputVerification) !== canonicalJson(inventory.authorityInputVerification)) {
    fail('UNIVERSAL_PROOF_AUTHORITY_INPUT_RECONSTRUCTION_MISMATCH',
      'authority input verification differs from independently rebound bytes');
  }
  const dataset = loadDataset(repositoryRoot);
  const analyzerSourceDigest = sha256(readFileSync(join(
    realpathSync(repositoryRoot),
    'assurance',
    'permutation-closure',
    'universal-semantic-coverage.mjs',
  )));
  if (registry.projectionAlgorithmSourceDigest !== analyzerSourceDigest
    || analysis.analysisAlgorithmSourceDigest !== analyzerSourceDigest
    || reviewProjection.projectionAlgorithmSourceDigest !== analyzerSourceDigest) {
    fail('UNIVERSAL_PROOF_ANALYZER_SOURCE_BINDING_MISMATCH',
      'inventory projections do not share the current analyzer source digest');
  }
  const independentlyReconstructedRegistry = independentlyReconstructExactFamilyRegistry(
    repositoryRoot,
    analyzerSourceDigest,
  );
  if (canonicalJson(independentlyReconstructedRegistry) !== canonicalJson(registry)) {
    const code = familyRegistryMismatchCode(registry, independentlyReconstructedRegistry);
    fail(code, 'candidate family registry differs from independent authored-model reconstruction', {
      actualRegistryDigest: registry.registryDigest,
      expectedRegistryDigest: independentlyReconstructedRegistry.registryDigest,
    });
  }
  const independent = reconstructInventory(
    dataset,
    authorityBinding,
    authorityInputVerification,
    analyzerSourceDigest,
  );
  const inventoryMismatches = uniqueSorted([...new Set([
    ...Object.keys(independent), ...Object.keys(inventory),
  ])].filter((field) => canonicalJson(independent[field]) !== canonicalJson(inventory[field])));
  if (inventoryMismatches.length) fail('UNIVERSAL_PROOF_INVENTORY_RECONSTRUCTION_MISMATCH',
    'independent semantic inventory differs', { fields: inventoryMismatches.sort(compare) });

  const directFamilies = directFamilySignatures(dataset, registry);
  const familySetMatch = canonicalJson(directFamilies.familyIris) === canonicalJson(directFamilies.candidateFamilyIris);
  const familySignatureMismatchIris = directFamilies.signatures.filter(({ match }) => !match)
    .map(({ familyIri }) => familyIri);
  if (!familySetMatch || familySignatureMismatchIris.length) fail('UNIVERSAL_PROOF_FAMILY_RECONSTRUCTION_MISMATCH',
    'registered family identities or direct signatures differ', { familySetMatch, familySignatureMismatchIris });

  const independentReviewProjection = reconstructReviewProjection(
    dataset,
    inventory,
    registry,
    analyzerSourceDigest,
  );
  if (canonicalJson(reviewProjection.reviewSourceRecords)
      !== canonicalJson(independentReviewProjection.reviewSourceRecords)
    || reviewProjection.reviewSourceCount !== independentReviewProjection.reviewSourceCount
    || reviewProjection.reviewSourceSetDigest !== independentReviewProjection.reviewSourceSetDigest) {
    fail('UNIVERSAL_PROOF_REVIEW_SOURCE_BINDING_MISMATCH',
      'review source records differ from independently rebound review graph bytes');
  }
  if (canonicalJson(independentReviewProjection) !== canonicalJson(reviewProjection)) {
    fail('UNIVERSAL_PROOF_REVIEW_PROJECTION_RECONSTRUCTION_MISMATCH',
      'review projection differs from current semantic source bytes');
  }
  const reconstructed = reconstructAnalysis(inventory, registry, reviewProjection);
  const analysisMismatches = [];
  const compareAnalysis = (field, expected, actual) => {
    if (canonicalJson(expected) !== canonicalJson(actual)) analysisMismatches.push(field);
  };
  compareAnalysis('witnesses', reconstructed.witnesses, analysis.witnesses);
  compareAnalysis('termDispositions', reconstructed.termDispositions, analysis.termDispositions);
  compareAnalysis('termDispositionPartition', reconstructed.termDispositionPartition,
    analysis.termDispositionPartition);
  compareAnalysis('termDispositionSetDigest', digest(reconstructed.termDispositions),
    analysis.termDispositionSetDigest);
  const witnessIndexCore = {
    inventoryDigest: inventory.inventoryDigest,
    recordKind: 'USF_UNIVERSAL_EXACT_COVERAGE_WITNESS_INDEX',
    records: reconstructed.witnesses,
    registryDigest: registry.registryDigest,
    schemaVersion: 2,
    witnessCount: reconstructed.witnesses.length,
  };
  compareAnalysis('witnessCount', reconstructed.witnesses.length, analysis.witnessCount);
  compareAnalysis('witnessIndexDigest', digest(witnessIndexCore), analysis.witnessIndexDigest);
  compareAnalysis('relationshipSignatureWitnesses', reconstructed.relationshipSignatureWitnesses,
    analysis.relationshipSignatureWitnesses);
  compareAnalysis('relationshipSignatureWitnessCount',
    reconstructed.relationshipSignatureWitnesses.length, analysis.relationshipSignatureWitnessCount);
  compareAnalysis('relationshipSignatureWitnessSetDigest',
    digest(reconstructed.relationshipSignatureWitnesses), analysis.relationshipSignatureWitnessSetDigest);
  compareAnalysis('relationshipSignatureDispositions',
    reconstructed.relationshipSignatureDispositions, analysis.relationshipSignatureDispositions);
  compareAnalysis('relationshipSignatureDispositionPartition',
    reconstructed.relationshipSignatureDispositionPartition,
    analysis.relationshipSignatureDispositionPartition);
  compareAnalysis('relationshipSignatureDispositionSetDigest',
    digest(reconstructed.relationshipSignatureDispositions),
    analysis.relationshipSignatureDispositionSetDigest);
  compareAnalysis('atomicCandidates', reconstructed.atomicCandidates, analysis.atomicCandidates);
  compareAnalysis('atomicCandidateCount', reconstructed.atomicCandidates.length, analysis.atomicCandidateCount);
  compareAnalysis('atomicCandidateSetDigest', digest(reconstructed.atomicCandidates),
    analysis.atomicCandidateSetDigest);
  const atomicCandidatePredicateCounts = uniqueSorted(reconstructed.atomicCandidates
    .map(({ predicateIri }) => predicateIri)).map((predicateIri) => ({
      candidateCount: reconstructed.atomicCandidates.filter((candidate) => (
        candidate.predicateIri === predicateIri
      )).length,
      predicateIri,
    }));
  compareAnalysis('atomicCandidatePredicateCounts', atomicCandidatePredicateCounts,
    analysis.atomicCandidatePredicateCounts);
  compareAnalysis('gaps', reconstructed.gaps, analysis.gaps);
  compareAnalysis('gapCount', reconstructed.gaps.length, analysis.gapCount);
  compareAnalysis('gapSetDigest', digest(reconstructed.gaps), analysis.gapSetDigest);
  const gapCodeCounts = Object.fromEntries(uniqueSorted(reconstructed.gaps.map(({ code }) => code))
    .map((code) => [code, reconstructed.gaps.filter((gap) => gap.code === code).length]));
  compareAnalysis('gapCodeCounts', gapCodeCounts, analysis.gapCodeCounts);
  compareAnalysis('registeredFamilyModelReview', reconstructed.registeredFamilyModelReview,
    analysis.registeredFamilyModelReview);
  compareAnalysis('registeredReviewCoverage', reconstructed.registeredReviewCoverage,
    analysis.registeredReviewCoverage);
  compareAnalysis('reviewProjectionDigest', reviewProjection.reviewProjectionDigest,
    analysis.reviewProjectionDigest);
  compareAnalysis('verdict', reconstructed.gaps.length === 0
    ? 'UNIVERSAL_FAMILY_MODEL_COMPLETE' : 'UNIVERSAL_FAMILY_MODEL_INCOMPLETE', analysis.verdict);
  if (analysisMismatches.length) fail('UNIVERSAL_PROOF_ANALYSIS_RECONSTRUCTION_MISMATCH',
    'candidate coverage analysis differs from independent reconstruction', { fields: analysisMismatches.sort(compare) });

  const resultCore = {
    algorithmSourceDigest,
    analysisDigest: analysis.analysisDigest,
    analyzerSourceDigest,
    authorityBinding,
    candidateVerdict: analysis.verdict,
    familyCount: directFamilies.familyIris.length,
    familySignatureSetDigest: digest(directFamilies.signatures.map(({ direct }) => direct)),
    foundationAssessmentDigest: foundationAssessment.assessmentDigest,
    foundationProofDigest: foundationProof.proofDigest,
    gapCount: reconstructed.gaps.length,
    gapSetDigest: digest(reconstructed.gaps),
    inventoryDigest: inventory.inventoryDigest,
    nonClaims: ['NOT_SEMANTIC_AUTHORITY', 'NOT_CAPABILITY_PERMUTATION_CLOSURE', 'NOT_PRODUCTION_READINESS'],
    recordKind: 'USF_UNIVERSAL_SEMANTIC_GAP_AND_CROSS_PRODUCT_INDEPENDENT_PROOF',
    registryDigest: registry.registryDigest,
    results: {
      analysisReconstructionMismatchCount: 0,
      familyReconstructionMismatchCount: 0,
      inventoryReconstructionMismatchCount: 0,
      reviewSourceReconstructionMismatchCount: 0,
      reviewProjectionReconstructionMismatchCount: 0,
      unresolvedFamilyReviewCount: reconstructed.registeredFamilyModelReview.rows
        .filter(({ reviewState }) => reviewState !== 'REVIEW_CURRENT').length,
      unresolvedSemanticTermCount: reconstructed.termDispositions
        .filter(({ disposition }) => disposition === 'AUTHORITY_REVIEW_REQUIRED').length,
    },
    reviewProjectionDigest: reviewProjection.reviewProjectionDigest,
    reviewSourceSetDigest: independentReviewProjection.reviewSourceSetDigest,
    schemaVersion: 3,
    sourceSetDigest: independent.sourceSetDigest,
    verdict: 'UNIVERSAL_SEMANTIC_GAP_AND_CROSS_PRODUCT_RECONSTRUCTION_PASS',
  };
  return { ...resultCore, proofDigest: digest(resultCore) };
}

function exactArgument(name) {
  const prefix = `--${name}=`;
  const matches = process.argv.filter((item) => item.startsWith(prefix));
  if (matches.length !== 1 || matches[0].length === prefix.length) {
    fail('UNIVERSAL_PROOF_EXACT_ARGUMENT_REQUIRED', prefix);
  }
  return matches[0].slice(prefix.length);
}

function readBoundJson(root, name) {
  const pathArgument = exactArgument(name);
  const expectedDigest = exactArgument(`${name}-digest`);
  const path = resolve(root, pathArgument);
  if (!contained(root, path)) fail('UNIVERSAL_PROOF_INPUT_PATH_ESCAPE', pathArgument);
  const bytes = readFileSync(path);
  if (sha256(bytes) !== expectedDigest) fail('UNIVERSAL_PROOF_INPUT_FILE_DIGEST_MISMATCH', name);
  return JSON.parse(bytes.toString('utf8'));
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const repositoryRoot = realpathSync(resolve(dirname(fileURLToPath(import.meta.url)), '..', '..'));
    const proof = proveUniversalSemanticCoverage({
      algorithmSourceDigest: sha256(readFileSync(fileURLToPath(import.meta.url))),
      analysis: readBoundJson(repositoryRoot, 'analysis'),
      authorityBinding: {
        authorityDigest: exactArgument('authority-digest'),
        authorityPacketDigest: exactArgument('authority-packet-digest'),
        authorityProjectionDigest: exactArgument('authority-projection-digest'),
      },
      authorityPacketPath: exactArgument('authority-packet'),
      authorityProjectionPath: exactArgument('authority-projection'),
      foundationAssessment: readBoundJson(repositoryRoot, 'foundation-assessment'),
      foundationProof: readBoundJson(repositoryRoot, 'foundation-proof'),
      inventory: readBoundJson(repositoryRoot, 'inventory'),
      reviewProjection: readBoundJson(repositoryRoot, 'review-projection'),
      registry: readBoundJson(repositoryRoot, 'registry'),
      repositoryRoot,
    });
    const content = `${canonicalJson(proof)}\n`;
    const fileDigest = sha256(content);
    const outputPath = join(
      '.work',
      'generated',
      `universal-semantic-coverage-proof-${fileDigest.slice(7)}.json`,
    );
    mkdirSync(join(repositoryRoot, '.work', 'generated'), { recursive: true });
    writeFileSync(join(repositoryRoot, outputPath), content);
    process.stdout.write(`${canonicalJson({
      candidateVerdict: proof.candidateVerdict,
      fileDigest,
      gapCount: proof.gapCount,
      outputPath,
      proofDigest: proof.proofDigest,
      results: proof.results,
      verdict: proof.verdict,
    })}\n`);
  } catch (error) {
    process.stderr.write(`${error.code ?? error.name}:${error.message}\n`);
    process.exitCode = 1;
  }
}
