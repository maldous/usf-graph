import {
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import N3 from 'n3';
import YAML from 'yaml';

import {
  canonicalJson,
  sha256,
} from '../semantic-model-compilation/realisation-option-evaluation.mjs';
import { loadPermutationFamilyRegistry } from './family-registry.mjs';

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
const STANDARD_DEFINES_CLASS = `${O}standardDefinesSemanticClass`;
const STANDARD_DEFINES_PROPERTY = `${O}standardDefinesSemanticProperty`;
const PERMUTATION_GRAPH = 'urn:usf:graph:permutation-families';
const FIXTURE_PATH = 'semantic-model/fixtures/conforming/universal-service-foundation.trig';
const SHA256 = /^sha256:[0-9a-f]{64}$/u;

const CLASS_KINDS = new Set([`${OWL}Class`, `${RDFS}Class`]);
const PROPERTY_KINDS = new Set([
  `${OWL}AnnotationProperty`, `${OWL}AsymmetricProperty`, `${OWL}DatatypeProperty`,
  `${OWL}DeprecatedProperty`, `${OWL}FunctionalProperty`, `${OWL}InverseFunctionalProperty`,
  `${OWL}IrreflexiveProperty`, `${OWL}ObjectProperty`, `${OWL}ReflexiveProperty`,
  `${OWL}SymmetricProperty`, `${OWL}TransitiveProperty`, `${RDF}Property`,
]);
const RESERVED = 'urn:usf:termusagestate:reservedfuturescope';
const ZERO_BY_DESIGN = 'urn:usf:termusagestate:zeroinstancebydesign';
const FAMILY_REVIEW_CLASS = `${O}PermutationFamilySignatureReview`;
const FAMILY_REVIEW_WARRANTED = 'urn:usf:permutationfamilymodelreviewdisposition:warranted';
const TERM_REVIEW_CLASS = `${O}SemanticTermPermutationReview`;
const REVIEW_COVERAGE_CLASS = `${O}PermutationReviewCoverage`;
const FAMILY_CANDIDATE_CLASS = `${O}PermutationFamilyCandidate`;
const VALIDATOR_SOURCE_GROUPS = new Set(['rules', 'shapeGraphs']);
const TERM_SET_ALGORITHM = 'semantic-input-term-key-set-v1';
const FAMILY_SIGNATURE_ALGORITHM = 'family-record-canonical-json-sha256-v1';

const compare = (left, right) => (left < right ? -1 : left > right ? 1 : 0);
const uniqueSorted = (values) => [...new Set(values)].sort(compare);
const digest = (value) => sha256(canonicalJson(value));
const ANALYZER_SOURCE_DIGEST = sha256(readFileSync(fileURLToPath(import.meta.url)));
const termIdentity = (term) => `${term.termType}\0${term.value}\0${term.datatypeIri ?? ''}\0${term.language ?? ''}`;

export class UniversalSemanticCoverageError extends Error {
  constructor(code, message, details = {}) {
    super(`${code}: ${message}`);
    this.name = 'UniversalSemanticCoverageError';
    this.code = code;
    this.details = details;
  }
}

const fail = (code, message, details) => {
  throw new UniversalSemanticCoverageError(code, message, details);
};

function canonicalTerm(term, sourcePath) {
  if (term.termType === 'NamedNode') return { termType: 'NamedNode', value: term.value };
  if (term.termType === 'BlankNode') {
    return { termType: 'BlankNode', value: `${sourcePath}#${term.value}` };
  }
  if (term.termType === 'Literal') {
    return {
      datatypeIri: term.datatype?.value || `${XSD}string`,
      language: term.language || '',
      termType: 'Literal',
      value: term.value,
    };
  }
  if (term.termType === 'DefaultGraph') return { termType: 'DefaultGraph', value: '' };
  fail('UNIVERSAL_RDF_TERM_UNSUPPORTED', `unsupported RDF term ${term.termType}`);
}

function exactAuthorityBinding(binding) {
  if (!binding || !SHA256.test(binding.authorityDigest ?? '')
    || !SHA256.test(binding.authorityPacketDigest ?? '')
    || !SHA256.test(binding.authorityProjectionDigest ?? '')) {
    fail('UNIVERSAL_AUTHORITY_BINDING_INVALID', 'three exact authority digests are required');
  }
  return Object.freeze({
    authorityDigest: binding.authorityDigest,
    authorityPacketDigest: binding.authorityPacketDigest,
    authorityProjectionDigest: binding.authorityProjectionDigest,
  });
}

function contained(root, target) {
  const value = relative(root, target);
  return value !== '' && value !== '..' && !value.startsWith(`..${sep}`);
}

function verifiedJsonInput(repositoryRoot, pathArgument, expectedDigest, code) {
  if (typeof pathArgument !== 'string' || pathArgument.length === 0 || pathArgument.startsWith('/')) {
    fail(code, 'authority input path must be one repository-relative path');
  }
  const path = resolve(repositoryRoot, pathArgument);
  if (!contained(repositoryRoot, path)) fail(code, 'authority input path escapes the repository', { path: pathArgument });
  let stat;
  let canonicalPath;
  try {
    stat = lstatSync(path);
    canonicalPath = realpathSync(path);
  } catch (error) {
    fail(code, 'authority input is absent or cannot be rebound', { causeCode: error?.code, path: pathArgument });
  }
  if (!stat.isFile() || stat.isSymbolicLink() || !contained(repositoryRoot, canonicalPath)) {
    fail(code, 'authority input must be a canonical regular file', { path: pathArgument });
  }
  const before = readFileSync(path);
  const observedDigest = sha256(before);
  if (observedDigest !== expectedDigest || observedDigest !== sha256(readFileSync(path))) {
    fail(code, 'authority input digest mismatch or mutation', {
      expectedDigest,
      observedDigest,
      path: pathArgument,
    });
  }
  let value;
  try {
    value = JSON.parse(before.toString('utf8'));
  } catch (error) {
    fail(code, 'authority input is not JSON', { message: error.message, path: pathArgument });
  }
  return { bytes: before, path: pathArgument, value };
}

export function verifyUniversalAuthorityInputs({ authorityBinding, authorityPacketPath,
  authorityProjectionPath, repositoryRoot }) {
  const binding = exactAuthorityBinding(authorityBinding);
  const packet = verifiedJsonInput(repositoryRoot, authorityPacketPath,
    binding.authorityPacketDigest, 'UNIVERSAL_AUTHORITY_PACKET_INVALID');
  const projection = verifiedJsonInput(repositoryRoot, authorityProjectionPath,
    binding.authorityProjectionDigest, 'UNIVERSAL_AUTHORITY_PROJECTION_INVALID');
  if (packet.value?.recordKind !== 'USF_PERMUTATION_AUTHORITY_INPUT_PACKET'
    || packet.value?.packetSchemaVersion !== 1
    || packet.value?.authorityDigest !== binding.authorityDigest) {
    fail('UNIVERSAL_AUTHORITY_PACKET_INVALID', 'packet identity or embedded authority digest is invalid');
  }
  if (projection.value?.recordKind !== 'USF_PERMUTATION_AUTHORITY_PROJECTION'
    || projection.value?.schemaVersion !== 1
    || projection.value?.authorityDigest !== binding.authorityDigest
    || projection.value?.basePacketDigest !== binding.authorityPacketDigest
    || projection.value?.projectionMethod !== 'BOUNDED_USF_MCP_SELECT'
    || !Array.isArray(projection.value?.triples)
    || !Array.isArray(projection.value?.projectedClassIris)
    || !Array.isArray(projection.value?.projectedPredicateIris)) {
    fail('UNIVERSAL_AUTHORITY_PROJECTION_INVALID', 'projection identity or packet binding is invalid');
  }
  const core = {
    authorityDigest: binding.authorityDigest,
    authorityPacket: {
      contentDigest: binding.authorityPacketDigest,
      path: packet.path,
      recordKind: packet.value.recordKind,
      schemaVersion: packet.value.packetSchemaVersion,
    },
    authorityProjection: {
      basePacketDigest: projection.value.basePacketDigest,
      contentDigest: binding.authorityProjectionDigest,
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
  return Object.freeze({ ...core, verificationDigest: digest(core) });
}

function sourcePath(root, modelRoot, entry) {
  if (!entry || typeof entry.file !== 'string' || typeof entry.graph !== 'string'
    || !/\.(?:ttl|trig)$/u.test(entry.file) || entry.file.startsWith('/')
    || entry.file.split('/').some((segment) => segment === '' || segment === '.' || segment === '..')) {
    fail('UNIVERSAL_MANIFEST_ENTRY_INVALID', 'semantic source entry is invalid', { entry });
  }
  const path = resolve(modelRoot, entry.file);
  if (!contained(root, path)) fail('UNIVERSAL_MANIFEST_PATH_ESCAPE', entry.file);
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || !contained(root, realpathSync(path))) {
    fail('UNIVERSAL_MANIFEST_INPUT_NOT_REGULAR', entry.file);
  }
  return path;
}

function stripSparqlCommentsAndStrings(source) {
  let output = '';
  let index = 0;
  let quote = null;
  let triple = false;
  let escaped = false;
  let iri = false;
  while (index < source.length) {
    const character = source[index];
    if (iri) {
      output += character;
      index += 1;
      if (character === '>') iri = false;
      continue;
    }
    if (quote !== null) {
      if (escaped) {
        escaped = false;
        output += ' ';
        index += 1;
      } else if (character === '\\') {
        escaped = true;
        output += ' ';
        index += 1;
      } else if (triple && source.slice(index, index + 3) === quote.repeat(3)) {
        output += '   ';
        index += 3;
        quote = null;
        triple = false;
      } else if (!triple && character === quote) {
        output += ' ';
        index += 1;
        quote = null;
      } else {
        output += character === '\n' ? '\n' : ' ';
        index += 1;
      }
      continue;
    }
    if (character === '<') {
      iri = true;
      output += character;
      index += 1;
      continue;
    }
    if (character === '#') {
      const end = source.indexOf('\n', index);
      if (end === -1) return `${output}${' '.repeat(source.length - index)}`;
      output += `${' '.repeat(end - index)}\n`;
      index = end + 1;
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
      triple = source.slice(index, index + 3) === character.repeat(3);
      output += triple ? '   ' : ' ';
      index += triple ? 3 : 1;
      continue;
    }
    output += character;
    index += 1;
  }
  return output;
}

function sparqlDependencyIris(bytes) {
  const source = bytes.toString('utf8');
  const stripped = stripSparqlCommentsAndStrings(source);
  const prefixes = new Map([...stripped.matchAll(/\bPREFIX\s+([A-Za-z][A-Za-z0-9_-]*):\s*<([^>]+)>/giu)]
    .map((match) => [match[1], match[2]]));
  const iris = new Set([...stripped.matchAll(/<([^<>\s]+)>/gu)].map((match) => match[1]));
  for (const match of stripped.matchAll(/\b([A-Za-z][A-Za-z0-9_-]*):([A-Za-z_][A-Za-z0-9._~-]*)/gu)) {
    if (prefixes.has(match[1])) iris.add(`${prefixes.get(match[1])}${match[2]}`);
  }
  return uniqueSorted(iris);
}

function readRuleDependencySources(root, modelRoot, rules) {
  const records = [];
  const sourceRecords = [];
  for (const entry of [...(rules ?? [])].sort((left, right) => compare(left.file, right.file))) {
    if (!entry || typeof entry.file !== 'string' || !entry.file.endsWith('.rq')
      || entry.file.startsWith('/') || entry.file.split('/').some((part) => ['', '.', '..'].includes(part))) {
      fail('UNIVERSAL_RULE_MANIFEST_ENTRY_INVALID', 'semantic rule entry is invalid', { entry });
    }
    const path = resolve(modelRoot, entry.file);
    if (!contained(root, path)) fail('UNIVERSAL_MANIFEST_PATH_ESCAPE', entry.file);
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || !contained(root, realpathSync(path))) {
      fail('UNIVERSAL_MANIFEST_INPUT_NOT_REGULAR', entry.file);
    }
    const bytes = readFileSync(path);
    if (sha256(bytes) !== sha256(readFileSync(path))) fail('UNIVERSAL_SOURCE_MUTATED_DURING_READ', entry.file);
    const core = {
      contentDigest: sha256(bytes),
      declaredGraphIri: entry.output,
      manifestGroup: 'rules',
      path: `semantic-model/${entry.file}`,
    };
    const source = { ...core, sourceRecordDigest: digest(core) };
    sourceRecords.push(source);
    for (const iri of sparqlDependencyIris(bytes)) records.push({
      dependencyIri: iri,
      sourcePath: source.path,
      sourceRecordDigest: source.sourceRecordDigest,
    });
  }
  return { records, sourceRecords };
}

function readGovernedDataset(repositoryRoot) {
  const root = realpathSync(repositoryRoot);
  const modelRoot = join(root, 'semantic-model');
  const manifestPath = join(modelRoot, 'manifest.yaml');
  const manifestBytes = readFileSync(manifestPath);
  const manifest = YAML.parse(manifestBytes.toString('utf8'));
  if (manifest?.version !== 1) fail('UNIVERSAL_MANIFEST_INVALID', 'semantic manifest version is unsupported');
  const entries = ['definitionGraphs', 'authoredGraphs', 'reviewGraphs', 'derivedGraphs', 'shapeGraphs']
    .flatMap((manifestGroup) => (manifest[manifestGroup] ?? [])
      .map((entry) => ({ ...entry, manifestGroup })))
    .sort((left, right) => compare(`${left.file}\0${left.graph}`, `${right.file}\0${right.graph}`));
  const identities = entries.map(({ file, graph }) => `${file}\0${graph}`);
  if (new Set(identities).size !== identities.length) {
    fail('UNIVERSAL_MANIFEST_ENTRY_DUPLICATE', 'semantic manifest contains a duplicate source identity');
  }
  const records = [];
  const sourceRecords = [];
  for (const entry of entries) {
    const path = sourcePath(root, modelRoot, entry);
    const before = readFileSync(path);
    let quads;
    try {
      quads = new N3.Parser({
        blankNodePrefix: `_:s${sha256(entry.file).slice('sha256:'.length)}_`,
        format: entry.file.endsWith('.trig') ? 'application/trig' : 'text/turtle',
      })
        .parse(before.toString('utf8'));
    } catch (error) {
      fail('UNIVERSAL_RDF_PARSE_FAILED', error.message, { path: entry.file });
    }
    const after = readFileSync(path);
    if (sha256(before) !== sha256(after)) fail('UNIVERSAL_SOURCE_MUTATED_DURING_READ', entry.file);
    const sourceCore = {
      contentDigest: sha256(before),
      declaredGraphIri: entry.graph,
      manifestGroup: entry.manifestGroup,
      path: `semantic-model/${entry.file}`,
    };
    const source = { ...sourceCore, sourceRecordDigest: digest(sourceCore) };
    sourceRecords.push(source);
    for (const quad of quads) {
      const graphIri = quad.graph.termType === 'DefaultGraph' ? entry.graph : quad.graph.value;
      const core = {
        graphIri,
        manifestGroup: entry.manifestGroup,
        object: canonicalTerm(quad.object, source.path),
        predicateIri: quad.predicate.value,
        sourceRecordDigest: source.sourceRecordDigest,
        subject: canonicalTerm(quad.subject, source.path),
      };
      records.push({ ...core, occurrenceDigest: digest(core), sourcePath: source.path });
    }
  }
  const ruleDependencies = readRuleDependencySources(root, modelRoot, manifest.rules);
  sourceRecords.push(...ruleDependencies.sourceRecords);
  const fixtureAbsolutePath = resolve(root, FIXTURE_PATH);
  const fixtureStat = lstatSync(fixtureAbsolutePath);
  if (!fixtureStat.isFile() || fixtureStat.isSymbolicLink()) {
    fail('UNIVERSAL_FIXTURE_INPUT_NOT_REGULAR', FIXTURE_PATH);
  }
  const fixtureBytes = readFileSync(fixtureAbsolutePath);
  let fixtureQuads;
  try {
    fixtureQuads = new N3.Parser({
      blankNodePrefix: `_:s${sha256(FIXTURE_PATH).slice('sha256:'.length)}_`,
      format: 'application/trig',
    }).parse(fixtureBytes.toString('utf8'));
  } catch (error) {
    fail('UNIVERSAL_RDF_PARSE_FAILED', error.message, { path: FIXTURE_PATH });
  }
  const fixtureCore = {
    contentDigest: sha256(fixtureBytes),
    declaredGraphIri: 'urn:usf:graph:foundation-conformance-fixture',
    manifestGroup: 'conformanceFixture',
    path: FIXTURE_PATH,
  };
  const fixtureSource = { ...fixtureCore, sourceRecordDigest: digest(fixtureCore) };
  sourceRecords.push(fixtureSource);
  for (const quad of fixtureQuads) {
    const core = {
      graphIri: quad.graph.termType === 'DefaultGraph' ? fixtureCore.declaredGraphIri : quad.graph.value,
      manifestGroup: fixtureCore.manifestGroup,
      object: canonicalTerm(quad.object, fixtureSource.path),
      predicateIri: quad.predicate.value,
      sourceRecordDigest: fixtureSource.sourceRecordDigest,
      subject: canonicalTerm(quad.subject, fixtureSource.path),
    };
    records.push({ ...core, occurrenceDigest: digest(core), sourcePath: fixtureSource.path });
  }
  records.sort((left, right) => compare(left.occurrenceDigest, right.occurrenceDigest));
  // RDF datasets have set semantics. Repeated serialised statements are
  // normalised here, while their exact duplicate set remains digest-bound for
  // diagnostics; they must never inflate usage or coverage counts.
  const duplicateOccurrences = records.filter((record, index) => (
    index > 0 && record.occurrenceDigest === records[index - 1].occurrenceDigest
  ));
  const canonicalRecords = records.filter((record, index) => (
    index === 0 || record.occurrenceDigest !== records[index - 1].occurrenceDigest
  ));
  sourceRecords.sort((left, right) => compare(canonicalJson(left), canonicalJson(right)));
  return {
    duplicateOccurrences,
    manifest,
    records: canonicalRecords,
    ruleDependencyRecords: ruleDependencies.records,
    sourceRecords,
  };
}

function objectValueIndex(records) {
  const index = new Map();
  for (const record of records) {
    if (record.subject.termType !== 'NamedNode' || record.object.termType !== 'NamedNode') continue;
    const key = `${record.subject.value}\0${record.predicateIri}`;
    if (!index.has(key)) index.set(key, []);
    index.get(key).push(record.object.value);
  }
  return new Map([...index].map(([key, values]) => [key, uniqueSorted(values)]));
}

function literalValueIndex(records) {
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
  return new Map([...index].map(([key, values]) => [key, values
    .sort((left, right) => compare(canonicalJson(left), canonicalJson(right)))
    .filter((value, index_) => index_ === 0 || canonicalJson(value) !== canonicalJson(values[index_ - 1]))]));
}

const objectValues = (index, subjectIri, predicateIri) => (
  index.get(`${subjectIri}\0${predicateIri}`) ?? []
);
const literalValues = (index, subjectIri, predicateIri) => (
  index.get(`${subjectIri}\0${predicateIri}`) ?? []
);

function explicitTypes(records) {
  const bySubject = new Map();
  for (const record of records) {
    if (record.predicateIri !== TYPE || record.subject.termType !== 'NamedNode'
      || record.object.termType !== 'NamedNode') continue;
    if (!bySubject.has(record.subject.value)) bySubject.set(record.subject.value, []);
    bySubject.get(record.subject.value).push(record.object.value);
  }
  return new Map([...bySubject].map(([iri, values]) => [iri, uniqueSorted(values)]));
}

function occurrenceIndexes(records) {
  const indexes = {
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
    const plane = record.manifestGroup === 'conformanceFixture'
      ? 'fixture' : record.manifestGroup === 'derivedGraphs' ? 'derived' : 'model';
    add(indexes.property[plane], record.predicateIri, record);
    if (record.subject.termType === 'NamedNode') add(indexes.individualSubject[plane], record.subject.value, record);
    if (record.object.termType === 'NamedNode') add(indexes.individualObject[plane], record.object.value, record);
    if (record.predicateIri === TYPE && record.object.termType === 'NamedNode') {
      add(indexes.class[plane], record.object.value, record);
    }
  }
  return indexes;
}

function individualOccurrenceSummary(indexes, iri) {
  const plane = (name) => uniqueSorted([
    ...(indexes.individualSubject[name].get(iri) ?? []),
    ...(indexes.individualObject[name].get(iri) ?? []),
  ].map(({ occurrenceDigest }) => occurrenceDigest));
  const model = plane('model');
  const derived = plane('derived');
  const fixture = plane('fixture');
  const sourcePaths = uniqueSorted(['model', 'derived', 'fixture'].flatMap((name) => [
    ...(indexes.individualSubject[name].get(iri) ?? []),
    ...(indexes.individualObject[name].get(iri) ?? []),
  ].map(({ sourcePath }) => sourcePath)));
  return {
    activeOccurrenceCount: model.length,
    activeOccurrenceSetDigest: digest(model),
    derivedOccurrenceCount: derived.length,
    derivedOccurrenceSetDigest: digest(derived),
    fixtureOccurrenceCount: fixture.length,
    fixtureOccurrenceSetDigest: digest(fixture),
    sourcePaths,
  };
}

function occurrenceSummary(indexes, iri, kind, typeIndex) {
  const model = indexes[kind].model.get(iri) ?? [];
  const derived = indexes[kind].derived.get(iri) ?? [];
  const fixture = indexes[kind].fixture.get(iri) ?? [];
  const all = [...model, ...derived, ...fixture];
  const endpointSubjectClassIris = kind === 'property' ? uniqueSorted(all.flatMap(({ subject }) => (
    subject.termType === 'NamedNode' ? typeIndex.get(subject.value) ?? [] : []
  ))) : [];
  const endpointObjectClassIris = kind === 'property' ? uniqueSorted(all.flatMap(({ object }) => (
    object.termType === 'NamedNode' ? typeIndex.get(object.value) ?? [] : []
  ))) : [];
  return {
    activeGraphIris: uniqueSorted(model.map(({ graphIri }) => graphIri)),
    activeOccurrenceCount: model.length,
    activeOccurrenceSetDigest: digest(model.map(({ occurrenceDigest }) => occurrenceDigest).sort(compare)),
    derivedGraphIris: uniqueSorted(derived.map(({ graphIri }) => graphIri)),
    derivedOccurrenceCount: derived.length,
    derivedOccurrenceSetDigest: digest(derived.map(({ occurrenceDigest }) => occurrenceDigest).sort(compare)),
    endpointObjectClassIris,
    endpointSubjectClassIris,
    fixtureGraphIris: uniqueSorted(fixture.map(({ graphIri }) => graphIri)),
    fixtureOccurrenceCount: fixture.length,
    fixtureOccurrenceSetDigest: digest(fixture.map(({ occurrenceDigest }) => occurrenceDigest).sort(compare)),
    sourcePaths: uniqueSorted(all.map(({ sourcePath }) => sourcePath)),
  };
}

function mechanismDependencies(records, termRecords) {
  const termKeys = new Set();
  const byIriKinds = new Map();
  for (const term of termRecords) {
    if (!byIriKinds.has(term.iri)) byIriKinds.set(term.iri, []);
    byIriKinds.get(term.iri).push(term.termKind);
  }
  for (const record of records.filter(({ graphIri }) => graphIri === PERMUTATION_GRAPH)) {
    if (record.predicateIri.startsWith(O)) termKeys.add(`property\0${record.predicateIri}`);
    if (record.predicateIri === TYPE && record.object.termType === 'NamedNode'
      && record.object.value.startsWith(O)) termKeys.add(`class\0${record.object.value}`);
    for (const term of [record.subject, record.object]) {
      if (term.termType !== 'NamedNode') continue;
      for (const kind of byIriKinds.get(term.value) ?? []) termKeys.add(`${kind}\0${term.value}`);
    }
  }
  return uniqueSorted([...termKeys].filter((key) => termRecords.some(({ termKey }) => termKey === key)));
}

function transitiveParents(records) {
  const direct = new Map();
  for (const record of records) {
    if (record.predicateIri !== SUBCLASS || record.subject.termType !== 'NamedNode'
      || record.object.termType !== 'NamedNode') continue;
    if (!direct.has(record.subject.value)) direct.set(record.subject.value, new Set());
    direct.get(record.subject.value).add(record.object.value);
  }
  const memo = new Map();
  const visit = (iri, path = new Set()) => {
    if (memo.has(iri)) return memo.get(iri);
    if (path.has(iri)) fail('UNIVERSAL_CLASS_HIERARCHY_CYCLE', 'class hierarchy contains a cycle', { classIri: iri });
    const nextPath = new Set(path).add(iri);
    const result = new Set(direct.get(iri) ?? []);
    for (const parent of [...result]) for (const ancestor of visit(parent, nextPath)) result.add(ancestor);
    memo.set(iri, result);
    return result;
  };
  return { ancestors: (iri) => uniqueSorted(visit(iri)), direct };
}

function relationshipSignatures(records, typeIndex) {
  const groups = new Map();
  for (const record of records) {
    const signatureCore = {
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
    const key = canonicalJson(signatureCore);
    if (!groups.has(key)) groups.set(key, { core: signatureCore, records: [] });
    groups.get(key).records.push(record);
  }
  return [...groups.values()].map(({ core, records: occurrences }) => {
    const occurrenceDigests = uniqueSorted(occurrences.map(({ occurrenceDigest }) => occurrenceDigest));
    const signatureIdentityDigest = digest(core);
    const signature = {
      ...core,
      activeGraphIris: uniqueSorted(occurrences.map(({ graphIri }) => graphIri)),
      activeOccurrenceCount: occurrenceDigests.length,
      activeOccurrenceSetDigest: digest(occurrenceDigests),
      relationshipSignatureIri: `urn:usf:relationshipsignature:${signatureIdentityDigest.slice('sha256:'.length)}`,
      signatureIdentityDigest,
      sourcePaths: uniqueSorted(occurrences.map(({ sourcePath }) => sourcePath)),
    };
    return { ...signature, relationshipSignatureDigest: digest(signature) };
  }).sort((left, right) => compare(left.relationshipSignatureIri, right.relationshipSignatureIri));
}

function validatorDependencies(shapeRecords, ruleDependencyRecords, terms) {
  const byIriKinds = new Map();
  for (const term of terms) {
    if (!byIriKinds.has(term.iri)) byIriKinds.set(term.iri, []);
    byIriKinds.get(term.iri).push(term.termKind);
  }
  const records = [];
  const add = (iri, role, sourcePath, sourceRecordDigest) => {
    for (const termKind of byIriKinds.get(iri) ?? []) {
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
  records.sort((left, right) => compare(canonicalJson(left), canonicalJson(right)));
  const unique = records.filter((record, index) => index === 0
    || record.dependencyDigest !== records[index - 1].dependencyDigest);
  return {
    records: unique,
    setDigest: digest(unique),
    termKeys: uniqueSorted(unique.map(({ termKey }) => termKey)),
  };
}

export function buildUniversalSemanticInventory({ authorityBinding, authorityInputVerification, repositoryRoot }) {
  const binding = exactAuthorityBinding(authorityBinding);
  if (!authorityInputVerification
    || authorityInputVerification.recordKind !== 'USF_VERIFIED_BOUNDED_UNIVERSAL_AUTHORITY_INPUT'
    || authorityInputVerification.authorityDigest !== binding.authorityDigest
    || authorityInputVerification.authorityPacket?.contentDigest !== binding.authorityPacketDigest
    || authorityInputVerification.authorityProjection?.contentDigest !== binding.authorityProjectionDigest
    || authorityInputVerification.verificationDigest !== digest((({ verificationDigest, ...core }) => core)(authorityInputVerification))) {
    fail('UNIVERSAL_AUTHORITY_INPUT_VERIFICATION_REQUIRED', 'digest-valid packet and projection verification is required');
  }
  const {
    duplicateOccurrences,
    records,
    ruleDependencyRecords,
    sourceRecords,
  } = readGovernedDataset(repositoryRoot);
  const inventoryDuplicateOccurrences = duplicateOccurrences.filter(({ manifestGroup }) => (
    manifestGroup !== 'reviewGraphs'
  ));
  // Generated projections are observations, never semantic inventory inputs.
  // Excluding them from the inventory identity prevents a review projection
  // from recursively changing the term set or digest that it describes.
  const semanticRecords = records.filter(({ manifestGroup }) => [
    'authoredGraphs', 'definitionGraphs',
  ].includes(manifestGroup));
  const shapeRecords = records.filter(({ manifestGroup }) => manifestGroup === 'shapeGraphs');
  const occurrenceRecords = records.filter(({ manifestGroup }) => [
    'authoredGraphs', 'conformanceFixture', 'definitionGraphs', 'derivedGraphs',
  ].includes(manifestGroup));
  const types = explicitTypes(semanticRecords);
  const occurrences = occurrenceIndexes(occurrenceRecords);
  const values = objectValueIndex(semanticRecords);
  const declaredClassIris = uniqueSorted(semanticRecords
    .filter(({ predicateIri, object }) => predicateIri === TYPE
      && object.termType === 'NamedNode' && CLASS_KINDS.has(object.value))
    .map(({ subject }) => subject.termType === 'NamedNode' ? subject.value : null).filter(Boolean));
  const declaredPropertyIris = uniqueSorted(semanticRecords
    .filter(({ predicateIri, object }) => predicateIri === TYPE
      && object.termType === 'NamedNode' && PROPERTY_KINDS.has(object.value))
    .map(({ subject }) => subject.termType === 'NamedNode' ? subject.value : null).filter(Boolean));
  const externalClassBindings = semanticRecords.filter(({ predicateIri, subject, object }) => (
    predicateIri === STANDARD_DEFINES_CLASS
      && subject.termType === 'NamedNode'
      && object.termType === 'NamedNode'
  )).map(({ subject, object }) => ({ standardIri: subject.value, termIri: object.value }));
  const externalPropertyBindings = semanticRecords.filter(({ predicateIri, subject, object }) => (
    predicateIri === STANDARD_DEFINES_PROPERTY
      && subject.termType === 'NamedNode'
      && object.termType === 'NamedNode'
  )).map(({ subject, object }) => ({ standardIri: subject.value, termIri: object.value }));
  const externalClassIris = uniqueSorted(externalClassBindings.map(({ termIri }) => termIri));
  const externalPropertyIris = uniqueSorted(externalPropertyBindings.map(({ termIri }) => termIri));
  const referencedClassIris = uniqueSorted(semanticRecords.flatMap((record) => {
    if (record.object.termType !== 'NamedNode') return [];
    if (record.predicateIri === TYPE) return [record.object.value];
    if ([DOMAIN, RANGE, SUBCLASS].includes(record.predicateIri)) {
      return [record.object.value];
    }
    return [];
  }));
  const usedPredicateIris = uniqueSorted(semanticRecords.map(({ predicateIri }) => predicateIri));
  const referencedPropertyIris = uniqueSorted(semanticRecords.flatMap(({ predicateIri, subject, object }) => (
    [SUBPROPERTY, INVERSE].includes(predicateIri)
      ? [subject, object].filter(({ termType }) => termType === 'NamedNode').map(({ value }) => value)
      : []
  )));
  const classIris = uniqueSorted([...declaredClassIris, ...referencedClassIris, ...externalClassIris]);
  const propertyIris = uniqueSorted([
    ...declaredPropertyIris, ...externalPropertyIris, ...referencedPropertyIris, ...usedPredicateIris,
  ]);
  const classes = classIris.map((iri) => {
    const declarationKindIris = objectValues(values, iri, TYPE).filter((value) => CLASS_KINDS.has(value));
    const summary = occurrenceSummary(occurrences, iri, 'class', types);
    const core = {
      ...summary,
      declarationKindIris,
      declarationState: declarationKindIris.length > 0
        ? 'DECLARED'
        : externalClassIris.includes(iri) ? 'EXTERNAL_STANDARD_BINDING' : 'USED_BUT_UNDECLARED',
      directParentIris: objectValues(values, iri, SUBCLASS),
      iri,
      standardBindingIris: uniqueSorted(externalClassBindings
        .filter(({ termIri }) => termIri === iri).map(({ standardIri }) => standardIri)),
      termKey: `class\0${iri}`,
      termKind: 'class',
      termUsageStateIris: objectValues(values, iri, `${O}termUsageState`),
    };
    return { ...core, recordDigest: digest(core) };
  });
  const properties = propertyIris.map((iri) => {
    const declarationKindIris = objectValues(values, iri, TYPE).filter((value) => PROPERTY_KINDS.has(value));
    const summary = occurrenceSummary(occurrences, iri, 'property', types);
    const core = {
      ...summary,
      declarationKindIris,
      declarationState: declarationKindIris.length > 0
        ? 'DECLARED'
        : externalPropertyIris.includes(iri) ? 'EXTERNAL_STANDARD_BINDING' : 'USED_BUT_UNDECLARED',
      declaredDomainIris: objectValues(values, iri, DOMAIN),
      declaredRangeIris: objectValues(values, iri, RANGE),
      iri,
      standardBindingIris: uniqueSorted(externalPropertyBindings
        .filter(({ termIri }) => termIri === iri).map(({ standardIri }) => standardIri)),
      termKey: `property\0${iri}`,
      termKind: 'property',
      termUsageStateIris: objectValues(values, iri, `${O}termUsageState`),
    };
    return { ...core, recordDigest: digest(core) };
  });
  const classHierarchy = transitiveParents(semanticRecords);
  const namedIris = uniqueSorted(semanticRecords.flatMap(({ subject, object }) => [subject, object]
    .filter(({ termType }) => termType === 'NamedNode').map(({ value }) => value)));
  const classSet = new Set(classIris);
  const propertySet = new Set(propertyIris);
  const individualIris = namedIris.filter((iri) => !classSet.has(iri) && !propertySet.has(iri));
  const individuals = individualIris.map((iri) => {
    const explicitTypeIris = uniqueSorted(types.get(iri) ?? []);
    const controlledValueTypeIris = explicitTypeIris.filter((typeIri) => (
      typeIri === CONTROLLED_VALUE || classHierarchy.ancestors(typeIri).includes(CONTROLLED_VALUE)
    ));
    const core = {
      ...individualOccurrenceSummary(occurrences, iri),
      controlledValue: controlledValueTypeIris.length > 0,
      controlledValueTypeIris,
      explicitTypeIris,
      iri,
      termKey: `individual\0${iri}`,
      termKind: 'individual',
      termUsageStateIris: objectValues(values, iri, `${O}termUsageState`),
    };
    return { ...core, recordDigest: digest(core) };
  });
  const terms = [...classes, ...properties, ...individuals]
    .sort((left, right) => compare(left.termKey, right.termKey));
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
  const signatureRecords = relationshipSignatures(semanticRecords, types);
  const dependencyProjection = validatorDependencies(shapeRecords, ruleDependencyRecords, terms);
  const governedSourceRecords = sourceRecords.filter(({ manifestGroup }) => [
    'authoredGraphs', 'definitionGraphs',
  ].includes(manifestGroup));
  const validationSourceRecords = sourceRecords.filter(({ manifestGroup }) => VALIDATOR_SOURCE_GROUPS
    .has(manifestGroup));
  const sourceSetDigest = digest(governedSourceRecords);
  const core = {
    authorityBinding: binding,
    authorityInputVerification,
    classCount: classes.length,
    classes,
    controlledValueCount: individuals.filter(({ controlledValue }) => controlledValue).length,
    controlledValueSetDigest: digest(individuals.filter(({ controlledValue }) => controlledValue)
      .map(({ recordDigest }) => recordDigest)),
    duplicateOccurrenceCount: inventoryDuplicateOccurrences.length,
    duplicateOccurrenceSetDigest: digest(uniqueSorted(inventoryDuplicateOccurrences
      .map(({ occurrenceDigest }) => occurrenceDigest))),
    externalStandardBindings: {
      classes: externalClassBindings.sort((left, right) => compare(canonicalJson(left), canonicalJson(right))),
      properties: externalPropertyBindings.sort((left, right) => compare(canonicalJson(left), canonicalJson(right))),
    },
    fixtureSourceDigest: sourceRecords.find(({ path }) => path === FIXTURE_PATH)?.contentDigest ?? null,
    inventoryAlgorithmSourceDigest: ANALYZER_SOURCE_DIGEST,
    individualCount: individuals.length,
    individuals,
    mechanismDependencyTermKeys: mechanismDependencies(semanticRecords, terms),
    propertyCount: properties.length,
    properties,
    recordKind: 'USF_UNIVERSAL_SEMANTIC_OCCURRENCE_INVENTORY',
    relationshipCategories,
    relationshipCategoryCount: relationshipCategories.length,
    relationshipCategorySetDigest: digest(relationshipCategories.map(({ relationshipCategoryDigest }) => relationshipCategoryDigest)),
    relationshipSignatureCount: signatureRecords.length,
    relationshipSignatures: signatureRecords,
    relationshipSignatureSetDigest: digest(signatureRecords.map(({ relationshipSignatureDigest }) => relationshipSignatureDigest)),
    schemaVersion: 4,
    excludedSourceGroups: ['conformanceFixture', 'derivedGraphs', 'reviewGraphs', 'rules', 'shapeGraphs'],
    semanticInputSourceSetDigest: sourceSetDigest,
    sourceRecords: governedSourceRecords,
    sourceSetDigest,
    termCount: terms.length,
    termKeySetDigest: digest(terms.map(({ termKey }) => termKey)),
    terms,
    undeclaredClassIris: classIris.filter((iri) => !declaredClassIris.includes(iri)
      && !externalClassIris.includes(iri)),
    undeclaredPredicateIris: propertyIris.filter((iri) => !declaredPropertyIris.includes(iri)
      && !externalPropertyIris.includes(iri)),
    validationDependencyCount: dependencyProjection.records.length,
    validationDependencyRecords: dependencyProjection.records,
    validationDependencySetDigest: dependencyProjection.setDigest,
    validationDependencyTermKeys: dependencyProjection.termKeys,
    validationSourceRecords,
    validationSourceSetDigest: digest(validationSourceRecords),
  };
  return { ...core, inventoryDigest: digest(core) };
}

export function loadUniversalReviewProjection({ inventory, registry, repositoryRoot }) {
  const dataset = readGovernedDataset(repositoryRoot);
  const semanticSourceRecords = dataset.sourceRecords.filter(({ manifestGroup }) => [
    'authoredGraphs', 'definitionGraphs',
  ].includes(manifestGroup));
  const semanticInputSourceSetDigest = digest(semanticSourceRecords);
  if (semanticInputSourceSetDigest !== inventory.sourceSetDigest) {
    fail('UNIVERSAL_REVIEW_PROJECTION_SOURCE_DRIFT',
      'semantic input bytes changed between inventory and review projection');
  }
  const allTypes = explicitTypes(dataset.records);
  const reviewClassIris = new Set([
    TERM_REVIEW_CLASS, REVIEW_COVERAGE_CLASS, FAMILY_REVIEW_CLASS, FAMILY_CANDIDATE_CLASS,
  ]);
  const reviewResourceIris = uniqueSorted([...allTypes.entries()]
    .filter(([, classIris]) => classIris.some((classIri) => reviewClassIris.has(classIri)))
    .map(([iri]) => iri));
  const invalidReviewResourcePlanes = reviewResourceIris.flatMap((iri) => {
    const planes = uniqueSorted(dataset.records.filter(({ subject }) => (
      subject.termType === 'NamedNode' && subject.value === iri
    )).map(({ manifestGroup }) => manifestGroup));
    return canonicalJson(planes) === canonicalJson(['reviewGraphs']) ? [] : [{ iri, planes }];
  });
  if (invalidReviewResourcePlanes.length) {
    fail('UNIVERSAL_REVIEW_RESOURCE_PLANE_INVALID',
      'review resources must be isolated in registered review graphs', { invalidReviewResourcePlanes });
  }
  const records = dataset.records.filter(({ manifestGroup }) => manifestGroup === 'reviewGraphs');
  const reviewSourceRecords = dataset.sourceRecords.filter(({ manifestGroup }) => (
    manifestGroup === 'reviewGraphs'
  ));
  const objects = objectValueIndex(records);
  const literals = literalValueIndex(records);
  const types = explicitTypes(records);
  const typed = (classIri) => uniqueSorted([...types.entries()]
    .filter(([, classIris]) => classIris.includes(classIri)).map(([iri]) => iri));
  const sourcePlanes = (iri) => uniqueSorted(records.filter(({ subject }) => (
    subject.termType === 'NamedNode' && subject.value === iri
  )).map(({ manifestGroup }) => manifestGroup));
  const objectArray = (iri, localName) => objectValues(objects, iri, `${O}${localName}`);
  const literalArray = (iri, localName) => literalValues(literals, iri, `${O}${localName}`)
    .map(({ value }) => value);
  const termReviews = typed(TERM_REVIEW_CLASS).map((reviewIri) => {
    const core = {
      authorityDigests: literalArray(reviewIri, 'termPermutationAuthorityDigest'),
      axisBindingIris: objectArray(reviewIri, 'termPermutationAxisBinding'),
      familyCandidateStateIris: objectArray(reviewIri, 'termPermutationFamilyCandidateState'),
      inventoryDigests: literalArray(reviewIri, 'termPermutationInventoryDigest'),
      participationIris: objectArray(reviewIri, 'termPermutationParticipation'),
      reasonCodes: literalArray(reviewIri, 'termPermutationReasonCode'),
      reviewDigests: literalArray(reviewIri, 'termPermutationReviewDigest'),
      reviewIri,
      reviewedTermIris: objectArray(reviewIri, 'reviewedSemanticTerm'),
      sourcePlanes: sourcePlanes(reviewIri),
      statedSourcePlanes: literalArray(reviewIri, 'termPermutationSourcePlane'),
    };
    return { ...core, projectionRecordDigest: digest(core) };
  }).sort((left, right) => compare(left.reviewIri, right.reviewIri));
  const familySignatureReviews = typed(FAMILY_REVIEW_CLASS).map((reviewIri) => {
    const core = {
      applicabilityRuleIris: objectArray(reviewIri, 'reviewedFamilyApplicabilityRule'),
      authorityDigests: literalArray(reviewIri, 'familySignatureReviewAuthorityDigest'),
      dimensionBindingIris: objectArray(reviewIri, 'reviewedFamilyDimensionBinding'),
      dispositionIris: objectArray(reviewIri, 'familySignatureReviewDisposition'),
      familyIris: objectArray(reviewIri, 'reviewedPermutationFamily'),
      registryDigests: literalArray(reviewIri, 'familySignatureReviewRegistryDigest'),
      reviewDigests: literalArray(reviewIri, 'familySignatureReviewDigest'),
      reviewIri,
      signatureDigests: literalArray(reviewIri, 'reviewedFamilySignatureDigest'),
      sourcePlanes: sourcePlanes(reviewIri),
      subjectRegistrationIris: objectArray(reviewIri, 'reviewedFamilySubjectRegistration'),
    };
    return { ...core, projectionRecordDigest: digest(core) };
  }).sort((left, right) => compare(left.reviewIri, right.reviewIri));
  const coverages = typed(REVIEW_COVERAGE_CLASS).map((coverageIri) => {
    const core = {
      authorityDigests: literalArray(coverageIri, 'permutationReviewAuthorityDigest'),
      coverageDigests: literalArray(coverageIri, 'permutationReviewDigest'),
      coverageIri,
      expectedFamilyIris: objectArray(coverageIri, 'permutationReviewExpectedFamily'),
      expectedTermIris: objectArray(coverageIri, 'permutationReviewExpectedTerm'),
      familyRegistryDigests: literalArray(coverageIri, 'permutationReviewFamilyRegistryDigest'),
      familySignatureAlgorithms: literalArray(coverageIri, 'permutationReviewFamilySignatureAlgorithm'),
      familySignatureReviewIris: objectArray(coverageIri, 'permutationReviewFamilySignatureReview'),
      inventoryDigests: literalArray(coverageIri, 'permutationReviewInventoryDigest'),
      sourcePlanes: sourcePlanes(coverageIri),
      termReviewIris: objectArray(coverageIri, 'permutationReviewTermReview'),
      termSetAlgorithms: literalArray(coverageIri, 'permutationReviewTermSetAlgorithm'),
    };
    return { ...core, projectionRecordDigest: digest(core) };
  }).sort((left, right) => compare(left.coverageIri, right.coverageIri));
  const familyCandidates = typed(FAMILY_CANDIDATE_CLASS).map((candidateIri) => ({
    candidateIri,
    projectionRecordDigest: digest({
      candidateIri,
      sourcePlanes: sourcePlanes(candidateIri),
    }),
    sourcePlanes: sourcePlanes(candidateIri),
  }));
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
    projectionAlgorithmSourceDigest: ANALYZER_SOURCE_DIGEST,
    reviewSourceCount: reviewSourceRecords.length,
    reviewSourceRecords,
    reviewSourceSetDigest: digest(reviewSourceRecords),
    schemaVersion: 2,
    semanticInputSourceSetDigest,
    termReviewCount: termReviews.length,
    termReviews,
  };
  return { ...core, reviewProjectionDigest: digest(core) };
}

function selectorIrisFromClause(clause, result = new Set()) {
  if (clause.selectorIri) result.add(clause.selectorIri);
  for (const operand of clause.operands ?? []) selectorIrisFromClause(operand.clause, result);
  return result;
}

export function loadUniversalFamilyRegistry({ repositoryRoot }) {
  const production = loadPermutationFamilyRegistry({ repositoryRoot, verifyStoredDigests: true });
  const exactFamilyRecords = new Map(production.registryRecord.families
    .map((record) => [record.familyIri, record]));
  const dimensionsByIri = new Map();
  const families = production.families.map((family) => {
    const applicabilitySelectorIris = uniqueSorted([...selectorIrisFromClause(family.rule.rootClause)]);
    const applicabilitySelectors = applicabilitySelectorIris.map((iri) => production.selectors.get(iri));
    const orderedBindings = family.bindings.map((binding) => {
      const selector = binding.valueSelectorIri ? production.selectors.get(binding.valueSelectorIri) : null;
      const record = {
        axisClassClosures: binding.axisClassClosures.map((closure) => ({
          closureDigest: closure.digest,
          closureIri: closure.iri,
          memberClassIris: closure.memberClassIris,
          rootClassIri: closure.rootClassIri,
        })),
        bindingIri: binding.bindingIri,
        controlledValueSetDigest: binding.controlledValueSetDigest,
        controlledValues: binding.controlledValues,
        declaredValueSetDigest: binding.declaredValueSetDigest,
        declaredValues: binding.declaredValues,
        derivationPredicateIris: binding.derivationPredicateIris,
        dimensionIri: binding.dimensionIri,
        key: binding.key,
        position: binding.position,
        selector: selector ? {
          digest: selector.digest,
          iri: selector.iri,
          steps: selector.steps.map(({ directionIri, index, predicateIri }) => ({ directionIri, index, predicateIri })),
          subjectClassClosure: {
            closureDigest: selector.subjectClassClosure.digest,
            closureIri: selector.subjectClassClosure.iri,
            memberClassIris: selector.subjectClassClosure.memberClassIris,
            rootClassIri: selector.subjectClassClosure.rootClassIri,
          },
          terminalClassClosure: {
            closureDigest: selector.terminalClassClosure.digest,
            closureIri: selector.terminalClassClosure.iri,
            memberClassIris: selector.terminalClassClosure.memberClassIris,
            rootClassIri: selector.terminalClassClosure.rootClassIri,
          },
        } : null,
        sourceIri: binding.sourceIri,
        sourceKind: binding.sourceKind,
        sourceScopeIri: binding.sourceScopeIri,
        valueDerivationRootIri: binding.valueDerivationRootIri,
        valueSourceDigest: binding.valueSourceDigest,
      };
      const dimension = {
        axisClassClosures: record.axisClassClosures,
        controlledValueSetDigest: record.controlledValueSetDigest,
        controlledValues: record.controlledValues,
        declaredValueSetDigest: record.declaredValueSetDigest,
        declaredValues: record.declaredValues,
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
        fail('UNIVERSAL_DIMENSION_DEFINITION_CONFLICT', dimension.iri);
      }
      dimensionsByIri.set(dimension.iri, dimension);
      return record;
    });
    const exactFamilyRecord = exactFamilyRecords.get(family.iri);
    const familyRecordDigest = digest(exactFamilyRecord);
    return {
      applicabilitySelectors: applicabilitySelectors.map((selector) => ({
        digest: selector.digest,
        iri: selector.iri,
        steps: selector.steps.map(({ directionIri, index, predicateIri }) => ({ directionIri, index, predicateIri })),
        subjectClassClosure: {
          closureDigest: selector.subjectClassClosure.digest,
          closureIri: selector.subjectClassClosure.iri,
          memberClassIris: selector.subjectClassClosure.memberClassIris,
          rootClassIri: selector.subjectClassClosure.rootClassIri,
        },
        terminalClassClosure: {
          closureDigest: selector.terminalClassClosure.digest,
          closureIri: selector.terminalClassClosure.iri,
          memberClassIris: selector.terminalClassClosure.memberClassIris,
          rootClassIri: selector.terminalClassClosure.rootClassIri,
        },
      })),
      canonicalName: family.canonicalName,
      familyIri: family.iri,
      familyRecordDigest,
      orderedBindings,
      planeIri: family.planeIri,
      registrationIri: family.registrationIri,
      ruleDigest: family.rule.ruleDigest,
      ruleIri: family.ruleIri,
      subjectClassClosure: {
        closureDigest: family.subjectClassClosure.digest,
        closureIri: family.subjectClassClosure.iri,
        memberClassIris: family.subjectClassClosure.memberClassIris,
        rootClassIri: family.subjectClassClosure.rootClassIri,
      },
      subjectClassIri: family.subjectClassIri,
    };
  }).sort((left, right) => compare(left.familyIri, right.familyIri));
  const dimensions = [...dimensionsByIri.values()].sort((left, right) => compare(left.iri, right.iri));
  const core = {
    dimensionCount: dimensions.length,
    dimensions,
    families,
    familyCount: families.length,
    productionRegistryDigest: production.registryDigest,
    projectionAlgorithmSourceDigest: ANALYZER_SOURCE_DIGEST,
    recordKind: 'USF_UNIVERSAL_EXACT_FAMILY_REGISTRY_PROJECTION',
    schemaVersion: 5,
  };
  return { ...core, registryDigest: digest(core) };
}

function witness(core) {
  const compact = Object.fromEntries(Object.entries(core).filter(([, value]) => value !== null));
  return { ...compact, witnessDigest: digest(compact) };
}

export function buildExactCoverageWitnessIndex(inventory, registry) {
  const { registryDigest, ...registryCore } = registry;
  if (digest(registryCore) !== registryDigest) {
    fail('UNIVERSAL_COVERAGE_REGISTRY_DIGEST_MISMATCH',
      'family registry projection is not bound to its current bytes');
  }
  for (const family of registry.families) {
    for (const binding of family.orderedBindings) {
      const sortedDeclared = [...binding.declaredValues]
        .sort((left, right) => compare(left.key, right.key) || compare(left.iri, right.iri));
      const declaredDigest = sortedDeclared.length > 0 ? digest(sortedDeclared) : null;
      if (canonicalJson(sortedDeclared) !== canonicalJson(binding.declaredValues)
        || new Set(sortedDeclared.map(({ iri }) => iri)).size !== sortedDeclared.length
        || new Set(sortedDeclared.map(({ key }) => key)).size !== sortedDeclared.length
        || declaredDigest !== binding.declaredValueSetDigest) {
        fail('UNIVERSAL_COVERAGE_DECLARED_VALUE_BINDING_INVALID', binding.bindingIri);
      }
      const controlled = binding.sourceKind === 'controlledlist';
      if ((controlled && (binding.controlledValues.length === 0
        || canonicalJson(binding.controlledValues) !== canonicalJson(binding.declaredValues)
        || binding.controlledValueSetDigest !== binding.declaredValueSetDigest))
        || (!controlled && (binding.controlledValues.length !== 0
          || binding.controlledValueSetDigest !== null))) {
        fail('UNIVERSAL_COVERAGE_CONTROLLED_VALUE_BINDING_INVALID', binding.bindingIri);
      }
    }
  }
  const records = [];
  const add = (core) => records.push(witness({
    inventoryDigest: inventory.inventoryDigest,
    registryDigest: registry.registryDigest,
    schemaVersion: 3,
    ...core,
  }));
  const matchingIndividuals = (memberClassIris) => {
    const members = new Set(memberClassIris);
    return inventory.individuals.filter(({ explicitTypeIris }) => explicitTypeIris
      .some((typeIri) => members.has(typeIri)));
  };
  for (const family of registry.families) {
    add({
      bindingPosition: null,
      closureDigest: family.subjectClassClosure.closureDigest,
      closureIri: family.subjectClassClosure.closureIri,
      familyIri: family.familyIri,
      familyRecordDigest: family.familyRecordDigest,
      ownerIri: family.registrationIri,
      role: 'EXACT_FAMILY_SUBJECT_ROOT',
      termKey: `class\0${family.subjectClassIri}`,
    });
    for (const classIri of family.subjectClassClosure.memberClassIris) {
      add({
        bindingPosition: null,
        closureDigest: family.subjectClassClosure.closureDigest,
        closureIri: family.subjectClassClosure.closureIri,
        familyIri: family.familyIri,
        familyRecordDigest: family.familyRecordDigest,
        ownerIri: family.registrationIri,
        role: 'EXPLICIT_SUBJECT_CLOSURE_MEMBER',
        termKey: `class\0${classIri}`,
      });
    }
    for (const individual of matchingIndividuals(family.subjectClassClosure.memberClassIris)) add({
      bindingPosition: null,
      closureDigest: family.subjectClassClosure.closureDigest,
      closureIri: family.subjectClassClosure.closureIri,
      familyIri: family.familyIri,
      familyRecordDigest: family.familyRecordDigest,
      ownerIri: family.registrationIri,
      role: 'EXACT_FAMILY_SUBJECT_INSTANCE_CLASSIFICATION',
      termKey: individual.termKey,
    });
    for (const binding of family.orderedBindings) {
      for (const closure of binding.axisClassClosures) {
        for (const classIri of closure.memberClassIris) {
          add({
            bindingPosition: binding.position,
            closureDigest: closure.closureDigest,
            closureIri: closure.closureIri,
            bindingIri: binding.bindingIri,
            familyIri: family.familyIri,
            familyRecordDigest: family.familyRecordDigest,
            ownerIri: binding.dimensionIri,
            role: 'EXPLICIT_AXIS_CLOSURE_MEMBER',
            sourceIri: binding.sourceIri,
            sourceKind: binding.sourceKind,
            termKey: `class\0${classIri}`,
          });
        }
        if (binding.sourceKind === 'classinstances') {
          for (const individual of matchingIndividuals(closure.memberClassIris)) add({
            bindingIri: binding.bindingIri,
            bindingPosition: binding.position,
            closureDigest: closure.closureDigest,
            closureIri: closure.closureIri,
            dimensionIri: binding.dimensionIri,
            familyIri: family.familyIri,
            familyRecordDigest: family.familyRecordDigest,
            ownerIri: binding.dimensionIri,
            role: 'EXACT_CLASS_INSTANCE_VALUE_MEMBERSHIP',
            sourceIri: binding.sourceIri,
            sourceKind: binding.sourceKind,
            sourceScopeIri: binding.sourceScopeIri,
            termKey: individual.termKey,
          });
        }
      }
      if (binding.sourceKind === 'controlledlist') {
        for (const value of binding.controlledValues) add({
          bindingIri: binding.bindingIri,
          bindingPosition: binding.position,
          controlledValueKey: value.key,
          controlledValueSetDigest: binding.controlledValueSetDigest,
          dimensionIri: binding.dimensionIri,
          familyIri: family.familyIri,
          familyRecordDigest: family.familyRecordDigest,
          ownerIri: binding.dimensionIri,
          role: 'EXACT_CONTROLLED_LIST_VALUE_MEMBERSHIP',
          sourceIri: binding.sourceIri,
          sourceKind: binding.sourceKind,
          sourceScopeIri: binding.sourceScopeIri,
          termKey: `individual\0${value.iri}`,
        });
      } else if (!['classinstances', 'derivedselector'].includes(binding.sourceKind)) {
        fail('UNIVERSAL_COVERAGE_VALUE_SOURCE_KIND_UNSUPPORTED', binding.sourceKind);
      }
      for (const step of binding.selector?.steps ?? []) {
        add({
          bindingIri: binding.bindingIri,
          bindingPosition: binding.position,
          dimensionIri: binding.dimensionIri,
          directionIri: step.directionIri,
          familyIri: family.familyIri,
          familyRecordDigest: family.familyRecordDigest,
          ownerIri: binding.selector.iri,
          predicateIri: step.predicateIri,
          role: 'EXACT_DIMENSION_SELECTOR_STEP',
          selectorDigest: binding.selector.digest,
          sourceIri: binding.sourceIri,
          sourceKind: binding.sourceKind,
          stepIndex: step.index,
          termKey: `property\0${step.predicateIri}`,
        });
      }
      for (const predicateIri of binding.derivationPredicateIris) {
        add({
          bindingIri: binding.bindingIri,
          bindingPosition: binding.position,
          dimensionIri: binding.dimensionIri,
          familyIri: family.familyIri,
          familyRecordDigest: family.familyRecordDigest,
          ownerIri: binding.valueDerivationRootIri ?? binding.sourceIri,
          predicateIri,
          role: 'EXACT_VALUE_DERIVATION_PREDICATE',
          sourceIri: binding.sourceIri,
          sourceKind: binding.sourceKind,
          termKey: `property\0${predicateIri}`,
        });
      }
    }
    for (const selector of family.applicabilitySelectors) {
      for (const step of selector.steps) {
        add({
          bindingPosition: null,
          directionIri: step.directionIri,
          familyIri: family.familyIri,
          familyRecordDigest: family.familyRecordDigest,
          ownerIri: selector.iri,
          predicateIri: step.predicateIri,
          role: 'EXACT_APPLICABILITY_SELECTOR_STEP',
          selectorDigest: selector.digest,
          stepIndex: step.index,
          termKey: `property\0${step.predicateIri}`,
        });
      }
    }
  }
  for (const termKey of inventory.mechanismDependencyTermKeys) {
    add({
      bindingPosition: null,
      familyIri: null,
      familyRecordDigest: null,
      ownerIri: PERMUTATION_GRAPH,
      role: 'PERMUTATION_META_MODEL_DEPENDENCY',
      termKey,
    });
  }
  for (const termKey of inventory.validationDependencyTermKeys) add({
    bindingPosition: null,
    familyIri: null,
    familyRecordDigest: null,
    ownerIri: 'urn:usf:graph:validation-dependencies',
    role: 'VALIDATOR_DEPENDENCY',
    termKey,
  });
  records.sort((left, right) => compare(canonicalJson(left), canonicalJson(right)));
  const duplicate = records.find((record, index) => index > 0
    && record.witnessDigest === records[index - 1].witnessDigest);
  if (duplicate) fail('UNIVERSAL_COVERAGE_WITNESS_DUPLICATE', duplicate.witnessDigest);
  const knownTerms = new Set(inventory.terms.map(({ termKey }) => termKey));
  const unknown = records.filter(({ termKey }) => !knownTerms.has(termKey));
  if (unknown.length > 0) {
    fail('UNIVERSAL_COVERAGE_WITNESS_TERM_UNDECLARED', 'coverage witness references an absent term', {
      termKeys: uniqueSorted(unknown.map(({ termKey }) => termKey)),
    });
  }
  const core = {
    inventoryDigest: inventory.inventoryDigest,
    recordKind: 'USF_UNIVERSAL_EXACT_COVERAGE_WITNESS_INDEX',
    records,
    registryDigest: registry.registryDigest,
    schemaVersion: 3,
    witnessCount: records.length,
  };
  return { ...core, witnessIndexDigest: digest(core) };
}

function familyModelReviews(inventory, registry, reviewProjection) {
  const knownFamilies = new Set(registry.families.map(({ familyIri }) => familyIri));
  const reviews = reviewProjection?.familySignatureReviews ?? [];
  const orphanReviewIris = reviews.filter(({ familyIris }) => (
    familyIris.length !== 1 || !knownFamilies.has(familyIris[0])
  )).map(({ reviewIri }) => reviewIri);
  let signatureDriftCount = 0;
  const rows = registry.families.map((family) => {
    const related = reviews.filter(({ familyIris }) => familyIris.length === 1
      && familyIris[0] === family.familyIri);
    const expectedCore = (review) => ({
      applicabilityRuleIri: family.ruleIri,
      authorityDigest: inventory.authorityBinding.authorityDigest,
      dimensionBindingIris: family.orderedBindings.map(({ bindingIri }) => bindingIri).sort(compare),
      dispositionIri: FAMILY_REVIEW_WARRANTED,
      familyIri: family.familyIri,
      registryDigest: registry.registryDigest,
      signatureDigest: family.familyRecordDigest,
      subjectRegistrationIri: family.registrationIri,
    });
    const exact = related.filter((review) => {
      const core = expectedCore(review);
      const match = canonicalJson(review.applicabilityRuleIris) === canonicalJson([core.applicabilityRuleIri])
        && canonicalJson(review.authorityDigests) === canonicalJson([core.authorityDigest])
        && canonicalJson(review.dimensionBindingIris) === canonicalJson(core.dimensionBindingIris)
        && canonicalJson(review.dispositionIris) === canonicalJson([core.dispositionIri])
        && canonicalJson(review.registryDigests) === canonicalJson([core.registryDigest])
        && canonicalJson(review.signatureDigests) === canonicalJson([core.signatureDigest])
        && canonicalJson(review.subjectRegistrationIris) === canonicalJson([core.subjectRegistrationIri])
        && canonicalJson(review.reviewDigests) === canonicalJson([digest(core)]);
      if (!match) signatureDriftCount += 1;
      return match;
    });
    const state = related.length === 0
      ? 'REVIEW_MISSING'
      : related.length > 1
        ? 'REVIEW_DUPLICATE'
        : exact.length === 1 ? 'REVIEW_CURRENT' : 'REVIEW_STALE_OR_INVALID';
    return {
      acceptedReviewIri: state === 'REVIEW_CURRENT' ? exact[0].reviewIri : null,
      expectedFamilyRecordDigest: family.familyRecordDigest,
      familyIri: family.familyIri,
      relatedReviewCount: related.length,
      reviewState: state,
    };
  });
  return {
    duplicateReviewCount: rows.filter(({ reviewState }) => reviewState === 'REVIEW_DUPLICATE').length,
    exactReviewCount: rows.filter(({ reviewState }) => reviewState === 'REVIEW_CURRENT').length,
    missingReviewCount: rows.filter(({ reviewState }) => reviewState === 'REVIEW_MISSING').length,
    orphanReviewCount: orphanReviewIris.length,
    orphanReviewIris,
    reviewClassIri: FAMILY_REVIEW_CLASS,
    reviewSetDigest: digest(rows),
    rows,
    signatureDriftCount,
    staleOrInvalidReviewCount: rows.filter(({ reviewState }) => reviewState === 'REVIEW_STALE_OR_INVALID').length,
    warrantedDispositionIri: FAMILY_REVIEW_WARRANTED,
  };
}

function buildRelationshipSignatureWitnesses(inventory, registry) {
  const records = [];
  const addSelector = (family, selector, sourceRole) => {
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
        familyIri: family.familyIri,
        familyRecordDigest: family.familyRecordDigest,
        relationshipSignatureDigest: signature.relationshipSignatureDigest,
        relationshipSignatureIri: signature.relationshipSignatureIri,
        role: sourceRole,
        selectorDigest: selector.digest,
        selectorIri: selector.iri,
        stepDirectionIri: step.directionIri,
        stepIndex: step.index,
      };
      records.push({ ...core, witnessDigest: digest(core) });
    }
  };
  for (const family of registry.families) {
    for (const binding of family.orderedBindings) {
      if (binding.selector) addSelector(family, binding.selector, 'EXACT_SINGLE_STEP_DIMENSION_SELECTOR');
    }
    for (const selector of family.applicabilitySelectors) {
      addSelector(family, selector, 'EXACT_SINGLE_STEP_APPLICABILITY_SELECTOR');
    }
  }
  records.sort((left, right) => compare(canonicalJson(left), canonicalJson(right)));
  const unique = records.filter((record, index) => index === 0
    || record.witnessDigest !== records[index - 1].witnessDigest);
  return {
    records: unique,
    setDigest: digest(unique),
    witnessCount: unique.length,
  };
}

function relationshipSignatureDispositions(inventory, signatureWitnesses) {
  const bySignature = new Map();
  for (const witness of signatureWitnesses.records) {
    if (!bySignature.has(witness.relationshipSignatureIri)) bySignature.set(witness.relationshipSignatureIri, []);
    bySignature.get(witness.relationshipSignatureIri).push(witness);
  }
  const dispositions = [];
  const gaps = [];
  for (const signature of inventory.relationshipSignatures) {
    const witnesses = bySignature.get(signature.relationshipSignatureIri) ?? [];
    const covered = witnesses.length > 0;
    const reasonCode = covered
      ? 'UNIVERSAL_RELATIONSHIP_SIGNATURE_EXACT_SELECTOR_WITNESS'
      : 'UNIVERSAL_RELATIONSHIP_SIGNATURE_UNDISPOSITIONED';
    const core = {
      authorityDigest: inventory.authorityBinding.authorityDigest,
      disposition: covered ? 'EXACT_FAMILY_COVERAGE' : 'AUTHORITY_REVIEW_REQUIRED',
      inventoryDigest: inventory.inventoryDigest,
      reasonCode,
      relationshipSignatureDigest: signature.relationshipSignatureDigest,
      relationshipSignatureIri: signature.relationshipSignatureIri,
      schemaVersion: 1,
      witnessDigests: witnesses.map(({ witnessDigest }) => witnessDigest).sort(compare),
    };
    dispositions.push({ ...core, dispositionDigest: digest(core) });
    if (!covered) gaps.push({
      code: reasonCode,
      predicateIri: signature.predicateIri,
      relationshipSignatureIri: signature.relationshipSignatureIri,
    });
  }
  return { bySignature, dispositions, gaps };
}

function discoverAtomicRelationshipCandidates(inventory, signatureWitnessByIri) {
  const candidates = [];
  const gaps = [];
  for (const signature of inventory.relationshipSignatures) {
    if ((signatureWitnessByIri.get(signature.relationshipSignatureIri) ?? []).length > 0
      || signature.activeOccurrenceCount === 0) continue;
    const namedObject = signature.objectTermKind === 'NamedNode';
    const literalObject = signature.objectTermKind === 'Literal';
    if (signature.subjectClassIris.length !== 1
      || (namedObject && signature.objectClassIris.length !== 1)
      || (literalObject && !signature.objectDatatypeIri)
      || (!namedObject && !literalObject)) {
      gaps.push({
        code: 'UNIVERSAL_ATOMIC_CANDIDATE_ENDPOINT_AMBIGUOUS',
        objectClassIris: signature.objectClassIris,
        objectDatatypeIri: signature.objectDatatypeIri,
        predicateIri: signature.predicateIri,
        relationshipSignatureIri: signature.relationshipSignatureIri,
        subjectClassIris: signature.subjectClassIris,
      });
      continue;
    }
    const core = {
      authorityDigest: inventory.authorityBinding.authorityDigest,
      candidateKind: namedObject ? 'OBJECT_RELATIONSHIP' : 'DATATYPE_RELATIONSHIP',
      classification: 'AUTHORITY_REVIEW_REQUIRED',
      directionIri: 'urn:usf:permutationpathdirection:outbound',
      inventoryDigest: inventory.inventoryDigest,
      predicateIri: signature.predicateIri,
      reasonCode: 'UNIVERSAL_RELATIONSHIP_SIGNATURE_UNDISPOSITIONED',
      relationshipSignatureDigest: signature.relationshipSignatureDigest,
      relationshipSignatureIri: signature.relationshipSignatureIri,
      schemaVersion: 2,
      subjectClassIri: signature.subjectClassIris[0],
      terminalClassIri: namedObject ? signature.objectClassIris[0] : null,
      terminalDatatypeIri: literalObject ? signature.objectDatatypeIri : null,
    };
    const candidateDigest = digest(core);
    candidates.push({
      ...core,
      candidateDigest,
      candidateIri: `urn:usf:permutationfamilycandidate:${candidateDigest.slice('sha256:'.length)}`,
      recordKind: 'USF_ATOMIC_PERMUTATION_FAMILY_CANDIDATE',
    });
  }
  candidates.sort((left, right) => compare(left.candidateIri, right.candidateIri));
  gaps.sort((left, right) => compare(canonicalJson(left), canonicalJson(right)));
  return { candidates, gaps };
}

function currentTermReviewIndex(inventory, reviewProjection) {
  const byTerm = new Map();
  const invalidReviewIris = [];
  const termsByIri = new Map();
  for (const term of inventory.terms) {
    if (!termsByIri.has(term.iri)) termsByIri.set(term.iri, []);
    termsByIri.get(term.iri).push(term);
  }
  const ambiguousTermIris = uniqueSorted([...termsByIri]
    .filter(([, terms]) => terms.length !== 1).map(([iri]) => iri));
  if (ambiguousTermIris.length > 0) {
    fail('UNIVERSAL_REVIEW_TERM_IDENTITY_AMBIGUOUS',
      'reviewedSemanticTerm cannot distinguish multiple semantic term kinds', { ambiguousTermIris });
  }
  const sourceGroupByPath = new Map(inventory.sourceRecords
    .map(({ manifestGroup, path }) => [path, manifestGroup]));
  const orphanReviewIris = [];
  for (const review of reviewProjection?.termReviews ?? []) {
    if (review.reviewedTermIris.length !== 1 || review.authorityDigests.length !== 1
      || review.axisBindingIris.length !== 1 || review.familyCandidateStateIris.length !== 1
      || review.inventoryDigests.length !== 1 || review.participationIris.length !== 1
      || review.reasonCodes.length !== 1 || review.reviewDigests.length !== 1
      || review.statedSourcePlanes.length !== 1) {
      invalidReviewIris.push(review.reviewIri);
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
      invalidReviewIris.push(review.reviewIri);
      continue;
    }
    const reviewedTerms = termsByIri.get(core.reviewedTermIri) ?? [];
    if (reviewedTerms.length === 0) {
      orphanReviewIris.push(review.reviewIri);
      continue;
    }
    const expectedSourcePlane = uniqueSorted(reviewedTerms[0].sourcePaths
      .map((path) => sourceGroupByPath.get(path)).filter(Boolean)).join('+');
    if (core.sourcePlane !== expectedSourcePlane) {
      invalidReviewIris.push(review.reviewIri);
      continue;
    }
    if (!byTerm.has(core.reviewedTermIri)) byTerm.set(core.reviewedTermIri, []);
    byTerm.get(core.reviewedTermIri).push({ ...core, reviewDigest: review.reviewDigests[0], reviewIri: review.reviewIri });
  }
  return {
    byTerm,
    invalidReviewIris: uniqueSorted(invalidReviewIris),
    orphanReviewIris: uniqueSorted(orphanReviewIris),
  };
}

function termDispositions(inventory, witnessIndex, reviewProjection) {
  const byTerm = new Map();
  for (const record of witnessIndex.records) {
    if (!byTerm.has(record.termKey)) byTerm.set(record.termKey, []);
    byTerm.get(record.termKey).push(record);
  }
  const dispositions = [];
  const gaps = [];
  const reviewIndex = currentTermReviewIndex(inventory, reviewProjection);
  for (const term of inventory.terms) {
    const witnesses = byTerm.get(term.termKey) ?? [];
    const exactWitnesses = witnesses.filter(({ role }) => ![
      'PERMUTATION_META_MODEL_DEPENDENCY', 'VALIDATOR_DEPENDENCY',
    ].includes(role));
    const mechanismWitnesses = witnesses.filter(({ role }) => role === 'PERMUTATION_META_MODEL_DEPENDENCY');
    const validatorWitnesses = witnesses.filter(({ role }) => role === 'VALIDATOR_DEPENDENCY');
    const currentReviews = reviewIndex.byTerm.get(term.iri) ?? [];
    const currentReview = currentReviews.length === 1 ? currentReviews[0] : null;
    let reviewClosureState = currentReviews.length === 1
      ? 'CURRENT' : currentReviews.length > 1 ? 'DUPLICATE' : 'MISSING';
    let disposition;
    let reasonCode;
    if (exactWitnesses.length > 0) {
      disposition = 'EXACT_CLOSURE_PARTICIPATION';
      reasonCode = 'UNIVERSAL_EXACT_WITNESS_PRESENT';
    } else if (mechanismWitnesses.length > 0) {
      disposition = 'STRUCTURAL_META_MODEL_DEPENDENCY';
      reasonCode = 'UNIVERSAL_META_MODEL_DEPENDENCY_EXPLICIT';
    } else if (term.termUsageStateIris.includes(RESERVED)
      && term.activeOccurrenceCount === 0 && term.fixtureOccurrenceCount === 0) {
      disposition = 'RESERVED_WITH_EXPLICIT_STATE';
      reasonCode = 'UNIVERSAL_RESERVED_SCOPE_EXPLICIT';
    } else if (term.termUsageStateIris.includes(ZERO_BY_DESIGN)
      && term.activeOccurrenceCount === 0 && term.fixtureOccurrenceCount === 0) {
      disposition = 'ZERO_INSTANCE_WITH_EXPLICIT_STATE';
      reasonCode = 'UNIVERSAL_ZERO_INSTANCE_BY_DESIGN_EXPLICIT';
    } else {
      disposition = 'AUTHORITY_REVIEW_REQUIRED';
      reasonCode = validatorWitnesses.length > 0
        ? 'UNIVERSAL_VALIDATOR_DEPENDENCY_UNDISPOSITIONED'
        : term.termKind === 'class'
        ? 'UNIVERSAL_ACTIVE_CLASS_UNDISPOSITIONED'
        : term.termKind === 'individual'
          ? 'UNIVERSAL_ACTIVE_INDIVIDUAL_UNDISPOSITIONED'
          : term.declarationKindIris.includes(`${OWL}ObjectProperty`)
          ? 'UNIVERSAL_ACTIVE_RELATIONSHIP_UNCOVERED'
          : 'UNIVERSAL_ACTIVE_PROPERTY_UNDISPOSITIONED';
    }
    if (currentReview) {
      const nonAxis = currentReview.participationIri
        === 'urn:usf:permutationparticipationclassification:metadataprovenancenonaxis'
        && currentReview.axisBindingIri === 'urn:usf:permutationaxisbindingclassification:notanaxis'
        && ['urn:usf:permutationfamilycandidateclassification:notafamilycandidate',
          'urn:usf:permutationfamilycandidateclassification:rejected']
          .includes(currentReview.familyCandidateStateIri);
      const existingAxis = [
        'urn:usf:permutationparticipationclassification:operationalaxis',
        'urn:usf:permutationparticipationclassification:assuranceaxis',
        'urn:usf:permutationparticipationclassification:structuralselector',
        'urn:usf:permutationparticipationclassification:lifecyclederivationinput',
      ].includes(currentReview.participationIri)
        && currentReview.axisBindingIri === 'urn:usf:permutationaxisbindingclassification:existingaxis'
        && ['urn:usf:permutationfamilycandidateclassification:notafamilycandidate',
          'urn:usf:permutationfamilycandidateclassification:rejected']
          .includes(currentReview.familyCandidateStateIri)
        && exactWitnesses.length > 0;
      const remainsOpen = currentReview.participationIri
        === 'urn:usf:permutationparticipationclassification:authoritydecisionrequired'
        || currentReview.axisBindingIri
          === 'urn:usf:permutationaxisbindingclassification:unregisteredcontrolledaxis'
        || currentReview.familyCandidateStateIri
          === 'urn:usf:permutationfamilycandidateclassification:authorityreviewrequired';
      if (nonAxis && exactWitnesses.length > 0) {
        disposition = 'AUTHORITY_REVIEW_REQUIRED';
        reasonCode = 'UNIVERSAL_TERM_REVIEW_CONTRADICTS_EXACT_COVERAGE';
        reviewClosureState = 'CONFLICT';
      } else if (nonAxis) disposition = 'AUTHORITY_REVIEWED_NON_AXIS';
      else if (existingAxis) disposition = 'AUTHORITY_REVIEWED_EXACT_PARTICIPATION';
      else if (remainsOpen) disposition = 'AUTHORITY_REVIEW_REQUIRED';
      else {
        disposition = 'AUTHORITY_REVIEW_REQUIRED';
        reasonCode = 'UNIVERSAL_TERM_REVIEW_SEMANTIC_COMBINATION_INVALID';
        reviewClosureState = 'CONFLICT';
      }
      if ((nonAxis && exactWitnesses.length === 0) || existingAxis || remainsOpen) {
        reasonCode = currentReview.reasonCode;
      }
    }
    const gapDigest = disposition === 'AUTHORITY_REVIEW_REQUIRED'
      ? digest({ reasonCode, termKey: term.termKey }) : null;
    const core = {
      authorityDigest: inventory.authorityBinding.authorityDigest,
      disposition,
      gapIri: gapDigest ? `urn:usf:universalsemanticgap:${gapDigest.slice('sha256:'.length)}` : null,
      inventoryDigest: inventory.inventoryDigest,
      reasonCode,
      reviewClosureState,
      reviewDecisionDigest: currentReview?.reviewDigest ?? null,
      reviewDecisionIri: currentReview?.reviewIri ?? null,
      schemaVersion: 3,
      termKey: term.termKey,
      witnessDigests: witnesses.map(({ witnessDigest }) => witnessDigest).sort(compare),
    };
    dispositions.push({ ...core, dispositionDigest: digest(core) });
    if (gapDigest) gaps.push({ code: reasonCode, gapIri: core.gapIri, termIri: term.iri, termKind: term.termKind });
    if (currentReviews.length === 0) gaps.push({
      code: 'UNIVERSAL_TERM_REVIEW_MISSING', termIri: term.iri, termKind: term.termKind,
    });
    if (currentReviews.length > 1) gaps.push({
      code: 'UNIVERSAL_TERM_REVIEW_DUPLICATE', reviewCount: currentReviews.length,
      termIri: term.iri, termKind: term.termKind,
    });
  }
  for (const reviewIri of reviewIndex.invalidReviewIris) gaps.push({
    code: 'UNIVERSAL_TERM_REVIEW_STALE_OR_INVALID', reviewIri,
  });
  for (const reviewIri of reviewIndex.orphanReviewIris) gaps.push({
    code: 'UNIVERSAL_TERM_REVIEW_ORPHAN', reviewIri,
  });
  return { byTerm, dispositions, gaps, reviewIndex };
}

function reviewCoverageState(inventory, registry, reviewProjection, termReviewIndex, familyReview) {
  const expectedTermIris = uniqueSorted(inventory.terms.map(({ iri }) => iri));
  const expectedFamilyIris = registry.families.map(({ familyIri }) => familyIri).sort(compare);
  const coverages = reviewProjection?.coverages ?? [];
  const current = coverages.filter((coverage) => (
    canonicalJson(coverage.authorityDigests) === canonicalJson([inventory.authorityBinding.authorityDigest])
      && canonicalJson(coverage.inventoryDigests) === canonicalJson([inventory.inventoryDigest])
      && canonicalJson(coverage.familyRegistryDigests) === canonicalJson([registry.registryDigest])
  ));
  const exactTermReviews = expectedTermIris.map((termIri) => termReviewIndex.byTerm.get(termIri) ?? []);
  const exactFamilyReviews = familyReview.rows.map(({ acceptedReviewIri }) => acceptedReviewIri);
  const exactCoverage = current.filter((coverage) => {
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
  const orphanCoverageIris = coverages.filter((coverage) => !current.includes(coverage))
    .map(({ coverageIri }) => coverageIri).sort(compare);
  return {
    acceptedCoverageIri: exactCoverage.length === 1 ? exactCoverage[0].coverageIri : null,
    coverageState: exactCoverage.length === 1
      ? 'COVERAGE_CURRENT' : exactCoverage.length > 1 ? 'COVERAGE_DUPLICATE'
        : current.length > 0 ? 'COVERAGE_STALE_OR_INVALID' : 'COVERAGE_MISSING',
    currentCoverageCount: current.length,
    expectedFamilyCount: expectedFamilyIris.length,
    expectedFamilySetDigest: digest(expectedFamilyIris),
    expectedTermCount: expectedTermIris.length,
    expectedTermSetDigest: digest(expectedTermIris),
    orphanCoverageCount: orphanCoverageIris.length,
    orphanCoverageIris,
  };
}

export function analyseUniversalFamilyCompleteness({
  foundationAssessment,
  foundationProof,
  inventory,
  reviewProjection,
  registry,
}) {
  const foundationGate = assertFoundationGate(
    foundationAssessment,
    foundationProof,
    inventory.authorityBinding,
  );
  if (!reviewProjection
    || reviewProjection.recordKind !== 'USF_UNIVERSAL_REVIEW_PROJECTION'
    || reviewProjection.schemaVersion !== 2
    || reviewProjection.authorityDigest !== inventory.authorityBinding.authorityDigest
    || reviewProjection.inventoryDigest !== inventory.inventoryDigest
    || reviewProjection.familyRegistryDigest !== registry.registryDigest
    || reviewProjection.semanticInputSourceSetDigest !== inventory.sourceSetDigest
    || reviewProjection.projectionAlgorithmSourceDigest !== ANALYZER_SOURCE_DIGEST
    || reviewProjection.termReviewCount !== reviewProjection.termReviews?.length
    || reviewProjection.familySignatureReviewCount !== reviewProjection.familySignatureReviews?.length
    || reviewProjection.coverageCount !== reviewProjection.coverages?.length
    || reviewProjection.familyCandidateCount !== reviewProjection.familyCandidates?.length
    || reviewProjection.reviewSourceCount !== reviewProjection.reviewSourceRecords?.length
    || reviewProjection.reviewSourceSetDigest !== digest(reviewProjection.reviewSourceRecords ?? [])
    || reviewProjection.reviewProjectionDigest
      !== digest((({ reviewProjectionDigest, ...core }) => core)(reviewProjection))) {
    fail('UNIVERSAL_REVIEW_PROJECTION_INVALID', 'a digest-valid exact review projection is required');
  }
  const wrongPlaneResources = [
    ...reviewProjection.termReviews.map(({ reviewIri, sourcePlanes }) => ({ iri: reviewIri, sourcePlanes })),
    ...reviewProjection.familySignatureReviews.map(({ reviewIri, sourcePlanes }) => ({ iri: reviewIri, sourcePlanes })),
    ...reviewProjection.coverages.map(({ coverageIri, sourcePlanes }) => ({ iri: coverageIri, sourcePlanes })),
    ...reviewProjection.familyCandidates.map(({ candidateIri, sourcePlanes }) => ({ iri: candidateIri, sourcePlanes })),
  ].filter(({ sourcePlanes }) => canonicalJson(sourcePlanes) !== canonicalJson(['reviewGraphs']));
  if (wrongPlaneResources.length) {
    fail('UNIVERSAL_REVIEW_RESOURCE_PLANE_INVALID',
      'projected review resources must remain isolated from semantic inputs', { wrongPlaneResources });
  }
  const witnessIndex = buildExactCoverageWitnessIndex(inventory, registry);
  const dispositionResult = termDispositions(inventory, witnessIndex, reviewProjection);
  const signatureWitnesses = buildRelationshipSignatureWitnesses(inventory, registry);
  const signatureDispositionResult = relationshipSignatureDispositions(inventory, signatureWitnesses);
  const candidateResult = discoverAtomicRelationshipCandidates(inventory, signatureDispositionResult.bySignature);
  const registeredFamilyModelReview = familyModelReviews(inventory, registry, reviewProjection);
  const registeredReviewCoverage = reviewCoverageState(
    inventory,
    registry,
    reviewProjection,
    dispositionResult.reviewIndex,
    registeredFamilyModelReview,
  );
  const familyReviewGaps = registeredFamilyModelReview.rows.flatMap(({ familyIri, reviewState }) => (
    reviewState === 'REVIEW_CURRENT' ? [] : [{
      code: `UNIVERSAL_REGISTERED_FAMILY_${reviewState}`,
      familyIri,
    }]
  )).concat(registeredFamilyModelReview.orphanReviewIris.map((reviewIri) => ({
    code: 'UNIVERSAL_REGISTERED_FAMILY_REVIEW_ORPHAN',
    reviewIri,
  })));
  const coverageGaps = [
    ...(registeredReviewCoverage.coverageState === 'COVERAGE_CURRENT' ? [] : [{
      code: `UNIVERSAL_REVIEW_${registeredReviewCoverage.coverageState}`,
    }]),
    ...registeredReviewCoverage.orphanCoverageIris.map((coverageIri) => ({
      code: 'UNIVERSAL_REVIEW_COVERAGE_ORPHAN', coverageIri,
    })),
  ];
  const gaps = [
    ...(inventory.authorityInputVerification.fullAuthorityTermParityState === 'PROVEN_EQUAL'
      ? [] : [{ code: 'UNIVERSAL_LIVE_AUTHORITY_FULL_TERM_PARITY_UNPROVEN' }]),
    ...inventory.undeclaredClassIris.map((termIri) => ({ code: 'UNIVERSAL_ACTIVE_CLASS_UNDECLARED', termIri })),
    ...inventory.undeclaredPredicateIris.map((predicateIri) => ({ code: 'UNIVERSAL_ACTIVE_RELATIONSHIP_UNDECLARED', predicateIri })),
    ...dispositionResult.gaps,
    ...signatureDispositionResult.gaps,
    ...candidateResult.gaps,
    ...candidateResult.candidates.map(({ candidateIri, predicateIri, relationshipSignatureIri }) => ({
      candidateIri,
      code: 'UNIVERSAL_CANDIDATE_MODEL_NOT_AUTHORITY',
      predicateIri,
      relationshipSignatureIri,
    })),
    ...familyReviewGaps,
    ...coverageGaps,
  ].sort((left, right) => compare(canonicalJson(left), canonicalJson(right)));
  const duplicateGap = gaps.find((gap, index) => index > 0 && canonicalJson(gap) === canonicalJson(gaps[index - 1]));
  if (duplicateGap) fail('UNIVERSAL_GAP_IDENTITY_DUPLICATE', 'duplicate gap exists', { gap: duplicateGap });
  const termDispositionPartition = Object.fromEntries([
    'AUTHORITY_REVIEW_REQUIRED',
    'AUTHORITY_REVIEWED_EXACT_PARTICIPATION',
    'AUTHORITY_REVIEWED_NON_AXIS',
    'EXACT_CLOSURE_PARTICIPATION',
    'RESERVED_WITH_EXPLICIT_STATE',
    'STRUCTURAL_META_MODEL_DEPENDENCY',
    'ZERO_INSTANCE_WITH_EXPLICIT_STATE',
  ].map((state) => [state, dispositionResult.dispositions.filter(({ disposition }) => disposition === state).length]));
  const relationshipSignatureDispositionPartition = Object.fromEntries([
    'AUTHORITY_REVIEW_REQUIRED', 'EXACT_FAMILY_COVERAGE',
  ].map((state) => [state, signatureDispositionResult.dispositions
    .filter(({ disposition }) => disposition === state).length]));
  const gapCodeCounts = Object.fromEntries(uniqueSorted(gaps.map(({ code }) => code))
    .map((code) => [code, gaps.filter((gap) => gap.code === code).length]));
  const atomicCandidatePredicateCounts = uniqueSorted(candidateResult.candidates
    .map(({ predicateIri }) => predicateIri)).map((predicateIri) => ({
      candidateCount: candidateResult.candidates.filter((candidate) => (
        candidate.predicateIri === predicateIri
      )).length,
      predicateIri,
    }));
  const core = {
    analysisAlgorithmSourceDigest: ANALYZER_SOURCE_DIGEST,
    atomicCandidateCount: candidateResult.candidates.length,
    atomicCandidatePredicateCounts,
    atomicCandidateSetDigest: digest(candidateResult.candidates),
    atomicCandidates: candidateResult.candidates,
    authorityDigest: inventory.authorityBinding.authorityDigest,
    foundationAssessmentDigest: foundationAssessment.assessmentDigest,
    foundationProofDigest: foundationGate.proofDigest,
    gapCount: gaps.length,
    gapCodeCounts,
    gaps,
    gapSetDigest: digest(gaps),
    inventoryDigest: inventory.inventoryDigest,
    nonClaims: [
      'NOT_CAPABILITY_PERMUTATION_CLOSURE',
      'NOT_PRODUCTION_READINESS',
      'NOT_SEMANTIC_AUTHORITY',
    ],
    recordKind: 'USF_UNIVERSAL_FAMILY_COMPLETENESS_ANALYSIS',
    registeredFamilyModelReview,
    registeredReviewCoverage,
    registryDigest: registry.registryDigest,
    reviewProjectionDigest: reviewProjection.reviewProjectionDigest,
    relationshipSignatureDispositionPartition,
    relationshipSignatureDispositionSetDigest: digest(signatureDispositionResult.dispositions),
    relationshipSignatureDispositions: signatureDispositionResult.dispositions,
    relationshipSignatureWitnessCount: signatureWitnesses.witnessCount,
    relationshipSignatureWitnessSetDigest: signatureWitnesses.setDigest,
    relationshipSignatureWitnesses: signatureWitnesses.records,
    schemaVersion: 4,
    termDispositionPartition,
    termDispositionSetDigest: digest(dispositionResult.dispositions),
    termDispositions: dispositionResult.dispositions,
    verdict: gaps.length === 0
      ? 'UNIVERSAL_FAMILY_MODEL_COMPLETE'
      : 'UNIVERSAL_FAMILY_MODEL_INCOMPLETE',
    witnessCount: witnessIndex.witnessCount,
    witnessIndexDigest: witnessIndex.witnessIndexDigest,
    witnesses: witnessIndex.records,
  };
  return { ...core, analysisDigest: digest(core) };
}

export function assertFoundationGate(foundationAssessment, foundationProof, authorityBinding) {
  const binding = exactAuthorityBinding(authorityBinding);
  if (!foundationAssessment || foundationAssessment.recordKind !== 'USF_FOUNDATION_DOMAIN_CLOSURE_ASSESSMENT'
    || foundationAssessment.schemaVersion !== 2
    || foundationAssessment.foundationDomainClosureComplete !== true
    || foundationAssessment.foundationVerdict !== 'FOUNDATION_DOMAIN_CLOSURE_COMPLETE'
    || foundationAssessment.assessmentDigest !== digest((({ assessmentDigest, ...core }) => core)(foundationAssessment))) {
    fail('UNIVERSAL_FOUNDATION_PROOF_REQUIRED', 'a digest-valid complete foundation assessment is required');
  }
  if (!foundationProof || foundationProof.recordKind !== 'USF_FOUNDATION_DOMAIN_CLOSURE_INDEPENDENT_PROOF'
    || foundationProof.schemaVersion !== 2
    || foundationProof.verdict !== 'FOUNDATION_DOMAIN_CLOSURE_PROOF_PASS'
    || foundationProof.results?.emptyDomainCount !== 0
    || foundationProof.results?.reconstructionMismatchCount !== 0
    || foundationProof.proofDigest !== digest((({ proofDigest, ...core }) => core)(foundationProof))) {
    fail('UNIVERSAL_FOUNDATION_PROOF_REQUIRED', 'a successful digest-valid independent proof is required');
  }
  const fields = [
    'assessmentDigest', 'fixtureDigest', 'fixtureInputDigest', 'fixtureProjectionDigest',
    'foundationStructuralProjectionDigest', 'foundationStructuralProjectionRecordCount',
    'foundationStructuralProjectionRuleSetDigest', 'metaModelDigest',
  ];
  const mismatches = fields.filter((field) => {
    const assessmentValue = field === 'assessmentDigest'
      ? foundationAssessment.assessmentDigest : foundationAssessment[field];
    return canonicalJson(foundationProof[field]) !== canonicalJson(assessmentValue);
  });
  if (canonicalJson(foundationAssessment.baselineAuthorityBinding) !== canonicalJson(binding)
    || canonicalJson(foundationProof.baselineAuthorityBinding) !== canonicalJson(binding)) {
    mismatches.push('baselineAuthorityBinding');
  }
  if (mismatches.length > 0) {
    fail('UNIVERSAL_FOUNDATION_PROOF_BINDING_MISMATCH', 'foundation inputs do not share exact bindings', {
      fields: uniqueSorted(mismatches),
    });
  }
  return { assessmentDigest: foundationAssessment.assessmentDigest, proofDigest: foundationProof.proofDigest };
}

export function runUniversalSemanticCoverage({
  authorityBinding,
  authorityPacketPath,
  authorityProjectionPath,
  foundationAssessment,
  foundationProof,
  repositoryRoot,
}) {
  const authorityInputVerification = verifyUniversalAuthorityInputs({
    authorityBinding,
    authorityPacketPath,
    authorityProjectionPath,
    repositoryRoot,
  });
  const inventory = buildUniversalSemanticInventory({ authorityBinding, authorityInputVerification, repositoryRoot });
  const registry = loadUniversalFamilyRegistry({ repositoryRoot });
  const reviewProjection = loadUniversalReviewProjection({ inventory, registry, repositoryRoot });
  const analysis = analyseUniversalFamilyCompleteness({
    foundationAssessment,
    foundationProof,
    inventory,
    reviewProjection,
    registry,
  });
  return { analysis, inventory, registry, reviewProjection };
}

export const universalSemanticCoverageInternals = Object.freeze({
  buildRelationshipSignatureWitnesses,
  canonicalTerm,
  discoverAtomicRelationshipCandidates,
  readGovernedDataset,
  relationshipSignatureDispositions,
  sparqlDependencyIris,
  termDispositions,
});

function exactArgument(name) {
  const prefix = `--${name}=`;
  const matches = process.argv.filter((argument) => argument.startsWith(prefix));
  if (matches.length !== 1 || matches[0].length === prefix.length) {
    fail('UNIVERSAL_EXACT_ARGUMENT_REQUIRED', `exactly one ${prefix}<value> is required`);
  }
  return matches[0].slice(prefix.length);
}

function readDigestBoundJson(repositoryRoot, pathArgument, digestArgument, code) {
  const path = resolve(repositoryRoot, pathArgument);
  if (!contained(repositoryRoot, path)) fail('UNIVERSAL_INPUT_PATH_ESCAPE', pathArgument);
  const bytes = readFileSync(path);
  if (sha256(bytes) !== digestArgument) fail(code, pathArgument);
  return JSON.parse(bytes.toString('utf8'));
}

function writeAddressedJson(repositoryRoot, prefix, value) {
  const content = `${canonicalJson(value)}\n`;
  const fileDigest = sha256(content);
  const outputPath = join('.work', 'generated', `${prefix}-${fileDigest.slice('sha256:'.length)}.json`);
  mkdirSync(dirname(join(repositoryRoot, outputPath)), { recursive: true });
  writeFileSync(join(repositoryRoot, outputPath), content);
  return { fileDigest, outputPath };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const repositoryRoot = realpathSync(resolve(dirname(fileURLToPath(import.meta.url)), '..', '..'));
    const foundationAssessment = readDigestBoundJson(
      repositoryRoot,
      exactArgument('foundation-assessment'),
      exactArgument('foundation-assessment-digest'),
      'UNIVERSAL_FOUNDATION_ASSESSMENT_FILE_DIGEST_MISMATCH',
    );
    const foundationProof = readDigestBoundJson(
      repositoryRoot,
      exactArgument('foundation-proof'),
      exactArgument('foundation-proof-digest'),
      'UNIVERSAL_FOUNDATION_PROOF_FILE_DIGEST_MISMATCH',
    );
    const result = runUniversalSemanticCoverage({
      authorityBinding: {
        authorityDigest: exactArgument('authority-digest'),
        authorityPacketDigest: exactArgument('authority-packet-digest'),
        authorityProjectionDigest: exactArgument('authority-projection-digest'),
      },
      authorityPacketPath: exactArgument('authority-packet'),
      authorityProjectionPath: exactArgument('authority-projection'),
      foundationAssessment,
      foundationProof,
      repositoryRoot,
    });
    const inventory = writeAddressedJson(repositoryRoot, 'universal-semantic-inventory', result.inventory);
    const registry = writeAddressedJson(repositoryRoot, 'universal-family-registry', result.registry);
    const reviewProjection = writeAddressedJson(
      repositoryRoot,
      'universal-review-projection',
      result.reviewProjection,
    );
    const analysis = writeAddressedJson(repositoryRoot, 'universal-family-completeness-analysis', result.analysis);
    process.stdout.write(`${canonicalJson({
      analysisDigest: result.analysis.analysisDigest,
      analysisFileDigest: analysis.fileDigest,
      analysisPath: analysis.outputPath,
      atomicCandidateCount: result.analysis.atomicCandidateCount,
      classCount: result.inventory.classCount,
      familyCount: result.registry.familyCount,
      gapCount: result.analysis.gapCount,
      individualCount: result.inventory.individualCount,
      inventoryDigest: result.inventory.inventoryDigest,
      inventoryFileDigest: inventory.fileDigest,
      inventoryPath: inventory.outputPath,
      propertyCount: result.inventory.propertyCount,
      reviewProjectionDigest: result.reviewProjection.reviewProjectionDigest,
      reviewProjectionFileDigest: reviewProjection.fileDigest,
      reviewProjectionPath: reviewProjection.outputPath,
      registryDigest: result.registry.registryDigest,
      registryFileDigest: registry.fileDigest,
      registryPath: registry.outputPath,
      relationshipCategoryCount: result.inventory.relationshipCategoryCount,
      relationshipSignatureCount: result.inventory.relationshipSignatureCount,
      verdict: result.analysis.verdict,
    })}\n`);
  } catch (error) {
    process.stderr.write(`${error.code ?? error.name}:${error.message}\n`);
    process.exitCode = 1;
  }
}
