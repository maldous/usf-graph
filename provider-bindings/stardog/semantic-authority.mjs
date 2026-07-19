import { resolveLiveSemanticAuthorityConfiguration } from '../../configuration/semantic-assurance/semantic-authority.mjs';
import { createHash } from 'node:crypto';

const TURTLE = 'text/turtle';
const NQUADS = 'application/n-quads';
const SPARQL_JSON = 'application/sparql-results+json';
const GRAPH_IRI = /^[A-Za-z][A-Za-z0-9+.-]*:[^<>"{}\\\s]+$/;
const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]))
    : value;
const canonicalJson = (value) => JSON.stringify(stable(value));
const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;

export class StardogSemanticAuthorityError extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'StardogSemanticAuthorityError';
    this.status = status;
  }
}

function successful(response, operation) {
  if (response?.ok) return response;
  throw new StardogSemanticAuthorityError(`Stardog ${operation} failed (status ${response?.status})`, response?.status);
}

function bindings(response) {
  const rows = response?.body?.results?.bindings;
  return Array.isArray(rows) ? rows : [];
}

function shapeDocuments(shapes) {
  return Array.isArray(shapes) ? shapes : [{ file: 'inline-shapes.ttl', content: shapes }];
}

function booleanValue(value) {
  if (typeof value === 'boolean') return value;
  if (Array.isArray(value)) return value.length === 1 ? booleanValue(value[0]) : null;
  if (value && typeof value === 'object' && Object.hasOwn(value, '@value')) return booleanValue(value['@value']);
  if (value === 'true') return true;
  if (value === 'false') return false;
  return null;
}

function reportConforms(body) {
  const nodes = Array.isArray(body?.['@graph']) ? body['@graph'] : [body];
  const reports = nodes.filter((node) => {
    const types = Array.isArray(node?.['@type']) ? node['@type'] : [node?.['@type']];
    return types.includes('sh:ValidationReport') || types.includes('http://www.w3.org/ns/shacl#ValidationReport');
  });
  if (reports.length !== 1) return null;
  return booleanValue(reports[0]['sh:conforms'] ?? reports[0]['http://www.w3.org/ns/shacl#conforms']);
}

function validateSdk(sdk) {
  if (typeof sdk?.Connection !== 'function' || !sdk.db || !sdk.query) throw new StardogSemanticAuthorityError('Stardog SDK binding is incomplete');
  return sdk;
}

export function createStardogSemanticAuthorityClient({ sdk, configuration, resolveSecret }) {
  const { Connection, db, query } = validateSdk(sdk);
  const resolved = resolveLiveSemanticAuthorityConfiguration(configuration, resolveSecret);
  const connection = new Connection(resolved.auth.kind === 'token'
    ? { endpoint: resolved.endpoint, token: resolved.auth.token }
    : { endpoint: resolved.endpoint, username: resolved.auth.username, password: resolved.auth.password });
  const database = resolved.database;
  const validateInTransactionWithReceipt = async (transaction, shapes) => {
    const inputs = [];
    const observations = [];
    for (const document of shapeDocuments(shapes)) {
      const input = {
        path: `semantic-model/${document.file}`,
        digest: sha256(document.content),
      };
      inputs.push(input);
      const response = successful(await db.icv.validateInTx(connection, database, transaction, document.content, { contentType: TURTLE }), `validate ${document.file}`);
      let conforms = response.body === true;
      let reportDigest = null;
      if (!conforms) {
        const report = successful(await db.icv.reportInTx(connection, database, transaction, document.content, { contentType: TURTLE }), `report ${document.file}`);
        conforms = reportConforms(report.body);
        reportDigest = sha256(canonicalJson(report.body));
        if (conforms === null) throw new StardogSemanticAuthorityError(`Stardog report ${document.file} did not contain one explicit SHACL conformance result`);
      }
      observations.push({
        ...input,
        conforms,
        validationResponseDigest: sha256(canonicalJson(response.body)),
        reportDigest,
      });
      if (!conforms) break;
    }
    inputs.sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
    observations.sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
    const receiptCore = {
      conforms: observations.length === inputs.length && observations.every(({ conforms: item }) => item === true),
      validatedDocumentCount: observations.length,
      validatedDocumentSetDigest: sha256(canonicalJson(inputs)),
      observationSetDigest: sha256(canonicalJson(observations)),
    };
    return Object.freeze({ ...receiptCore, receiptDigest: sha256(canonicalJson(receiptCore)) });
  };

  return Object.freeze({
    expectedAuthorityDigest: resolved.expectedAuthorityDigest,

    async connectivity() {
      return Number(successful(await db.size(connection, database), 'connectivity').body);
    },

    async begin() {
      return successful(await db.transaction.begin(connection, database), 'transaction.begin').transactionId;
    },

    async commit(transaction) {
      successful(await db.transaction.commit(connection, database, transaction), 'transaction.commit');
    },

    async rollback(transaction) {
      successful(await db.transaction.rollback(connection, database, transaction), 'transaction.rollback');
    },

    isTransactionClosedError(error) {
      return [400, 404, 410].includes(error?.status);
    },

    async clearGraphs(transaction, graphIris) {
      if (!Array.isArray(graphIris) || graphIris.length === 0) throw new StardogSemanticAuthorityError('clearGraphs requires explicit named-graph IRIs');
      const unique = [...new Set(graphIris)];
      if (unique.some((graphIri) => typeof graphIri !== 'string' || !GRAPH_IRI.test(graphIri))) throw new StardogSemanticAuthorityError('clearGraphs received an invalid named-graph IRI');
      const update = unique.map((graphIri) => `CLEAR SILENT GRAPH <${graphIri}>`).join(';\n');
      successful(await query.executeInTransaction(connection, database, transaction, update, { accept: 'text/plain' }), 'clear registered graphs');
    },

    async addData(transaction, content, contentType, graphIri) {
      const parameters = contentType === TURTLE && graphIri ? { graphUri: graphIri } : {};
      successful(await db.add(connection, database, transaction, content, { contentType }, parameters), 'add');
    },

    async constructInTransaction(transaction, sparql) {
      const response = successful(await query.executeInTransaction(connection, database, transaction, sparql, { accept: TURTLE }), 'construct');
      return typeof response.body === 'string' ? response.body : '';
    },

    async selectInTransaction(transaction, sparql) {
      return bindings(successful(await query.executeInTransaction(connection, database, transaction, sparql, { accept: SPARQL_JSON }), 'select (transaction)'));
    },

    async validateInTransaction(transaction, shapes) {
      return (await validateInTransactionWithReceipt(transaction, shapes)).conforms;
    },

    validateInTransactionWithReceipt,

    async reportInTransaction(transaction, shapes) {
      const reports = [];
      for (const document of shapeDocuments(shapes)) {
        const validation = successful(await db.icv.validateInTx(connection, database, transaction, document.content, { contentType: TURTLE }), `validate ${document.file}`);
        if (validation.body === true) continue;
        const report = successful(await db.icv.reportInTx(connection, database, transaction, document.content, { contentType: TURTLE }), `report ${document.file}`);
        const conforms = reportConforms(report.body);
        if (conforms === null) throw new StardogSemanticAuthorityError(`Stardog report ${document.file} did not contain one explicit SHACL conformance result`);
        if (!conforms) reports.push({ file: document.file, report: report.body });
      }
      return reports;
    },

    async select(sparql) {
      return bindings(successful(await query.execute(connection, database, sparql, SPARQL_JSON), 'select'));
    },

    async ask(sparql) {
      const response = successful(await query.execute(connection, database, sparql, SPARQL_JSON), 'ask');
      return Boolean(response.body?.boolean);
    },

    async construct(sparql, accept = NQUADS) {
      const response = successful(await query.execute(connection, database, sparql, accept), 'construct');
      return typeof response.body === 'string' ? response.body : '';
    },

    async validate(shapes) {
      for (const document of shapeDocuments(shapes)) {
        const response = successful(await db.icv.validate(connection, database, document.content, { contentType: TURTLE }), `validate ${document.file}`);
        if (response.body === true) continue;
        if (typeof db.icv.report !== 'function') throw new StardogSemanticAuthorityError('Stardog SDK binding lacks the SHACL report operation required to resolve a non-true validation response');
        const report = successful(await db.icv.report(connection, database, document.content, { contentType: TURTLE }), `report ${document.file}`);
        const conforms = reportConforms(report.body);
        if (conforms === null) throw new StardogSemanticAuthorityError(`Stardog report ${document.file} did not contain one explicit SHACL conformance result`);
        if (!conforms) return false;
      }
      return true;
    },

    async size() {
      return Number(successful(await db.size(connection, database), 'size').body);
    },
  });
}

export const stardogSemanticAuthorityInternals = Object.freeze({ bindings, reportConforms, successful });
