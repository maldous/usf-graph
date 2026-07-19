// Stardog SDK adapter for the USF semantic compiler.
//
// This is the ONLY module that imports the SDK. Every Stardog interaction goes
// through the client returned by createClient. No Stardog CLI, no spawned
// process, no raw HTTP, no direct fetch. There is deliberately no operation
// that clears the whole database: clearing is only ever per named graph.

import stardog from 'stardog';

const { Connection, db, query } = stardog;

const TURTLE = 'text/turtle';
const NQUADS = 'application/n-quads';
const SPARQL_JSON = 'application/sparql-results+json';
const shapeDocuments = (shapes) => (Array.isArray(shapes) ? shapes : [{ file: 'inline-shapes.ttl', content: shapes }]);

export class StardogError extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'StardogError';
    this.status = status;
  }
}

// Confirm an SDK response succeeded. Error text carries only the operation and
// HTTP status — never credentials. (The SDK never returns credentials in a
// body, and this deliberately does not stringify the whole response.)
function ok(res, op) {
  if (res && res.ok) return res;
  const status = res ? res.status : undefined;
  throw new StardogError(`Stardog ${op} failed (status ${status})`, status);
}

function bindings(res) {
  const b = res && res.body && res.body.results && res.body.results.bindings;
  return Array.isArray(b) ? b : [];
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

export function createClient(config) {
  const conn = new Connection(
    config.auth.kind === 'token'
      ? { endpoint: config.endpoint, token: config.auth.token }
      : { endpoint: config.endpoint, username: config.auth.username, password: config.auth.password }
  );
  const database = config.database;

  return {
    // A cheap authenticated round-trip that fails closed if the endpoint is
    // unreachable or the credentials are rejected.
    async connectivity() {
      const res = await db.size(conn, database);
      ok(res, 'connectivity');
      return Number(res.body);
    },

    async begin() {
      const res = await db.transaction.begin(conn, database);
      ok(res, 'transaction.begin');
      return res.transactionId;
    },
    async commit(tx) {
      ok(await db.transaction.commit(conn, database, tx), 'transaction.commit');
    },
    async rollback(tx) {
      ok(await db.transaction.rollback(conn, database, tx), 'transaction.rollback');
    },
    isTransactionClosedError(error) {
      return [400, 404, 410].includes(error?.status);
    },

    // Clear exactly one named graph inside a transaction. A missing IRI is a
    // programming error, not a request to clear everything.
    async clearGraph(tx, graphIri) {
      if (!graphIri) throw new StardogError('clearGraph requires a named-graph IRI', undefined);
      ok(await db.clear(conn, database, tx, { graphUri: graphIri }), `clear ${graphIri}`);
    },
    async clearGraphs(tx, graphIris) {
      if (!Array.isArray(graphIris) || graphIris.length === 0) throw new StardogError('clearGraphs requires explicit named-graph IRIs', undefined);
      const unique = [...new Set(graphIris)];
      for (const graphIri of unique) {
        if (typeof graphIri !== 'string' || !/^[A-Za-z][A-Za-z0-9+.-]*:[^<>"{}\\\s]+$/.test(graphIri)) {
          throw new StardogError('clearGraphs received an invalid named-graph IRI', undefined);
        }
      }
      const update = unique.map((graphIri) => `CLEAR SILENT GRAPH <${graphIri}>`).join(';\n');
      ok(await query.executeInTransaction(conn, database, tx, update, { accept: 'text/plain' }), 'clear registered graphs');
    },

    // Add RDF into the transaction. Turtle is targeted at an explicit graph;
    // TriG carries its own graph names, so no override is applied.
    async addData(tx, content, contentType, graphIri) {
      const params = contentType === TURTLE && graphIri ? { graphUri: graphIri } : {};
      ok(await db.add(conn, database, tx, content, { contentType }, params), 'add');
    },

    // Run a CONSTRUCT inside the transaction and return the constructed triples
    // as Turtle (empty string when nothing is constructed).
    async constructInTx(tx, sparql) {
      const res = await query.executeInTransaction(conn, database, tx, sparql, { accept: TURTLE });
      ok(res, 'construct');
      return typeof res.body === 'string' ? res.body : '';
    },

    // Run a SELECT inside the transaction and return its bindings.
    async selectInTx(tx, sparql) {
      const res = await query.executeInTransaction(conn, database, tx, sparql, {
        accept: SPARQL_JSON,
      });
      ok(res, 'select (tx)');
      return bindings(res);
    },

    // SHACL-validate the current transaction state against the supplied shapes.
    // Returns whether the data conforms.
    async validateInTx(tx, shapes) {
      for (const document of shapeDocuments(shapes)) {
        const res = await db.icv.validateInTx(conn, database, tx, document.content, { contentType: TURTLE });
        if (!res?.ok) throw new StardogError(`Stardog validateInTx failed for ${document.file} (status ${res?.status})`, res?.status);
        if (res.body === true) continue;
        const report = await db.icv.reportInTx(conn, database, tx, document.content, { contentType: TURTLE });
        if (!report?.ok) throw new StardogError(`Stardog reportInTx failed for ${document.file} (status ${report?.status})`, report?.status);
        const conforms = reportConforms(report.body);
        if (conforms === null) throw new StardogError(`Stardog reportInTx did not contain one explicit SHACL conformance result for ${document.file}`, report?.status);
        if (!conforms) return false;
      }
      return true;
    },
    // A full SHACL report for diagnostics when validation fails.
    async reportInTx(tx, shapes) {
      const reports = [];
      for (const document of shapeDocuments(shapes)) {
        const validation = await db.icv.validateInTx(conn, database, tx, document.content, { contentType: TURTLE });
        if (!validation?.ok) throw new StardogError(`Stardog validateInTx failed for ${document.file} (status ${validation?.status})`, validation?.status);
        if (validation.body === true) continue;
        const report = await db.icv.reportInTx(conn, database, tx, document.content, { contentType: TURTLE });
        if (!report?.ok) throw new StardogError(`Stardog reportInTx failed for ${document.file} (status ${report?.status})`, report?.status);
        const conforms = reportConforms(report.body);
        if (conforms === null) throw new StardogError(`Stardog reportInTx did not contain one explicit SHACL conformance result for ${document.file}`, report?.status);
        if (!conforms) reports.push({ file: document.file, report: report.body });
      }
      return reports;
    },

    // Read-only SELECT outside any transaction (used by verify).
    async select(sparql) {
      const res = await query.execute(conn, database, sparql, SPARQL_JSON);
      ok(res, 'select');
      return bindings(res);
    },

    // Read-only ASK outside any transaction.
    async ask(sparql) {
      const res = await query.execute(conn, database, sparql, SPARQL_JSON);
      ok(res, 'ask');
      return Boolean(res.body && res.body.boolean);
    },

    // Read-only graph export through SPARQL CONSTRUCT. N-Quads is used by the
    // external attestation path so RDF Dataset Canonicalization can make blank
    // node identifiers irrelevant before hashing.
    async construct(sparql, accept = NQUADS) {
      const res = await query.execute(conn, database, sparql, accept);
      ok(res, 'construct');
      return typeof res.body === 'string' ? res.body : '';
    },

    // Read-only SHACL validation against the committed database (used by
    // verify). Passing constraints ad hoc means no stored ICV is required and
    // nothing is written.
    async validate(shapes) {
      for (const document of shapeDocuments(shapes)) {
        const res = await db.icv.validate(conn, database, document.content, { contentType: TURTLE });
        if (!res?.ok) throw new StardogError(`Stardog validate failed for ${document.file} (status ${res?.status})`, res?.status);
        if (res.body === true) continue;
        if (typeof db.icv.report !== 'function') throw new StardogError('Stardog SDK lacks the SHACL report operation required to resolve a non-true validation response', res?.status);
        const report = await db.icv.report(conn, database, document.content, { contentType: TURTLE });
        if (!report?.ok) throw new StardogError(`Stardog report failed for ${document.file} (status ${report?.status})`, report?.status);
        const conforms = reportConforms(report.body);
        if (conforms === null) throw new StardogError(`Stardog report did not contain one explicit SHACL conformance result for ${document.file}`, report?.status);
        if (!conforms) return false;
      }
      return true;
    },

    async size() {
      const res = await db.size(conn, database);
      ok(res, 'size');
      return Number(res.body);
    },
  };
}

export const stardogInternals = Object.freeze({ ok, reportConforms });
