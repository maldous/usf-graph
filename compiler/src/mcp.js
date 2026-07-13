#!/usr/bin/env node
// USF read-only Stardog MCP server (stdio, newline-delimited JSON-RPC 2.0).
//
// Exposes bounded, read-only Stardog interrogation to agents so they query the
// live semantic authority directly instead of reading graph files or a census.
// Every Stardog interaction goes through the compiler's single SDK boundary
// (stardog.js). Mutations are rejected by classifySparql. Credentials never
// reach stdout/stderr: every outbound line is passed through a redactor built
// from the live secrets.
//
// Tool names use underscores (usf_health, usf_query, usf_bootstrap) because
// downstream model tool-callers restrict names to [A-Za-z0-9_-]. They realise
// the usf.health / usf.query / usf.bootstrap surface of USF-1154. Placement is
// provisional pending the USF-1155 clean-room layout contract; it lives inside
// the (authorised) compiler package for now.

import { createInterface } from 'node:readline';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { loadConfig, describeConfig } from './config.js';
import { createClient } from './stardog.js';
import { classifySparql } from './sparql-guard.js';
import { bootstrapPacket } from './bootstrap.js';

const PROTOCOL_VERSION = '2024-11-05';
const MAX_ROWS = 200;
const MAX_TEXT_BYTES = 100_000;

// Cap a SELECT server-side so a broad query never streams the full authority
// before slicing. LIMIT MAX_ROWS+1 keeps truncation detectable. Queries that
// already carry LIMIT anywhere (theirs may be a subquery's) or a trailing
// VALUES block (grammar puts it after solution modifiers) are left untouched
// and fall back to the client-side slice — fail-safe, just less optimal.
export function cappedSelect(sparql) {
  const tokens = sparql.toUpperCase();
  if (/\bLIMIT\b/.test(tokens) || /\bVALUES\b/.test(tokens)) return sparql;
  return `${sparql.trimEnd()}\nLIMIT ${MAX_ROWS + 1}`;
}

const pkgPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'package.json');
const VERSION = JSON.parse(readFileSync(pkgPath, 'utf8')).version;

// Build a redactor from whatever secret the live config carries. Applied to
// every outbound string; long random tokens make false hits negligible.
export function makeRedactor(config) {
  const secrets = [];
  if (config.auth.kind === 'token') secrets.push(config.auth.token);
  if (config.auth.kind === 'basic') secrets.push(config.auth.password);
  const real = secrets.filter((s) => typeof s === 'string' && s.length >= 4);
  return (text) => {
    let out = String(text);
    for (const s of real) out = out.split(s).join('***');
    return out;
  };
}

export const TOOLS = [
  {
    name: 'usf_health',
    description: 'Stardog connectivity and authority size: endpoint, database, auth mode, total triple count. No arguments.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'usf_query',
    description: 'Run a read-only SPARQL query (SELECT/ASK/CONSTRUCT/DESCRIBE) against the USF Stardog database. Mutations (INSERT/DELETE/LOAD/CLEAR/DROP/CREATE/COPY/MOVE/ADD) are rejected. SELECT returns up to 200 bindings; CONSTRUCT/DESCRIBE return Turtle.',
    inputSchema: {
      type: 'object',
      properties: { sparql: { type: 'string', description: 'A read-only SPARQL query.' } },
      required: ['sparql'],
      additionalProperties: false,
    },
  },
  {
    name: 'usf_bootstrap',
    description: 'Bounded semantic bootstrap from the live authority. With no contract: live-state digest, graph inventory, key-class census, and a contract index. With { contract: "<canonicalName or urn:usf: IRI>" }: the model->facet->obligation->contract->realisation trace for that contract (claims, non-claims, facets, realisations, obligations), each list bounded. Optional task string is echoed for context.',
    inputSchema: {
      type: 'object',
      properties: {
        contract: { type: 'string', description: 'Contract canonical-name slug or urn:usf: IRI to trace.' },
        task: { type: 'string' },
      },
      additionalProperties: false,
    },
  },
];

export async function callTool(name, args, ctx) {
  const { client, config } = ctx;
  if (name === 'usf_health') {
    return { ...describeConfig(config), triples: await client.size(), ok: true };
  }
  if (name === 'usf_query') {
    const sparql = args && args.sparql;
    const verdict = classifySparql(sparql);
    if (!verdict.readOnly) {
      const err = new Error(`refused: ${verdict.reason}`);
      err.userFacing = true;
      throw err;
    }
    if (verdict.form === 'CONSTRUCT' || verdict.form === 'DESCRIBE') {
      const full = await client.construct(sparql, 'text/turtle');
      const truncated = Buffer.byteLength(full, 'utf8') > MAX_TEXT_BYTES;
      return { form: verdict.form, truncated, turtle: truncated ? full.slice(0, MAX_TEXT_BYTES) : full };
    }
    if (verdict.form === 'ASK') {
      return { form: 'ASK', boolean: await client.ask(sparql) };
    }
    const rows = await client.select(cappedSelect(sparql));
    return {
      form: 'SELECT',
      truncated: rows.length > MAX_ROWS,
      rowCount: Math.min(rows.length, MAX_ROWS),
      bindings: rows.slice(0, MAX_ROWS),
    };
  }
  if (name === 'usf_bootstrap') {
    return bootstrapPacket(ctx, { contract: args && args.contract, task: args && args.task });
  }
  const err = new Error(`unknown tool ${name}`);
  err.userFacing = true;
  throw err;
}

export async function runMcpServer({ input = process.stdin, output = process.stdout } = {}) {
  const config = loadConfig();
  const redact = makeRedactor(config);
  const ctx = { client: createClient(config), config };
  const send = (msg) => output.write(redact(JSON.stringify(msg)) + '\n');

  const rl = createInterface({ input, crlfDelay: Infinity });
  for await (const line of rl) {
    const text = line.trim();
    if (!text) continue;
    let req;
    try {
      req = JSON.parse(text);
    } catch {
      continue; // ignore non-JSON noise on the transport
    }
    const { id, method, params } = req;
    const isNotification = id === undefined || id === null;
    try {
      if (method === 'initialize') {
        send({
          jsonrpc: '2.0',
          id,
          result: {
            protocolVersion: (params && params.protocolVersion) || PROTOCOL_VERSION,
            capabilities: { tools: {} },
            serverInfo: { name: 'usf', version: VERSION },
          },
        });
      } else if (method === 'ping') {
        send({ jsonrpc: '2.0', id, result: {} });
      } else if (method === 'tools/list') {
        send({ jsonrpc: '2.0', id, result: { tools: TOOLS } });
      } else if (method === 'tools/call') {
        try {
          const result = await callTool(params && params.name, params && params.arguments, ctx);
          send({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: redact(JSON.stringify(result, null, 2)) }] } });
        } catch (err) {
          // Report tool failures as tool results with isError (MCP convention),
          // not JSON-RPC protocol errors.
          send({ jsonrpc: '2.0', id, result: { isError: true, content: [{ type: 'text', text: redact(err.message || 'tool error') }] } });
        }
      } else if (method && method.startsWith('notifications/')) {
        // notifications carry no id and expect no response
      } else if (!isNotification) {
        send({ jsonrpc: '2.0', id, error: { code: -32601, message: `method not found: ${method}` } });
      }
    } catch (err) {
      if (!isNotification) send({ jsonrpc: '2.0', id, error: { code: -32603, message: redact(err.message || 'internal error') } });
    }
  }
}

// Direct launch: node src/mcp.js
if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  runMcpServer().catch((err) => {
    process.stderr.write(`usf-mcp fatal: ${err.message}\n`);
    process.exit(1);
  });
}
