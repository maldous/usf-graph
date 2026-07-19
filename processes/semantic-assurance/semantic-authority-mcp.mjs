#!/usr/bin/env node
// USF bounded Stardog and materialisation MCP server (stdio JSON-RPC 2.0).
//
// Exposes bounded Stardog interrogation and authority-bound materialisation to
// agents so they query live semantic state instead of reconstructing meaning
// from authored graph files or retained lineage data.
// Every Stardog interaction goes through the compiler's single SDK boundary
// (stardog.js). Mutations are rejected by classifySparql. Credentials never
// reach stdout/stderr: every outbound line is passed through a redactor built
// from the live secrets.
//
// Tool names use underscores because downstream model tool-callers restrict
// names to [A-Za-z0-9_-]. Semantic mutation is never accepted through the MCP
// transport; coordinators publish registered source through the compiler's
// validated transaction.

import { createInterface } from 'node:readline';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { loadConfig, describeConfig } from '../../configuration/semantic-assurance/stardog-connection.mjs';
import { createClient } from '../../provider-bindings/stardog/stardog-read-gateway.mjs';
import { classifySparql } from './sparql-guard.mjs';
import { bootstrapPacket } from './semantic-bootstrap-packet.mjs';
import {
  applyLayoutPlan,
  createLayoutPlan,
  describeArtifact,
  layoutContext,
  planWork,
  projectContract,
  refuseLifecycleMutation,
  validateLayoutPlan,
  verifyArtifact,
} from './repository-materialisation-gateway.mjs';

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

const pkgPath = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'package.json');
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
    description: 'Bounded evidence-first semantic bootstrap from live authority. A focused packet traces model -> evidence -> proof -> contract -> realisation -> validation, preserves category visibility, and stays within 8 KiB, 50 semantic items, and traversal depth three. Continuations are deterministic and authority-digest-bound.',
    inputSchema: {
      type: 'object',
      properties: {
        contract: { type: 'string', description: 'Contract canonical-name slug or urn:usf: IRI to trace.' },
        task: { type: 'string' },
        continuation: { type: 'string', description: 'Digest-bound continuation token returned by an earlier packet.' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'usf_layout_context',
    description: 'usf.layout.context: retrieve the active authority digest, proof/decision state, path roles, storage and representation rules for repository materialisation.',
    inputSchema: { type: 'object', properties: { contract: { type: 'string' } }, additionalProperties: false },
  },
  {
    name: 'usf_layout_plan',
    description: 'usf.layout.plan: create a bounded JCS-canonical, authority-bound materialisation plan from explicitly requested operations.',
    inputSchema: { type: 'object', properties: { contract: { type: 'string' }, operations: { type: 'array', minItems: 1, maxItems: 256, items: { type: 'object' } } }, required: ['operations'], additionalProperties: false },
  },
  {
    name: 'usf_layout_validate',
    description: 'usf.layout.validate: validate a materialisation plan against the current live digest, active proof, path roles and format rules.',
    inputSchema: { type: 'object', properties: { plan: { type: 'object' } }, required: ['plan'], additionalProperties: false },
  },
  {
    name: 'usf_materialise',
    description: 'usf.materialise: dry-run a validated materialisation plan; apply mode is coordinator-only and digest-checks every source and payload.',
    inputSchema: { type: 'object', properties: { plan: { type: 'object' }, apply: { type: 'boolean', default: false } }, required: ['plan'], additionalProperties: false },
  },
  {
    name: 'usf_artifact_describe',
    description: 'usf.artifact.describe: retrieve the authoritative Stardog descriptor for one immutable external payload digest.',
    inputSchema: { type: 'object', properties: { digest: { type: 'string', pattern: '^sha256:[0-9a-f]{64}$' } }, required: ['digest'], additionalProperties: false },
  },
  {
    name: 'usf_artifact_verify',
    description: 'usf.artifact.verify: verify bytes in the configured operator-local content-addressed store against the Stardog descriptor.',
    inputSchema: { type: 'object', properties: { digest: { type: 'string', pattern: '^sha256:[0-9a-f]{64}$' } }, required: ['digest'], additionalProperties: false },
  },
  {
    name: 'usf_contract_project',
    description: 'usf.contract.project: produce the bounded digest-bound AI-agent packet for realisation or validation, including claims, nonclaims, authorisations, obligations and stop conditions.',
    inputSchema: { type: 'object', properties: { contract: { type: 'string' }, objective: { type: 'string', maxLength: 1024 } }, additionalProperties: false },
  },
  {
    name: 'usf_work_plan',
    description: 'usf.work.plan: project current semantic gaps suitable for work tracking. The projection is not authority and creates no ticket.',
    inputSchema: { type: 'object', properties: { contract: { type: 'string' } }, additionalProperties: false },
  },
  ...['evidence_admit', 'proof_evaluate', 'validation_record'].map((name) => ({
    name: `usf_${name}`,
    description: `usf.${name.replace('_', '.')}: coordinator-only lifecycle mutation boundary. Direct MCP mutation is refused; registered authored source must be published by the compiler transaction.`,
    inputSchema: { type: 'object', properties: { authorityDigest: { type: 'string', pattern: '^sha256:[0-9a-f]{64}$' }, semanticResource: { type: 'string' } }, required: ['authorityDigest', 'semanticResource'], additionalProperties: false },
  })),
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
    return bootstrapPacket(ctx, { contract: args && args.contract, task: args && args.task, continuation: args && args.continuation });
  }
  if (name === 'usf_layout_context') return layoutContext(ctx, args);
  if (name === 'usf_layout_plan') return createLayoutPlan(ctx, args);
  if (name === 'usf_layout_validate') return validateLayoutPlan(ctx, args && args.plan);
  if (name === 'usf_materialise') return applyLayoutPlan(ctx, args);
  if (name === 'usf_artifact_describe') return describeArtifact(ctx, args);
  if (name === 'usf_artifact_verify') return verifyArtifact(ctx, args);
  if (name === 'usf_contract_project') return projectContract(ctx, args);
  if (name === 'usf_work_plan') return planWork(ctx, args);
  if (['usf_evidence_admit', 'usf_proof_evaluate', 'usf_validation_record'].includes(name)) return refuseLifecycleMutation(name.replaceAll('_', '.'));
  const err = new Error(`unknown tool ${name}`);
  err.userFacing = true;
  throw err;
}

export async function runMcpServer({ input = process.stdin, output = process.stdout } = {}) {
  const config = loadConfig();
  const redact = makeRedactor(config);
  const ctx = {
    client: createClient(config),
    config,
    casRoot: process.env.USF_CAS_ROOT || null,
    coordinator: process.env.USF_COORDINATOR_MODE === 'apply',
    repositoryRoot: resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..'),
  };
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
      } else if (method === 'resources/list') {
        // Tools-only server; answer the standard discovery probes (Codex sends
        // them regardless of advertised capabilities) instead of erroring.
        send({ jsonrpc: '2.0', id, result: { resources: [] } });
      } else if (method === 'resources/templates/list') {
        send({ jsonrpc: '2.0', id, result: { resourceTemplates: [] } });
      } else if (method === 'prompts/list') {
        send({ jsonrpc: '2.0', id, result: { prompts: [] } });
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
