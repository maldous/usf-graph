import assert from "node:assert/strict";
import test from "node:test";
import {
  graphqlParser,
  javascriptTypescriptParser,
  pythonParser,
  rdfParser,
  sourceSemanticParsers,
  sparqlParser,
} from "../src/parsers/source-semantic.mjs";
import { createParserRegistry } from "../src/parsers/registry.mjs";
import { buildRelationships } from "../src/relationships.mjs";

function parse(parser, syntaxKind, text, memberPath) {
  return parser.parse({
    member: { path: memberPath },
    syntaxKind,
    pathContext: "ordinary",
    text,
  });
}

function declarationsOf(parsed, kind) {
  return parsed.declarations
    .filter((entry) => entry.kind === kind)
    .map((entry) => entry.identifier);
}

function relationshipsOf(parsed, extractionMethod) {
  return parsed.relationships.filter((entry) => entry.extractionMethod === extractionMethod);
}

test("source semantic parser objects satisfy and deterministically order the registry contract", () => {
  const registry = createParserRegistry(sourceSemanticParsers);
  assert.deepEqual(
    registry.map((entry) => entry.id),
    [
      "babel-javascript-typescript",
      "graphql-ast",
      "n3-rdf",
      "python-stdlib-ast",
      "structural-sparql",
    ],
  );
  assert.ok(registry.every((entry) => entry.mode === "structural"));
});

test("Babel parsing recovers TypeScript declarations, imports, exports, calls, and executable commands only from AST nodes", () => {
  const parsed = parse(
    javascriptTypescriptParser,
    "javascript-typescript",
    String.raw`
    /** execSync('documented-only') and class Imaginary {} */
    const prose = "spawnSync('string-only')";
    import { execFileSync as execute } from 'node:child_process';
    import helper from './helper.mjs';
    export type Identifier = string;
    export interface Port { run(): void }
    export class Service extends BaseService {
      run(): void {
        execute('node', ['task.mjs']);
        helper();
      }
    }
    export { helper as publicHelper };
  `,
    "src/service.ts",
  );

  assert.equal(parsed.structuralCoverage, "complete");
  assert.deepEqual(declarationsOf(parsed, "type"), ["Identifier"]);
  assert.deepEqual(declarationsOf(parsed, "interface"), ["Port"]);
  assert.deepEqual(declarationsOf(parsed, "class"), ["Service"]);
  assert.deepEqual(declarationsOf(parsed, "method"), ["Service.run"]);
  assert.deepEqual(declarationsOf(parsed, "call"), ["execute", "helper"]);
  assert.ok(declarationsOf(parsed, "export").includes("publicHelper"));
  assert.deepEqual(
    relationshipsOf(parsed, "babel-import-declaration").map((entry) => [
      entry.target,
      entry.targetKind,
    ]),
    [
      ["./helper.mjs", "artifact"],
      ["node:child_process", "package"],
    ],
  );
  assert.deepEqual(
    relationshipsOf(parsed, "babel-executable-command-call").map((entry) => entry.target),
    ["node"],
  );
  assert.ok(
    !parsed.declarations.some((entry) =>
      /documented-only|Imaginary|string-only/.test(entry.identifier),
    ),
  );
  assert.ok(
    !parsed.relationships.some((entry) => /documented-only|string-only/.test(entry.target)),
  );
});

test("Babel parsing handles CommonJS, dynamic imports, destructuring, enums, and static shell templates", () => {
  const parsed = parse(
    javascriptTypescriptParser,
    "javascript-typescript",
    [
      "const { value: renamed, ...rest } = require('./values.cjs');",
      "enum State { Ready }",
      "async function load() { return import('./lazy.mjs'); }",
      "$`node static-task.mjs`;",
    ].join("\n"),
    "src/loader.ts",
  );
  assert.deepEqual(declarationsOf(parsed, "enum"), ["State"]);
  assert.ok(declarationsOf(parsed, "variable").includes("renamed"));
  assert.ok(declarationsOf(parsed, "variable").includes("rest"));
  assert.deepEqual(
    parsed.relationships
      .filter((entry) => entry.relationshipType === "imports")
      .map((entry) => entry.target),
    ["./lazy.mjs", "./values.cjs"],
  );
  assert.deepEqual(
    relationshipsOf(parsed, "babel-static-shell-template").map((entry) => entry.target),
    ["node static-task.mjs"],
  );
});

test("command attribution uses imported child-process bindings and reports dynamic targets without matching arbitrary exec methods", () => {
  const javascript = parse(
    javascriptTypescriptParser,
    "javascript-typescript",
    String.raw`
    function run(command) {
      database.exec('select value from records');
      execute(command);
    }
    import { execFileSync as execute } from 'node:child_process';
  `,
    "src/dynamic.ts",
  );
  assert.equal(javascript.structuralCoverage, "partial");
  assert.deepEqual(javascript.unsupportedStructures, ["dynamic-javascript-command-target:execute"]);
  assert.deepEqual(relationshipsOf(javascript, "babel-executable-command-call"), []);

  const python = parse(
    pythonParser,
    "python",
    String.raw`
def run(command):
    process.run(command)

import subprocess as process
`,
    "src/dynamic.py",
  );
  assert.equal(python.structuralCoverage, "partial");
  assert.deepEqual(python.unsupportedStructures, ["dynamic-python-command-target:process.run"]);
  assert.deepEqual(relationshipsOf(python, "python-ast-executable-command-call"), []);
});

test("Python stdlib AST parsing recovers declarations, imports, exports, annotations, calls, and subprocess commands without docstring matches", () => {
  const parsed = parse(
    pythonParser,
    "python",
    String.raw`
"""subprocess.run(['documented-only'])
class Imaginary: pass
"""
import subprocess as process
from pathlib import Path
from subprocess import check_call as execute

__all__ = ['Worker', 'run']
Identifier: TypeAlias = str

class Worker(BaseWorker):
    async def run(self):
        process.run(['python3', 'worker.py'])
        execute(['node', 'task.mjs'])
        Path('value')
`,
    "src/worker.py",
  );

  assert.equal(parsed.structuralCoverage, "complete");
  assert.deepEqual(declarationsOf(parsed, "class"), ["Worker"]);
  assert.deepEqual(declarationsOf(parsed, "async-function"), ["Worker.run"]);
  assert.deepEqual(declarationsOf(parsed, "type"), ["Identifier"]);
  assert.deepEqual(declarationsOf(parsed, "export"), ["run", "Worker"]);
  assert.deepEqual(
    relationshipsOf(parsed, "python-ast-import").map((entry) => entry.target),
    ["subprocess"],
  );
  assert.deepEqual(
    relationshipsOf(parsed, "python-ast-import-from").map((entry) => entry.target),
    ["pathlib", "subprocess"],
  );
  assert.deepEqual(
    relationshipsOf(parsed, "python-ast-executable-command-call").map((entry) => entry.target),
    ["node", "python3"],
  );
  assert.ok(
    !parsed.declarations.some((entry) => /Imaginary|documented-only/.test(entry.identifier)),
  );
  assert.ok(!parsed.relationships.some((entry) => /documented-only/.test(entry.target)));
});

test("Python relative imports resolve as artifacts including package initializers", () => {
  const parsed = parse(
    pythonParser,
    "python",
    "from .helpers import run\nfrom ..core import value\nfrom . import sibling\n",
    "packages/example/sub/module.py",
  );
  const imports = relationshipsOf(parsed, "python-ast-import-from");
  assert.deepEqual(imports.map((entry) => [entry.target, entry.targetKind]), [
    ["../core", "artifact"],
    ["./helpers", "artifact"],
    ["./sibling", "artifact"],
  ]);
  const members = [
    "packages/example/sub/module.py",
    "packages/example/sub/helpers.py",
    "packages/example/core/__init__.py",
    "packages/example/sub/sibling/__init__.py",
  ].map((path) => ({ path }));
  const relationships = buildRelationships(members, [{ path: "packages/example/sub/module.py", relationships: parsed.relationships }]).relationships
    .filter((entry) => entry.extractionMethod === "python-ast-import-from");
  assert.deepEqual(relationships.map((entry) => [entry.target, entry.resolved]), [
    ["packages/example/core/__init__.py", true],
    ["packages/example/sub/helpers.py", true],
    ["packages/example/sub/sibling/__init__.py", true],
  ]);
});

test("Python syntax outside the available stdlib AST is reported as partial, not lexically invented", () => {
  const parsed = parse(pythonParser, "python", "def broken(:\n    pass\n", "src/broken.py");
  assert.equal(parsed.structuralCoverage, "partial");
  assert.equal(parsed.declarations.length, 0);
  assert.ok(parsed.unsupportedStructures[0].startsWith("python-ast-parse-error:"));
});

test("N3 parsing recovers TriG graphs, semantic triples, RDF declarations, and simple and compound SHACL paths", () => {
  const parsed = parse(
    rdfParser,
    "rdf-trig",
    String.raw`
    @prefix ex: <urn:example:>.
    @prefix sh: <http://www.w3.org/ns/shacl#>.
    @prefix owl: <http://www.w3.org/2002/07/owl#>.
    ex:authority {
      ex:Entity a owl:Class.
      ex:Shape a sh:NodeShape;
        sh:path (ex:parent ex:name).
      ex:Alternative a sh:PropertyShape;
        sh:path [ sh:alternativePath (ex:title ex:label) ].
    }
  `,
    "graph/shapes.trig",
  );

  assert.equal(parsed.structuralCoverage, "complete");
  assert.deepEqual(declarationsOf(parsed, "semantic-graph"), ["urn:example:authority"]);
  assert.deepEqual(declarationsOf(parsed, "owl-class"), ["urn:example:Entity"]);
  assert.deepEqual(declarationsOf(parsed, "shacl-node-shape"), ["urn:example:Shape"]);
  assert.equal(declarationsOf(parsed, "semantic-triple").length, 14);
  const paths = parsed.declarations
    .filter((entry) => entry.kind === "shape-path")
    .map((entry) => entry.attributes.path);
  assert.deepEqual(paths, [
    "(urn:example:title|urn:example:label)",
    "(urn:example:parent/urn:example:name)",
  ]);
  assert.deepEqual(
    relationshipsOf(parsed, "n3-shacl-path").map((entry) => entry.target),
    ["(urn:example:parent/urn:example:name)", "(urn:example:title|urn:example:label)"],
  );
});

test("N3 parsing reports invalid RDF as partial without regex-derived triples", () => {
  const parsed = parse(
    rdfParser,
    "rdf-turtle",
    "@prefix ex: <urn:example:>. ex:a ex:p .",
    "graph/broken.ttl",
  );
  assert.equal(parsed.structuralCoverage, "partial");
  assert.equal(parsed.declarations.length, 0);
  assert.ok(parsed.unsupportedStructures[0].startsWith("rdf-parse-error:"));
});

test("structural SPARQL parsing recovers operations, prefixes, graphs, services, and ignores comments and strings", () => {
  const parsed = parse(
    sparqlParser,
    "sparql",
    String.raw`
    # GRAPH <urn:comment-only> SERVICE <urn:comment-service>
    PREFIX ex: <urn:example:>
    SELECT * FROM NAMED <urn:source> WHERE {
      GRAPH ex:authority { ?s ?p "GRAPH <urn:string-only>" }
      SERVICE <urn:service> { ?s ?p ?o }
      FILTER (?score >= 1 && ?score < 10)
    };
    CREATE SILENT GRAPH <urn:created>
  `,
    "graph/query.sparql",
  );

  assert.equal(parsed.structuralCoverage, "complete");
  assert.deepEqual(declarationsOf(parsed, "sparql-prefix"), ["ex:"]);
  assert.deepEqual(declarationsOf(parsed, "sparql-operation"), ["create", "select"]);
  assert.deepEqual(declarationsOf(parsed, "semantic-graph"), ["urn:created"]);
  assert.deepEqual(
    relationshipsOf(parsed, "sparql-graph-clause").map((entry) => entry.target),
    ["ex:authority", "urn:created", "urn:source"],
  );
  assert.deepEqual(
    relationshipsOf(parsed, "sparql-service-clause").map((entry) => entry.target),
    ["urn:service"],
  );
  assert.ok(!parsed.relationships.some((entry) => /comment|string-only/.test(entry.target)));
});

test("dynamic SPARQL graph and service targets remain explicit unsupported structures", () => {
  const parsed = parse(
    sparqlParser,
    "sparql",
    "SELECT * WHERE { GRAPH ?g { ?s ?p ?o } SERVICE ?endpoint {} }",
    "graph/dynamic.rq",
  );
  assert.equal(parsed.structuralCoverage, "partial");
  assert.deepEqual(parsed.unsupportedStructures, [
    "dynamic-sparql-graph-variable",
    "dynamic-sparql-service-target",
  ]);
});

test("GraphQL AST parsing recovers schema types and executable selection calls without description false positives", () => {
  const parsed = parse(
    graphqlParser,
    "graphql",
    String.raw`
    """Fake type Ghost { documentedOnly: String }"""
    interface Node { id: ID! }
    type User implements Node { id: ID!, name: String! }
    type Query { user(id: ID!): User }
    fragment UserFields on User { id name }
    query GetUser { user(id: "GRAPH <urn:not-a-graph>") { ...UserFields } }
  `,
    "schema/service.graphql",
  );

  assert.equal(parsed.structuralCoverage, "complete");
  assert.deepEqual(declarationsOf(parsed, "graphql-interface"), ["Node"]);
  assert.deepEqual(declarationsOf(parsed, "graphql-object-type"), ["Query", "User"]);
  assert.deepEqual(declarationsOf(parsed, "graphql-operation"), ["query:GetUser"]);
  assert.deepEqual(declarationsOf(parsed, "graphql-fragment"), ["UserFields"]);
  assert.deepEqual(
    relationshipsOf(parsed, "graphql-executable-field").map((entry) => entry.target),
    ["id", "name", "user"],
  );
  assert.ok(!parsed.declarations.some((entry) => /Ghost|documentedOnly/.test(entry.identifier)));
  assert.ok(
    !parsed.relationships.some((entry) => /Ghost|documentedOnly|not-a-graph/.test(entry.target)),
  );
});

test("all source semantic parsers return byte-for-byte stable structures for repeated input", () => {
  const cases = [
    [
      javascriptTypescriptParser,
      "javascript-typescript",
      "export function run() { return helper(); }",
      "src/a.mjs",
    ],
    [pythonParser, "python", "def run():\n    return helper()\n", "src/a.py"],
    [rdfParser, "rdf-turtle", "@prefix ex:<urn:example:>. ex:a ex:p ex:b.", "graph/a.ttl"],
    [sparqlParser, "sparql", "ASK FROM <urn:graph> { ?s ?p ?o }", "graph/a.rq"],
    [graphqlParser, "graphql", "query Q { health }", "schema/a.graphql"],
  ];
  for (const [parser, syntaxKind, text, memberPath] of cases) {
    assert.deepEqual(
      parse(parser, syntaxKind, text, memberPath),
      parse(parser, syntaxKind, text, memberPath),
    );
  }
});
