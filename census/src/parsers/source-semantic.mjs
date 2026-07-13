import { spawnSync } from "node:child_process";
import path from "node:path";
import { parse as parseJavaScript } from "@babel/parser";
import { Kind, parse as parseGraphql } from "graphql";
import { Parser as N3Parser } from "n3";
import { confidence, declaration, relationship, result } from "./shared.mjs";

const RDF = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";
const RDFS = "http://www.w3.org/2000/01/rdf-schema#";
const OWL = "http://www.w3.org/2002/07/owl#";
const SH = "http://www.w3.org/ns/shacl#";

function compareRecord(left, right) {
  return JSON.stringify(left).localeCompare(JSON.stringify(right));
}

function stableRecords(records) {
  return [...new Map(records.map((record) => [JSON.stringify(record), record])).values()].sort(
    compareRecord,
  );
}

function complete(declarations, relationships, options = {}) {
  return result({
    declarations: stableRecords(declarations),
    relationships: stableRecords(relationships),
    ...options,
  });
}

function parseFailure(kind, error) {
  const message = String(error?.message ?? error)
    .split("\n")[0]
    .slice(0, 240);
  return complete([], [], {
    structuralCoverage: "partial",
    unsupportedStructures: [`${kind}-parse-error:${message}`],
    confidence: confidence.ambiguous,
  });
}

function lineOf(node) {
  return node?.loc?.start?.line ?? null;
}

function moduleTargetKind(specifier) {
  return /^(?:\.{1,2}\/|\/)/.test(specifier) ? "artifact" : "package";
}

function patternNames(pattern, names = []) {
  if (!pattern) return names;
  if (pattern.type === "Identifier") names.push(pattern.name);
  else if (pattern.type === "RestElement") patternNames(pattern.argument, names);
  else if (pattern.type === "AssignmentPattern") patternNames(pattern.left, names);
  else if (pattern.type === "ObjectPattern")
    pattern.properties.forEach((property) =>
      patternNames(property.value ?? property.argument, names),
    );
  else if (pattern.type === "ArrayPattern")
    pattern.elements.forEach((element) => patternNames(element, names));
  return names;
}

function memberName(node) {
  if (!node) return null;
  if (node.type === "Identifier" || node.type === "PrivateName")
    return node.name ?? memberName(node.id);
  if (node.type === "ThisExpression") return "this";
  if (node.type === "Super") return "super";
  if (node.type === "Import") return "import";
  if (node.type === "StringLiteral" || node.type === "NumericLiteral") return String(node.value);
  if (node.type === "MemberExpression" || node.type === "OptionalMemberExpression") {
    const object = memberName(node.object);
    const property = memberName(node.property);
    return object && property ? `${object}.${property}` : (object ?? property);
  }
  if (
    [
      "TSInstantiationExpression",
      "TSAsExpression",
      "TSTypeAssertion",
      "TypeCastExpression",
      "ChainExpression",
    ].includes(node.type)
  )
    return memberName(node.expression);
  return null;
}

function staticJavaScriptValue(node) {
  if (!node) return null;
  if (node.type === "StringLiteral" || node.type === "NumericLiteral") return String(node.value);
  if (node.type === "TemplateLiteral" && node.expressions.length === 0)
    return node.quasis.map((quasi) => quasi.value.cooked ?? quasi.value.raw).join("");
  if (node.type === "ArrayExpression") return staticJavaScriptValue(node.elements[0]);
  if (node.type === "ObjectExpression") {
    const command = node.properties.find(
      (property) => memberName(property.key) === "cmd" || memberName(property.key) === "command",
    );
    return staticJavaScriptValue(command?.value);
  }
  return null;
}

function exportedNames(node) {
  if (!node) return [];
  if (node.id?.name) return [node.id.name];
  if (node.type === "VariableDeclaration")
    return node.declarations.flatMap((entry) => patternNames(entry.id));
  return [];
}

function javaScriptPlugins(memberPath, text) {
  const extension = path.posix.extname(memberPath).toLowerCase();
  const typed = [".ts", ".tsx", ".mts", ".cts"].includes(extension);
  const plugins = ["decorators-legacy", "importAttributes"];
  if (typed) plugins.push("typescript");
  else if (/^\s*(?:\/\/|\/\*)\s*@flow\b/m.test(text)) plugins.push("flow");
  if ([".jsx", ".tsx"].includes(extension) || /<[A-Za-z][A-Za-z0-9.:_-]*(?:\s|\/?>)/.test(text))
    plugins.push("jsx");
  return plugins;
}

function parseJavaScriptTypescript({ member, text }) {
  let ast;
  try {
    ast = parseJavaScript(text, {
      sourceType: "unambiguous",
      sourceFilename: member.path,
      plugins: javaScriptPlugins(member.path, text),
      errorRecovery: true,
    });
  } catch (error) {
    return parseFailure("javascript-typescript", error);
  }

  const declarations = [];
  const relationships = [];
  const unsupported = [];
  for (const match of text.matchAll(/^\s*\/\/\/\s*<reference\s+(types|path)=["']([^"']+)["']\s*\/>/gm)) {
    declarations.push(declaration('typescript-reference-directive', match[2], { referenceKind: match[1] }));
    relationships.push(relationship('references', match[2], match[1] === 'path' ? 'artifact' : 'package', 'babel-typescript-reference-directive'));
  }
  const commandMethods = new Set([
    "exec",
    "execSync",
    "execFile",
    "execFileSync",
    "fork",
    "spawn",
    "spawnSync",
    "execa",
    "execaSync",
  ]);
  const commandAliases = new Set();
  const commandNamespaces = new Set(["child_process"]);

  function collectCommandBindings(node) {
    if (!node || typeof node !== "object") return;
    if (node.type === "ImportDeclaration") {
      const source = node.source.value;
      if (/^(?:node:)?child_process$/.test(source)) {
        for (const specifier of node.specifiers) {
          if (
            specifier.type === "ImportNamespaceSpecifier" ||
            specifier.type === "ImportDefaultSpecifier"
          )
            commandNamespaces.add(specifier.local.name);
          else if (commandMethods.has(memberName(specifier.imported)))
            commandAliases.add(specifier.local.name);
        }
      } else if (source === "execa") {
        for (const specifier of node.specifiers) {
          if (specifier.type === "ImportNamespaceSpecifier")
            commandNamespaces.add(specifier.local.name);
          else commandAliases.add(specifier.local.name);
        }
      }
    }
    if (
      node.type === "VariableDeclarator" &&
      node.init?.type === "CallExpression" &&
      memberName(node.init.callee) === "require"
    ) {
      const source = staticJavaScriptValue(node.init.arguments?.[0]);
      if (/^(?:node:)?child_process$/.test(source ?? "")) {
        if (node.id.type === "Identifier") commandNamespaces.add(node.id.name);
        else if (node.id.type === "ObjectPattern")
          for (const property of node.id.properties) {
            if (commandMethods.has(memberName(property.key))) {
              for (const name of patternNames(property.value ?? property.argument))
                commandAliases.add(name);
            }
          }
      }
    }
    for (const [key, value] of Object.entries(node)) {
      if (["loc", "start", "end", "extra", "errors", "comments", "tokens"].includes(key)) continue;
      if (Array.isArray(value)) value.forEach(collectCommandBindings);
      else if (value && typeof value === "object" && typeof value.type === "string")
        collectCommandBindings(value);
    }
  }
  collectCommandBindings(ast.program);

  const addDeclaration = (kind, identifier, node, attributes = {}) => {
    if (identifier)
      declarations.push(declaration(kind, identifier, { line: lineOf(node), ...attributes }));
  };
  const addModule = (type, specifier, method, node) => {
    relationships.push(
      relationship(
        type,
        specifier,
        moduleTargetKind(specifier),
        method,
        "structurally-proven",
        confidence.structural,
        { line: lineOf(node) },
      ),
    );
  };

  function visit(node, context = {}) {
    if (!node || typeof node !== "object") return;
    const nextContext = { ...context };
    switch (node.type) {
      case "ImportDeclaration": {
        addModule("imports", node.source.value, "babel-import-declaration", node);
        for (const specifier of node.specifiers) {
          addDeclaration("import-binding", specifier.local.name, specifier, {
            source: node.source.value,
          });
        }
        break;
      }
      case "TSImportEqualsDeclaration": {
        const source = node.moduleReference?.expression?.value;
        addDeclaration("import-binding", node.id.name, node, source ? { source } : {});
        if (source) addModule("imports", source, "babel-typescript-import-equals", node);
        break;
      }
      case "FunctionDeclaration":
      case "TSDeclareFunction":
        addDeclaration(node.async ? "async-function" : "function", node.id?.name, node);
        nextContext.functionName = node.id?.name ?? context.functionName;
        break;
      case "ClassDeclaration":
        addDeclaration("class", node.id?.name, node);
        nextContext.className = node.id?.name ?? context.className;
        if (node.superClass)
          relationships.push(
            relationship(
              "depends-on",
              memberName(node.superClass) ?? "<computed>",
              "semantic-entity",
              "babel-class-extends",
            ),
          );
        break;
      case "ClassMethod":
      case "ClassPrivateMethod":
      case "ObjectMethod": {
        const name = memberName(node.key) ?? "<computed>";
        addDeclaration("method", context.className ? `${context.className}.${name}` : name, node, {
          async: Boolean(node.async),
          static: Boolean(node.static),
        });
        nextContext.functionName = name;
        break;
      }
      case "VariableDeclaration":
        for (const item of node.declarations)
          for (const name of patternNames(item.id))
            addDeclaration("variable", name, item, { declarationKind: node.kind });
        break;
      case "TSTypeAliasDeclaration":
        addDeclaration("type", node.id.name, node);
        break;
      case "TSInterfaceDeclaration":
        addDeclaration("interface", node.id.name, node);
        break;
      case "TSEnumDeclaration":
        addDeclaration("enum", node.id.name, node);
        break;
      case "TSModuleDeclaration":
        addDeclaration("namespace", memberName(node.id), node);
        break;
      case "ExportNamedDeclaration":
      case "ExportDefaultDeclaration":
      case "ExportAllDeclaration": {
        const names =
          node.type === "ExportDefaultDeclaration"
            ? exportedNames(node.declaration).length
              ? exportedNames(node.declaration)
              : ["default"]
            : [
                ...exportedNames(node.declaration),
                ...(node.specifiers ?? [])
                  .map((specifier) => memberName(specifier.exported))
                  .filter(Boolean),
              ];
        for (const name of names) {
          addDeclaration("export", name, node, { source: node.source?.value ?? null });
          relationships.push(
            relationship(
              "exports",
              name,
              "semantic-entity",
              "babel-export-declaration",
              "structurally-proven",
              confidence.structural,
              { line: lineOf(node) },
            ),
          );
        }
        if (node.source?.value)
          addModule("exports", node.source.value, "babel-re-export-source", node);
        break;
      }
      case "CallExpression":
      case "OptionalCallExpression":
      case "NewExpression": {
        const callee = memberName(node.callee) ?? "<computed-call>";
        addDeclaration(node.type === "NewExpression" ? "constructor-call" : "call", callee, node, {
          executableContext: true,
          function: context.functionName ?? null,
        });
        const lastName = callee.split(".").at(-1);
        const isRequire = callee === "require";
        const isDynamicImport = callee === "import";
        const staticTarget = staticJavaScriptValue(node.arguments?.[0]);
        if (staticTarget && isRequire)
          addModule("imports", staticTarget, "babel-commonjs-require", node);
        if (staticTarget && isDynamicImport)
          addModule("imports", staticTarget, "babel-dynamic-import", node);
        const [namespace] = callee.split(".");
        const commandCall =
          commandAliases.has(callee) ||
          (commandNamespaces.has(namespace) && commandMethods.has(lastName)) ||
          /^(?:Bun\.spawn|Bun\.spawnSync|Deno\.Command)$/.test(callee);
        if (staticTarget && commandCall)
          relationships.push(
            relationship(
              "invokes",
              staticTarget,
              "command",
              "babel-executable-command-call",
              "structurally-proven",
              confidence.structural,
              { callee, line: lineOf(node), executableContext: true },
            ),
          );
        else if (commandCall) unsupported.push(`dynamic-javascript-command-target:${callee}`);
        break;
      }
      case "ImportExpression": {
        const staticTarget = staticJavaScriptValue(node.source);
        addDeclaration("call", "import", node, {
          executableContext: true,
          function: context.functionName ?? null,
        });
        if (staticTarget) addModule("imports", staticTarget, "babel-dynamic-import", node);
        break;
      }
      case "TaggedTemplateExpression": {
        const callee = memberName(node.tag) ?? "<computed-tag>";
        addDeclaration("tagged-call", callee, node, { executableContext: true });
        if ((callee === "$" || callee.endsWith(".$")) && node.quasi.expressions.length === 0) {
          const command = staticJavaScriptValue(node.quasi);
          if (command)
            relationships.push(
              relationship("invokes", command, "command", "babel-static-shell-template"),
            );
        }
        break;
      }
      default:
        break;
    }
    for (const [key, value] of Object.entries(node)) {
      if (["loc", "start", "end", "extra", "errors", "comments", "tokens"].includes(key)) continue;
      if (Array.isArray(value)) value.forEach((entry) => visit(entry, nextContext));
      else if (value && typeof value === "object" && typeof value.type === "string")
        visit(value, nextContext);
    }
  }
  visit(ast.program);
  const parseErrors = ast.errors ?? [];
  return complete(declarations, relationships, {
    structuralCoverage: parseErrors.length || unsupported.length ? "partial" : "complete",
    unsupportedStructures: [
      ...parseErrors.map(
        (error) => `babel-recovered-error:${String(error.message).split("\n")[0].slice(0, 200)}`,
      ),
      ...unsupported,
    ],
    confidence:
      parseErrors.length || unsupported.length ? confidence.bounded : confidence.structural,
  });
}

const PYTHON_AST_PROGRAM = String.raw`
import ast, json, sys

source = sys.stdin.read()
tree = ast.parse(source, filename='<census>', type_comments=True)
declarations = []
relationships = []
unsupported = []
command_aliases = {'subprocess.run', 'subprocess.call', 'subprocess.check_call', 'subprocess.check_output', 'subprocess.Popen', 'os.system', 'os.popen'}

def add_decl(kind, identifier, node, **attributes):
    if identifier:
        declarations.append({'kind': kind, 'identifier': str(identifier), 'attributes': {'line': getattr(node, 'lineno', None), **attributes}})

def add_rel(kind, target, target_kind, method, node, **attributes):
    relationships.append({'relationshipType': kind, 'target': str(target), 'targetKind': target_kind, 'extractionMethod': method, 'attributes': {'line': getattr(node, 'lineno', None), **attributes}})

def dotted(node):
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute):
        owner = dotted(node.value)
        return (owner + '.' if owner else '') + node.attr
    return None

def static_value(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int, float)): return str(node.value)
    if isinstance(node, (ast.List, ast.Tuple)) and node.elts: return static_value(node.elts[0])
    return None

class Visitor(ast.NodeVisitor):
    def __init__(self): self.scope = []
    def visit_Import(self, node):
        for item in node.names:
            add_decl('import-binding', item.asname or item.name.split('.')[0], node, source=item.name)
            add_rel('imports', item.name, 'package', 'python-ast-import', node)
    def visit_ImportFrom(self, node):
        module = '.' * node.level + (node.module or '')
        if node.level > 0:
            if node.module: add_rel('imports', module, 'artifact', 'python-ast-import-from', node, relativeLevel=node.level, module=node.module)
            else:
                for item in node.names: add_rel('imports', '.' * node.level + item.name, 'artifact', 'python-ast-import-from', node, relativeLevel=node.level, module=item.name)
        elif module: add_rel('imports', module, 'package', 'python-ast-import-from', node, relativeLevel=0, module=node.module)
        for item in node.names:
            local = item.asname or item.name
            add_decl('import-binding', local, node, source=module, imported=item.name)
    def visit_FunctionDef(self, node):
        add_decl('function', '.'.join(self.scope + [node.name]), node, asyncFunction=False)
        self.scope.append(node.name); self.generic_visit(node); self.scope.pop()
    def visit_AsyncFunctionDef(self, node):
        add_decl('async-function', '.'.join(self.scope + [node.name]), node, asyncFunction=True)
        self.scope.append(node.name); self.generic_visit(node); self.scope.pop()
    def visit_ClassDef(self, node):
        name = '.'.join(self.scope + [node.name])
        add_decl('class', name, node)
        for base in node.bases:
            target = dotted(base)
            if target: add_rel('depends-on', target, 'semantic-entity', 'python-ast-class-base', node)
        self.scope.append(node.name); self.generic_visit(node); self.scope.pop()
    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, (ast.Name, ast.Tuple, ast.List)):
                for name in [entry.id for entry in ast.walk(target) if isinstance(entry, ast.Name)]: add_decl('variable', name, node)
        if any(isinstance(target, ast.Name) and target.id == '__all__' for target in node.targets):
            if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                for item in node.value.elts:
                    value = static_value(item)
                    if value: add_decl('export', value, item); add_rel('exports', value, 'semantic-entity', 'python-ast-all', item)
        self.generic_visit(node)
    def visit_AnnAssign(self, node):
        name = dotted(node.target)
        annotation = ast.unparse(node.annotation)
        add_decl('type' if annotation.endswith('TypeAlias') else 'annotated-variable', name, node, annotation=annotation)
        self.generic_visit(node)
    def visit_Call(self, node):
        callee = dotted(node.func) or '<computed-call>'
        add_decl('call', callee, node, executableContext=True, scope='.'.join(self.scope) or None)
        target = static_value(node.args[0]) if node.args else None
        if target is None:
            target = next((static_value(item.value) for item in node.keywords if item.arg in ('args', 'command', 'cmd')), None)
        if target and callee in command_aliases:
            add_rel('invokes', target, 'command', 'python-ast-executable-command-call', node, callee=callee, executableContext=True)
        elif callee in command_aliases:
            unsupported.append('dynamic-python-command-target:' + callee)
        self.generic_visit(node)

for imported in ast.walk(tree):
    if isinstance(imported, ast.Import):
        for item in imported.names:
            if item.name in ('subprocess', 'os') and item.asname:
                for name in list(command_aliases):
                    if name.startswith(item.name + '.'): command_aliases.add(item.asname + name[len(item.name):])
    elif isinstance(imported, ast.ImportFrom):
        for item in imported.names:
            absolute = ((imported.module + '.') if imported.module else '') + item.name
            if absolute in command_aliases: command_aliases.add(item.asname or item.name)

Visitor().visit(tree)
print(json.dumps({'declarations': declarations, 'relationships': relationships, 'unsupported': unsupported}, sort_keys=True, separators=(',', ':')))
`;

function pythonRelativeTarget(specifier, level) {
  const module = specifier.slice(level).replaceAll('.', '/');
  const prefix = level === 1 ? './' : '../'.repeat(level - 1);
  return `${prefix}${module}`;
}

function parsePython({ text }) {
  const execution = spawnSync("python3", ["-I", "-c", PYTHON_AST_PROGRAM], {
    input: text,
    encoding: "utf8",
    env: { ...process.env, LC_ALL: "C.UTF-8", PYTHONHASHSEED: "0" },
    maxBuffer: 32 * 1024 * 1024,
    timeout: 30_000,
  });
  if (execution.error) return parseFailure("python-ast", execution.error);
  if (execution.status !== 0)
    return parseFailure(
      "python-ast",
      execution.stderr.trim() || `python exited ${execution.status}`,
    );
  try {
    const parsed = JSON.parse(execution.stdout);
    const relationships = parsed.relationships.map((entry) =>
      relationship(
        entry.relationshipType,
        entry.extractionMethod === 'python-ast-import-from' && entry.attributes?.relativeLevel > 0
          ? pythonRelativeTarget(entry.target, entry.attributes.relativeLevel)
          : entry.target,
        entry.extractionMethod === 'python-ast-import-from' && entry.attributes?.relativeLevel > 0 ? 'artifact' : entry.targetKind,
        entry.extractionMethod,
        "structurally-proven",
        confidence.structural,
        entry.attributes,
      ),
    );
    return complete(parsed.declarations, relationships, {
      structuralCoverage: parsed.unsupported.length ? "partial" : "complete",
      unsupportedStructures: parsed.unsupported,
      confidence: parsed.unsupported.length ? confidence.bounded : confidence.structural,
    });
  } catch (error) {
    return parseFailure("python-ast-output", error);
  }
}

function rdfTerm(term) {
  if (!term) return null;
  if (term.termType === "NamedNode") return term.value;
  if (term.termType === "BlankNode") return `_:${term.value}`;
  if (term.termType === "DefaultGraph") return null;
  if (term.termType === "Variable") return `?${term.value}`;
  if (term.termType === "Literal") {
    const suffix = term.language
      ? `@${term.language}`
      : term.datatype?.value
        ? `^^${term.datatype.value}`
        : "";
    return `${JSON.stringify(term.value)}${suffix}`;
  }
  if (term.termType === "Quad")
    return `<<${rdfTerm(term.subject)} ${rdfTerm(term.predicate)} ${rdfTerm(term.object)}>>`;
  return String(term.value ?? term.id ?? term);
}

function quadKey(term) {
  return `${term.termType}\0${term.value ?? rdfTerm(term)}`;
}

function parseRdf({ syntaxKind, text }) {
  let quads;
  try {
    quads = new N3Parser({ format: syntaxKind === "rdf-trig" ? "TriG" : "Turtle" }).parse(text);
  } catch (error) {
    return parseFailure("rdf", error);
  }
  const declarations = [];
  const relationships = [];
  const unsupported = [];
  const bySubject = new Map();
  for (const quad of quads) {
    const key = `${quadKey(quad.graph)}\0${quadKey(quad.subject)}`;
    if (!bySubject.has(key)) bySubject.set(key, []);
    bySubject.get(key).push(quad);
  }

  function subjectQuads(term, graph) {
    return bySubject.get(`${quadKey(graph)}\0${quadKey(term)}`) ?? [];
  }
  function objectFor(term, graph, predicate) {
    return subjectQuads(term, graph).find((quad) => quad.predicate.value === predicate)?.object;
  }
  function rdfList(head, graph, seen) {
    const values = [];
    let cursor = head;
    while (cursor?.value !== `${RDF}nil`) {
      const key = quadKey(cursor);
      if (seen.has(key)) return null;
      seen.add(key);
      const first = objectFor(cursor, graph, `${RDF}first`);
      const rest = objectFor(cursor, graph, `${RDF}rest`);
      if (!first || !rest) return null;
      values.push(first);
      cursor = rest;
    }
    return values;
  }
  function shapePath(term, graph, seen = new Set()) {
    if (term.termType === "NamedNode") return term.value;
    if (term.termType !== "BlankNode") return rdfTerm(term);
    const key = quadKey(term);
    if (seen.has(key)) return null;
    const next = new Set(seen).add(key);
    const unary = [
      [`${SH}inversePath`, "^"],
      [`${SH}zeroOrMorePath`, "*"],
      [`${SH}oneOrMorePath`, "+"],
      [`${SH}zeroOrOnePath`, "?"],
    ];
    for (const [predicate, operator] of unary) {
      const value = objectFor(term, graph, predicate);
      if (value) {
        const nested = shapePath(value, graph, next);
        return nested ? `${operator}(${nested})` : null;
      }
    }
    const alternative = objectFor(term, graph, `${SH}alternativePath`);
    if (alternative) {
      const values = rdfList(alternative, graph, next);
      return values ? `(${values.map((value) => shapePath(value, graph, next)).join("|")})` : null;
    }
    const sequence = rdfList(term, graph, seen);
    return sequence
      ? `(${sequence.map((value) => shapePath(value, graph, next)).join("/")})`
      : null;
  }

  const typeKinds = new Map([
    [`${RDFS}Class`, "rdf-class"],
    [`${OWL}Class`, "owl-class"],
    [`${OWL}ObjectProperty`, "owl-object-property"],
    [`${OWL}DatatypeProperty`, "owl-datatype-property"],
    [`${SH}NodeShape`, "shacl-node-shape"],
    [`${SH}PropertyShape`, "shacl-property-shape"],
  ]);
  for (const quad of quads) {
    const subject = rdfTerm(quad.subject);
    const predicate = rdfTerm(quad.predicate);
    const object = rdfTerm(quad.object);
    const graph = rdfTerm(quad.graph);
    const identifier = `${graph ? `${graph} ` : ""}${subject} ${predicate} ${object}`;
    declarations.push(
      declaration("semantic-triple", identifier, { subject, predicate, object, graph }),
    );
    relationships.push(
      relationship(
        "declares",
        object,
        "semantic-entity",
        "n3-rdf-quad",
        "structurally-proven",
        confidence.structural,
        { subject, predicate, graph },
      ),
    );
    if (graph) declarations.push(declaration("semantic-graph", graph));
    if (quad.predicate.value === `${RDF}type` && typeKinds.has(quad.object.value))
      declarations.push(declaration(typeKinds.get(quad.object.value), subject, { graph }));
    if (quad.predicate.value === `${SH}path`) {
      const expression = shapePath(quad.object, quad.graph);
      if (expression) {
        declarations.push(declaration("shape-path", subject, { graph, path: expression }));
        relationships.push(
          relationship(
            "references",
            expression,
            "semantic-entity",
            "n3-shacl-path",
            "structurally-proven",
            confidence.structural,
            { shape: subject, graph },
          ),
        );
      } else unsupported.push(`complex-shacl-path:${subject}`);
    }
  }
  return complete(declarations, relationships, {
    structuralCoverage: unsupported.length ? "partial" : "complete",
    unsupportedStructures: unsupported,
    confidence: unsupported.length ? confidence.bounded : confidence.structural,
  });
}

function tokenizeSparql(text) {
  const tokens = [];
  let index = 0;
  while (index < text.length) {
    const char = text[index];
    if (/\s/.test(char)) {
      index += 1;
      continue;
    }
    if (char === "#") {
      while (index < text.length && text[index] !== "\n") index += 1;
      continue;
    }
    const iriClose = char === "<" ? text.indexOf(">", index + 1) : -1;
    const iriBody = iriClose >= 0 ? text.slice(index + 1, iriClose) : "";
    if (char === "<" && iriClose >= 0 && iriBody.length > 0 && !/\s/.test(iriBody)) {
      let value = "";
      index += 1;
      while (index < text.length && text[index] !== ">") {
        if (text[index] === "\\" && index + 1 < text.length) value += text[index++];
        value += text[index++];
      }
      if (text[index] === ">") index += 1;
      tokens.push({ type: "iri", value });
      continue;
    }
    if (["<", ">", "=", "&"].includes(char)) {
      const pair = text.slice(index, index + 2);
      const value = ["<=", ">=", "!=", "&&", "||"].includes(pair) ? pair : char;
      tokens.push({ type: "operator", value });
      index += value.length;
      continue;
    }
    if (char === '"' || char === "'") {
      const quote = char;
      const triple = text.slice(index, index + 3) === quote.repeat(3);
      index += triple ? 3 : 1;
      while (index < text.length) {
        if (text[index] === "\\") {
          index += 2;
          continue;
        }
        if (triple ? text.slice(index, index + 3) === quote.repeat(3) : text[index] === quote) {
          index += triple ? 3 : 1;
          break;
        }
        index += 1;
      }
      tokens.push({ type: "string", value: "" });
      continue;
    }
    if ("{}()[];,.*+/|!^".includes(char)) {
      tokens.push({ type: char, value: char });
      index += 1;
      continue;
    }
    const start = index;
    while (
      index < text.length &&
      !/\s/.test(text[index]) &&
      !"<>#\"'{}()[];,.*+/|!^".includes(text[index])
    )
      index += 1;
    const value = text.slice(start, index);
    if (!value) {
      tokens.push({ type: "operator", value: char });
      index += 1;
      continue;
    }
    tokens.push({
      type:
        value.startsWith("?") || value.startsWith("$")
          ? "variable"
          : value.includes(":")
            ? "prefixed"
            : "word",
      value,
      upper: value.toUpperCase(),
    });
  }
  return tokens;
}

function parseSparql({ text }) {
  const tokens = tokenizeSparql(text);
  const declarations = [];
  const relationships = [];
  const unsupported = [];
  let braces = 0;
  let parentheses = 0;
  const operations = new Set([
    "SELECT",
    "ASK",
    "CONSTRUCT",
    "DESCRIBE",
    "INSERT",
    "DELETE",
    "LOAD",
    "CLEAR",
    "CREATE",
    "DROP",
    "COPY",
    "MOVE",
    "ADD",
  ]);
  const graphKeywords = new Set(["FROM", "GRAPH", "WITH", "USING", "INTO", "TO"]);
  const nextStaticTerm = (start) => {
    for (let cursor = start; cursor < tokens.length; cursor += 1) {
      const token = tokens[cursor];
      if (token.type === "iri" || token.type === "prefixed") return token.value;
      if (token.type === "variable" || ["{", "}", ";", "."].includes(token.type)) return null;
      if (!["SILENT", "NAMED", "GRAPH", "DEFAULT"].includes(token.upper)) return null;
    }
    return null;
  };
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token.type === "{") braces += 1;
    if (token.type === "}") braces -= 1;
    if (token.type === "(") parentheses += 1;
    if (token.type === ")") parentheses -= 1;
    if (token.upper === "PREFIX") {
      const prefix = tokens[index + 1];
      const iri = tokens[index + 2];
      if (prefix?.type === "prefixed" && iri?.type === "iri")
        declarations.push(declaration("sparql-prefix", prefix.value, { iri: iri.value }));
    }
    if (token.upper === "BASE" && tokens[index + 1]?.type === "iri")
      declarations.push(declaration("sparql-base", tokens[index + 1].value));
    if (operations.has(token.upper))
      declarations.push(declaration("sparql-operation", token.upper.toLowerCase()));
    if (token.upper === "CREATE") {
      const target = nextStaticTerm(index + 1);
      if (target) declarations.push(declaration("semantic-graph", target));
    }
    if (graphKeywords.has(token.upper)) {
      const target = nextStaticTerm(index + 1);
      if (target) {
        relationships.push(
          relationship(
            "references",
            target,
            "semantic-entity",
            "sparql-graph-clause",
            "structurally-proven",
            confidence.structural,
            { clause: token.upper.toLowerCase() },
          ),
        );
      } else if (tokens[index + 1]?.type === "variable")
        unsupported.push("dynamic-sparql-graph-variable");
    }
    if (token.upper === "SERVICE") {
      const target = nextStaticTerm(index + 1);
      if (target)
        relationships.push(
          relationship("consumes", target, "external-resource", "sparql-service-clause"),
        );
      else unsupported.push("dynamic-sparql-service-target");
    }
    if (token.upper === "LOAD") {
      const target = nextStaticTerm(index + 1);
      if (target)
        relationships.push(
          relationship("consumes", target, "external-resource", "sparql-load-source"),
        );
    }
  }
  if (braces !== 0) unsupported.push("unbalanced-sparql-braces");
  if (parentheses !== 0) unsupported.push("unbalanced-sparql-parentheses");
  return complete(declarations, relationships, {
    structuralCoverage: unsupported.length ? "partial" : "complete",
    unsupportedStructures: unsupported,
    confidence: unsupported.length ? confidence.bounded : confidence.structural,
  });
}

function graphqlTypeName(type) {
  let current = type;
  while (current && (current.kind === Kind.NON_NULL_TYPE || current.kind === Kind.LIST_TYPE))
    current = current.type;
  return current?.name?.value ?? null;
}

function parseGraphqlDocument({ text }) {
  let document;
  try {
    document = parseGraphql(text, { noLocation: false });
  } catch (error) {
    return parseFailure("graphql", error);
  }
  const declarations = [];
  const relationships = [];
  const typeKinds = new Map([
    [Kind.OBJECT_TYPE_DEFINITION, "graphql-object-type"],
    [Kind.OBJECT_TYPE_EXTENSION, "graphql-object-extension"],
    [Kind.INTERFACE_TYPE_DEFINITION, "graphql-interface"],
    [Kind.INPUT_OBJECT_TYPE_DEFINITION, "graphql-input-type"],
    [Kind.ENUM_TYPE_DEFINITION, "graphql-enum"],
    [Kind.SCALAR_TYPE_DEFINITION, "graphql-scalar"],
    [Kind.UNION_TYPE_DEFINITION, "graphql-union"],
    [Kind.DIRECTIVE_DEFINITION, "graphql-directive"],
    [Kind.SCHEMA_DEFINITION, "graphql-schema"],
  ]);
  const nodeLine = (node) => node.loc?.startToken?.line ?? null;

  function visitDefinition(node) {
    const kind = typeKinds.get(node.kind);
    if (kind)
      declarations.push(declaration(kind, node.name?.value ?? "schema", { line: nodeLine(node) }));
    const owner = node.name?.value ?? "schema";
    for (const interfaceNode of node.interfaces ?? [])
      relationships.push(
        relationship(
          "depends-on",
          interfaceNode.name.value,
          "semantic-entity",
          "graphql-implements-interface",
        ),
      );
    for (const member of node.types ?? [])
      relationships.push(
        relationship("references", member.name.value, "semantic-entity", "graphql-union-member"),
      );
    for (const field of node.fields ?? []) {
      declarations.push(
        declaration("graphql-field", `${owner}.${field.name.value}`, { line: nodeLine(field) }),
      );
      const target = graphqlTypeName(field.type);
      if (target)
        relationships.push(
          relationship(
            "references",
            target,
            "semantic-entity",
            "graphql-field-type",
            "structurally-proven",
            confidence.structural,
            { field: `${owner}.${field.name.value}` },
          ),
        );
      for (const argument of field.arguments ?? []) {
        declarations.push(
          declaration("graphql-argument", `${owner}.${field.name.value}(${argument.name.value})`, {
            line: nodeLine(argument),
          }),
        );
        const argumentType = graphqlTypeName(argument.type);
        if (argumentType)
          relationships.push(
            relationship("references", argumentType, "semantic-entity", "graphql-argument-type"),
          );
      }
    }
    for (const value of node.values ?? [])
      declarations.push(
        declaration("graphql-enum-value", `${owner}.${value.name.value}`, {
          line: nodeLine(value),
        }),
      );
  }

  function visitSelectionSet(selectionSet, operation, selectionPath = []) {
    for (const selection of selectionSet?.selections ?? []) {
      if (selection.kind === Kind.FIELD) {
        const fieldPath = [...selectionPath, selection.name.value];
        declarations.push(
          declaration("graphql-call", `${operation}:${fieldPath.join(".")}`, {
            line: nodeLine(selection),
            executableContext: true,
          }),
        );
        relationships.push(
          relationship(
            "invokes",
            selection.name.value,
            "semantic-entity",
            "graphql-executable-field",
            "structurally-proven",
            confidence.structural,
            { operation, path: fieldPath.join(".") },
          ),
        );
        visitSelectionSet(selection.selectionSet, operation, fieldPath);
      } else if (selection.kind === Kind.FRAGMENT_SPREAD) {
        relationships.push(
          relationship(
            "references",
            selection.name.value,
            "semantic-entity",
            "graphql-fragment-spread",
          ),
        );
      } else if (selection.kind === Kind.INLINE_FRAGMENT) {
        if (selection.typeCondition)
          relationships.push(
            relationship(
              "references",
              selection.typeCondition.name.value,
              "semantic-entity",
              "graphql-inline-fragment-type",
            ),
          );
        visitSelectionSet(selection.selectionSet, operation, selectionPath);
      }
    }
  }

  for (const definition of document.definitions) {
    visitDefinition(definition);
    if (definition.kind === Kind.OPERATION_DEFINITION) {
      const name = definition.name?.value ?? "<anonymous>";
      const operation = `${definition.operation}:${name}`;
      declarations.push(
        declaration("graphql-operation", operation, { line: nodeLine(definition) }),
      );
      visitSelectionSet(definition.selectionSet, operation);
    } else if (definition.kind === Kind.FRAGMENT_DEFINITION) {
      declarations.push(
        declaration("graphql-fragment", definition.name.value, {
          line: nodeLine(definition),
          on: definition.typeCondition.name.value,
        }),
      );
      relationships.push(
        relationship(
          "references",
          definition.typeCondition.name.value,
          "semantic-entity",
          "graphql-fragment-type",
        ),
      );
      visitSelectionSet(definition.selectionSet, `fragment:${definition.name.value}`);
    }
  }
  return complete(declarations, relationships);
}

export const javascriptTypescriptParser = {
  id: "babel-javascript-typescript",
  version: "1",
  mode: "structural",
  supports: ({ syntaxKind }) => syntaxKind === "javascript-typescript",
  parse: parseJavaScriptTypescript,
};

export const pythonParser = {
  id: "python-stdlib-ast",
  version: "1",
  mode: "structural",
  supports: ({ syntaxKind }) => syntaxKind === "python",
  parse: parsePython,
};

export const rdfParser = {
  id: "n3-rdf",
  version: "1",
  mode: "structural",
  supports: ({ syntaxKind }) => syntaxKind === "rdf-turtle" || syntaxKind === "rdf-trig",
  parse: parseRdf,
};

export const sparqlParser = {
  id: "structural-sparql",
  version: "1",
  mode: "structural",
  supports: ({ syntaxKind }) => syntaxKind === "sparql",
  parse: parseSparql,
};

export const graphqlParser = {
  id: "graphql-ast",
  version: "1",
  mode: "structural",
  supports: ({ syntaxKind }) => syntaxKind === "graphql",
  parse: parseGraphqlDocument,
};

export const sourceSemanticParsers = [
  javascriptTypescriptParser,
  pythonParser,
  rdfParser,
  sparqlParser,
  graphqlParser,
];
