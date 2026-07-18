#!/usr/bin/env bash
# Deterministic repository-local RDF parsing and bounded pySHACL validation.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
GRAPH_DIR="${USF_GRAPH_DIR:-$REPO_ROOT/graph}"
SCRIPT_PATH="$HERE/validate-graph.sh"

usable(){ [ -x "$1" ] && "$1" -c 'import rdflib, pyshacl, yaml' 2>/dev/null; }
PY="${USF_GRAPH_PY:-}"
[ -n "$PY" ] || { p="$REPO_ROOT/.venv/bin/python"; usable "$p" && PY="$p"; } || true
[ -n "$PY" ] || { echo "error: no Python with rdflib, pyshacl and yaml is available" >&2; exit 1; }

MODE="${1:-parse}"
if [ "$#" -gt 0 ]; then shift; fi

if [ "$MODE" = "parse" ]; then
  exec "$PY" - "$GRAPH_DIR" <<'PY'
import pathlib
import sys

from rdflib import Dataset, Graph

root = pathlib.Path(sys.argv[1])
formats = {".ttl": "turtle", ".trig": "trig"}
ok = empty = errors = 0
for path in sorted(root.rglob("*")):
    if path.suffix not in formats or not path.is_file():
        continue
    if path.stat().st_size == 0:
        empty += 1
        continue
    try:
        graph = Dataset() if path.suffix == ".trig" else Graph()
        graph.parse(str(path), format=formats[path.suffix])
        ok += 1
    except Exception as error:  # noqa: BLE001
        errors += 1
        print(f"INVALID {path}: {error}", file=sys.stderr)
print(f"validate-graph: parsed_ok={ok} empty_placeholders={empty} invalid={errors}")
sys.exit(1 if errors else 0)
PY
fi

if [ "$MODE" != "shacl-affected" ]; then
  echo "error: unsupported validation mode: $MODE" >&2
  exit 2
fi

exec "$PY" - "$REPO_ROOT" "$SCRIPT_PATH" "$@" <<'PY'
import argparse
import hashlib
import importlib.metadata
import json
import os
import pathlib
import re
import sys

import pyshacl
import rdflib
import yaml
from pyshacl import validate
from pyshacl.helper.sparql_query_helper import SPARQLQueryHelper
from rdflib import BNode, Dataset, Graph, Literal, Namespace, RDF, URIRef
from rdflib.namespace import SH
from rdflib.plugins.sparql import prepareQuery
from rdflib.plugins.sparql.parser import parseQuery
from rdflib.plugins.sparql.parserutils import CompValue

REPO_ROOT = pathlib.Path(sys.argv[1]).resolve()
SCRIPT_PATH = pathlib.Path(sys.argv[2]).resolve()
USF = Namespace("urn:usf:ontology:")
PREFIX_PATTERN = re.compile(r"(?im)^\s*PREFIX\s+([A-Za-z][A-Za-z0-9_-]*):\s*<([^>]+)>\s*$")

FORWARD_PREDICATES = (
    "accountableOwner", "accountableProcessBoundary", "admissionForEvidence",
    "asserts", "authorisedByDecision", "bindsProvider", "collectedBy",
    "collectedEvidence", "collectedOn", "collectionForRequirement", "collectsEvidence",
    "confidenceBasis", "considersOption", "decisionState", "declaresFacet", "derivedFrom", "disclaims",
    "entersEvidenceLifecycleAs", "evaluatedByValidator", "evaluatesObligation", "evidenceChecksum", "evidenceFor",
    "evidenceForContract", "evidenceSignature", "executesProof", "executesValidation",
    "fulfilsPort", "hasAuthorityBinding", "hasContract", "hasFreshnessPolicy",
    "hasInvalidationCondition", "hasProviderMode", "implementsContract", "implementsPort",
    "ingestedBy", "ingestsEvidence", "integrityVerification", "mandatoryProofObligation",
    "normalisedBy", "normalisesEvidence", "obligationFor", "participatesInProcess",
    "permitsProviderMode", "portForContract", "producesProofResult", "producesResult",
    "producesValidationResult", "proofAlgorithmVersionOf", "proofExecutionEnvironment",
    "proofNonclaim", "proofResultForObligation", "realisesContract",
    "realisingImplementation", "recordsDecision", "reliesOnProofResult", "requiredValidation",
    "requiresADR", "requiresEnvironmentClass", "requiresEvidence", "requiresEvidenceKind",
    "requiresEvidenceStage", "requiresFreshness", "requiresProviderMode", "requiresRung",
    "responsibleOwner", "signedBy", "supportsClaim", "supersededBy",
    "supersedesDecision", "usesAdmittedEvidence", "usesAlgorithmVersion", "usesAssuranceCell",
    "usesProofAlgorithm", "validationEnvironment", "validationForContract", "verifiesEvidence",
    "viaAdapter", "wasProducedBy",
)
INVERSE_PREDICATES = (
    "admissionForEvidence", "authorisedByDecision", "bindsProvider", "collectedBy",
    "collectedEvidence", "collectionForRequirement", "collectsEvidence", "confidenceBasis",
    "entersEvidenceLifecycleAs", "evaluatesObligation", "evidenceChecksum", "evidenceFor",
    "evidenceForContract", "evidenceSignature", "executesProof", "executesValidation",
    "exercises", "fulfilsPort", "hasAuthorityBinding", "hasContract", "hasFreshnessPolicy",
    "implementsContract", "implementsPort", "ingestedBy", "ingestsEvidence",
    "integrityVerification", "mandatoryProofObligation", "normalisedBy", "normalisesEvidence",
    "obligationFor", "portForContract", "producesProofResult", "producesResult",
    "producesValidationResult", "proofAlgorithmVersionOf", "proofResultForObligation",
    "provesSubject", "realisesContract", "recordsDecision", "reliesOnProofResult", "surfaceOf",
    "requiredValidation", "usesAdmittedEvidence", "usesAlgorithmVersion",
    "usesProofAlgorithm", "validationForContract", "verifiesEvidence", "wasProducedBy",
)


def stable(value):
    if isinstance(value, list):
        return [stable(item) for item in value]
    if isinstance(value, dict):
        return {key: stable(value[key]) for key in sorted(value)}
    return value


def canonical_json(value):
    return json.dumps(stable(value), ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def sha256(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return "sha256:" + hashlib.sha256(value).hexdigest()


def file_record(path, root):
    return {"path": path.relative_to(root).as_posix(), "digest": sha256(path.read_bytes())}


def load_dataset(model_root, manifest):
    authored = Graph()
    data = Graph()
    records = []
    for group in ("definitionGraphs", "authoredGraphs", "derivedGraphs"):
        for entry in manifest[group]:
            path = model_root / entry["file"]
            dataset = Dataset()
            dataset.parse(path, format="trig" if path.suffix == ".trig" else "turtle")
            for subject, predicate, obj, _ in dataset.quads((None, None, None, None)):
                data.add((subject, predicate, obj))
                if group != "derivedGraphs":
                    authored.add((subject, predicate, obj))
            records.append(file_record(path, REPO_ROOT))
    return authored, data, sorted(records, key=lambda item: item["path"])


def load_shapes(model_root, manifest):
    shapes = Graph()
    records = []
    for entry in manifest["shapeGraphs"]:
        path = model_root / entry["file"]
        shapes.parse(path, format="turtle")
        records.append(file_record(path, REPO_ROOT))
    return shapes, sorted(records, key=lambda item: item["path"])


def prefix_context(shapes, shape, constraint):
    contexts = set(shapes.objects(constraint, SH.prefixes)) | set(shapes.objects(shape, SH.prefixes))
    result = {}
    for context in sorted(contexts, key=str):
        for declaration in shapes.objects(context, SH.declare):
            prefix = shapes.value(declaration, SH.prefix)
            namespace = shapes.value(declaration, SH.namespace)
            if prefix is None or namespace is None:
                raise RuntimeError("INCOMPLETE_PREFIX_DECLARATION")
            key = str(prefix)
            value = str(namespace)
            if key in result and result[key] != value:
                raise RuntimeError(f"CONFLICTING_PREFIX_DECLARATION:{key}")
            result[key] = value
    return dict(sorted(result.items()))


def inject_prefixes(query, prefixes):
    explicit = {name: namespace for name, namespace in PREFIX_PATTERN.findall(query)}
    for name, namespace in prefixes.items():
        if name in explicit and explicit[name] != namespace:
            raise RuntimeError(f"CONFLICTING_QUERY_PREFIX:{name}")
    missing = [f"PREFIX {name}: <{prefixes[name]}>" for name in sorted(prefixes) if name not in explicit]
    return ("\n".join(missing) + ("\n" if missing else "") + query), len(missing)


def service_algebra_node_count(value):
    if isinstance(value, CompValue):
        return (1 if value.name == "ServiceGraphPattern" else 0) + sum(service_algebra_node_count(item) for item in value.values())
    if isinstance(value, dict):
        return sum(service_algebra_node_count(item) for item in value.values())
    if isinstance(value, (list, tuple)) or value.__class__.__name__ == "ParseResults":
        return sum(service_algebra_node_count(item) for item in value)
    return 0


def query_has_service(query):
    return service_algebra_node_count(parseQuery(query)) > 0


class ParsedServiceDetector:
    """pySHACL compatibility adapter: preserve its API, replace its text heuristic."""

    @staticmethod
    def search(query):
        return object() if query_has_service(query) else None


def constraint_descriptor(shapes, shape, constraint, query, prefixes):
    record = {
        "owningShape": str(shape),
        "queryDigest": sha256(query),
        "messages": sorted(str(item) for item in shapes.objects(constraint, SH.message)),
        "severity": str(shapes.value(constraint, SH.severity) or shapes.value(shape, SH.severity) or SH.Violation),
        "deactivated": str(shapes.value(constraint, SH.deactivated) or "false").lower(),
        "prefixContextDigest": sha256(canonical_json(prefixes)),
    }
    return {**record, "identity": sha256(canonical_json(record))}


def prepare_constraints(shapes, expected_service_identities):
    transformed = Graph()
    for triple in shapes:
        transformed.add(triple)
    registered = []
    compatible = []
    excluded = []
    original_queries = []
    transformed_queries = []
    prefix_contexts = []
    injection_count = 0
    equivalence_count = 0
    service_node_count = 0
    for shape, _, constraint in sorted(shapes.triples((None, SH.sparql, None)), key=lambda row: (str(row[0]), str(shapes.value(row[2], SH.message)))):
        value = shapes.value(constraint, SH.select)
        if value is None:
            raise RuntimeError(f"SPARQL_CONSTRAINT_WITHOUT_SELECT:{shape}")
        query = str(value)
        prefixes = prefix_context(shapes, shape, constraint)
        rewritten, injected = inject_prefixes(query, prefixes)
        if inject_prefixes(query, prefixes)[0] != rewritten:
            raise RuntimeError("NONDETERMINISTIC_PREFIX_INJECTION")
        original_algebra = prepareQuery(query, initNs=prefixes).algebra
        transformed_algebra = prepareQuery(rewritten).algebra
        if original_algebra != transformed_algebra:
            raise RuntimeError(f"PREFIX_SEMANTICS_CHANGED:{shape}")
        equivalence_count += 1
        descriptor = constraint_descriptor(shapes, shape, constraint, query, prefixes)
        registered.append(descriptor)
        original_queries.append({"identity": descriptor["identity"], "digest": descriptor["queryDigest"]})
        transformed_queries.append({"identity": descriptor["identity"], "digest": sha256(rewritten)})
        prefix_contexts.append({"identity": descriptor["identity"], "prefixes": prefixes})
        query_service_nodes = service_algebra_node_count(parseQuery(rewritten))
        service_node_count += query_service_nodes
        if query_service_nodes:
            excluded.append(descriptor)
            transformed.remove((shape, SH.sparql, constraint))
        else:
            compatible.append(descriptor)
            transformed.remove((constraint, SH.select, value))
            transformed.add((constraint, SH.select, Literal(rewritten, lang=value.language, datatype=value.datatype)))
        injection_count += injected
    identities = [item["identity"] for item in excluded]
    if identities != sorted(expected_service_identities):
        raise RuntimeError(f"UNEXPECTED_SERVICE_EXCLUSIONS:expected={sorted(expected_service_identities)}:actual={identities}")
    if len({item["identity"] for item in registered}) != len(registered):
        raise RuntimeError("AMBIGUOUS_CONSTRAINT_IDENTITY")
    return {
        "graph": transformed,
        "registered": registered,
        "compatible": compatible,
        "excluded": excluded,
        "originalQueries": original_queries,
        "transformedQueries": transformed_queries,
        "prefixContexts": prefix_contexts,
        "injectedPrefixCount": injection_count,
        "equivalenceCount": equivalence_count,
        "serviceAlgebraNodeCount": service_node_count,
    }


def normalise_query_result(result):
    if result.type == "ASK":
        return {"type": "ASK", "value": bool(result.askAnswer)}
    rows = sorted(tuple("UNBOUND" if item is None else item.n3() for item in row) for row in result)
    return {"type": result.type, "rows": rows}


def equivalence_fixtures():
    graph = Graph()
    item = URIRef("urn:usf:fixture:prefixitem")
    graph.add((item, RDF.type, USF.Capability))
    graph.add((item, USF.canonicalName, Literal("alpha")))
    graph.add((item, rdflib.RDFS.label, Literal("Alpha")))
    prefixes = {
        "rdf": str(RDF),
        "rdfs": str(rdflib.RDFS),
        "usf": str(USF),
    }
    queries = [
        'SELECT ?item WHERE { ?item usf:canonicalName "alpha" . }',
        'ASK { <urn:usf:fixture:prefixitem> rdf:type usf:Capability . }',
        'SELECT ?label WHERE { <urn:usf:fixture:prefixitem> rdfs:label ?label . }',
    ]
    records = []
    for query in queries:
        rewritten, _ = inject_prefixes(query, prefixes)
        original = normalise_query_result(graph.query(query, initNs=prefixes))
        transformed = normalise_query_result(graph.query(rewritten))
        if original != transformed:
            raise RuntimeError("REPRESENTATIVE_PREFIX_SEMANTICS_CHANGED")
        records.append({"queryDigest": sha256(query), "resultDigest": sha256(canonical_json(original))})
    return records


def classifier_self_tests():
    prefixes = "PREFIX usf: <urn:usf:ontology:>\n"
    cases = [
        ("via-service-predicate", prefixes + "SELECT ?x WHERE { ?x usf:viaService ?service . }", False),
        ("managed-service-token", prefixes + "SELECT ?x WHERE { VALUES ?x { <urn:usf:storageclass:managedservicereference> } }", False),
        ("service-string-literal", prefixes + 'SELECT ?x WHERE { BIND("SERVICE" AS ?label) ?x usf:canonicalName ?label . }', False),
        ("service-comment", prefixes + "SELECT ?x WHERE { # SERVICE <urn:usf:fixture:endpoint> { ?x ?p ?o }\n ?x usf:canonicalName ?name . }", False),
        ("service-variable-name", prefixes + "SELECT ?SERVICE WHERE { ?SERVICE usf:canonicalName ?name . }", False),
        ("service-iri", prefixes + "SELECT ?x WHERE { VALUES ?x { <urn:usf:service:local> } }", False),
        ("service-clause", prefixes + "SELECT ?x WHERE { SERVICE <urn:usf:fixture:endpoint> { ?x ?p ?o } }", True),
    ]
    results = [{"id": identifier, "queryDigest": sha256(query), "expectedLiveDependent": expected, "actualLiveDependent": query_has_service(query)} for identifier, query, expected in cases]
    if any(item["actualLiveDependent"] != item["expectedLiveDependent"] for item in results):
        raise RuntimeError("SERVICE_CLASSIFIER_SELF_TEST_FAILED")
    return results


def closure(data, roots):
    forward = tuple(URIRef(str(USF) + local) for local in FORWARD_PREDICATES)
    inverse = tuple(URIRef(str(USF) + local) for local in INVERSE_PREDICATES)
    known = set(roots)
    frontier = set(roots)
    layers = []
    while frontier:
        additions = {}
        for node in sorted(frontier, key=str):
            for predicate in forward:
                for target in data.objects(node, predicate):
                    if isinstance(target, URIRef) and target not in known:
                        additions.setdefault(target, {"from": str(node), "predicate": str(predicate), "direction": "forward"})
            for predicate in inverse:
                for target in data.subjects(predicate, node):
                    if isinstance(target, URIRef) and target not in known:
                        additions.setdefault(target, {"from": str(node), "predicate": str(predicate), "direction": "inverse"})
        if not additions:
            break
        layer = [{"node": str(node), **additions[node]} for node in sorted(additions, key=str)]
        layers.append(layer)
        frontier = set(additions)
        known.update(frontier)
    further = set()
    for node in known:
        for predicate in forward:
            further.update(item for item in data.objects(node, predicate) if isinstance(item, URIRef) and item not in known)
        for predicate in inverse:
            further.update(item for item in data.subjects(predicate, node) if isinstance(item, URIRef) and item not in known)
    if further:
        raise RuntimeError("TRANSITIVE_FOCUS_GAP")
    ordered = sorted(str(item) for item in known)
    policy = {
        "forward": [str(item) for item in forward],
        "inverse": [str(item) for item in inverse],
    }
    return ordered, layers, policy


def dependency_bytes():
    records = []
    for name in ("rdflib", "pyshacl", "PyYAML"):
        distribution = importlib.metadata.distribution(name)
        files = []
        for relative_path in distribution.files or []:
            path_text = str(relative_path).replace("\\", "/")
            if "/__pycache__/" in f"/{path_text}" or path_text.endswith((".pyc", ".pyo")):
                continue
            path = pathlib.Path(distribution.locate_file(relative_path))
            if path.is_file() and not path.is_symlink():
                files.append({"path": path_text, "digest": sha256(path.read_bytes())})
        files.sort(key=lambda item: item["path"])
        records.append({"name": name, "version": distribution.version, "fileCount": len(files), "byteSetDigest": sha256(canonical_json(files))})
    return records


def validation_results(report_graph):
    records = []
    for result in report_graph.subjects(RDF.type, SH.ValidationResult):
        records.append({
            "focusNode": str(report_graph.value(result, SH.focusNode) or ""),
            "message": str(report_graph.value(result, SH.resultMessage) or ""),
            "resultPath": str(report_graph.value(result, SH.resultPath) or ""),
            "sourceShape": str(report_graph.value(result, SH.sourceShape) or ""),
            "value": str(report_graph.value(result, SH.value) or ""),
        })
    return sorted(records, key=canonical_json)


def validate_phase(data, shapes, focus_nodes, phase):
    conforms, report_graph, report_text = validate(
        data,
        shacl_graph=shapes,
        advanced=True,
        allow_infos=False,
        allow_warnings=False,
        abort_on_first=False,
        focus_nodes=focus_nodes,
        iterate_rules=False,
        inplace=False,
        meta_shacl=False,
    )
    if not isinstance(report_graph, Graph):
        raise RuntimeError(f"PYSHACL_VALIDATION_FAILURE:{phase}:{report_text}")
    violations = validation_results(report_graph)
    if not conforms or violations:
        raise RuntimeError(f"CANDIDATE_SHACL_VIOLATIONS:{phase}:{canonical_json(violations)}")
    return {"phase": phase, "conforms": True, "violationCount": 0, "resultDigest": sha256(canonical_json([]))}


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--focus", action="append", default=[])
    parser.add_argument("--expect-no-service", action="store_true")
    parser.add_argument("--expected-service-identity", action="append", default=[])
    args = parser.parse_args(sys.argv[3:])
    if not args.focus:
        raise RuntimeError("EMPTY_FOCUS_ROOTS")
    if args.expect_no_service == bool(args.expected_service_identity):
        raise RuntimeError("EXACTLY_ONE_SERVICE_EXPECTATION_REQUIRED")
    expected = [] if args.expect_no_service else sorted(args.expected_service_identity)
    model_root = REPO_ROOT / "semantic-model"
    manifest_path = model_root / "manifest.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    authored_data, data, data_sources = load_dataset(model_root, manifest)
    shapes, shape_sources = load_shapes(model_root, manifest)
    roots = sorted({URIRef(value) for value in args.focus}, key=str)
    missing_roots = [str(root) for root in roots if not (root, None, None) in data and not (None, None, root) in data]
    if missing_roots:
        raise RuntimeError(f"FOCUS_ROOT_NOT_FOUND:{missing_roots}")
    focus_nodes, focus_layers, predicate_policy = closure(data, roots)
    constraints = prepare_constraints(shapes, expected)
    fixtures = equivalence_fixtures()
    classifier_cases = classifier_self_tests()
    original_service_detector = SPARQLQueryHelper.has_service_regex
    SPARQLQueryHelper.has_service_regex = ParsedServiceDetector()
    try:
        phase_results = [
            validate_phase(authored_data, constraints["graph"], focus_nodes, "AFFECTED_AUTHORED"),
            validate_phase(data, constraints["graph"], focus_nodes, "AFFECTED_REGISTERED_DERIVED_SNAPSHOT"),
        ]
    finally:
        SPARQLQueryHelper.has_service_regex = original_service_detector
    script_bytes = SCRIPT_PATH.read_bytes()
    manifest_record = file_record(manifest_path, REPO_ROOT)
    dependencies = dependency_bytes()
    original_query_records = sorted(constraints["originalQueries"], key=lambda item: item["identity"])
    transformed_query_records = sorted(constraints["transformedQueries"], key=lambda item: item["identity"])
    registered = sorted(constraints["registered"], key=lambda item: item["identity"])
    compatible = sorted(constraints["compatible"], key=lambda item: item["identity"])
    excluded = sorted(constraints["excluded"], key=lambda item: item["identity"])
    result = {
        "schemaVersion": 1,
        "evidenceScope": "HERMETIC_SUBSTITUTE",
        "validationScope": "LOCAL_PYSHACL_COMPATIBLE_AFFECTED_CLOSURE",
        "localCompatibleConforms": True,
        "validationPhaseResults": phase_results,
        "validationPhaseResultDigest": sha256(canonical_json(phase_results)),
        "candidateViolationCount": 0,
        "unexpectedExclusionCount": 0,
        "registeredSparqlConstraintCount": len(registered),
        "locallyEvaluatedConstraintCount": len(compatible),
        "registeredConstraintSetDigest": sha256(canonical_json(registered)),
        "compatibleValidatedConstraintCount": len(compatible),
        "compatibleConstraintSetDigest": sha256(canonical_json(compatible)),
        "liveServiceConstraintCount": len(excluded),
        "actualServiceAlgebraNodeCount": constraints["serviceAlgebraNodeCount"],
        "liveServiceConstraintSetDigest": sha256(canonical_json(excluded)),
        "liveServiceConstraintState": "LIVE_STARDOG_REQUIRED" if excluded else "NO_REGISTERED_SERVICE_GRAPH_PATTERN",
        "liveServiceConstraints": excluded,
        "serviceConstraintsCountedAsLocalPass": 0,
        "substringBasedExclusionCount": 0,
        "pyshaclServiceDetectionMode": "PARSED_SPARQL_ALGEBRA",
        "prefixInjectionDeterministic": True,
        "prefixSemanticsEquivalent": True,
        "prefixSemanticEquivalenceCount": constraints["equivalenceCount"],
        "injectedPrefixCount": constraints["injectedPrefixCount"],
        "prefixContextSetDigest": sha256(canonical_json(sorted(constraints["prefixContexts"], key=lambda item: item["identity"]))),
        "originalQuerySetDigest": sha256(canonical_json(original_query_records)),
        "transformedQuerySetDigest": sha256(canonical_json(transformed_query_records)),
        "representativeEquivalenceFixtureCount": len(fixtures),
        "representativeEquivalenceDigest": sha256(canonical_json(fixtures)),
        "serviceClassifierSelfTestDigest": sha256(canonical_json(classifier_cases)),
        "serviceClassifierSelfTestCount": len(classifier_cases),
        "serviceClassifierSelfTests": classifier_cases,
        "focusRootCount": len(roots),
        "focusRootDigest": sha256(canonical_json([str(item) for item in roots])),
        "focusNodeCount": len(focus_nodes),
        "focusNodeDigest": sha256(canonical_json(focus_nodes)),
        "focusClosureLayerCount": len(focus_layers),
        "focusClosureWitnessDigest": sha256(canonical_json(focus_layers)),
        "focusPredicatePolicyDigest": sha256(canonical_json(predicate_policy)),
        "transitiveFocusGap": 0,
        "dataTripleCount": len(data),
        "authoredDataTripleCount": len(authored_data),
        "shapeTripleCount": len(shapes),
        "dataSourceSetDigest": sha256(canonical_json(data_sources)),
        "shapeSourceSetDigest": sha256(canonical_json(shape_sources)),
        "candidateSourceSetDigest": sha256(canonical_json([manifest_record, *data_sources, *shape_sources])),
        "semanticManifestDigest": manifest_record["digest"],
        "harnessSourceDigest": sha256(script_bytes),
        "prefixInjectionAlgorithmDigest": sha256(b"prefix-injection-v1\0" + script_bytes),
        "serviceClassificationAlgorithmDigest": sha256(b"sparql-algebra-service-graph-pattern-v1\0" + script_bytes),
        "focusClosureAlgorithmDigest": sha256(b"directional-semantic-fixed-point-v1\0" + script_bytes),
        "pythonVersion": ".".join(str(item) for item in sys.version_info[:3]),
        "pythonExecutableDigest": sha256(pathlib.Path(os.path.realpath(sys.executable)).read_bytes()),
        "pythonDependencyByteSets": dependencies,
        "pythonDependencyByteSetDigest": sha256(canonical_json(dependencies)),
        "dependencySpecificationDigest": sha256((REPO_ROOT / "tools/chroot/bootstrap.sh").read_bytes()),
        "rdflibVersion": rdflib.__version__,
        "pyshaclVersion": pyshacl.__version__,
        "pyyamlVersion": importlib.metadata.version("PyYAML"),
    }
    result["evidenceDigest"] = sha256(canonical_json(result))
    print(canonical_json(result))


try:
    main()
except Exception as error:  # noqa: BLE001
    print(f"{error.__class__.__name__}:{error}", file=sys.stderr)
    sys.exit(1)
PY
