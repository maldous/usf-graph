import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, isAbsolute, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const modulePath = fileURLToPath(import.meta.url);
const dependencySpecificationPath = join(dirname(modulePath), 'local-shacl-dependencies.json');
export const localShaclPythonSource = "import argparse\nimport hashlib\nimport importlib.metadata\nimport json\nimport os\nimport pathlib\nimport re\nimport sys\n\nimport pyshacl\nimport rdflib\nimport yaml\nfrom pyshacl import validate\nfrom pyshacl.helper.sparql_query_helper import SPARQLQueryHelper\nfrom rdflib import BNode, Dataset, Graph, Literal, Namespace, RDF, URIRef\nfrom rdflib.namespace import SH\nfrom rdflib.plugins.sparql import prepareQuery\nfrom rdflib.plugins.sparql.parser import parseQuery\nfrom rdflib.plugins.sparql.parserutils import CompValue\n\nREPO_ROOT = pathlib.Path(sys.argv[1]).resolve()\nSCRIPT_PATH = pathlib.Path(sys.argv[2]).resolve()\nDEPENDENCY_SPEC_PATH = pathlib.Path(sys.argv[3]).resolve()\nUSF = Namespace(\"urn:usf:ontology:\")\nPREFIX_PATTERN = re.compile(r\"(?im)^\\s*PREFIX\\s+([A-Za-z][A-Za-z0-9_-]*):\\s*<([^>]+)>\\s*$\")\n\nFORWARD_PREDICATES = (\n    \"accountableOwner\", \"accountableProcessBoundary\", \"admissionForEvidence\",\n    \"asserts\", \"authorisedByDecision\", \"bindsProvider\", \"collectedBy\",\n    \"collectedEvidence\", \"collectedOn\", \"collectionForRequirement\", \"collectsEvidence\",\n    \"confidenceBasis\", \"considersOption\", \"decisionState\", \"declaresFacet\", \"derivedFrom\", \"disclaims\",\n    \"entersEvidenceLifecycleAs\", \"evaluatedByValidator\", \"evaluatesObligation\", \"evidenceChecksum\", \"evidenceFor\",\n    \"evidenceForContract\", \"evidenceSignature\", \"executesProof\", \"executesValidation\",\n    \"fulfilsPort\", \"hasAuthorityBinding\", \"hasContract\", \"hasFreshnessPolicy\",\n    \"hasInvalidationCondition\", \"hasProviderMode\", \"implementsContract\", \"implementsPort\",\n    \"ingestedBy\", \"ingestsEvidence\", \"integrityVerification\", \"mandatoryProofObligation\",\n    \"normalisedBy\", \"normalisesEvidence\", \"obligationFor\", \"participatesInProcess\",\n    \"permitsProviderMode\", \"portForContract\", \"producesProofResult\", \"producesResult\",\n    \"producesValidationResult\", \"proofAlgorithmVersionOf\", \"proofExecutionEnvironment\",\n    \"proofNonclaim\", \"proofResultForObligation\", \"realisesContract\",\n    \"realisingImplementation\", \"recordsDecision\", \"reliesOnProofResult\", \"requiredValidation\",\n    \"requiresADR\", \"requiresEnvironmentClass\", \"requiresEvidence\", \"requiresEvidenceKind\",\n    \"requiresEvidenceStage\", \"requiresFreshness\", \"requiresProviderMode\", \"requiresRung\",\n    \"responsibleOwner\", \"signedBy\", \"supportsClaim\", \"supersededBy\",\n    \"supersedesDecision\", \"usesAdmittedEvidence\", \"usesAlgorithmVersion\", \"usesAssuranceCell\",\n    \"usesProofAlgorithm\", \"validationEnvironment\", \"validationForContract\", \"verifiesEvidence\",\n    \"viaAdapter\", \"wasProducedBy\",\n)\nINVERSE_PREDICATES = (\n    \"admissionForEvidence\", \"authorisedByDecision\", \"bindsProvider\", \"collectedBy\",\n    \"collectedEvidence\", \"collectionForRequirement\", \"collectsEvidence\", \"confidenceBasis\",\n    \"entersEvidenceLifecycleAs\", \"evaluatesObligation\", \"evidenceChecksum\", \"evidenceFor\",\n    \"evidenceForContract\", \"evidenceSignature\", \"executesProof\", \"executesValidation\",\n    \"exercises\", \"fulfilsPort\", \"hasAuthorityBinding\", \"hasContract\", \"hasFreshnessPolicy\",\n    \"implementsContract\", \"implementsPort\", \"ingestedBy\", \"ingestsEvidence\",\n    \"integrityVerification\", \"mandatoryProofObligation\", \"normalisedBy\", \"normalisesEvidence\",\n    \"obligationFor\", \"portForContract\", \"producesProofResult\", \"producesResult\",\n    \"producesValidationResult\", \"proofAlgorithmVersionOf\", \"proofResultForObligation\",\n    \"provesSubject\", \"realisesContract\", \"recordsDecision\", \"reliesOnProofResult\", \"surfaceOf\",\n    \"requiredValidation\", \"usesAdmittedEvidence\", \"usesAlgorithmVersion\",\n    \"usesProofAlgorithm\", \"validationForContract\", \"verifiesEvidence\", \"wasProducedBy\",\n)\n\n\ndef stable(value):\n    if isinstance(value, list):\n        return [stable(item) for item in value]\n    if isinstance(value, dict):\n        return {key: stable(value[key]) for key in sorted(value)}\n    return value\n\n\ndef canonical_json(value):\n    return json.dumps(stable(value), ensure_ascii=False, separators=(\",\", \":\"), sort_keys=True)\n\n\ndef sha256(value):\n    if isinstance(value, str):\n        value = value.encode(\"utf-8\")\n    return \"sha256:\" + hashlib.sha256(value).hexdigest()\n\n\ndef file_record(path, root):\n    return {\"path\": path.relative_to(root).as_posix(), \"digest\": sha256(path.read_bytes())}\n\n\ndef load_dataset(model_root, manifest):\n    authored = Graph()\n    data = Graph()\n    records = []\n    for group in (\"definitionGraphs\", \"authoredGraphs\", \"derivedGraphs\"):\n        for entry in manifest[group]:\n            path = model_root / entry[\"file\"]\n            dataset = Dataset()\n            dataset.parse(path, format=\"trig\" if path.suffix == \".trig\" else \"turtle\")\n            for subject, predicate, obj, _ in dataset.quads((None, None, None, None)):\n                data.add((subject, predicate, obj))\n                if group != \"derivedGraphs\":\n                    authored.add((subject, predicate, obj))\n            records.append(file_record(path, REPO_ROOT))\n    return authored, data, sorted(records, key=lambda item: item[\"path\"])\n\n\ndef load_shapes(model_root, manifest):\n    shapes = Graph()\n    records = []\n    for entry in manifest[\"shapeGraphs\"]:\n        path = model_root / entry[\"file\"]\n        shapes.parse(path, format=\"turtle\")\n        records.append(file_record(path, REPO_ROOT))\n    return shapes, sorted(records, key=lambda item: item[\"path\"])\n\n\ndef prefix_context(shapes, shape, constraint):\n    contexts = set(shapes.objects(constraint, SH.prefixes)) | set(shapes.objects(shape, SH.prefixes))\n    result = {}\n    for context in sorted(contexts, key=str):\n        for declaration in shapes.objects(context, SH.declare):\n            prefix = shapes.value(declaration, SH.prefix)\n            namespace = shapes.value(declaration, SH.namespace)\n            if prefix is None or namespace is None:\n                raise RuntimeError(\"INCOMPLETE_PREFIX_DECLARATION\")\n            key = str(prefix)\n            value = str(namespace)\n            if key in result and result[key] != value:\n                raise RuntimeError(f\"CONFLICTING_PREFIX_DECLARATION:{key}\")\n            result[key] = value\n    return dict(sorted(result.items()))\n\n\ndef inject_prefixes(query, prefixes):\n    explicit = {name: namespace for name, namespace in PREFIX_PATTERN.findall(query)}\n    for name, namespace in prefixes.items():\n        if name in explicit and explicit[name] != namespace:\n            raise RuntimeError(f\"CONFLICTING_QUERY_PREFIX:{name}\")\n    missing = [f\"PREFIX {name}: <{prefixes[name]}>\" for name in sorted(prefixes) if name not in explicit]\n    return (\"\\n\".join(missing) + (\"\\n\" if missing else \"\") + query), len(missing)\n\n\ndef service_algebra_node_count(value):\n    if isinstance(value, CompValue):\n        return (1 if value.name == \"ServiceGraphPattern\" else 0) + sum(service_algebra_node_count(item) for item in value.values())\n    if isinstance(value, dict):\n        return sum(service_algebra_node_count(item) for item in value.values())\n    if isinstance(value, (list, tuple)) or value.__class__.__name__ == \"ParseResults\":\n        return sum(service_algebra_node_count(item) for item in value)\n    return 0\n\n\ndef query_has_service(query):\n    return service_algebra_node_count(parseQuery(query)) > 0\n\n\nclass ParsedServiceDetector:\n    \"\"\"pySHACL compatibility adapter: preserve its API, replace its text heuristic.\"\"\"\n\n    @staticmethod\n    def search(query):\n        return object() if query_has_service(query) else None\n\n\ndef constraint_descriptor(shapes, shape, constraint, query, prefixes):\n    record = {\n        \"owningShape\": str(shape),\n        \"queryDigest\": sha256(query),\n        \"messages\": sorted(str(item) for item in shapes.objects(constraint, SH.message)),\n        \"severity\": str(shapes.value(constraint, SH.severity) or shapes.value(shape, SH.severity) or SH.Violation),\n        \"deactivated\": str(shapes.value(constraint, SH.deactivated) or \"false\").lower(),\n        \"prefixContextDigest\": sha256(canonical_json(prefixes)),\n    }\n    return {**record, \"identity\": sha256(canonical_json(record))}\n\n\ndef prepare_constraints(shapes, expected_service_identities):\n    transformed = Graph()\n    for triple in shapes:\n        transformed.add(triple)\n    registered = []\n    compatible = []\n    excluded = []\n    original_queries = []\n    transformed_queries = []\n    prefix_contexts = []\n    injection_count = 0\n    equivalence_count = 0\n    service_node_count = 0\n    for shape, _, constraint in sorted(shapes.triples((None, SH.sparql, None)), key=lambda row: (str(row[0]), str(shapes.value(row[2], SH.message)))):\n        value = shapes.value(constraint, SH.select)\n        if value is None:\n            raise RuntimeError(f\"SPARQL_CONSTRAINT_WITHOUT_SELECT:{shape}\")\n        query = str(value)\n        prefixes = prefix_context(shapes, shape, constraint)\n        rewritten, injected = inject_prefixes(query, prefixes)\n        if inject_prefixes(query, prefixes)[0] != rewritten:\n            raise RuntimeError(\"NONDETERMINISTIC_PREFIX_INJECTION\")\n        original_algebra = prepareQuery(query, initNs=prefixes).algebra\n        transformed_algebra = prepareQuery(rewritten).algebra\n        if original_algebra != transformed_algebra:\n            raise RuntimeError(f\"PREFIX_SEMANTICS_CHANGED:{shape}\")\n        equivalence_count += 1\n        descriptor = constraint_descriptor(shapes, shape, constraint, query, prefixes)\n        registered.append(descriptor)\n        original_queries.append({\"identity\": descriptor[\"identity\"], \"digest\": descriptor[\"queryDigest\"]})\n        transformed_queries.append({\"identity\": descriptor[\"identity\"], \"digest\": sha256(rewritten)})\n        prefix_contexts.append({\"identity\": descriptor[\"identity\"], \"prefixes\": prefixes})\n        query_service_nodes = service_algebra_node_count(parseQuery(rewritten))\n        service_node_count += query_service_nodes\n        if query_service_nodes:\n            excluded.append(descriptor)\n            transformed.remove((shape, SH.sparql, constraint))\n        else:\n            compatible.append(descriptor)\n            transformed.remove((constraint, SH.select, value))\n            transformed.add((constraint, SH.select, Literal(rewritten, lang=value.language, datatype=value.datatype)))\n        injection_count += injected\n    identities = [item[\"identity\"] for item in excluded]\n    if identities != sorted(expected_service_identities):\n        raise RuntimeError(f\"UNEXPECTED_SERVICE_EXCLUSIONS:expected={sorted(expected_service_identities)}:actual={identities}\")\n    if len({item[\"identity\"] for item in registered}) != len(registered):\n        raise RuntimeError(\"AMBIGUOUS_CONSTRAINT_IDENTITY\")\n    return {\n        \"graph\": transformed,\n        \"registered\": registered,\n        \"compatible\": compatible,\n        \"excluded\": excluded,\n        \"originalQueries\": original_queries,\n        \"transformedQueries\": transformed_queries,\n        \"prefixContexts\": prefix_contexts,\n        \"injectedPrefixCount\": injection_count,\n        \"equivalenceCount\": equivalence_count,\n        \"serviceAlgebraNodeCount\": service_node_count,\n    }\n\n\ndef normalise_query_result(result):\n    if result.type == \"ASK\":\n        return {\"type\": \"ASK\", \"value\": bool(result.askAnswer)}\n    rows = sorted(tuple(\"UNBOUND\" if item is None else item.n3() for item in row) for row in result)\n    return {\"type\": result.type, \"rows\": rows}\n\n\ndef equivalence_fixtures():\n    graph = Graph()\n    item = URIRef(\"urn:usf:fixture:prefixitem\")\n    graph.add((item, RDF.type, USF.Capability))\n    graph.add((item, USF.canonicalName, Literal(\"alpha\")))\n    graph.add((item, rdflib.RDFS.label, Literal(\"Alpha\")))\n    prefixes = {\n        \"rdf\": str(RDF),\n        \"rdfs\": str(rdflib.RDFS),\n        \"usf\": str(USF),\n    }\n    queries = [\n        'SELECT ?item WHERE { ?item usf:canonicalName \"alpha\" . }',\n        'ASK { <urn:usf:fixture:prefixitem> rdf:type usf:Capability . }',\n        'SELECT ?label WHERE { <urn:usf:fixture:prefixitem> rdfs:label ?label . }',\n    ]\n    records = []\n    for query in queries:\n        rewritten, _ = inject_prefixes(query, prefixes)\n        original = normalise_query_result(graph.query(query, initNs=prefixes))\n        transformed = normalise_query_result(graph.query(rewritten))\n        if original != transformed:\n            raise RuntimeError(\"REPRESENTATIVE_PREFIX_SEMANTICS_CHANGED\")\n        records.append({\"queryDigest\": sha256(query), \"resultDigest\": sha256(canonical_json(original))})\n    return records\n\n\ndef classifier_self_tests():\n    prefixes = \"PREFIX usf: <urn:usf:ontology:>\\n\"\n    cases = [\n        (\"via-service-predicate\", prefixes + \"SELECT ?x WHERE { ?x usf:viaService ?service . }\", False),\n        (\"managed-service-token\", prefixes + \"SELECT ?x WHERE { VALUES ?x { <urn:usf:storageclass:managedservicereference> } }\", False),\n        (\"service-string-literal\", prefixes + 'SELECT ?x WHERE { BIND(\"SERVICE\" AS ?label) ?x usf:canonicalName ?label . }', False),\n        (\"service-comment\", prefixes + \"SELECT ?x WHERE { # SERVICE <urn:usf:fixture:endpoint> { ?x ?p ?o }\\n ?x usf:canonicalName ?name . }\", False),\n        (\"service-variable-name\", prefixes + \"SELECT ?SERVICE WHERE { ?SERVICE usf:canonicalName ?name . }\", False),\n        (\"service-iri\", prefixes + \"SELECT ?x WHERE { VALUES ?x { <urn:usf:service:local> } }\", False),\n        (\"service-clause\", prefixes + \"SELECT ?x WHERE { SERVICE <urn:usf:fixture:endpoint> { ?x ?p ?o } }\", True),\n    ]\n    results = [{\"id\": identifier, \"queryDigest\": sha256(query), \"expectedLiveDependent\": expected, \"actualLiveDependent\": query_has_service(query)} for identifier, query, expected in cases]\n    if any(item[\"actualLiveDependent\"] != item[\"expectedLiveDependent\"] for item in results):\n        raise RuntimeError(\"SERVICE_CLASSIFIER_SELF_TEST_FAILED\")\n    return results\n\n\ndef closure(data, roots):\n    forward = tuple(URIRef(str(USF) + local) for local in FORWARD_PREDICATES)\n    inverse = tuple(URIRef(str(USF) + local) for local in INVERSE_PREDICATES)\n    known = set(roots)\n    frontier = set(roots)\n    layers = []\n    while frontier:\n        additions = {}\n        for node in sorted(frontier, key=str):\n            for predicate in forward:\n                for target in data.objects(node, predicate):\n                    if isinstance(target, URIRef) and target not in known:\n                        additions.setdefault(target, {\"from\": str(node), \"predicate\": str(predicate), \"direction\": \"forward\"})\n            for predicate in inverse:\n                for target in data.subjects(predicate, node):\n                    if isinstance(target, URIRef) and target not in known:\n                        additions.setdefault(target, {\"from\": str(node), \"predicate\": str(predicate), \"direction\": \"inverse\"})\n        if not additions:\n            break\n        layer = [{\"node\": str(node), **additions[node]} for node in sorted(additions, key=str)]\n        layers.append(layer)\n        frontier = set(additions)\n        known.update(frontier)\n    further = set()\n    for node in known:\n        for predicate in forward:\n            further.update(item for item in data.objects(node, predicate) if isinstance(item, URIRef) and item not in known)\n        for predicate in inverse:\n            further.update(item for item in data.subjects(predicate, node) if isinstance(item, URIRef) and item not in known)\n    if further:\n        raise RuntimeError(\"TRANSITIVE_FOCUS_GAP\")\n    ordered = sorted(str(item) for item in known)\n    policy = {\n        \"forward\": [str(item) for item in forward],\n        \"inverse\": [str(item) for item in inverse],\n    }\n    return ordered, layers, policy\n\n\ndef validate_dependency_specification():\n    specification = json.loads(DEPENDENCY_SPEC_PATH.read_text(encoding=\"utf-8\"))\n    if specification.get(\"schemaVersion\") != 1:\n        raise RuntimeError(\"DEPENDENCY_SPECIFICATION_SCHEMA_UNSUPPORTED\")\n    expected_python = specification.get(\"python\", {}).get(\"version\")\n    observed_python = \".\".join(str(item) for item in sys.version_info[:3])\n    if expected_python != observed_python:\n        raise RuntimeError(f\"PYTHON_VERSION_MISMATCH:expected={expected_python}:actual={observed_python}\")\n    expected = {item.get(\"name\"): item.get(\"version\") for item in specification.get(\"distributions\", [])}\n    if set(expected) != {\"rdflib\", \"pyshacl\", \"PyYAML\"}:\n        raise RuntimeError(\"DEPENDENCY_SPECIFICATION_SET_MISMATCH\")\n    for name in sorted(expected):\n        actual = importlib.metadata.version(name)\n        if expected[name] != actual:\n            raise RuntimeError(f\"DEPENDENCY_VERSION_MISMATCH:{name}:expected={expected[name]}:actual={actual}\")\n    return specification\n\n\ndef dependency_bytes():\n    records = []\n    for name in (\"rdflib\", \"pyshacl\", \"PyYAML\"):\n        distribution = importlib.metadata.distribution(name)\n        files = []\n        for relative_path in distribution.files or []:\n            path_text = str(relative_path).replace(\"\\\\\", \"/\")\n            if \"/__pycache__/\" in f\"/{path_text}\" or path_text.endswith((\".pyc\", \".pyo\")):\n                continue\n            path = pathlib.Path(distribution.locate_file(relative_path))\n            if path.is_file() and not path.is_symlink():\n                files.append({\"path\": path_text, \"digest\": sha256(path.read_bytes())})\n        files.sort(key=lambda item: item[\"path\"])\n        records.append({\"name\": name, \"version\": distribution.version, \"fileCount\": len(files), \"byteSetDigest\": sha256(canonical_json(files))})\n    return records\n\n\ndef validation_results(report_graph):\n    records = []\n    for result in report_graph.subjects(RDF.type, SH.ValidationResult):\n        records.append({\n            \"focusNode\": str(report_graph.value(result, SH.focusNode) or \"\"),\n            \"message\": str(report_graph.value(result, SH.resultMessage) or \"\"),\n            \"resultPath\": str(report_graph.value(result, SH.resultPath) or \"\"),\n            \"sourceShape\": str(report_graph.value(result, SH.sourceShape) or \"\"),\n            \"value\": str(report_graph.value(result, SH.value) or \"\"),\n        })\n    return sorted(records, key=canonical_json)\n\n\ndef validate_phase(data, shapes, focus_nodes, phase):\n    conforms, report_graph, report_text = validate(\n        data,\n        shacl_graph=shapes,\n        advanced=True,\n        allow_infos=False,\n        allow_warnings=False,\n        abort_on_first=False,\n        focus_nodes=focus_nodes,\n        iterate_rules=False,\n        inplace=False,\n        meta_shacl=False,\n    )\n    if not isinstance(report_graph, Graph):\n        raise RuntimeError(f\"PYSHACL_VALIDATION_FAILURE:{phase}:{report_text}\")\n    violations = validation_results(report_graph)\n    if not conforms or violations:\n        raise RuntimeError(f\"CANDIDATE_SHACL_VIOLATIONS:{phase}:{canonical_json(violations)}\")\n    return {\"phase\": phase, \"conforms\": True, \"violationCount\": 0, \"resultDigest\": sha256(canonical_json([]))}\n\n\ndef main():\n    parser = argparse.ArgumentParser(add_help=False)\n    parser.add_argument(\"--focus\", action=\"append\", default=[])\n    parser.add_argument(\"--expect-no-service\", action=\"store_true\")\n    parser.add_argument(\"--expected-service-identity\", action=\"append\", default=[])\n    args = parser.parse_args(sys.argv[4:])\n    validate_dependency_specification()\n    if not args.focus:\n        raise RuntimeError(\"EMPTY_FOCUS_ROOTS\")\n    if args.expect_no_service == bool(args.expected_service_identity):\n        raise RuntimeError(\"EXACTLY_ONE_SERVICE_EXPECTATION_REQUIRED\")\n    expected = [] if args.expect_no_service else sorted(args.expected_service_identity)\n    model_root = REPO_ROOT / \"semantic-model\"\n    manifest_path = model_root / \"manifest.yaml\"\n    manifest = yaml.safe_load(manifest_path.read_text(encoding=\"utf-8\"))\n    authored_data, data, data_sources = load_dataset(model_root, manifest)\n    shapes, shape_sources = load_shapes(model_root, manifest)\n    roots = sorted({URIRef(value) for value in args.focus}, key=str)\n    missing_roots = [str(root) for root in roots if not (root, None, None) in data and not (None, None, root) in data]\n    if missing_roots:\n        raise RuntimeError(f\"FOCUS_ROOT_NOT_FOUND:{missing_roots}\")\n    focus_nodes, focus_layers, predicate_policy = closure(data, roots)\n    constraints = prepare_constraints(shapes, expected)\n    fixtures = equivalence_fixtures()\n    classifier_cases = classifier_self_tests()\n    original_service_detector = SPARQLQueryHelper.has_service_regex\n    SPARQLQueryHelper.has_service_regex = ParsedServiceDetector()\n    try:\n        phase_results = [\n            validate_phase(authored_data, constraints[\"graph\"], focus_nodes, \"AFFECTED_AUTHORED\"),\n            validate_phase(data, constraints[\"graph\"], focus_nodes, \"AFFECTED_REGISTERED_DERIVED_SNAPSHOT\"),\n        ]\n    finally:\n        SPARQLQueryHelper.has_service_regex = original_service_detector\n    script_bytes = SCRIPT_PATH.read_bytes()\n    manifest_record = file_record(manifest_path, REPO_ROOT)\n    dependencies = dependency_bytes()\n    original_query_records = sorted(constraints[\"originalQueries\"], key=lambda item: item[\"identity\"])\n    transformed_query_records = sorted(constraints[\"transformedQueries\"], key=lambda item: item[\"identity\"])\n    registered = sorted(constraints[\"registered\"], key=lambda item: item[\"identity\"])\n    compatible = sorted(constraints[\"compatible\"], key=lambda item: item[\"identity\"])\n    excluded = sorted(constraints[\"excluded\"], key=lambda item: item[\"identity\"])\n    result = {\n        \"schemaVersion\": 1,\n        \"evidenceScope\": \"HERMETIC_SUBSTITUTE\",\n        \"validationScope\": \"LOCAL_PYSHACL_COMPATIBLE_AFFECTED_CLOSURE\",\n        \"localCompatibleConforms\": True,\n        \"validationPhaseResults\": phase_results,\n        \"validationPhaseResultDigest\": sha256(canonical_json(phase_results)),\n        \"candidateViolationCount\": 0,\n        \"unexpectedExclusionCount\": 0,\n        \"registeredSparqlConstraintCount\": len(registered),\n        \"locallyEvaluatedConstraintCount\": len(compatible),\n        \"registeredConstraintSetDigest\": sha256(canonical_json(registered)),\n        \"compatibleValidatedConstraintCount\": len(compatible),\n        \"compatibleConstraintSetDigest\": sha256(canonical_json(compatible)),\n        \"liveServiceConstraintCount\": len(excluded),\n        \"actualServiceAlgebraNodeCount\": constraints[\"serviceAlgebraNodeCount\"],\n        \"liveServiceConstraintSetDigest\": sha256(canonical_json(excluded)),\n        \"liveServiceConstraintState\": \"LIVE_STARDOG_REQUIRED\" if excluded else \"NO_REGISTERED_SERVICE_GRAPH_PATTERN\",\n        \"liveServiceConstraints\": excluded,\n        \"serviceConstraintsCountedAsLocalPass\": 0,\n        \"substringBasedExclusionCount\": 0,\n        \"pyshaclServiceDetectionMode\": \"PARSED_SPARQL_ALGEBRA\",\n        \"prefixInjectionDeterministic\": True,\n        \"prefixSemanticsEquivalent\": True,\n        \"prefixSemanticEquivalenceCount\": constraints[\"equivalenceCount\"],\n        \"injectedPrefixCount\": constraints[\"injectedPrefixCount\"],\n        \"prefixContextSetDigest\": sha256(canonical_json(sorted(constraints[\"prefixContexts\"], key=lambda item: item[\"identity\"]))),\n        \"originalQuerySetDigest\": sha256(canonical_json(original_query_records)),\n        \"transformedQuerySetDigest\": sha256(canonical_json(transformed_query_records)),\n        \"representativeEquivalenceFixtureCount\": len(fixtures),\n        \"representativeEquivalenceDigest\": sha256(canonical_json(fixtures)),\n        \"serviceClassifierSelfTestDigest\": sha256(canonical_json(classifier_cases)),\n        \"serviceClassifierSelfTestCount\": len(classifier_cases),\n        \"serviceClassifierSelfTests\": classifier_cases,\n        \"focusRootCount\": len(roots),\n        \"focusRootDigest\": sha256(canonical_json([str(item) for item in roots])),\n        \"focusNodeCount\": len(focus_nodes),\n        \"focusNodeDigest\": sha256(canonical_json(focus_nodes)),\n        \"focusClosureLayerCount\": len(focus_layers),\n        \"focusClosureWitnessDigest\": sha256(canonical_json(focus_layers)),\n        \"focusPredicatePolicyDigest\": sha256(canonical_json(predicate_policy)),\n        \"transitiveFocusGap\": 0,\n        \"dataTripleCount\": len(data),\n        \"authoredDataTripleCount\": len(authored_data),\n        \"shapeTripleCount\": len(shapes),\n        \"dataSourceSetDigest\": sha256(canonical_json(data_sources)),\n        \"shapeSourceSetDigest\": sha256(canonical_json(shape_sources)),\n        \"candidateSourceSetDigest\": sha256(canonical_json([manifest_record, *data_sources, *shape_sources])),\n        \"semanticManifestDigest\": manifest_record[\"digest\"],\n        \"harnessSourceDigest\": sha256(script_bytes),\n        \"prefixInjectionAlgorithmDigest\": sha256(b\"prefix-injection-v1\\0\" + script_bytes),\n        \"serviceClassificationAlgorithmDigest\": sha256(b\"sparql-algebra-service-graph-pattern-v1\\0\" + script_bytes),\n        \"focusClosureAlgorithmDigest\": sha256(b\"directional-semantic-fixed-point-v1\\0\" + script_bytes),\n        \"pythonVersion\": \".\".join(str(item) for item in sys.version_info[:3]),\n        \"pythonExecutableDigest\": sha256(pathlib.Path(os.path.realpath(sys.executable)).read_bytes()),\n        \"pythonDependencyByteSets\": dependencies,\n        \"pythonDependencyByteSetDigest\": sha256(canonical_json(dependencies)),\n        \"dependencySpecificationDigest\": sha256(DEPENDENCY_SPEC_PATH.read_bytes()),\n        \"rdflibVersion\": rdflib.__version__,\n        \"pyshaclVersion\": pyshacl.__version__,\n        \"pyyamlVersion\": importlib.metadata.version(\"PyYAML\"),\n    }\n    result[\"evidenceDigest\"] = sha256(canonical_json(result))\n    print(canonical_json(result))\n\n\ntry:\n    main()\nexcept Exception as error:  # noqa: BLE001\n    print(f\"{error.__class__.__name__}:{error}\", file=sys.stderr)\n    sys.exit(1)";
const STRUCTURED_PERMUTATION_FORWARD_PREDICATES = Object.freeze([
  'applicabilityClauseOperand',
  'applicabilityOperandClause',
  'applicabilityRootClause',
  'applicabilitySignalSelector',
  'bindsDimension',
  'classClosureMemberClass',
  'classClosurePolicy',
  'classClosureRootClass',
  'dimensionAxisClassClosure',
  'dimensionValueSource',
  'familyApplicabilityRule',
  'familySubjectRegistration',
  'foundationProjectionPredicateMapping',
  'hasDimensionValue',
  'hasFamilyDimensionBinding',
  'selectorPathStep',
  'selectorSubjectClassClosure',
  'selectorTerminalClassClosure',
  'subjectClassClosure',
  'universePublicationBudget',
  'valueDerivationOperand',
  'valueDerivationOperandExpression',
  'valueDerivationPathStep',
  'valueDerivationClassClosure',
  'valueSourceDerivationRoot',
  'valueSourceSelector',
]);

const STRUCTURED_PERMUTATION_INVERSE_PREDICATES = Object.freeze([
  'applicabilityClauseOperand',
  'applicabilityOperandClause',
  'applicabilityRootClause',
  'applicabilitySignalSelector',
  'bindsDimension',
  'classClosureMemberClass',
  'classClosurePolicy',
  'classClosureRootClass',
  'dimensionAxisClassClosure',
  'dimensionValueSource',
  'familyApplicabilityRule',
  'familyOfUniverse',
  'familySubjectRegistration',
  'foundationProjectionPredicateMapping',
  'hasDimensionValue',
  'hasFamilyDimensionBinding',
  'selectorPathStep',
  'selectorSubjectClassClosure',
  'selectorTerminalClassClosure',
  'subjectClassClosure',
  'universePublicationBudget',
  'valueDerivationOperand',
  'valueDerivationOperandExpression',
  'valueDerivationPathStep',
  'valueDerivationClassClosure',
  'valueSourceDerivationRoot',
  'valueSourceSelector',
]);

function extendPythonPredicateTuple(source, tupleName, additions) {
  const startMarker = `${tupleName} = (\n`;
  const start = source.indexOf(startMarker);
  if (start < 0) throw new Error(`local SHACL Python tuple absent: ${tupleName}`);
  const end = source.indexOf('\n)\n', start + startMarker.length);
  if (end < 0) throw new Error(`local SHACL Python tuple unterminated: ${tupleName}`);
  const current = source.slice(start + startMarker.length, end);
  for (const predicate of additions) {
    if (current.includes(`"${predicate}"`)) throw new Error(`local SHACL predicate already present: ${tupleName}:${predicate}`);
  }
  const inserted = additions.map((predicate) => `    "${predicate}",`).join('\n');
  return `${source.slice(0, end)}\n${inserted}${source.slice(end)}`;
}

function replacePythonMarkerExactly(source, marker, replacement, label) {
  const first = source.indexOf(marker);
  if (first < 0) throw new Error(`local SHACL Python marker absent: ${label}`);
  if (source.indexOf(marker, first + marker.length) >= 0) throw new Error(`local SHACL Python marker ambiguous: ${label}`);
  return `${source.slice(0, first)}${replacement}${source.slice(first + marker.length)}`;
}

const PLANTED_FIXTURE_PYTHON_SOURCE = `def planted_fixture_evidence(authored_data, shapes):
    data = Graph()
    fixture = Graph()
    for triple in authored_data:
        data.add(triple)

    def add(subject, predicate, obj):
        triple = (subject, predicate, obj)
        data.add(triple)
        fixture.add(triple)

    def node(identifier):
        return URIRef("urn:usf:fixture:permutation-review:" + identifier.replace("-", ""))

    def digest(identifier):
        return Literal(sha256("planted-fixture:" + identifier), datatype=rdflib.XSD.string)

    def identify(resource, kind, identifier):
        add(resource, RDF.type, kind)
        add(resource, USF.canonicalName, Literal(identifier.replace("-", "")))

    participation = URIRef("urn:usf:permutationparticipationclassification:metadataprovenancenonaxis")
    axis_binding = URIRef("urn:usf:permutationaxisbindingclassification:notanaxis")
    not_candidate = URIRef("urn:usf:permutationfamilycandidateclassification:notafamilycandidate")
    review_candidate = URIRef("urn:usf:permutationfamilycandidateclassification:authorityreviewrequired")
    warranted_candidate = URIRef("urn:usf:permutationfamilycandidateclassification:warranted")
    warranted_family = URIRef("urn:usf:permutationfamilymodelreviewdisposition:warranted")
    multi_axis_kind = URIRef("urn:usf:permutationfamilycandidatekind:multiaxisfamily")
    object_relationship_kind = URIRef("urn:usf:permutationfamilycandidatekind:objectrelationship")
    datatype_relationship_kind = URIRef("urn:usf:permutationfamilycandidatekind:datatyperelationship")
    named_node_kind = URIRef("urn:usf:permutationrelationshipobjecttermkind:namednode")
    literal_kind = URIRef("urn:usf:permutationrelationshipobjecttermkind:literal")
    redundant_relationship = URIRef("urn:usf:permutationrelationshipreviewdisposition:invalidorredundant")
    required_controlled_values = (
        (participation, USF.PermutationParticipationClassification),
        (axis_binding, USF.PermutationAxisBindingClassification),
        (not_candidate, USF.PermutationFamilyCandidateClassification),
        (review_candidate, USF.PermutationFamilyCandidateClassification),
        (warranted_candidate, USF.PermutationFamilyCandidateClassification),
        (warranted_family, USF.PermutationFamilyModelReviewDisposition),
        (multi_axis_kind, USF.PermutationFamilyCandidateKind),
        (object_relationship_kind, USF.PermutationFamilyCandidateKind),
        (datatype_relationship_kind, USF.PermutationFamilyCandidateKind),
        (named_node_kind, USF.PermutationRelationshipObjectTermKind),
        (literal_kind, USF.PermutationRelationshipObjectTermKind),
        (redundant_relationship, USF.PermutationRelationshipReviewDisposition),
    )
    missing_controlled_values = [str(value) for value, kind in required_controlled_values if (value, RDF.type, kind) not in data]
    if missing_controlled_values:
        raise RuntimeError("PLANTED_FIXTURE_CONTROLLED_VALUE_ABSENT:" + canonical_json(missing_controlled_values))

    family_record = None
    for family in sorted(set(data.subjects(RDF.type, USF.PermutationFamily)), key=str):
        subjects = sorted(set(data.objects(family, USF.familySubjectRegistration)), key=str)
        dimensions = sorted(set(data.objects(family, USF.hasFamilyDimensionBinding)), key=str)
        rules = sorted(set(data.objects(family, USF.familyApplicabilityRule)), key=str)
        if len(subjects) == 1 and dimensions and len(rules) == 1:
            family_record = (family, subjects[0], dimensions, rules[0])
            break
    if family_record is None:
        raise RuntimeError("PLANTED_FIXTURE_REGISTERED_FAMILY_ABSENT")
    family, family_subject, family_dimensions, family_rule = family_record

    def add_term_review(identifier, authority, inventory, reviewed_term=USF.Capability, omit_term=False):
        review = node(identifier)
        identify(review, USF.SemanticTermPermutationReview, identifier)
        if not omit_term:
            add(review, USF.reviewedSemanticTerm, reviewed_term)
        add(review, USF.termPermutationParticipation, participation)
        add(review, USF.termPermutationAxisBinding, axis_binding)
        add(review, USF.termPermutationFamilyCandidateState, not_candidate)
        add(review, USF.termPermutationReasonCode, Literal("UNIVERSAL_METADATA_PROVENANCE_NON_AXIS"))
        add(review, USF.termPermutationSourcePlane, Literal("planted-fixture"))
        add(review, USF.termPermutationAuthorityDigest, authority)
        add(review, USF.termPermutationInventoryDigest, inventory)
        add(review, USF.termPermutationReviewDigest, digest(identifier + ":review"))
        return review

    def add_family_review(identifier, authority, registry, omit_subject=False, mismatched_subject=False):
        review = node(identifier)
        identify(review, USF.PermutationFamilySignatureReview, identifier)
        add(review, USF.reviewedPermutationFamily, family)
        if not omit_subject:
            if mismatched_subject:
                subject = node(identifier + ":alternate-subject")
                identify(subject, USF.PermutationSubjectRegistration, identifier + "alternatesubject")
            else:
                subject = family_subject
            add(review, USF.reviewedFamilySubjectRegistration, subject)
        for dimension in family_dimensions:
            add(review, USF.reviewedFamilyDimensionBinding, dimension)
        add(review, USF.reviewedFamilyApplicabilityRule, family_rule)
        add(review, USF.familySignatureReviewAuthorityDigest, authority)
        add(review, USF.familySignatureReviewRegistryDigest, registry)
        add(review, USF.reviewedFamilySignatureDigest, digest(identifier + ":signature"))
        add(review, USF.familySignatureReviewDigest, digest(identifier + ":review"))
        add(review, USF.familySignatureReviewDisposition, warranted_family)
        return review

    def add_coverage(identifier, authority, inventory, registry, term_review, family_review, expected_term, omit_term_algorithm=False):
        coverage = node(identifier)
        identify(coverage, USF.PermutationReviewCoverage, identifier)
        add(coverage, USF.permutationReviewAuthorityDigest, authority)
        add(coverage, USF.permutationReviewInventoryDigest, inventory)
        add(coverage, USF.permutationReviewFamilyRegistryDigest, registry)
        if not omit_term_algorithm:
            add(coverage, USF.permutationReviewTermSetAlgorithm, Literal("semantic-input-term-key-set-v1"))
        add(coverage, USF.permutationReviewFamilySignatureAlgorithm, Literal("family-record-canonical-json-sha256-v1"))
        add(coverage, USF.permutationReviewExpectedTerm, expected_term)
        add(coverage, USF.permutationReviewTermReview, term_review)
        add(coverage, USF.permutationReviewExpectedFamily, family)
        add(coverage, USF.permutationReviewFamilySignatureReview, family_review)
        add(coverage, USF.permutationReviewDigest, digest(identifier + ":coverage"))
        return coverage

    def add_candidate(identifier, classification=warranted_candidate, missing_count=0, authorisation_claim=False):
        candidate = node(identifier)
        identify(candidate, USF.PermutationFamilyCandidate, identifier)
        add(candidate, USF.candidateFamilyKind, multi_axis_kind)
        add(candidate, USF.candidateFamilySubjectClass, USF.Capability)
        add(candidate, USF.candidateFamilyAxisClass, USF.Role)
        add(candidate, USF.candidateFamilySelectorProperty, USF.requiresPermission)
        add(candidate, USF.candidateFamilyClassification, classification)
        add(candidate, USF.candidateFamilyReasonCode, Literal("UNIVERSAL_FAMILY_CANDIDATE_REVIEW"))
        add(candidate, USF.candidateFamilyAuthorityDigest, digest(identifier + ":authority"))
        add(candidate, USF.candidateFamilyInventoryDigest, digest(identifier + ":inventory"))
        add(candidate, USF.candidateFamilyDigest, digest(identifier + ":candidate"))
        add(candidate, USF.candidateFamilyMissingTermCount, Literal(missing_count, datatype=rdflib.XSD.nonNegativeInteger))
        add(candidate, USF.candidateFamilyEmptyAxisCount, Literal(0, datatype=rdflib.XSD.nonNegativeInteger))
        if authorisation_claim:
            add(candidate, USF.establishesSemanticTruth, Literal(True))
        return candidate

    def add_atomic_candidate(identifier, kind, terminal, add_axis=False):
        candidate = node(identifier)
        identify(candidate, USF.PermutationFamilyCandidate, identifier)
        add(candidate, USF.candidateFamilyKind, kind)
        add(candidate, USF.candidateFamilySubjectClass, USF.Capability)
        add(candidate, USF.candidateRelationshipSignature, node(identifier + ":signature"))
        add(candidate, USF.candidateRelationshipSignatureDigest, digest(identifier + ":signature"))
        add(candidate, USF.candidateRelationshipDirection, URIRef("urn:usf:permutationpathdirection:outbound"))
        add(candidate, USF.candidateRelationshipPredicate, USF.requiresPermission)
        if kind == object_relationship_kind:
            add(candidate, USF.candidateRelationshipTerminalClass, terminal)
        else:
            add(candidate, USF.candidateRelationshipTerminalDatatype, terminal)
        if add_axis:
            add(candidate, USF.candidateFamilyAxisClass, USF.Role)
        add(candidate, USF.candidateFamilyClassification, review_candidate)
        add(candidate, USF.candidateFamilyReasonCode, Literal("UNIVERSAL_RELATIONSHIP_SIGNATURE_UNDISPOSITIONED"))
        add(candidate, USF.candidateFamilyAuthorityDigest, digest(identifier + ":authority"))
        add(candidate, USF.candidateFamilyInventoryDigest, digest(identifier + ":inventory"))
        add(candidate, USF.candidateFamilyDigest, digest(identifier + ":candidate"))
        return candidate

    def add_relationship_review(identifier, omit_signature=False, authorisation_claim=False):
        review = node(identifier)
        identify(review, USF.PermutationRelationshipSignatureReview, identifier)
        if not omit_signature:
            add(review, USF.reviewedRelationshipSignature, node(identifier + ":signature"))
        add(review, USF.reviewedRelationshipSignatureDigest, digest(identifier + ":signature"))
        add(review, USF.reviewedRelationshipPredicate, USF.requiresPermission)
        add(review, USF.reviewedRelationshipDirection, URIRef("urn:usf:permutationpathdirection:outbound"))
        add(review, USF.reviewedRelationshipSubjectTermKind, named_node_kind)
        add(review, USF.reviewedRelationshipSubjectClass, USF.Operation)
        add(review, USF.reviewedRelationshipSubjectClassSetDigest, digest(identifier + ":subjects"))
        add(review, USF.reviewedRelationshipObjectTermKind, named_node_kind)
        add(review, USF.reviewedRelationshipObjectClass, USF.Permission)
        add(review, USF.reviewedRelationshipObjectClassSetDigest, digest(identifier + ":objects"))
        add(review, USF.reviewedRelationshipActiveOccurrenceCount, Literal(1, datatype=rdflib.XSD.nonNegativeInteger))
        add(review, USF.reviewedRelationshipActiveOccurrenceSetDigest, digest(identifier + ":occurrences"))
        add(review, USF.reviewedRelationshipWitnessSetDigest, digest(identifier + ":witnesses"))
        add(review, USF.relationshipSignatureReviewDisposition, redundant_relationship)
        add(review, USF.relationshipSignatureReviewReasonCode, Literal("UNIVERSAL_REVIEW_INVALID_OR_REDUNDANT"))
        add(review, USF.relationshipSignatureReviewAuthorityDigest, digest(identifier + ":authority"))
        add(review, USF.relationshipSignatureReviewInventoryDigest, digest(identifier + ":inventory"))
        add(review, USF.relationshipSignatureReviewRegistryDigest, digest(identifier + ":registry"))
        add(review, USF.relationshipSignatureReviewEvidenceDigest, digest(identifier + ":evidence"))
        add(review, USF.relationshipSignatureReviewAlgorithmDigest, digest(identifier + ":algorithm"))
        add(review, USF.relationshipSignatureReviewDigest, digest(identifier + ":review"))
        if authorisation_claim:
            add(review, USF.establishesSemanticTruth, Literal(True))
        return review

    catalogue = []

    def expected(identifier, focus, reason_codes):
        catalogue.append({
            "id": identifier,
            "focusNode": str(focus),
            "expectedResult": "ACCEPTED" if not reason_codes else "REJECTED",
            "expectedReasonCodes": sorted(reason_codes),
        })

    shared_authority = digest("positive:authority")
    shared_inventory = digest("positive:inventory")
    shared_registry = digest("positive:registry")
    positive_term = add_term_review("positive-term-review", shared_authority, shared_inventory)
    positive_family = add_family_review("positive-family-review", shared_authority, shared_registry)
    positive_coverage = add_coverage(
        "positive-review-coverage", shared_authority, shared_inventory, shared_registry,
        positive_term, positive_family, USF.Capability,
    )
    positive_candidate = add_candidate("positive-family-candidate")
    positive_object_candidate = add_atomic_candidate(
        "positive-object-candidate", object_relationship_kind, USF.Permission,
    )
    positive_datatype_candidate = add_atomic_candidate(
        "positive-datatype-candidate", datatype_relationship_kind, rdflib.XSD.string,
    )
    positive_relationship_review = add_relationship_review("positive-relationship-review")
    expected("positive-term-review", positive_term, [])
    expected("positive-family-review", positive_family, [])
    expected("positive-review-coverage", positive_coverage, [])
    expected("positive-family-candidate", positive_candidate, [])
    expected("positive-object-candidate", positive_object_candidate, [])
    expected("positive-datatype-candidate", positive_datatype_candidate, [])
    expected("positive-relationship-review", positive_relationship_review, [])

    missing_term = add_term_review("missing-reviewed-term", digest("missing-term:authority"), digest("missing-term:inventory"), omit_term=True)
    expected("missing-reviewed-term", missing_term, ["UNIVERSAL_REVIEW_TERM_ABSENT"])

    missing_subject = add_family_review("missing-family-subject", digest("missing-subject:authority"), digest("missing-subject:registry"), omit_subject=True)
    expected("missing-family-subject", missing_subject, ["PERMUTATION_FAMILY_SIGNATURE_SUBJECT_ABSENT"])

    mismatched_subject = add_family_review("mismatched-family-components", digest("mismatch:authority"), digest("mismatch:registry"), mismatched_subject=True)
    expected("mismatched-family-components", mismatched_subject, ["PERMUTATION_FAMILY_SIGNATURE_COMPONENT_MISMATCH"])

    algorithm_authority = digest("algorithm:authority")
    algorithm_inventory = digest("algorithm:inventory")
    algorithm_registry = digest("algorithm:registry")
    algorithm_term = add_term_review("algorithm-support-term", algorithm_authority, algorithm_inventory)
    algorithm_family = add_family_review("algorithm-support-family", algorithm_authority, algorithm_registry)
    missing_algorithm = add_coverage(
        "missing-term-algorithm", algorithm_authority, algorithm_inventory, algorithm_registry,
        algorithm_term, algorithm_family, USF.Capability, omit_term_algorithm=True,
    )
    expected("missing-term-algorithm", missing_algorithm, ["PERMUTATION_REVIEW_TERM_ALGORITHM_ABSENT"])

    mismatch_authority = digest("term-set-mismatch:authority")
    mismatch_inventory = digest("term-set-mismatch:inventory")
    mismatch_registry = digest("term-set-mismatch:registry")
    mismatch_term = add_term_review("term-set-support-term", mismatch_authority, mismatch_inventory, reviewed_term=USF.Role)
    mismatch_family = add_family_review("term-set-support-family", mismatch_authority, mismatch_registry)
    term_set_mismatch = add_coverage(
        "term-set-mismatch", mismatch_authority, mismatch_inventory, mismatch_registry,
        mismatch_term, mismatch_family, USF.Capability,
    )
    expected("term-set-mismatch", term_set_mismatch, ["PERMUTATION_REVIEW_TERM_SET_MISMATCH"])

    missing_candidate_subject = add_candidate("candidate-missing-subject")
    data.remove((missing_candidate_subject, USF.candidateFamilySubjectClass, None))
    fixture.remove((missing_candidate_subject, USF.candidateFamilySubjectClass, None))
    expected("candidate-missing-subject", missing_candidate_subject, ["UNIVERSAL_CANDIDATE_SUBJECT_ABSENT"])

    warranted_with_gaps = add_candidate("candidate-warranted-with-gaps", missing_count=1)
    expected("candidate-warranted-with-gaps", warranted_with_gaps, ["UNIVERSAL_CANDIDATE_WARRANTED_WITH_GAPS"])

    authorising_candidate = add_candidate("candidate-authorisation-prohibited", authorisation_claim=True)
    expected("candidate-authorisation-prohibited", authorising_candidate, ["UNIVERSAL_CANDIDATE_AUTHORISATION_PROHIBITED"])

    missing_candidate_kind = add_candidate("candidate-kind-absent")
    data.remove((missing_candidate_kind, USF.candidateFamilyKind, None))
    fixture.remove((missing_candidate_kind, USF.candidateFamilyKind, None))
    expected("candidate-kind-absent", missing_candidate_kind, ["UNIVERSAL_CANDIDATE_KIND_ABSENT"])

    conflicting_endpoint = add_atomic_candidate(
        "candidate-object-endpoint-conflict", object_relationship_kind, USF.Permission,
    )
    add(conflicting_endpoint, USF.candidateRelationshipTerminalDatatype, rdflib.XSD.string)
    expected("candidate-object-endpoint-conflict", conflicting_endpoint, ["UNIVERSAL_CANDIDATE_ENDPOINT_MODE_INVALID"])

    missing_datatype = add_atomic_candidate(
        "candidate-datatype-endpoint-absent", datatype_relationship_kind, rdflib.XSD.string,
    )
    data.remove((missing_datatype, USF.candidateRelationshipTerminalDatatype, None))
    fixture.remove((missing_datatype, USF.candidateRelationshipTerminalDatatype, None))
    expected("candidate-datatype-endpoint-absent", missing_datatype, ["UNIVERSAL_CANDIDATE_ENDPOINT_MODE_INVALID"])

    mixed_candidate = add_atomic_candidate(
        "candidate-form-component-conflict", object_relationship_kind, USF.Permission, add_axis=True,
    )
    expected("candidate-form-component-conflict", mixed_candidate, ["UNIVERSAL_CANDIDATE_FORM_COMPONENT_CONFLICT"])

    missing_relationship_signature = add_relationship_review(
        "relationship-review-signature-absent", omit_signature=True,
    )
    expected("relationship-review-signature-absent", missing_relationship_signature, ["PERMUTATION_RELATIONSHIP_REVIEW_SIGNATURE_ABSENT"])

    authorising_relationship_review = add_relationship_review(
        "relationship-review-authorisation-prohibited", authorisation_claim=True,
    )
    expected("relationship-review-authorisation-prohibited", authorising_relationship_review, ["PERMUTATION_RELATIONSHIP_REVIEW_AUTHORISATION_PROHIBITED"])

    catalogue.sort(key=lambda item: item["id"])
    focus_nodes = [item["focusNode"] for item in catalogue]
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
        raise RuntimeError("PLANTED_FIXTURE_VALIDATION_FAILURE:" + str(report_text))
    violations = validation_results(report_graph)
    by_focus = {}
    for violation in violations:
        message = violation["message"]
        code = message.split(":", 1)[0]
        by_focus.setdefault(violation["focusNode"], []).append(code)

    expected_focus = {item["focusNode"] for item in catalogue}
    unrecognised_results = [item for item in violations if item["focusNode"] not in expected_focus]
    result_records = []
    missing_expected_count = 0
    unexpected_code_count = 0
    multiple_code_count = 0
    for case in catalogue:
        raw_codes = sorted(by_focus.get(case["focusNode"], []))
        actual_codes = sorted(set(raw_codes))
        expected_codes = case["expectedReasonCodes"]
        missing_expected_count += len(set(expected_codes) - set(actual_codes))
        unexpected_code_count += len(set(actual_codes) - set(expected_codes))
        multiple_code_count += 1 if len(raw_codes) != len(expected_codes) else 0
        result_records.append({
            "id": case["id"],
            "focusNode": case["focusNode"],
            "expectedResult": case["expectedResult"],
            "actualResult": "REJECTED" if raw_codes else "ACCEPTED",
            "expectedReasonCodes": expected_codes,
            "actualReasonCodes": actual_codes,
            "resultCount": len(raw_codes),
        })

    negative_count = sum(1 for item in catalogue if item["expectedResult"] == "REJECTED")
    positive_count = len(catalogue) - negative_count
    fixture_triples = sorted(([term.n3() for term in triple] for triple in fixture), key=canonical_json)
    reason_codes = sorted({code for item in catalogue for code in item["expectedReasonCodes"]})
    core = {
        "schemaVersion": 1,
        "validationScope": "PLANTED_PERMUTATION_REVIEW_FIXTURES",
        "fixtureIsolation": "IN_MEMORY_UNPUBLISHED_CANDIDATE",
        "caseCount": len(catalogue),
        "positiveControlCount": positive_count,
        "negativeControlCount": negative_count,
        "catalogue": catalogue,
        "catalogueDigest": sha256(canonical_json(catalogue)),
        "focusNodeSetDigest": sha256(canonical_json(sorted(focus_nodes))),
        "fixtureTripleCount": len(fixture_triples),
        "fixtureGraphDigest": sha256(canonical_json(fixture_triples)),
        "rawValidationConforms": bool(conforms),
        "resultRecords": result_records,
        "resultDigest": sha256(canonical_json(result_records)),
        "reasonCodeSet": reason_codes,
        "reasonCodeSetDigest": sha256(canonical_json(reason_codes)),
        "missingExpectedCount": missing_expected_count,
        "unexpectedCodeCount": unexpected_code_count,
        "multipleCodeCount": multiple_code_count,
        "unrecognisedResultCount": len(unrecognised_results),
        "contractConforms": missing_expected_count == 0 and unexpected_code_count == 0 and multiple_code_count == 0 and not unrecognised_results and not conforms,
    }
    if not core["contractConforms"]:
        raise RuntimeError("PLANTED_FIXTURE_CONTRACT_FAILED:" + canonical_json(core))
    return {**core, "evidenceDigest": sha256(canonical_json(core))}
`;

function injectPythonFixtureContract(source) {
  let result = replacePythonMarkerExactly(
    source,
    '\ndef main():\n',
    `\n${PLANTED_FIXTURE_PYTHON_SOURCE}\n\ndef main():\n`,
    'planted fixture function insertion',
  );
  result = replacePythonMarkerExactly(
    result,
    '    try:\n        phase_results = [\n',
    '    try:\n        planted_fixtures = planted_fixture_evidence(authored_data, constraints["graph"])\n        phase_results = [\n',
    'planted fixture execution',
  );
  result = replacePythonMarkerExactly(
    result,
    '        "serviceClassifierSelfTests": classifier_cases,\n',
    '        "serviceClassifierSelfTests": classifier_cases,\n        "plantedFixtureEvidence": planted_fixtures,\n        "plantedFixtureEvidenceDigest": planted_fixtures["evidenceDigest"],\n',
    'planted fixture evidence binding',
  );
  return result;
}

function injectReviewGraphPlane(source) {
  let result = replacePythonMarkerExactly(
    source,
    '    authored = Graph()\n    data = Graph()\n',
    '    authored = Graph()\n    reviewed = Graph()\n    data = Graph()\n',
    'review graph accumulator',
  );
  result = replacePythonMarkerExactly(
    result,
    '    for group in ("definitionGraphs", "authoredGraphs", "derivedGraphs"):\n        for entry in manifest[group]:\n',
    '    for group in ("definitionGraphs", "authoredGraphs", "reviewGraphs", "derivedGraphs"):\n        for entry in manifest.get(group, []):\n',
    'review graph manifest plane',
  );
  result = replacePythonMarkerExactly(
    result,
    '                if group != "derivedGraphs":\n                    authored.add((subject, predicate, obj))\n',
    '                if group in ("definitionGraphs", "authoredGraphs"):\n                    authored.add((subject, predicate, obj))\n                if group != "derivedGraphs":\n                    reviewed.add((subject, predicate, obj))\n',
    'review graph semantic-input separation',
  );
  result = replacePythonMarkerExactly(
    result,
    '    return authored, data, sorted(records, key=lambda item: item["path"])\n',
    '    return authored, reviewed, data, sorted(records, key=lambda item: item["path"])\n',
    'review graph dataset return',
  );
  result = replacePythonMarkerExactly(
    result,
    '    authored_data, data, data_sources = load_dataset(model_root, manifest)\n',
    '    authored_data, review_data, data, data_sources = load_dataset(model_root, manifest)\n',
    'review graph dataset binding',
  );
  result = replacePythonMarkerExactly(
    result,
    '        planted_fixtures = planted_fixture_evidence(authored_data, constraints["graph"])\n        phase_results = [\n            validate_phase(authored_data, constraints["graph"], focus_nodes, "AFFECTED_AUTHORED"),\n            validate_phase(data, constraints["graph"], focus_nodes, "AFFECTED_REGISTERED_DERIVED_SNAPSHOT"),\n        ]\n',
    '        planted_fixtures = planted_fixture_evidence(authored_data, constraints["graph"])\n        phase_results = [validate_phase(authored_data, constraints["graph"], focus_nodes, "AFFECTED_AUTHORED")]\n        if manifest.get("reviewGraphs", []):\n            phase_results.append(validate_phase(review_data, constraints["graph"], focus_nodes, "AFFECTED_REVIEW_ENRICHED"))\n        phase_results.append(validate_phase(data, constraints["graph"], focus_nodes, "AFFECTED_REGISTERED_DERIVED_SNAPSHOT"))\n',
    'review graph validation phase',
  );
  result = replacePythonMarkerExactly(
    result,
    '        "authoredDataTripleCount": len(authored_data),\n',
    '        "authoredDataTripleCount": len(authored_data),\n        "reviewEnrichedDataTripleCount": len(review_data),\n',
    'review graph evidence count',
  );
  return result;
}

export const effectiveLocalShaclPythonSource = injectReviewGraphPlane(injectPythonFixtureContract(
  extendPythonPredicateTuple(
    extendPythonPredicateTuple(localShaclPythonSource, 'FORWARD_PREDICATES', STRUCTURED_PERMUTATION_FORWARD_PREDICATES),
    'INVERSE_PREDICATES',
    STRUCTURED_PERMUTATION_INVERSE_PREDICATES,
  ),
));

const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

export function validateLocalShaclRuntime(runtime) {
  if (!runtime || typeof runtime !== 'object' || !isAbsolute(runtime.executablePath || '')
      || !isAbsolute(runtime.resolvedExecutablePath || '') || !SHA256.test(runtime.executableDigest || '')) {
    throw new TypeError('local SHACL runtime requires absolute launcher and resolved executable paths plus an exact digest');
  }
  const stat = lstatSync(runtime.executablePath);
  if ((!stat.isSymbolicLink() && !stat.isFile()) || realpathSync(runtime.executablePath) !== runtime.resolvedExecutablePath) {
    throw new TypeError('local SHACL runtime launcher must resolve to its declared executable');
  }
  const resolvedStat = lstatSync(runtime.resolvedExecutablePath);
  if (resolvedStat.isSymbolicLink() || !resolvedStat.isFile()) throw new TypeError('local SHACL resolved executable must be a canonical regular file');
  const observedDigest = sha256(readFileSync(runtime.resolvedExecutablePath));
  if (observedDigest !== runtime.executableDigest) throw new TypeError('local SHACL runtime executable digest mismatch');
  return Object.freeze({
    executableDigest: observedDigest,
    executablePath: runtime.executablePath,
    resolvedExecutablePath: runtime.resolvedExecutablePath,
  });
}

export function runLocalShaclValidation({ repositoryRoot, runtime, arguments: validationArguments }) {
  const binding = validateLocalShaclRuntime(runtime);
  if (!isAbsolute(repositoryRoot || '') || !Array.isArray(validationArguments)) throw new TypeError('local SHACL repository root and arguments are required');
  const result = spawnSync(binding.executablePath, [
    '-', repositoryRoot, modulePath, dependencySpecificationPath, ...validationArguments,
  ], {
    cwd: repositoryRoot,
    encoding: 'utf8',
    env: { LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', PATH: '/usr/bin:/bin', TZ: 'UTC' },
    input: effectiveLocalShaclPythonSource,
    maxBuffer: 64 * 1024 * 1024,
    timeout: 600_000,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`local SHACL validation failed (${result.status}): ${result.stderr.trim()}`);
  if (result.signal) throw new Error(`local SHACL validation terminated by ${result.signal}`);
  return result.stdout;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const [executablePath, resolvedExecutablePath, executableDigest, ...validationArguments] = process.argv.slice(2);
    process.stdout.write(runLocalShaclValidation({
      repositoryRoot: process.cwd(),
      runtime: { executablePath, resolvedExecutablePath, executableDigest },
      arguments: validationArguments,
    }));
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
