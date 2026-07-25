#!/usr/bin/env python3
"""Adversarial SHACL counterexample harness for the USF ValidationObligation
contract and its sibling families.

Read-only: parses tracked semantic-model source, adds one counterexample fixture
per case in memory, and validates with pyshacl (rdflib engine - the second
supported engine). Nothing is written to the repository or to Stardog.

Each case declares whether the authoritative model MUST reject it. A case that
must be rejected but conforms is a semantic defect.
"""
import json
import pathlib
import re
import sys

import yaml
from pyshacl import validate
from rdflib import Dataset, Graph, Literal, Namespace, RDF, URIRef, XSD
from rdflib.namespace import SH

import os
ROOT = pathlib.Path(os.environ.get("USF_ROOT", "/usf"))
MODEL = ROOT / "semantic-model"
U = Namespace("urn:usf:ontology:")
FX = "urn:usf:fixtureadversarial"

manifest = yaml.safe_load((MODEL / "manifest.yaml").read_text())


def load_data():
    g = Graph()
    for group in ("definitionGraphs", "authoredGraphs", "derivedGraphs"):
        for entry in manifest[group]:
            p = MODEL / entry["file"]
            ds = Dataset()
            ds.parse(p, format="trig" if p.suffix == ".trig" else "turtle")
            for s, pr, o, _ in ds.quads((None, None, None, None)):
                g.add((s, pr, o))
    return g


def load_shapes():
    g = Graph()
    for entry in manifest["shapeGraphs"]:
        g.parse(MODEL / entry["file"], format="turtle")
    return g


BASE = load_data()
SHAPES = load_shapes()

RESERVED = URIRef("urn:usf:validationactivationstate:reserved")
ACTIVATED = URIRef("urn:usf:validationactivationstate:activated")
BLOCKED = URIRef("urn:usf:validationactivationstate:blocked")
PASSED = URIRef("urn:usf:resultstate:passed")
FAILED = URIRef("urn:usf:resultstate:failed")
GOOD_DIGEST = Literal("sha256:" + "a" * 64)
GOOD_HEAD = Literal("1637909fe21a64834b034dc1593543c5dd8adec5")

# An existing real contract, so validationForContract points at something real.
CONTRACT = URIRef("urn:usf:semanticcontract:repositoryexternalartefactmaterialisation")


_MINTED = {}


def n(name):
    """Hyphen-free canonical fixture IRI; canonicalName is attached on first use."""
    slug = re.sub(r"[^a-z0-9]", "", name.lower())
    iri = URIRef(FX + slug)
    _MINTED[iri] = slug
    return iri


def finish(g):
    for iri, slug in _MINTED.items():
        if (iri, U.canonicalName, None) not in g:
            g.add((iri, U.canonicalName, Literal(slug)))


def obligation(g, name, state=ACTIVATED, contract=CONTRACT):
    o = n(name)
    g.add((o, RDF.type, U.ValidationObligation))
    if state is not None:
        g.add((o, U.hasValidationActivationState, state))
    if contract is not None:
        g.add((o, U.validationForContract, contract))
    return o


def result(g, name, obl, state=PASSED, evidence=True, digest=GOOD_DIGEST, head=GOOD_HEAD):
    r = n(name)
    g.add((r, RDF.type, U.ValidationResult))
    g.add((r, U.entersEvidenceLifecycleAs, n(name + "-ve")))
    g.add((n(name + "-ve"), RDF.type, U.ValidationEvidence))
    if obl is not None:
        g.add((r, U.resultForValidationObligation, obl))
    if state is not None:
        if isinstance(state, (list, tuple)):
            for s in state:
                g.add((r, U.resultState, s))
        else:
            g.add((r, U.resultState, state))
    if evidence is True:
        g.add((r, U.usesAdmittedValidationEvidence, n(name + "-ev")))
    elif evidence not in (None, False):
        g.add((r, U.usesAdmittedValidationEvidence, evidence))
    if digest is not None:
        g.add((r, U.validationEvaluatedAuthorityDigest, digest))
    if head is not None:
        g.add((r, U.validationEvaluatedSourceHead, head))
    return r


CASES = []


def case(cid, must_reject, description, build):
    CASES.append({"id": cid, "mustReject": must_reject, "description": description, "build": build})


# ---------------------------------------------------------------- baseline
def c_baseline(g):
    o = obligation(g, "ok-obl")
    r = result(g, "ok-res", o)
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r]


case("BASELINE-well-formed", False,
     "activated obligation satisfied by a passing result with all required bindings", c_baseline)

# ------------------------------------------------------ evidence admission
def c_ev_untyped(g):
    o = obligation(g, "ev1-obl")
    r = result(g, "ev1-res", o, evidence=n("ev1notevidenceatall"))
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r]


case("EV-01-not-typed-ValidationEvidence", True,
     "satisfaction cites an object that is not typed as any evidence class", c_ev_untyped)


def c_ev_not_admitted(g):
    o = obligation(g, "ev2-obl")
    ev = n("ev2-ev")
    g.add((ev, RDF.type, U.EvidenceResult))          # right class, never admitted
    g.add((ev, U.hasAdmissionState, URIRef("urn:usf:evidenceadmissionstate:rejected")))
    r = result(g, "ev2-res", o, evidence=ev)
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r, ev]


case("EV-02-explicitly-rejected-evidence", True,
     "satisfaction cites EvidenceResult whose admission state is rejected", c_ev_not_admitted)


def c_ev_stale(g):
    o = obligation(g, "ev3-obl")
    ev = n("ev3-ev")
    g.add((ev, RDF.type, U.EvidenceResult))
    g.add((ev, U.hasAdmissionState, URIRef("urn:usf:evidenceadmissionstate:admitted")))
    g.add((ev, U.hasFreshnessState, URIRef("urn:usf:evidencefreshnessstate:stale")))
    g.add((ev, U.hasIntegrityState, URIRef("urn:usf:evidenceintegritystate:valid")))
    r = result(g, "ev3-res", o, evidence=ev)
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r, ev]


case("EV-03-stale-evidence", True,
     "satisfaction cites admitted but stale evidence", c_ev_stale)


def c_ev_integrity_invalid(g):
    o = obligation(g, "ev4-obl")
    ev = n("ev4-ev")
    g.add((ev, RDF.type, U.EvidenceResult))
    g.add((ev, U.hasAdmissionState, URIRef("urn:usf:evidenceadmissionstate:admitted")))
    g.add((ev, U.hasFreshnessState, URIRef("urn:usf:evidencefreshnessstate:fresh")))
    g.add((ev, U.hasIntegrityState, URIRef("urn:usf:evidenceintegritystate:invalid")))
    r = result(g, "ev4-res", o, evidence=ev)
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r, ev]


case("EV-04-integrity-invalid-evidence", True,
     "satisfaction cites admitted fresh but integrity-INVALID evidence", c_ev_integrity_invalid)


def c_ev_out_of_scope(g):
    o = obligation(g, "ev5-obl")
    ev = n("ev5-ev")
    g.add((ev, RDF.type, U.EvidenceResult))
    g.add((ev, U.hasAdmissionState, URIRef("urn:usf:evidenceadmissionstate:admitted")))
    g.add((ev, U.hasFreshnessState, URIRef("urn:usf:evidencefreshnessstate:fresh")))
    g.add((ev, U.hasIntegrityState, URIRef("urn:usf:evidenceintegritystate:valid")))
    g.add((ev, U.withinValidityScope, Literal(False)))
    r = result(g, "ev5-res", o, evidence=ev)
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r, ev]


case("EV-05-outside-validity-scope", True,
     "satisfaction cites evidence explicitly outside its validity scope", c_ev_out_of_scope)


def c_ev_wrong_obligation(g):
    o = obligation(g, "ev6-obl")
    other = obligation(g, "ev6-other", state=RESERVED)
    ev = n("ev6-ev")
    g.add((ev, RDF.type, U.EvidenceResult))
    g.add((ev, U.hasAdmissionState, URIRef("urn:usf:evidenceadmissionstate:admitted")))
    g.add((ev, U.applicableToObligation, other))    # applicable to a DIFFERENT obligation
    r = result(g, "ev6-res", o, evidence=ev)
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, other, r, ev]


case("EV-06-evidence-applicable-to-other-obligation", True,
     "satisfaction cites evidence declared applicable only to a different obligation", c_ev_wrong_obligation)


def c_ev_no_provenance(g):
    o = obligation(g, "ev7-obl")
    ev = n("ev7-ev")
    g.add((ev, RDF.type, U.EvidenceResult))
    g.add((ev, U.hasAdmissionState, URIRef("urn:usf:evidenceadmissionstate:admitted")))
    g.add((ev, U.hasFreshnessState, URIRef("urn:usf:evidencefreshnessstate:fresh")))
    g.add((ev, U.hasIntegrityState, URIRef("urn:usf:evidenceintegritystate:valid")))
    g.add((ev, U.withinValidityScope, Literal(True)))
    # No collectedBy / normalisedBy / ingestedBy / signature / checksum / verification.
    r = result(g, "ev7-res", o, evidence=ev)
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r, ev]


case("EV-07-no-collection-normalisation-ingestion-provenance", True,
     "satisfaction cites evidence with no collection, normalisation or ingestion provenance",
     c_ev_no_provenance)


def c_ev_unsigned(g):
    o = obligation(g, "ev8-obl")
    ev = n("ev8-ev")
    g.add((ev, RDF.type, U.EvidenceResult))
    g.add((ev, U.hasAdmissionState, URIRef("urn:usf:evidenceadmissionstate:admitted")))
    g.add((ev, U.collectedBy, n("ev8-coll")))
    g.add((n("ev8-coll"), RDF.type, U.EvidenceCollection))
    # unsigned, no checksum, no integrity verification
    r = result(g, "ev8-res", o, evidence=ev)
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r, ev]


case("EV-08-unsigned-no-checksum-no-integrity-verification", True,
     "satisfaction cites evidence with no signature, checksum or integrity verification", c_ev_unsigned)


def c_ev_self_reference(g):
    o = obligation(g, "ev9-obl")
    r = result(g, "ev9-res", o, evidence=None)
    g.add((r, U.usesAdmittedValidationEvidence, r))   # cites ITSELF as its evidence
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r]


case("EV-09-result-cites-itself-as-evidence", True,
     "satisfaction where the result cites itself as its own admitted evidence", c_ev_self_reference)


def c_ev_cites_obligation(g):
    o = obligation(g, "ev10-obl")
    r = result(g, "ev10-res", o, evidence=None)
    g.add((r, U.usesAdmittedValidationEvidence, o))   # cites the obligation as evidence
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r]


case("EV-10-result-cites-the-obligation-as-evidence", True,
     "satisfaction where the cited 'admitted evidence' is the obligation itself", c_ev_cites_obligation)


# ---------------------------------------------------- result-state consistency
def c_rs_passed_and_failed(g):
    o = obligation(g, "rs1-obl")
    r = result(g, "rs1-res", o, state=[PASSED, FAILED])
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r]


case("RS-01-passed-and-failed-simultaneously", True,
     "satisfying result asserts resultState passed AND failed at the same time", c_rs_passed_and_failed)


def c_rs_failed_only(g):
    o = obligation(g, "rs2-obl")
    r = result(g, "rs2-res", o, state=FAILED)
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r]


case("RS-02-failed-only", True, "satisfying result is failing only", c_rs_failed_only)


def c_rs_none(g):
    o = obligation(g, "rs3-obl")
    r = result(g, "rs3-res", o, state=None)
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r]


case("RS-03-no-result-state", True, "satisfying result declares no result state at all", c_rs_none)


def c_rs_outside_vocabulary(g):
    o = obligation(g, "rs4-obl")
    r = result(g, "rs4-res", o, state=[PASSED, URIRef("urn:usf:resultstate:probablyfine")])
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r]


case("RS-04-extra-undeclared-result-state", True,
     "satisfying result carries passed plus an undeclared result-state value", c_rs_outside_vocabulary)


# ---------------------------------------------------------------- identity
def c_id_cross_binding(g):
    a = obligation(g, "id1-a")
    b = obligation(g, "id1-b")
    r = result(g, "id1-res", b)          # bound to B
    g.add((a, U.satisfiedByValidationResult, r))   # claimed by A
    return [a, b, r]


case("ID-01-result-bound-to-A-satisfies-B", True,
     "obligation A claims satisfaction from a result bound to obligation B", c_id_cross_binding)


def c_id_two_obligations(g):
    a = obligation(g, "id2-a")
    b = obligation(g, "id2-b")
    r = result(g, "id2-res", a)
    g.add((r, U.resultForValidationObligation, b))   # bound to two obligations
    g.add((a, U.satisfiedByValidationResult, r))
    return [a, b, r]


case("ID-02-result-bound-to-two-obligations", True,
     "a satisfying result binds two ValidationObligations", c_id_two_obligations)


def c_id_proof_obligation(g):
    o = obligation(g, "id3-obl")
    po = n("id3-proofobl")
    g.add((po, RDF.type, U.ProofObligation))
    g.add((po, U.requiresEvidence, n("id3-req")))
    g.add((n("id3-req"), RDF.type, U.EvidenceRequirement))
    r = result(g, "id3-res", po)     # bound to a ProofObligation, not a ValidationObligation
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, po, r]


case("ID-03-result-bound-to-a-ProofObligation", True,
     "satisfaction from a result whose binding target is a ProofObligation of the same family name",
     c_id_proof_obligation)


def c_id_evidence_requirement(g):
    o = obligation(g, "id4-obl")
    er = n("id4-evreq")
    g.add((er, RDF.type, U.EvidenceRequirement))
    r = result(g, "id4-res", er)
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, er, r]


case("ID-04-result-bound-to-an-EvidenceRequirement", True,
     "satisfaction from a result bound to an EvidenceRequirement rather than a ValidationObligation",
     c_id_evidence_requirement)


def c_id_reuse(g):
    a = obligation(g, "id5-a")
    b = obligation(g, "id5-b")
    r = result(g, "id5-res", a)
    g.add((a, U.satisfiedByValidationResult, r))
    g.add((b, U.satisfiedByValidationResult, r))   # one result reused for two obligations
    return [a, b, r]


case("ID-05-one-result-reused-across-two-obligations", True,
     "the same result is asserted as satisfying two distinct obligations", c_id_reuse)


def c_id_proof_result(g):
    o = obligation(g, "id6-obl")
    pr = n("id6-proofresult")
    g.add((pr, RDF.type, U.ProofResult))
    g.add((pr, U.hasProofResultState, URIRef("urn:usf:proofresultstate:successful")))
    g.add((pr, U.resultForValidationObligation, o))
    g.add((pr, U.resultState, PASSED))
    g.add((pr, U.usesAdmittedValidationEvidence, n("id6-ev")))
    g.add((pr, U.validationEvaluatedAuthorityDigest, GOOD_DIGEST))
    g.add((pr, U.validationEvaluatedSourceHead, GOOD_HEAD))
    g.add((o, U.satisfiedByValidationResult, pr))   # a ProofResult used as the satisfying result
    return [o, pr]


case("ID-06-ProofResult-used-as-the-satisfying-ValidationResult", True,
     "a ProofResult (not a ValidationResult) is asserted as satisfying a ValidationObligation",
     c_id_proof_result)


# ---------------------------------------------------------------- activation
def c_act_reserved(g):
    o = obligation(g, "ac1-obl", state=RESERVED)
    r = result(g, "ac1-res", o)
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r]


case("AC-01-satisfied-while-reserved", True, "reserved obligation is satisfied", c_act_reserved)


def c_act_blocked(g):
    o = obligation(g, "ac2-obl", state=BLOCKED)
    r = result(g, "ac2-res", o)
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r]


case("AC-02-satisfied-while-blocked", True, "blocked obligation is satisfied", c_act_blocked)


def c_act_missing(g):
    o = obligation(g, "ac3-obl", state=None)
    r = result(g, "ac3-res", o)
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r]


case("AC-03-satisfied-with-no-activation-state", True,
     "obligation with no activation state at all is satisfied", c_act_missing)


def c_act_multiple(g):
    o = obligation(g, "ac4-obl", state=ACTIVATED)
    g.add((o, U.hasValidationActivationState, RESERVED))
    r = result(g, "ac4-res", o)
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r]


case("AC-04-two-conflicting-activation-states", True,
     "obligation asserts both activated and reserved, and is satisfied", c_act_multiple)


def c_act_unknown_value(g):
    # A newly-minted activation value, typed with the controlled class.
    novel = URIRef("urn:usf:validationactivationstate:autoactivated")
    g.add((novel, RDF.type, U.ValidationObligationActivationState))
    g.add((novel, U.canonicalName, Literal("autoactivated")))
    o = obligation(g, "ac5-obl", state=novel)
    r = result(g, "ac5-res", o)
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r, novel]


case("AC-05-novel-activation-value-bypasses-reserved-blocked-gate", True,
     "a 4th activation value outside {reserved, activated, blocked} permits satisfaction",
     c_act_unknown_value)


def c_act_bare_activated(g):
    # activated asserted with NO prerequisite, reason, authority, event, time or traceability
    o = obligation(g, "ac6-obl", state=ACTIVATED)
    r = result(g, "ac6-res", o)
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r]


case("AC-06-bare-activated-without-any-activation-authority", True,
     "activation asserted with no prerequisite, reason, authority, event, time or traceability",
     c_act_bare_activated)


# ------------------------------------------------------- authority / source
def c_dg_empty(g):
    o = obligation(g, "dg1-obl")
    r = result(g, "dg1-res", o, digest=Literal(""), head=Literal(""))
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r]


case("DG-01-empty-string-digest-and-head", True,
     "satisfying result binds empty-string authority digest and source head", c_dg_empty)


def c_dg_malformed(g):
    o = obligation(g, "dg2-obl")
    r = result(g, "dg2-res", o, digest=Literal("not-a-digest"), head=Literal("HEAD"))
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r]


case("DG-02-malformed-digest-and-head", True,
     "satisfying result binds a non-digest literal and a symbolic source head", c_dg_malformed)


def c_dg_wrong_datatype(g):
    o = obligation(g, "dg3-obl")
    r = result(g, "dg3-res", o, digest=Literal(12345), head=Literal(True))
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r]


case("DG-03-wrong-datatype-digest-and-head", True,
     "satisfying result binds xsd:integer digest and xsd:boolean source head", c_dg_wrong_datatype)


def c_dg_wrong_length(g):
    o = obligation(g, "dg4-obl")
    r = result(g, "dg4-res", o, digest=Literal("sha256:abc"), head=Literal("163790"))
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r]


case("DG-04-truncated-digest-and-short-head", True,
     "satisfying result binds a truncated sha256 digest and an abbreviated commit", c_dg_wrong_length)


def c_dg_wrong_algorithm(g):
    o = obligation(g, "dg5-obl")
    r = result(g, "dg5-res", o, digest=Literal("md5:" + "0" * 32))
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r]


case("DG-05-wrong-digest-algorithm", True,
     "satisfying result binds an md5 digest instead of sha256", c_dg_wrong_algorithm)


def c_dg_nonexistent_commit(g):
    o = obligation(g, "dg6-obl")
    r = result(g, "dg6-res", o, head=Literal("f" * 40))
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r]


case("DG-06-well-formed-but-nonexistent-commit", True,
     "satisfying result binds a well-formed source head that is not a real commit",
     c_dg_nonexistent_commit)


def c_dg_stale_but_wellformed(g):
    o = obligation(g, "dg7-obl")
    # A genuinely old but well-formed authority digest and a real older commit.
    r = result(g, "dg7-res", o,
               digest=Literal("sha256:d246f0510000000000000000000000000000000000000000000000000000dead"),
               head=Literal("36b28b5c5371770e4c5ce43598d8824279628ed5"))
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r]


case("DG-07-stale-authority-digest-and-old-source-head", True,
     "satisfying result binds an OLD authority digest and an OLD source head and keeps satisfying",
     c_dg_stale_but_wellformed)


def c_dg_multivalued(g):
    o = obligation(g, "dg8-obl")
    r = result(g, "dg8-res", o)
    g.add((r, U.validationEvaluatedAuthorityDigest, Literal("sha256:" + "b" * 64)))
    g.add((r, U.validationEvaluatedSourceHead, Literal("0" * 40)))
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r]


case("DG-08-multivalued-digest-and-head", True,
     "satisfying result binds two different authority digests and two source heads", c_dg_multivalued)


# ------------------------------------------------------------ directionality
def c_dir_result_only(g):
    o = obligation(g, "dr1-obl")
    r = result(g, "dr1-res", o)
    # resultForValidationObligation asserted, satisfiedByValidationResult NOT asserted
    return [o, r]


case("DR-01-resultFor-without-satisfiedBy", False,
     "result binds the obligation but the obligation does not assert satisfaction (no closure claimed)",
     c_dir_result_only)


def c_dir_satisfied_only(g):
    o = obligation(g, "dr2-obl")
    r = n("dr2-res")
    g.add((r, RDF.type, U.ValidationResult))
    g.add((r, U.entersEvidenceLifecycleAs, n("dr2-ve")))
    g.add((n("dr2-ve"), RDF.type, U.ValidationEvidence))
    g.add((r, U.resultState, PASSED))
    g.add((r, U.usesAdmittedValidationEvidence, n("dr2-ev")))
    g.add((r, U.validationEvaluatedAuthorityDigest, GOOD_DIGEST))
    g.add((r, U.validationEvaluatedSourceHead, GOOD_HEAD))
    g.add((o, U.satisfiedByValidationResult, r))   # no resultForValidationObligation
    return [o, r]


case("DR-02-satisfiedBy-without-resultFor", True,
     "obligation asserts satisfaction from a result that binds no obligation", c_dir_satisfied_only)


def c_dir_multiple_satisfying(g):
    o = obligation(g, "dr3-obl")
    r1 = result(g, "dr3-res1", o)
    r2 = result(g, "dr3-res2", o)
    g.add((o, U.satisfiedByValidationResult, r1))
    g.add((o, U.satisfiedByValidationResult, r2))
    return [o, r1, r2]


case("DR-03-two-different-satisfying-results", True,
     "one obligation is satisfied by two distinct results at once", c_dir_multiple_satisfying)


def c_dir_superseded_still_satisfying(g):
    o = obligation(g, "dr4-obl")
    old = result(g, "dr4-old", o)
    new = result(g, "dr4-new", o)
    g.add((old, U.supersededByValidationResult, new))
    g.add((o, U.satisfiedByValidationResult, old))   # superseded result still claimed
    return [o, old, new]


case("DR-04-superseded-result-still-satisfying", True,
     "a superseded historical result remains the satisfying result", c_dir_superseded_still_satisfying)


def c_dir_invalidated_still_satisfying(g):
    o = obligation(g, "dr5-obl")
    r = result(g, "dr5-res", o)
    g.add((r, U.hasValidationInvalidationCondition,
           URIRef("urn:usf:validationinvalidationcondition:authoritydigestchanged")))
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r]


case("DR-05-invalidated-result-still-satisfying", True,
     "an invalidated result remains the satisfying result", c_dir_invalidated_still_satisfying)


# -------------------------------------------------------- control-plane nonclaim
def c_np_execution_only(g):
    o = obligation(g, "np1-obl")
    ex = n("np1-exec")
    g.add((ex, RDF.type, U.ValidationExecution))
    g.add((ex, U.executesValidation, o))
    g.add((o, U.satisfiedByValidationResult, ex))   # execution asserted as satisfying
    return [o, ex]


case("NP-01-ValidationExecution-as-satisfying-object", True,
     "a ValidationExecution is asserted as the satisfying result", c_np_execution_only)


def c_np_receipt(g):
    o = obligation(g, "np2-obl")
    rc = n("np2-receipt")
    g.add((rc, RDF.type, U.MaterialisationReceipt))
    g.add((o, U.satisfiedByValidationResult, rc))
    return [o, rc]


case("NP-02-control-plane-receipt-as-satisfying-object", True,
     "a materialisation (control-plane) receipt is asserted as the satisfying result", c_np_receipt)


def c_np_lifecycle_state(g):
    o = obligation(g, "np3-obl", state=RESERVED)
    g.add((o, U.semanticLifecycleState, URIRef("urn:usf:semanticlifecyclestate:active")))
    return [o]


case("NP-03-semanticLifecycleState-on-an-obligation", True,
     "obligation re-introduces semanticLifecycleState as a closure signal", c_np_lifecycle_state)


# ----------------------------------------------------- sibling family probes
def c_pf_proof_digest(g):
    # ProofAuthorityBinding comparator: malformed digest must be rejected.
    b = n("pf1-binding")
    pr = n("pf1-proofresult")
    g.add((b, RDF.type, U.ProofAuthorityBinding))
    g.add((b, U.bindingEvaluatedAuthorityDigest, Literal("not-a-digest")))
    g.add((pr, RDF.type, U.ProofResult))
    g.add((pr, U.hasAuthorityBinding, b))
    return [b, pr]


case("PF-01-ProofAuthorityBinding-malformed-digest", True,
     "comparator: the proof family rejects a malformed evaluated-authority digest", c_pf_proof_digest)


def c_pf_evidence_supersession(g):
    # Evidence supersession has no closure effect anywhere.
    e1 = n("pf2-ev1")
    e2 = n("pf2-ev2")
    for e in (e1, e2):
        g.add((e, RDF.type, U.EvidenceResult))
        g.add((e, U.hasAdmissionState, URIRef("urn:usf:evidenceadmissionstate:admitted")))
    g.add((e2, U.supersedesEvidence, e1))
    g.add((e1, U.isSupersededByEvidence, e2))
    g.add((e1, U.hasFreshnessState, URIRef("urn:usf:evidencefreshnessstate:fresh")))
    return [e1, e2]


case("PF-02-superseded-evidence-still-admitted-and-fresh", True,
     "comparator: superseded evidence keeps admitted+fresh with no invalidation effect",
     c_pf_evidence_supersession)


# ============================ round 2: conformant-node probes ===============
# Round 1 showed several rejections came from the fixture evidence node failing
# EvidenceResultShape, not from the satisfaction contract. These cases cite
# REAL, fully shape-conformant nodes from the live model so the only thing under
# test is the satisfaction contract itself.

REAL_EVIDENCE_PROOFONLY = URIRef("urn:usf:evidenceresult:compilerhermeticsubstituteruntime")
REAL_EVIDENCE_MATERIALISATION = URIRef("urn:usf:evidenceresult:repositorymaterialisationcontrolplane")
REAL_CONTRACT = URIRef("urn:usf:semanticcontract:compilersemanticenforcement")
REAL_PROOF_RESULT_OBL = URIRef("urn:usf:proofobligation:compilersemantics")


def c_r2_inapplicable_real_evidence(g):
    o = obligation(g, "r2aobl")
    r = result(g, "r2ares", o, evidence=REAL_EVIDENCE_PROOFONLY)
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r]


case("EV-11-real-admitted-evidence-not-applicable-to-this-obligation", True,
     "satisfaction cites a real admitted/fresh/valid EvidenceResult that is applicable only to "
     "unrelated proof obligations", c_r2_inapplicable_real_evidence)


def c_r2_contract_as_evidence(g):
    o = obligation(g, "r2bobl")
    r = result(g, "r2bres", o, evidence=REAL_CONTRACT)
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r]


case("EV-12-a-SemanticContract-cited-as-admitted-validation-evidence", True,
     "satisfaction cites a fully conformant SemanticContract as its admitted validation evidence",
     c_r2_contract_as_evidence)


def c_r2_declared_novel_result_state(g):
    novel = URIRef("urn:usf:resultstate:probablyfine")
    g.add((novel, RDF.type, U.ResultState))
    g.add((novel, U.canonicalName, Literal("probablyfine")))
    o = obligation(g, "r2cobl")
    r = result(g, "r2cres", o, state=[PASSED, novel])
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r, novel]


case("RS-05-declared-novel-result-state-alongside-passed", True,
     "a satisfying result carries passed plus a properly DECLARED novel result state",
     c_r2_declared_novel_result_state)


def c_r2_declared_novel_activation(g):
    novel = URIRef("urn:usf:validationactivationstate:autoactivated")
    g.add((novel, RDF.type, U.ValidationObligationActivationState))
    g.add((novel, U.canonicalName, Literal("autoactivated")))
    o = obligation(g, "r2dobl", state=novel)
    r = result(g, "r2dres", o)
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r, novel]


case("AC-07-properly-declared-4th-activation-value-permits-satisfaction", True,
     "a declared 4th ValidationObligationActivationState is neither reserved nor blocked, so the "
     "closure gate does not apply", c_r2_declared_novel_activation)


def c_r2_untyped_subject(g):
    # A subject that is NOT typed usf:ValidationObligation still asserts satisfaction.
    o = n("r2eobl")
    g.add((o, U.hasValidationActivationState, RESERVED))
    g.add((o, U.validationForContract, CONTRACT))
    r = result(g, "r2eres", o)
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r]


case("AC-08-untyped-subject-escapes-activation-and-identity-shapes", True,
     "a subject not typed usf:ValidationObligation asserts satisfaction while reserved",
     c_r2_untyped_subject)


def c_r2_real_obligation_satisfied(g):
    # The real materialisation obligation, satisfied by the real control-plane evidence.
    o = URIRef("urn:usf:validationobligation:repositoryexternalartefactmaterialisation")
    r = result(g, "r2fres", o, evidence=REAL_EVIDENCE_MATERIALISATION)
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r]


case("NP-04-real-reserved-obligation-satisfied-by-real-control-plane-evidence", True,
     "the live materialisation obligation is claimed satisfied using its real control-plane evidence",
     c_r2_real_obligation_satisfied)


def c_r2_activated_real_obligation(g):
    # Flip the real obligation to activated and satisfy it: does anything else object?
    o = URIRef("urn:usf:validationobligation:repositoryexternalartefactmaterialisation")
    g.remove((o, U.hasValidationActivationState, RESERVED))
    g.add((o, U.hasValidationActivationState, ACTIVATED))
    r = result(g, "r2gres", o, evidence=REAL_EVIDENCE_MATERIALISATION)
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r]


case("AC-09-real-obligation-flipped-to-activated-then-satisfied", True,
     "a bare activation flip on the live obligation is enough to close it with control-plane evidence",
     c_r2_activated_real_obligation)


def c_r2_stale_digest_real(g):
    # Well-formed but superseded authority digest on the live obligation.
    o = URIRef("urn:usf:validationobligation:compilersemanticenforcement")
    g.remove((o, U.hasValidationActivationState, RESERVED))
    g.add((o, U.hasValidationActivationState, ACTIVATED))
    r = result(g, "r2hres", o, evidence=REAL_EVIDENCE_PROOFONLY,
               digest=Literal("sha256:d246f051" + "0" * 56),
               head=Literal("5593612158cc421ee9d8b1e9e10a268b693e1434"))
    g.add((o, U.satisfiedByValidationResult, r))
    return [o, r]


case("DG-09-live-obligation-closed-against-a-superseded-authority-digest", True,
     "a live obligation is closed by a result bound to the SUPERSEDED authority digest and an "
     "older source head", c_r2_stale_digest_real)


# ================== round 3: contradictory controlled values ================
# Cross-family probe: add a CONTRADICTORY second controlled value to a real,
# currently-conformant live node. Nothing is removed; only one triple is added.

REAL_CONTRACT_ACTIVE = URIRef("urn:usf:semanticcontract:repositoryexternalartefactmaterialisation")
REAL_PROOF_RESULT = URIRef("urn:usf:proofresult:repositorymaterialisationcontrolplane")
REAL_EV = URIRef("urn:usf:evidenceresult:repositorymaterialisationcontrolplane")


def c_cv_contract_active_and_retired(g):
    g.add((REAL_CONTRACT_ACTIVE, U.hasActivationState,
           URIRef("urn:usf:contractactivationstate:retired")))
    return [REAL_CONTRACT_ACTIVE]


case("CV-01-contract-active-and-retired-simultaneously", True,
     "a live active SemanticContract also asserts contractactivationstate:retired",
     c_cv_contract_active_and_retired)


def c_cv_proof_successful_and_failed(g):
    g.add((REAL_PROOF_RESULT, U.hasProofResultState, URIRef("urn:usf:proofresultstate:failed")))
    return [REAL_PROOF_RESULT]


case("CV-02-proof-result-successful-and-failed-simultaneously", True,
     "a live successful ProofResult also asserts proofresultstate:failed",
     c_cv_proof_successful_and_failed)


def c_cv_evidence_admitted_and_rejected(g):
    g.add((REAL_EV, U.hasAdmissionState, URIRef("urn:usf:evidenceadmissionstate:rejected")))
    return [REAL_EV]


case("CV-03-evidence-admitted-and-rejected-simultaneously", True,
     "a live admitted EvidenceResult also asserts evidenceadmissionstate:rejected",
     c_cv_evidence_admitted_and_rejected)


def c_cv_evidence_fresh_and_stale(g):
    g.add((REAL_EV, U.hasFreshnessState, URIRef("urn:usf:evidencefreshnessstate:stale")))
    g.add((REAL_EV, U.hasIntegrityState, URIRef("urn:usf:evidenceintegritystate:invalid")))
    return [REAL_EV]


case("CV-04-evidence-fresh-and-stale-valid-and-invalid", True,
     "a live fresh valid EvidenceResult also asserts stale and integrity-invalid",
     c_cv_evidence_fresh_and_stale)


def c_cv_novel_contract_activation(g):
    novel = URIRef("urn:usf:contractactivationstate:provisionallyactive")
    g.add((novel, RDF.type, U.ContractActivationState))
    g.add((novel, U.canonicalName, Literal("provisionallyactive")))
    c = n("cv5contract")
    g.add((c, RDF.type, U.SemanticContract))
    g.add((c, U.hasActivationState, novel))
    return [c, novel]


case("CV-05-novel-declared-contract-activation-state", True,
     "a newly declared 8th ContractActivationState is accepted on a contract",
     c_cv_novel_contract_activation)


def run_case(spec):
    g = Graph()
    for triple in BASE:
        g.add(triple)
    _MINTED.clear()
    focus = spec["build"](g)
    finish(g)
    focus_iris = [str(x) for x in focus if isinstance(x, URIRef)]
    conforms, report, text = validate(
        g, shacl_graph=SHAPES, advanced=True, allow_infos=False, allow_warnings=False,
        abort_on_first=False, focus_nodes=focus_iris, iterate_rules=False, inplace=False,
        meta_shacl=False,
    )
    violations = []
    for res in report.subjects(RDF.type, SH.ValidationResult):
        violations.append({
            "focus": str(report.value(res, SH.focusNode) or ""),
            "shape": str(report.value(res, SH.sourceShape) or ""),
            "path": str(report.value(res, SH.resultPath) or ""),
            "message": str(report.value(res, SH.resultMessage) or "")[:160],
        })
    scope = set(focus_iris)
    fixture_violations = [v for v in violations if FX in v["focus"] or v["focus"] in scope]
    rejected = len(fixture_violations) > 0
    return {
        "id": spec["id"],
        "mustReject": spec["mustReject"],
        "rejected": rejected,
        "outcome": "EXPECTED" if rejected == spec["mustReject"] else "DEFECT",
        "violationCount": len(fixture_violations),
        "shapes": sorted({v["shape"] for v in fixture_violations}),
        "messages": sorted({v["message"] for v in fixture_violations})[:4],
        "description": spec["description"],
    }


selected = sys.argv[1:] if len(sys.argv) > 1 else None
results = []
for spec in CASES:
    if selected and spec["id"] not in selected:
        continue
    try:
        results.append(run_case(spec))
    except Exception as exc:  # noqa: BLE001
        results.append({"id": spec["id"], "outcome": "HARNESS_ERROR",
                        "error": f"{exc.__class__.__name__}:{exc}"[:400]})
    r = results[-1]
    print(f"{r.get('outcome','?'):>14}  {r['id']:<58} "
          f"mustReject={r.get('mustReject')} rejected={r.get('rejected')} "
          f"n={r.get('violationCount')}", flush=True)

print()
defects = [r for r in results if r.get("outcome") == "DEFECT"]
print(f"cases={len(results)} expected={len([r for r in results if r.get('outcome')=='EXPECTED'])} "
      f"defects={len(defects)} harnessErrors={len([r for r in results if r.get('outcome')=='HARNESS_ERROR'])}")
pathlib.Path(os.environ.get("USF_RESULTS", "/tmp/adversarial-results.json")).write_text(
    json.dumps(results, indent=1))
