"""Durable domain models (Pydantic v2).

These are the records that make the factory replayable: provider catalogues,
model records, agent profiles, qualification runs, semantic snapshots,
obligation graphs, packets, results, integration attempts, reviews, validation
and publication receipts, cycle receipts, routing decisions, and events.

Identity rule
-------------
Content-addressed records derive their id from their *semantic content*.
Volatile metadata (timestamps, provenance stamps) is excluded from the content
address via ``_volatile_fields`` so that identical state reproduces an identical
id — the basis of deterministic replay.
"""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field

from .canonical import content_digest, stable_id
from .enums import (
    AdmissionRole,
    AuthMode,
    ConflictClass,
    CycleState,
    FailureClass,
    HealthStatus,
    Modality,
    PacketResultStatus,
    PrivacyClass,
    ProbeKind,
    Risk,
)


class FactoryModel(BaseModel):
    """Base model with canonical content addressing."""

    model_config = ConfigDict(extra="forbid", frozen=False, populate_by_name=True)

    _volatile_fields: ClassVar[frozenset[str]] = frozenset()

    def content_dict(self) -> dict[str, Any]:
        """Identity-relevant, JSON-safe representation (volatile fields removed)."""
        exclude = set(self._volatile_fields) or None
        return self.model_dump(mode="json", exclude=exclude)

    def digest(self) -> str:
        return content_digest(self.content_dict())


# --------------------------------------------------------------------------- #
# Providers and models.
# --------------------------------------------------------------------------- #


class ProviderConfig(FactoryModel):
    """Static provider definition (from config/providers.yaml)."""

    provider_id: str
    display_name: str
    auth_mode: AuthMode
    credential_reference: str | None = None  # e.g. "env:OPENAI_API_KEY" or "cli:codex"
    adapter: str  # adapter kind key, e.g. "openai_compatible", "codex_cli"
    base_url: str | None = None
    models_endpoint: str | None = None
    catalog_ttl_s: int = 6 * 3600
    health_ttl_s: int = 5 * 60
    quota_ttl_s: int = 2 * 60
    privacy_class: PrivacyClass = PrivacyClass.EXTERNAL_CLOUD
    default_enabled: bool = False
    supports_tool_probe: bool = True
    supports_structured_output_probe: bool = True
    notes: str = ""

    def config_digest(self) -> str:
        return self.digest()


class DiscoveredModel(FactoryModel):
    """Raw model as reported by a provider adapter (a dated claim, not proof)."""

    provider_id: str
    requested_model_id: str
    display_name: str | None = None
    context_tokens: int | None = None
    output_tokens: int | None = None
    modalities: list[Modality] = Field(default_factory=lambda: [Modality.TEXT])
    claims_tools: bool | None = None
    claims_structured_output: bool | None = None
    claims_reasoning: bool | None = None
    claims_streaming: bool | None = None
    prompt_cost_per_mtok: float | None = None
    output_cost_per_mtok: float | None = None
    free: bool | None = None
    deprecation: str | None = None
    supported_parameters: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class ProviderHealth(FactoryModel):
    """A dated health observation for a provider."""

    provider_id: str
    status: HealthStatus
    detail: str = ""
    latency_ms: float | None = None
    observed_at: str = ""

    _volatile_fields = frozenset({"observed_at"})


class QuotaObservation(FactoryModel):
    provider_id: str
    remaining: int | None = None
    limit: int | None = None
    reset_at: str | None = None
    observed_at: str = ""

    _volatile_fields = frozenset({"observed_at"})


class ProviderCatalogueSnapshot(FactoryModel):
    """Content-addressed snapshot of a provider's model catalogue."""

    provider_id: str
    models: list[DiscoveredModel] = Field(default_factory=list)
    discovered_at: str = ""
    expires_at: str = ""
    source: str = ""  # adapter kind or endpoint used

    _volatile_fields = frozenset({"discovered_at", "expires_at"})

    @property
    def catalog_id(self) -> str:
        return stable_id("cat", self.content_dict())


class ModelRecord(FactoryModel):
    """Provider-independent normalized model record (build task §7)."""

    provider_id: str
    requested_model_id: str
    canonical_family: str
    display_name: str | None = None
    actual_model_id: str | None = None  # populated for routed providers
    catalogue_id: str = ""
    catalogue_digest: str = ""
    context_tokens: int | None = None
    output_tokens: int | None = None
    modalities: list[Modality] = Field(default_factory=lambda: [Modality.TEXT])
    claims_tools: bool | None = None
    claims_structured_output: bool | None = None
    claims_reasoning: bool | None = None
    claims_streaming: bool | None = None
    prompt_cost_per_mtok: float | None = None
    output_cost_per_mtok: float | None = None
    free: bool | None = None
    deprecation: str | None = None
    data_policy_class: PrivacyClass = PrivacyClass.EXTERNAL_CLOUD
    adapter: str = ""
    config_digest: str = ""
    discovered_at: str = ""

    _volatile_fields = frozenset({"discovered_at", "catalogue_id"})

    @property
    def model_key(self) -> str:
        return f"{self.provider_id}:{self.requested_model_id}"


class AgentProfile(FactoryModel):
    """The qualified agent identity (build task §7).

    A "model" is not an agent. Suitability attaches to the full tuple below.
    North through OpenCode and North through another harness are distinct
    profiles.
    """

    provider_id: str
    requested_model_id: str
    adapter: str
    auth_mode: AuthMode
    tool_profile: str = "default"
    prompt_version: str = "v1"
    context_config: str = "default"
    output_config: str = "default"

    @property
    def profile_id(self) -> str:
        return stable_id("agent", self.content_dict())


# --------------------------------------------------------------------------- #
# Probes and qualification.
# --------------------------------------------------------------------------- #


class ProbeSpec(FactoryModel):
    """A versioned mechanical probe (build task §8.1)."""

    kind: ProbeKind
    version: str = "v1"
    prompt: str = ""
    expected: dict[str, Any] = Field(default_factory=dict)
    permitted_tools: list[str] = Field(default_factory=list)
    prohibited_tools: list[str] = Field(default_factory=list)

    @property
    def probe_id(self) -> str:
        return stable_id("probe", self.content_dict())


class ProbeResult(FactoryModel):
    kind: ProbeKind
    version: str
    passed: bool
    score: float = 0.0
    detail: str = ""
    actual_model_id: str | None = None
    latency_ms: float | None = None
    observed_at: str = ""

    _volatile_fields = frozenset({"observed_at", "latency_ms"})


class QualificationCase(FactoryModel):
    """A single qualification fixture with a known answer (build task §8.2)."""

    case_id: str
    task_class: str
    dimension: str  # one of enums.SCORE_DIMENSIONS
    prompt: str
    grader: str  # grader kind: "exact", "json_schema", "contains", "iri_exact", ...
    expected: dict[str, Any] = Field(default_factory=dict)
    holdout: bool = False
    weight: float = 1.0
    notes: str = ""


class QualificationSuite(FactoryModel):
    suite_id: str
    version: str
    cases: list[QualificationCase] = Field(default_factory=list)

    def suite_digest(self) -> str:
        return self.digest()


class QualificationRun(FactoryModel):
    """Result of running the suite against one agent profile."""

    agent_profile_id: str
    suite_id: str
    suite_version: str
    dimension_scores: dict[str, float] = Field(default_factory=dict)
    task_class_scores: dict[str, float] = Field(default_factory=dict)
    cases_passed: int = 0
    cases_total: int = 0
    roles_admitted: list[AdmissionRole] = Field(default_factory=list)
    billable: bool = False
    ran_at: str = ""
    expires_at: str = ""

    _volatile_fields = frozenset({"ran_at", "expires_at"})


class ModelTaskScore(FactoryModel):
    """Task- and dimension-segmented score with confidence (build task §17)."""

    agent_profile_id: str
    task_class: str
    dimension: str
    mean: float = 0.0
    n: int = 0
    variance: float = 0.0
    ci_low: float = 0.0
    ci_high: float = 1.0
    updated_at: str = ""

    _volatile_fields = frozenset({"updated_at"})


# --------------------------------------------------------------------------- #
# Semantic snapshot.
# --------------------------------------------------------------------------- #


class SemanticSnapshot(FactoryModel):
    """Immutable, content-addressed USF semantic snapshot (DESIGN Phase 4).

    Compiled deterministically by the factory (not a model) via the USF MCP
    boundary + Git inspection. ``captured_at`` is metadata and excluded from the
    content address so identical state reproduces an identical snapshot id.
    """

    authority_digest: str
    graph_count: int | None = None
    triple_count: int | None = None
    repository_head: str
    working_tree_digest: str
    checkpoint_digest: str | None = None
    ledger_digest: str | None = None
    goal_digest: str | None = None
    active_phase: str | None = None
    unresolved_obligations: list[str] = Field(default_factory=list)
    admitted_evidence: list[str] = Field(default_factory=list)
    open_transactions: list[str] = Field(default_factory=list)
    # Compact programme obligations parsed from the MCP work-plan/bootstrap
    # contents (id + dependencies + task hints). Drives deterministic planning.
    programme_obligations: list[dict[str, Any]] = Field(default_factory=list)
    checkpoint_present: bool = False
    ledger_present: bool = False
    health_ok: bool = True
    mcp_tools: list[str] = Field(default_factory=list)
    captured_at: str = ""
    source: str = "usf-mcp"

    _volatile_fields = frozenset({"captured_at"})

    @property
    def snapshot_id(self) -> str:
        return stable_id("snap", self.content_dict())


# --------------------------------------------------------------------------- #
# Planning and obligations.
# --------------------------------------------------------------------------- #


class Obligation(FactoryModel):
    """An obligation in the planner's obligation graph (DESIGN Phase 5)."""

    id: str
    root_cause: str
    semantic_subjects: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    required_outcomes: list[str] = Field(default_factory=list)
    acceptance_criteria: list[str] = Field(default_factory=list)
    risk: Risk = Risk.MEDIUM
    task_class: str = "unknown"
    suggested_read_scope: list[str] = Field(default_factory=list)
    suggested_write_scope: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    human_decision_required: bool = False


class ObligationGraph(FactoryModel):
    snapshot_id: str
    obligations: list[Obligation] = Field(default_factory=list)
    planner_profile_id: str | None = None
    critic_profile_id: str | None = None
    critic_findings: list[str] = Field(default_factory=list)
    produced_at: str = ""

    _volatile_fields = frozenset({"produced_at"})

    @property
    def graph_id(self) -> str:
        return stable_id("oblg", self.content_dict())


# --------------------------------------------------------------------------- #
# Packets and conflicts.
# --------------------------------------------------------------------------- #


class RequiredCapabilities(FactoryModel):
    semantic_reasoning: float = 0.0
    rdf_owl: float = 0.0
    shacl_sparql: float = 0.0
    structured_output: float = 0.0
    repository_editing: bool = False
    min_context_tokens: int = 8000


class Packet(FactoryModel):
    """A content-addressed, deterministically compiled unit of work (§12)."""

    obligation_id: str
    snapshot_id: str
    authority_digest: str
    base_head: str
    objective: str
    task_class: str
    risk: Risk = Risk.MEDIUM
    semantic_subjects: list[str] = Field(default_factory=list)
    read_paths: list[str] = Field(default_factory=list)
    write_paths: list[str] = Field(default_factory=list)
    generated_outputs: list[str] = Field(default_factory=list)
    input_digests: dict[str, str] = Field(default_factory=dict)
    dependencies: list[str] = Field(default_factory=list)
    conflicts_with: list[str] = Field(default_factory=list)
    required_capabilities: RequiredCapabilities = Field(default_factory=RequiredCapabilities)
    acceptance_criteria: list[str] = Field(default_factory=list)
    required_validation: list[str] = Field(default_factory=list)
    permitted_tools: list[str] = Field(default_factory=list)
    data_classification: str = "private-source"
    human_decision_required: bool = False

    # conflicts_with is DERIVED from other packets, so it must not participate in
    # this packet's intrinsic content address.
    _volatile_fields = frozenset({"conflicts_with"})

    @property
    def packet_id(self) -> str:
        return stable_id("pkt", self.content_dict())


class ConflictEdge(FactoryModel):
    packet_a: str
    packet_b: str
    conflict_class: ConflictClass
    reason: str = ""


class PacketSet(FactoryModel):
    """A frozen wave: the first eligible antichain (DESIGN Phase 6)."""

    snapshot_id: str
    graph_id: str
    packets: list[Packet] = Field(default_factory=list)
    selected_packet_ids: list[str] = Field(default_factory=list)
    deferred_packet_ids: list[str] = Field(default_factory=list)
    conflicts: list[ConflictEdge] = Field(default_factory=list)
    compiled_at: str = ""

    _volatile_fields = frozenset({"compiled_at"})

    @property
    def set_id(self) -> str:
        return stable_id("pktset", self.content_dict())


# --------------------------------------------------------------------------- #
# Scheduling / routing.
# --------------------------------------------------------------------------- #


class RoutingCandidate(FactoryModel):
    agent_profile_id: str
    eligible: bool
    exclusion_reasons: list[str] = Field(default_factory=list)
    score: float = 0.0
    score_breakdown: dict[str, float] = Field(default_factory=dict)


class RoutingDecision(FactoryModel):
    packet_id: str
    task_class: str
    role: AdmissionRole
    selected_profile_id: str | None = None
    selection_kind: str = "exploit"  # exploit | second_tier | explore | none
    candidates: list[RoutingCandidate] = Field(default_factory=list)
    seed: str = ""
    decided_at: str = ""

    _volatile_fields = frozenset({"decided_at"})


# --------------------------------------------------------------------------- #
# Execution results.
# --------------------------------------------------------------------------- #


class AgentRequest(FactoryModel):
    agent_profile_id: str
    packet_id: str
    instructions: str
    # Explicit routing — never recovered by parsing the opaque agent_profile_id.
    provider_id: str = ""
    requested_model_id: str = ""
    adapter_id: str = ""
    tool_profile_id: str = "default"
    prompt_version: str = "v1"
    packet_json: dict[str, Any] = Field(default_factory=dict)
    permitted_tools: list[str] = Field(default_factory=list)
    result_schema: dict[str, Any] = Field(default_factory=dict)
    max_wall_s: int = 7200

    def model_id_for(self, fallback: str) -> str:
        """The model id to send to the provider. Explicit field wins; fallback is
        used only when the field is unset (e.g. legacy callers)."""
        return self.requested_model_id or fallback


class AgentResponse(FactoryModel):
    agent_profile_id: str
    actual_provider: str | None = None
    actual_model: str | None = None
    output_text: str = ""
    structured: dict[str, Any] = Field(default_factory=dict)
    tokens_in: int | None = None
    tokens_out: int | None = None
    cost_usd: float = 0.0
    latency_ms: float | None = None
    error: str | None = None


class PacketResult(FactoryModel):
    """A worker's structured result (DESIGN Phase 10)."""

    packet_id: str
    status: PacketResultStatus
    agent_profile_id: str
    actual_provider: str | None = None
    actual_model: str | None = None
    base_head: str = ""
    snapshot_id: str = ""
    patch_digest: str | None = None
    patch_ref: str | None = None  # CAS ref, not the patch content
    changed_paths: list[str] = Field(default_factory=list)
    semantic_subjects_changed: list[str] = Field(default_factory=list)
    tests_run: list[str] = Field(default_factory=list)
    evidence_produced: list[str] = Field(default_factory=list)
    obligations_closed: list[str] = Field(default_factory=list)
    obligations_discovered: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    scope_violation: bool = False
    failure_class: FailureClass | None = None
    failure_detail: str = ""
    produced_at: str = ""

    _volatile_fields = frozenset({"produced_at"})


class ResultQualification(FactoryModel):
    """Deterministic verdict on a packet result (DESIGN Phase 10)."""

    packet_id: str
    accepted: bool
    checks: dict[str, bool] = Field(default_factory=dict)
    failure_class: FailureClass | None = None
    reasons: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Integration, review, validation, publication.
# --------------------------------------------------------------------------- #


class Attribution(FactoryModel):
    worker_patch_digest: str | None = None
    lines_preserved: int = 0
    lines_modified_by_integrator: int = 0
    lines_discarded: int = 0
    semantic_subjects_preserved: list[str] = Field(default_factory=list)
    integrator_rewrite_ratio: float = 0.0
    reason: str = ""


class IntegrationAttempt(FactoryModel):
    set_id: str
    accepted_packet_ids: list[str] = Field(default_factory=list)
    deterministic_merge_ok: bool = False
    semantic_conflicts: list[str] = Field(default_factory=list)
    used_ai_integrator: bool = False
    integrator_profile_id: str | None = None
    wave_patch_digest: str | None = None
    attributions: dict[str, Attribution] = Field(default_factory=dict)
    attempted_at: str = ""

    _volatile_fields = frozenset({"attempted_at"})


class WavePatch(FactoryModel):
    set_id: str
    patch_digest: str
    patch_ref: str | None = None
    changed_paths: list[str] = Field(default_factory=list)
    semantic_subjects: list[str] = Field(default_factory=list)


class WaveReview(FactoryModel):
    set_id: str
    reviewer_profile_id: str | None = None
    advisory: bool = True  # review is never proof
    findings: list[str] = Field(default_factory=list)
    risk_flags: list[str] = Field(default_factory=list)
    reviewed_at: str = ""

    _volatile_fields = frozenset({"reviewed_at"})


class ValidationReceipt(FactoryModel):
    set_id: str
    gates: dict[str, bool] = Field(default_factory=dict)
    all_passed: bool = False
    detail: dict[str, str] = Field(default_factory=dict)
    validated_at: str = ""

    _volatile_fields = frozenset({"validated_at"})


class PublicationReceipt(FactoryModel):
    """Publication is gated + disabled by default; this records the (no-op) state."""

    set_id: str
    published: bool = False
    gate_enabled: bool = False
    authority_digest_before: str | None = None
    authority_digest_after: str | None = None
    reason: str = "publication gate disabled by default"
    receipt_at: str = ""

    _volatile_fields = frozenset({"receipt_at"})


# --------------------------------------------------------------------------- #
# Cycle receipt & events.
# --------------------------------------------------------------------------- #


class CycleReceipt(FactoryModel):
    cycle_id: str
    mode: str
    state: CycleState
    snapshot_id: str | None = None
    graph_id: str | None = None
    set_id: str | None = None
    selected_packets: int = 0
    accepted_packets: int = 0
    published: bool = False
    no_progress: bool = False
    blockers: list[str] = Field(default_factory=list)
    started_at: str = ""
    ended_at: str = ""

    _volatile_fields = frozenset({"started_at", "ended_at"})


class DeliveryArtifact(FactoryModel):
    """A prepared (but NOT pushed) delivery of an accepted wave to usf-graph."""

    set_id: str
    prepared: bool = False
    gate_enabled: bool = False
    branch: str | None = None
    pr_title: str | None = None
    pr_body: str | None = None
    wave_patch_ref: str | None = None
    reason: str = ""
    prepared_at: str = ""

    _volatile_fields = frozenset({"prepared_at"})


class Event(FactoryModel):
    """An append-only event log entry."""

    cycle_id: str | None = None
    kind: str
    stage: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)
    at: str = ""

    _volatile_fields = frozenset({"at"})
