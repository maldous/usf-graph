"""Controlled vocabularies for the factory.

These enums are the closed value sets the deterministic control plane relies on.
Keeping them explicit (rather than free strings) is what lets scoring,
conflict detection, and failure attribution stay deterministic and auditable.
"""

from __future__ import annotations

from enum import Enum


class StrEnum(str, Enum):
    """A string enum whose members compare/serialize as their value."""

    def __str__(self) -> str:  # pragma: no cover - trivial
        return str(self.value)


class AuthMode(StrEnum):
    """How a provider authenticates."""

    API_TOKEN = "api_token"
    OIDC_CLI = "oidc_cli"
    LOCAL = "local"  # e.g. Ollama on localhost, usually no key
    NONE = "none"


class PrivacyClass(StrEnum):
    """Data-privacy profile for a provider (governs egress decisions)."""

    LOCAL_ONLY = "local_only"
    EXTERNAL_CLOUD = "external_cloud"
    EXTERNAL_CLOUD_RETAINED = "external_cloud_retained"
    FIRST_PARTY_CLI = "first_party_cli"


class AdmissionRole(StrEnum):
    """Trust tier a qualified agent profile may hold for a given task class.

    Ordered from least to most privileged; higher roles subsume lower ones for
    read capabilities but each write capability is granted explicitly.
    """

    UNQUALIFIED = "UNQUALIFIED"
    READ_ONLY_ANALYST = "READ_ONLY_ANALYST"
    PLANNER_CANDIDATE = "PLANNER_CANDIDATE"
    PATCH_PRODUCER = "PATCH_PRODUCER"
    REVIEWER = "REVIEWER"
    INTEGRATOR = "INTEGRATOR"
    ADJUDICATOR = "ADJUDICATOR"
    TRUSTED_COORDINATOR = "TRUSTED_COORDINATOR"


# Rank for ordering/comparison. Higher = more privileged.
ADMISSION_RANK: dict[AdmissionRole, int] = {
    AdmissionRole.UNQUALIFIED: 0,
    AdmissionRole.READ_ONLY_ANALYST: 1,
    AdmissionRole.PLANNER_CANDIDATE: 2,
    AdmissionRole.PATCH_PRODUCER: 3,
    AdmissionRole.REVIEWER: 4,
    AdmissionRole.INTEGRATOR: 5,
    AdmissionRole.ADJUDICATOR: 6,
    AdmissionRole.TRUSTED_COORDINATOR: 7,
}


class Risk(StrEnum):
    """Risk classification for obligations, packets, and waves."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    PROTECTED = "protected"


class ConflictClass(StrEnum):
    """Relationship between two packets (build task §12)."""

    DISJOINT = "DISJOINT"
    READ_OVERLAP = "READ_OVERLAP"
    GENERATED_OUTPUT_OVERLAP = "GENERATED_OUTPUT_OVERLAP"
    WRITE_OVERLAP = "WRITE_OVERLAP"
    SEMANTIC_OVERLAP = "SEMANTIC_OVERLAP"
    AUTHORITY_DEPENDENT = "AUTHORITY_DEPENDENT"
    HUMAN_DECISION_REQUIRED = "HUMAN_DECISION_REQUIRED"


# Conflict classes that make two packets UNSAFE to run in the same wave.
UNSAFE_CONFLICTS: frozenset[ConflictClass] = frozenset(
    {
        ConflictClass.GENERATED_OUTPUT_OVERLAP,
        ConflictClass.WRITE_OVERLAP,
        ConflictClass.SEMANTIC_OVERLAP,
        ConflictClass.AUTHORITY_DEPENDENT,
        ConflictClass.HUMAN_DECISION_REQUIRED,
    }
)


class FailureClass(StrEnum):
    """Deterministic failure taxonomy for fair attribution (build task §15)."""

    PLANNER_ERROR = "PLANNER_ERROR"
    PACKET_COMPILER_ERROR = "PACKET_COMPILER_ERROR"
    WORKER_ERROR = "WORKER_ERROR"
    ADAPTER_ERROR = "ADAPTER_ERROR"
    PROVIDER_OUTAGE = "PROVIDER_OUTAGE"
    QUOTA_BLOCKED = "QUOTA_BLOCKED"
    STALE_PACKET = "STALE_PACKET"
    SCOPE_VIOLATION = "SCOPE_VIOLATION"
    VALIDATION_FAILURE = "VALIDATION_FAILURE"
    ENVIRONMENT_FAILURE = "ENVIRONMENT_FAILURE"
    UNCERTAIN_MUTATION = "UNCERTAIN_MUTATION"


# Failures NOT attributable to the worker (do not penalize the worker).
NON_WORKER_FAULTS: frozenset[FailureClass] = frozenset(
    {
        FailureClass.PLANNER_ERROR,
        FailureClass.PACKET_COMPILER_ERROR,
        FailureClass.PROVIDER_OUTAGE,
        FailureClass.QUOTA_BLOCKED,
        FailureClass.STALE_PACKET,
        FailureClass.ENVIRONMENT_FAILURE,
    }
)


class CycleState(StrEnum):
    """States of the deterministic cycle state machine (build task §10, §22)."""

    INIT = "INIT"
    READY = "READY"
    BLOCKED = "BLOCKED"
    SNAPSHOT = "SNAPSHOT"
    PLANNED = "PLANNED"
    COMPILED = "COMPILED"
    SCHEDULED = "SCHEDULED"
    EXECUTING = "EXECUTING"
    INTEGRATING = "INTEGRATING"
    REVIEWING = "REVIEWING"
    VALIDATING = "VALIDATING"
    LEARNED = "LEARNED"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    PAUSED = "PAUSED"
    NO_PROGRESS = "NO_PROGRESS"


class RunMode(StrEnum):
    """Operating modes (build task §18, DESIGN Phase 7)."""

    OBSERVE = "observe"
    PLAN_ONLY = "plan-only"
    SHADOW = "shadow"
    APPROVE_WAVE = "approve-wave"
    AUTONOMOUS_SAFE = "autonomous-safe"


class ProtectedAction(StrEnum):
    """Actions requiring an explicit gate; all disabled by default."""

    PAID_INFERENCE = "paid_inference"
    SOURCE_EGRESS = "source_egress"
    MAIN_INTEGRATION = "main_integration"
    PUSH_PR = "push_pr"
    STARDOG_PUBLICATION = "stardog_publication"
    RISK_ACCEPTANCE = "risk_acceptance"
    TERMINAL_COMPLETION = "terminal_completion"


class PacketResultStatus(StrEnum):
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    BLOCKED = "BLOCKED"
    HUMAN_DECISION_REQUIRED = "HUMAN_DECISION_REQUIRED"


class ProbeKind(StrEnum):
    """The ten mechanical probes (build task §8.1)."""

    TEXT_RESPONSE = "text_response"
    STRICT_JSON = "strict_json"
    FORCED_TOOL_CALL = "forced_tool_call"
    TOOL_RESULT_FOLLOWUP = "tool_result_followup"
    PROHIBITED_TOOL_COMPLIANCE = "prohibited_tool_compliance"
    IRI_PRESERVATION = "iri_preservation"
    DIGEST_PRESERVATION = "digest_preservation"
    EXPLICIT_UNCERTAINTY = "explicit_uncertainty"
    STOP_CONDITION = "stop_condition"
    PATCH_FORMAT = "patch_format"


class Modality(StrEnum):
    TEXT = "text"
    VISION = "vision"
    AUDIO = "audio"
    IMAGE_OUT = "image_out"


class HealthStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    UNAUTHENTICATED = "unauthenticated"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


# Task-specific metric dimensions (build task §8.2). Scores are always segmented
# by (agent_profile, task_class, dimension) — never a single universal score.
SCORE_DIMENSIONS: tuple[str, ...] = (
    "semantic_planning",
    "rdf_owl_reasoning",
    "shacl_sparql",
    "repository_navigation",
    "implementation",
    "debugging",
    "tool_selection",
    "structured_output",
    "scope_discipline",
    "evidence_discipline",
    "uncertainty_handling",
    "review",
    "wave_integration",
    "latency",
    "cost",
    "false_completion",
    "later_regression",
)
