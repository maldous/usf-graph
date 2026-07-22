"""Configuration loading and validation.

Loads the YAML files under ``config/`` into validated Pydantic settings. Missing
or malformed configuration is a hard error (fail closed). Nothing here contains
secrets — only variable *references* like ``env:OPENAI_API_KEY``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from .enums import AdmissionRole, Risk, RunMode
from .errors import ConfigError
from .models import ProviderConfig
from .paths import bundled_config_dir


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RoutingConfig(_Base):
    exploit_pct: float = 0.85
    second_tier_pct: float = 0.10
    explore_pct: float = 0.05
    default_seed: str = "usf-factory"
    disable_exploration_for_risk: list[Risk] = Field(
        default_factory=lambda: [Risk.HIGH, Risk.PROTECTED]
    )
    weights: dict[str, float] = Field(
        default_factory=lambda: {
            "expected_success": 1.0,
            "task_class_success": 1.0,
            "tool_reliability": 0.5,
            "scope_discipline": 0.5,
            "latency": -0.2,
            "cost": -0.5,
            "quota_risk": -0.3,
            "provider_diversity": 0.2,
        }
    )

    def validate_split(self) -> None:
        total = self.exploit_pct + self.second_tier_pct + self.explore_pct
        if abs(total - 1.0) > 1e-6:
            raise ConfigError(f"routing exploration split must sum to 1.0, got {total:.4f}")


class RoleThreshold(_Base):
    """Minimum dimension scores required to hold a role for a task class."""

    min_scores: dict[str, float] = Field(default_factory=dict)


class TrustPolicy(_Base):
    # role -> {dimension: min_score}
    role_thresholds: dict[AdmissionRole, RoleThreshold] = Field(default_factory=dict)
    # newly discovered models never get write access automatically.
    default_role: AdmissionRole = AdmissionRole.UNQUALIFIED
    write_roles: list[AdmissionRole] = Field(
        default_factory=lambda: [
            AdmissionRole.PATCH_PRODUCER,
            AdmissionRole.INTEGRATOR,
            AdmissionRole.TRUSTED_COORDINATOR,
        ]
    )
    qualification_expiry_days: int = 30


class EgressPolicy(_Base):
    # data_classification -> allowed privacy classes
    allowed: dict[str, list[str]] = Field(default_factory=dict)
    source_egress_enabled: bool = False  # protected; only via --allow-source-egress
    default_data_classification: str = "private-source"
    # Per-provider overrides: provider_id -> explicitly approved data classifications
    # (with retention/terms evidence recorded out of band). A provider NOT listed
    # here may never receive private-source, even if its privacy class would allow.
    provider_overrides: dict[str, list[str]] = Field(default_factory=dict)

    def is_allowed(self, data_classification: str, privacy_class: str) -> bool:
        allowed = self.allowed.get(data_classification, [])
        return privacy_class in allowed

    def provider_approved_for(self, provider_id: str, data_classification: str) -> bool:
        """True iff this specific provider is explicitly approved for the class.

        local_only never needs approval (it does not egress). For private-source
        and stricter classes, an explicit per-provider approval is required in
        addition to the privacy-class rule."""
        return data_classification in self.provider_overrides.get(provider_id, [])

    def source_content_allowed(self, provider_id: str, privacy_class: str) -> tuple[bool, str]:
        """May raw repository source CONTENT be returned to this provider?

        Mirrors the scheduler's private-source rule so the tool broker can
        recheck egress on every content-returning tool call (defense in depth):
        local providers are always fine; a non-local provider needs the
        privacy-class/override rule, the global source-egress gate, AND an
        explicit per-provider approval."""
        if privacy_class == "local_only":
            return True, "local-only provider (no egress)"
        class_ok = self.is_allowed("private-source", privacy_class)
        provider_ok = self.provider_approved_for(provider_id, "private-source")
        if not (class_ok or provider_ok):
            return False, f"egress not allowed: private-source -> {privacy_class}"
        if not self.source_egress_enabled:
            return False, "source egress disabled"
        if not provider_ok:
            return False, f"provider {provider_id} not approved for private-source"
        return True, "explicitly approved"


class TaskClassDef(_Base):
    task_class: str
    display_name: str = ""
    description: str = ""
    default_risk: Risk = Risk.MEDIUM
    primary_dimensions: list[str] = Field(default_factory=list)
    required_capabilities: dict[str, Any] = Field(default_factory=dict)
    default_validation: list[str] = Field(default_factory=list)
    max_files: int = 20
    max_semantic_subjects: int = 25
    # Scope authority: ONLY a task class the operator explicitly marks here may
    # take its write scope from the planner's suggestion (an operator-approved,
    # committed definition). Semantic packets NEVER do — their writes come from
    # the snapshot-bound materialisation contract alone.
    planner_write_scope_allowed: bool = False
    # Explicitly low-risk mechanical work may proceed without substantive wave
    # review; everything else with a patch requires a real reviewer.
    mechanical: bool = False


class TaskClassConfig(_Base):
    task_classes: list[TaskClassDef] = Field(default_factory=list)

    def by_name(self) -> dict[str, TaskClassDef]:
        return {t.task_class: t for t in self.task_classes}


class BudgetConfig(_Base):
    billable_usd: float = 0.0
    free_daily_request_limit: int = 500
    max_packet_wall_s: int = 2 * 3600
    max_planner_wall_s: int = 30 * 60
    max_critic_wall_s: int = 30 * 60
    max_reviewer_wall_s: int = 30 * 60
    max_integration_wall_s: int = 2 * 3600
    max_validation_wall_s: int = 2 * 3600
    # The initial coordinator lease must cover the SYNCHRONOUS preflight phase
    # (mirror fetch, recovery), during which the heartbeat cannot renew it.
    max_preflight_wall_s: int = 900
    max_no_progress_cycles: int = 2


class QualificationConfig(_Base):
    suite_version: str = "v1"
    corpus_dir: str = "qualifications"
    holdout_dir: str = "qualifications/holdout"
    expiry_days: int = 30
    allow_billable: bool = False
    default_probe_budget_usd: float = 0.0


class ProvidersConfig(_Base):
    exclude: list[str] = Field(default_factory=list)
    providers: list[ProviderConfig] = Field(default_factory=list)

    def enabled_provider_ids(self) -> list[str]:
        return [p.provider_id for p in self.providers if p.default_enabled]

    def by_id(self) -> dict[str, ProviderConfig]:
        return {p.provider_id: p for p in self.providers}


class SafetyConfig(_Base):
    """Protected-action gates. All disabled by default."""

    allow_billable: bool = False
    allow_source_egress: bool = False
    allow_main_integration: bool = False
    allow_push_pr: bool = False
    allow_stardog_publication: bool = False
    allow_risk_acceptance: bool = False
    allow_terminal_completion: bool = False
    autonomous_safe_enabled: bool = False
    default_mode: RunMode = RunMode.OBSERVE


class FactoryConfig(_Base):
    providers: ProvidersConfig
    routing: RoutingConfig
    trust: TrustPolicy
    egress: EgressPolicy
    task_classes: TaskClassConfig
    budgets: BudgetConfig
    qualification: QualificationConfig
    safety: SafetyConfig = Field(default_factory=SafetyConfig)
    config_dir: str = ""

    def validate_all(self) -> None:
        self.routing.validate_split()
        # Codebuff must be absent entirely.
        ids = {p.provider_id for p in self.providers.providers}
        if "codebuff" in ids or "codebuff" in set(self.providers.exclude) - {"codebuff"}:
            pass  # excluded is fine; presence in providers is not
        if "codebuff" in ids:
            raise ConfigError("Codebuff must not be a configured provider")


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ConfigError(f"missing config file: {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:  # pragma: no cover - defensive
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"config file {path} must be a mapping")
    return data


def load_config(config_dir: Path | str | None = None) -> FactoryConfig:
    """Load and validate all factory configuration from ``config_dir``."""
    base = Path(config_dir) if config_dir else bundled_config_dir()
    if not base.is_dir():
        raise ConfigError(f"config directory not found: {base}")

    try:
        cfg = FactoryConfig(
            providers=ProvidersConfig(**_read_yaml(base / "providers.yaml")),
            routing=RoutingConfig(**_read_yaml(base / "routing.yaml")),
            trust=TrustPolicy(**_read_yaml(base / "trust-policy.yaml")),
            egress=EgressPolicy(**_read_yaml(base / "data-egress-policy.yaml")),
            task_classes=TaskClassConfig(**_read_yaml(base / "task-classes.yaml")),
            budgets=BudgetConfig(**_read_yaml(base / "budgets.yaml")),
            qualification=QualificationConfig(**_read_yaml(base / "qualification-suite.yaml")),
            safety=SafetyConfig(**_read_yaml(base / "safety.yaml"))
            if (base / "safety.yaml").exists()
            else SafetyConfig(),
            config_dir=str(base),
        )
    except ConfigError:
        raise
    except Exception as exc:  # pydantic ValidationError etc.
        raise ConfigError(f"configuration failed validation: {exc}") from exc

    cfg.validate_all()
    return cfg
