"""First controlled semantic result (Phase 15).

Attempts EXACTLY ONE candidate semantic patch, and only when every prerequisite
holds:

  - the obligation comes from current USF programme state,
  - the materialisation owner is explicitly VERIFIED,
  - the selected worker is qualified (admitted PATCH_PRODUCER),
  - execution is brokered (or sandbox-attested),
  - the packet is low/medium risk,
  - source-egress rules pass,
  - an independent reviewer is qualified,
  - the real USF validation profile is available.

The patch stays entirely in the factory mirror/integration area — never pushed
to usf-graph, never applied to /usf. If any prerequisite is missing, this returns
the exact blocker (no fabricated progress) and the operator sees a shadow-only
result. On success the flow stops at AWAITING_OPERATOR_DELIVERY.
"""

from __future__ import annotations

from typing import Any

from .context import RuntimeContext
from .enums import AdmissionRole


def _has_admitted(ctx: RuntimeContext, role: AdmissionRole) -> bool:
    from .admission import admission_ineligibility
    from .models import AgentProfile

    for _key, row in ctx.store.items("agent_profiles"):
        profile = AgentProfile(**row)
        decision, _run, reason = admission_ineligibility(ctx, profile)
        if reason is None and decision and role.value in set(decision.get("roles", [])):
            return True
    return False


def _provider_diverse_reviewer_and_producer(ctx: RuntimeContext) -> bool:
    """A reviewer must exist on a DIFFERENT provider than at least one producer."""
    from .admission import admission_ineligibility
    from .models import AgentProfile

    producers, reviewers = set(), set()
    for _key, row in ctx.store.items("agent_profiles"):
        profile = AgentProfile(**row)
        decision, _run, reason = admission_ineligibility(ctx, profile)
        if reason is not None or not decision:
            continue
        roles = set(decision.get("roles", []))
        if AdmissionRole.PATCH_PRODUCER.value in roles:
            producers.add(profile.provider_id)
        if AdmissionRole.REVIEWER.value in roles:
            reviewers.add(profile.provider_id)
    return bool(reviewers) and any(r != p for r in reviewers for p in producers)


def check_prerequisites(ctx: RuntimeContext) -> list[str]:
    """Return the list of UNMET prerequisites for a candidate semantic packet."""
    blockers: list[str] = []

    # Qualified producer + independent reviewer.
    if not _has_admitted(ctx, AdmissionRole.PATCH_PRODUCER):
        blockers.append("no admitted PATCH_PRODUCER")
    if not _has_admitted(ctx, AdmissionRole.REVIEWER):
        blockers.append("no admitted REVIEWER (independent review required)")
    elif not _provider_diverse_reviewer_and_producer(ctx):
        blockers.append("no provider-diverse independent reviewer vs a producer")

    # A VERIFIED materialisation owner whose subject appears in CURRENT programme
    # obligations (objective declaration / operator / contract evidence — never
    # fabricated). This both verifies (persists evidence) and cross-checks the
    # subject against the live obligation set.
    try:
        from .ownership import verify_owner_for_obligations

        owner = verify_owner_for_obligations(ctx)
        if owner.get("status") != "VERIFIED":
            best = owner.get("best_candidate")
            blockers.append(
                "no VERIFIED materialisation owner for a current obligation subject "
                f"(status={owner.get('status')}; best_candidate={best}; "
                f"missing={owner.get('missing')})"
            )
    except Exception as exc:
        blockers.append(f"materialisation contract unavailable: {type(exc).__name__}")

    # S9: the required semantic validation profile must be EXECUTABLE in the
    # factory integration clone (real runners, no environment-blocked stub gates).
    ok, detail = _validation_profile_executable(ctx)
    if not ok:
        blockers.append(f"required validation profile not executable: {detail}")

    # Egress: a semantic write packet carries source; a non-local producer needs
    # source egress enabled + approval. If the only producers are external and
    # egress is off, that is a blocker.
    # local producers still fine; flag only if egress is off AND no local producer.
    if not ctx.config.egress.source_egress_enabled and not _local_producer_admitted(ctx):
        blockers.append(
            "source egress disabled and no LOCAL admitted producer "
            "(external producers cannot receive source)"
        )

    # Protected gates must remain disabled (they do); autonomous-safe is required
    # to actually execute a mutating wave, and stays disabled by default.
    if not ctx.config.safety.autonomous_safe_enabled:
        blockers.append(
            "autonomous_safe_enabled is false (approve-wave mutation disabled by default)"
        )

    return blockers


def _validation_profile_executable(ctx: RuntimeContext) -> tuple[bool, str]:
    """Prove the validation gates a current-obligation candidate would require are
    executable in the integration clone: every gate has a REAL runner and none is
    an environment-blocked USF stub. Prefers bounded local validation; avoids the
    known-stalling live-Stardog paths (which are not among these runners)."""
    from .isolation import RepoIsolation
    from .materialisation import build_index_at
    from .validation_runners import _USF_GATES, build_runners

    rows = list(ctx.store.items("semantic_snapshots"))
    snap = sorted(rows, key=lambda kv: kv[1].get("captured_at", ""))[-1][1] if rows else {}
    head = str(snap.get("repository_head") or "")
    try:
        iso = RepoIsolation(ctx.paths, ctx.usf_repo)
        if not iso.mirror_exists():
            iso.ensure_mirror()
        if not head:
            head = iso.usf_head()
        index = build_index_at(ctx.paths.mirror, head)
    except Exception as exc:
        return False, f"mirror/index unavailable: {type(exc).__name__}"

    tc = ctx.config.task_classes.by_name()
    gates: set[str] = set()
    for o in snap.get("programme_obligations") or []:
        subjects = o.get("semantic_subjects") or []
        if subjects:
            # SEMANTIC packet: authority-derived RDF/SHACL profile (mirrors the
            # compiler), never code-oriented task defaults.
            for s in subjects:
                e = index.entries.get(s)
                if e is not None:
                    gates |= set(e.validation_profiles)
            gates.add("syntax-parse")
        else:
            t = tc.get(o.get("task_class", ""))
            if t is not None:
                gates |= set(t.default_validation)
    if not gates:
        return True, "no validation gates required"
    runners = build_runners(ctx.paths.integration / "profile-check")
    missing = sorted(g for g in gates if g not in runners)
    stubbed = sorted(g for g in gates if g in _USF_GATES)
    if missing:
        return False, f"no runner for gates {missing}"
    if stubbed:
        return False, f"environment-blocked stub gates required: {stubbed}"
    return True, f"executable gates: {sorted(gates)}"


def _local_producer_admitted(ctx: RuntimeContext) -> bool:
    from .admission import admission_ineligibility
    from .enums import PrivacyClass
    from .models import AgentProfile

    provs = ctx.config.providers.by_id()
    for _key, row in ctx.store.items("agent_profiles"):
        profile = AgentProfile(**row)
        decision, _run, reason = admission_ineligibility(ctx, profile)
        if reason is not None or not decision:
            continue
        if AdmissionRole.PATCH_PRODUCER.value not in set(decision.get("roles", [])):
            continue
        cfg = provs.get(profile.provider_id)
        if cfg and cfg.privacy_class == PrivacyClass.LOCAL_ONLY:
            return True
    return False


def attempt_candidate_packet(ctx: RuntimeContext, opts: Any) -> dict[str, Any]:
    """Attempt one candidate semantic packet iff all prerequisites hold. Returns a
    structured result including the exact blocker when prerequisites are missing
    (never fabricated progress). Mutation stays in the factory mirror; on success
    the flow halts at AWAITING_OPERATOR_DELIVERY."""
    blockers = check_prerequisites(ctx)
    if blockers:
        return {
            "attempted": True,
            "produced": False,
            "status": "PREREQUISITES_UNMET",
            "blocker": "; ".join(blockers),
            "blockers": blockers,
        }
    # All prerequisites hold: run one APPROVE_WAVE cycle. The engine enforces
    # every safety gate again (verified-owner write scope, review, validation,
    # fail-closed). The wave patch remains in the factory integration area.
    import asyncio

    from .enums import RunMode
    from .runtime import build_engine

    allow_billable = bool(getattr(opts, "allow_billable", False))
    eng = build_engine(ctx, mode=RunMode.APPROVE_WAVE, allow_billable=allow_billable)
    receipt = asyncio.run(eng.run_cycle(RunMode.APPROVE_WAVE))
    produced = receipt.accepted_packets > 0
    return {
        "attempted": True,
        "produced": produced,
        "status": "AWAITING_OPERATOR_DELIVERY" if produced else "BLOCKED",
        "cycle_state": receipt.state.value,
        "selected": receipt.selected_packets,
        "accepted": receipt.accepted_packets,
        "blockers": receipt.blockers,
        "note": "candidate patch (if any) stays in the factory mirror; never pushed to usf-graph",
    }
