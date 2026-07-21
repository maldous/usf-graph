"""P0-10: real git-apply integration produces a correct combined wave patch."""

from __future__ import annotations

import subprocess

import pytest

from usf_factory.enums import PacketResultStatus
from usf_factory.event_store import open_store
from usf_factory.integration import deterministic_preintegrate
from usf_factory.isolation import RepoIsolation
from usf_factory.models import PacketResult
from usf_factory.paths import resolve_paths


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True)


@pytest.mark.contract
def test_real_integration_applies_patches_and_derives_diff(tmp_path, factory_paths, tmp_usf):
    # tmp_usf already has files: semantic/ontology.ttl, semantic/shapes/lifecycle.ttl.
    iso = RepoIsolation(resolve_paths().ensure(), tmp_usf)
    iso.ensure_mirror()
    base = iso.mirror_head()
    store = open_store(tmp_path / "f.sqlite", tmp_path / "cas")

    # Two patches touching DIFFERENT files (no semantic conflict).
    patch_a = (
        "diff --git a/semantic/ontology.ttl b/semantic/ontology.ttl\n"
        "--- a/semantic/ontology.ttl\n+++ b/semantic/ontology.ttl\n"
        "@@ -1 +1,2 @@\n # ontology\n+# added by A\n"
    )
    patch_b = (
        "diff --git a/semantic/shapes/lifecycle.ttl b/semantic/shapes/lifecycle.ttl\n"
        "--- a/semantic/shapes/lifecycle.ttl\n+++ b/semantic/shapes/lifecycle.ttl\n"
        "@@ -1 +1,2 @@\n # lifecycle\n+# added by B\n"
    )
    ref_a = store.cas_put_text(patch_a)
    ref_b = store.cas_put_text(patch_b)
    results = [
        PacketResult(
            packet_id="pA",
            status=PacketResultStatus.COMPLETED,
            agent_profile_id="x",
            base_head=base,
            snapshot_id="s",
            patch_digest="a",
            patch_ref=ref_a,
            changed_paths=["semantic/ontology.ttl"],
        ),
        PacketResult(
            packet_id="pB",
            status=PacketResultStatus.COMPLETED,
            agent_profile_id="x",
            base_head=base,
            snapshot_id="s",
            patch_digest="b",
            patch_ref=ref_b,
            changed_paths=["semantic/shapes/lifecycle.ttl"],
        ),
    ]

    def fetch(r):
        return store.cas_get(r.patch_ref).decode()

    attempt, wave = deterministic_preintegrate(
        "set1", results, iso, base_head=base, patch_fetch=fetch, apply_patches=True, store=store
    )
    assert attempt.deterministic_merge_ok
    assert wave is not None
    # changed paths are derived from the ACTUAL git diff, not model claims.
    assert wave.changed_paths == ["semantic/ontology.ttl", "semantic/shapes/lifecycle.ttl"]
    combined = store.cas_get(wave.patch_ref).decode()
    assert "added by A" in combined and "added by B" in combined
    store.close()


@pytest.mark.contract
def test_integration_reports_failed_apply(tmp_path, factory_paths, tmp_usf):
    iso = RepoIsolation(resolve_paths().ensure(), tmp_usf)
    iso.ensure_mirror()
    base = iso.mirror_head()
    store = open_store(tmp_path / "f.sqlite", tmp_path / "cas")
    # A patch that will not apply (wrong context).
    bad = (
        "diff --git a/semantic/ontology.ttl b/semantic/ontology.ttl\n"
        "--- a/semantic/ontology.ttl\n+++ b/semantic/ontology.ttl\n"
        "@@ -5 +5 @@\n-nonexistent line\n+replacement\n"
    )
    ref = store.cas_put_text(bad)
    results = [
        PacketResult(
            packet_id="pX",
            status=PacketResultStatus.COMPLETED,
            agent_profile_id="x",
            base_head=base,
            snapshot_id="s",
            patch_digest="x",
            patch_ref=ref,
        )
    ]
    attempt, wave = deterministic_preintegrate(
        "set2",
        results,
        iso,
        base_head=base,
        patch_fetch=lambda r: store.cas_get(r.patch_ref).decode(),
        apply_patches=True,
        store=store,
    )
    assert not attempt.deterministic_merge_ok
    assert wave is None
    store.close()
