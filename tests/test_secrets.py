"""Credential allowlist, alias normalization, conflict detection, redaction."""

from __future__ import annotations

import pytest

from usf_factory import secrets


@pytest.mark.unit
def test_alias_normalization_precedence_and_import():
    norm = secrets.normalize(
        {
            "OPENAI_API_KEY": "v-openai",
            "OPENROUTER_TOKEN": "v-router",  # alias for OPENROUTER_API_KEY
            "GOOGLE_GEMINI_API_KEY": "v-gemini",  # alias for GEMINI_API_KEY
            "CERABRAS_TOKEN": "v-cerebras",  # misspelled alias for CEREBRAS_API_KEY
        }
    )
    assert "OPENAI_API_KEY" in norm.resolved
    assert norm.resolved["OPENROUTER_API_KEY"].provenance_alias == "OPENROUTER_TOKEN"
    assert norm.resolved["GEMINI_API_KEY"].provenance_alias == "GOOGLE_GEMINI_API_KEY"
    assert norm.resolved["CEREBRAS_API_KEY"].provenance_alias == "CERABRAS_TOKEN"


@pytest.mark.unit
def test_conflicting_aliases_are_not_imported():
    norm = secrets.normalize({"OPENROUTER_API_KEY": "a", "OPENROUTER_TOKEN": "b"})
    assert "OPENROUTER_API_KEY" in norm.conflicts
    assert "OPENROUTER_API_KEY" not in norm.resolved


@pytest.mark.unit
def test_identical_aliases_are_not_a_conflict():
    norm = secrets.normalize({"GROQ_API_KEY": "same", "GROQ_TOKEN": "same"})
    assert "GROQ_API_KEY" not in norm.conflicts
    assert "GROQ_API_KEY" in norm.resolved


@pytest.mark.unit
def test_excluded_and_unmapped_reported_by_name_never_imported():
    norm = secrets.normalize({"STARDOG_TOKEN": "x", "LINEAR_API_KEY": "y", "AIS_API_KEY": "z"})
    assert "STARDOG_TOKEN" in norm.excluded_present
    assert "LINEAR_API_KEY" in norm.excluded_present
    assert "AIS_API_KEY" in norm.unmapped_candidates
    assert not norm.resolved


@pytest.mark.unit
def test_github_models_not_written_from_general_token():
    norm = secrets.normalize({"GITHUB_PERSONAL_ACCESS_TOKEN": "pat"})
    write, reason = secrets.github_models_write_policy(norm)
    assert write is False
    assert "GITHUB_MODELS_TOKEN" not in secrets.select_for_write(norm)
    assert "GITHUB_PERSONAL_ACCESS_TOKEN" in secrets.select_for_write(norm)


@pytest.mark.unit
def test_github_models_written_from_explicit_source():
    norm = secrets.normalize({"GITHUB_MODELS_TOKEN": "gm"})
    write, _ = secrets.github_models_write_policy(norm)
    assert write is True
    assert "GITHUB_MODELS_TOKEN" in secrets.select_for_write(norm)


@pytest.mark.unit
def test_normalization_repr_never_contains_values():
    norm = secrets.normalize({"OPENAI_API_KEY": "super-secret-value-123456"})
    assert "super-secret-value-123456" not in repr(norm)


@pytest.mark.unit
def test_redaction_scrubs_known_and_shaped_secrets():
    r = secrets.Redactor(["my-exact-secret-value"])
    out = r.scrub("here my-exact-secret-value and sk-abcdef0123456789ABCDEF token")
    assert "my-exact-secret-value" not in out
    assert "sk-abcdef0123456789ABCDEF" not in out
    assert out.count("[REDACTED]") == 2


@pytest.mark.unit
def test_parse_env0():
    data = b"OPENAI_API_KEY=abc\x00PATH=/bin\x00BAD ENTRY\x00"
    parsed = secrets.parse_env0(data)
    assert parsed["OPENAI_API_KEY"] == "abc"
    assert parsed["PATH"] == "/bin"


@pytest.mark.unit
def test_write_env_file_is_0600(tmp_path):
    norm = secrets.normalize({"OPENAI_API_KEY": "v"})
    content = secrets.render_env_content(norm, ["OPENAI_API_KEY"])
    target = tmp_path / "e.env"
    secrets.write_env_file(target, content)
    assert oct(target.stat().st_mode & 0o777) == "0o600"
    assert "OPENAI_API_KEY=v" in target.read_text()


@pytest.mark.unit
def test_load_allowlisted_ignores_excluded(tmp_path):
    p = tmp_path / "e.env"
    p.write_text("OPENAI_API_KEY=v\nSTARDOG_TOKEN=nope\nLINEAR_API_KEY=nope\n")
    allow = secrets.load_allowlisted_env(p)
    assert allow == {"OPENAI_API_KEY": "v"}
