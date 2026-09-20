"""Regression tests for Threat Composer import compatibility.

These cover the four import-failure classes seen against a real Threat Composer
build: non-UUID ids, unknown top-level keys, over-limit statement fields/tags,
and over-limit mitigation content -- plus the "A A" statement wording bug.
"""

import json

import pytest

from threat_modeling_mcp_server.tools.threat_generator import (
    add_threat_impl,
    update_threat_impl,
    add_mitigation_impl,
    update_mitigation_impl,
    link_mitigation_to_threat_impl,
    threats,
    mitigations,
)
from threat_modeling_mcp_server.utils.comprehensive_exporter import (
    export_threat_model_files,
)
from threat_modeling_mcp_server.utils.statement import compose_statement
from threat_modeling_mcp_server.utils.text_limits import (
    FREE_TEXT_SMALL_MAX_LENGTH,
    SINGLE_FIELD_MAX_LENGTH,
    STATEMENT_MAX_LENGTH,
    TAG_MAX_LENGTH,
    truncate_field,
    truncate_tags,
)
from threat_modeling_mcp_server.utils.tc_schema_check import (
    validate_threat_composer_payload,
)


class TestComposeStatement:
    """The composed statement must read naturally and not double the article."""

    def test_source_without_article_gets_one(self):
        s = compose_statement("malicious insider", "with access", "read data", "disclosure")
        assert s.startswith("A malicious insider ")
        assert "A A" not in s

    def test_source_starting_with_a_is_not_doubled(self):
        s = compose_statement("A misdirected agent", "with tools", "invoke a tool", "damage")
        assert s.startswith("A misdirected agent ")
        assert "A A" not in s

    def test_source_starting_with_an_is_not_doubled(self):
        s = compose_statement("An external attacker", "on the network", "spoof a user", "impact")
        assert s.startswith("An external attacker ")
        assert not s.startswith("An An")

    def test_vowel_source_gets_an(self):
        s = compose_statement("insider", "", "exfiltrate data", "loss")
        assert s.startswith("An insider ")

    def test_no_repeated_whitespace_when_prerequisites_empty(self):
        s = compose_statement("attacker", "", "flood the API", "downtime")
        assert "  " not in s
        assert "can flood the API" in s

    def test_silent_h_source_takes_an(self):
        s = compose_statement("honest broker", "", "leak a secret", "exposure")
        assert s.startswith("An honest broker ")

    def test_u_consonant_sound_source_takes_a(self):
        s = compose_statement("unique service account", "", "escalate", "impact")
        assert s.startswith("A unique service account ")

    def test_empty_source_emits_no_leading_article(self):
        s = compose_statement("", "", "do a thing", "harm")
        assert not s.startswith("A ")
        assert not s.startswith("An ")


class TestTruncateHelpers:
    def test_truncate_field_leaves_short_values(self):
        assert truncate_field("short", 200) == "short"

    def test_truncate_field_clamps_long_values(self):
        assert len(truncate_field("x" * 500, 200)) <= 200

    def test_truncate_tags_clamps_and_drops_blanks(self):
        tags = ["ok", "y" * 60, "   ", None]
        out = truncate_tags(tags)
        assert all(len(t) <= TAG_MAX_LENGTH for t in out)
        assert "" not in out
        assert None not in out
        assert "ok" in out


class TestAddClampsToLimits:
    """add/update must store values already within Threat Composer limits."""

    @pytest.mark.asyncio
    async def test_add_threat_clamps_fields_and_tags(self):
        await add_threat_impl(
            None,
            "s" * 400,
            "p" * 400,
            "a" * 400,
            "i" * 400,
            tags=["t" * 80, "keep"],
        )
        threat = list(threats.values())[0]
        assert len(threat.threatSource) <= SINGLE_FIELD_MAX_LENGTH
        assert len(threat.prerequisites) <= SINGLE_FIELD_MAX_LENGTH
        assert len(threat.threatAction) <= SINGLE_FIELD_MAX_LENGTH
        assert len(threat.threatImpact) <= SINGLE_FIELD_MAX_LENGTH
        assert len(threat.statement) <= STATEMENT_MAX_LENGTH
        assert all(len(t) <= TAG_MAX_LENGTH for t in threat.tags)

    @pytest.mark.asyncio
    async def test_update_threat_clamps_tags(self):
        result = await add_threat_impl(None, "attacker", "with access", "act", "impact")
        threat_id = result.rsplit(": ", 1)[1]
        await update_threat_impl(None, threat_id, tags=["z" * 90])
        assert all(len(t) <= TAG_MAX_LENGTH for t in threats[threat_id].tags)

    @pytest.mark.asyncio
    async def test_add_mitigation_clamps_content(self):
        await add_mitigation_impl(None, "c" * 5000)
        mitigation = list(mitigations.values())[0]
        assert len(mitigation.content) <= FREE_TEXT_SMALL_MAX_LENGTH

    @pytest.mark.asyncio
    async def test_update_mitigation_clamps_content(self):
        result = await add_mitigation_impl(None, "short")
        mid = result.rsplit(": ", 1)[1]
        await update_mitigation_impl(None, mid, content="d" * 5000)
        assert len(mitigations[mid].content) <= FREE_TEXT_SMALL_MAX_LENGTH


class TestExportedFileImportsCleanly:
    """The exported .tc.json must satisfy every Threat Composer constraint."""

    @pytest.mark.asyncio
    async def test_export_passes_self_validation(self, tmp_path):
        # Build a model with deliberately over-limit inputs across every field.
        t = await add_threat_impl(
            None,
            "A malicious insider " + "x" * 400,
            "p" * 400,
            "a" * 400,
            "i" * 400,
            tags=["OWASP LLM06: Excessive Agency is a very long tag", "anchor-threat"],
        )
        threat_id = t.rsplit(": ", 1)[1]
        m = await add_mitigation_impl(None, "m" * 5000)
        mitigation_id = m.rsplit(": ", 1)[1]
        await link_mitigation_to_threat_impl(None, mitigation_id, threat_id)

        export_threat_model_files(str(tmp_path / "model"))

        with open(tmp_path / ".threatmodel" / "model.tc.json", encoding="utf-8") as f:
            data = json.load(f)

        # The dedicated self-check finds nothing wrong.
        assert validate_threat_composer_payload(data) == []

        # And the specific constraints hold end to end.
        threat = data["threats"][0]
        assert len(threat["id"]) >= 36
        for field in ("threatSource", "prerequisites", "threatAction", "threatImpact"):
            assert len(threat[field]) <= SINGLE_FIELD_MAX_LENGTH
        assert len(threat["statement"]) <= STATEMENT_MAX_LENGTH
        assert all(len(tag) <= TAG_MAX_LENGTH for tag in threat["tags"])
        assert "A A" not in threat["statement"]

        mitigation = data["mitigations"][0]
        assert len(mitigation["id"]) >= 36
        assert len(mitigation["content"]) <= FREE_TEXT_SMALL_MAX_LENGTH

        link = data["mitigationLinks"][0]
        assert len(link["linkedId"]) >= 36
        assert len(link["mitigationId"]) >= 36
        assert link["linkedId"] == threat["id"]
        assert link["mitigationId"] == mitigation["id"]

    @pytest.mark.asyncio
    async def test_schema_violation_fails_the_json_export(self, tmp_path, monkeypatch):
        """If the self-check finds a violation, the .tc.json is not written and
        the summary reports the JSON export as failed (fail-closed)."""
        import threat_modeling_mcp_server.utils.comprehensive_exporter as exporter

        await add_threat_impl(None, "attacker", "with access", "act", "impact")
        monkeypatch.setattr(
            exporter,
            "validate_threat_composer_payload",
            lambda data: ["threats[0].id: 'T001' shorter than 36"],
        )

        summary = export_threat_model_files(str(tmp_path / "model"))

        assert not (tmp_path / ".threatmodel" / "model.tc.json").exists()
        assert "❌ Not exported" in summary or "JSON failed" in summary
        assert "shorter than 36" in summary

    @pytest.mark.asyncio
    async def test_tc_json_has_no_unknown_top_level_keys(self, tmp_path):
        await add_threat_impl(None, "attacker", "with access", "act", "impact")
        export_threat_model_files(str(tmp_path / "model"))

        with open(tmp_path / ".threatmodel" / "model.tc.json", encoding="utf-8") as f:
            data = json.load(f)

        allowed = {
            "schema", "applicationInfo", "architecture", "dataflow",
            "assumptions", "mitigations", "assumptionLinks", "mitigationLinks",
            "threats",
        }
        assert set(data) <= allowed


class TestSchemaSelfCheck:
    """The self-validator catches each violation class."""

    def test_flags_short_ids(self):
        data = {"threats": [{"id": "T001", "statement": "ok", "tags": []}], "mitigations": [], "mitigationLinks": []}
        errors = validate_threat_composer_payload(data)
        assert any("shorter than 36" in e for e in errors)

    def test_flags_unknown_top_level_key(self):
        data = {"threats": [], "mitigations": [], "components": []}
        errors = validate_threat_composer_payload(data)
        assert any("unrecognized top-level keys" in e for e in errors)

    def test_flags_over_limit_tag(self):
        data = {
            "threats": [{"id": "u" * 36, "statement": "ok", "tags": ["z" * 40]}],
            "mitigations": [],
            "mitigationLinks": [],
        }
        errors = validate_threat_composer_payload(data)
        assert any("tags[0]" in e for e in errors)

    def test_flags_unresolved_link(self):
        data = {
            "threats": [{"id": "a" * 36, "statement": "ok", "tags": []}],
            "mitigations": [{"id": "b" * 36, "content": "ok"}],
            "mitigationLinks": [{"linkedId": "c" * 36, "mitigationId": "b" * 36}],
        }
        errors = validate_threat_composer_payload(data)
        assert any("does not resolve to a threat" in e for e in errors)

    def test_clean_payload_has_no_errors(self):
        data = {
            "schema": 1,
            "applicationInfo": {"name": "x"},
            "architecture": {"description": ""},
            "dataflow": {"description": ""},
            "assumptions": [],
            "mitigations": [{"id": "b" * 36, "content": "ok"}],
            "assumptionLinks": [],
            "mitigationLinks": [{"linkedId": "a" * 36, "mitigationId": "b" * 36}],
            "threats": [{"id": "a" * 36, "statement": "ok", "tags": ["short"]}],
        }
        assert validate_threat_composer_payload(data) == []
