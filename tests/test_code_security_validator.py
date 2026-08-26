"""Tests for structured Phase 7.5 code validation."""

import pytest

import threat_modeling_mcp_server.server as srv
import threat_modeling_mcp_server.tools.code_security_validator as csv
import threat_modeling_mcp_server.tools.step_orchestrator as orch
import threat_modeling_mcp_server.tools.threat_generator as tg
from threat_modeling_mcp_server.models.threat_models import (
    MitigationStatus,
    ThreatStatus,
)
from threat_modeling_mcp_server.utils.state_collector import get_state_summary


async def call(action, values=None):
    """Call the registered code-validation tool and return its text result."""
    arguments = {"action": action}
    if values is not None:
        arguments["values"] = values
    _, structured = await srv.mcp.call_tool("manage_code_validation", arguments)
    return structured["result"]


async def seed_pair(link=True):
    """Create one threat and mitigation and return their IDs."""
    await tg.add_threat_impl(
        None,
        threat_source="attacker",
        prerequisites="with API access",
        threat_action="read another tenant's records",
        threat_impact="confidential data disclosure",
        category="Information Disclosure",
    )
    await tg.add_mitigation_impl(None, content="Enforce object-level authorization")
    threat_id = next(reversed(tg.threats))
    mitigation_id = next(reversed(tg.mitigations))
    if link:
        await tg.link_mitigation_to_threat_impl(None, mitigation_id, threat_id)
    return threat_id, mitigation_id


def complete_values(threat_id, mitigation_id, threat_outcome="fully_mitigated",
                    mitigation_outcome="implemented"):
    """Return a complete finding payload for one threat/mitigation pair."""
    return {
        "threat_findings": [{
            "threat_id": threat_id,
            "outcome": threat_outcome,
            "evidence": ["src/auth.py:42 enforces tenant ownership"],
        }],
        "mitigation_findings": [{
            "mitigation_id": mitigation_id,
            "outcome": mitigation_outcome,
            "evidence": ["tests/test_auth.py:18 rejects cross-tenant access"],
            "recommendation": "Keep the negative authorization test",
        }],
    }


class TestToolSurface:
    @pytest.mark.asyncio
    async def test_only_consolidated_validation_tool_is_registered(self):
        names = {tool.name for tool in await srv.mcp.list_tools()}
        assert "manage_code_validation" in names
        assert not names & {
            "validate_security_controls",
            "validate_threat_remediation",
            "generate_remediation_report",
            "validate_threat_model_against_code",
            "export_threat_model_with_remediation_status",
            "execute_code_validation_step",
        }

    @pytest.mark.asyncio
    async def test_describe_returns_exact_outcomes(self):
        result = await call("describe")
        for value in (
            "fully_mitigated", "partially_mitigated", "not_mitigated",
            "not_applicable", "implemented", "partially_implemented",
            "not_implemented",
        ):
            assert value in result


class TestAtomicRecording:
    @pytest.mark.asyncio
    async def test_unknown_id_rejects_whole_batch(self, empty_threat_model_state):
        threat_id, mitigation_id = await seed_pair()
        tg.threats[threat_id].status = ThreatStatus.RESOLVED
        values = complete_values(threat_id, "missing-mitigation")

        result = await call("record", values)

        assert "rejected" in result
        assert "missing-mitigation" in result
        assert tg.threats[threat_id].status is ThreatStatus.RESOLVED
        assert tg.mitigations[mitigation_id].status is MitigationStatus.IDENTIFIED
        assert not csv.threat_findings and not csv.mitigation_findings

    @pytest.mark.asyncio
    async def test_duplicate_ids_and_blank_evidence_are_rejected(
        self, empty_threat_model_state,
    ):
        threat_id, _ = await seed_pair()
        duplicate = {
            "threat_findings": [
                {"threat_id": threat_id, "outcome": "not_mitigated", "evidence": ["a"]},
                {"threat_id": threat_id, "outcome": "not_mitigated", "evidence": ["b"]},
            ]
        }
        assert "duplicate threat IDs" in await call("record", duplicate)
        assert not csv.threat_findings

        blank = {
            "threat_findings": [
                {"threat_id": threat_id, "outcome": "not_mitigated", "evidence": ["  "]},
            ]
        }
        assert "must not be blank" in await call("record", blank)
        assert not csv.threat_findings

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "threat_outcome,expected_threat,mitigation_outcome,expected_mitigation",
        [
            ("fully_mitigated", ThreatStatus.RESOLVED,
             "implemented", MitigationStatus.RESOLVED),
            ("partially_mitigated", ThreatStatus.IDENTIFIED,
             "partially_implemented", MitigationStatus.IN_PROGRESS),
            ("not_mitigated", ThreatStatus.IDENTIFIED,
             "not_implemented", MitigationStatus.IDENTIFIED),
            ("not_applicable", ThreatStatus.NOT_USEFUL,
             "not_applicable", MitigationStatus.WILL_NOT_ACTION),
        ],
    )
    async def test_outcomes_apply_canonical_statuses(
        self, empty_threat_model_state, threat_outcome, expected_threat,
        mitigation_outcome, expected_mitigation,
    ):
        threat_id, mitigation_id = await seed_pair()
        tg.threats[threat_id].status = ThreatStatus.RESOLVED
        tg.mitigations[mitigation_id].status = MitigationStatus.RESOLVED

        result = await call(
            "record",
            complete_values(
                threat_id, mitigation_id, threat_outcome, mitigation_outcome,
            ),
        )

        assert "Recorded 1 threat finding(s)" in result
        assert tg.threats[threat_id].status is expected_threat
        assert tg.mitigations[mitigation_id].status is expected_mitigation


class TestCompletionAndFreshness:
    @pytest.mark.asyncio
    async def test_report_is_required(
        self, empty_threat_model_state, tmp_path,
    ):
        (tmp_path / "app.py").write_text("pass", encoding="utf-8")
        orch.set_project_directory(str(tmp_path))
        threat_id, mitigation_id = await seed_pair()

        await call("record", complete_values(threat_id, mitigation_id))
        assert "coverage is complete" in await call("validate")

        orch.detect_phase_completion()
        assert orch.phase_completion[7.5] == 0.0

        report = await call("report")
        assert "# Code Validation Report" in report
        assert "src/auth.py:42" in report
        assert "security_score" not in report
        assert "Compliance and Governance" not in report

        orch.detect_phase_completion()
        assert orch.phase_completion[7.5] == 1.0
        assert get_state_summary()["code_validation"]["is_complete"] is True

    @pytest.mark.asyncio
    async def test_partial_coverage_cannot_report(self, empty_threat_model_state, tmp_path):
        (tmp_path / "app.py").write_text("pass", encoding="utf-8")
        orch.set_project_directory(str(tmp_path))
        threat_id, _ = await seed_pair()

        await call("record", {
            "threat_findings": [{
                "threat_id": threat_id,
                "outcome": "not_mitigated",
                "evidence": ["app.py has no relevant control"],
            }]
        })

        result = await call("report")
        assert "Cannot generate" in result
        assert "Missing mitigations" in result
        orch.detect_phase_completion()
        assert orch.phase_completion[7.5] == 0.0

    @pytest.mark.asyncio
    async def test_record_or_model_change_invalidates_report(
        self, empty_threat_model_state, tmp_path,
    ):
        (tmp_path / "app.py").write_text("pass", encoding="utf-8")
        orch.set_project_directory(str(tmp_path))
        threat_id, mitigation_id = await seed_pair()
        values = complete_values(threat_id, mitigation_id)
        await call("record", values)
        await call("report")
        assert csv.build_code_validation_export_data()["is_complete"]

        await call("record", values)
        assert not csv.build_code_validation_export_data()["is_complete"]
        await call("report")
        tg.threats[threat_id].threatAction = "read every tenant's records"

        status = csv.build_code_validation_export_data()
        assert status["stale_threat_ids"] == [threat_id]
        assert not status["is_complete"]

    @pytest.mark.asyncio
    async def test_link_or_project_change_reopens_validation(
        self, empty_threat_model_state, tmp_path,
    ):
        first = tmp_path / "first"
        second = tmp_path / "second"
        first.mkdir(); second.mkdir()
        (first / "app.py").write_text("pass", encoding="utf-8")
        (second / "app.py").write_text("pass", encoding="utf-8")
        orch.set_project_directory(str(first))
        threat_id, mitigation_id = await seed_pair()
        values = complete_values(threat_id, mitigation_id)
        await call("record", values)
        await call("report")

        tg.mitigation_links.clear()
        assert mitigation_id in csv.build_code_validation_export_data()["stale_mitigation_ids"]

        orch.set_project_directory(str(second))
        status = csv.build_code_validation_export_data()
        assert status["project_matches"] is False
        await call("record", values)
        assert csv.validation_project_directory == str(second)
        assert len(csv.threat_findings) == 1
        assert len(csv.mitigation_findings) == 1
        assert not csv.build_code_validation_export_data()["is_complete"]

    @pytest.mark.asyncio
    async def test_clear_reopens_phase(self, empty_threat_model_state, tmp_path):
        (tmp_path / "app.py").write_text("pass", encoding="utf-8")
        orch.set_project_directory(str(tmp_path))
        threat_id, mitigation_id = await seed_pair()
        await call("record", complete_values(threat_id, mitigation_id))
        await call("report")
        assert csv.build_code_validation_export_data()["is_complete"]

        assert "cleared" in (await call("clear")).lower()
        assert not csv.build_code_validation_export_data()["is_complete"]
        assert not csv.threat_findings and not csv.mitigation_findings
