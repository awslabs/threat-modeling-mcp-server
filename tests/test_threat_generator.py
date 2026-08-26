"""Unit tests for the threat generator module."""

import pytest
from unittest.mock import MagicMock

import threat_modeling_mcp_server.tools.threat_generator as threat_generator_module
from threat_modeling_mcp_server.tools.threat_generator import (
    add_threat_impl,
    update_threat_impl,
    list_threats_impl,
    get_threat_impl,
    delete_threat_impl,
    assess_threat_impl,
    assess_threats_atomically_impl,
    is_residual_assessment_current,
    add_mitigation_impl,
    update_mitigation_impl,
    list_mitigations_impl,
    delete_mitigation_impl,
    link_mitigation_to_threat_impl,
    unlink_mitigation_from_threat_impl,
    threats,
    mitigations,
    residual_risk_assessments,
)
from threat_modeling_mcp_server.models.threat_models import (
    ThreatStatus,
    ThreatCategory,
    ThreatSeverity,
    MitigationStatus,
    MitigationType,
    ResidualRiskDecision,
    ThreatLikelihood,
)


@pytest.fixture
def mock_context():
    """Create a mock MCP context for testing."""
    ctx = MagicMock()
    return ctx


@pytest.fixture(autouse=True)
def clear_global_state():
    """Clear global state before each test."""
    threats.clear()
    mitigations.clear()
    # Use module reference to handle reassignment
    threat_generator_module.mitigation_links = []
    residual_risk_assessments.clear()
    yield
    # Cleanup after test
    threats.clear()
    mitigations.clear()
    threat_generator_module.mitigation_links = []
    residual_risk_assessments.clear()


class TestAddThreat:
    """Tests for add_threat_impl function."""

    @pytest.mark.asyncio
    async def test_add_minimal_threat(self, mock_context):
        """Test adding a threat with minimal required fields."""
        result = await add_threat_impl(
            ctx=mock_context,
            threat_source="external attacker",
            prerequisites="with network access",
            threat_action="exploit vulnerability",
            threat_impact="data breach",
        )
        assert "Threat added with ID:" in result
        assert len(threats) == 1
        assert result.endswith("T001")

    @pytest.mark.asyncio
    async def test_add_threat_with_category(self, mock_context):
        """Test adding a threat with category."""
        result = await add_threat_impl(
            ctx=mock_context,
            threat_source="attacker",
            prerequisites="access",
            threat_action="inject SQL",
            threat_impact="data loss",
            category="Tampering",
        )
        assert "Threat added with ID:" in result
        threat_id = result.split(": ")[1]
        assert threats[threat_id].category == ThreatCategory.TAMPERING

    @pytest.mark.asyncio
    async def test_add_threat_with_severity(self, mock_context):
        """Test adding a threat with severity."""
        result = await add_threat_impl(
            ctx=mock_context,
            threat_source="attacker",
            prerequisites="access",
            threat_action="attack",
            threat_impact="damage",
            severity="High",
        )
        threat_id = result.split(": ")[1]
        assert threats[threat_id].severity == ThreatSeverity.HIGH

    @pytest.mark.asyncio
    async def test_add_threat_with_components(self, mock_context):
        """Test adding a threat with affected components."""
        result = await add_threat_impl(
            ctx=mock_context,
            threat_source="attacker",
            prerequisites="access",
            threat_action="attack",
            threat_impact="damage",
            affected_components=["comp1", "comp2"],
        )
        threat_id = result.split(": ")[1]
        assert "comp1" in threats[threat_id].affected_components
        assert "comp2" in threats[threat_id].affected_components

    @pytest.mark.asyncio
    async def test_add_threat_creates_statement(self, mock_context):
        """Test that adding a threat creates a proper statement."""
        await add_threat_impl(
            ctx=mock_context,
            threat_source="attacker",
            prerequisites="with access",
            threat_action="perform attack",
            threat_impact="cause damage",
        )
        threat = list(threats.values())[0]
        assert "attacker" in threat.statement
        assert "with access" in threat.statement
        assert "perform attack" in threat.statement
        assert "cause damage" in threat.statement

    @pytest.mark.asyncio
    async def test_add_multiple_threats_increments_id(self, mock_context):
        """Test that adding multiple threats increments numeric IDs."""
        await add_threat_impl(
            ctx=mock_context,
            threat_source="attacker1",
            prerequisites="access1",
            threat_action="action1",
            threat_impact="impact1",
        )
        await add_threat_impl(
            ctx=mock_context,
            threat_source="attacker2",
            prerequisites="access2",
            threat_action="action2",
            threat_impact="impact2",
        )
        threat_list = list(threats.values())
        assert len(threat_list) == 2
        # Second threat should have higher numericId
        assert threat_list[1].numericId > threat_list[0].numericId

    @pytest.mark.asyncio
    async def test_deleted_threat_id_is_not_reused(self, mock_context):
        first = await add_threat_impl(
            ctx=mock_context,
            threat_source="attacker1",
            prerequisites="access1",
            threat_action="action1",
            threat_impact="impact1",
        )
        first_id = first.split(": ")[1]
        await delete_threat_impl(mock_context, first_id)

        second = await add_threat_impl(
            ctx=mock_context,
            threat_source="attacker2",
            prerequisites="access2",
            threat_action="action2",
            threat_impact="impact2",
        )

        assert second.endswith("T002")


class TestUpdateThreat:
    """Tests for update_threat_impl function."""

    @pytest.mark.asyncio
    async def test_update_threat_source(self, mock_context):
        """Test updating threat source."""
        result = await add_threat_impl(
            ctx=mock_context,
            threat_source="original attacker",
            prerequisites="access",
            threat_action="attack",
            threat_impact="damage",
        )
        threat_id = result.split(": ")[1]
        
        update_result = await update_threat_impl(
            ctx=mock_context,
            id=threat_id,
            threat_source="updated attacker",
        )
        assert "updated successfully" in update_result
        assert threats[threat_id].threatSource == "updated attacker"

    @pytest.mark.asyncio
    async def test_update_threat_status(self, mock_context):
        """Test updating threat status."""
        result = await add_threat_impl(
            ctx=mock_context,
            threat_source="attacker",
            prerequisites="access",
            threat_action="attack",
            threat_impact="damage",
        )
        threat_id = result.split(": ")[1]
        
        await update_threat_impl(
            ctx=mock_context,
            id=threat_id,
            status="threatResolved",
        )
        assert threats[threat_id].status == ThreatStatus.RESOLVED

    @pytest.mark.asyncio
    async def test_update_nonexistent_threat(self, mock_context):
        """Test updating a non-existent threat."""
        result = await update_threat_impl(
            ctx=mock_context,
            id="nonexistent-id",
            threat_source="new source",
        )
        assert "not found" in result

    @pytest.mark.asyncio
    async def test_update_threat_updates_statement(self, mock_context):
        """Test that updating threat components updates the statement."""
        result = await add_threat_impl(
            ctx=mock_context,
            threat_source="original",
            prerequisites="access",
            threat_action="attack",
            threat_impact="damage",
        )
        threat_id = result.split(": ")[1]
        
        await update_threat_impl(
            ctx=mock_context,
            id=threat_id,
            threat_source="updated",
        )
        assert "updated" in threats[threat_id].statement


class TestListThreats:
    """Tests for list_threats_impl function."""

    @pytest.mark.asyncio
    async def test_list_empty_threats(self, mock_context):
        """Test listing when no threats exist."""
        result = await list_threats_impl(ctx=mock_context)
        assert "No threats found" in result

    @pytest.mark.asyncio
    async def test_list_all_threats(self, mock_context):
        """Test listing all threats."""
        await add_threat_impl(
            ctx=mock_context,
            threat_source="attacker1",
            prerequisites="access",
            threat_action="action1",
            threat_impact="impact1",
        )
        await add_threat_impl(
            ctx=mock_context,
            threat_source="attacker2",
            prerequisites="access",
            threat_action="action2",
            threat_impact="impact2",
        )
        result = await list_threats_impl(ctx=mock_context)
        assert "attacker1" in result
        assert "attacker2" in result

    @pytest.mark.asyncio
    async def test_registered_tool_lists_id_required_by_follow_up_tools(self):
        import threat_modeling_mcp_server.server as srv

        _, added = await srv.mcp.call_tool("manage_threats", {
            "action": "add",
            "section": "threats",
            "values": {
                "threat_source": "attacker",
                "prerequisites": "with access",
                "threat_action": "tamper with data",
                "threat_impact": "loss of integrity",
            },
        })
        threat_id = added["result"].split("Threat added with ID: ", 1)[1]

        _, listed = await srv.mcp.call_tool("manage_threats", {
            "action": "list",
            "section": "threats",
        })

        assert f"**ID:** {threat_id}" in listed["result"]

    @pytest.mark.asyncio
    async def test_list_threats_filter_by_category(self, mock_context):
        """Test filtering threats by category."""
        await add_threat_impl(
            ctx=mock_context,
            threat_source="attacker1",
            prerequisites="access",
            threat_action="spoof",
            threat_impact="identity theft",
            category="Spoofing",
        )
        await add_threat_impl(
            ctx=mock_context,
            threat_source="attacker2",
            prerequisites="access",
            threat_action="tamper",
            threat_impact="data loss",
            category="Tampering",
        )
        result = await list_threats_impl(ctx=mock_context, category="Spoofing")
        assert "attacker1" in result
        assert "attacker2" not in result


class TestGetThreat:
    """Tests for get_threat_impl function."""

    @pytest.mark.asyncio
    async def test_get_existing_threat(self, mock_context):
        """Test getting an existing threat."""
        add_result = await add_threat_impl(
            ctx=mock_context,
            threat_source="attacker",
            prerequisites="access",
            threat_action="attack",
            threat_impact="damage",
        )
        threat_id = add_result.split(": ")[1]
        
        result = await get_threat_impl(ctx=mock_context, id=threat_id)
        assert "attacker" in result
        assert threat_id in result

    @pytest.mark.asyncio
    async def test_get_nonexistent_threat(self, mock_context):
        """Test getting a non-existent threat."""
        result = await get_threat_impl(ctx=mock_context, id="nonexistent")
        assert "not found" in result


class TestDeleteThreat:
    """Tests for delete_threat_impl function."""

    @pytest.mark.asyncio
    async def test_delete_existing_threat(self, mock_context):
        """Test deleting an existing threat."""
        add_result = await add_threat_impl(
            ctx=mock_context,
            threat_source="attacker",
            prerequisites="access",
            threat_action="attack",
            threat_impact="damage",
        )
        threat_id = add_result.split(": ")[1]
        
        result = await delete_threat_impl(ctx=mock_context, id=threat_id)
        assert "deleted successfully" in result
        assert threat_id not in threats

    @pytest.mark.asyncio
    async def test_delete_nonexistent_threat(self, mock_context):
        """Test deleting a non-existent threat."""
        result = await delete_threat_impl(ctx=mock_context, id="nonexistent")
        assert "not found" in result


class TestResidualRiskAssessments:
    """Tests for explicit, freshness-aware residual-risk decisions."""

    async def add_linked_threat(self, mock_context):
        threat_result = await add_threat_impl(
            ctx=mock_context,
            threat_source="attacker",
            prerequisites="with access",
            threat_action="exfiltrate records",
            threat_impact="a data breach",
            severity="High",
            likelihood="Likely",
        )
        threat_id = threat_result.split(": ")[1]
        mitigation_result = await add_mitigation_impl(
            ctx=mock_context,
            content="Enforce scoped authorization",
            type="Preventive",
        )
        mitigation_id = mitigation_result.split(": ")[1]
        await link_mitigation_to_threat_impl(
            ctx=mock_context,
            mitigation_id=mitigation_id,
            threat_id=threat_id,
        )
        return threat_id, mitigation_id

    @pytest.mark.asyncio
    async def test_assessment_maps_decision_and_renders_details(self, mock_context):
        threat_id, _ = await self.add_linked_threat(mock_context)

        result = await assess_threat_impl(
            ctx=mock_context,
            threat_id=threat_id,
            decision="Accepted",
            residual_severity="Low",
            residual_likelihood="Unlikely",
            rationale="The remaining exposure is within risk appetite.",
        )

        assessment = residual_risk_assessments[threat_id]
        assert result.endswith(": Accepted")
        assert assessment.decision is ResidualRiskDecision.ACCEPTED
        assert assessment.residual_likelihood is ThreatLikelihood.UNLIKELY
        assert threats[threat_id].status is ThreatStatus.RESOLVED
        assert is_residual_assessment_current(threat_id) is True
        rendered = await get_threat_impl(mock_context, threat_id)
        assert "Residual Risk Assessment" in rendered
        assert "Assessment State: Current" in rendered

    @pytest.mark.asyncio
    async def test_not_applicable_does_not_require_residual_ratings(
        self, mock_context
    ):
        threat_id, _ = await self.add_linked_threat(mock_context)

        await assess_threat_impl(
            ctx=mock_context,
            threat_id=threat_id,
            decision="Not Applicable",
            rationale="The reviewed deployment does not include this interface.",
        )

        assert threats[threat_id].status is ThreatStatus.NOT_USEFUL
        assert is_residual_assessment_current(threat_id) is True

    @pytest.mark.asyncio
    async def test_linked_mitigation_change_makes_assessment_stale(
        self, mock_context
    ):
        threat_id, mitigation_id = await self.add_linked_threat(mock_context)
        await assess_threat_impl(
            ctx=mock_context,
            threat_id=threat_id,
            decision="Mitigated",
            residual_severity="Low",
            residual_likelihood="Possible",
            rationale="Authorization reduces both likelihood and blast radius.",
        )

        await update_mitigation_impl(
            ctx=mock_context,
            id=mitigation_id,
            effectiveness="High",
        )

        assert is_residual_assessment_current(threat_id) is False
        assert "Assessment State: Stale" in await list_threats_impl(mock_context)

    @pytest.mark.asyncio
    async def test_batch_assessment_is_atomic(self, mock_context):
        first_id, _ = await self.add_linked_threat(mock_context)
        second_id, _ = await self.add_linked_threat(mock_context)

        result = await assess_threats_atomically_impl(
            mock_context,
            [
                {
                    "threat_id": first_id,
                    "decision": "Open",
                    "residual_severity": "High",
                    "residual_likelihood": "Likely",
                    "rationale": "Additional controls are required.",
                },
                {
                    "threat_id": second_id,
                    "decision": "Invented",
                    "residual_severity": "Low",
                    "residual_likelihood": "Unlikely",
                    "rationale": "Invalid decision for atomicity coverage.",
                },
            ],
        )

        assert result.startswith("❌ No residual-risk assessments were saved")
        assert "Valid options are" in result
        assert residual_risk_assessments == {}
        assert threats[first_id].status is ThreatStatus.IDENTIFIED
        assert threats[second_id].status is ThreatStatus.IDENTIFIED

    @pytest.mark.asyncio
    async def test_deleting_threat_removes_assessment(self, mock_context):
        threat_id, _ = await self.add_linked_threat(mock_context)
        await assess_threat_impl(
            ctx=mock_context,
            threat_id=threat_id,
            decision="Open",
            residual_severity="High",
            residual_likelihood="Likely",
            rationale="The mitigation is not yet implemented.",
        )

        await delete_threat_impl(mock_context, threat_id)

        assert threat_id not in residual_risk_assessments


class TestAddMitigation:
    """Tests for add_mitigation_impl function."""

    @pytest.mark.asyncio
    async def test_add_minimal_mitigation(self, mock_context):
        """Test adding a mitigation with minimal required fields."""
        result = await add_mitigation_impl(
            ctx=mock_context,
            content="Implement input validation",
        )
        assert "Mitigation added with ID:" in result
        assert len(mitigations) == 1
        assert result.endswith("M001")

    @pytest.mark.asyncio
    async def test_deleted_mitigation_id_is_not_reused(self, mock_context):
        first = await add_mitigation_impl(
            ctx=mock_context,
            content="First mitigation",
        )
        first_id = first.split(": ")[1]
        await delete_mitigation_impl(mock_context, first_id)

        second = await add_mitigation_impl(
            ctx=mock_context,
            content="Second mitigation",
        )

        assert second.endswith("M002")

    @pytest.mark.asyncio
    async def test_add_mitigation_with_type(self, mock_context):
        """Test adding a mitigation with type."""
        result = await add_mitigation_impl(
            ctx=mock_context,
            content="Enable encryption",
            type="Preventive",
        )
        mitigation_id = result.split(": ")[1]
        assert mitigations[mitigation_id].type == MitigationType.PREVENTIVE

    @pytest.mark.asyncio
    async def test_add_mitigation_with_status(self, mock_context):
        """Test adding a mitigation with custom status."""
        result = await add_mitigation_impl(
            ctx=mock_context,
            content="Review code",
            status="mitigationInProgress",
        )
        mitigation_id = result.split(": ")[1]
        assert mitigations[mitigation_id].status == MitigationStatus.IN_PROGRESS

    @pytest.mark.asyncio
    async def test_add_mitigation_default_status(self, mock_context):
        """Test that mitigation defaults to identified status."""
        result = await add_mitigation_impl(
            ctx=mock_context,
            content="Default status mitigation",
        )
        mitigation_id = result.split(": ")[1]
        assert mitigations[mitigation_id].status == MitigationStatus.IDENTIFIED


class TestUpdateMitigation:
    """Tests for update_mitigation_impl function."""

    @pytest.mark.asyncio
    async def test_update_mitigation_content(self, mock_context):
        """Test updating mitigation content."""
        result = await add_mitigation_impl(
            ctx=mock_context,
            content="Original content",
        )
        mitigation_id = result.split(": ")[1]
        
        update_result = await update_mitigation_impl(
            ctx=mock_context,
            id=mitigation_id,
            content="Updated content",
        )
        assert "updated successfully" in update_result
        assert mitigations[mitigation_id].content == "Updated content"

    @pytest.mark.asyncio
    async def test_update_mitigation_status(self, mock_context):
        """Test updating mitigation status."""
        result = await add_mitigation_impl(
            ctx=mock_context,
            content="Test mitigation",
        )
        mitigation_id = result.split(": ")[1]
        
        await update_mitigation_impl(
            ctx=mock_context,
            id=mitigation_id,
            status="mitigationResolved",
        )
        assert mitigations[mitigation_id].status == MitigationStatus.RESOLVED


class TestListMitigations:
    """Tests for list_mitigations_impl function."""

    @pytest.mark.asyncio
    async def test_list_empty_mitigations(self, mock_context):
        """Test listing when no mitigations exist."""
        result = await list_mitigations_impl(ctx=mock_context)
        assert "No mitigations found" in result

    @pytest.mark.asyncio
    async def test_list_all_mitigations(self, mock_context):
        """Test listing all mitigations."""
        await add_mitigation_impl(
            ctx=mock_context,
            content="Mitigation 1",
        )
        await add_mitigation_impl(
            ctx=mock_context,
            content="Mitigation 2",
        )
        result = await list_mitigations_impl(ctx=mock_context)
        assert "Mitigation 1" in result
        assert "Mitigation 2" in result


class TestMitigationThreatLinks:
    """Tests for linking and unlinking mitigations to threats."""

    @pytest.mark.asyncio
    async def test_link_mitigation_to_threat(self, mock_context):
        """Test linking a mitigation to a threat."""
        threat_result = await add_threat_impl(
            ctx=mock_context,
            threat_source="attacker",
            prerequisites="access",
            threat_action="attack",
            threat_impact="damage",
        )
        threat_id = threat_result.split(": ")[1]
        
        mitigation_result = await add_mitigation_impl(
            ctx=mock_context,
            content="Mitigation",
        )
        mitigation_id = mitigation_result.split(": ")[1]
        
        link_result = await link_mitigation_to_threat_impl(
            ctx=mock_context,
            mitigation_id=mitigation_id,
            threat_id=threat_id,
        )
        assert "linked" in link_result
        # Access module's current list reference
        current_links = threat_generator_module.mitigation_links
        assert len(current_links) == 1
        assert current_links[0].mitigationId == mitigation_id
        assert current_links[0].linkedId == threat_id

    @pytest.mark.asyncio
    async def test_link_duplicate_returns_already_linked(self, mock_context):
        """Test that linking the same mitigation twice returns already linked message."""
        threat_result = await add_threat_impl(
            ctx=mock_context,
            threat_source="attacker",
            prerequisites="access",
            threat_action="attack",
            threat_impact="damage",
        )
        threat_id = threat_result.split(": ")[1]
        
        mitigation_result = await add_mitigation_impl(
            ctx=mock_context,
            content="Mitigation",
        )
        mitigation_id = mitigation_result.split(": ")[1]
        
        await link_mitigation_to_threat_impl(
            ctx=mock_context,
            mitigation_id=mitigation_id,
            threat_id=threat_id,
        )
        
        # Try to link again
        result = await link_mitigation_to_threat_impl(
            ctx=mock_context,
            mitigation_id=mitigation_id,
            threat_id=threat_id,
        )
        assert "already linked" in result

    @pytest.mark.asyncio
    async def test_link_nonexistent_mitigation(self, mock_context):
        """Test linking a non-existent mitigation."""
        threat_result = await add_threat_impl(
            ctx=mock_context,
            threat_source="attacker",
            prerequisites="access",
            threat_action="attack",
            threat_impact="damage",
        )
        threat_id = threat_result.split(": ")[1]
        
        result = await link_mitigation_to_threat_impl(
            ctx=mock_context,
            mitigation_id="nonexistent",
            threat_id=threat_id,
        )
        assert "not found" in result

    @pytest.mark.asyncio
    async def test_link_nonexistent_threat(self, mock_context):
        """Test linking to a non-existent threat."""
        mitigation_result = await add_mitigation_impl(
            ctx=mock_context,
            content="Mitigation",
        )
        mitigation_id = mitigation_result.split(": ")[1]
        
        result = await link_mitigation_to_threat_impl(
            ctx=mock_context,
            mitigation_id=mitigation_id,
            threat_id="nonexistent",
        )
        assert "not found" in result

    @pytest.mark.asyncio
    async def test_unlink_mitigation_from_threat(self, mock_context):
        """Test unlinking a mitigation from a threat."""
        threat_result = await add_threat_impl(
            ctx=mock_context,
            threat_source="attacker",
            prerequisites="access",
            threat_action="attack",
            threat_impact="damage",
        )
        threat_id = threat_result.split(": ")[1]
        
        mitigation_result = await add_mitigation_impl(
            ctx=mock_context,
            content="Mitigation",
        )
        mitigation_id = mitigation_result.split(": ")[1]
        
        await link_mitigation_to_threat_impl(
            ctx=mock_context,
            mitigation_id=mitigation_id,
            threat_id=threat_id,
        )
        
        unlink_result = await unlink_mitigation_from_threat_impl(
            ctx=mock_context,
            mitigation_id=mitigation_id,
            threat_id=threat_id,
        )
        assert "unlinked" in unlink_result
        # Access module's current list reference
        assert len(threat_generator_module.mitigation_links) == 0

    @pytest.mark.asyncio
    async def test_unlink_nonexistent_link(self, mock_context):
        """Test unlinking when no link exists."""
        threat_result = await add_threat_impl(
            ctx=mock_context,
            threat_source="attacker",
            prerequisites="access",
            threat_action="attack",
            threat_impact="damage",
        )
        threat_id = threat_result.split(": ")[1]
        
        mitigation_result = await add_mitigation_impl(
            ctx=mock_context,
            content="Mitigation",
        )
        mitigation_id = mitigation_result.split(": ")[1]
        
        result = await unlink_mitigation_from_threat_impl(
            ctx=mock_context,
            mitigation_id=mitigation_id,
            threat_id=threat_id,
        )
        assert "not linked" in result


class TestDeleteCascade:
    """Tests for cascade behavior on delete."""

    @pytest.mark.asyncio
    async def test_delete_threat_removes_links(self, mock_context):
        """Test that deleting a threat removes associated links."""
        threat_result = await add_threat_impl(
            ctx=mock_context,
            threat_source="attacker",
            prerequisites="access",
            threat_action="attack",
            threat_impact="damage",
        )
        threat_id = threat_result.split(": ")[1]
        
        mitigation_result = await add_mitigation_impl(
            ctx=mock_context,
            content="Mitigation",
        )
        mitigation_id = mitigation_result.split(": ")[1]
        
        await link_mitigation_to_threat_impl(
            ctx=mock_context,
            mitigation_id=mitigation_id,
            threat_id=threat_id,
        )
        
        # Access module's current list reference
        assert len(threat_generator_module.mitigation_links) == 1
        
        await delete_threat_impl(ctx=mock_context, id=threat_id)
        
        # Link should be removed - access module's current list reference
        assert len(threat_generator_module.mitigation_links) == 0

    @pytest.mark.asyncio
    async def test_delete_mitigation_removes_links(self, mock_context):
        """Test that deleting a mitigation removes associated links."""
        threat_result = await add_threat_impl(
            ctx=mock_context,
            threat_source="attacker",
            prerequisites="access",
            threat_action="attack",
            threat_impact="damage",
        )
        threat_id = threat_result.split(": ")[1]
        
        mitigation_result = await add_mitigation_impl(
            ctx=mock_context,
            content="Mitigation",
        )
        mitigation_id = mitigation_result.split(": ")[1]
        
        await link_mitigation_to_threat_impl(
            ctx=mock_context,
            mitigation_id=mitigation_id,
            threat_id=threat_id,
        )
        
        # Access module's current list reference
        assert len(threat_generator_module.mitigation_links) == 1
        
        await delete_mitigation_impl(ctx=mock_context, id=mitigation_id)
        
        # Link should be removed - access module's current list reference
        assert len(threat_generator_module.mitigation_links) == 0
