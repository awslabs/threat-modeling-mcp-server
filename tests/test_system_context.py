"""Tests for the unified system-context MCP tool.

Boundary tests call through ``mcp.call_tool`` so they exercise schema validation
as well as the underlying implementation.
"""

import pytest
from unittest.mock import AsyncMock

import threat_modeling_mcp_server.server as srv
import threat_modeling_mcp_server.tools.business_context as bctx
import threat_modeling_mcp_server.tools.classification_profiles as cp
import threat_modeling_mcp_server.tools.system_context as system_context


async def call(tool_name, **arguments):
    """Invoke a registered MCP tool and return its text result."""
    _, structured = await srv.mcp.call_tool(tool_name, arguments)
    return structured["result"]



async def context_call(action, section, **arguments):
    """Invoke the unified system-context MCP tool."""
    return await call(
        "manage_system_context", action=action, section=section, **arguments
    )


def complete_business_values():
    """Return a complete, valid business payload for boundary tests."""
    return {
        "description": "Payment platform",
        "industry_sector": "Finance",
        "sensitivity_tier": "Restricted",
        "user_base_size": "Small",
        "geographic_scope": "National / Single-Country",
        "regulatory_requirements": ["PCI-DSS"],
        "system_criticality": "High",
        "financial_impact": "High",
        "authentication_requirement": "MFA",
        "deployment_model": "PaaS",
        "user_base_metric": "Monthly Active Users",
        "revenue_band": "Mid-market",
        "data_residency": "National / Single-Country",
        "compute_location": "National / Single-Country",
        "user_base_location": "National / Single-Country",
        "organizational_headquarters": "National / Single-Country",
    }

@pytest.fixture
def ctx():
    return AsyncMock()


class TestUnifiedSystemContextTool:
    """The compact context tool preserves every profile operation."""
    def test_only_the_unified_context_tool_is_registered(self):
        from mcp.server.fastmcp import FastMCP

        probe = FastMCP("system-context-probe")
        system_context.register_tools(probe)
        assert [tool.name for tool in probe._tool_manager.list_tools()] == [
            "manage_system_context"
        ]
        assert not hasattr(cp, "register_tools")
        assert "manage_system_context" in {
            tool.name for tool in srv.mcp._tool_manager.list_tools()
        }

    async def test_describe_returns_exact_values_on_demand(self):
        overview = await context_call("describe", "all")
        assert "set" in overview and "data_assets" in overview

        software = await context_call("describe", "software")
        assert "software_type" in software
        assert "Web Application" in software

        nfrs = await context_call("describe", "nfrs")
        assert "Availability" in nfrs and "99.9%" in nfrs
        assert "quality_class" in nfrs and "rationale" in nfrs

    async def test_complete_context_round_trip_and_validation(self):
        result = await context_call("set", "all", values={
            "business": complete_business_values(),
            "software": {"software_type": "API Service", "deployment_model": "PaaS"},
            "data_assets": [
                {"structural_category": "Structured Data", "name": "Orders"},
            ],
            "user_personas": [
                {"persona_type": "Authenticated Standard User", "name": "Customer"},
            ],
            "nfrs": [
                {"quality_class": "Availability", "level": "99.9%"},
            ],
        })
        assert "System Context Update" in result
        assert bctx.business_context.description == "Payment platform"
        assert cp.software_profile.software_type.value == "API Service"
        assert set(cp.data_asset_profiles) == {"DP001"}
        assert set(cp.user_personas) == {"UP001"}
        assert any(
            requirement.quality_class.value == "Availability"
            and requirement.level == "99.9%"
            for requirement in cp.nfr_profile.requirements
        )

        rendered = await context_call("get", "all")
        assert "Payment platform" in rendered
        assert "Orders" in rendered
        assert "Customer" in rendered

        validation = await context_call("validate", "all")
        assert "VALIDATION PASSED" in validation
        assert "Classification Profile Coverage" in validation

    async def test_batch_add_update_delete_data_asset_profiles(self):
        result = await context_call("add", "data_assets", items=[
            {"structural_category": "Structured Data", "name": "Orders"},
            {"structural_category": "Secrets and Credentials", "name": "API keys"},
        ])
        assert "Successfully added 2 data asset profile(s)" in result

        result = await context_call("update", "data_assets", items=[
            {"id": "DP001", "sensitivity_tier": "Restricted"},
            {"id": "DP002", "sensitivity_tier": "Public"},
        ])
        assert "Successfully updated 2 data asset profile(s)" in result
        assert cp.data_asset_profiles["DP001"].sensitivity_tier.value == "Restricted"

        result = await context_call(
            "delete", "data_assets", item_ids=["DP001", "DP002"]
        )
        assert "Successfully deleted 2 data asset profile(s)" in result
        assert cp.data_asset_profiles == {}

    async def test_batch_failure_does_not_discard_valid_profile(self):
        result = await context_call("add", "data_assets", items=[
            {"structural_category": "Structured Data", "name": "Orders"},
            {"structural_category": "Not A Category", "name": "Broken"},
        ])
        assert "Successfully added 1 data asset profile(s)" in result
        assert "Failed to add 1 data asset profile(s)" in result
        assert len(cp.data_asset_profiles) == 1

    async def test_single_and_batch_persona_crud(self):
        assert "UP001" in await context_call(
            "add", "user_personas",
            values={"persona_type": "System Administrator"},
        )
        await context_call(
            "add", "user_personas",
            items=[{"persona_type": "Data Subject"}],
        )
        result = await context_call(
            "update", "user_personas", item_id="UP001",
            values={"privilege_level": "Administrative"},
        )
        assert "updated" in result
        assert cp.user_personas["UP001"].privilege_level.value == "Administrative"

        result = await context_call(
            "delete", "user_personas", item_ids=["UP001", "UP002"]
        )
        assert "Successfully deleted 2 user persona(s)" in result
        assert cp.user_personas == {}

    async def test_nfr_set_list_and_delete(self):
        await context_call("set", "nfrs", items=[
            {"quality_class": "Availability", "level": "99.9%"},
            {"quality_class": "Scalability", "level": "Elastic"},
        ])
        listed = await context_call("list", "nfrs")
        assert "Availability" in listed and "Scalability" in listed

        result = await context_call("delete", "nfrs", item_id="Availability")
        assert "removed" in result
        assert all(
            requirement.quality_class.value != "Availability"
            for requirement in cp.nfr_profile.requirements
        )

    async def test_clear_all_resets_every_context_section(self):
        await context_call("set", "business", values=complete_business_values())
        await context_call("set", "software", values={"software_type": "API Service"})
        await context_call(
            "add", "data_assets", values={"structural_category": "API Data"}
        )
        result = await context_call("clear", "all")
        assert "Business context cleared" in result
        assert not bctx.business_context.description
        assert cp.software_profile is None
        assert cp.data_asset_profiles == {}

    @pytest.mark.parametrize("action,section,arguments,expected", [
        ("add", "data_assets", {}, "missing required field(s): structural_category"),
        ("add", "user_personas", {}, "missing required field(s): persona_type"),
        ("update", "data_assets", {}, "missing required field(s): id"),
        ("update", "user_personas", {}, "missing required field(s): id"),
        ("add", "software", {}, "not supported"),
        ("set", "software", {"values": {"bogus": "x"}}, "unexpected field(s): bogus"),
    ])
    async def test_invalid_requests_are_actionable(
        self, action, section, arguments, expected,
    ):
        assert expected in await context_call(action, section, **arguments)

    @pytest.mark.parametrize("arguments,field", [
        ({"action": "bogus", "section": "all"}, "action"),
        ({"action": "describe", "section": "bogus"}, "section"),
    ])
    async def test_schema_rejects_unknown_action_or_section(self, arguments, field):
        from mcp.server.fastmcp.exceptions import ToolError

        with pytest.raises(ToolError) as exc:
            await call("manage_system_context", **arguments)
        assert field in str(exc.value)

    async def test_empty_batch_is_not_an_error(self):
        assert "No data asset profiles provided" in await context_call(
            "add", "data_assets", items=[]
        )
        assert "No user persona IDs provided" in await context_call(
            "delete", "user_personas", item_ids=[]
        )

    async def test_business_updates_are_validated_and_atomic(self):
        await context_call("clear", "all")
        await context_call("set", "business", values=complete_business_values())
        before = bctx.business_context.model_dump()

        invalid_enum = await context_call(
            "set", "business", values={"industry_sector": "Nope"},
        )
        assert "BUSINESS CONTEXT REJECTED" in invalid_enum
        assert "BUSINESS CONTEXT COMPLETE" not in invalid_enum
        assert bctx.business_context.model_dump() == before

        invalid_type = await context_call(
            "set", "business", values={"description": 123},
        )
        assert "description: value must be text" in invalid_type
        assert bctx.business_context.model_dump() == before

    async def test_set_all_is_idempotent_for_collection_sections(self):
        await context_call("clear", "all")
        values = {
            "data_assets": [
                {"structural_category": "Structured Data", "name": "Orders"},
            ],
            "user_personas": [
                {"persona_type": "Data Subject", "name": "Customer"},
            ],
            "nfrs": [
                {"quality_class": "Availability", "level": "99.9%"},
            ],
        }

        await context_call("set", "all", values=values)
        await context_call("set", "all", values=values)

        assert set(cp.data_asset_profiles) == {"DP001"}
        assert set(cp.user_personas) == {"UP001"}
        assert len(cp.nfr_profile.requirements) == 1

    async def test_set_all_replaces_business_context_from_fresh_defaults(self):
        await context_call(
            "set", "business", values=complete_business_values(),
        )

        result = await context_call("set", "all", values={
            "business": {
                "description": "Replacement context",
                "industry_sector": "Healthcare",
            },
        })

        assert "still missing" in result
        assert bctx.business_context.description == "Replacement context"
        assert bctx.business_context.industry_sector.value == "Healthcare"
        assert bctx.business_context.sensitivity_tier is None
        assert bctx.business_context.regulatory_requirements == set()
        assert bctx.business_context.geographic_profile is None

    async def test_set_all_business_replacement_requires_its_own_description(self):
        await context_call(
            "set", "business", values=complete_business_values(),
        )
        before = bctx.business_context.model_dump()

        result = await context_call("set", "all", values={
            "business": {"industry_sector": "Healthcare"},
        })

        assert "SYSTEM CONTEXT REJECTED" in result
        assert "missing required field(s): description" in result
        assert bctx.business_context.model_dump() == before

    async def test_set_all_rejects_every_section_atomically(self):
        await context_call("clear", "all")
        await context_call(
            "add", "data_assets",
            values={"structural_category": "Metadata", "name": "Existing"},
        )

        result = await context_call("set", "all", values={
            "software": {"software_type": "Not A Software Type"},
            "data_assets": [
                {"structural_category": "Structured Data", "name": "Replacement"},
            ],
        })

        assert "SYSTEM CONTEXT REJECTED" in result
        assert cp.software_profile is None
        assert set(cp.data_asset_profiles) == {"DP001"}
        assert cp.data_asset_profiles["DP001"].name == "Existing"

    async def test_batch_refusals_are_not_reported_as_success(self):
        await context_call("clear", "all")
        add_result = await context_call(
            "add", "data_assets", items=[{"structural_category": ""}],
        )
        assert "Failed to add 1 data asset profile(s)" in add_result
        assert "Successfully added" not in add_result
        assert cp.data_asset_profiles == {}

        await context_call(
            "set", "nfrs",
            values={"quality_class": "Availability", "level": "99.9%"},
        )
        delete_result = await context_call(
            "delete", "nfrs", item_ids=["Scalability"],
        )
        assert "Failed to delete 1 NFR requirement(s)" in delete_result
        assert "Successfully deleted" not in delete_result

    async def test_regulatory_sentinel_values_are_exclusive(self):
        await context_call("clear", "all")
        values = complete_business_values()
        values["regulatory_requirements"] = ["None", "GDPR"]

        result = await context_call("set", "business", values=values)

        assert "cannot be combined" in result
        assert not bctx.business_context.description

    async def test_deployment_conflict_is_reported_in_reverse_order(self):
        await context_call("clear", "all")
        await context_call(
            "set", "software",
            values={"software_type": "API Service", "deployment_model": "IaaS"},
        )

        result = await context_call(
            "set", "business", values=complete_business_values(),
        )

        assert "Deployment model conflict" in result
        assert "IaaS" in result and "PaaS" in result

    async def test_profile_updates_can_clear_nullable_fields(self):
        await context_call("clear", "all")
        await context_call("add", "data_assets", values={
            "structural_category": "Structured Data",
            "asset_id": "A001",
            "description": "Customer records",
        })
        await context_call("add", "user_personas", values={
            "persona_type": "Data Subject",
            "name": "Customer",
            "authentication_method": "Password",
        })

        data_result = await context_call(
            "update", "data_assets", item_id="DP001",
            values={"clear_fields": ["asset_id", "description"]},
        )
        persona_result = await context_call(
            "update", "user_personas", item_id="UP001",
            values={"clear_fields": ["name", "authentication_method"]},
        )

        assert "updated" in data_result and "updated" in persona_result
        assert cp.data_asset_profiles["DP001"].asset_id is None
        assert cp.data_asset_profiles["DP001"].description is None
        assert cp.user_personas["UP001"].name is None
        assert cp.user_personas["UP001"].authentication_method is None

    async def test_classification_profile_ids_are_monotonic(self):
        await context_call(
            "add", "data_assets",
            values={"structural_category": "Metadata"},
        )
        await context_call(
            "add", "data_assets",
            values={"structural_category": "API Data"},
        )
        await context_call("delete", "data_assets", item_id="DP001")
        await context_call(
            "add", "data_assets",
            values={"structural_category": "Structured Data"},
        )

        assert set(cp.data_asset_profiles) == {"DP002", "DP003"}

    async def test_batch_data_profile_accepts_scalar_data_state(self):
        result = await context_call("add", "data_assets", items=[
            {
                "structural_category": "Structured Data",
                "data_states": "At rest",
            },
        ])

        assert "Successfully added 1 data asset profile(s)" in result
        assert [
            state.value for state in cp.data_asset_profiles["DP001"].data_states
        ] == ["At rest"]



class TestRegulatoryRequirementTokens:
    """Each comma-separated token is validated on its own."""

    async def test_a_bad_token_rejects_the_entire_update(self, ctx):
        await bctx.clear_business_context_impl(ctx)
        result = await bctx.set_business_context_with_features_impl(
            ctx, description="Payments platform",
            regulatory_requirements="GDPR, HIPPA, PCI-DSS",
        )
        assert bctx.business_context.regulatory_requirements == set()
        assert not bctx.business_context.description
        assert "HIPPA" in result
        assert "no changes were applied" in result

    async def test_all_tokens_valid_stores_all_of_them(self, ctx):
        await bctx.set_business_context_with_features_impl(
            ctx, description="Health platform",
            regulatory_requirements="HIPAA, CCPA / CPRA",
        )
        stored = {r.value for r in bctx.business_context.regulatory_requirements}
        assert stored == {"HIPAA", "CCPA / CPRA"}


class TestDeploymentModelConflict:
    """deployment_model has two homes; a disagreement must be surfaced."""

    async def test_conflicting_values_warn(self, ctx):
        await bctx.set_business_context_with_features_impl(
            ctx, description="Service", deployment_model="SaaS")
        result = await cp.set_software_profile_impl(
            ctx, "API Service", deployment_model="On-premises")
        assert "Deployment model conflict" in result
        assert "SaaS" in result and "On-premises" in result

    async def test_agreeing_values_do_not_warn(self, ctx):
        await bctx.set_business_context_with_features_impl(
            ctx, description="Service", deployment_model="SaaS")
        result = await cp.set_software_profile_impl(
            ctx, "API Service", deployment_model="SaaS")
        assert "conflict" not in result

    async def test_no_business_context_value_does_not_warn(self, ctx):
        result = await cp.set_software_profile_impl(
            ctx, "API Service", deployment_model="Serverless / FaaS")
        assert "conflict" not in result
