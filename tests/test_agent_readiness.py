"""Tests for the four faults a live stdio session hit when driving this server.

Each class covers one of them:

1. Pre-loaded reference data satisfied phase gates and was exported as project data.
2. ``get_current_phase_status`` always failed: the registered tool shadowed the
   module-level function of the same name and called itself. The server
   instructions advertise it, and ``advance_phase``'s own refusal message tells a
   blocked agent to call it.
3. ``batch_update``/``batch_delete`` counted an impl's "not found" message as a
   success, reporting "Successfully deleted 1" for an ID that never existed.
4. A malformed ``items=[...]`` entry surfaced a raw ``TypeError`` naming the
   internal ``*_impl`` function instead of the field the caller had to fix.
"""

from unittest.mock import AsyncMock

import pytest

import threat_modeling_mcp_server.tools.asset_flow_analyzer as afa
import threat_modeling_mcp_server.tools.threat_actor_analyzer as taa
import threat_modeling_mcp_server.tools.trust_boundary_analyzer as tba
from threat_modeling_mcp_server.tools.step_orchestrator import (
    detect_phase_completion,
    get_current_phase_status_impl,
    phase_completion,
)
from threat_modeling_mcp_server.utils.batch_utils import (
    batch_add,
    batch_delete,
    batch_update,
)
from threat_modeling_mcp_server.utils.comprehensive_exporter import (
    build_extended_export_data,
    generate_threat_model_markdown,
)
from threat_modeling_mcp_server.utils.state_collector import (
    collect_all_state,
    get_state_summary,
)


@pytest.fixture
def only_defaults(empty_threat_model_state):
    """A fresh server with only the threat-actor catalogue loaded."""
    taa.initialize_threat_actors()
    yield


class TestPreloadedDefaultsDoNotCountAsWork:
    """Catalog defaults do not count as work, and trust state starts empty."""

    def test_actor_catalogue_is_unreviewed_and_project_state_is_empty(self, only_defaults):
        summary = get_state_summary()

        assert summary["threat_actors"] > 0
        assert summary["reviewed_threat_actors"] == 0
        assert summary["trust_boundaries"]["trust_zones"] == 0
        assert summary["asset_flows"] == {"assets": 0, "flows": 0}

    def test_cold_server_reports_no_phase_complete(self, only_defaults):
        detect_phase_completion()

        assert phase_completion[3] == 0.0
        assert phase_completion[4] == 0.0
        assert phase_completion[5] == 0.0
        assert get_current_phase_status_impl()["overall_completion"] == 0.0

    @pytest.mark.asyncio
    async def test_assessing_a_default_actor_completes_phase_3(self, only_defaults):
        actor_id = next(iter(taa.threat_actors))

        # Recording a priority for a pre-loaded actor is exactly the decision the
        # gate is meant to detect, so the catalogue stays useful as a starting
        # point rather than something to be re-typed.
        await taa.update_threat_actor_impl(AsyncMock(), id=actor_id, priority=7)

        detect_phase_completion()
        assert phase_completion[3] == 1.0

    @pytest.mark.asyncio
    async def test_set_relevance_completes_phase_3(self, only_defaults):
        # Step 3 of the documented Phase 3 workflow. Ruling an actor *out* is a
        # decision too, so is_relevant=False has to count.
        actor_id = next(iter(taa.threat_actors))
        await taa.set_threat_actor_relevance_impl(
            AsyncMock(), id=actor_id, is_relevant=False
        )

        detect_phase_completion()
        assert phase_completion[3] == 1.0

    @pytest.mark.asyncio
    async def test_set_priority_completes_phase_3(self, only_defaults):
        # Step 4 of the documented Phase 3 workflow.
        actor_id = next(iter(taa.threat_actors))
        await taa.set_threat_actor_priority_impl(AsyncMock(), id=actor_id, priority=2)

        detect_phase_completion()
        assert phase_completion[3] == 1.0

    @pytest.mark.asyncio
    async def test_adding_a_zone_completes_phase_4(self, only_defaults):
        await tba.add_trust_zone_impl(
            AsyncMock(), name="Payments VPC", trust_level="Medium"
        )

        detect_phase_completion()
        assert phase_completion[4] == 1.0

    @pytest.mark.asyncio
    async def test_clear_trust_boundaries_stays_empty(self, only_defaults):
        await tba.add_trust_zone_impl(
            AsyncMock(), name="Public", trust_level="Untrusted"
        )
        await tba.add_trust_zone_impl(
            AsyncMock(), name="Private", trust_level="High"
        )
        zone_ids = list(tba.trust_zones)
        await tba.add_crossing_point_impl(
            AsyncMock(), source_zone_id=zone_ids[0], destination_zone_id=zone_ids[1]
        )
        crossing_id = next(iter(tba.crossing_points))
        await tba.add_trust_boundary_impl(
            AsyncMock(), name="Network Edge", type="Network",
            crossing_point_ids=[crossing_id],
        )
        stores = (tba.trust_zones, tba.crossing_points, tba.trust_boundaries)

        await tba.clear_trust_boundaries_impl(AsyncMock())

        assert all(
            original is current
            for original, current in zip(
                stores, (tba.trust_zones, tba.crossing_points, tba.trust_boundaries)
            )
        )
        assert not any(stores)
        result = await tba.list_trust_zones_impl(AsyncMock())
        assert result == "No trust zones have been added yet."

    @pytest.mark.asyncio
    async def test_adding_an_asset_completes_phase_5(self, only_defaults):
        await afa.add_asset_impl(
            AsyncMock(), name="Card number", type="Data", classification="Restricted"
        )

        detect_phase_completion()
        assert phase_completion[5] == 1.0


class TestExportSeparatesTheCatalogue:
    """The deliverable reports assessed records; the rest goes in an appendix."""

    def test_statistics_and_sections_exclude_unreviewed_defaults(self, only_defaults):
        md = generate_threat_model_markdown(collect_all_state())

        assert "- **Assets**: 0" in md
        assert "- **Threat Actors**: 0" in md
        assert "*No threat actors reviewed for this system.*" in md
        assert "*No trust zones or boundaries defined for this system.*" in md
        assert "*No assets or flows defined for this system.*" in md

    def test_unreviewed_defaults_are_listed_in_the_appendix(self, only_defaults):
        md = generate_threat_model_markdown(collect_all_state())

        assert "## Appendix: Reference Catalogue (Not Reviewed)" in md
        assert "never assessed for this system" in md
        # Named, so a reviewer can see what was available and skipped.
        for actor in taa.threat_actors.values():
            assert actor.name in md

    @pytest.mark.asyncio
    async def test_project_assets_are_exported_in_the_body(self, only_defaults):
        await afa.add_asset_impl(
            AsyncMock(), name="Card number", type="Data", classification="Restricted"
        )

        md = generate_threat_model_markdown(collect_all_state())

        assert "- **Assets**: 1" in md
        assert "| Card number |" in md
        appendix = md.split("## Appendix: Reference Catalogue (Not Reviewed)")[1]
        assert "Card number" not in appendix

    def test_no_appendix_when_there_is_nothing_unreviewed(self, empty_threat_model_state):
        md = generate_threat_model_markdown(collect_all_state())

        assert "## Appendix" not in md
        assert "12. [Appendix" not in md

    @pytest.mark.asyncio
    async def test_json_export_keeps_the_catalogue_out_of_the_model(self, only_defaults):
        await taa.add_threat_actor_impl(
            AsyncMock(),
            name="Contractor with repo access",
            type="Insider Threat",
            sophistication_tier="Tier 1 - Opportunistic / script kiddie",
            motivations=["Financial gain"],
            resources="Individual",
        )

        data = build_extended_export_data(collect_all_state())

        names = [actor["name"] for actor in data["threatActors"]]
        assert names == ["Contractor with repo access"]

        catalogue = data["referenceCatalogue"]
        assert len(catalogue["threatActors"]) == len(taa.threat_actors) - 1
        for key in ("trustZones", "crossingPoints", "trustBoundaries"):
            assert key not in catalogue
        assert "assets" not in catalogue
        assert "flows" not in catalogue
        assert data["assets"] == []


class TestGetCurrentPhaseStatusTool:
    """The tool an agent is told to call when advance_phase refuses."""

    @pytest.mark.asyncio
    async def test_registered_tool_returns_a_status(self):
        from mcp.server.fastmcp import FastMCP

        from threat_modeling_mcp_server.tools import step_orchestrator

        mcp = FastMCP("test")
        step_orchestrator.register_tools(mcp)

        # Called the way a client calls it: through FastMCP, not by reaching for
        # the module-level function. The registered closure used to shadow that
        # function and recurse into itself, so every call failed.
        result = await mcp.call_tool("get_current_phase_status", {})

        assert "current_phase" in str(result)
        assert "overall_completion" in str(result)


class TestBatchFailuresAreReported:
    """A refusal returned as prose is a failure, not a success."""

    @pytest.mark.asyncio
    async def test_delete_does_not_claim_to_have_deleted_a_missing_id(self, only_defaults):
        await afa.add_asset_impl(
            AsyncMock(), name="Temporary", type="Data", classification="Internal"
        )
        real_id = next(iter(afa.assets))

        result = await batch_delete(
            AsyncMock(),
            ids=[real_id, "A999-does-not-exist"],
            single_id=None,
            impl_fn=afa.delete_asset_impl,
            entity_name="asset",
        )

        assert "Successfully deleted 1 asset(s)" in result
        assert "Failed to delete 1 asset(s)" in result
        assert "A999-does-not-exist" in result

    @pytest.mark.asyncio
    async def test_update_does_not_claim_to_have_updated_a_missing_id(self, only_defaults):
        await afa.add_asset_impl(
            AsyncMock(), name="Temporary", type="Data", classification="Internal"
        )
        real_id = next(iter(afa.assets))

        result = await batch_update(
            AsyncMock(),
            items=[
                {"id": real_id, "owner": "payments-team"},
                {"id": "A999-does-not-exist", "owner": "nobody"},
            ],
            single_item_kwargs={},
            impl_fn=afa.update_asset_impl,
            entity_name="asset",
        )

        assert "Successfully updated 1 asset(s)" in result
        assert "Failed to update 1 asset(s)" in result

    @pytest.mark.asyncio
    async def test_partial_batch_still_applies_the_good_items(self, only_defaults):
        before = len(afa.assets)

        await batch_add(
            AsyncMock(),
            items=[
                {"name": "Card number", "type": "Data", "classification": "Restricted"},
                {"name": "Broken", "type": "Data", "classification": "Not a tier"},
            ],
            single_item_kwargs={},
            impl_fn=afa.add_asset_impl,
            entity_name="asset",
        )

        assert len(afa.assets) == before + 1


class TestBatchItemErrorsNameTheField:
    """A malformed item should say which field is wrong, not leak a TypeError."""

    @pytest.mark.asyncio
    async def test_missing_required_field_is_named(self, only_defaults):
        result = await batch_add(
            AsyncMock(),
            items=[{"name": "Card number", "type": "Data"}],
            single_item_kwargs={},
            impl_fn=afa.add_asset_impl,
            entity_name="asset",
        )

        assert "missing required field(s): classification" in result
        assert "accepted fields:" in result
        # None of the internal plumbing.
        assert "positional argument" not in result
        assert "add_asset_impl" not in result

    @pytest.mark.asyncio
    async def test_misspelled_field_is_named(self, only_defaults):
        result = await batch_add(
            AsyncMock(),
            items=[
                {
                    "name": "Card number",
                    "type": "Data",
                    "classification": "Restricted",
                    "criticallity": 5,
                }
            ],
            single_item_kwargs={},
            impl_fn=afa.add_asset_impl,
            entity_name="asset",
        )

        assert "unexpected field(s): criticallity" in result
        assert "criticality" in result, "the accepted spelling should be listed"
