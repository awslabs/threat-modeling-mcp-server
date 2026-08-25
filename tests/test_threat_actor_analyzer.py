"""Tests for threat-actor MCP operations and taxonomy validation."""

from unittest.mock import AsyncMock

import pytest

import threat_modeling_mcp_server.server as srv
import threat_modeling_mcp_server.tools.threat_actor_analyzer as actors


async def call(tool_name, **arguments):
    """Invoke a registered MCP tool and return its text result."""
    _, structured = await srv.mcp.call_tool(tool_name, arguments)
    return structured["result"]


@pytest.fixture
def ctx():
    return AsyncMock()


class TestThreatActorBatchToolBoundary:
    async def test_batch_add_threat_actors(self):
        result = await call("add_threat_actor", items=[
            {
                "name": "Batch Hacktivist",
                "type": "Hacktivist",
                "sophistication_tier": "Tier 2 - Hacktivist / campaign-driven",
                "motivations": ["Ideological / hacktivism"],
                "resources": "Contest / crowd",
            },
            {
                "name": "Batch Competitor",
                "type": "Competitor / Corporate Espionage",
                "sophistication_tier": "Tier 3 - Organized cybercrime",
                "motivations": [
                    "Competitive advantage",
                    "Espionage / intelligence collection",
                ],
                "resources": "Organization",
            },
        ])

        assert "Successfully added 2 threat actor(s)" in result
        by_name = {actor.name: actor for actor in actors.threat_actors.values()}
        assert {"Batch Hacktivist", "Batch Competitor"} <= by_name.keys()
        assert by_name["Batch Hacktivist"].resources.value == "Contest / crowd"


class TestThreatActorTaxonomyOperations:
    async def test_update_is_atomic_when_a_taxonomy_value_is_invalid(self, ctx):
        actors.initialize_threat_actors()
        actor_id = next(iter(actors.threat_actors))
        original = actors.threat_actors[actor_id]
        before = original.model_dump()

        with pytest.raises(ValueError):
            await actors.update_threat_actor_impl(
                ctx,
                id=actor_id,
                name="Name that must not persist",
                resources="Not a resource level",
            )

        assert actors.threat_actors[actor_id] is original
        assert actors.threat_actors[actor_id].model_dump() == before

    async def test_type_filter_uses_canonical_validation(self, ctx):
        result = await actors.list_threat_actors_impl(
            ctx, type="nation-state / apt",
        )
        assert "**Type:** Nation-State / APT" in result

        with pytest.raises(ValueError) as exc:
            await actors.list_threat_actors_impl(ctx, type="APT")
        assert "Valid options are" in str(exc.value)
        assert "Nation-State / APT" in str(exc.value)

    async def test_unprioritized_analysis_includes_all_actor_facets(self, ctx):
        await actors.add_threat_actor_impl(
            ctx,
            name="Unranked Taxonomy Actor",
            type="External Attacker",
            sophistication_tier="Tier 2 - Hacktivist / campaign-driven",
            motivations=["Ideological / hacktivism"],
            resources="Club / small group",
            relationship_to_target="Partner / third-party",
            state_nexus="State-aligned",
            targeting_specificity="Sector-focused",
        )

        result = await actors.analyze_threat_actors_impl(ctx)
        unprioritized = result.split("## Unprioritized Threat Actors", 1)[1]
        assert "Unranked Taxonomy Actor" in unprioritized
        assert "**Relationship to Target:** Partner / third-party" in unprioritized
        assert "**State Nexus:** State-aligned" in unprioritized
        assert "**Targeting Specificity:** Sector-focused" in unprioritized

    async def test_accepts_differently_cased_values(self, ctx):
        await actors.add_threat_actor_impl(
            ctx,
            name="Casing test",
            type="hacktivist",
            sophistication_tier="tier 2 - hacktivist / campaign-driven",
            motivations=["ideological / hacktivism"],
            resources="club / small group",
            relationship_to_target="external",
            state_nexus="none",
            targeting_specificity="opportunistic",
        )

        actor = next(
            actor for actor in actors.threat_actors.values()
            if actor.name == "Casing test"
        )
        assert actor.sophistication_tier.value == (
            "Tier 2 - Hacktivist / campaign-driven"
        )
        assert actor.resources.value == "Club / small group"

    async def test_invalid_value_lists_valid_options(self, ctx):
        with pytest.raises(ValueError) as exc:
            await actors.add_threat_actor_impl(
                ctx,
                name="Bad tier",
                type="Hacktivist",
                sophistication_tier="Tier 9 - Imaginary",
                motivations=["Ideology / hacktivism"],
                resources="Team",
            )
        assert "Valid options are" in str(exc.value)


class TestThreatActorIds:
    async def test_id_is_not_reused_after_delete(self, ctx):
        actors.initialize_threat_actors()
        original_ids = set(actors.threat_actors)
        victim = sorted(original_ids)[0]

        await actors.delete_threat_actor_impl(ctx, victim)
        await actors.add_threat_actor_impl(
            ctx,
            name="New actor",
            type="Insider Threat",
            sophistication_tier="Tier 1 - Opportunistic / script kiddie",
            motivations=["Financial gain"],
            resources="Individual",
        )

        assert original_ids - {victim} <= set(actors.threat_actors)
        assert len(actors.threat_actors) == len(original_ids)
