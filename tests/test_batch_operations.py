"""Tests for batch operation support across all CRUD tools."""

import pytest
from unittest.mock import AsyncMock

from threat_modeling_mcp_server.tools.architecture_analyzer import (
    add_component_impl, update_component_impl, delete_component_impl,
    components, architecture
)
from threat_modeling_mcp_server.tools.assumption_manager import (
    add_assumption_impl, update_assumption_impl, delete_assumption_impl,
    assumptions
)
from threat_modeling_mcp_server.tools.threat_actor_analyzer import (
    add_threat_actor_impl, update_threat_actor_impl, delete_threat_actor_impl,
    threat_actors, initialize_threat_actors
)
from threat_modeling_mcp_server.tools.threat_generator import (
    add_threat_impl, update_threat_impl, delete_threat_impl,
    add_mitigation_impl, update_mitigation_impl, delete_mitigation_impl,
    threats, mitigations
)
from threat_modeling_mcp_server.tools.asset_flow_analyzer import (
    add_asset_impl, update_asset_impl, delete_asset_impl,
    add_flow_impl, update_flow_impl, delete_flow_impl,
    assets, flows
)
from threat_modeling_mcp_server.tools.trust_boundary_analyzer import (
    add_trust_zone_impl, update_trust_zone_impl, delete_trust_zone_impl,
    add_crossing_point_impl, delete_crossing_point_impl,
    add_trust_boundary_impl, delete_trust_boundary_impl,
    trust_zones, crossing_points, trust_boundaries
)
from threat_modeling_mcp_server.utils.batch_utils import batch_add, batch_update, batch_delete


@pytest.fixture
def ctx():
    """Create a mock context."""
    return AsyncMock()


@pytest.fixture(autouse=True)
def clear_state():
    """Clear global state before each test."""
    components.clear()
    architecture.components = []
    architecture.connections = []
    architecture.data_stores = []
    assumptions.clear()
    threats.clear()
    mitigations.clear()
    assets.clear()
    flows.clear()
    trust_zones.clear()
    crossing_points.clear()
    trust_boundaries.clear()
    yield


# ============================================================
# Architecture: Components
# ============================================================

class TestBatchAddComponents:
    async def test_single_item_mode(self, ctx):
        """Single item mode still works (backwards compat)."""
        result = await batch_add(
            ctx, None,
            {"name": "Web Server", "type": "Compute"},
            add_component_impl, "component"
        )
        assert "Component added with ID:" in result
        assert len(components) == 1

    async def test_batch_mode(self, ctx):
        """Batch mode adds multiple components."""
        items = [
            {"name": "Web Server", "type": "Compute"},
            {"name": "Database", "type": "Storage"},
            {"name": "Load Balancer", "type": "Network"},
        ]
        result = await batch_add(ctx, items, {}, add_component_impl, "component")
        assert "Successfully added 3 component(s)" in result
        assert len(components) == 3

    async def test_batch_empty_list(self, ctx):
        """Empty batch returns appropriate message."""
        result = await batch_add(ctx, [], {}, add_component_impl, "component")
        assert "No components provided in batch" in result

    async def test_batch_with_optional_fields(self, ctx):
        """Batch items can include optional fields."""
        items = [
            {"name": "Lambda", "type": "Compute", "service_provider": "AWS", "specific_service": "Lambda"},
            {"name": "S3 Bucket", "type": "Storage", "service_provider": "AWS", "description": "Main storage"},
        ]
        result = await batch_add(ctx, items, {}, add_component_impl, "component")
        assert "Successfully added 2 component(s)" in result
        # Verify optional fields were set
        comp_list = list(components.values())
        assert comp_list[0].specific_service == "Lambda"
        assert comp_list[1].description == "Main storage"

    async def test_batch_with_invalid_item(self, ctx):
        """Batch handles errors gracefully for individual items."""
        items = [
            {"name": "Web Server", "type": "Compute"},
            {"name": "Bad Component", "type": "InvalidType"},  # Invalid enum
        ]
        result = await batch_add(ctx, items, {}, add_component_impl, "component")
        assert "Successfully added 1 component(s)" in result
        assert "Failed to add 1 component(s)" in result


class TestBatchUpdateComponents:
    async def test_single_item_mode(self, ctx):
        """Single item update still works."""
        await add_component_impl(ctx, "Web Server", "Compute")
        comp_id = list(components.keys())[0]
        result = await batch_update(
            ctx, None,
            {"id": comp_id, "name": "Updated Server"},
            update_component_impl, "component"
        )
        assert "updated successfully" in result
        assert components[comp_id].name == "Updated Server"

    async def test_batch_mode(self, ctx):
        """Batch update modifies multiple components."""
        await add_component_impl(ctx, "Server A", "Compute")
        await add_component_impl(ctx, "Server B", "Compute")
        ids = list(components.keys())
        
        items = [
            {"id": ids[0], "name": "Updated A"},
            {"id": ids[1], "name": "Updated B"},
        ]
        result = await batch_update(ctx, items, {}, update_component_impl, "component")
        assert "Successfully updated 2 component(s)" in result
        assert components[ids[0]].name == "Updated A"
        assert components[ids[1]].name == "Updated B"


class TestBatchDeleteComponents:
    async def test_single_item_mode(self, ctx):
        """Single item delete still works."""
        await add_component_impl(ctx, "Web Server", "Compute")
        comp_id = list(components.keys())[0]
        result = await batch_delete(ctx, None, comp_id, delete_component_impl, "component")
        assert "deleted successfully" in result
        assert len(components) == 0

    async def test_batch_mode(self, ctx):
        """Batch delete removes multiple components."""
        await add_component_impl(ctx, "Server A", "Compute")
        await add_component_impl(ctx, "Server B", "Compute")
        await add_component_impl(ctx, "Server C", "Compute")
        ids = list(components.keys())
        
        result = await batch_delete(ctx, [ids[0], ids[2]], None, delete_component_impl, "component")
        assert "Successfully deleted 2 component(s)" in result
        assert len(components) == 1
        assert ids[1] in components

    async def test_batch_with_nonexistent_id(self, ctx):
        """Batch delete handles missing IDs gracefully."""
        await add_component_impl(ctx, "Server A", "Compute")
        comp_id = list(components.keys())[0]
        
        result = await batch_delete(ctx, [comp_id, "NONEXISTENT"], None, delete_component_impl, "component")
        # The first should succeed, second should report "not found" (not an exception)
        assert "deleted successfully" in result


# ============================================================
# Assumptions
# ============================================================

class TestBatchAssumptions:
    async def test_batch_add(self, ctx):
        items = [
            {"description": "Network is secure", "category": "Network", "impact": "Low", "rationale": "Internal only"},
            {"description": "Auth is MFA", "category": "Authentication", "impact": "Medium", "rationale": "Policy"},
        ]
        result = await batch_add(ctx, items, {}, add_assumption_impl, "assumption")
        assert "Successfully added 2 assumption(s)" in result
        assert len(assumptions) == 2

    async def test_batch_delete(self, ctx):
        await add_assumption_impl(ctx, "Assumption 1", "Network", "Low", "Reason")
        await add_assumption_impl(ctx, "Assumption 2", "Auth", "High", "Reason")
        ids = list(assumptions.keys())
        result = await batch_delete(ctx, ids, None, delete_assumption_impl, "assumption")
        assert "Successfully deleted 2 assumption(s)" in result
        assert len(assumptions) == 0


# ============================================================
# Threats and Mitigations
# ============================================================

class TestBatchThreats:
    async def test_batch_add_threats(self, ctx):
        items = [
            {"threat_source": "attacker", "prerequisites": "network access",
             "threat_action": "intercept data", "threat_impact": "data breach"},
            {"threat_source": "insider", "prerequisites": "valid credentials",
             "threat_action": "exfiltrate data", "threat_impact": "IP theft"},
        ]
        result = await batch_add(ctx, items, {}, add_threat_impl, "threat")
        assert "Successfully added 2 threat(s)" in result
        assert len(threats) == 2

    async def test_batch_delete_threats(self, ctx):
        await add_threat_impl(ctx, "src", "pre", "action", "impact")
        await add_threat_impl(ctx, "src2", "pre2", "action2", "impact2")
        ids = list(threats.keys())
        result = await batch_delete(ctx, ids, None, delete_threat_impl, "threat")
        assert "Successfully deleted 2 threat(s)" in result

    async def test_batch_add_mitigations(self, ctx):
        items = [
            {"content": "Implement TLS"},
            {"content": "Add WAF", "type": "Preventive"},
        ]
        result = await batch_add(ctx, items, {}, add_mitigation_impl, "mitigation")
        assert "Successfully added 2 mitigation(s)" in result
        assert len(mitigations) == 2


# ============================================================
# Assets and Flows
# ============================================================

class TestBatchAssets:
    async def test_batch_add_assets(self, ctx):
        items = [
            {"name": "User PII", "type": "Data", "classification": "Confidential"},
            {"name": "API Key", "type": "Credential", "classification": "Restricted"},
        ]
        result = await batch_add(ctx, items, {}, add_asset_impl, "asset")
        assert "Successfully added 2 asset(s)" in result
        assert len(assets) == 2

    async def test_batch_delete_assets(self, ctx):
        await add_asset_impl(ctx, "Asset 1", "Data", "Public")
        await add_asset_impl(ctx, "Asset 2", "Data", "Internal")
        ids = list(assets.keys())
        result = await batch_delete(ctx, ids, None, delete_asset_impl, "asset")
        assert "Successfully deleted 2 asset(s)" in result


# ============================================================
# Trust Zones
# ============================================================

class TestBatchTrustZones:
    async def test_batch_add_trust_zones(self, ctx):
        import threat_modeling_mcp_server.tools.trust_boundary_analyzer as tba
        initial_count = len(tba.trust_zones)
        items = [
            {"name": "Public Zone", "trust_level": "Untrusted"},
            {"name": "Internal Zone", "trust_level": "High"},
        ]
        result = await batch_add(ctx, items, {}, add_trust_zone_impl, "trust zone")
        assert "Successfully added 2 trust zone(s)" in result
        assert len(tba.trust_zones) == initial_count + 2

    async def test_batch_delete_trust_zones(self, ctx):
        import threat_modeling_mcp_server.tools.trust_boundary_analyzer as tba
        await add_trust_zone_impl(ctx, "Zone A", "Untrusted")
        await add_trust_zone_impl(ctx, "Zone B", "High")
        all_ids = list(tba.trust_zones.keys())
        new_ids = all_ids[-2:]
        result = await batch_delete(ctx, new_ids, None, delete_trust_zone_impl, "trust zone")
        assert "Successfully deleted 2 trust zone(s)" in result
