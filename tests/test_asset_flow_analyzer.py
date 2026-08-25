"""Regression tests for asset and flow state integrity."""

from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

import threat_modeling_mcp_server.tools.architecture_analyzer as architecture
import threat_modeling_mcp_server.tools.asset_flow_analyzer as asset_flows
import threat_modeling_mcp_server.server as srv
from threat_modeling_mcp_server.utils.batch_utils import batch_update
from threat_modeling_mcp_server.utils.comprehensive_exporter import (
    build_extended_export_data,
)
from threat_modeling_mcp_server.utils.state_collector import collect_all_state


pytestmark = pytest.mark.usefixtures("empty_threat_model_state")


async def call(tool_name, **arguments):
    _, structured = await srv.mcp.call_tool(tool_name, arguments)
    return structured["result"]


async def add_components(ctx):
    await architecture.add_component_impl(ctx, "Client", "Compute")
    await architecture.add_component_impl(ctx, "Service", "Compute")
    return list(architecture.components)


async def add_asset(ctx, **overrides):
    values = {
        "name": "Customer record",
        "type": "Data",
        "classification": "Confidential",
    }
    values.update(overrides)
    result = await asset_flows.add_asset_impl(ctx, **values)
    assert result.startswith("Asset added with ID:")
    return next(reversed(asset_flows.assets))


async def add_flow(ctx, asset_id, source_id, destination_id, **overrides):
    result = await asset_flows.add_flow_impl(
        ctx,
        asset_id=asset_id,
        source_id=source_id,
        destination_id=destination_id,
        **overrides,
    )
    assert result.startswith("Flow added with ID:")
    return next(reversed(asset_flows.flows))


def test_asset_flow_state_starts_empty():
    assert asset_flows.assets == {}
    assert asset_flows.flows == {}


@pytest.mark.asyncio
async def test_flows_require_existing_components_and_accept_case_insensitive_enums():
    ctx = AsyncMock()
    asset_id = await add_asset(ctx)

    result = await asset_flows.add_flow_impl(ctx, asset_id, "C404", "C405")
    assert result == "Source component with ID C404 not found"
    assert asset_flows.flows == {}

    source_id, destination_id = await add_components(ctx)
    flow_id = await add_flow(
        ctx,
        asset_id,
        source_id,
        destination_id,
        transformation_type="encryption",
        controls=["input validation"],
    )

    flow = asset_flows.flows[flow_id]
    assert flow.transformation_type.value == "Encryption"
    assert [control.value for control in flow.controls] == ["Input Validation"]
    assert "Customer record" in await asset_flows.list_assets_impl(ctx, type="data")


@pytest.mark.asyncio
async def test_asset_updates_are_atomic_and_enforce_criticality_range():
    ctx = AsyncMock()
    asset_id = await add_asset(ctx, criticality=3)
    before = asset_flows.assets[asset_id].model_dump()

    result = await asset_flows.update_asset_impl(
        ctx, asset_id, name="Changed", criticality=6
    )

    assert result.startswith("Invalid asset update:")
    assert asset_flows.assets[asset_id].model_dump() == before

    batch_result = await batch_update(
        ctx,
        items=[{"id": asset_id, "name": "Changed", "criticality": "high"}],
        single_item_kwargs={},
        impl_fn=asset_flows.update_asset_impl,
        entity_name="asset",
    )
    assert "Failed to update 1 asset(s)" in batch_result
    assert asset_flows.assets[asset_id].model_dump() == before

    with pytest.raises(ValidationError):
        await asset_flows.add_asset_impl(
            ctx, "Invalid", "Data", "Internal", criticality=0
        )


@pytest.mark.asyncio
async def test_flow_updates_are_atomic_and_enforce_risk_range():
    ctx = AsyncMock()
    source_id, destination_id = await add_components(ctx)
    asset_id = await add_asset(ctx)
    flow_id = await add_flow(
        ctx, asset_id, source_id, destination_id, risk_level=3
    )
    before = asset_flows.flows[flow_id].model_dump()

    result = await asset_flows.update_flow_impl(ctx, flow_id, source_id="C404")
    assert result == "Source component with ID C404 not found"
    assert asset_flows.flows[flow_id].model_dump() == before

    result = await asset_flows.update_flow_impl(
        ctx, flow_id, description="Changed", risk_level=8
    )
    assert result.startswith("Invalid flow update:")
    assert asset_flows.flows[flow_id].model_dump() == before

    batch_result = await batch_update(
        ctx,
        items=[{"id": flow_id, "encryption": "false", "risk_level": "high"}],
        single_item_kwargs={},
        impl_fn=asset_flows.update_flow_impl,
        entity_name="flow",
    )
    assert "Failed to update 1 flow(s)" in batch_result
    assert asset_flows.flows[flow_id].model_dump() == before

    with pytest.raises(ValidationError):
        await asset_flows.add_flow_impl(
            ctx, asset_id, source_id, destination_id, risk_level=0
        )


@pytest.mark.asyncio
async def test_nullable_fields_can_be_cleared_explicitly():
    ctx = AsyncMock()
    source_id, destination_id = await add_components(ctx)
    asset_id = await add_asset(
        ctx,
        lifecycle_state="Active",
        owner="Payments",
        criticality=4,
        metadata={"source": "schema"},
    )
    flow_id = await add_flow(
        ctx,
        asset_id,
        source_id,
        destination_id,
        transformation_type="Processing",
        protocol="HTTPS",
        risk_level=2,
    )

    result = await asset_flows.update_asset_impl(
        ctx, asset_id, clear_fields=["owner", "criticality", "metadata"]
    )
    assert result == f"Asset {asset_id} updated successfully"
    asset = asset_flows.assets[asset_id]
    assert asset.owner is None
    assert asset.criticality is None
    assert asset.metadata is None

    result = await asset_flows.update_flow_impl(
        ctx,
        flow_id,
        clear_fields=["transformation_type", "protocol", "risk_level"],
    )
    assert result == f"Flow {flow_id} updated successfully"
    flow = asset_flows.flows[flow_id]
    assert flow.transformation_type is None
    assert flow.protocol is None
    assert flow.risk_level is None


@pytest.mark.asyncio
async def test_component_deletion_and_architecture_clear_preserve_flow_references():
    ctx = AsyncMock()
    source_id, destination_id = await add_components(ctx)
    asset_id = await add_asset(ctx)
    flow_id = await add_flow(ctx, asset_id, source_id, destination_id)

    result = await architecture.delete_component_impl(ctx, source_id)
    assert result == (
        f"Cannot delete component {source_id} because it is used in asset flows: "
        f"{flow_id}"
    )
    assert source_id in architecture.components

    result = await architecture.clear_architecture_impl(ctx)
    assert result == (
        f"Cannot clear architecture because it is used by asset flows: {flow_id}"
    )
    assert set(architecture.components) == {source_id, destination_id}


@pytest.mark.asyncio
async def test_export_contains_project_assets_and_no_asset_catalogue():
    ctx = AsyncMock()
    source_id, destination_id = await add_components(ctx)
    asset_id = await add_asset(ctx)
    flow_id = await add_flow(ctx, asset_id, source_id, destination_id)

    data = build_extended_export_data(collect_all_state())

    assert [asset["id"] for asset in data["assets"]] == [asset_id]
    assert [flow["id"] for flow in data["flows"]] == [flow_id]
    assert data["flows"][0]["asset_id"] == asset_id
    assert "assets" not in data["referenceCatalogue"]
    assert "flows" not in data["referenceCatalogue"]


@pytest.mark.asyncio
async def test_batch_items_accept_scalar_data_state():
    result = await call("add_asset", items=[
        {
            "name": "Session token",
            "type": "Credential",
            "classification": "Restricted",
            "data_states": "In transit",
        },
        {
            "name": "Audit log",
            "type": "Data",
            "classification": "Internal",
            "data_states": ["At rest", "In use"],
        },
    ])

    assert "Successfully added 2 asset(s)" in result
    by_name = {asset.name: asset for asset in asset_flows.assets.values()}
    assert [state.value for state in by_name["Session token"].data_states] == [
        "In transit"
    ]
    assert [state.value for state in by_name["Audit log"].data_states] == [
        "At rest", "In use",
    ]


@pytest.mark.asyncio
async def test_top_level_scalar_data_state_is_rejected_by_tool_schema():
    from mcp.server.fastmcp.exceptions import ToolError

    with pytest.raises(ToolError) as exc:
        await call(
            "add_asset",
            name="Customer record",
            type="Data",
            classification="Internal",
            data_states="At rest",
        )

    assert "data_states" in str(exc.value)
    assert "valid list" in str(exc.value)
