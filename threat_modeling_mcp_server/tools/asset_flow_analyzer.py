"""Asset Flow Analysis functionality for the Cline Threat Modeling MCP Server."""

from typing import Dict, List, Optional, Any
from loguru import logger
from mcp.server.fastmcp import Context
from pydantic import Field
from threat_modeling_mcp_server.models.models import SensitivityTier
from threat_modeling_mcp_server.models.asset_flow_models import Asset, AssetFlow, AssetType
import threat_modeling_mcp_server.tools.architecture_analyzer as architecture_analyzer
from threat_modeling_mcp_server.utils.batch_utils import batch_add, batch_update, batch_delete
from threat_modeling_mcp_server.utils.id_utils import next_id
from threat_modeling_mcp_server.validation.enum_validator import validate_enum_with_enhanced_error


assets: Dict[str, Asset] = {}
flows: Dict[str, AssetFlow] = {}


ASSET_CLEARABLE_FIELDS = {
    "lifecycle_state",
    "description",
    "owner",
    "criticality",
    "metadata",
}
FLOW_CLEARABLE_FIELDS = {
    "transformation_type",
    "description",
    "protocol",
    "risk_level",
}


def _validated_update(model, updates, clear_fields, clearable_fields):
    fields_to_clear = set(clear_fields or [])
    unknown = fields_to_clear - clearable_fields
    if unknown:
        raise ValueError(
            "Field 'clear_fields': fields cannot be cleared: "
            + ", ".join(sorted(unknown))
        )

    conflicts = fields_to_clear & updates.keys()
    if conflicts:
        raise ValueError(
            "Field 'clear_fields': fields cannot be updated and cleared together: "
            + ", ".join(sorted(conflicts))
        )

    candidate = model.model_dump()
    candidate.update(updates)
    candidate.update({field: None for field in fields_to_clear})
    return type(model).model_validate(candidate)


def _validate_flow_endpoints(source_id: str, destination_id: str) -> Optional[str]:
    if source_id not in architecture_analyzer.components:
        return f"Source component with ID {source_id} not found"
    if destination_id not in architecture_analyzer.components:
        return f"Destination component with ID {destination_id} not found"
    return None


async def add_asset_impl(
    ctx: Context,
    name: str,
    type: str,
    classification: str,
    lifecycle_state: Optional[str] = None,
    data_states: Optional[List[str]] = None,
    description: Optional[str] = None,
    owner: Optional[str] = None,
    criticality: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> str:
    """Add a new asset to the system.

    Args:
        ctx: MCP context for logging and error handling
        name: Name of the asset
        type: Asset type
        classification: Sensitivity tier
        lifecycle_state: Active, Archived, Pending deletion, or Quarantined
        data_states: At rest, In transit, and/or In use
        description: Description of the asset
        owner: Owner of the asset
        criticality: Business criticality from 1 to 5
        metadata: Additional metadata for the asset

    Returns:
        A confirmation message with the asset ID
    """
    logger.debug(f'Adding asset: {name}')

    asset_id = next_id(assets, "A")
    asset = Asset(
        id=asset_id,
        name=name,
        type=type,
        classification=classification,
        lifecycle_state=lifecycle_state,
        data_states=data_states,
        description=description,
        owner=owner,
        criticality=criticality,
        metadata=metadata or {},
    )
    assets[asset_id] = asset

    return f"Asset added with ID: {asset_id}"


async def update_asset_impl(
    ctx: Context,
    id: str,
    name: Optional[str] = None,
    type: Optional[str] = None,
    classification: Optional[str] = None,
    lifecycle_state: Optional[str] = None,
    data_states: Optional[List[str]] = None,
    description: Optional[str] = None,
    owner: Optional[str] = None,
    criticality: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None,
    clear_fields: Optional[List[str]] = None,
) -> str:
    """Update an existing asset atomically.

    Args:
        ctx: MCP context for logging and error handling
        id: ID of the asset to update
        name: New name of the asset
        type: New asset type
        classification: New sensitivity tier
        lifecycle_state: New lifecycle state
        data_states: New physical data states
        description: New description
        owner: New owner
        criticality: New business criticality from 1 to 5
        metadata: New metadata
        clear_fields: Optional fields to set to null

    Returns:
        A confirmation message
    """
    logger.debug(f'Updating asset: {id}')

    if id not in assets:
        return f"Asset with ID {id} not found"

    values = {
        "name": name,
        "type": type,
        "classification": classification,
        "lifecycle_state": lifecycle_state,
        "data_states": data_states,
        "description": description,
        "owner": owner,
        "criticality": criticality,
        "metadata": metadata,
    }
    updates = {field: value for field, value in values.items() if value is not None}

    try:
        updated_asset = _validated_update(
            assets[id], updates, clear_fields, ASSET_CLEARABLE_FIELDS
        )
    except ValueError as error:
        return f"Invalid asset update: {error}"

    assets[id] = updated_asset
    return f"Asset {id} updated successfully"


async def list_assets_impl(
    ctx: Context,
    type: Optional[str] = None,
    classification: Optional[str] = None,
) -> str:
    """List all assets in the system.

    Args:
        ctx: MCP context for logging and error handling
        type: Optional type to filter assets
        classification: Optional classification to filter assets

    Returns:
        A markdown-formatted list of assets
    """
    logger.debug('Listing assets')

    # Filter assets by type and classification if provided
    filtered_assets = assets.values()
    if type:
        asset_type = validate_enum_with_enhanced_error(type, AssetType, 'type')
        filtered_assets = [a for a in filtered_assets if a.type == asset_type]
    if classification:
        filtered_assets = [a for a in filtered_assets if a.classification == validate_enum_with_enhanced_error(classification, SensitivityTier, 'classification')]

    # Sort assets by ID
    sorted_assets = sorted(filtered_assets, key=lambda a: a.id)

    # Generate the markdown output
    result = "# Assets\n\n"

    if not sorted_assets:
        result += "No assets found.\n"
        return result

    for asset in sorted_assets:
        result += f"## {asset.id}: {asset.name}\n\n"
        result += f"**Type:** {asset.type.value}\n\n"
        result += f"**Classification:** {asset.classification.value}\n\n"

        if asset.lifecycle_state:
            result += f"**Lifecycle State:** {asset.lifecycle_state.value}\n\n"
        if asset.data_states:
            result += f"**Data States:** {', '.join(d.value for d in asset.data_states)}\n\n"

        if asset.description:
            result += f"**Description:** {asset.description}\n\n"

        if asset.owner:
            result += f"**Owner:** {asset.owner}\n\n"


        if asset.criticality is not None:
            result += f"**Criticality:** {asset.criticality}/5\n\n"

        if asset.metadata:
            result += "**Metadata:**\n\n"
            for key, value in asset.metadata.items():
                result += f"- {key}: {value}\n"
            result += "\n"

        result += "---\n\n"

    return result


async def get_asset_impl(
    ctx: Context,
    id: str,
) -> str:
    """Get details about a specific asset.

    Args:
        ctx: MCP context for logging and error handling
        id: ID of the asset to retrieve

    Returns:
        A markdown-formatted description of the asset
    """
    logger.debug(f'Getting asset: {id}')

    # Check if the asset exists
    if id not in assets:
        return f"Asset with ID {id} not found"

    # Get the asset
    asset = assets[id]

    # Generate the markdown output
    result = f"# Asset {asset.id}: {asset.name}\n\n"
    result += f"**Type:** {asset.type.value}\n\n"
    result += f"**Classification:** {asset.classification.value}\n\n"

    if asset.lifecycle_state:
        result += f"**Lifecycle State:** {asset.lifecycle_state.value}\n\n"
    if asset.data_states:
        result += f"**Data States:** {', '.join(d.value for d in asset.data_states)}\n\n"

    if asset.description:
        result += f"**Description:** {asset.description}\n\n"

    if asset.owner:
        result += f"**Owner:** {asset.owner}\n\n"


    if asset.criticality is not None:
        result += f"**Criticality:** {asset.criticality}/5\n\n"

    if asset.metadata:
        result += "**Metadata:**\n\n"
        for key, value in asset.metadata.items():
            result += f"- {key}: {value}\n"
        result += "\n"

    # List flows involving this asset
    asset_flows = [f for f in flows.values() if f.asset_id == id]
    if asset_flows:
        result += "## Asset Flows\n\n"
        for flow in asset_flows:
            result += f"- **{flow.id}**: {flow.description or 'No description'} (From {flow.source_id} to {flow.destination_id})\n"

    return result


async def delete_asset_impl(
    ctx: Context,
    id: str,
) -> str:
    """Delete an asset from the system.

    Args:
        ctx: MCP context for logging and error handling
        id: ID of the asset to delete

    Returns:
        A confirmation message
    """
    logger.debug(f'Deleting asset: {id}')

    # Check if the asset exists
    if id not in assets:
        return f"Asset with ID {id} not found"

    # Check if the asset is used in any flows
    asset_flows = [f for f in flows.values() if f.asset_id == id]
    if asset_flows:
        flow_ids = [f.id for f in asset_flows]
        return f"Cannot delete asset {id} because it is used in flows: {', '.join(flow_ids)}"

    # Delete the asset
    del assets[id]

    return f"Asset {id} deleted successfully"


async def add_flow_impl(
    ctx: Context,
    asset_id: str,
    source_id: str,
    destination_id: str,
    transformation_type: Optional[str] = None,
    controls: Optional[List[str]] = None,
    description: Optional[str] = None,
    protocol: Optional[str] = None,
    encryption: bool = False,
    authenticated: bool = False,
    authorized: bool = False,
    validated: bool = False,
    risk_level: Optional[int] = None,
) -> str:
    """Add a flow between two architecture components.

    Args:
        ctx: MCP context for logging and error handling
        asset_id: ID of the asset being transferred
        source_id: ID of the source component
        destination_id: ID of the destination component
        transformation_type: Transformation applied to the asset
        controls: Security controls applied to the flow
        description: Description of the flow
        protocol: Protocol used for the flow
        encryption: Whether the flow is encrypted
        authenticated: Whether the flow is authenticated
        authorized: Whether the flow is authorized
        validated: Whether the flow is validated
        risk_level: Risk level from 1 to 5

    Returns:
        A confirmation message with the flow ID
    """
    logger.debug(f'Adding flow for asset: {asset_id}')

    if asset_id not in assets:
        return f"Asset with ID {asset_id} not found"

    endpoint_error = _validate_flow_endpoints(source_id, destination_id)
    if endpoint_error:
        return endpoint_error

    flow_id = next_id(flows, "F")
    flow = AssetFlow(
        id=flow_id,
        asset_id=asset_id,
        source_id=source_id,
        destination_id=destination_id,
        transformation_type=transformation_type,
        controls=controls,
        description=description,
        protocol=protocol,
        encryption=encryption,
        authenticated=authenticated,
        authorized=authorized,
        validated=validated,
        risk_level=risk_level,
    )
    flows[flow_id] = flow

    return f"Flow added with ID: {flow_id}"


async def update_flow_impl(
    ctx: Context,
    id: str,
    asset_id: Optional[str] = None,
    source_id: Optional[str] = None,
    destination_id: Optional[str] = None,
    transformation_type: Optional[str] = None,
    controls: Optional[List[str]] = None,
    description: Optional[str] = None,
    protocol: Optional[str] = None,
    encryption: Optional[bool] = None,
    authenticated: Optional[bool] = None,
    authorized: Optional[bool] = None,
    validated: Optional[bool] = None,
    risk_level: Optional[int] = None,
    clear_fields: Optional[List[str]] = None,
) -> str:
    """Update an existing asset flow atomically.

    Args:
        ctx: MCP context for logging and error handling
        id: ID of the flow to update
        asset_id: New asset ID
        source_id: New source component ID
        destination_id: New destination component ID
        transformation_type: New transformation type
        controls: New security controls
        description: New description
        protocol: New protocol
        encryption: New encryption status
        authenticated: New authentication status
        authorized: New authorization status
        validated: New validation status
        risk_level: New risk level from 1 to 5
        clear_fields: Optional fields to set to null

    Returns:
        A confirmation message
    """
    logger.debug(f'Updating flow: {id}')

    if id not in flows:
        return f"Flow with ID {id} not found"

    flow = flows[id]
    target_asset_id = asset_id if asset_id is not None else flow.asset_id
    if target_asset_id not in assets:
        return f"Asset with ID {target_asset_id} not found"

    target_source_id = source_id if source_id is not None else flow.source_id
    target_destination_id = (
        destination_id if destination_id is not None else flow.destination_id
    )
    endpoint_error = _validate_flow_endpoints(
        target_source_id, target_destination_id
    )
    if endpoint_error:
        return endpoint_error

    values = {
        "asset_id": asset_id,
        "source_id": source_id,
        "destination_id": destination_id,
        "transformation_type": transformation_type,
        "controls": controls,
        "description": description,
        "protocol": protocol,
        "encryption": encryption,
        "authenticated": authenticated,
        "authorized": authorized,
        "validated": validated,
        "risk_level": risk_level,
    }
    updates = {field: value for field, value in values.items() if value is not None}

    try:
        updated_flow = _validated_update(
            flow, updates, clear_fields, FLOW_CLEARABLE_FIELDS
        )
    except ValueError as error:
        return f"Invalid flow update: {error}"

    flows[id] = updated_flow
    return f"Flow {id} updated successfully"


async def list_flows_impl(
    ctx: Context,
    asset_id: Optional[str] = None,
    component_id: Optional[str] = None,
) -> str:
    """List all asset flows in the system.

    Args:
        ctx: MCP context for logging and error handling
        asset_id: Optional asset ID to filter flows
        component_id: Optional component ID to filter flows

    Returns:
        A markdown-formatted list of flows
    """
    logger.debug('Listing flows')

    # Filter flows by asset ID and component ID if provided
    filtered_flows = flows.values()
    if asset_id:
        filtered_flows = [f for f in filtered_flows if f.asset_id == asset_id]
    if component_id:
        filtered_flows = [f for f in filtered_flows if f.source_id == component_id or f.destination_id == component_id]

    # Sort flows by ID
    sorted_flows = sorted(filtered_flows, key=lambda f: f.id)

    # Generate the markdown output
    result = "# Asset Flows\n\n"

    if not sorted_flows:
        result += "No flows found.\n"
        return result

    for flow in sorted_flows:
        # Get the asset name
        asset_name = assets[flow.asset_id].name if flow.asset_id in assets else "Unknown Asset"

        result += f"## {flow.id}: {asset_name}\n\n"
        result += f"**Source:** {flow.source_id}\n\n"
        result += f"**Destination:** {flow.destination_id}\n\n"

        if flow.transformation_type:
            result += f"**Transformation:** {flow.transformation_type.value}\n\n"

        if flow.controls:
            result += "**Controls:**\n\n"
            for control in flow.controls:
                result += f"- {control.value}\n"
            result += "\n"

        if flow.description:
            result += f"**Description:** {flow.description}\n\n"

        if flow.protocol:
            result += f"**Protocol:** {flow.protocol}\n\n"

        result += f"**Encryption:** {'Yes' if flow.encryption else 'No'}\n\n"
        result += f"**Authentication:** {'Yes' if flow.authenticated else 'No'}\n\n"
        result += f"**Authorization:** {'Yes' if flow.authorized else 'No'}\n\n"
        result += f"**Validation:** {'Yes' if flow.validated else 'No'}\n\n"

        if flow.risk_level is not None:
            result += f"**Risk Level:** {flow.risk_level}/5\n\n"

        result += "---\n\n"

    return result


async def get_flow_impl(
    ctx: Context,
    id: str,
) -> str:
    """Get details about a specific asset flow.

    Args:
        ctx: MCP context for logging and error handling
        id: ID of the flow to retrieve

    Returns:
        A markdown-formatted description of the flow
    """
    logger.debug(f'Getting flow: {id}')

    # Check if the flow exists
    if id not in flows:
        return f"Flow with ID {id} not found"

    # Get the flow
    flow = flows[id]

    # Get the asset name
    asset_name = assets[flow.asset_id].name if flow.asset_id in assets else "Unknown Asset"

    # Generate the markdown output
    result = f"# Flow {flow.id}: {asset_name}\n\n"
    result += f"**Asset ID:** {flow.asset_id}\n\n"
    result += f"**Source:** {flow.source_id}\n\n"
    result += f"**Destination:** {flow.destination_id}\n\n"

    if flow.transformation_type:
        result += f"**Transformation:** {flow.transformation_type.value}\n\n"

    if flow.controls:
        result += "**Controls:**\n\n"
        for control in flow.controls:
            result += f"- {control.value}\n"
        result += "\n"

    if flow.description:
        result += f"**Description:** {flow.description}\n\n"

    if flow.protocol:
        result += f"**Protocol:** {flow.protocol}\n\n"

    result += f"**Encryption:** {'Yes' if flow.encryption else 'No'}\n\n"
    result += f"**Authentication:** {'Yes' if flow.authenticated else 'No'}\n\n"
    result += f"**Authorization:** {'Yes' if flow.authorized else 'No'}\n\n"
    result += f"**Validation:** {'Yes' if flow.validated else 'No'}\n\n"

    if flow.risk_level is not None:
        result += f"**Risk Level:** {flow.risk_level}/5\n\n"

    return result


async def delete_flow_impl(
    ctx: Context,
    id: str,
) -> str:
    """Delete an asset flow from the system.

    Args:
        ctx: MCP context for logging and error handling
        id: ID of the flow to delete

    Returns:
        A confirmation message
    """
    logger.debug(f'Deleting flow: {id}')

    # Check if the flow exists
    if id not in flows:
        return f"Flow with ID {id} not found"

    # Delete the flow
    del flows[id]

    return f"Flow {id} deleted successfully"


async def clear_asset_flows_impl(
    ctx: Context,
) -> str:
    """Clear all assets and flows from the system.

    Args:
        ctx: MCP context for logging and error handling

    Returns:
        A confirmation message
    """
    logger.debug('Clearing asset flows')

    # Clear the dictionaries
    assets.clear()
    flows.clear()

    return "All assets and flows have been cleared."


def register_tools(mcp):
    """Register asset flow analysis tools with the MCP server.

    Args:
        mcp: The MCP server instance
    """
    @mcp.tool()
    async def add_asset(
        ctx: Context,
        name: str = None,
        type: str = None,
        classification: str = None,
        lifecycle_state: Optional[str] = None,
        data_states: Optional[List[str]] = None,
        description: Optional[str] = None,
        owner: Optional[str] = None,
        criticality: Optional[int] = Field(default=None, ge=1, le=5),
        metadata: Optional[Dict[str, Any]] = None,
        items: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """Add a new asset to the system. Supports batch operations via the 'items' parameter.

        This tool adds one or more assets to the system.
        For single item: provide name, type, classification, and optional fields directly.
        For batch: provide a list of asset dicts in the 'items' parameter.

        Args:
            ctx: MCP context for logging and error handling
            name: Name of the asset (required for single item mode)
            type: Type of the asset (e.g., 'Data', 'Credential', 'Process') (required for single item mode)
            classification: Classification of the asset (e.g., 'Public', 'Confidential') (required for single item mode)
            lifecycle_state: Lifecycle stage of the asset (Active, Archived, Pending deletion, Quarantined)
            data_states: Physical states the data exists in; multiple allowed (At rest, In transit, In use)
            description: Description of the asset
            owner: Owner of the asset
            criticality: Criticality level of the asset (1-5)
            metadata: Additional metadata for the asset
            items: Optional list of asset dicts for batch operation

        Returns:
            A confirmation message with the asset ID(s)
        """
        return await batch_add(
            ctx, items,
            {"name": name, "type": type, "classification": classification,
             "lifecycle_state": lifecycle_state, "data_states": data_states,
             "description": description,
             "owner": owner, "criticality": criticality,
             "metadata": metadata},
            add_asset_impl, "asset"
        )

    @mcp.tool()
    async def update_asset(
        ctx: Context,
        id: str = None,
        name: Optional[str] = None,
        type: Optional[str] = None,
        classification: Optional[str] = None,
        lifecycle_state: Optional[str] = None,
        data_states: Optional[List[str]] = None,
        description: Optional[str] = None,
        owner: Optional[str] = None,
        criticality: Optional[int] = Field(default=None, ge=1, le=5),
        metadata: Optional[Dict[str, Any]] = None,
        clear_fields: Optional[List[str]] = None,
        items: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """Update an existing asset. Supports batch operations via the 'items' parameter.

        This tool updates one or more existing assets in the system.
        For single item: provide id and fields to update directly.
        For batch: provide a list of asset dicts in the 'items' parameter (each must include 'id').

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the asset to update (required for single item mode)
            name: New name of the asset
            type: New type of the asset
            classification: New classification of the asset
            lifecycle_state: New lifecycle stage (Active, Archived, Pending deletion, Quarantined)
            data_states: New physical data states; multiple allowed (At rest, In transit, In use)
            description: New description of the asset
            owner: New owner of the asset
            criticality: New criticality level of the asset
            metadata: New metadata for the asset
            clear_fields: Optional fields to set to null
            items: Optional list of asset dicts for batch update

        Returns:
            A confirmation message
        """
        return await batch_update(
            ctx, items,
            {"id": id, "name": name, "type": type, "classification": classification,
             "lifecycle_state": lifecycle_state, "data_states": data_states,
             "description": description,
             "owner": owner, "criticality": criticality,
             "metadata": metadata, "clear_fields": clear_fields},
            update_asset_impl, "asset"
        )

    @mcp.tool()
    async def list_assets(
        ctx: Context,
        type: Optional[str] = None,
        classification: Optional[str] = None,
    ) -> str:
        """List all assets in the system.

        This tool lists all assets in the system, optionally filtered by type or classification.

        Args:
            ctx: MCP context for logging and error handling
            type: Optional type to filter assets
            classification: Optional classification to filter assets

        Returns:
            A markdown-formatted list of assets
        """
        return await list_assets_impl(ctx, type, classification)

    @mcp.tool()
    async def get_asset(
        ctx: Context,
        id: str,
    ) -> str:
        """Get details about a specific asset.

        This tool retrieves details about a specific asset in the system.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the asset to retrieve

        Returns:
            A markdown-formatted description of the asset
        """
        return await get_asset_impl(ctx, id)

    @mcp.tool()
    async def delete_asset(
        ctx: Context,
        id: Optional[str] = None,
        ids: Optional[List[str]] = None,
    ) -> str:
        """Delete an asset from the system. Supports batch operations via the 'ids' parameter.

        This tool deletes one or more assets from the system. Assets cannot be deleted if used in any flows.
        For single item: provide the id directly.
        For batch: provide a list of IDs in the 'ids' parameter.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the asset to delete (required for single item mode)
            ids: Optional list of asset IDs for batch deletion

        Returns:
            A confirmation message
        """
        return await batch_delete(ctx, ids, id, delete_asset_impl, "asset")

    @mcp.tool()
    async def add_flow(
        ctx: Context,
        asset_id: str = None,
        source_id: str = None,
        destination_id: str = None,
        transformation_type: Optional[str] = None,
        controls: Optional[List[str]] = None,
        description: Optional[str] = None,
        protocol: Optional[str] = None,
        encryption: bool = False,
        authenticated: bool = False,
        authorized: bool = False,
        validated: bool = False,
        risk_level: Optional[int] = Field(default=None, ge=1, le=5),
        items: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """Add a new asset flow to the system. Supports batch operations via the 'items' parameter.

        This tool adds one or more asset flows to the system.
        For single item: provide asset_id, source_id, destination_id, and optional fields directly.
        For batch: provide a list of flow dicts in the 'items' parameter.

        Args:
            ctx: MCP context for logging and error handling
            asset_id: ID of the asset being transferred (required for single item mode)
            source_id: ID of the source component (required for single item mode)
            destination_id: ID of the destination component (required for single item mode)
            transformation_type: Type of transformation applied to the asset
            controls: List of security controls applied to the flow
            description: Description of the flow
            protocol: Protocol used for the flow
            encryption: Whether the flow is encrypted
            authenticated: Whether the flow is authenticated
            authorized: Whether the flow is authorized
            validated: Whether the flow is validated
            risk_level: Risk level of the flow (1-5)
            items: Optional list of flow dicts for batch operation

        Returns:
            A confirmation message with the flow ID(s)
        """
        return await batch_add(
            ctx, items,
            {"asset_id": asset_id, "source_id": source_id, "destination_id": destination_id,
             "transformation_type": transformation_type, "controls": controls,
             "description": description, "protocol": protocol, "encryption": encryption,
             "authenticated": authenticated, "authorized": authorized,
             "validated": validated, "risk_level": risk_level},
            add_flow_impl, "flow"
        )

    @mcp.tool()
    async def update_flow(
        ctx: Context,
        id: str = None,
        asset_id: Optional[str] = None,
        source_id: Optional[str] = None,
        destination_id: Optional[str] = None,
        transformation_type: Optional[str] = None,
        controls: Optional[List[str]] = None,
        description: Optional[str] = None,
        protocol: Optional[str] = None,
        encryption: Optional[bool] = None,
        authenticated: Optional[bool] = None,
        authorized: Optional[bool] = None,
        validated: Optional[bool] = None,
        risk_level: Optional[int] = Field(default=None, ge=1, le=5),
        clear_fields: Optional[List[str]] = None,
        items: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """Update an existing asset flow. Supports batch operations via the 'items' parameter.

        This tool updates one or more existing asset flows in the system.
        For single item: provide id and fields to update directly.
        For batch: provide a list of flow dicts in the 'items' parameter (each must include 'id').

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the flow to update (required for single item mode)
            asset_id: New ID of the asset being transferred
            source_id: New ID of the source component
            destination_id: New ID of the destination component
            transformation_type: New type of transformation applied to the asset
            controls: New list of security controls applied to the flow
            description: New description of the flow
            protocol: New protocol used for the flow
            encryption: New encryption status
            authenticated: New authentication status
            authorized: New authorization status
            validated: New validation status
            risk_level: New risk level of the flow (1-5)
            clear_fields: Optional fields to set to null
            items: Optional list of flow dicts for batch update

        Returns:
            A confirmation message
        """
        return await batch_update(
            ctx, items,
            {"id": id, "asset_id": asset_id, "source_id": source_id,
             "destination_id": destination_id, "transformation_type": transformation_type,
             "controls": controls, "description": description, "protocol": protocol,
             "encryption": encryption, "authenticated": authenticated,
             "authorized": authorized, "validated": validated, "risk_level": risk_level,
             "clear_fields": clear_fields},
            update_flow_impl, "flow"
        )

    @mcp.tool()
    async def list_flows(
        ctx: Context,
        asset_id: Optional[str] = None,
        component_id: Optional[str] = None,
    ) -> str:
        """List all asset flows in the system.

        This tool lists all asset flows in the system, optionally filtered by asset ID or component ID.

        Args:
            ctx: MCP context for logging and error handling
            asset_id: Optional asset ID to filter flows
            component_id: Optional component ID to filter flows

        Returns:
            A markdown-formatted list of flows
        """
        return await list_flows_impl(ctx, asset_id, component_id)

    @mcp.tool()
    async def get_flow(
        ctx: Context,
        id: str,
    ) -> str:
        """Get details about a specific asset flow.

        This tool retrieves details about a specific asset flow in the system.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the flow to retrieve

        Returns:
            A markdown-formatted description of the flow
        """
        return await get_flow_impl(ctx, id)

    @mcp.tool()
    async def delete_flow(
        ctx: Context,
        id: Optional[str] = None,
        ids: Optional[List[str]] = None,
    ) -> str:
        """Delete an asset flow from the system. Supports batch operations via the 'ids' parameter.

        This tool deletes one or more asset flows from the system.
        For single item: provide the id directly.
        For batch: provide a list of IDs in the 'ids' parameter.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the flow to delete (required for single item mode)
            ids: Optional list of flow IDs for batch deletion

        Returns:
            A confirmation message
        """
        return await batch_delete(ctx, ids, id, delete_flow_impl, "flow")

    @mcp.tool()
    async def clear_asset_flows(
        ctx: Context,
    ) -> str:
        """Clear all assets and flows from the system.

        This tool clears all assets and flows from the system.

        Args:
            ctx: MCP context for logging and error handling

        Returns:
            A confirmation message
        """
        return await clear_asset_flows_impl(ctx)
