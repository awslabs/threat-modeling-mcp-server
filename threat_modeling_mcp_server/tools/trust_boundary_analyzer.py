"""Trust Boundary Analysis functionality for the Threat Modeling MCP Server."""

from typing import Dict, List, Optional
from loguru import logger
from mcp.server.fastmcp import Context

from threat_modeling_mcp_server.models.trust_boundary_models import (
    TrustZone, CrossingPoint, TrustBoundary,
    BoundaryType, AuthenticationMethod, AuthorizationMethod, TrustLevel
)
from threat_modeling_mcp_server.tools import architecture_analyzer as architecture
from threat_modeling_mcp_server.utils.id_utils import next_id


# Global state
trust_zones: Dict[str, TrustZone] = {}
crossing_points: Dict[str, CrossingPoint] = {}
trust_boundaries: Dict[str, TrustBoundary] = {}


# Trust Zone Management Functions

async def add_trust_zone_impl(
    ctx: Context,
    name: str,
    trust_level: str,
    description: Optional[str] = None,
) -> str:
    """Add a new trust zone.

    Args:
        ctx: MCP context for logging and error handling
        name: Name of the trust zone
        trust_level: Trust level of the zone
        description: Description of the trust zone

    Returns:
        A confirmation message with the trust zone ID
    """
    logger.debug(f'Adding trust zone: {name}')

    # Generate a unique ID
    trust_zone_id = next_id(trust_zones, "TZ")

    # Create the trust zone
    trust_zone = TrustZone(
        id=trust_zone_id,
        name=name,
        trust_level=TrustLevel(trust_level),
        contained_nodes=[],
        description=description,
    )

    # Store the trust zone
    trust_zones[trust_zone_id] = trust_zone

    return f"Trust zone added with ID: {trust_zone_id}"


async def update_trust_zone_impl(
    ctx: Context,
    id: str,
    name: Optional[str] = None,
    trust_level: Optional[str] = None,
    description: Optional[str] = None,
) -> str:
    """Update an existing trust zone.

    Args:
        ctx: MCP context for logging and error handling
        id: ID of the trust zone to update
        name: New name of the trust zone
        trust_level: New trust level of the zone
        description: New description of the trust zone

    Returns:
        A confirmation message
    """
    logger.debug(f'Updating trust zone: {id}')

    if id not in trust_zones:
        return f"Trust zone with ID {id} not found."

    trust_zone = trust_zones[id]

    # Update only the provided fields
    if name is not None:
        trust_zone.name = name

    if trust_level is not None:
        trust_zone.trust_level = TrustLevel(trust_level)

    if description is not None:
        trust_zone.description = description

    # Store the updated trust zone
    trust_zones[id] = trust_zone

    return f"Trust zone {id} updated successfully."


async def list_trust_zones_impl(
    ctx: Context,
    trust_level: Optional[str] = None,
) -> str:
    """List all trust zones.

    Args:
        ctx: MCP context for logging and error handling
        trust_level: Optional trust level to filter zones

    Returns:
        A markdown-formatted list of trust zones
    """
    logger.debug('Listing trust zones')

    if not trust_zones:
        return "No trust zones have been added yet."

    filtered_zones = trust_zones.values()

    if trust_level:
        filtered_zones = [z for z in filtered_zones if z.trust_level == TrustLevel(trust_level)]

    if not filtered_zones:
        return "No trust zones found with the specified criteria."

    # Sort by trust level
    sorted_zones = sorted(filtered_zones, key=lambda z: z.trust_level.value)

    result = "# Trust Zones\n\n"

    for zone in sorted_zones:
        result += f"## {zone.id}: {zone.name}\n\n"
        result += f"**Trust Level:** {zone.trust_level.value}\n\n"

        if zone.description:
            result += f"**Description:** {zone.description}\n\n"

        if zone.contained_nodes:
            result += "**Contained Architecture Nodes:**\n\n"
            for node_id in zone.contained_nodes:
                result += (
                    f"- {architecture.get_architecture_node_name(node_id)} "
                    f"({node_id})\n"
                )
            result += "\n"
        else:
            result += "**Contained Architecture Nodes:** None\n\n"

        result += "---\n\n"

    return result


async def get_trust_zone_impl(
    ctx: Context,
    id: str,
) -> str:
    """Get details about a specific trust zone.

    Args:
        ctx: MCP context for logging and error handling
        id: ID of the trust zone to retrieve

    Returns:
        A markdown-formatted description of the trust zone
    """
    logger.debug(f'Getting trust zone: {id}')

    if id not in trust_zones:
        return f"Trust zone with ID {id} not found."

    zone = trust_zones[id]

    result = f"# {zone.name} ({zone.id})\n\n"
    result += f"**Trust Level:** {zone.trust_level.value}\n\n"

    if zone.description:
        result += f"**Description:** {zone.description}\n\n"

    if zone.contained_nodes:
        result += "**Contained Architecture Nodes:**\n\n"
        for node_id in zone.contained_nodes:
            result += (
                f"- {architecture.get_architecture_node_name(node_id)} "
                f"({node_id})\n"
            )
        result += "\n"
    else:
        result += "**Contained Architecture Nodes:** None\n\n"

    # Find crossing points that involve this zone
    related_crossing_points = [
        cp for cp in crossing_points.values() 
        if cp.source_zone_id == id or cp.destination_zone_id == id
    ]

    if related_crossing_points:
        result += "**Related Crossing Points:**\n\n"
        for cp in related_crossing_points:
            direction = "→" if cp.source_zone_id == id else "←"
            other_zone_id = cp.destination_zone_id if cp.source_zone_id == id else cp.source_zone_id
            other_zone_name = trust_zones[other_zone_id].name if other_zone_id in trust_zones else "Unknown"
            result += f"- {cp.id}: {direction} {other_zone_name}\n"
        result += "\n"

    return result


async def delete_trust_zone_impl(
    ctx: Context,
    id: str,
) -> str:
    """Delete a trust zone.

    Args:
        ctx: MCP context for logging and error handling
        id: ID of the trust zone to delete

    Returns:
        A confirmation message
    """
    logger.debug(f'Deleting trust zone: {id}')

    if id not in trust_zones:
        return f"Trust zone with ID {id} not found."

    # Check if there are any crossing points that reference this zone
    related_crossing_points = [
        cp for cp in crossing_points.values() 
        if cp.source_zone_id == id or cp.destination_zone_id == id
    ]

    if related_crossing_points:
        cp_ids = [cp.id for cp in related_crossing_points]
        return f"Cannot delete trust zone {id} because it is referenced by crossing points: {', '.join(cp_ids)}"

    # Delete the trust zone
    del trust_zones[id]

    return f"Trust zone {id} deleted successfully."


async def add_node_to_zone_impl(
    ctx: Context,
    zone_id: str,
    node_id: str,
) -> str:
    """Add an architecture node to a trust zone.

    Args:
        ctx: MCP context for logging and error handling
        zone_id: ID of the trust zone
        node_id: ID of the component or data store to add

    Returns:
        A confirmation message
    """
    logger.debug(f'Adding architecture node {node_id} to trust zone {zone_id}')

    if zone_id not in trust_zones:
        return f"Trust zone with ID {zone_id} not found."

    if architecture.get_architecture_node(node_id) is None:
        return f"Architecture node with ID {node_id} not found."

    for z_id, zone in trust_zones.items():
        if node_id in zone.contained_nodes and z_id != zone_id:
            return (
                f"Architecture node {node_id} is already in trust zone {z_id}. "
                "Remove it first."
            )

    if node_id not in trust_zones[zone_id].contained_nodes:
        trust_zones[zone_id].contained_nodes.append(node_id)

    return f"Architecture node {node_id} added to trust zone {zone_id}."


async def remove_node_from_zone_impl(
    ctx: Context,
    zone_id: str,
    node_id: str,
) -> str:
    """Remove an architecture node from a trust zone.

    Args:
        ctx: MCP context for logging and error handling
        zone_id: ID of the trust zone
        node_id: ID of the component or data store to remove

    Returns:
        A confirmation message
    """
    logger.debug(f'Removing architecture node {node_id} from trust zone {zone_id}')

    if zone_id not in trust_zones:
        return f"Trust zone with ID {zone_id} not found."

    if node_id not in trust_zones[zone_id].contained_nodes:
        return f"Architecture node {node_id} is not in trust zone {zone_id}."

    trust_zones[zone_id].contained_nodes.remove(node_id)

    return f"Architecture node {node_id} removed from trust zone {zone_id}."


# Crossing Point Management Functions

async def add_crossing_point_impl(
    ctx: Context,
    source_zone_id: str,
    destination_zone_id: str,
    authentication_method: Optional[str] = None,
    authorization_method: Optional[str] = None,
    description: Optional[str] = None,
) -> str:
    """Add a new crossing point.

    Args:
        ctx: MCP context for logging and error handling
        source_zone_id: ID of the source trust zone
        destination_zone_id: ID of the destination trust zone
        authentication_method: Authentication method used at the crossing point
        authorization_method: Authorization method used at the crossing point
        description: Description of the crossing point

    Returns:
        A confirmation message with the crossing point ID
    """
    logger.debug(f'Adding crossing point from {source_zone_id} to {destination_zone_id}')

    # Check if the trust zones exist
    if source_zone_id not in trust_zones:
        return f"Source trust zone with ID {source_zone_id} not found."

    if destination_zone_id not in trust_zones:
        return f"Destination trust zone with ID {destination_zone_id} not found."

    # Generate a unique ID
    crossing_point_id = next_id(crossing_points, "CP")

    # Create the crossing point
    crossing_point = CrossingPoint(
        id=crossing_point_id,
        source_zone_id=source_zone_id,
        destination_zone_id=destination_zone_id,
        connection_ids=[],
        authentication_method=AuthenticationMethod(authentication_method) if authentication_method else None,
        authorization_method=AuthorizationMethod(authorization_method) if authorization_method else None,
        description=description,
    )

    # Store the crossing point
    crossing_points[crossing_point_id] = crossing_point

    return f"Crossing point added with ID: {crossing_point_id}"


async def update_crossing_point_impl(
    ctx: Context,
    id: str,
    source_zone_id: Optional[str] = None,
    destination_zone_id: Optional[str] = None,
    authentication_method: Optional[str] = None,
    authorization_method: Optional[str] = None,
    description: Optional[str] = None,
) -> str:
    """Update an existing crossing point.

    Args:
        ctx: MCP context for logging and error handling
        id: ID of the crossing point to update
        source_zone_id: New ID of the source trust zone
        destination_zone_id: New ID of the destination trust zone
        authentication_method: New authentication method
        authorization_method: New authorization method
        description: New description of the crossing point

    Returns:
        A confirmation message
    """
    logger.debug(f'Updating crossing point: {id}')

    if id not in crossing_points:
        return f"Crossing point with ID {id} not found."

    crossing_point = crossing_points[id]

    # Update only the provided fields
    if source_zone_id is not None:
        if source_zone_id not in trust_zones:
            return f"Source trust zone with ID {source_zone_id} not found."
        crossing_point.source_zone_id = source_zone_id

    if destination_zone_id is not None:
        if destination_zone_id not in trust_zones:
            return f"Destination trust zone with ID {destination_zone_id} not found."
        crossing_point.destination_zone_id = destination_zone_id

    if authentication_method is not None:
        crossing_point.authentication_method = AuthenticationMethod(authentication_method)

    if authorization_method is not None:
        crossing_point.authorization_method = AuthorizationMethod(authorization_method)

    if description is not None:
        crossing_point.description = description

    # Store the updated crossing point
    crossing_points[id] = crossing_point

    return f"Crossing point {id} updated successfully."


async def list_crossing_points_impl(
    ctx: Context,
    zone_id: Optional[str] = None,
) -> str:
    """List all crossing points.

    Args:
        ctx: MCP context for logging and error handling
        zone_id: Optional trust zone ID to filter crossing points

    Returns:
        A markdown-formatted list of crossing points
    """
    logger.debug('Listing crossing points')

    if not crossing_points:
        return "No crossing points have been added yet."

    filtered_points = crossing_points.values()

    if zone_id:
        filtered_points = [
            cp for cp in filtered_points 
            if cp.source_zone_id == zone_id or cp.destination_zone_id == zone_id
        ]

    if not filtered_points:
        return "No crossing points found with the specified criteria."

    result = "# Crossing Points\n\n"

    for cp in filtered_points:
        source_zone = trust_zones.get(cp.source_zone_id, None)
        dest_zone = trust_zones.get(cp.destination_zone_id, None)

        source_name = source_zone.name if source_zone else "Unknown"
        dest_name = dest_zone.name if dest_zone else "Unknown"

        result += f"## {cp.id}: {source_name} → {dest_name}\n\n"

        if cp.authentication_method:
            result += f"**Authentication Method:** {cp.authentication_method.value}\n\n"
        else:
            result += "**Authentication Method:** None\n\n"

        if cp.authorization_method:
            result += f"**Authorization Method:** {cp.authorization_method.value}\n\n"
        else:
            result += "**Authorization Method:** None\n\n"

        if cp.description:
            result += f"**Description:** {cp.description}\n\n"

        if cp.connection_ids:
            result += "**Connections:**\n\n"
            for conn_id in cp.connection_ids:
                result += f"- {conn_id}\n"
            result += "\n"
        else:
            result += "**Connections:** None\n\n"

        result += "---\n\n"

    return result


async def get_crossing_point_impl(
    ctx: Context,
    id: str,
) -> str:
    """Get details about a specific crossing point.

    Args:
        ctx: MCP context for logging and error handling
        id: ID of the crossing point to retrieve

    Returns:
        A markdown-formatted description of the crossing point
    """
    logger.debug(f'Getting crossing point: {id}')

    if id not in crossing_points:
        return f"Crossing point with ID {id} not found."

    cp = crossing_points[id]

    source_zone = trust_zones.get(cp.source_zone_id, None)
    dest_zone = trust_zones.get(cp.destination_zone_id, None)

    source_name = source_zone.name if source_zone else "Unknown"
    dest_name = dest_zone.name if dest_zone else "Unknown"

    result = f"# {source_name} → {dest_name} ({cp.id})\n\n"

    result += f"**Source Zone:** {source_name} ({cp.source_zone_id})\n\n"
    result += f"**Destination Zone:** {dest_name} ({cp.destination_zone_id})\n\n"

    if cp.authentication_method:
        result += f"**Authentication Method:** {cp.authentication_method.value}\n\n"
    else:
        result += "**Authentication Method:** None\n\n"

    if cp.authorization_method:
        result += f"**Authorization Method:** {cp.authorization_method.value}\n\n"
    else:
        result += "**Authorization Method:** None\n\n"

    if cp.description:
        result += f"**Description:** {cp.description}\n\n"

    if cp.connection_ids:
        result += "**Connections:**\n\n"
        for conn_id in cp.connection_ids:
            result += f"- {conn_id}\n"
        result += "\n"
    else:
        result += "**Connections:** None\n\n"

    # Find trust boundaries that include this crossing point
    related_boundaries = [
        tb for tb in trust_boundaries.values() 
        if id in tb.crossing_points
    ]

    if related_boundaries:
        result += "**Related Trust Boundaries:**\n\n"
        for tb in related_boundaries:
            result += f"- {tb.id}: {tb.name}\n"
        result += "\n"

    return result


async def delete_crossing_point_impl(
    ctx: Context,
    id: str,
) -> str:
    """Delete a crossing point.

    Args:
        ctx: MCP context for logging and error handling
        id: ID of the crossing point to delete

    Returns:
        A confirmation message
    """
    logger.debug(f'Deleting crossing point: {id}')

    if id not in crossing_points:
        return f"Crossing point with ID {id} not found."

    # Check if there are any trust boundaries that reference this crossing point
    related_boundaries = [
        tb for tb in trust_boundaries.values() 
        if id in tb.crossing_points
    ]

    if related_boundaries:
        tb_ids = [tb.id for tb in related_boundaries]
        return f"Cannot delete crossing point {id} because it is referenced by trust boundaries: {', '.join(tb_ids)}"

    # Delete the crossing point
    del crossing_points[id]

    return f"Crossing point {id} deleted successfully."


async def add_connection_to_crossing_point_impl(
    ctx: Context,
    crossing_point_id: str,
    connection_id: str,
) -> str:
    """Add a connection to a crossing point.

    Args:
        ctx: MCP context for logging and error handling
        crossing_point_id: ID of the crossing point
        connection_id: ID of the connection to add

    Returns:
        A confirmation message
    """
    logger.debug(f'Adding connection {connection_id} to crossing point {crossing_point_id}')

    if crossing_point_id not in crossing_points:
        return f"Crossing point with ID {crossing_point_id} not found."

    if connection_id not in architecture.connections:
        return f"Connection with ID {connection_id} not found."

    if connection_id not in crossing_points[crossing_point_id].connection_ids:
        crossing_points[crossing_point_id].connection_ids.append(connection_id)

    return f"Connection {connection_id} added to crossing point {crossing_point_id}."


async def remove_connection_from_crossing_point_impl(
    ctx: Context,
    crossing_point_id: str,
    connection_id: str,
) -> str:
    """Remove a connection from a crossing point.

    Args:
        ctx: MCP context for logging and error handling
        crossing_point_id: ID of the crossing point
        connection_id: ID of the connection to remove

    Returns:
        A confirmation message
    """
    logger.debug(f'Removing connection {connection_id} from crossing point {crossing_point_id}')

    if crossing_point_id not in crossing_points:
        return f"Crossing point with ID {crossing_point_id} not found."

    if connection_id not in crossing_points[crossing_point_id].connection_ids:
        return f"Connection {connection_id} is not in crossing point {crossing_point_id}."

    # Remove the connection from the crossing point
    crossing_points[crossing_point_id].connection_ids.remove(connection_id)

    return f"Connection {connection_id} removed from crossing point {crossing_point_id}."


# Trust Boundary Management Functions

async def add_trust_boundary_impl(
    ctx: Context,
    name: str,
    type: str,
    crossing_point_ids: List[str] = [],
    controls: List[str] = [],
    description: Optional[str] = None,
) -> str:
    """Add a new trust boundary.

    Args:
        ctx: MCP context for logging and error handling
        name: Name of the trust boundary
        type: Type of the trust boundary
        crossing_point_ids: IDs of crossing points that cross this boundary
        controls: Security controls implemented at this boundary
        description: Description of the trust boundary

    Returns:
        A confirmation message with the trust boundary ID
    """
    logger.debug(f'Adding trust boundary: {name}')

    # Check if all crossing points exist
    for cp_id in crossing_point_ids:
        if cp_id not in crossing_points:
            return f"Crossing point with ID {cp_id} not found."

    # Generate a unique ID
    trust_boundary_id = next_id(trust_boundaries, "TB")

    # Create the trust boundary
    trust_boundary = TrustBoundary(
        id=trust_boundary_id,
        name=name,
        type=BoundaryType(type),
        crossing_points=crossing_point_ids,
        controls=controls,
        description=description,
    )

    # Store the trust boundary
    trust_boundaries[trust_boundary_id] = trust_boundary

    return f"Trust boundary added with ID: {trust_boundary_id}"


async def update_trust_boundary_impl(
    ctx: Context,
    id: str,
    name: Optional[str] = None,
    type: Optional[str] = None,
    crossing_point_ids: Optional[List[str]] = None,
    controls: Optional[List[str]] = None,
    description: Optional[str] = None,
) -> str:
    """Update an existing trust boundary.

    Args:
        ctx: MCP context for logging and error handling
        id: ID of the trust boundary to update
        name: New name of the trust boundary
        type: New type of the trust boundary
        crossing_point_ids: New IDs of crossing points
        controls: New security controls
        description: New description of the trust boundary

    Returns:
        A confirmation message
    """
    logger.debug(f'Updating trust boundary: {id}')

    if id not in trust_boundaries:
        return f"Trust boundary with ID {id} not found."

    trust_boundary = trust_boundaries[id]

    # Update only the provided fields
    if name is not None:
        trust_boundary.name = name

    if type is not None:
        trust_boundary.type = BoundaryType(type)

    if crossing_point_ids is not None:
        # Check if all crossing points exist
        for cp_id in crossing_point_ids:
            if cp_id not in crossing_points:
                return f"Crossing point with ID {cp_id} not found."
        trust_boundary.crossing_points = crossing_point_ids

    if controls is not None:
        trust_boundary.controls = controls

    if description is not None:
        trust_boundary.description = description

    # Store the updated trust boundary
    trust_boundaries[id] = trust_boundary

    return f"Trust boundary {id} updated successfully."


async def list_trust_boundaries_impl(
    ctx: Context,
    type: Optional[str] = None,
) -> str:
    """List all trust boundaries.

    Args:
        ctx: MCP context for logging and error handling
        type: Optional type to filter trust boundaries

    Returns:
        A markdown-formatted list of trust boundaries
    """
    logger.debug('Listing trust boundaries')

    if not trust_boundaries:
        return "No trust boundaries have been added yet."

    filtered_boundaries = trust_boundaries.values()

    if type:
        filtered_boundaries = [b for b in filtered_boundaries if b.type == BoundaryType(type)]

    if not filtered_boundaries:
        return "No trust boundaries found with the specified criteria."

    result = "# Trust Boundaries\n\n"

    for boundary in filtered_boundaries:
        result += f"## {boundary.id}: {boundary.name}\n\n"
        result += f"**Type:** {boundary.type.value}\n\n"

        if boundary.description:
            result += f"**Description:** {boundary.description}\n\n"

        if boundary.crossing_points:
            result += "**Crossing Points:**\n\n"
            for cp_id in boundary.crossing_points:
                cp = crossing_points.get(cp_id, None)
                if cp:
                    source_zone = trust_zones.get(cp.source_zone_id, None)
                    dest_zone = trust_zones.get(cp.destination_zone_id, None)

                    source_name = source_zone.name if source_zone else "Unknown"
                    dest_name = dest_zone.name if dest_zone else "Unknown"

                    result += f"- {cp_id}: {source_name} → {dest_name}\n"
                else:
                    result += f"- {cp_id}: Unknown\n"
            result += "\n"
        else:
            result += "**Crossing Points:** None\n\n"

        if boundary.controls:
            result += "**Security Controls:**\n\n"
            for control in boundary.controls:
                result += f"- {control}\n"
            result += "\n"
        else:
            result += "**Security Controls:** None\n\n"

        result += "---\n\n"

    return result


async def get_trust_boundary_impl(
    ctx: Context,
    id: str,
) -> str:
    """Get details about a specific trust boundary.

    Args:
        ctx: MCP context for logging and error handling
        id: ID of the trust boundary to retrieve

    Returns:
        A markdown-formatted description of the trust boundary
    """
    logger.debug(f'Getting trust boundary: {id}')

    if id not in trust_boundaries:
        return f"Trust boundary with ID {id} not found."

    boundary = trust_boundaries[id]

    result = f"# {boundary.name} ({boundary.id})\n\n"
    result += f"**Type:** {boundary.type.value}\n\n"

    if boundary.description:
        result += f"**Description:** {boundary.description}\n\n"

    if boundary.crossing_points:
        result += "**Crossing Points:**\n\n"
        for cp_id in boundary.crossing_points:
            cp = crossing_points.get(cp_id, None)
            if cp:
                source_zone = trust_zones.get(cp.source_zone_id, None)
                dest_zone = trust_zones.get(cp.destination_zone_id, None)

                source_name = source_zone.name if source_zone else "Unknown"
                dest_name = dest_zone.name if dest_zone else "Unknown"

                result += f"- {cp_id}: {source_name} → {dest_name}\n"
            else:
                result += f"- {cp_id}: Unknown\n"
        result += "\n"
    else:
        result += "**Crossing Points:** None\n\n"

    if boundary.controls:
        result += "**Security Controls:**\n\n"
        for control in boundary.controls:
            result += f"- {control}\n"
        result += "\n"
    else:
        result += "**Security Controls:** None\n\n"

    return result

async def delete_trust_boundary_impl(
    ctx: Context,
    id: str,
) -> str:
    """Delete a trust boundary.

    Args:
        ctx: MCP context for logging and error handling
        id: ID of the trust boundary to delete

    Returns:
        A confirmation message
    """
    logger.debug(f'Deleting trust boundary: {id}')

    if id not in trust_boundaries:
        return f"Trust boundary with ID {id} not found."

    # Delete the trust boundary
    del trust_boundaries[id]

    return f"Trust boundary {id} deleted successfully."


async def get_trust_boundary_analysis_plan_impl(
    ctx: Context,
) -> str:
    """Get a comprehensive trust boundary analysis plan with enforced AWS documentation validation.

    Args:
        ctx: MCP context for logging and error handling

    Returns:
        A markdown-formatted trust boundary analysis plan with AWS documentation validation
    """
    logger.debug('Getting trust boundary analysis plan with AWS validation')

    # Import components from architecture analyzer to check for AWS components
    from threat_modeling_mcp_server.tools.architecture_analyzer import components

    # Check if there are any AWS components that might affect trust boundaries
    aws_components = []
    aws_services = set()

    for component in components.values():
        if component.service_provider and component.service_provider.value == "AWS":
            aws_components.append(component)
            if component.specific_service:
                aws_services.add(component.specific_service)

    result = "# Trust Boundary Analysis Plan with AWS Documentation Validation\n\n"

    if aws_components:
        result += "## AWS Components Detected in Architecture\n\n"
        result += f"Found {len(aws_components)} AWS components that may affect trust boundaries:\n\n"
        for component in aws_components:
            result += f"- **{component.name}** ({component.id}): {component.specific_service or 'AWS Service'}\n"
        result += "\n"

        result += "**⚠️ MANDATORY AWS DOCUMENTATION VALIDATION REQUIRED ⚠️**\n\n"
        result += "Trust boundary analysis MUST include AWS documentation validation for network security, VPC configurations, and IAM policies.\n\n"

        # Automatically search for AWS security documentation for detected services
        result += "## Required AWS Documentation Searches\n\n"
        result += "The following AWS documentation searches are MANDATORY for trust boundary analysis:\n\n"

        # Add general AWS network security searches
        result += "### AWS Network Security Documentation\n\n"
        result += "**REQUIRED**: Search AWS documentation for VPC and network security:\n"
        result += "```\n"
        result += "use_mcp_tool(\n"
        result += '  server_name: "github.com/awslabs/mcp/tree/main/src/aws-documentation-mcp-server",\n'
        result += '  tool_name: "search_documentation",\n'
        result += '  arguments: {"search_phrase": "VPC security groups network ACL"}\n'
        result += ")\n"
        result += "```\n\n"

        result += "### AWS IAM and Access Control Documentation\n\n"
        result += "**REQUIRED**: Search AWS documentation for IAM policies and access control:\n"
        result += "```\n"
        result += "use_mcp_tool(\n"
        result += '  server_name: "github.com/awslabs/mcp/tree/main/src/aws-documentation-mcp-server",\n'
        result += '  tool_name: "search_documentation",\n'
        result += '  arguments: {"search_phrase": "IAM policies cross-account access"}\n'
        result += ")\n"
        result += "```\n\n"

        for service in aws_services:
            result += f"### {service} Security Documentation\n\n"
            result += f"**REQUIRED**: Search AWS documentation for {service} security best practices:\n"
            result += "```\n"
            result += "use_mcp_tool(\n"
            result += '  server_name: "github.com/awslabs/mcp/tree/main/src/aws-documentation-mcp-server",\n'
            result += '  tool_name: "search_documentation",\n'
            result += f'  arguments: {{"search_phrase": "{service} security best practices"}}\n'
            result += ")\n"
            result += "```\n\n"

        result += "**ENFORCEMENT**: Trust boundary analysis cannot be completed without validating AWS network security configurations against official AWS documentation.\n\n"

    result += """## Analysis Process

### Step 1: Gather Trust Boundary Data
First, collect all trust boundary information using the following tools:

1. **Get Trust Zones**: Use `manage_trust_boundaries(action="list", section="zones")`
2. **Get Crossing Points**: Use `manage_trust_boundaries(action="list", section="crossing_points")`
3. **Get Trust Boundaries**: Use `manage_trust_boundaries(action="list", section="boundaries")`
4. **Get Detailed Information**: Use `manage_trust_boundaries(action="get", section=SECTION, item_id=ID)`

### Step 2: AWS Documentation Validation (MANDATORY if AWS components present)
"""

    if aws_components:
        result += "**THIS STEP IS REQUIRED** - AWS components detected that affect trust boundaries.\n\n"
        result += "You MUST validate all AWS-specific trust boundary findings against official AWS documentation using:\n\n"
        result += "1. **Search AWS Documentation**: \n"
        result += "   ```\n"
        result += "   use_mcp_tool(\n"
        result += '     server_name: "github.com/awslabs/mcp/tree/main/src/aws-documentation-mcp-server",\n'
        result += '     tool_name: "search_documentation", \n'
        result += '     arguments: {"search_phrase": "[security concern or service name]"}\n'
        result += "   )\n"
        result += "   ```\n\n"
        result += "2. **Read Specific Documentation**:\n"
        result += "   ```\n"
        result += "   use_mcp_tool(\n"
        result += '     server_name: "github.com/awslabs/mcp/tree/main/src/aws-documentation-mcp-server",\n'
        result += '     tool_name: "read_documentation",\n'
        result += '     arguments: {"url": "[AWS documentation URL]"}\n'
        result += "   )\n"
        result += "   ```\n\n"
    else:
        result += "No AWS components detected - AWS documentation validation not required.\n\n"

    result += """### Step 3: LLM Analysis Prompt
Use the following prompt structure with an LLM to analyze the trust boundaries:

```
You are a cybersecurity expert analyzing trust boundaries for security concerns and access control risks.

TRUST BOUNDARY DATA:
[Insert the output from manage_trust_boundaries list calls here]
"""

    if aws_components:
        result += """
AWS DOCUMENTATION VALIDATION DATA:
[Insert the results from AWS documentation searches here - THIS IS MANDATORY]
"""

    result += """
ANALYSIS INSTRUCTIONS:
1. **Trust Zone Analysis**:
   - Identify trust zones with inappropriate trust levels
   - Check for trust zones without assigned components
   - Analyze trust level consistency and hierarchy
   - Look for missing or unclear zone boundaries

2. **Crossing Point Analysis**:
   - Identify crossing points without proper authentication
   - Check for crossing points without authorization controls
   - Analyze authentication and authorization method appropriateness
   - Look for crossing points without mapped connections

3. **Trust Boundary Analysis**:
   - Check for trust boundaries without security controls
   - Analyze the adequacy of implemented security controls
   - Identify missing boundary types or incomplete coverage
   - Look for boundaries that don't align with crossing points

4. **Security Control Analysis**:
   - Evaluate the effectiveness of implemented controls
   - Identify gaps in security control coverage
   - Analyze control redundancy and defense in depth
   - Look for missing industry-standard controls

5. **Access Control Analysis**:
   - Check for proper authentication mechanisms at boundaries
   - Analyze authorization models and their implementation
   - Identify privilege escalation risks across boundaries
   - Look for inadequate access logging and monitoring
"""

    if aws_components:
        result += """
6. **AWS-Specific Analysis** (MANDATORY - AWS components detected):
   - Validate AWS security group configurations against documentation
   - Check VPC and subnet boundary implementations per AWS best practices
   - Analyze IAM policies for cross-boundary access per AWS guidelines
   - Identify missing AWS security services (WAF, Shield, etc.) per documentation
   - Cross-reference findings with AWS documentation search results
"""

    result += """
OUTPUT FORMAT:
Provide your analysis in the following markdown format:

# Trust Boundary Security Analysis

## Executive Summary
[Brief overview of trust boundary security posture and critical findings]

## Trust Zone Analysis
[Detailed analysis of trust zone configuration and security issues]

## Crossing Point Analysis
[Detailed analysis of crossing point security controls and access mechanisms]

## Trust Boundary Analysis
[Detailed analysis of boundary definitions and security controls]

## Security Control Assessment
[Analysis of implemented controls and their effectiveness]

## Access Control Evaluation
[Assessment of authentication and authorization mechanisms]
"""

    if aws_components:
        result += """
## AWS-Specific Findings (MANDATORY SECTION)
[AWS service-specific security concerns with documentation references - MUST include citations to AWS documentation]
"""

    result += """
## Risk Assessment
[Prioritized list of security risks with severity levels and impact analysis]

## Recommendations
[Actionable security recommendations with implementation guidance]

## Compliance Considerations
[Relevant compliance requirements and regulatory implications]
```

### Step 4: Generate Final Report
"""

    if aws_components:
        result += "Combine the LLM analysis with MANDATORY AWS documentation validation to produce a comprehensive trust boundary security assessment.\n\n"
        result += "**VALIDATION CHECKPOINT**: Ensure all AWS-specific trust boundary findings are backed by official AWS documentation.\n\n"
    else:
        result += "Generate comprehensive trust boundary security assessment based on analysis.\n\n"

    result += """## Key Security Areas to Focus On

### 1. Trust Zone Security
- Appropriate trust level assignments
- Component-to-zone mappings
- Zone isolation and segmentation
- Trust level hierarchy consistency

### 2. Boundary Controls
- Authentication mechanisms at boundaries
- Authorization and access control
- Encryption and data protection
- Monitoring and logging

### 3. Crossing Point Security
- Secure communication protocols
- Identity verification mechanisms
- Access control enforcement
- Audit trail generation

### 4. Network Security
- Network segmentation implementation
- Firewall and security group rules
- VPN and secure tunneling
- Intrusion detection and prevention

### 5. Access Management
- Identity and access management (IAM)
- Role-based access control (RBAC)
- Principle of least privilege
- Regular access reviews

### 6. Monitoring and Compliance
- Security event logging
- Real-time monitoring and alerting
- Compliance with security frameworks
- Incident response procedures

## Analysis Techniques

### 1. Trust Model Validation
- Verify trust assumptions and relationships
- Identify trust boundary violations
- Analyze trust propagation and delegation
- Check for circular trust dependencies

### 2. Attack Surface Analysis
- Map potential attack vectors across boundaries
- Identify exposed services and interfaces
- Analyze privilege escalation paths
- Check for lateral movement opportunities

### 3. Control Effectiveness Assessment
- Evaluate control implementation quality
- Test control bypass scenarios
- Analyze control coverage gaps
- Check for defense in depth

### 4. Compliance Mapping
- Map boundaries to regulatory requirements
- Identify compliance gaps and violations
- Analyze audit trail completeness
- Check for data protection compliance

## Expected Deliverables

1. **Trust Boundary Security Assessment**: Comprehensive analysis of all trust boundaries
2. **Risk Register**: Prioritized list of identified security risks
3. **Control Recommendations**: Specific security controls to implement
4. **Compliance Report**: Assessment against relevant security frameworks
5. **Remediation Roadmap**: Step-by-step plan for addressing security gaps
"""

    if aws_components:
        result += "6. **AWS Documentation Validation Report**: Evidence of AWS network security best practice compliance\n"

    result += """
## Tools and Resources

- **Trust Boundary Tool**: manage_trust_boundaries
"""

    if aws_components:
        result += "- **AWS Documentation**: AWS Documentation MCP Server (MANDATORY for validation)\n"

    result += """- **Security Frameworks**: NIST Cybersecurity Framework, ISO 27001, OWASP
- **Compliance Standards**: SOC 2, PCI DSS, GDPR (as applicable)

This plan ensures a thorough, AI-powered analysis of your trust boundaries with proper validation against authoritative sources and security best practices.
"""

    if aws_components:
        result += "\n**⚠️ CRITICAL**: AWS documentation validation is MANDATORY and cannot be skipped when AWS components are present in the architecture.\n"

    return result


async def clear_trust_boundaries_impl(
    ctx: Context,
) -> str:
    """Clear all trust boundaries, crossing points, and trust zones.

    Args:
        ctx: MCP context for logging and error handling

    Returns:
        A confirmation message
    """
    logger.debug('Clearing trust boundaries')

    trust_zones.clear()
    crossing_points.clear()
    trust_boundaries.clear()

    return "All trust boundaries, crossing points, and trust zones cleared."
