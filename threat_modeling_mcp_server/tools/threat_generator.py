"""Threat Generator and Analyzer for the Cline Threat Modeling MCP Server."""

from typing import Dict, List, Optional, Set, Tuple, Any
from loguru import logger
from mcp.server.fastmcp import Context
from uuid import uuid4
import json
import os

from threat_modeling_mcp_server.models.threat_models import (
    Threat, Mitigation, ThreatCategory, ThreatSeverity, ThreatLikelihood,
    AttackVector, AttackComplexity, ThreatStatus, MitigationType, MitigationStatus,
    MitigationCost, MitigationEffectiveness, MetadataItem, AssumptionLink, MitigationLink,
    ThreatModel, ThreatLibrary, MitigationLibrary
)
from threat_modeling_mcp_server.tools.assumption_manager import assumptions
from threat_modeling_mcp_server.utils.file_utils import normalize_output_path


# Global dictionaries to store threats and mitigations
threats: Dict[str, Threat] = {}
mitigations: Dict[str, Mitigation] = {}
assumption_links: List[AssumptionLink] = []
mitigation_links: List[MitigationLink] = []

# Counter for numeric IDs
threat_counter = 1
mitigation_counter = 1


async def add_threat_impl(
    ctx: Context,
    threat_source: str,
    prerequisites: str,
    threat_action: str,
    threat_impact: str,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    likelihood: Optional[str] = None,
    affected_components: Optional[List[str]] = None,
    affected_assets: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
) -> str:
    """Add a new threat to the model."""
    global threat_counter
    
    logger.debug(f'Adding threat: {threat_source} {threat_action}')
    
    # Generate ID
    threat_id = str(uuid4())
    
    # Create statement from components
    statement = f"A {threat_source} {prerequisites} can {threat_action}, which leads to {threat_impact}"
    
    # Create threat
    threat = Threat(
        id=threat_id,
        numericId=threat_counter,
        threatSource=threat_source,
        prerequisites=prerequisites,
        threatAction=threat_action,
        threatImpact=threat_impact,
        statement=statement,
        displayOrder=threat_counter,
        category=ThreatCategory(category) if category else None,
        severity=ThreatSeverity(severity) if severity else None,
        likelihood=ThreatLikelihood(likelihood) if likelihood else None,
        impactedAssets=affected_assets or [],
        affected_components=affected_components or [],
        tags=tags or []
    )
    
    # Add to dictionary
    threats[threat_id] = threat
    threat_counter += 1
    
    return f"Threat added with ID: {threat_id}"


async def update_threat_impl(
    ctx: Context,
    id: str,
    threat_source: Optional[str] = None,
    prerequisites: Optional[str] = None,
    threat_action: Optional[str] = None,
    threat_impact: Optional[str] = None,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    likelihood: Optional[str] = None,
    status: Optional[str] = None,
    affected_components: Optional[List[str]] = None,
    affected_assets: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
) -> str:
    """Update an existing threat."""
    logger.debug(f'Updating threat: {id}')
    
    # Check if the threat exists
    if id not in threats:
        return f"Threat with ID {id} not found"
    
    # Get the existing threat
    threat = threats[id]
    
    # Update the threat fields
    if threat_source is not None:
        threat.threatSource = threat_source
    
    if prerequisites is not None:
        threat.prerequisites = prerequisites
    
    if threat_action is not None:
        threat.threatAction = threat_action
    
    if threat_impact is not None:
        threat.threatImpact = threat_impact
    
    # Update the statement if any of the components changed
    if threat_source is not None or prerequisites is not None or threat_action is not None or threat_impact is not None:
        threat.statement = f"A {threat.threatSource} {threat.prerequisites} can {threat.threatAction}, which leads to {threat.threatImpact}"
    
    if category is not None:
        threat.category = ThreatCategory(category)
    
    if severity is not None:
        threat.severity = ThreatSeverity(severity)
    
    if likelihood is not None:
        threat.likelihood = ThreatLikelihood(likelihood)
    
    if status is not None:
        threat.status = ThreatStatus(status)
    
    if affected_components is not None:
        threat.affected_components = affected_components
    
    if affected_assets is not None:
        threat.impactedAssets = affected_assets
    
    if tags is not None:
        threat.tags = tags
    
    return f"Threat {id} updated successfully"


async def list_threats_impl(
    ctx: Context,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
) -> str:
    """List all threats in the model."""
    logger.debug('Listing threats')
    
    # Filter threats by category, severity, and status if provided
    filtered_threats = threats.values()
    
    if category:
        filtered_threats = [t for t in filtered_threats if t.category == ThreatCategory(category)]
    
    if severity:
        filtered_threats = [t for t in filtered_threats if t.severity == ThreatSeverity(severity)]
    
    if status:
        filtered_threats = [t for t in filtered_threats if t.status == ThreatStatus(status)]
    
    # Sort threats by numeric ID
    sorted_threats = sorted(filtered_threats, key=lambda t: t.numericId)
    
    # Generate the markdown output
    result = "# Threats\n\n"
    
    if not sorted_threats:
        result += "No threats found.\n"
        return result
    
    for threat in sorted_threats:
        result += f"## {threat.numericId}: {threat.statement}\n\n"
        
        if threat.category:
            result += f"**Category:** {threat.category.value}\n\n"
        
        if threat.severity:
            result += f"**Severity:** {threat.severity.value}\n\n"
        
        if threat.likelihood:
            result += f"**Likelihood:** {threat.likelihood.value}\n\n"
        
        result += f"**Status:** {threat.status.value}\n\n"
        
        if threat.affected_components:
            result += "**Affected Components:**\n\n"
            for comp_id in threat.affected_components:
                result += f"- {comp_id}\n"
            result += "\n"
        
        if threat.impactedAssets:
            result += "**Impacted Assets:**\n\n"
            for asset_id in threat.impactedAssets:
                result += f"- {asset_id}\n"
            result += "\n"
        
        if threat.tags:
            result += "**Tags:**\n\n"
            for tag in threat.tags:
                result += f"- {tag}\n"
            result += "\n"
        
        # Get linked mitigations
        linked_mitigations = [link.mitigationId for link in mitigation_links if link.linkedId == threat.id]
        if linked_mitigations:
            result += "**Mitigations:**\n\n"
            for mitigation_id in linked_mitigations:
                if mitigation_id in mitigations:
                    mitigation = mitigations[mitigation_id]
                    result += f"- {mitigation.content} ({mitigation_id})\n"
            result += "\n"
        
        # Get linked assumptions
        linked_assumptions = [link.assumptionId for link in assumption_links if link.linkedId == threat.id]
        if linked_assumptions:
            result += "**Assumptions:**\n\n"
            for assumption_id in linked_assumptions:
                if assumption_id in assumptions:
                    assumption = assumptions[assumption_id]
                    result += f"- {assumption.description} ({assumption_id})\n"
            result += "\n"
        
        result += "---\n\n"
    
    return result


async def get_threat_impl(
    ctx: Context,
    id: str,
) -> str:
    """Get details about a specific threat."""
    logger.debug(f'Getting threat: {id}')
    
    # Check if the threat exists
    if id not in threats:
        return f"Threat with ID {id} not found"
    
    # Get the threat
    threat = threats[id]
    
    # Generate the markdown output
    result = f"# Threat {threat.numericId}: {threat.statement}\n\n"
    
    result += f"**ID:** {threat.id}\n\n"
    result += f"**Source:** {threat.threatSource}\n\n"
    result += f"**Prerequisites:** {threat.prerequisites}\n\n"
    result += f"**Action:** {threat.threatAction}\n\n"
    result += f"**Impact:** {threat.threatImpact}\n\n"
    
    if threat.category:
        result += f"**Category:** {threat.category.value}\n\n"
    
    if threat.severity:
        result += f"**Severity:** {threat.severity.value}\n\n"
    
    if threat.likelihood:
        result += f"**Likelihood:** {threat.likelihood.value}\n\n"
    
    result += f"**Status:** {threat.status.value}\n\n"
    
    if threat.affected_components:
        result += "**Affected Components:**\n\n"
        for comp_id in threat.affected_components:
            result += f"- {comp_id}\n"
        result += "\n"
    
    if threat.impactedAssets:
        result += "**Impacted Assets:**\n\n"
        for asset_id in threat.impactedAssets:
            result += f"- {asset_id}\n"
        result += "\n"
    
    if threat.tags:
        result += "**Tags:**\n\n"
        for tag in threat.tags:
            result += f"- {tag}\n"
        result += "\n"
    
    # Get linked mitigations
    linked_mitigations = [link.mitigationId for link in mitigation_links if link.linkedId == threat.id]
    if linked_mitigations:
        result += "**Mitigations:**\n\n"
        for mitigation_id in linked_mitigations:
            if mitigation_id in mitigations:
                mitigation = mitigations[mitigation_id]
                result += f"- {mitigation.content} ({mitigation_id})\n"
        result += "\n"
    
    # Get linked assumptions
    linked_assumptions = [link.assumptionId for link in assumption_links if link.linkedId == threat.id]
    if linked_assumptions:
        result += "**Assumptions:**\n\n"
        for assumption_id in linked_assumptions:
            if assumption_id in assumptions:
                assumption = assumptions[assumption_id]
                result += f"- {assumption.description} ({assumption_id})\n"
        result += "\n"
    
    return result


async def delete_threat_impl(
    ctx: Context,
    id: str,
) -> str:
    """Delete a threat from the model."""
    logger.debug(f'Deleting threat: {id}')
    
    # Check if the threat exists
    if id not in threats:
        return f"Threat with ID {id} not found"
    
    # Delete the threat
    del threats[id]
    
    # Delete any links to this threat
    global assumption_links, mitigation_links
    assumption_links = [link for link in assumption_links if link.linkedId != id]
    mitigation_links = [link for link in mitigation_links if link.linkedId != id]
    
    return f"Threat {id} deleted successfully"


async def add_mitigation_impl(
    ctx: Context,
    content: str,
    type: Optional[str] = None,
    status: str = "mitigationIdentified",
    implementation_details: Optional[str] = None,
    cost: Optional[str] = None,
    effectiveness: Optional[str] = None,
    metadata: Optional[List[Dict[str, str]]] = None,
) -> str:
    """Add a new mitigation to the model."""
    global mitigation_counter
    
    logger.debug(f'Adding mitigation: {content}')
    
    # Generate ID
    mitigation_id = str(uuid4())
    
    # Create metadata items
    metadata_items = []
    if metadata:
        for item in metadata:
            metadata_items.append(MetadataItem(key=item["key"], value=item["value"]))
    
    # Create mitigation
    mitigation = Mitigation(
        id=mitigation_id,
        numericId=mitigation_counter,
        status=MitigationStatus(status),
        content=content,
        displayOrder=mitigation_counter,
        metadata=metadata_items,
        type=MitigationType(type) if type else None,
        cost=MitigationCost(cost) if cost else None,
        effectiveness=MitigationEffectiveness(effectiveness) if effectiveness else None,
        implementation_details=implementation_details
    )
    
    # Add to dictionary
    mitigations[mitigation_id] = mitigation
    mitigation_counter += 1
    
    return f"Mitigation added with ID: {mitigation_id}"


async def list_mitigations_impl(
    ctx: Context,
    type: Optional[str] = None,
    status: Optional[str] = None,
) -> str:
    """List all mitigations in the model."""
    logger.debug('Listing mitigations')
    
    # Filter mitigations by type and status if provided
    filtered_mitigations = mitigations.values()
    
    if type:
        filtered_mitigations = [m for m in filtered_mitigations if m.type and m.type == MitigationType(type)]
    
    if status:
        filtered_mitigations = [m for m in filtered_mitigations if m.status == MitigationStatus(status)]
    
    # Sort mitigations by numeric ID
    sorted_mitigations = sorted(filtered_mitigations, key=lambda m: m.numericId)
    
    # Generate the markdown output
    result = "# Mitigations\n\n"
    
    if not sorted_mitigations:
        result += "No mitigations found.\n"
        return result
    
    for mitigation in sorted_mitigations:
        result += f"## {mitigation.numericId}: {mitigation.content}\n\n"
        
        result += f"**ID:** {mitigation.id}\n\n"
        result += f"**Status:** {mitigation.status.value}\n\n"
        
        if mitigation.type:
            result += f"**Type:** {mitigation.type.value}\n\n"
        
        if mitigation.implementation_details:
            result += f"**Implementation Details:** {mitigation.implementation_details}\n\n"
        
        if mitigation.cost:
            result += f"**Cost:** {mitigation.cost.value}\n\n"
        
        if mitigation.effectiveness:
            result += f"**Effectiveness:** {mitigation.effectiveness.value}\n\n"
        
        if mitigation.metadata:
            result += "**Metadata:**\n\n"
            for item in mitigation.metadata:
                result += f"- {item.key}: {item.value}\n"
            result += "\n"
        
        # Get linked threats
        linked_threats = [link.linkedId for link in mitigation_links if link.mitigationId == mitigation.id]
        if linked_threats:
            result += "**Linked Threats:**\n\n"
            for threat_id in linked_threats:
                if threat_id in threats:
                    threat = threats[threat_id]
                    result += f"- {threat.statement} ({threat_id})\n"
            result += "\n"
        
        result += "---\n\n"
    
    return result


async def get_mitigation_impl(
    ctx: Context,
    id: str,
) -> str:
    """Get details about a specific mitigation."""
    logger.debug(f'Getting mitigation: {id}')
    
    # Check if the mitigation exists
    if id not in mitigations:
        return f"Mitigation with ID {id} not found"
    
    # Get the mitigation
    mitigation = mitigations[id]
    
    # Generate the markdown output
    result = f"# Mitigation {mitigation.numericId}: {mitigation.content}\n\n"
    
    result += f"**ID:** {mitigation.id}\n\n"
    result += f"**Status:** {mitigation.status.value}\n\n"
    
    if mitigation.type:
        result += f"**Type:** {mitigation.type.value}\n\n"
    
    if mitigation.implementation_details:
        result += f"**Implementation Details:** {mitigation.implementation_details}\n\n"
    
    if mitigation.cost:
        result += f"**Cost:** {mitigation.cost.value}\n\n"
    
    if mitigation.effectiveness:
        result += f"**Effectiveness:** {mitigation.effectiveness.value}\n\n"
    
    if mitigation.metadata:
        result += "**Metadata:**\n\n"
        for item in mitigation.metadata:
            result += f"- {item.key}: {item.value}\n"
        result += "\n"
    
    # Get linked threats
    linked_threats = [link.linkedId for link in mitigation_links if link.mitigationId == mitigation.id]
    if linked_threats:
        result += "**Linked Threats:**\n\n"
        for threat_id in linked_threats:
            if threat_id in threats:
                threat = threats[threat_id]
                result += f"- {threat.statement} ({threat_id})\n"
        result += "\n"
    
    return result


async def update_mitigation_impl(
    ctx: Context,
    id: str,
    content: Optional[str] = None,
    type: Optional[str] = None,
    status: Optional[str] = None,
    implementation_details: Optional[str] = None,
    cost: Optional[str] = None,
    effectiveness: Optional[str] = None,
    metadata: Optional[List[Dict[str, str]]] = None,
) -> str:
    """Update an existing mitigation."""
    logger.debug(f'Updating mitigation: {id}')
    
    # Check if the mitigation exists
    if id not in mitigations:
        return f"Mitigation with ID {id} not found"
    
    # Get the existing mitigation
    mitigation = mitigations[id]
    
    # Update the mitigation fields
    if content is not None:
        mitigation.content = content
    
    if type is not None:
        mitigation.type = MitigationType(type)
    
    if status is not None:
        mitigation.status = MitigationStatus(status)
    
    if implementation_details is not None:
        mitigation.implementation_details = implementation_details
    
    if cost is not None:
        mitigation.cost = MitigationCost(cost)
    
    if effectiveness is not None:
        mitigation.effectiveness = MitigationEffectiveness(effectiveness)
    
    if metadata is not None:
        metadata_items = []
        for item in metadata:
            metadata_items.append(MetadataItem(key=item["key"], value=item["value"]))
        mitigation.metadata = metadata_items
    
    # Store the updated mitigation
    mitigations[id] = mitigation
    
    return f"Mitigation {id} updated successfully"


async def delete_mitigation_impl(
    ctx: Context,
    id: str,
) -> str:
    """Delete a mitigation from the model."""
    logger.debug(f'Deleting mitigation: {id}')
    
    # Check if the mitigation exists
    if id not in mitigations:
        return f"Mitigation with ID {id} not found"
    
    # Delete the mitigation
    del mitigations[id]
    
    # Delete any links to this mitigation
    global mitigation_links
    mitigation_links = [link for link in mitigation_links if link.mitigationId != id]
    
    return f"Mitigation {id} deleted successfully"




async def link_mitigation_to_threat_impl(
    ctx: Context,
    mitigation_id: str,
    threat_id: str,
) -> str:
    """Link a mitigation to a threat."""
    logger.debug(f'Linking mitigation {mitigation_id} to threat {threat_id}')
    
    # Check if the mitigation exists
    if mitigation_id not in mitigations:
        return f"Mitigation with ID {mitigation_id} not found"
    
    # Check if the threat exists
    if threat_id not in threats:
        return f"Threat with ID {threat_id} not found"
    
    # Check if the link already exists
    for link in mitigation_links:
        if link.mitigationId == mitigation_id and link.linkedId == threat_id:
            return f"Mitigation {mitigation_id} is already linked to threat {threat_id}"
    
    # Create the link
    link = MitigationLink(
        linkedId=threat_id,
        mitigationId=mitigation_id
    )
    
    # Add the link
    mitigation_links.append(link)
    
    return f"Mitigation {mitigation_id} linked to threat {threat_id}"


async def unlink_mitigation_from_threat_impl(
    ctx: Context,
    mitigation_id: str,
    threat_id: str,
) -> str:
    """Unlink a mitigation from a threat."""
    logger.debug(f'Unlinking mitigation {mitigation_id} from threat {threat_id}')
    
    # Check if the link exists
    found = False
    global mitigation_links
    for i, link in enumerate(mitigation_links):
        if link.mitigationId == mitigation_id and link.linkedId == threat_id:
            found = True
            break
    
    if not found:
        return f"Mitigation {mitigation_id} is not linked to threat {threat_id}"
    
    # Remove the link
    mitigation_links = [link for link in mitigation_links if not (link.mitigationId == mitigation_id and link.linkedId == threat_id)]
    
    return f"Mitigation {mitigation_id} unlinked from threat {threat_id}"


# Register tools with the MCP server
def register_tools(mcp):
    """Register threat generator tools with the MCP server."""
    @mcp.tool()
    async def add_threat(
        ctx: Context,
        threat_source: str,
        prerequisites: str,
        threat_action: str,
        threat_impact: str,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        likelihood: Optional[str] = None,
        affected_components: Optional[List[str]] = None,
        affected_assets: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
    ) -> str:
        """Add a new threat to the model.

        This tool adds a new threat to the threat model.

        Args:
            ctx: MCP context for logging and error handling
            threat_source: Source of the threat (e.g., 'external attacker')
            prerequisites: Prerequisites for the threat (e.g., 'with access to the network')
            threat_action: Action performed by the threat (e.g., 'intercept unencrypted data')
            threat_impact: Impact of the threat (e.g., 'exposure of sensitive data')
            category: STRIDE category of the threat
            severity: Severity of the threat
            likelihood: Likelihood of the threat
            affected_components: List of component IDs affected by the threat
            affected_assets: List of asset IDs affected by the threat
            tags: List of tags for the threat

        Returns:
            A confirmation message with the threat ID
        """
        return await add_threat_impl(
            ctx, threat_source, prerequisites, threat_action, threat_impact,
            category, severity, likelihood, affected_components, affected_assets, tags
        )
    
    @mcp.tool()
    async def list_threats(
        ctx: Context,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> str:
        """List all threats in the model.

        This tool lists all threats in the threat model, optionally filtered by category, severity, or status.

        Args:
            ctx: MCP context for logging and error handling
            category: Optional category to filter threats
            severity: Optional severity to filter threats
            status: Optional status to filter threats

        Returns:
            A markdown-formatted list of threats
        """
        return await list_threats_impl(ctx, category, severity, status)
    
    @mcp.tool()
    async def get_threat(
        ctx: Context,
        id: str,
    ) -> str:
        """Get details about a specific threat.

        This tool retrieves details about a specific threat in the threat model.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the threat to retrieve

        Returns:
            A markdown-formatted description of the threat
        """
        return await get_threat_impl(ctx, id)
    
    @mcp.tool()
    async def update_threat(
        ctx: Context,
        id: str,
        threat_source: Optional[str] = None,
        prerequisites: Optional[str] = None,
        threat_action: Optional[str] = None,
        threat_impact: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        likelihood: Optional[str] = None,
        status: Optional[str] = None,
        affected_components: Optional[List[str]] = None,
        affected_assets: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
    ) -> str:
        """Update an existing threat.

        This tool updates an existing threat in the threat model.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the threat to update
            threat_source: New source of the threat
            prerequisites: New prerequisites for the threat
            threat_action: New action performed by the threat
            threat_impact: New impact of the threat
            category: New STRIDE category of the threat
            severity: New severity of the threat
            likelihood: New likelihood of the threat
            status: New status of the threat
            affected_components: New list of component IDs affected by the threat
            affected_assets: New list of asset IDs affected by the threat
            tags: New list of tags for the threat

        Returns:
            A confirmation message
        """
        return await update_threat_impl(
            ctx, id, threat_source, prerequisites, threat_action, threat_impact,
            category, severity, likelihood, status, affected_components, affected_assets, tags
        )
    
    @mcp.tool()
    async def delete_threat(
        ctx: Context,
        id: str,
    ) -> str:
        """Delete a threat from the model.

        This tool deletes a threat from the threat model.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the threat to delete

        Returns:
            A confirmation message
        """
        return await delete_threat_impl(ctx, id)
    
    @mcp.tool()
    async def add_mitigation(
        ctx: Context,
        content: str,
        type: Optional[str] = None,
        status: str = "mitigationIdentified",
        implementation_details: Optional[str] = None,
        cost: Optional[str] = None,
        effectiveness: Optional[str] = None,
        metadata: Optional[List[Dict[str, str]]] = None,
    ) -> str:
        """Add a new mitigation to the model.

        This tool adds a new mitigation to the threat model.

        Args:
            ctx: MCP context for logging and error handling
            content: Content of the mitigation
            type: Type of the mitigation
            status: Status of the mitigation
            implementation_details: Implementation details of the mitigation
            cost: Cost of the mitigation
            effectiveness: Effectiveness of the mitigation
            metadata: Metadata for the mitigation

        Returns:
            A confirmation message with the mitigation ID
        """
        return await add_mitigation_impl(
            ctx, content, type, status, implementation_details, cost, effectiveness, metadata
        )
    
    @mcp.tool()
    async def list_mitigations(
        ctx: Context,
        type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> str:
        """List all mitigations in the model.

        This tool lists all mitigations in the threat model, optionally filtered by type or status.

        Args:
            ctx: MCP context for logging and error handling
            type: Optional type to filter mitigations
            status: Optional status to filter mitigations

        Returns:
            A markdown-formatted list of mitigations
        """
        return await list_mitigations_impl(ctx, type, status)
    
    @mcp.tool()
    async def get_mitigation(
        ctx: Context,
        id: str,
    ) -> str:
        """Get details about a specific mitigation.

        This tool retrieves details about a specific mitigation in the threat model.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the mitigation to retrieve

        Returns:
            A markdown-formatted description of the mitigation
        """
        return await get_mitigation_impl(ctx, id)
    
    @mcp.tool()
    async def update_mitigation(
        ctx: Context,
        id: str,
        content: Optional[str] = None,
        type: Optional[str] = None,
        status: Optional[str] = None,
        implementation_details: Optional[str] = None,
        cost: Optional[str] = None,
        effectiveness: Optional[str] = None,
        metadata: Optional[List[Dict[str, str]]] = None,
    ) -> str:
        """Update an existing mitigation.

        This tool updates an existing mitigation in the threat model.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the mitigation to update
            content: New content of the mitigation
            type: New type of the mitigation
            status: New status of the mitigation
            implementation_details: New implementation details of the mitigation
            cost: New cost of the mitigation
            effectiveness: New effectiveness of the mitigation
            metadata: New metadata for the mitigation

        Returns:
            A confirmation message
        """
        return await update_mitigation_impl(ctx, id, content, type, status, implementation_details, cost, effectiveness, metadata)
    
    @mcp.tool()
    async def delete_mitigation(
        ctx: Context,
        id: str,
    ) -> str:
        """Delete a mitigation from the model.

        This tool deletes a mitigation from the threat model.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the mitigation to delete

        Returns:
            A confirmation message
        """
        return await delete_mitigation_impl(ctx, id)
    
    @mcp.tool()
    async def link_mitigation_to_threat(
        ctx: Context,
        mitigation_id: str,
        threat_id: str,
    ) -> str:
        """Link a mitigation to a threat.

        This tool links a mitigation to a threat in the threat model.

        Args:
            ctx: MCP context for logging and error handling
            mitigation_id: ID of the mitigation to link
            threat_id: ID of the threat to link to

        Returns:
            A confirmation message
        """
        return await link_mitigation_to_threat_impl(ctx, mitigation_id, threat_id)
    
    @mcp.tool()
    async def unlink_mitigation_from_threat(
        ctx: Context,
        mitigation_id: str,
        threat_id: str,
    ) -> str:
        """Unlink a mitigation from a threat.

        This tool unlinks a mitigation from a threat in the threat model.

        Args:
            ctx: MCP context for logging and error handling
            mitigation_id: ID of the mitigation to unlink
            threat_id: ID of the threat to unlink from

        Returns:
            A confirmation message
        """
        return await unlink_mitigation_from_threat_impl(ctx, mitigation_id, threat_id)
    
    
    @mcp.tool()
    async def export_comprehensive_threat_model(
        ctx: Context,
        output_path: str,
        include_extended_data: bool = True,
    ) -> str:
        """Export comprehensive threat model with all global variables to Threat Composer JSON format.

        This tool exports the complete threat model including all global variables from all phases
        of the threat modeling process. It collects business context, assumptions, architecture,
        threat actors, trust boundaries, asset flows, threats, mitigations, and phase progress.

        Args:
            ctx: MCP context for logging and error handling
            output_path: Path to save the exported threat model (will be saved in .threatmodel directory)
            include_extended_data: Whether to include extended data beyond standard Threat Composer format

        Returns:
            A comprehensive export summary with details about what was exported
        """
        logger.info(f"Exporting comprehensive threat model to {output_path}")
        from threat_modeling_mcp_server.utils.comprehensive_exporter import export_comprehensive_threat_model
        return export_comprehensive_threat_model(output_path, include_extended_data)
