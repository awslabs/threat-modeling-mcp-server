"""Threat Actor Analysis functionality for the Cline Threat Modeling MCP Server."""

from typing import Dict, List, Optional, Any
from loguru import logger
from mcp.server.fastmcp import Context
from pydantic import Field

from threat_modeling_mcp_server.models.threat_actor_models import (
    ThreatActor, ThreatActorLibrary, ThreatActorType, 
    Motivation, CapabilityLevel, ResourceLevel
)


# Global state
threat_actor_library = ThreatActorLibrary()
threat_actors: Dict[str, ThreatActor] = {}


def initialize_threat_actors():
    """Initialize the threat actor library with default actors."""
    global threat_actors
    if not threat_actors:
        threat_actors = threat_actor_library.get_default_actors()


async def add_threat_actor_impl(
    ctx: Context,
    name: str,
    type: str,
    capability_level: str,
    motivations: List[str],
    resources: str,
    description: Optional[str] = None,
    priority: int = 0,
    relevance_score: float = 0.5,
    is_relevant: bool = True,
) -> str:
    """Add a new threat actor.
    
    Args:
        ctx: MCP context for logging and error handling
        name: Name of the threat actor
        type: Type of the threat actor
        capability_level: Capability level of the threat actor
        motivations: Motivations of the threat actor
        resources: Resources available to the threat actor
        description: Description of the threat actor
        priority: Priority of the threat actor (1-10)
        relevance_score: Relevance score of the threat actor (0.0-1.0)
        is_relevant: Whether the threat actor is relevant to the system
        
    Returns:
        A confirmation message with the threat actor ID
    """
    logger.debug(f'Adding threat actor: {name}')
    
    # Initialize threat actors if not already done
    initialize_threat_actors()
    
    # Generate a unique ID
    threat_actor_id = f"TA{len(threat_actors) + 1:03d}"
    
    # Create the threat actor
    threat_actor = ThreatActor(
        id=threat_actor_id,
        name=name,
        type=ThreatActorType(type),
        capability_level=CapabilityLevel(capability_level),
        motivations=[Motivation(m) for m in motivations],
        resources=ResourceLevel(resources),
        description=description,
        priority=priority,
        relevance_score=relevance_score,
        is_relevant=is_relevant
    )
    
    # Store the threat actor
    threat_actors[threat_actor_id] = threat_actor
    
    return f"Threat actor added with ID: {threat_actor_id}"


async def update_threat_actor_impl(
    ctx: Context,
    id: str,
    name: Optional[str] = None,
    type: Optional[str] = None,
    capability_level: Optional[str] = None,
    motivations: Optional[List[str]] = None,
    resources: Optional[str] = None,
    description: Optional[str] = None,
    priority: Optional[int] = None,
    relevance_score: Optional[float] = None,
    is_relevant: Optional[bool] = None,
) -> str:
    """Update an existing threat actor.
    
    Args:
        ctx: MCP context for logging and error handling
        id: ID of the threat actor to update
        name: New name of the threat actor
        type: New type of the threat actor
        capability_level: New capability level of the threat actor
        motivations: New motivations of the threat actor
        resources: New resources available to the threat actor
        description: New description of the threat actor
        priority: New priority of the threat actor (1-10)
        relevance_score: New relevance score of the threat actor (0.0-1.0)
        is_relevant: New relevance status of the threat actor
        
    Returns:
        A confirmation message
    """
    logger.debug(f'Updating threat actor: {id}')
    
    # Initialize threat actors if not already done
    initialize_threat_actors()
    
    if id not in threat_actors:
        return f"Threat actor with ID {id} not found."
    
    threat_actor = threat_actors[id]
    
    # Update only the provided fields
    if name is not None:
        threat_actor.name = name
    
    if type is not None:
        threat_actor.type = ThreatActorType(type)
    
    if capability_level is not None:
        threat_actor.capability_level = CapabilityLevel(capability_level)
    
    if motivations is not None:
        threat_actor.motivations = [Motivation(m) for m in motivations]
    
    if resources is not None:
        threat_actor.resources = ResourceLevel(resources)
    
    if description is not None:
        threat_actor.description = description
    
    if priority is not None:
        threat_actor.priority = priority
    
    if relevance_score is not None:
        threat_actor.relevance_score = relevance_score
    
    if is_relevant is not None:
        threat_actor.is_relevant = is_relevant
    
    # Store the updated threat actor
    threat_actors[id] = threat_actor
    
    return f"Threat actor {id} updated successfully."


async def list_threat_actors_impl(
    ctx: Context,
    type: Optional[str] = None,
    relevant_only: bool = False,
) -> str:
    """List all threat actors.
    
    Args:
        ctx: MCP context for logging and error handling
        type: Optional type to filter threat actors
        relevant_only: Whether to only show relevant threat actors
        
    Returns:
        A markdown-formatted list of threat actors
    """
    logger.debug('Listing threat actors')
    
    # Initialize threat actors if not already done
    initialize_threat_actors()
    
    if not threat_actors:
        return "No threat actors have been added yet."
    
    filtered_actors = threat_actors.values()
    
    if type:
        filtered_actors = [a for a in filtered_actors if a.type == ThreatActorType(type)]
    
    if relevant_only:
        filtered_actors = [a for a in filtered_actors if a.is_relevant]
    
    if not filtered_actors:
        return f"No threat actors found with the specified criteria."
    
    # Sort by priority (if set)
    sorted_actors = sorted(filtered_actors, key=lambda a: a.priority if a.priority > 0 else 999)
    
    result = "# Threat Actors\n\n"
    
    for actor in sorted_actors:
        result += f"## {actor.id}: {actor.name}\n\n"
        result += f"**Type:** {actor.type.value}\n\n"
        result += f"**Capability Level:** {actor.capability_level.value}\n\n"
        
        result += "**Motivations:**\n\n"
        for motivation in actor.motivations:
            result += f"- {motivation.value}\n"
        result += "\n"
        
        result += f"**Resources:** {actor.resources.value}\n\n"
        
        if actor.description:
            result += f"**Description:** {actor.description}\n\n"
        
        if actor.priority > 0:
            result += f"**Priority:** {actor.priority}\n\n"
        
        result += f"**Relevance Score:** {actor.relevance_score:.1f}\n\n"
        result += f"**Relevant:** {'Yes' if actor.is_relevant else 'No'}\n\n"
        
        result += "---\n\n"
    
    return result


async def get_threat_actor_impl(
    ctx: Context,
    id: str,
) -> str:
    """Get details about a specific threat actor.
    
    Args:
        ctx: MCP context for logging and error handling
        id: ID of the threat actor to retrieve
        
    Returns:
        A markdown-formatted description of the threat actor
    """
    logger.debug(f'Getting threat actor: {id}')
    
    # Initialize threat actors if not already done
    initialize_threat_actors()
    
    if id not in threat_actors:
        return f"Threat actor with ID {id} not found."
    
    actor = threat_actors[id]
    
    result = f"# {actor.name} ({actor.id})\n\n"
    result += f"**Type:** {actor.type.value}\n\n"
    result += f"**Capability Level:** {actor.capability_level.value}\n\n"
    
    result += "**Motivations:**\n\n"
    for motivation in actor.motivations:
        result += f"- {motivation.value}\n"
    result += "\n"
    
    result += f"**Resources:** {actor.resources.value}\n\n"
    
    if actor.description:
        result += f"**Description:** {actor.description}\n\n"
    
    if actor.priority > 0:
        result += f"**Priority:** {actor.priority}\n\n"
    
    result += f"**Relevance Score:** {actor.relevance_score:.1f}\n\n"
    result += f"**Relevant:** {'Yes' if actor.is_relevant else 'No'}\n\n"
    
    return result


async def delete_threat_actor_impl(
    ctx: Context,
    id: str,
) -> str:
    """Delete a threat actor.
    
    Args:
        ctx: MCP context for logging and error handling
        id: ID of the threat actor to delete
        
    Returns:
        A confirmation message
    """
    logger.debug(f'Deleting threat actor: {id}')
    
    # Initialize threat actors if not already done
    initialize_threat_actors()
    
    if id not in threat_actors:
        return f"Threat actor with ID {id} not found."
    
    # Delete the threat actor
    del threat_actors[id]
    
    return f"Threat actor {id} deleted successfully."


async def set_threat_actor_relevance_impl(
    ctx: Context,
    id: str,
    is_relevant: bool,
) -> str:
    """Set the relevance of a threat actor.
    
    Args:
        ctx: MCP context for logging and error handling
        id: ID of the threat actor
        is_relevant: Whether the threat actor is relevant to the system
        
    Returns:
        A confirmation message
    """
    logger.debug(f'Setting relevance of threat actor {id} to {is_relevant}')
    
    # Initialize threat actors if not already done
    initialize_threat_actors()
    
    if id not in threat_actors:
        return f"Threat actor with ID {id} not found."
    
    # Update the relevance
    threat_actors[id].is_relevant = is_relevant
    
    return f"Threat actor {id} relevance set to {'relevant' if is_relevant else 'not relevant'}."


async def set_threat_actor_priority_impl(
    ctx: Context,
    id: str,
    priority: int,
) -> str:
    """Set the priority of a threat actor.
    
    Args:
        ctx: MCP context for logging and error handling
        id: ID of the threat actor
        priority: Priority of the threat actor (1-10)
        
    Returns:
        A confirmation message
    """
    logger.debug(f'Setting priority of threat actor {id} to {priority}')
    
    # Initialize threat actors if not already done
    initialize_threat_actors()
    
    if id not in threat_actors:
        return f"Threat actor with ID {id} not found."
    
    # Validate priority
    if priority < 1 or priority > 10:
        return f"Priority must be between 1 and 10."
    
    # Update the priority
    threat_actors[id].priority = priority
    
    return f"Threat actor {id} priority set to {priority}."


async def analyze_threat_actors_impl(
    ctx: Context,
) -> str:
    """Analyze the threat actors.
    
    Args:
        ctx: MCP context for logging and error handling
        
    Returns:
        A markdown-formatted analysis of the threat actors
    """
    logger.debug('Analyzing threat actors')
    
    # Initialize threat actors if not already done
    initialize_threat_actors()
    
    if not threat_actors:
        return "No threat actors have been added yet."
    
    # Filter to relevant actors only
    relevant_actors = [a for a in threat_actors.values() if a.is_relevant]
    
    if not relevant_actors:
        return "No relevant threat actors have been identified."
    
    # Sort by priority (if set)
    sorted_actors = sorted(relevant_actors, key=lambda a: a.priority if a.priority > 0 else 999)
    
    result = "# Threat Actor Analysis\n\n"
    
    # Summary
    result += "## Summary\n\n"
    result += f"- **Total Threat Actors:** {len(threat_actors)}\n"
    result += f"- **Relevant Threat Actors:** {len(relevant_actors)}\n\n"
    
    # Count by type
    type_counts = {}
    for actor in relevant_actors:
        if actor.type.value in type_counts:
            type_counts[actor.type.value] += 1
        else:
            type_counts[actor.type.value] = 1
    
    result += "### Threat Actor Types\n\n"
    for type_name, count in type_counts.items():
        result += f"- **{type_name}:** {count}\n"
    
    result += "\n"
    
    # Count by capability level
    capability_counts = {}
    for actor in relevant_actors:
        if actor.capability_level.value in capability_counts:
            capability_counts[actor.capability_level.value] += 1
        else:
            capability_counts[actor.capability_level.value] = 1
    
    result += "### Capability Levels\n\n"
    for level, count in capability_counts.items():
        result += f"- **{level}:** {count}\n"
    
    result += "\n"
    
    # Count by motivation
    motivation_counts = {}
    for actor in relevant_actors:
        for motivation in actor.motivations:
            if motivation.value in motivation_counts:
                motivation_counts[motivation.value] += 1
            else:
                motivation_counts[motivation.value] = 1
    
    result += "### Motivations\n\n"
    for motivation, count in motivation_counts.items():
        result += f"- **{motivation}:** {count}\n"
    
    result += "\n"
    
    # Prioritized list
    result += "## Prioritized Threat Actors\n\n"
    
    for actor in sorted_actors:
        if actor.priority > 0:
            result += f"### {actor.priority}. {actor.name} ({actor.id})\n\n"
            result += f"**Type:** {actor.type.value}\n\n"
            result += f"**Capability Level:** {actor.capability_level.value}\n\n"
            result += f"**Primary Motivations:** {', '.join([m.value for m in actor.motivations])}\n\n"
            result += f"**Resources:** {actor.resources.value}\n\n"
            result += f"**Relevance Score:** {actor.relevance_score:.1f}\n\n"
            
            if actor.description:
                result += f"**Description:** {actor.description}\n\n"
            
            result += "---\n\n"
    
    # Unprioritized actors
    unprioritized = [a for a in sorted_actors if a.priority == 0]
    if unprioritized:
        result += "## Unprioritized Threat Actors\n\n"
        
        for actor in unprioritized:
            result += f"- **{actor.name} ({actor.id}):** {actor.type.value}, {actor.capability_level.value} capability\n"
        
        result += "\n"
    
    # Recommendations
    result += "## Recommendations\n\n"
    
    # Check for high capability actors
    high_capability = [a for a in relevant_actors if a.capability_level == CapabilityLevel.HIGH]
    if high_capability:
        result += "- **High Capability Actors:** Pay special attention to threat actors with high capability levels, as they pose the greatest risk.\n"
    
    # Check for financially motivated actors
    financial_motivation = [a for a in relevant_actors if Motivation.FINANCIAL in a.motivations]
    if financial_motivation:
        result += "- **Financial Motivation:** Many threat actors are financially motivated, suggesting that assets with monetary value are at risk.\n"
    
    # Check for insider threats
    insider_threats = [a for a in relevant_actors if a.type in [ThreatActorType.INSIDER, ThreatActorType.DISGRUNTLED_EMPLOYEE, ThreatActorType.PRIVILEGED_USER]]
    if insider_threats:
        result += "- **Insider Threats:** Consider implementing strong access controls and monitoring to mitigate insider threats.\n"
    
    # Check for nation-state actors
    nation_state = [a for a in relevant_actors if a.type == ThreatActorType.NATION_STATE]
    if nation_state:
        result += "- **Nation-state Actors:** The presence of nation-state actors suggests a need for advanced security measures and threat intelligence.\n"
    
    # Check for unprioritized actors
    if unprioritized:
        result += "- **Prioritization:** Consider prioritizing all relevant threat actors to better focus security efforts.\n"
    
    return result


async def reset_threat_actors_impl(
    ctx: Context,
) -> str:
    """Reset the threat actors to the default set.
    
    Args:
        ctx: MCP context for logging and error handling
        
    Returns:
        A confirmation message
    """
    logger.debug('Resetting threat actors')
    
    global threat_actors
    threat_actors = threat_actor_library.get_default_actors()
    
    return "Threat actors reset to default set."


async def clear_threat_actors_impl(
    ctx: Context,
) -> str:
    """Clear all threat actors.
    
    Args:
        ctx: MCP context for logging and error handling
        
    Returns:
        A confirmation message
    """
    logger.debug('Clearing threat actors')
    
    global threat_actors
    threat_actors = {}
    
    return "All threat actors cleared."


# Register tools with the MCP server
def register_tools(mcp):
    """Register threat actor analysis tools with the MCP server.
    
    Args:
        mcp: The MCP server instance
    """
    # Initialize threat actors
    initialize_threat_actors()
    
    @mcp.tool()
    async def add_threat_actor(
        ctx: Context,
        name: str = Field(description="Name of the threat actor"),
        type: str = Field(description="Type of the threat actor (e.g., 'Insider', 'External', 'Nation-state')"),
        capability_level: str = Field(description="Capability level of the threat actor (Low, Medium, High)"),
        motivations: List[str] = Field(description="Motivations of the threat actor (e.g., 'Financial', 'Political', 'Espionage')"),
        resources: str = Field(description="Resources available to the threat actor (Limited, Moderate, Extensive)"),
        description: Optional[str] = Field(default=None, description="Description of the threat actor"),
        priority: int = Field(default=0, description="Priority of the threat actor (1-10, 0 means not ranked)"),
        relevance_score: float = Field(default=0.5, description="Relevance score of the threat actor (0.0-1.0)"),
        is_relevant: bool = Field(default=True, description="Whether the threat actor is relevant to the system"),
    ) -> str:
        """Add a new threat actor.

        This tool adds a new threat actor to the threat model.

        Args:
            ctx: MCP context for logging and error handling
            name: Name of the threat actor
            type: Type of the threat actor (e.g., 'Insider', 'External', 'Nation-state')
            capability_level: Capability level of the threat actor (Low, Medium, High)
            motivations: Motivations of the threat actor (e.g., 'Financial', 'Political', 'Espionage')
            resources: Resources available to the threat actor (Limited, Moderate, Extensive)
            description: Description of the threat actor
            priority: Priority of the threat actor (1-10, 0 means not ranked)
            relevance_score: Relevance score of the threat actor (0.0-1.0)
            is_relevant: Whether the threat actor is relevant to the system

        Returns:
            A confirmation message with the threat actor ID
        """
        return await add_threat_actor_impl(ctx, name, type, capability_level, motivations, resources, description, priority, relevance_score, is_relevant)

    @mcp.tool()
    async def update_threat_actor(
        ctx: Context,
        id: str = Field(description="ID of the threat actor to update"),
        name: Optional[str] = Field(default=None, description="New name of the threat actor"),
        type: Optional[str] = Field(default=None, description="New type of the threat actor"),
        capability_level: Optional[str] = Field(default=None, description="New capability level of the threat actor"),
        motivations: Optional[List[str]] = Field(default=None, description="New motivations of the threat actor"),
        resources: Optional[str] = Field(default=None, description="New resources available to the threat actor"),
        description: Optional[str] = Field(default=None, description="New description of the threat actor"),
        priority: Optional[int] = Field(default=None, description="New priority of the threat actor (1-10)"),
        relevance_score: Optional[float] = Field(default=None, description="New relevance score of the threat actor (0.0-1.0)"),
        is_relevant: Optional[bool] = Field(default=None, description="New relevance status of the threat actor"),
    ) -> str:
        """Update an existing threat actor.

        This tool updates an existing threat actor in the threat model.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the threat actor to update
            name: New name of the threat actor
            type: New type of the threat actor
            capability_level: New capability level of the threat actor
            motivations: New motivations of the threat actor
            resources: New resources available to the threat actor
            description: New description of the threat actor
            priority: New priority of the threat actor (1-10)
            relevance_score: New relevance score of the threat actor (0.0-1.0)
            is_relevant: New relevance status of the threat actor

        Returns:
            A confirmation message
        """
        return await update_threat_actor_impl(ctx, id, name, type, capability_level, motivations, resources, description, priority, relevance_score, is_relevant)

    @mcp.tool()
    async def list_threat_actors(
        ctx: Context,
        type: Optional[str] = Field(default=None, description="Optional type to filter threat actors"),
        relevant_only: bool = Field(default=False, description="Whether to only show relevant threat actors"),
    ) -> str:
        """List all threat actors.

        This tool lists all threat actors in the threat model.

        Args:
            ctx: MCP context for logging and error handling
            type: Optional type to filter threat actors
            relevant_only: Whether to only show relevant threat actors

        Returns:
            A markdown-formatted list of threat actors
        """
        return await list_threat_actors_impl(ctx, type, relevant_only)

    @mcp.tool()
    async def get_threat_actor(
        ctx: Context,
        id: str = Field(description="ID of the threat actor to retrieve"),
    ) -> str:
        """Get details about a specific threat actor.

        This tool retrieves details about a specific threat actor in the threat model.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the threat actor to retrieve

        Returns:
            A markdown-formatted description of the threat actor
        """
        return await get_threat_actor_impl(ctx, id)

    @mcp.tool()
    async def delete_threat_actor(
        ctx: Context,
        id: str = Field(description="ID of the threat actor to delete"),
    ) -> str:
        """Delete a threat actor.

        This tool deletes a threat actor from the threat model.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the threat actor to delete

        Returns:
            A confirmation message
        """
        return await delete_threat_actor_impl(ctx, id)

    @mcp.tool()
    async def set_threat_actor_relevance(
        ctx: Context,
        id: str = Field(description="ID of the threat actor"),
        is_relevant: bool = Field(description="Whether the threat actor is relevant to the system"),
    ) -> str:
        """Set the relevance of a threat actor.

        This tool sets whether a threat actor is relevant to the system.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the threat actor
            is_relevant: Whether the threat actor is relevant to the system

        Returns:
            A confirmation message
        """
        return await set_threat_actor_relevance_impl(ctx, id, is_relevant)

    @mcp.tool()
    async def set_threat_actor_priority(
        ctx: Context,
        id: str = Field(description="ID of the threat actor"),
        priority: int = Field(description="Priority of the threat actor (1-10)"),
    ) -> str:
        """Set the priority of a threat actor.

        This tool sets the priority of a threat actor in the threat model.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the threat actor
            priority: Priority of the threat actor (1-10)

        Returns:
            A confirmation message
        """
        return await set_threat_actor_priority_impl(ctx, id, priority)

    @mcp.tool()
    async def analyze_threat_actors(
        ctx: Context,
    ) -> str:
        """Analyze the threat actors.

        This tool analyzes the threat actors in the threat model and provides recommendations.

        Args:
            ctx: MCP context for logging and error handling

        Returns:
            A markdown-formatted analysis of the threat actors
        """
        return await analyze_threat_actors_impl(ctx)

    @mcp.tool()
    async def reset_threat_actors(
        ctx: Context,
    ) -> str:
        """Reset the threat actors to the default set.

        This tool resets the threat actors to the default set.

        Args:
            ctx: MCP context for logging and error handling

        Returns:
            A confirmation message
        """
        return await reset_threat_actors_impl(ctx)

    @mcp.tool()
    async def clear_threat_actors(
        ctx: Context,
    ) -> str:
        """Clear all threat actors.

        This tool clears all threat actors from the threat model.

        Args:
            ctx: MCP context for logging and error handling

        Returns:
            A confirmation message
        """
        return await clear_threat_actors_impl(ctx)
