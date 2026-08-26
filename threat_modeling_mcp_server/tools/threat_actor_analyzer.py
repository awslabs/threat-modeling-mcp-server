"""Threat Actor Analysis functionality for the Cline Threat Modeling MCP Server."""

from typing import Dict, List, Optional
from loguru import logger
from mcp.server.fastmcp import Context

from threat_modeling_mcp_server.models.threat_actor_models import (
    ThreatActor, ThreatActorLibrary, ThreatActorType,
    Motivation, SophisticationTier,
)
from threat_modeling_mcp_server.utils.id_utils import next_id
from threat_modeling_mcp_server.validation.enum_validator import validate_enum_with_enhanced_error


threat_actors: Dict[str, ThreatActor] = {}


def initialize_threat_actors():
    """Initialize the threat actor library with default actors."""
    global threat_actors
    if not threat_actors:
        threat_actors = ThreatActorLibrary.get_default_actors()


def _format_taxonomy_dimensions(actor) -> str:
    """Render the Threat Actor Taxonomy dimensions 2, 4, 6 and 7, if set."""
    lines = ""
    if actor.relationship_to_target:
        lines += f"**Relationship to Target:** {actor.relationship_to_target.value}\n\n"
    if actor.sophistication_tier:
        lines += f"**Sophistication Tier:** {actor.sophistication_tier.value}\n\n"
    if actor.state_nexus:
        lines += f"**State Nexus:** {actor.state_nexus.value}\n\n"
    if actor.targeting_specificity:
        lines += f"**Targeting Specificity:** {actor.targeting_specificity.value}\n\n"
    return lines


async def add_threat_actor_impl(
    ctx: Context,
    name: str,
    type: str,
    sophistication_tier: str,
    motivations: List[str],
    resources: str,
    relationship_to_target: Optional[str] = None,
    state_nexus: Optional[str] = None,
    targeting_specificity: Optional[str] = None,
    description: Optional[str] = None,
    priority: int = 0,
    is_relevant: bool = True,
) -> str:
    """Add a new threat actor.

    Args:
        ctx: MCP context for logging and error handling
        name: Name of the threat actor
        type: Type of the threat actor
        sophistication_tier: Sophistication tier (Tier 1 - Opportunistic / script kiddie .. Tier 5 - Nation-state APT / elite)
        motivations: Motivations of the threat actor
        resources: Resources available to the threat actor (Individual, Club / small group, Contest / crowd, Team, Organization, Government)
        relationship_to_target: External, Internal, or Partner / third-party
        state_nexus: None, State-aligned, State-sponsored, or State-executed
        targeting_specificity: Opportunistic, Sector-focused, or Targeted
        description: Description of the threat actor
        priority: Priority of the threat actor (1-10)
        is_relevant: Whether the threat actor is relevant to the system

    Returns:
        A confirmation message with the threat actor ID
    """
    logger.debug(f'Adding threat actor: {name}')

    # Initialize threat actors if not already done
    initialize_threat_actors()

    # Generate a unique ID
    threat_actor_id = next_id(threat_actors, "TA")

    # Create the threat actor
    # Pass the raw strings: ThreatActor's field validators route every enum
    # through validate_enum_with_enhanced_error, which matches case-insensitively
    # and lists the valid options on failure. Pre-converting here would bypass
    # both.
    threat_actor = ThreatActor(
        id=threat_actor_id,
        name=name,
        type=type,
        sophistication_tier=sophistication_tier,
        motivations=motivations,
        resources=resources,
        relationship_to_target=relationship_to_target,
        state_nexus=state_nexus,
        targeting_specificity=targeting_specificity,
        description=description,
        priority=priority,
        is_relevant=is_relevant,
        # The agent asked for this actor, so it is by definition reviewed.
        reviewed=True
    )

    # Store the threat actor
    threat_actors[threat_actor_id] = threat_actor

    return f"Threat actor added with ID: {threat_actor_id}"


async def update_threat_actor_impl(
    ctx: Context,
    id: str,
    name: Optional[str] = None,
    type: Optional[str] = None,
    sophistication_tier: Optional[str] = None,
    motivations: Optional[List[str]] = None,
    resources: Optional[str] = None,
    relationship_to_target: Optional[str] = None,
    state_nexus: Optional[str] = None,
    targeting_specificity: Optional[str] = None,
    description: Optional[str] = None,
    priority: Optional[int] = None,
    is_relevant: Optional[bool] = None,
) -> str:
    """Update an existing threat actor.

    Args:
        ctx: MCP context for logging and error handling
        id: ID of the threat actor to update
        name: New name of the threat actor
        type: New type of the threat actor
        sophistication_tier: New sophistication tier of the threat actor
        motivations: New motivations of the threat actor
        resources: New resources available to the threat actor
        description: New description of the threat actor
        priority: New priority of the threat actor (1-10)
        is_relevant: New relevance status of the threat actor

    Returns:
        A confirmation message
    """
    logger.debug(f'Updating threat actor: {id}')

    # Initialize threat actors if not already done
    initialize_threat_actors()

    if id not in threat_actors:
        return f"Threat actor with ID {id} not found."

    updates = {}
    if name is not None:
        updates["name"] = name

    if type is not None:
        updates["type"] = type

    if sophistication_tier is not None:
        updates["sophistication_tier"] = sophistication_tier

    if motivations is not None:
        updates["motivations"] = motivations

    if resources is not None:
        updates["resources"] = resources
    if relationship_to_target is not None:
        updates["relationship_to_target"] = relationship_to_target
    if state_nexus is not None:
        updates["state_nexus"] = state_nexus
    if targeting_specificity is not None:
        updates["targeting_specificity"] = targeting_specificity

    if description is not None:
        updates["description"] = description

    if priority is not None:
        updates["priority"] = priority

    if is_relevant is not None:
        updates["is_relevant"] = is_relevant

    updates["reviewed"] = True

    candidate_values = threat_actors[id].model_dump()
    candidate_values.update(updates)
    threat_actors[id] = ThreatActor.model_validate(candidate_values)

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
        actor_type = validate_enum_with_enhanced_error(
            type, ThreatActorType, "type",
        )
        filtered_actors = [a for a in filtered_actors if a.type == actor_type]

    if relevant_only:
        filtered_actors = [a for a in filtered_actors if a.is_relevant]

    if not filtered_actors:
        return "No threat actors found with the specified criteria."

    # Sort by priority (if set)
    sorted_actors = sorted(filtered_actors, key=lambda a: a.priority if a.priority > 0 else 999)

    result = "# Threat Actors\n\n"

    for actor in sorted_actors:
        result += f"## {actor.id}: {actor.name}\n\n"
        result += f"**Type:** {actor.type.value}\n\n"

        result += "**Motivations:**\n\n"
        for motivation in actor.motivations:
            result += f"- {motivation.value}\n"
        result += "\n"

        result += f"**Resources:** {actor.resources.value}\n\n"
        result += _format_taxonomy_dimensions(actor)

        if actor.description:
            result += f"**Description:** {actor.description}\n\n"

        if actor.priority > 0:
            result += f"**Priority:** {actor.priority}\n\n"

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

    result += "**Motivations:**\n\n"
    for motivation in actor.motivations:
        result += f"- {motivation.value}\n"
    result += "\n"

    result += f"**Resources:** {actor.resources.value}\n\n"
    result += _format_taxonomy_dimensions(actor)

    if actor.description:
        result += f"**Description:** {actor.description}\n\n"

    if actor.priority > 0:
        result += f"**Priority:** {actor.priority}\n\n"

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

    # Count by sophistication tier
    tier_counts = {}
    for actor in relevant_actors:
        tier = actor.sophistication_tier.value
        tier_counts[tier] = tier_counts.get(tier, 0) + 1

    result += "### Sophistication Tiers\n\n"
    for tier, count in sorted(tier_counts.items()):
        result += f"- **{tier}:** {count}\n"

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
            result += f"**Primary Motivations:** {', '.join([m.value for m in actor.motivations])}\n\n"
            result += f"**Resources:** {actor.resources.value}\n\n"
            result += _format_taxonomy_dimensions(actor)

            if actor.description:
                result += f"**Description:** {actor.description}\n\n"

            result += "---\n\n"

    # Unprioritized actors
    unprioritized = [a for a in sorted_actors if a.priority == 0]
    if unprioritized:
        result += "## Unprioritized Threat Actors\n\n"

        for actor in unprioritized:
            result += f"### {actor.name} ({actor.id})\n\n"
            result += f"**Type:** {actor.type.value}\n\n"
            result += f"**Primary Motivations:** {', '.join(m.value for m in actor.motivations)}\n\n"
            result += f"**Resources:** {actor.resources.value}\n\n"
            result += _format_taxonomy_dimensions(actor)
            if actor.description:
                result += f"**Description:** {actor.description}\n\n"
            result += "---\n\n"

        result += "\n"

    # Recommendations
    result += "## Recommendations\n\n"

    # Check for advanced actors
    advanced_actors = [
        a for a in relevant_actors
        if a.sophistication_tier in (
            SophisticationTier.TIER_4_STATE_NEXUS,
            SophisticationTier.TIER_5_ELITE_APT,
        )
    ]
    if advanced_actors:
        result += "- **Advanced Actors:** Pay special attention to threat actors at Tier 4 or Tier 5 sophistication, as they pose the greatest risk.\n"

    # Check for financially motivated actors
    financial_motivation = [a for a in relevant_actors if Motivation.FINANCIAL_GAIN in a.motivations]
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
    threat_actors = ThreatActorLibrary.get_default_actors()

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
