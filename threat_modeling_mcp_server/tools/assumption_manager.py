"""Assumption Manager functionality for the Cline Threat Modeling MCP Server."""

from typing import Dict, Optional
from loguru import logger
from mcp.server.fastmcp import Context

from threat_modeling_mcp_server.models.models import Assumption
from threat_modeling_mcp_server.utils.id_utils import next_id


# In-memory storage for assumptions
assumptions: Dict[str, Assumption] = {}


async def add_assumption_impl(
    ctx: Context,
    description: str,
    category: str,
    impact: str,
    rationale: str,
) -> str:
    """Add a new assumption to the threat model.

    Args:
        ctx: MCP context for logging and error handling
        description: Description of the assumption
        category: Category of the assumption (e.g., 'Network', 'Authentication', 'AWS Services')
        impact: Impact of the assumption on the threat model
        rationale: Rationale for making this assumption

    Returns:
        A confirmation message with the assumption ID
    """
    logger.debug(f'Adding assumption: {description}')
    
    # Generate a simple ID based on the number of assumptions
    assumption_id = next_id(assumptions, "A")
    
    # Create and store the assumption
    assumption = Assumption(
        id=assumption_id,
        description=description,
        category=category,
        impact=impact,
        rationale=rationale
    )
    
    assumptions[assumption_id] = assumption
    
    return f"Assumption added with ID: {assumption_id}"


async def list_assumptions_impl(
    ctx: Context,
    category: Optional[str] = None,
) -> str:
    """List all current assumptions in the threat model.

    Args:
        ctx: MCP context for logging and error handling
        category: Optional category to filter assumptions

    Returns:
        A markdown-formatted list of assumptions
    """
    logger.debug('Listing assumptions')
    
    if not assumptions:
        return "No assumptions have been added yet."
    
    filtered_assumptions = assumptions.values()
    if category:
        filtered_assumptions = [a for a in filtered_assumptions if a.category.lower() == category.lower()]
    
    if not filtered_assumptions:
        return f"No assumptions found in category: {category}"
    
    result = "# Threat Model Assumptions\n\n"
    
    for assumption in filtered_assumptions:
        result += f"## {assumption.id}: {assumption.description}\n\n"
        result += f"**Category:** {assumption.category}\n\n"
        result += f"**Impact:** {assumption.impact}\n\n"
        result += f"**Rationale:** {assumption.rationale}\n\n"
        result += "---\n\n"
    
    return result


async def get_assumption_impl(
    ctx: Context,
    id: str,
) -> str:
    """Get details about a specific assumption.

    Args:
        ctx: MCP context for logging and error handling
        id: ID of the assumption to retrieve

    Returns:
        A markdown-formatted description of the assumption
    """
    logger.debug(f'Getting assumption: {id}')
    
    if id not in assumptions:
        return f"Assumption with ID {id} not found."
    
    assumption = assumptions[id]
    
    result = f"# Assumption {assumption.id}\n\n"
    result += f"**Description:** {assumption.description}\n\n"
    result += f"**Category:** {assumption.category}\n\n"
    result += f"**Impact:** {assumption.impact}\n\n"
    result += f"**Rationale:** {assumption.rationale}\n\n"
    
    return result


async def update_assumption_impl(
    ctx: Context,
    id: str,
    description: Optional[str] = None,
    category: Optional[str] = None,
    impact: Optional[str] = None,
    rationale: Optional[str] = None,
) -> str:
    """Update an existing assumption.

    Args:
        ctx: MCP context for logging and error handling
        id: ID of the assumption to update
        description: New description of the assumption
        category: New category of the assumption
        impact: New impact of the assumption
        rationale: New rationale for the assumption

    Returns:
        A confirmation message
    """
    logger.debug(f'Updating assumption: {id}')
    
    if id not in assumptions:
        return f"Assumption with ID {id} not found."
    
    assumption = assumptions[id]
    
    # Update only the provided fields
    if description is not None:
        assumption.description = description
    if category is not None:
        assumption.category = category
    if impact is not None:
        assumption.impact = impact
    if rationale is not None:
        assumption.rationale = rationale
    
    # Store the updated assumption
    assumptions[id] = assumption
    
    return f"Assumption {id} updated successfully."


async def delete_assumption_impl(
    ctx: Context,
    id: str,
) -> str:
    """Delete an assumption from the threat model.

    Args:
        ctx: MCP context for logging and error handling
        id: ID of the assumption to delete

    Returns:
        A confirmation message
    """
    logger.debug(f'Deleting assumption: {id}')
    
    if id not in assumptions:
        return f"Assumption with ID {id} not found."
    
    del assumptions[id]
    
    return f"Assumption {id} deleted successfully."
