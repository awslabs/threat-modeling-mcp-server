"""Assumption Manager functionality for the Cline Threat Modeling MCP Server."""

from typing import Dict, List, Optional, Any
from loguru import logger
from mcp.server.mcpserver import Context
from pydantic import Field

from threat_modeling_mcp_server.models.models import Assumption
from threat_modeling_mcp_server.utils.batch_utils import batch_add, batch_update, batch_delete


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
    assumption_id = f"A{len(assumptions) + 1:03d}"
    
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


# Register tools with the MCP server
def register_tools(mcp):
    """Register assumption management tools with the MCP server.
    
    Args:
        mcp: The MCP server instance
    """
    @mcp.tool()
    async def add_assumption(
        ctx: Context,
        description: str = Field(default=None, description="Description of the assumption (required for single item mode)"),
        category: str = Field(default=None, description="Category of the assumption (e.g., 'Network', 'Authentication', 'AWS Services') (required for single item mode)"),
        impact: str = Field(default=None, description="Impact of the assumption on the threat model (required for single item mode)"),
        rationale: str = Field(default=None, description="Rationale for making this assumption (required for single item mode)"),
        items: Optional[List[Dict[str, Any]]] = Field(default=None, description="Optional list of assumptions to add in batch. Each dict should contain 'description', 'category', 'impact', 'rationale'. When provided, individual parameters are ignored."),
    ) -> str:
        """Add a new assumption to the threat model. Supports batch operations via the 'items' parameter.

        Assumptions are statements that we accept as true without requiring further validation.
        They help scope the threat model by establishing boundaries and constraints.
        For single item: provide description, category, impact, rationale directly.
        For batch: provide a list of assumption dicts in the 'items' parameter.

        Args:
            ctx: MCP context for logging and error handling
            description: Description of the assumption (required for single item mode)
            category: Category of the assumption (required for single item mode)
            impact: Impact of the assumption on the threat model (required for single item mode)
            rationale: Rationale for making this assumption (required for single item mode)
            items: Optional list of assumption dicts for batch operation

        Returns:
            A confirmation message with the assumption ID(s)
        """
        return await batch_add(
            ctx, items,
            {"description": description, "category": category, "impact": impact, "rationale": rationale},
            add_assumption_impl, "assumption"
        )

    @mcp.tool()
    async def list_assumptions(
        ctx: Context,
        category: Optional[str] = Field(default=None, description="Optional category filter"),
    ) -> str:
        """List all current assumptions in the threat model.

        Args:
            ctx: MCP context for logging and error handling
            category: Optional category to filter assumptions

        Returns:
            A markdown-formatted list of assumptions
        """
        return await list_assumptions_impl(ctx, category)

    @mcp.tool()
    async def get_assumption(
        ctx: Context,
        id: str = Field(description="ID of the assumption to retrieve"),
    ) -> str:
        """Get details about a specific assumption.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the assumption to retrieve

        Returns:
            A markdown-formatted description of the assumption
        """
        return await get_assumption_impl(ctx, id)

    @mcp.tool()
    async def update_assumption(
        ctx: Context,
        id: str = Field(default=None, description="ID of the assumption to update (required for single item mode)"),
        description: Optional[str] = Field(default=None, description="New description of the assumption"),
        category: Optional[str] = Field(default=None, description="New category of the assumption"),
        impact: Optional[str] = Field(default=None, description="New impact of the assumption"),
        rationale: Optional[str] = Field(default=None, description="New rationale for the assumption"),
        items: Optional[List[Dict[str, Any]]] = Field(default=None, description="Optional list of assumptions to update in batch. Each dict must contain 'id' and any fields to update. When provided, individual parameters are ignored."),
    ) -> str:
        """Update an existing assumption. Supports batch operations via the 'items' parameter.

        For single item: provide id and fields to update directly.
        For batch: provide a list of assumption dicts in the 'items' parameter (each must include 'id').

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the assumption to update (required for single item mode)
            description: New description of the assumption
            category: New category of the assumption
            impact: New impact of the assumption
            rationale: New rationale for the assumption
            items: Optional list of assumption dicts for batch update

        Returns:
            A confirmation message
        """
        return await batch_update(
            ctx, items,
            {"id": id, "description": description, "category": category, "impact": impact, "rationale": rationale},
            update_assumption_impl, "assumption"
        )

    @mcp.tool()
    async def delete_assumption(
        ctx: Context,
        id: Optional[str] = Field(default=None, description="ID of the assumption to delete (required for single item mode)"),
        ids: Optional[List[str]] = Field(default=None, description="Optional list of assumption IDs to delete in batch. When provided, the 'id' parameter is ignored."),
    ) -> str:
        """Delete an assumption from the threat model. Supports batch operations via the 'ids' parameter.

        For single item: provide the id directly.
        For batch: provide a list of IDs in the 'ids' parameter.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the assumption to delete (required for single item mode)
            ids: Optional list of assumption IDs for batch deletion

        Returns:
            A confirmation message
        """
        return await batch_delete(ctx, ids, id, delete_assumption_impl, "assumption")
