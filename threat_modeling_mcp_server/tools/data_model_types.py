"""Data model types functionality for the Threat Modeling MCP Server."""

import inspect
from enum import Enum
from loguru import logger
from mcp.server.fastmcp import Context
from pydantic import Field
from typing import Dict, Optional, Type

# Import all modules that contain Enum classes
import threat_modeling_mcp_server.models.architecture_models as architecture_models
import threat_modeling_mcp_server.models.asset_flow_models as asset_flow_models
import threat_modeling_mcp_server.models.threat_actor_models as threat_actor_models
import threat_modeling_mcp_server.models.trust_boundary_models as trust_boundary_models
import threat_modeling_mcp_server.models.threat_models as threat_models
import threat_modeling_mcp_server.models.models as models
import threat_modeling_mcp_server.models.software_models as software_models
import threat_modeling_mcp_server.models.data_classification_models as data_classification_models
import threat_modeling_mcp_server.models.user_models as user_models
import threat_modeling_mcp_server.models.nfr_models as nfr_models


def discover_enum_classes() -> Dict[str, Type[Enum]]:
    """Dynamically discover all Enum classes in the imported modules.
    
    Returns:
        A dictionary mapping enum class names to enum classes
    """
    modules = [
        architecture_models,
        asset_flow_models,
        threat_actor_models,
        trust_boundary_models,
        threat_models,
        models,
        software_models,
        data_classification_models,
        user_models,
        nfr_models,
    ]
    
    enum_classes = {}
    
    for module in modules:
        # Get all members of the module
        for name, obj in inspect.getmembers(module):
            # Check if it's a class and a subclass of Enum
            if inspect.isclass(obj) and issubclass(obj, Enum) and obj != Enum:
                enum_classes[name] = obj
    
    return enum_classes


# Dynamically discover all Enum classes
DATA_MODELS = discover_enum_classes()


async def inspect_data_models_impl(
    ctx: Context,
    model_name: Optional[str] = None,
) -> str:
    """List available enum models or inspect one model's accepted values.

    Args:
        ctx: MCP context for logging and error handling
        model_name: Optional enum model name to inspect

    Returns:
        A markdown-formatted model list or accepted-value list
    """
    if model_name is None:
        logger.debug('Listing all data models')
        result = "# Available Data Models\n\n"
        for available_model in sorted(DATA_MODELS):
            result += f"- {available_model}\n"
        return result

    logger.debug(f'Getting types for data model: {model_name}')

    if model_name not in DATA_MODELS:
        available_models = ", ".join(sorted(DATA_MODELS.keys()))
        return f"Data model '{model_name}' not found. Available models: {available_models}"

    model_enum = DATA_MODELS[model_name]

    result = f"# Available Types for {model_name}\n\n"
    result += "**Important**: Use the VALUE (not the name) when calling tools.\n\n"

    for enum_value in model_enum:
        result += f"- **Use**: `\"{enum_value.value}\"` (Name: {enum_value.name})\n"

    result += "\n**Example**: For authorization_method, use `\"Policy-based\"` not `\"POLICY_BASED\"`\n"

    return result


# Register tools with the MCP server
def register_tools(mcp):
    """Register data model types tools with the MCP server.
    
    Args:
        mcp: The MCP server instance
    """
    @mcp.tool()
    async def inspect_data_models(
        ctx: Context,
        model_name: Optional[str] = Field(
            default=None,
            description="Enum model to inspect; omit to list all available models",
        ),
    ) -> str:
        """List enum models or inspect the accepted values for one model."""
        return await inspect_data_models_impl(ctx, model_name)
