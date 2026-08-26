"""Threat Modeling MCP Server implementation.

This module provides the core MCP server for threat modeling.
It registers all threat modeling tools and runs the server.
"""

import sys
import os
from loguru import logger
from mcp.server.fastmcp import FastMCP

# Import modules
import threat_modeling_mcp_server.tools.system_context as system_context
import threat_modeling_mcp_server.tools.domain_managers as domain_managers
import threat_modeling_mcp_server.tools.data_model_types as data_model_types
import threat_modeling_mcp_server.tools.code_security_validator as code_security_validator
import threat_modeling_mcp_server.tools.step_orchestrator as step_orchestrator
from threat_modeling_mcp_server.validation.instruction_validator import validate_instructions_against_tools, generate_tool_documentation

# List of all tool modules for validation
TOOL_MODULES = [
    step_orchestrator,
    system_context,
    domain_managers,
    data_model_types,
    code_security_validator,
]


# Set up logging
logger.remove()
logger.add(sys.stderr, level=os.getenv('FASTMCP_LOG_LEVEL', 'WARNING'))

# Server instructions
SERVER_INSTRUCTIONS = """
    # Threat Modeling MCP Server

    This server provides tools for threat modeling.

    ## Usage

    ### Workflow
    - `manage_workflow`: Describe, plan, get phase guidance/status/progress, set the project directory, and advance phases
    - `export_threat_model`: Export Threat Composer JSON and Markdown, with a timestamped filename when no path is supplied

    ### System Context
    - `manage_system_context`: Describe, plan, set, get/list, add/update/delete, validate, and clear business context plus software, data asset, user persona, and NFR profiles

    ### Domain Managers
    - `manage_assumptions`: Describe, add, update, list, get, and delete assumptions
    - `manage_architecture`: Manage component/data-store nodes, their connections, architecture planning, and clearing
    - `manage_threat_actors`: Manage, assess, analyze, reset, and clear threat actors
    - `manage_trust_boundaries`: Manage zones, crossing points, boundaries, relationships, plans, and clearing
    - `manage_asset_flows`: Manage assets and flows
    - `manage_threats`: Manage threats, mitigations, links, and residual-risk assessments
    
    ### Data Model Types
    - `inspect_data_models`: List available enum models or inspect one model's accepted values
    
    ### Code Validation
    - `manage_code_validation`: Describe, record, inspect, validate, report, or clear evidence-based Phase 7.5 findings
    
    """

# Server dependencies
SERVER_DEPENDENCIES = ['pydantic']


def validate_server_instructions(mcp: FastMCP) -> bool:
    """Validate that all tools are properly documented in instructions.
    
    Args:
        mcp: The MCP server instance to validate.
        
    Returns:
        True if validation passed, False otherwise.
    """
    instructions = mcp.instructions
    is_valid, issues = validate_instructions_against_tools(instructions, TOOL_MODULES)
    
    if not is_valid:
        logger.error("Tool/instruction validation failed!")
        for issue in issues:
            logger.error(f"  {issue}")
        
        # Optionally generate updated documentation
        logger.info("Generating updated tool documentation...")
        updated_docs = generate_tool_documentation(TOOL_MODULES)
        logger.info("Updated documentation:")
        logger.info(updated_docs)
        
        logger.warning("Continuing server startup despite validation issues...")
        return False
    
    return True


# Create MCP server instance
mcp: FastMCP = FastMCP(
    'threat-modeling-mcp-server',
    instructions=SERVER_INSTRUCTIONS,
    dependencies=SERVER_DEPENDENCIES,
)

# Register all tools from modules
for module in TOOL_MODULES:
    module.register_tools(mcp)


def main():
    """Run the threat modeling MCP server."""
    logger.info('Starting Threat Modeling MCP Server')
    
    # Validate instructions
    validate_server_instructions(mcp)
    
    mcp.run(transport='stdio')


if __name__ == '__main__':
    main()
