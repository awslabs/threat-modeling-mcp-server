"""Threat Modeling MCP Server implementation.

This module provides the core MCP server for threat modeling.
It registers all threat modeling tools and runs the server.
"""

import sys
import os
from loguru import logger
from mcp.server.fastmcp import FastMCP

# Import modules
import threat_modeling_mcp_server.tools.threat_model_plan as threat_model_plan
import threat_modeling_mcp_server.tools.assumption_manager as assumption_manager
import threat_modeling_mcp_server.tools.business_context as business_context
import threat_modeling_mcp_server.tools.architecture_analyzer as architecture_analyzer
import threat_modeling_mcp_server.tools.threat_actor_analyzer as threat_actor_analyzer
import threat_modeling_mcp_server.tools.trust_boundary_analyzer as trust_boundary_analyzer
import threat_modeling_mcp_server.tools.trust_boundary_detector as trust_boundary_detector
import threat_modeling_mcp_server.tools.asset_flow_analyzer as asset_flow_analyzer
import threat_modeling_mcp_server.tools.threat_generator as threat_generator
import threat_modeling_mcp_server.tools.data_model_types as data_model_types
import threat_modeling_mcp_server.tools.code_security_validator as code_security_validator
import threat_modeling_mcp_server.tools.threat_model_validator as threat_model_validator
import threat_modeling_mcp_server.tools.step_orchestrator as step_orchestrator
from threat_modeling_mcp_server.validation.instruction_validator import validate_instructions_against_tools, generate_tool_documentation

# List of all tool modules for validation
TOOL_MODULES = [
    threat_model_plan,
    assumption_manager,
    business_context,
    architecture_analyzer,
    threat_actor_analyzer,
    trust_boundary_analyzer,
    trust_boundary_detector,
    asset_flow_analyzer,
    threat_generator,
    data_model_types,
    code_security_validator,
    threat_model_validator,
    step_orchestrator,
]


# Set up logging
logger.remove()
logger.add(sys.stderr, level=os.getenv('FASTMCP_LOG_LEVEL', 'WARNING'))

# Server instructions
SERVER_INSTRUCTIONS = """
    # Threat Modeling MCP Server

    This server provides tools for threat modeling.

    ## Usage

    ### Threat Modeling Plan
    - `get_threat_modeling_plan`: Get a comprehensive threat modeling plan

    ### Assumption Management
    - `add_assumption`: Add a new assumption to the threat model
    - `list_assumptions`: List all current assumptions
    - `get_assumption`: Get details about a specific assumption
    - `update_assumption`: Update an existing assumption
    - `delete_assumption`: Remove an assumption

    ### Business Context Analysis
    - `set_business_context`: Set business context description and features in one call
    - `get_business_context`: Get the current business context
    - `clear_business_context`: Clear the business context
    - `validate_business_context_completeness`: Validate that all required business context features are set
    - `get_business_context_features`: Get all business context features with descriptions
    - `get_business_context_analysis_plan`: Get a plan to analyze business context using AI
    - `get_data_model_types`: Get available types for any data model (replaces individual option tools)
    
    ### Architecture Analysis
    - `add_component`: Add a new component to the architecture
    - `update_component`: Update an existing component
    - `list_components`: List all components
    - `delete_component`: Delete a component
    - `add_connection`: Add a new connection between components
    - `update_connection`: Update an existing connection
    - `list_connections`: List all connections
    - `delete_connection`: Delete a connection
    - `add_data_store`: Add a new data store
    - `update_data_store`: Update an existing data store
    - `list_data_stores`: List all data stores
    - `delete_data_store`: Delete a data store
    - `get_architecture_analysis_plan`: Get a plan to analyze the architecture
    - `clear_architecture`: Clear the architecture
    
    ### Threat Actor Analysis
    - `add_threat_actor`: Add a new threat actor
    - `update_threat_actor`: Update an existing threat actor
    - `list_threat_actors`: List all threat actors
    - `get_threat_actor`: Get details about a specific threat actor
    - `delete_threat_actor`: Delete a threat actor
    - `set_threat_actor_relevance`: Set whether a threat actor is relevant
    - `set_threat_actor_priority`: Set the priority of a threat actor
    - `analyze_threat_actors`: Analyze the threat actors
    - `reset_threat_actors`: Reset to default threat actors
    - `clear_threat_actors`: Clear all threat actors
    
    ### Trust Boundary Analysis
    - `add_trust_zone`: Add a new trust zone
    - `update_trust_zone`: Update an existing trust zone
    - `list_trust_zones`: List all trust zones
    - `get_trust_zone`: Get details about a specific trust zone
    - `delete_trust_zone`: Delete a trust zone
    - `add_component_to_zone`: Add a component to a trust zone
    - `remove_component_from_zone`: Remove a component from a trust zone
    - `add_crossing_point`: Add a new crossing point between trust zones
    - `update_crossing_point`: Update an existing crossing point
    - `list_crossing_points`: List all crossing points
    - `get_crossing_point`: Get details about a specific crossing point
    - `delete_crossing_point`: Delete a crossing point
    - `add_conn_to_crossing`: Add a connection to a crossing point
    - `remove_conn_from_crossing`: Remove a connection from a crossing point
    - `add_trust_boundary`: Add a new trust boundary
    - `update_trust_boundary`: Update an existing trust boundary
    - `list_trust_boundaries`: List all trust boundaries
    - `get_trust_boundary`: Get details about a specific trust boundary
    - `delete_trust_boundary`: Delete a trust boundary
    - `get_trust_boundary_analysis_plan`: Get a plan to analyze trust boundaries for security concerns
    - `clear_trust_boundaries`: Clear all trust boundaries
    
    ### Trust Boundary Detection
    - `get_trust_boundary_detection_plan`: Get a plan to detect trust boundaries using AI analysis
    
    ### Asset Flow Analysis
    - `add_asset`: Add a new asset to the system
    - `update_asset`: Update an existing asset
    - `list_assets`: List all assets
    - `get_asset`: Get details about a specific asset
    - `delete_asset`: Delete an asset
    - `add_flow`: Add a new asset flow
    - `update_flow`: Update an existing asset flow
    - `list_flows`: List all asset flows
    - `get_flow`: Get details about a specific asset flow
    - `delete_flow`: Delete an asset flow
    - `get_asset_flow_analysis_plan`: Get a plan to analyze asset flows for security concerns
    - `clear_asset_flows`: Clear all assets and flows
    - `reset_asset_flows`: Reset assets and flows to the default set
    
    ### Threat Generator
    - `add_threat`: Add a new threat to the model
    - `update_threat`: Update an existing threat
    - `list_threats`: List all threats in the model
    - `get_threat`: Get details about a specific threat
    - `delete_threat`: Delete a threat from the model
    
    ### Mitigation Management
    - `add_mitigation`: Add a new mitigation to the model
    - `list_mitigations`: List all mitigations in the model
    - `get_mitigation`: Get details about a specific mitigation
    - `update_mitigation`: Update an existing mitigation
    - `delete_mitigation`: Delete a mitigation from the model
    - `link_mitigation_to_threat`: Link a mitigation to a threat
    - `unlink_mitigation_from_threat`: Unlink a mitigation from a threat
    - `export_comprehensive_threat_model`: Export comprehensive threat model with all global variables to both JSON and Markdown formats
    
    ### Data Model Types
    - `get_data_model_types`: Get available types for a data model
    - `list_data_models`: List all available data models
    
    ### Code Security Validation
    - `validate_security_controls`: Validate security controls in code
    - `validate_threat_remediation`: Validate if threats are remediated in code
    - `generate_remediation_report`: Generate a comprehensive remediation report
    
    ### Threat Model Validation
    - `validate_threat_model_against_code`: Validate the threat model against the actual codebase
    - `export_threat_model_with_remediation_status`: Export the threat model with remediation status
    
    ### Step Orchestrator
    - `get_phase_1_guidance`: Get detailed guidance for Phase 1: Business Context Analysis
    - `get_phase_2_guidance`: Get detailed guidance for Phase 2: Architecture Analysis
    - `get_phase_3_guidance`: Get detailed guidance for Phase 3: Threat Actor Analysis
    - `get_phase_4_guidance`: Get detailed guidance for Phase 4: Trust Boundary Analysis
    - `get_phase_5_guidance`: Get detailed guidance for Phase 5: Asset Flow Analysis
    - `get_phase_6_guidance`: Get detailed guidance for Phase 6: Threat Identification
    - `get_phase_7_guidance`: Get detailed guidance for Phase 7: Mitigation Planning
    - `get_phase_7_5_guidance`: Get detailed guidance for Phase 7.5: Code Validation Analysis
    - `get_phase_8_guidance`: Get detailed guidance for Phase 8: Residual Risk Analysis
    - `get_phase_9_guidance`: Get detailed guidance for Phase 9: Output Generation and Documentation
    - `execute_code_validation_step`: Execute the complete code validation step (Phase 7.5) automatically
    - `execute_final_export_step`: Execute the complete final export step (Phase 9) automatically
    - `get_current_phase_status`: Get the current phase status and completion progress
    - `follow_threat_modeling_plan`: Get step-by-step guidance for the current threat modeling phase
    - `advance_phase`: Advance to the next phase of the threat modeling process
    - `get_threat_model_progress`: Get the current progress of the threat modeling process
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
