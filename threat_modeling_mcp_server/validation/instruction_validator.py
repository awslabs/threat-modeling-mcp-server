"""Instruction Validator for the Threat Modeling MCP Server.

This module validates that all registered tools are documented in the instructions
and vice versa, ensuring consistency between the actual tools and documentation.
"""

import re
import inspect
from typing import Set, List, Tuple
from loguru import logger


def extract_tools_from_module(module) -> Set[str]:
    """Extract tool names from a module by inspecting the register_tools function.
    
    Args:
        module: The module to inspect
        
    Returns:
        Set of tool names found in the module
    """
    tools = set()
    
    if not hasattr(module, 'register_tools'):
        return tools
    
    # Get the source code of the register_tools function
    try:
        source = inspect.getsource(module.register_tools)
        
        # Find all @mcp.tool() decorators followed by function definitions
        tool_pattern = r'@mcp\.tool\(\)\s*async\s+def\s+(\w+)\s*\('
        matches = re.findall(tool_pattern, source)
        
        for match in matches:
            tools.add(match)
            
    except Exception as e:
        logger.warning(f"Could not extract tools from module {module.__name__}: {e}")
    
    return tools


def extract_tools_from_instructions(instructions: str) -> Set[str]:
    """Extract tool names from the instructions string.
    
    Args:
        instructions: The instructions string
        
    Returns:
        Set of tool names found in the instructions
    """
    tools = set()
    
    # Pattern to match tool names in markdown format: - `tool_name`: description
    tool_pattern = r'-\s*`([^`]+)`:'
    matches = re.findall(tool_pattern, instructions)
    
    for match in matches:
        tools.add(match)
    
    return tools


def validate_instructions_against_tools(instructions: str, modules: List) -> Tuple[bool, List[str]]:
    """Validate that instructions match registered tools.
    
    Args:
        instructions: The instructions string
        modules: List of tool modules
        
    Returns:
        Tuple of (is_valid, list_of_issues)
    """
    issues = []
    
    # Extract tools from all modules
    registered_tools = set()
    for module in modules:
        module_tools = extract_tools_from_module(module)
        registered_tools.update(module_tools)
        logger.debug(f"Module {module.__name__} has tools: {module_tools}")
    
    # Extract tools from instructions
    instruction_tools = extract_tools_from_instructions(instructions)
    
    logger.info(f"Found {len(registered_tools)} registered tools")
    logger.info(f"Found {len(instruction_tools)} tools in instructions")
    
    # Check for tools in code but not in instructions
    missing_in_instructions = registered_tools - instruction_tools
    if missing_in_instructions:
        issues.append(f"Tools registered but not documented in instructions: {sorted(missing_in_instructions)}")
    
    # Check for tools in instructions but not in code
    missing_in_code = instruction_tools - registered_tools
    if missing_in_code:
        issues.append(f"Tools documented in instructions but not registered: {sorted(missing_in_code)}")
    
    # Log detailed comparison
    logger.debug(f"Registered tools: {sorted(registered_tools)}")
    logger.debug(f"Instruction tools: {sorted(instruction_tools)}")
    
    is_valid = len(issues) == 0
    
    if is_valid:
        logger.info("✅ All tools are properly documented in instructions")
    else:
        logger.error("❌ Tool/instruction mismatch detected")
        for issue in issues:
            logger.error(f"  - {issue}")
    
    return is_valid, issues


def generate_tool_documentation(modules: List) -> str:
    """Generate documentation for all registered tools.
    
    Args:
        modules: List of tool modules
        
    Returns:
        Generated documentation string
    """
    registered_tools = {}
    
    # Extract tools and their docstrings from all modules
    for module in modules:
        if not hasattr(module, 'register_tools'):
            continue
            
        try:
            source = inspect.getsource(module.register_tools)
            
            # Find tool definitions with their docstrings
            # This is a simplified approach - in practice, you might want to use AST parsing
            tool_pattern = r'@mcp\.tool\(\)\s*async\s+def\s+(\w+)\s*\([^)]*\)\s*->\s*str:\s*"""([^"]*?)"""'
            matches = re.findall(tool_pattern, source, re.DOTALL)
            
            for tool_name, docstring in matches:
                # Extract the first line of the docstring as description
                description = docstring.strip().split('\n')[0]
                registered_tools[tool_name] = description
                
        except Exception as e:
            logger.warning(f"Could not extract tool documentation from module {module.__name__}: {e}")
    
    # Generate markdown documentation
    doc_lines = []
    current_category = ""
    
    # Group tools by category (based on module name patterns)
    categories = {
        'threat_model_plan': 'Threat Modeling Plan',
        'assumption_manager': 'Assumption Management',
        'business_context': 'Business Context Analysis',
        'architecture_analyzer': 'Architecture Analysis',
        'threat_actor_analyzer': 'Threat Actor Analysis',
        'trust_boundary_analyzer': 'Trust Boundary Analysis',
        'trust_boundary_detector': 'Trust Boundary Detection',
        'asset_flow_analyzer': 'Asset Flow Analysis',
        'threat_generator': 'Threat Generator',
        'data_model_types': 'Data Model Types',
    }
    
    for module in modules:
        module_name = module.__name__.split('.')[-1]
        category = categories.get(module_name, module_name.replace('_', ' ').title())
        
        module_tools = extract_tools_from_module(module)
        if module_tools:
            doc_lines.append(f"### {category}")
            for tool in sorted(module_tools):
                description = registered_tools.get(tool, "Tool description")
                doc_lines.append(f"- `{tool}`: {description}")
            doc_lines.append("")
    
    return "\n".join(doc_lines)
