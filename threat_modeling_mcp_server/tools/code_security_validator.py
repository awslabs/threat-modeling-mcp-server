"""Code Security Validator for the Threat Modeling MCP Server.

This module analyzes code to detect existing security controls and maps them to
identified threats and mitigations, providing validation of which security
controls are already implemented using LLM-based analysis.
"""

import os
import json
from typing import Dict, List, Set, Optional, Tuple, Any
from loguru import logger
from mcp.server.fastmcp import Context

from threat_modeling_mcp_server.models.threat_models import Threat, Mitigation
from threat_modeling_mcp_server.models.code_validation_models import (
    SecurityControl, 
    CodeValidationResult,
    RemediationStatus,
    SecurityControlDetection
)


# LLM-based security analysis prompts and structures
SECURITY_ANALYSIS_PROMPT = """
You are a security expert analyzing code for security controls and vulnerabilities.

Analyze the following code file for security-related implementations:

File: {file_path}
Language: {language}

Code:
```{language}
{code_content}
```

Threats to specifically check for:
{threats_context}

Please analyze this code and identify:

1. **Security Controls Present**: Any code that implements security measures (input validation, authentication, authorization, encryption, logging, error handling, etc.)

2. **Threat Mitigation**: Which specific threats from the list above are mitigated by the existing code

3. **Security Gaps**: Areas where security controls are missing or insufficient

4. **Code Quality**: Assessment of the security implementation quality

Return your analysis in the following JSON format:
{{
    "security_controls": [
        {{
            "control_type": "input_validation|authentication|authorization|encryption|logging|error_handling|access_control|other",
            "description": "Brief description of what this control does",
            "line_numbers": [10, 15, 20],
            "code_snippet": "relevant code snippet",
            "effectiveness": "high|medium|low",
            "threats_mitigated": ["Spoofing", "Tampering", "etc"]
        }}
    ],
    "threat_analysis": [
        {{
            "threat_id": "threat_id_if_provided",
            "threat_category": "Spoofing|Tampering|Repudiation|Information Disclosure|Denial of Service|Elevation of Privilege",
            "mitigation_status": "fully_mitigated|partially_mitigated|not_mitigated",
            "explanation": "Why this threat is or isn't mitigated by existing code"
        }}
    ],
    "security_gaps": [
        {{
            "gap_type": "missing_validation|weak_authentication|etc",
            "description": "Description of the security gap",
            "risk_level": "high|medium|low",
            "recommendation": "How to address this gap"
        }}
    ],
    "overall_assessment": {{
        "security_score": 0.8,
        "summary": "Overall security posture summary"
    }}
}}

Focus on actual security implementations, not just function names. Consider the context and effectiveness of security measures.
"""

# Mapping from security controls to STRIDE threat categories (kept for compatibility)
CONTROL_TO_THREAT_MAPPING = {
    "input_validation": ["Tampering", "Elevation of Privilege"],
    "authentication": ["Spoofing", "Elevation of Privilege"],
    "authorization": ["Elevation of Privilege"],
    "encryption": ["Information Disclosure", "Tampering"],
    "csrf_protection": ["Spoofing", "Tampering"],
    "xss_protection": ["Tampering", "Information Disclosure"],
    "sql_injection_protection": ["Tampering", "Information Disclosure", "Elevation of Privilege"],
    "logging": ["Repudiation"],
    "error_handling": ["Information Disclosure"],
    "access_control": ["Elevation of Privilege"],
    "rate_limiting": ["Denial of Service"],
    "secure_headers": ["Information Disclosure", "Tampering"]
}


def get_file_extension(file_path: str) -> str:
    """Get the file extension from a file path.
    
    Args:
        file_path: Path to the file
        
    Returns:
        File extension without the dot
    """
    _, ext = os.path.splitext(file_path)
    return ext.lstrip('.').lower()


def get_language_from_extension(extension: str) -> str:
    """Map file extension to programming language.
    
    Args:
        extension: File extension
        
    Returns:
        Programming language name
    """
    extension_map = {
        'py': 'python',
        'js': 'javascript',
        'ts': 'typescript',
        'jsx': 'javascript',
        'tsx': 'typescript',
        'java': 'java',
        'cs': 'csharp',
        'go': 'go',
        'rb': 'ruby',
        'php': 'php',
        'html': 'html',
        'htm': 'html',
        'sql': 'sql',
        'yml': 'yaml',
        'yaml': 'yaml',
        'json': 'json',
        'xml': 'xml',
        'md': 'markdown',
        'txt': 'text'
    }
    return extension_map.get(extension, 'unknown')


def format_threats_for_analysis(threats: List[Threat]) -> str:
    """Format threats for LLM analysis context.
    
    Args:
        threats: List of threats to analyze
        
    Returns:
        Formatted string describing threats
    """
    if not threats:
        return "No specific threats provided - analyze for general security controls."
    
    threat_descriptions = []
    for threat in threats:
        threat_desc = f"- **{threat.category.value if threat.category else 'Unknown'}**: {threat.threatAction} → {threat.threatImpact}"
        if hasattr(threat, 'id'):
            threat_desc = f"- **{threat.id}** ({threat.category.value if threat.category else 'Unknown'}): {threat.threatAction} → {threat.threatImpact}"
        threat_descriptions.append(threat_desc)
    
    return "\n".join(threat_descriptions)


async def analyze_code_with_llm(
    code_content: str, 
    file_path: str, 
    threats: List[Threat],
    ctx: Context
) -> str:
    """Generate a prompt for LLM to analyze code for security controls.
    
    Args:
        code_content: The code content to analyze
        file_path: Path to the code file
        threats: List of threats to check for
        ctx: MCP context for logging
        
    Returns:
        A prompt string for LLM analysis
    """
    extension = get_file_extension(file_path)
    language = get_language_from_extension(extension)
    
    if language == 'unknown':
        return f"Unable to analyze file {file_path} - unsupported file type: {extension}"
    
    # Format threats for context
    threats_context = format_threats_for_analysis(threats)
    
    # Create and return the analysis prompt
    prompt = SECURITY_ANALYSIS_PROMPT.format(
        file_path=file_path,
        language=language,
        code_content=code_content[:8000],  # Limit code length for LLM
        threats_context=threats_context
    )
    
    logger.info(f"Generated LLM analysis prompt for {file_path}")
    return prompt


# This function is removed as we're no longer simulating LLM analysis
# Instead, we'll rely on the actual LLM to perform the analysis


async def scan_code_for_security_controls(
    code_files: Dict[str, str],
    threats: List[Threat] = None,
    ctx: Context = None
) -> Dict[str, str]:
    """Generate prompts for LLM to analyze code files for security controls.
    
    Args:
        code_files: Dictionary mapping file paths to file content
        threats: List of threats to analyze for
        ctx: MCP context for logging
        
    Returns:
        Dictionary mapping file paths to LLM analysis prompts
    """
    prompts: Dict[str, str] = {}
    
    if threats is None:
        threats = []
    
    for file_path, content in code_files.items():
        extension = get_file_extension(file_path)
        language = get_language_from_extension(extension)
        
        if language == 'unknown':
            continue
        
        # Skip very large files to avoid LLM token limits
        if len(content) > 50000:
            logger.warning(f"Skipping large file {file_path} ({len(content)} chars)")
            continue
            
        try:
            # Generate prompt for LLM analysis
            prompt = await analyze_code_with_llm(content, file_path, threats, ctx)
            prompts[file_path] = prompt
                    
        except Exception as e:
            logger.error(f"Error generating prompt for {file_path}: {e}")
            continue
    
    return prompts


def map_controls_to_threats(
    security_controls: Dict[str, List[SecurityControlDetection]],
    threats: List[Threat]
) -> Dict[str, RemediationStatus]:
    """Map detected security controls to threats.
    
    Args:
        security_controls: Dictionary of detected security controls
        threats: List of identified threats
        
    Returns:
        Dictionary mapping threat IDs to remediation status
    """
    threat_remediation: Dict[str, RemediationStatus] = {}
    
    for threat in threats:
        # Default to not remediated
        threat_remediation[threat.id] = RemediationStatus.NOT_REMEDIATED
        
        # Get the threat category (e.g., "Spoofing", "Tampering", etc.)
        threat_category = threat.category if hasattr(threat, 'category') else None
        
        if not threat_category:
            continue
            
        # Find controls that address this threat category
        relevant_controls = []
        for control_type, control_detections in security_controls.items():
            if control_type in CONTROL_TO_THREAT_MAPPING and threat_category in CONTROL_TO_THREAT_MAPPING[control_type]:
                if control_detections:  # If we found instances of this control
                    relevant_controls.extend(control_detections)
        
        # Update remediation status based on found controls
        if relevant_controls:
            # For simplicity, we're marking as PARTIALLY_REMEDIATED if any controls are found
            # In a real implementation, this would be more sophisticated
            threat_remediation[threat.id] = RemediationStatus.PARTIALLY_REMEDIATED
            
            # Check if we have strong evidence of full remediation
            # This is a simplified heuristic - real implementation would be more complex
            if len(relevant_controls) >= 3:  # Arbitrary threshold
                threat_remediation[threat.id] = RemediationStatus.FULLY_REMEDIATED
    
    return threat_remediation


async def validate_code_security(
    code_files: Dict[str, str],
    threats: List[Threat],
    mitigations: List[Mitigation],
    ctx: Context = None
) -> Dict[str, str]:
    """Generate prompts for LLM to validate code security.
    
    Args:
        code_files: Dictionary mapping file paths to file content
        threats: List of identified threats
        mitigations: List of proposed mitigations
        ctx: MCP context for logging
        
    Returns:
        Dictionary mapping file paths to LLM analysis prompts
    """
    # Generate prompts for LLM analysis
    prompts = await scan_code_for_security_controls(code_files, threats, ctx)
    
    # Return the prompts for LLM processing
    return prompts


# This function is removed as we're no longer simulating LLM analysis
# The actual mapping will be done by the LLM based on the prompts we generate


# Register tools with the MCP server
def register_tools(mcp):
    """Register code security validation tools with the MCP server.
    
    Args:
        mcp: The MCP server instance
    """
    @mcp.tool()
    async def validate_security_controls(
        ctx: Context,
        code_directory: str,
        file_patterns: Optional[List[str]] = None
    ) -> str:
        """Check what security controls are implemented in code and update threat model.

        Given the current threats and mitigations in the threat model, analyze the 
        codebase to determine what's actually implemented and update the threat model 
        accordingly. The agent should autonomously decide how to analyze the code.

        Args:
            ctx: MCP context for logging and error handling
            code_directory: Directory containing code to analyze
            file_patterns: Optional list of file patterns to include (e.g., ["*.py", "*.js"])

        Returns:
            Simple instruction for autonomous analysis
        """
        logger.info(f"Requesting autonomous code validation for {code_directory}")
        
        try:
            # Import threats and mitigations from threat_generator module
            from threat_modeling_mcp_server.tools.threat_generator import threats, mitigations
            
            # Get current threats and mitigations
            threat_list = list(threats.values())
            mitigation_list = list(mitigations.values())
            
            if not threat_list:
                return "No threats found in threat model. Please add threats before running code validation."
            
            # Simple autonomous instruction
            result = f"# Code Security Validation Task\n\n"
            result += f"**Directory:** {code_directory}\n"
            result += f"**Threats to check:** {len(threat_list)}\n"
            result += f"**Mitigations to check:** {len(mitigation_list)}\n\n"
            
            result += "## Current Threats:\n"
            for threat in threat_list:
                result += f"- **{threat.id}**: {threat.threatAction} → {threat.threatImpact}\n"
            
            result += "\n## Current Mitigations:\n"
            for mitigation in mitigation_list:
                result += f"- **{mitigation.id}**: {mitigation.content}\n"
            
            result += f"\n## Task:\n"
            result += f"Analyze the code in `{code_directory}` and determine:\n"
            result += f"1. Which threats are already mitigated by existing code\n"
            result += f"2. Which mitigations are already implemented in the code\n"
            result += f"3. **IMPORTANT**: Update the threat model with your findings using these tools:\n\n"
            
            result += f"### Required Actions After Analysis:\n"
            result += f"For each threat you analyze:\n"
            result += f"- If threat is **fully mitigated** by existing code: Use `update_threat(id, status='threatResolved')`\n"
            result += f"- If threat is **partially mitigated**: Use `update_threat(id, status='threatIdentified')` and add assumptions about partial mitigation\n"
            result += f"- If threat is **not mitigated**: Leave status as 'threatIdentified'\n\n"
            
            result += f"For each mitigation you analyze:\n"
            result += f"- If mitigation is **already implemented** in code: Use `update_mitigation(id, status='mitigationResolved')`\n"
            result += f"- If mitigation is **partially implemented**: Use `update_mitigation(id, status='mitigationInProgress')`\n"
            result += f"- If mitigation is **not implemented**: Leave status as 'mitigationIdentified'\n\n"
            
            result += f"**Example workflow:**\n"
            result += f"1. Read and analyze code files\n"
            result += f"2. For each threat, determine if code provides adequate protection\n"
            result += f"3. Call `update_threat()` with appropriate status\n"
            result += f"4. For each mitigation, check if it's implemented in code\n"
            result += f"5. Call `update_mitigation()` with appropriate status\n"
            result += f"6. Use `add_assumption()` to document your findings\n\n"
            
            result += f"**You must actually update the threat model - don't just analyze, take action!**\n"
            
            return result
            
        except Exception as e:
            logger.error(f"Error in validate_security_controls: {e}")
            return f"Error generating code validation task: {str(e)}"
    
    @mcp.tool()
    async def validate_threat_remediation(
        ctx: Context,
        code_directory: str,
        threat_ids: List[str]
    ) -> str:
        """Check if specific threats are remediated in code and update threat model.

        Given specific threat IDs, analyze the codebase to determine if these threats 
        are mitigated by existing code and update the threat model accordingly.

        Args:
            ctx: MCP context for logging and error handling
            code_directory: Directory containing code to analyze
            threat_ids: List of threat IDs to validate

        Returns:
            Simple instruction for autonomous threat-specific analysis
        """
        logger.info(f"Requesting threat-specific code validation for {len(threat_ids)} threats")
        
        try:
            # Import threats from threat_generator module
            from threat_modeling_mcp_server.tools.threat_generator import threats
            
            # Get the specific threats to validate
            target_threats = []
            for threat_id in threat_ids:
                if threat_id in threats:
                    target_threats.append(threats[threat_id])
                else:
                    logger.warning(f"Threat ID {threat_id} not found")
            
            if not target_threats:
                return f"No valid threats found for IDs: {threat_ids}"
            
            # Simple autonomous instruction
            result = f"# Threat-Specific Code Validation Task\n\n"
            result += f"**Directory:** {code_directory}\n"
            result += f"**Specific threats to check:** {len(target_threats)}\n\n"
            
            result += "## Threats to Validate:\n"
            for threat in target_threats:
                result += f"- **{threat.id}**: {threat.threatAction} → {threat.threatImpact}\n"
            
            result += f"\n## Task:\n"
            result += f"Analyze the code in `{code_directory}` and determine if these specific threats are mitigated by existing security controls.\n\n"
            
            result += f"### Required Actions After Analysis:\n"
            result += f"For each threat listed above:\n"
            result += f"1. **Read and analyze relevant code files** in `{code_directory}`\n"
            result += f"2. **Determine mitigation status** based on existing security controls\n"
            result += f"3. **Update the threat using the appropriate tool call:**\n\n"
            
            result += f"**Status Updates:**\n"
            result += f"- If threat is **fully mitigated** by existing code: `update_threat(id='{threat_ids[0] if threat_ids else 'THREAT_ID'}', status='threatResolved')`\n"
            result += f"- If threat is **partially mitigated**: `update_threat(id='THREAT_ID', status='threatIdentified')` + `add_assumption()` explaining partial mitigation\n"
            result += f"- If threat is **not mitigated**: Leave status unchanged but document findings with `add_assumption()`\n\n"
            
            result += f"**Example:**\n"
            result += f"```\n"
            result += f"# After analyzing code for threat {threat_ids[0] if threat_ids else 'T001'}\n"
            result += f"update_threat(id='{threat_ids[0] if threat_ids else 'T001'}', status='threatResolved')\n"
            result += f"add_assumption(\n"
            result += f"    description='Threat {threat_ids[0] if threat_ids else 'T001'} is mitigated by TLS encryption implemented in config files',\n"
            result += f"    category='Code Analysis',\n"
            result += f"    impact='This threat is fully addressed by existing implementation',\n"
            result += f"    rationale='Found TLS configuration in [specific files]'\n"
            result += f")\n"
            result += f"```\n\n"
            
            result += f"**You must actually call the update tools - don't just analyze, take action!**\n"
            
            return result
            
        except Exception as e:
            logger.error(f"Error in validate_threat_remediation: {e}")
            return f"Error generating threat-specific validation task: {str(e)}"
    
    @mcp.tool()
    async def generate_remediation_report(
        ctx: Context
    ) -> str:
        """Generate a prompt for LLM to create a comprehensive remediation report.

        This tool generates a prompt for LLM to create a report showing which threats 
        are remediated by existing security controls in the code, which are partially 
        remediated, and which require implementation.

        Args:
            ctx: MCP context for logging and error handling

        Returns:
            A markdown-formatted prompt for LLM to generate a remediation report
        """
        logger.info("Generating prompt for remediation report")
        
        try:
            # Import threats and mitigations from threat_generator module
            from threat_modeling_mcp_server.tools.threat_generator import threats, mitigations, mitigation_links
            
            if not threats:
                return "No threats found in the threat model. Please add threats before generating a remediation report."
            
            # Create comprehensive remediation report prompt
            report_prompt = """
# Comprehensive Threat Model Remediation Report

You are a security expert creating a comprehensive remediation report for a threat model. Based on the threat model data provided below, create a detailed report showing the current security posture and remediation status.

## Threat Model Data

### Identified Threats:

"""
            
            # Add all threats
            for i, threat in enumerate(threats.values(), 1):
                report_prompt += f"#### Threat {i}: {threat.id}\n"
                report_prompt += f"**Statement:** {threat.statement}\n"
                report_prompt += f"**Category:** {threat.category.value if threat.category else 'Unknown'}\n"
                report_prompt += f"**Severity:** {threat.severity.value if threat.severity else 'Unknown'}\n"
                report_prompt += f"**Likelihood:** {threat.likelihood.value if threat.likelihood else 'Unknown'}\n"
                report_prompt += f"**Status:** {threat.status.value}\n"
                
                if threat.affected_components:
                    report_prompt += f"**Affected Components:** {', '.join(threat.affected_components)}\n"
                
                if threat.impactedAssets:
                    report_prompt += f"**Impacted Assets:** {', '.join(threat.impactedAssets)}\n"
                
                # Find linked mitigations
                linked_mitigations = [link.mitigationId for link in mitigation_links if link.linkedId == threat.id]
                if linked_mitigations:
                    report_prompt += f"**Linked Mitigations:** {', '.join(linked_mitigations)}\n"
                
                report_prompt += "\n"
            
            report_prompt += "\n### Identified Mitigations:\n\n"
            
            # Add all mitigations
            for i, mitigation in enumerate(mitigations.values(), 1):
                report_prompt += f"#### Mitigation {i}: {mitigation.id}\n"
                report_prompt += f"**Content:** {mitigation.content}\n"
                report_prompt += f"**Status:** {mitigation.status.value}\n"
                
                if mitigation.type:
                    report_prompt += f"**Type:** {mitigation.type.value}\n"
                
                if mitigation.effectiveness:
                    report_prompt += f"**Effectiveness:** {mitigation.effectiveness.value}\n"
                
                if mitigation.cost:
                    report_prompt += f"**Cost:** {mitigation.cost.value}\n"
                
                if mitigation.implementation_details:
                    report_prompt += f"**Implementation Details:** {mitigation.implementation_details}\n"
                
                # Find linked threats
                linked_threats = [link.linkedId for link in mitigation_links if link.mitigationId == mitigation.id]
                if linked_threats:
                    report_prompt += f"**Addresses Threats:** {', '.join(linked_threats)}\n"
                
                report_prompt += "\n"
            
            report_prompt += """
## Report Generation Instructions

Based on the threat model data above, generate a comprehensive remediation report with the following sections:

### 1. Executive Summary
- Overall security posture assessment
- Key findings and recommendations
- Risk level summary (Critical/High/Medium/Low)

### 2. Threat Analysis Summary
- Total number of threats identified
- Breakdown by category (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
- Breakdown by severity (Critical, High, Medium, Low)
- Breakdown by status (Identified, Mitigated, Accepted, etc.)

### 3. Mitigation Coverage Analysis
- Total number of mitigations planned
- Mitigation status breakdown (Identified, In Progress, Implemented, etc.)
- Threat coverage analysis (which threats have mitigations vs. which don't)
- Effectiveness assessment of planned mitigations

### 4. Risk Assessment
- Unmitigated threats and their risk levels
- Partially mitigated threats requiring additional controls
- Fully mitigated threats
- Residual risk assessment

### 5. Implementation Roadmap
- Priority order for implementing mitigations
- Resource requirements (based on cost assessments)
- Timeline recommendations
- Dependencies between mitigations

### 6. Gaps and Recommendations
- Threats without adequate mitigations
- Missing security controls
- Recommendations for additional security measures
- Process improvements

### 7. Compliance and Governance
- Regulatory compliance considerations
- Security policy alignment
- Audit trail and documentation requirements

### 8. Metrics and KPIs
- Security metrics to track
- Success criteria for mitigation implementation
- Ongoing monitoring recommendations

## Output Format

Please provide the report in markdown format with clear headings, bullet points, and tables where appropriate. Include specific threat IDs and mitigation IDs in your analysis for traceability.

Focus on actionable insights and practical recommendations that can guide the security team in implementing an effective security program.
"""
            
            # Format the output
            result = "# Remediation Report Generation\n\n"
            result += f"**Total Threats:** {len(threats)}\n"
            result += f"**Total Mitigations:** {len(mitigations)}\n"
            result += f"**Mitigation Links:** {len(mitigation_links)}\n\n"
            
            result += "## LLM Analysis Prompt\n\n"
            result += "Use the following prompt with an LLM to generate a comprehensive remediation report:\n\n"
            result += "```\n"
            result += report_prompt
            result += "\n```\n\n"
            
            result += "## Instructions\n\n"
            result += "1. Copy the prompt above and submit it to your LLM\n"
            result += "2. The LLM will generate a comprehensive remediation report\n"
            result += "3. Review the report for completeness and accuracy\n"
            result += "4. Use the report to guide your security implementation efforts\n"
            result += "5. Share the report with stakeholders and security teams\n\n"
            
            result += "## Expected Report Sections\n\n"
            result += "- Executive Summary\n"
            result += "- Threat Analysis Summary\n"
            result += "- Mitigation Coverage Analysis\n"
            result += "- Risk Assessment\n"
            result += "- Implementation Roadmap\n"
            result += "- Gaps and Recommendations\n"
            result += "- Compliance and Governance\n"
            result += "- Metrics and KPIs\n\n"
            
            return result
            
        except Exception as e:
            logger.error(f"Error in generate_remediation_report: {e}")
            return f"Error generating remediation report: {str(e)}"
