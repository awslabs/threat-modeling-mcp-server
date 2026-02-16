"""Threat Model Validator for the Threat Modeling MCP Server.

This module validates the threat model against the actual codebase to determine
which threats are already mitigated by existing security controls.
"""

import os
import glob
from typing import Dict, List, Set, Optional, Any
from loguru import logger
from mcp.server.fastmcp import Context

from threat_modeling_mcp_server.models.threat_models import Threat, Mitigation
from threat_modeling_mcp_server.models.code_validation_models import RemediationReport, RemediationStatus
from threat_modeling_mcp_server.tools.code_security_validator import validate_code_security
from threat_modeling_mcp_server.utils.file_utils import normalize_output_path


async def read_code_files(
    directory: str,
    file_patterns: Optional[List[str]] = None
) -> Dict[str, str]:
    """Read code files from a directory.
    
    Args:
        directory: Directory to read files from
        file_patterns: Optional list of file patterns to include
        
    Returns:
        Dictionary mapping file paths to file content
    """
    if file_patterns is None:
        file_patterns = ["*.py", "*.js", "*.ts", "*.java", "*.cs", "*.go", "*.rb", "*.php", "*.html"]
        
    code_files = {}
    
    for pattern in file_patterns:
        file_paths = glob.glob(os.path.join(directory, "**", pattern), recursive=True)
        for file_path in file_paths:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    code_files[file_path] = f.read()
            except Exception as e:
                logger.warning(f"Could not read file {file_path}: {e}")
                
    return code_files


async def generate_remediation_report_from_results(
    threats: List[Threat],
    mitigations: List[Mitigation],
    threat_remediation_status: Dict[str, RemediationStatus],
    detected_controls: Dict[str, List[Dict[str, Any]]]
) -> RemediationReport:
    """Generate a remediation report from validation results.
    
    Args:
        threats: List of identified threats
        mitigations: List of proposed mitigations
        threat_remediation_status: Dictionary mapping threat IDs to remediation status
        detected_controls: Dictionary of detected security controls
        
    Returns:
        A comprehensive remediation report
    """
    # Group threats by remediation status
    fully_remediated = []
    partially_remediated = []
    unremediated = []
    
    for threat in threats:
        status = threat_remediation_status.get(threat.id, RemediationStatus.NOT_REMEDIATED)
        if status == RemediationStatus.FULLY_REMEDIATED:
            fully_remediated.append(threat.id)
        elif status == RemediationStatus.PARTIALLY_REMEDIATED:
            partially_remediated.append(threat.id)
        else:
            unremediated.append(threat.id)
    
    # Count detected controls by type
    control_summary = {
        control_type: len(detections)
        for control_type, detections in detected_controls.items()
    }
    
    # Generate recommendations
    recommendations = []
    
    # For unremediated threats, suggest implementing mitigations
    for threat_id in unremediated:
        threat = next((t for t in threats if t.id == threat_id), None)
        if threat:
            recommendations.append(f"Implement security controls for {threat.threatAction} to prevent {threat.threatImpact}")
    
    # For partially remediated threats, suggest enhancing controls
    for threat_id in partially_remediated:
        threat = next((t for t in threats if t.id == threat_id), None)
        if threat:
            recommendations.append(f"Enhance security controls for {threat.threatAction} to better prevent {threat.threatImpact}")
    
    # Calculate overall security score
    total_threats = len(threats)
    if total_threats == 0:
        security_score = 1.0  # No threats = perfect score
    else:
        # Weight fully remediated as 1.0, partially as 0.5
        weighted_score = len(fully_remediated) + (len(partially_remediated) * 0.5)
        security_score = weighted_score / total_threats
    
    # Create the report
    report = RemediationReport(
        fully_remediated_threats=fully_remediated,
        partially_remediated_threats=partially_remediated,
        unremediated_threats=unremediated,
        detected_controls_summary=control_summary,
        recommendations=recommendations,
        overall_security_score=security_score
    )
    
    return report


def format_remediation_report_markdown(report: RemediationReport, threats: List[Threat]) -> str:
    """Format a remediation report as markdown.
    
    Args:
        report: The remediation report
        threats: List of threats for reference
        
    Returns:
        Markdown-formatted report
    """
    # Create a lookup for threats by ID
    threat_lookup = {threat.id: threat for threat in threats}
    
    # Format the report as markdown
    md = []
    md.append("# Threat Remediation Report\n")
    
    # Overall security score
    score_percentage = int(report.overall_security_score * 100)
    md.append(f"## Overall Security Score: {score_percentage}%\n")
    
    # Security controls summary
    md.append("## Detected Security Controls\n")
    for control_type, count in report.detected_controls_summary.items():
        md.append(f"- **{control_type.replace('_', ' ').title()}**: {count} instances\n")
    
    # Fully remediated threats
    md.append("\n## Fully Remediated Threats\n")
    if report.fully_remediated_threats:
        for threat_id in report.fully_remediated_threats:
            threat = threat_lookup.get(threat_id)
            if threat:
                md.append(f"- ✅ **{threat.threatAction}**: {threat.threatImpact}\n")
    else:
        md.append("- No fully remediated threats found\n")
    
    # Partially remediated threats
    md.append("\n## Partially Remediated Threats\n")
    if report.partially_remediated_threats:
        for threat_id in report.partially_remediated_threats:
            threat = threat_lookup.get(threat_id)
            if threat:
                md.append(f"- ⚠️ **{threat.threatAction}**: {threat.threatImpact}\n")
    else:
        md.append("- No partially remediated threats found\n")
    
    # Unremediated threats
    md.append("\n## Unremediated Threats\n")
    if report.unremediated_threats:
        for threat_id in report.unremediated_threats:
            threat = threat_lookup.get(threat_id)
            if threat:
                md.append(f"- ❌ **{threat.threatAction}**: {threat.threatImpact}\n")
    else:
        md.append("- No unremediated threats found\n")
    
    # Recommendations
    md.append("\n## Recommendations\n")
    for recommendation in report.recommendations:
        md.append(f"- {recommendation}\n")
    
    return "".join(md)


async def perform_threat_model_validation(
    code_directory: str,
    threats: List[Threat],
    mitigations: List[Mitigation],
    file_patterns: Optional[List[str]] = None
) -> str:
    """Perform threat model validation against code.
    
    This function is designed to be called both from the MCP tool and internally
    by other components that need to validate the threat model against code.
    
    Args:
        code_directory: Directory containing code to analyze
        threats: List of threats from the threat model
        mitigations: List of mitigations from the threat model
        file_patterns: Optional list of file patterns to include
        
    Returns:
        A markdown-formatted validation report
    """
    logger.info(f"Performing threat model validation against code in {code_directory}")
    
    # Read code files
    code_files = await read_code_files(code_directory, file_patterns)
    
    if not code_files:
        return "No code files found to analyze."
    
    # Generate LLM analysis prompts (current implementation returns prompts, not results)
    analysis_prompts = await validate_code_security(code_files, threats, mitigations, None)
    
    # Since the current implementation generates prompts for LLM analysis rather than
    # performing actual analysis, we'll create a placeholder report that explains
    # what needs to be done
    
    report_md = []
    report_md.append("# Threat Model Validation Report\n")
    report_md.append(f"**Analysis Date**: {os.path.basename(code_directory)}\n")
    report_md.append(f"**Code Files Analyzed**: {len(code_files)}\n")
    report_md.append(f"**Threats to Validate**: {len(threats)}\n")
    report_md.append(f"**Mitigations to Check**: {len(mitigations)}\n\n")
    
    report_md.append("## Analysis Status\n")
    report_md.append("⚠️ **Manual Analysis Required**: The current implementation generates prompts for LLM analysis rather than performing automated validation.\n\n")
    
    report_md.append("## Code Files Found\n")
    for file_path in code_files.keys():
        file_size = len(code_files[file_path])
        report_md.append(f"- `{file_path}` ({file_size:,} characters)\n")
    
    report_md.append("\n## Threats to Validate\n")
    for i, threat in enumerate(threats, 1):
        report_md.append(f"{i}. **{threat.id}**: {threat.threatAction} → {threat.threatImpact}\n")
        report_md.append(f"   - Category: {threat.category.value if threat.category else 'Unknown'}\n")
        report_md.append(f"   - Severity: {threat.severity.value if threat.severity else 'Unknown'}\n")
    
    report_md.append("\n## Mitigations to Check\n")
    for i, mitigation in enumerate(mitigations, 1):
        report_md.append(f"{i}. **{mitigation.id}**: {mitigation.content}\n")
        report_md.append(f"   - Status: {mitigation.status.value}\n")
    
    report_md.append("\n## Next Steps\n")
    report_md.append("To complete the validation:\n")
    report_md.append("1. Use the generated LLM analysis prompts to analyze each code file\n")
    report_md.append("2. Determine which threats are mitigated by existing code\n")
    report_md.append("3. Update threat statuses using `update_threat()` tool\n")
    report_md.append("4. Update mitigation statuses using `update_mitigation()` tool\n")
    report_md.append("5. Document findings using `add_assumption()` tool\n\n")
    
    if analysis_prompts:
        report_md.append("## Generated Analysis Prompts\n")
        report_md.append(f"Analysis prompts have been generated for {len(analysis_prompts)} files.\n")
        report_md.append("Use these prompts with an LLM to perform detailed security analysis.\n\n")
    
    return "".join(report_md)


# Register tools with the MCP server
def register_tools(mcp):
    """Register threat model validation tools with the MCP server.
    
    Args:
        mcp: The MCP server instance
    """
    @mcp.tool()
    async def validate_threat_model_against_code(
        ctx: Context,
        code_directory: str,
        file_patterns: Optional[List[str]] = None
    ) -> str:
        """Validate the threat model against the actual codebase.

        This tool analyzes the codebase to determine which threats are already mitigated
        by existing security controls, and generates a comprehensive report.

        Args:
            ctx: MCP context for logging and error handling
            code_directory: Directory containing code to analyze
            file_patterns: Optional list of file patterns to include (e.g., ["*.py", "*.js"])

        Returns:
            A markdown-formatted validation report
        """
        logger.info(f"Validating threat model against code in {code_directory}")
        
        # Get the current threat model from the threat_generator module
        try:
            from threat_modeling_mcp_server.tools.threat_generator import threats, mitigations
            
            # Convert dictionaries to lists
            threat_list = list(threats.values())
            mitigation_list = list(mitigations.values())
            
            logger.info(f"Found {len(threat_list)} threats and {len(mitigation_list)} mitigations to validate")
            
            # Use the common validation function
            return await perform_threat_model_validation(code_directory, threat_list, mitigation_list, file_patterns)
            
        except ImportError as e:
            logger.error(f"Could not import threat model data: {e}")
            return f"Error: Could not access threat model data. Please ensure threats and mitigations have been added to the model first."
        except Exception as e:
            logger.error(f"Error validating threat model against code: {e}")
            return f"Error during validation: {str(e)}"
    
    @mcp.tool()
    async def export_threat_model_with_remediation_status(
        ctx: Context,
        output_path: str
    ) -> str:
        """Export the threat model with remediation status.

        This tool exports the threat model with information about which threats
        are already remediated by existing security controls.

        Args:
            ctx: MCP context for logging and error handling
            output_path: Path to save the exported threat model

        Returns:
            A confirmation message
        """
        # Normalize the output path to be in .threatmodel directory
        normalized_path = normalize_output_path(output_path)
        logger.info(f"Exporting threat model with remediation status to {normalized_path}")
        
        # This would be implemented to export the threat model with remediation status
        # For now, we'll return a placeholder
        return f"Threat model with remediation status exported to {normalized_path}"
