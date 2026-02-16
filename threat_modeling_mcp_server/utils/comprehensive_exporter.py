"""Comprehensive exporter for converting all global variables to Threat Composer JSON format."""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from loguru import logger

from threat_modeling_mcp_server.utils.state_collector import collect_all_state, ThreatModelState
from threat_modeling_mcp_server.models.threat_models import ThreatModel
from threat_modeling_mcp_server.utils.file_utils import normalize_output_path


def convert_business_context_to_dict(business_context) -> Dict[str, Any]:
    """Convert business context to dictionary format.
    
    Args:
        business_context: BusinessContext object
        
    Returns:
        Dictionary representation of business context
    """
    if not business_context:
        return {}
    
    result = {
        "description": business_context.description or "",
        "features": {}
    }
    
    if business_context.industry_sector:
        result["features"]["industry_sector"] = business_context.industry_sector.value
    
    if business_context.data_sensitivity:
        result["features"]["data_sensitivity"] = business_context.data_sensitivity.value
    
    if business_context.user_base_size:
        result["features"]["user_base_size"] = business_context.user_base_size.value
    
    if business_context.geographic_scope:
        result["features"]["geographic_scope"] = business_context.geographic_scope.value
    
    if business_context.regulatory_requirements:
        result["features"]["regulatory_requirements"] = [req.value for req in business_context.regulatory_requirements]
    
    if business_context.system_criticality:
        result["features"]["system_criticality"] = business_context.system_criticality.value
    
    if business_context.financial_impact:
        result["features"]["financial_impact"] = business_context.financial_impact.value
    
    if business_context.authentication_requirement:
        result["features"]["authentication_requirement"] = business_context.authentication_requirement.value
    
    if business_context.deployment_environment:
        result["features"]["deployment_environment"] = business_context.deployment_environment.value
    
    if business_context.integration_complexity:
        result["features"]["integration_complexity"] = business_context.integration_complexity.value
    
    return result


def convert_assumptions_to_threat_composer_format(assumptions: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert assumptions to Threat Composer format.
    
    Args:
        assumptions: Dictionary of assumption objects
        
    Returns:
        List of assumptions in Threat Composer format
    """
    result = []
    
    for assumption_id, assumption in assumptions.items():
        assumption_dict = {
            "id": assumption.id,
            "numericId": int(assumption.id.replace("A", "")) if assumption.id.startswith("A") else len(result) + 1,
            "content": assumption.description,
            "displayOrder": int(assumption.id.replace("A", "")) if assumption.id.startswith("A") else len(result) + 1,
            "metadata": []  # Keep metadata empty for Threat Composer compatibility
        }
        result.append(assumption_dict)
    
    return result


def convert_threats_to_threat_composer_format(threats: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert threats to Threat Composer format.
    
    Args:
        threats: Dictionary of threat objects
        
    Returns:
        List of threats in Threat Composer format
    """
    result = []
    
    for threat_id, threat in threats.items():
        # Use our internal status directly (now compatible with Threat Composer)
        threat_status = threat.status.value if threat.status else "threatIdentified"
        
        # Use only fields that are compatible with Threat Composer
        threat_dict = {
            "id": threat.id,
            "numericId": threat.numericId,
            "threatSource": threat.threatSource,
            "prerequisites": threat.prerequisites,
            "threatAction": threat.threatAction,
            "threatImpact": threat.threatImpact,
            "impactedGoal": threat.impactedGoal,
            "impactedAssets": threat.impactedAssets,
            "statement": threat.statement,
            "displayOrder": threat.displayOrder,
            "status": threat_status,
            "tags": threat.tags,
            "metadata": []  # Keep metadata empty for Threat Composer compatibility
        }
        
        result.append(threat_dict)
    
    return result


def convert_mitigations_to_threat_composer_format(mitigations: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert mitigations to Threat Composer format.
    
    Args:
        mitigations: Dictionary of mitigation objects
        
    Returns:
        List of mitigations in Threat Composer format
    """
    result = []
    
    for mitigation_id, mitigation in mitigations.items():
        # Use our internal status directly (now compatible with Threat Composer)
        mitigation_status = mitigation.status.value if mitigation.status else "mitigationIdentified"
        
        # Use only fields that are compatible with Threat Composer
        mitigation_dict = {
            "id": mitigation.id,
            "numericId": mitigation.numericId,
            "status": mitigation_status,
            "content": mitigation.content,
            "displayOrder": mitigation.displayOrder,
            "metadata": []  # Keep metadata empty for Threat Composer compatibility
        }
        
        result.append(mitigation_dict)
    
    return result


def convert_components_to_dict(components: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert components to dictionary format.
    
    Args:
        components: Dictionary of component objects
        
    Returns:
        List of components in dictionary format
    """
    result = []
    
    for component_id, component in components.items():
        component_dict = {
            "id": component.id,
            "name": component.name,
            "type": component.type.value,
            "service_provider": component.service_provider.value if component.service_provider else None,
            "specific_service": component.specific_service,
            "version": component.version,
            "description": component.description,
            "configuration": component.configuration
        }
        result.append(component_dict)
    
    return result


def convert_connections_to_dict(connections: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert connections to dictionary format.
    
    Args:
        connections: Dictionary of connection objects
        
    Returns:
        List of connections in dictionary format
    """
    result = []
    
    for connection_id, connection in connections.items():
        connection_dict = {
            "id": connection.id,
            "source_id": connection.source_id,
            "destination_id": connection.destination_id,
            "protocol": connection.protocol.value if connection.protocol else None,
            "port": connection.port,
            "encryption": connection.encryption,
            "description": connection.description
        }
        result.append(connection_dict)
    
    return result


def convert_data_stores_to_dict(data_stores: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert data stores to dictionary format.
    
    Args:
        data_stores: Dictionary of data store objects
        
    Returns:
        List of data stores in dictionary format
    """
    result = []
    
    for data_store_id, data_store in data_stores.items():
        data_store_dict = {
            "id": data_store.id,
            "name": data_store.name,
            "type": data_store.type.value,
            "classification": data_store.classification.value,
            "encryption_at_rest": data_store.encryption_at_rest,
            "backup_frequency": data_store.backup_frequency.value if data_store.backup_frequency else None,
            "description": data_store.description
        }
        result.append(data_store_dict)
    
    return result


def convert_generic_objects_to_dict(objects: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert generic objects to dictionary format using their dict() method.
    
    Args:
        objects: Dictionary of objects with dict() method
        
    Returns:
        List of objects in dictionary format
    """
    result = []
    
    for obj_id, obj in objects.items():
        if hasattr(obj, 'dict'):
            result.append(obj.dict())
        else:
            # Fallback to converting object attributes
            obj_dict = {}
            for attr_name in dir(obj):
                if not attr_name.startswith('_'):
                    attr_value = getattr(obj, attr_name)
                    if not callable(attr_value):
                        obj_dict[attr_name] = attr_value
            result.append(obj_dict)
    
    return result


def export_comprehensive_threat_model(output_path: str, include_extended_data: bool = True) -> str:
    """Export comprehensive threat model to both Threat Composer JSON and Markdown formats.
    
    Args:
        output_path: Path to save the exported threat model (without extension)
        include_extended_data: Whether to include extended data beyond standard Threat Composer format
        
    Returns:
        Confirmation message with export details for both formats
    """
    logger.info(f"Starting comprehensive threat model export to {output_path}")
    
    # Update phase completion before collecting state
    try:
        from threat_modeling_mcp_server.tools.step_orchestrator import detect_phase_completion
        detect_phase_completion()
    except Exception as e:
        logger.warning(f"Failed to update phase completion: {e}")
    
    # Collect all state
    state = collect_all_state()
    
    # Normalize the output path to be in .threatmodel directory
    normalized_path = normalize_output_path(output_path)
    
    # Remove any existing extension to create base path
    base_path = os.path.splitext(normalized_path)[0]
    
    # Create the .threatmodel directory if it doesn't exist
    threatmodel_dir = os.path.join(os.path.dirname(base_path), '.threatmodel')
    os.makedirs(threatmodel_dir, exist_ok=True)
    
    # Create paths for both formats
    base_filename = os.path.basename(base_path)
    json_path = os.path.join(threatmodel_dir, f"{base_filename}.json")
    markdown_path = os.path.join(threatmodel_dir, f"{base_filename}.md")
    
    # Export JSON format
    json_success = False
    json_size = 0
    try:
        # Create comprehensive threat model with ONLY standard Threat Composer fields
        threat_model_data = {
            "schema": 1,
            "applicationInfo": {
                "name": "Threat Model Export",
                "description": state.business_context.description if state.business_context and state.business_context.description else ""
            },
            "architecture": {
                "description": ""
            },
            "dataflow": {
                "description": ""
            },
            "assumptions": convert_assumptions_to_threat_composer_format(state.assumptions),
            "mitigations": convert_mitigations_to_threat_composer_format(state.mitigations),
            "assumptionLinks": [link.dict() for link in state.assumption_links],
            "mitigationLinks": [link.dict() for link in state.mitigation_links],
            "threats": convert_threats_to_threat_composer_format(state.threats)
        }
        
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(threat_model_data, f, indent=2, ensure_ascii=False)
        
        json_size = os.path.getsize(json_path)
        json_success = True
        logger.info(f"Successfully exported JSON threat model to {json_path}")
        
    except Exception as e:
        logger.error(f"Failed to export JSON threat model: {str(e)}")
    
    # Export Markdown format
    markdown_success = False
    markdown_size = 0
    try:
        markdown_content = generate_threat_model_markdown(state)
        
        with open(markdown_path, "w", encoding="utf-8") as f:
            f.write(markdown_content)
        
        markdown_size = os.path.getsize(markdown_path)
        markdown_success = True
        logger.info(f"Successfully exported Markdown threat model to {markdown_path}")
        
    except Exception as e:
        logger.error(f"Failed to export Markdown threat model: {str(e)}")
    
    # Generate comprehensive summary
    if json_success and markdown_success:
        status = "✅ Both formats exported successfully"
    elif json_success:
        status = "⚠️ JSON exported successfully, Markdown failed"
    elif markdown_success:
        status = "⚠️ Markdown exported successfully, JSON failed"
    else:
        status = "❌ Both exports failed"
    
    summary = f"""
# Comprehensive Threat Model Export Complete

**Status**: {status}
**Export Timestamp**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Export Summary
- **Threats**: {len(state.threats)}
- **Mitigations**: {len(state.mitigations)}
- **Assumptions**: {len(state.assumptions)}
- **Components**: {len(state.components)}
- **Assets**: {len(state.assets)}
- **Threat Actors**: {len(state.threat_actors)}
- **Trust Zones**: {len(state.trust_zones)}
- **Data Stores**: {len(state.data_stores)}

## Current Phase
- **Phase**: {state.current_phase} - {state.phases.get(state.current_phase, 'Unknown')}
- **Overall Completion**: {sum(state.phase_completion.values()) / len(state.phase_completion) * 100:.1f}%

## Exported Files"""
    
    if json_success:
        summary += f"""

### JSON Export (Threat Composer Compatible)
- **Path**: {json_path}
- **Format**: Threat Composer JSON (Standard Compatible)
- **Schema Version**: 1
- **File Size**: {json_size} bytes
- **Status**: ✅ Successfully exported"""
    
    if markdown_success:
        summary += f"""

### Markdown Export (Human-Readable Report)
- **Path**: {markdown_path}
- **Format**: Comprehensive Markdown Report
- **File Size**: {markdown_size} bytes
- **Status**: ✅ Successfully exported"""
    
    if json_success:
        summary += "\n\nThe JSON file is fully compatible with AWS Threat Composer and contains only standard schema fields."
    
    if markdown_success:
        summary += "\nThe Markdown file contains a comprehensive, human-readable threat model report with all sections and data."
    
    return summary.strip()


def export_comprehensive_threat_model_markdown(output_path: str) -> str:
    """Export comprehensive threat model to markdown format.
    
    Args:
        output_path: Path to save the exported threat model
        
    Returns:
        Confirmation message with export details
    """
    logger.info(f"Starting comprehensive threat model markdown export to {output_path}")
    
    # Collect all state
    state = collect_all_state()
    
    # Normalize the output path to be in .threatmodel directory
    normalized_path = normalize_output_path(output_path)
    
    # Ensure the path ends with .md
    if not normalized_path.endswith('.md'):
        normalized_path += '.md'
    
    # Create the .threatmodel directory if it doesn't exist
    threatmodel_dir = os.path.join(os.path.dirname(normalized_path), '.threatmodel')
    os.makedirs(threatmodel_dir, exist_ok=True)
    
    # Update the path to be in .threatmodel directory
    filename = os.path.basename(normalized_path)
    final_path = os.path.join(threatmodel_dir, filename)
    
    # Generate markdown content
    markdown_content = generate_threat_model_markdown(state)
    
    # Write to file
    try:
        with open(final_path, "w", encoding="utf-8") as f:
            f.write(markdown_content)
        
        logger.info(f"Successfully exported threat model markdown to {final_path}")
        
        # Generate summary
        summary = f"""
# Threat Model Markdown Export Complete

**Export Path**: {final_path}
**Export Timestamp**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Export Summary
- **Threats**: {len(state.threats)}
- **Mitigations**: {len(state.mitigations)}
- **Assumptions**: {len(state.assumptions)}
- **Components**: {len(state.components)}
- **Assets**: {len(state.assets)}
- **Threat Actors**: {len(state.threat_actors)}
- **Trust Zones**: {len(state.trust_zones)}
- **Data Stores**: {len(state.data_stores)}

## Current Phase
- **Phase**: {state.current_phase} - {state.phases.get(state.current_phase, 'Unknown')}
- **Overall Completion**: {sum(state.phase_completion.values()) / len(state.phase_completion) * 100:.1f}%

## File Details
- **Format**: Markdown (.md)
- **File Size**: {os.path.getsize(final_path)} bytes

The exported markdown file contains a comprehensive, human-readable threat model report.
"""
        
        return summary.strip()
        
    except Exception as e:
        error_msg = f"Failed to export threat model markdown: {str(e)}"
        logger.error(error_msg)
        return error_msg


def generate_threat_model_markdown(state: ThreatModelState) -> str:
    """Generate comprehensive threat model markdown content.
    
    Args:
        state: ThreatModelState containing all threat model data
        
    Returns:
        Markdown formatted threat model content
    """
    md = []
    
    # Title and metadata
    md.append("# Comprehensive Threat Model Report")
    md.append("")
    md.append(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    md.append(f"**Current Phase**: {state.current_phase} - {state.phases.get(state.current_phase, 'Unknown')}")
    md.append(f"**Overall Completion**: {sum(state.phase_completion.values()) / len(state.phase_completion) * 100:.1f}%")
    md.append("")
    
    # Table of Contents
    md.append("## Table of Contents")
    md.append("")
    md.append("1. [Executive Summary](#executive-summary)")
    md.append("2. [Business Context](#business-context)")
    md.append("3. [System Architecture](#system-architecture)")
    md.append("4. [Threat Actors](#threat-actors)")
    md.append("5. [Trust Boundaries](#trust-boundaries)")
    md.append("6. [Assets and Flows](#assets-and-flows)")
    md.append("7. [Threats](#threats)")
    md.append("8. [Mitigations](#mitigations)")
    md.append("9. [Assumptions](#assumptions)")
    md.append("10. [Phase Progress](#phase-progress)")
    md.append("")
    
    # Executive Summary
    md.append("## Executive Summary")
    md.append("")
    if state.business_context and state.business_context.description:
        md.append(state.business_context.description)
        md.append("")
    
    md.append("### Key Statistics")
    md.append("")
    md.append(f"- **Total Threats**: {len(state.threats)}")
    md.append(f"- **Total Mitigations**: {len(state.mitigations)}")
    md.append(f"- **Total Assumptions**: {len(state.assumptions)}")
    md.append(f"- **System Components**: {len(state.components)}")
    md.append(f"- **Assets**: {len(state.assets)}")
    md.append(f"- **Threat Actors**: {len(state.threat_actors)}")
    md.append("")
    
    # Business Context
    md.append("## Business Context")
    md.append("")
    if state.business_context:
        if state.business_context.description:
            md.append(f"**Description**: {state.business_context.description}")
            md.append("")
        
        md.append("### Business Features")
        md.append("")
        if state.business_context.industry_sector:
            md.append(f"- **Industry Sector**: {state.business_context.industry_sector.value}")
        if state.business_context.data_sensitivity:
            md.append(f"- **Data Sensitivity**: {state.business_context.data_sensitivity.value}")
        if state.business_context.user_base_size:
            md.append(f"- **User Base Size**: {state.business_context.user_base_size.value}")
        if state.business_context.geographic_scope:
            md.append(f"- **Geographic Scope**: {state.business_context.geographic_scope.value}")
        if state.business_context.regulatory_requirements:
            reqs = [req.value for req in state.business_context.regulatory_requirements]
            md.append(f"- **Regulatory Requirements**: {', '.join(reqs)}")
        if state.business_context.system_criticality:
            md.append(f"- **System Criticality**: {state.business_context.system_criticality.value}")
        if state.business_context.financial_impact:
            md.append(f"- **Financial Impact**: {state.business_context.financial_impact.value}")
        if state.business_context.authentication_requirement:
            md.append(f"- **Authentication Requirement**: {state.business_context.authentication_requirement.value}")
        if state.business_context.deployment_environment:
            md.append(f"- **Deployment Environment**: {state.business_context.deployment_environment.value}")
        if state.business_context.integration_complexity:
            md.append(f"- **Integration Complexity**: {state.business_context.integration_complexity.value}")
        md.append("")
    else:
        md.append("*No business context defined.*")
        md.append("")
    
    # System Architecture
    md.append("## System Architecture")
    md.append("")
    
    if state.components:
        md.append("### Components")
        md.append("")
        md.append("| ID | Name | Type | Service Provider | Description |")
        md.append("|---|---|---|---|---|")
        for comp_id, comp in state.components.items():
            provider = comp.service_provider.value if comp.service_provider else "N/A"
            description = comp.description or "N/A"
            md.append(f"| {comp.id} | {comp.name} | {comp.type.value} | {provider} | {description} |")
        md.append("")
    
    if state.connections:
        md.append("### Connections")
        md.append("")
        md.append("| ID | Source | Destination | Protocol | Port | Encrypted | Description |")
        md.append("|---|---|---|---|---|---|---|")
        for conn_id, conn in state.connections.items():
            protocol = conn.protocol.value if conn.protocol else "N/A"
            port = str(conn.port) if conn.port else "N/A"
            encrypted = "Yes" if conn.encryption else "No"
            description = conn.description or "N/A"
            md.append(f"| {conn.id} | {conn.source_id} | {conn.destination_id} | {protocol} | {port} | {encrypted} | {description} |")
        md.append("")
    
    if state.data_stores:
        md.append("### Data Stores")
        md.append("")
        md.append("| ID | Name | Type | Classification | Encrypted at Rest | Description |")
        md.append("|---|---|---|---|---|---|")
        for ds_id, ds in state.data_stores.items():
            encrypted = "Yes" if ds.encryption_at_rest else "No"
            description = ds.description or "N/A"
            md.append(f"| {ds.id} | {ds.name} | {ds.type.value} | {ds.classification.value} | {encrypted} | {description} |")
        md.append("")
    
    # Threat Actors
    md.append("## Threat Actors")
    md.append("")
    if state.threat_actors:
        for actor_id, actor in state.threat_actors.items():
            md.append(f"### {actor.name}")
            md.append("")
            md.append(f"- **Type**: {actor.type}")
            md.append(f"- **Capability Level**: {actor.capability_level}")
            md.append(f"- **Motivations**: {', '.join(actor.motivations)}")
            md.append(f"- **Resources**: {actor.resources}")
            md.append(f"- **Relevant**: {'Yes' if actor.is_relevant else 'No'}")
            if actor.priority > 0:
                md.append(f"- **Priority**: {actor.priority}/10")
            if actor.description:
                md.append(f"- **Description**: {actor.description}")
            md.append("")
    else:
        md.append("*No threat actors defined.*")
        md.append("")
    
    # Trust Boundaries
    md.append("## Trust Boundaries")
    md.append("")
    
    if state.trust_zones:
        md.append("### Trust Zones")
        md.append("")
        for zone_id, zone in state.trust_zones.items():
            md.append(f"#### {zone.name}")
            md.append("")
            md.append(f"- **Trust Level**: {zone.trust_level}")
            if zone.description:
                md.append(f"- **Description**: {zone.description}")
            md.append("")
    
    if state.trust_boundaries:
        md.append("### Trust Boundaries")
        md.append("")
        for boundary_id, boundary in state.trust_boundaries.items():
            md.append(f"#### {boundary.name}")
            md.append("")
            md.append(f"- **Type**: {boundary.type}")
            if boundary.controls:
                md.append(f"- **Controls**: {', '.join(boundary.controls)}")
            if boundary.description:
                md.append(f"- **Description**: {boundary.description}")
            md.append("")
    
    # Assets and Flows
    md.append("## Assets and Flows")
    md.append("")
    
    if state.assets:
        md.append("### Assets")
        md.append("")
        md.append("| ID | Name | Type | Classification | Sensitivity | Criticality | Owner |")
        md.append("|---|---|---|---|---|---|---|")
        for asset_id, asset in state.assets.items():
            sensitivity = str(asset.sensitivity) if asset.sensitivity else "N/A"
            criticality = str(asset.criticality) if asset.criticality else "N/A"
            owner = asset.owner or "N/A"
            md.append(f"| {asset.id} | {asset.name} | {asset.type} | {asset.classification} | {sensitivity} | {criticality} | {owner} |")
        md.append("")
    
    if state.flows:
        md.append("### Asset Flows")
        md.append("")
        md.append("| ID | Asset | Source | Destination | Protocol | Encrypted | Risk Level |")
        md.append("|---|---|---|---|---|---|---|")
        for flow_id, flow in state.flows.items():
            # Find asset name
            asset_name = "Unknown"
            if flow.asset_id in state.assets:
                asset_name = state.assets[flow.asset_id].name
            
            protocol = flow.protocol or "N/A"
            encrypted = "Yes" if flow.encryption else "No"
            risk_level = str(flow.risk_level) if flow.risk_level else "N/A"
            md.append(f"| {flow.id} | {asset_name} | {flow.source_id} | {flow.destination_id} | {protocol} | {encrypted} | {risk_level} |")
        md.append("")
    
    # Threats
    md.append("## Threats")
    md.append("")
    if state.threats:
        # Group threats by status
        threats_by_status = {}
        for threat_id, threat in state.threats.items():
            status = threat.status.value if threat.status else "threatIdentified"
            if status not in threats_by_status:
                threats_by_status[status] = []
            threats_by_status[status].append(threat)
        
        for status, threats in threats_by_status.items():
            status_name = {
                "threatIdentified": "Identified Threats",
                "threatResolved": "Resolved Threats", 
                "threatResolvedNotUseful": "Not Useful Threats"
            }.get(status, f"Threats ({status})")
            
            md.append(f"### {status_name}")
            md.append("")
            
            for threat in threats:
                md.append(f"#### T{threat.numericId}: {threat.threatSource}")
                md.append("")
                md.append(f"**Statement**: {threat.statement}")
                md.append("")
                md.append(f"- **Prerequisites**: {threat.prerequisites}")
                md.append(f"- **Action**: {threat.threatAction}")
                md.append(f"- **Impact**: {threat.threatImpact}")
                if threat.impactedGoal:
                    md.append(f"- **Impacted Goals**: {', '.join(threat.impactedGoal)}")
                if threat.impactedAssets:
                    md.append(f"- **Impacted Assets**: {', '.join(threat.impactedAssets)}")
                if threat.tags:
                    md.append(f"- **Tags**: {', '.join(threat.tags)}")
                md.append("")
    else:
        md.append("*No threats defined.*")
        md.append("")
    
    # Mitigations
    md.append("## Mitigations")
    md.append("")
    if state.mitigations:
        # Group mitigations by status
        mitigations_by_status = {}
        for mitigation_id, mitigation in state.mitigations.items():
            status = mitigation.status.value if mitigation.status else "mitigationIdentified"
            if status not in mitigations_by_status:
                mitigations_by_status[status] = []
            mitigations_by_status[status].append(mitigation)
        
        for status, mitigations in mitigations_by_status.items():
            status_name = {
                "mitigationIdentified": "Identified Mitigations",
                "mitigationInProgress": "In Progress Mitigations",
                "mitigationResolved": "Resolved Mitigations",
                "mitigationResolvedWillNotAction": "Will Not Action Mitigations"
            }.get(status, f"Mitigations ({status})")
            
            md.append(f"### {status_name}")
            md.append("")
            
            for mitigation in mitigations:
                md.append(f"#### M{mitigation.numericId}: {mitigation.content}")
                md.append("")
                
                # Find linked threats
                linked_threats = []
                for link in state.mitigation_links:
                    if link.mitigationId == mitigation.id:
                        if link.linkedId in state.threats:
                            threat = state.threats[link.linkedId]
                            linked_threats.append(f"T{threat.numericId}")
                
                if linked_threats:
                    md.append(f"**Addresses Threats**: {', '.join(linked_threats)}")
                    md.append("")
    else:
        md.append("*No mitigations defined.*")
        md.append("")
    
    # Assumptions
    md.append("## Assumptions")
    md.append("")
    if state.assumptions:
        for assumption_id, assumption in state.assumptions.items():
            md.append(f"### A{assumption.id.replace('A', '')}: {assumption.category}")
            md.append("")
            md.append(f"**Description**: {assumption.description}")
            md.append("")
            md.append(f"- **Impact**: {assumption.impact}")
            md.append(f"- **Rationale**: {assumption.rationale}")
            md.append("")
    else:
        md.append("*No assumptions defined.*")
        md.append("")
    
    # Phase Progress
    md.append("## Phase Progress")
    md.append("")
    md.append("| Phase | Name | Completion |")
    md.append("|---|---|---|")
    for phase_num in sorted(state.phases.keys()):
        phase_name = state.phases[phase_num]
        completion = state.phase_completion.get(phase_num, 0.0)
        completion_pct = f"{completion * 100:.0f}%"
        status = "✅" if completion >= 1.0 else ("🔄" if phase_num == state.current_phase else "⏳")
        md.append(f"| {phase_num} | {phase_name} | {completion_pct} {status} |")
    md.append("")
    
    # Footer
    md.append("---")
    md.append("")
    md.append("*This threat model report was generated automatically by the Threat Modeling MCP Server.*")
    md.append("")
    
    return "\n".join(md)


def export_comprehensive_threat_model_with_extended_data(output_path: str) -> str:
    """Export comprehensive threat model with all extended data to a separate file.
    
    This function creates a separate export with all the extended data that's not
    compatible with standard Threat Composer but useful for comprehensive analysis.
    
    Args:
        output_path: Path to save the exported threat model
        
    Returns:
        Confirmation message with export details
    """
    logger.info(f"Starting comprehensive threat model export with extended data to {output_path}")
    
    # Collect all state
    state = collect_all_state()
    
    # Normalize the output path to be in .threatmodel directory
    normalized_path = normalize_output_path(output_path)
    
    # Ensure the path ends with .json
    if not normalized_path.endswith('.json'):
        normalized_path += '.json'
    
    # Add "_extended" to the filename
    base_name = os.path.splitext(os.path.basename(normalized_path))[0]
    extended_filename = f"{base_name}_extended.json"
    
    # Create the .threatmodel directory if it doesn't exist
    threatmodel_dir = os.path.join(os.path.dirname(normalized_path), '.threatmodel')
    os.makedirs(threatmodel_dir, exist_ok=True)
    
    # Update the path to be in .threatmodel directory
    final_path = os.path.join(threatmodel_dir, extended_filename)
    
    # Create comprehensive threat model with ALL data
    threat_model = ThreatModel(schema=1)
    
    # Set application info from business context
    if state.business_context and state.business_context.description:
        threat_model.applicationInfo = {
            "name": "Threat Model Export (Extended)",
            "description": state.business_context.description
        }
    
    # Convert and add core Threat Composer data
    threat_model.assumptions = convert_assumptions_to_threat_composer_format(state.assumptions)
    threat_model.threats = convert_threats_to_threat_composer_format(state.threats)
    threat_model.mitigations = convert_mitigations_to_threat_composer_format(state.mitigations)
    
    # Add links
    threat_model.assumptionLinks = [link.dict() for link in state.assumption_links]
    threat_model.mitigationLinks = [link.dict() for link in state.mitigation_links]
    
    # Add extended data
    threat_model.businessContext = convert_business_context_to_dict(state.business_context)
    threat_model.components = convert_components_to_dict(state.components)
    threat_model.connections = convert_connections_to_dict(state.connections)
    threat_model.dataStores = convert_data_stores_to_dict(state.data_stores)
    threat_model.threatActors = convert_generic_objects_to_dict(state.threat_actors)
    threat_model.trustZones = convert_generic_objects_to_dict(state.trust_zones)
    threat_model.crossingPoints = convert_generic_objects_to_dict(state.crossing_points)
    threat_model.trustBoundaries = convert_generic_objects_to_dict(state.trust_boundaries)
    threat_model.assets = convert_generic_objects_to_dict(state.assets)
    threat_model.flows = convert_generic_objects_to_dict(state.flows)
    
    # Add phase progress information
    threat_model.phaseProgress = {
        "current_phase": state.current_phase,
        "current_phase_name": state.phases.get(state.current_phase, "Unknown"),
        "phase_completion": state.phase_completion,
        "phases": state.phases,
        "overall_completion": sum(state.phase_completion.values()) / len(state.phase_completion) if state.phase_completion else 0.0
    }
    
    # Add metadata
    threat_model.metadata = {
        "export_timestamp": datetime.now().isoformat(),
        "export_version": "1.0",
        "total_threats": len(state.threats),
        "total_mitigations": len(state.mitigations),
        "total_assumptions": len(state.assumptions),
        "total_components": len(state.components),
        "total_assets": len(state.assets),
        "includes_extended_data": True
    }
    
    # Write to file
    try:
        with open(final_path, "w", encoding="utf-8") as f:
            json.dump(threat_model.dict(), f, indent=2, ensure_ascii=False)
        
        logger.info(f"Successfully exported extended threat model to {final_path}")
        
        # Generate summary
        summary = f"""
# Extended Threat Model Export Complete

**Export Path**: {final_path}
**Export Timestamp**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Export Summary
- **Threats**: {len(state.threats)}
- **Mitigations**: {len(state.mitigations)}
- **Assumptions**: {len(state.assumptions)}
- **Components**: {len(state.components)}
- **Assets**: {len(state.assets)}
- **Threat Actors**: {len(state.threat_actors)}
- **Trust Zones**: {len(state.trust_zones)}
- **Data Stores**: {len(state.data_stores)}

## Current Phase
- **Phase**: {state.current_phase} - {state.phases.get(state.current_phase, 'Unknown')}
- **Overall Completion**: {sum(state.phase_completion.values()) / len(state.phase_completion) * 100:.1f}%

## File Details
- **Format**: Extended Threat Model JSON (with all global variables)
- **Schema Version**: 1
- **Extended Data**: Included
- **File Size**: {os.path.getsize(final_path)} bytes

This extended file contains all global variables and extended data for comprehensive analysis.
"""
        
        return summary.strip()
        
    except Exception as e:
        error_msg = f"Failed to export extended threat model: {str(e)}"
        logger.error(error_msg)
        return error_msg
