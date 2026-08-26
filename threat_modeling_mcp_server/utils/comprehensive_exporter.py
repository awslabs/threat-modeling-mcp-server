"""Comprehensive exporter for converting all global variables to Threat Composer JSON format."""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from loguru import logger

from threat_modeling_mcp_server.utils.state_collector import (
    collect_all_state,
    count_reviewed,
    model_state_fingerprint,
    split_reviewed,
    ThreatModelState,
)
from threat_modeling_mcp_server.utils.file_utils import normalize_output_path


last_successful_export_fingerprint: Optional[str] = None
last_successful_export_paths: Dict[str, str] = {}


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

    if business_context.sensitivity_tier:
        result["features"]["sensitivity_tier"] = business_context.sensitivity_tier.value

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

    if business_context.deployment_model:
        result["features"]["deployment_model"] = business_context.deployment_model.value

    if business_context.user_base_metric:
        result["features"]["user_base_metric"] = business_context.user_base_metric.value

    if business_context.revenue_band:
        result["features"]["revenue_band"] = business_context.revenue_band.value

    if business_context.geographic_profile:
        facets = {
            facet: level.value
            for facet, level in business_context.geographic_profile.model_dump().items()
            if level is not None
        }
        if facets:
            result["features"]["geographic_profile"] = facets


    return result


def convert_assumptions_to_threat_composer_format(assumptions: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert assumptions to Threat Composer format.

    Args:
        assumptions: Dictionary of assumption objects

    Returns:
        List of assumptions in Threat Composer format
    """
    result = []

    for assumption in assumptions.values():
        assumption_dict = {
            "id": assumption.id,
            "numericId": int(assumption.id.replace("A", "")) if assumption.id.startswith("A") else len(result) + 1,
            "content": assumption.description,
            "displayOrder": int(assumption.id.replace("A", "")) if assumption.id.startswith("A") else len(result) + 1,
            "metadata": []  # Keep metadata empty for Threat Composer compatibility
        }
        result.append(assumption_dict)

    return result


def _truncate(value: str, max_length: int) -> str:
    """Truncate a string to max_length, preserving whole words where possible."""
    if not value or len(value) <= max_length:
        return value
    # Try to break at last space before the limit
    truncated = value[:max_length]
    last_space = truncated.rfind(' ')
    if last_space > max_length * 0.6:
        return truncated[:last_space]
    return truncated


def convert_threats_to_threat_composer_format(threats: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert threats to Threat Composer format.

    Args:
        threats: Dictionary of threat objects

    Returns:
        List of threats in Threat Composer format
    """
    result = []

    for threat in threats.values():
        # Use our internal status directly (now compatible with Threat Composer)
        threat_status = threat.status.value if threat.status else "threatIdentified"

        # Enforce Threat Composer schema maxLength constraints
        threat_source = _truncate(threat.threatSource, 200)
        prerequisites = _truncate(threat.prerequisites, 200)
        threat_action = _truncate(threat.threatAction, 200)
        threat_impact = _truncate(threat.threatImpact, 200)
        statement = _truncate(threat.statement, 1400)
        impacted_goal = [_truncate(g, 200) for g in (threat.impactedGoal or [])]
        impacted_assets = [_truncate(a, 200) for a in (threat.impactedAssets or [])]
        tags = [_truncate(t, 30) for t in (threat.tags or [])]

        # Use only fields that are compatible with Threat Composer
        threat_dict = {
            "id": threat.id,
            "numericId": threat.numericId,
            "threatSource": threat_source,
            "prerequisites": prerequisites,
            "threatAction": threat_action,
            "threatImpact": threat_impact,
            "impactedGoal": impacted_goal,
            "impactedAssets": impacted_assets,
            "statement": statement,
            "displayOrder": threat.displayOrder,
            "status": threat_status,
            "tags": tags,
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

    for mitigation in mitigations.values():
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

    for component in components.values():
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

    for connection in connections.values():
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

    for data_store in data_stores.values():
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
    """Convert a dictionary of objects to a list of dictionaries.

    The dictionary key is preserved as "id" so exported records remain
    identifiable even when the model itself has no id field.

    Args:
        objects: Dictionary of objects keyed by id

    Returns:
        List of dictionaries, each carrying its id
    """
    result = []

    for object_id, obj in objects.items():
        if hasattr(obj, "model_dump"):
            data = obj.model_dump(mode="json")
        elif hasattr(obj, "dict"):
            data = obj.dict()
        elif isinstance(obj, dict):
            data = dict(obj)
        else:
            data = {"value": str(obj)}

        if not data.get("id"):
            data["id"] = object_id
        result.append(data)

    return result


def convert_residual_assessments_to_dict(state) -> List[Dict[str, Any]]:
    """Convert residual-risk records without exposing internal fingerprints."""
    from threat_modeling_mcp_server.tools.threat_generator import (
        is_residual_assessment_current,
    )

    result = []
    for threat_id, assessment in state.residual_risk_assessments.items():
        result.append({
            "threat_id": threat_id,
            "decision": assessment.decision.value,
            "residual_severity": (
                assessment.residual_severity.value
                if assessment.residual_severity else None
            ),
            "residual_likelihood": (
                assessment.residual_likelihood.value
                if assessment.residual_likelihood else None
            ),
            "rationale": assessment.rationale,
            "is_current": is_residual_assessment_current(threat_id),
        })
    return result


def build_extended_export_data(state) -> Dict[str, Any]:
    """Build the non-Threat-Composer keys, including classification profiles.

    Used by both the standard export (when include_extended_data is set) and the
    separate extended export so the two cannot drift apart.

    Args:
        state: Collected ThreatModelState

    Returns:
        Dictionary of extended export keys
    """
    threat_actors, unreviewed_actors = split_reviewed(state.threat_actors)
    assets = state.assets
    flows = state.flows

    return {
        "businessContext": convert_business_context_to_dict(state.business_context),
        "components": convert_components_to_dict(state.components),
        "connections": convert_connections_to_dict(state.connections),
        "dataStores": convert_data_stores_to_dict(state.data_stores),
        "threatActors": convert_generic_objects_to_dict(threat_actors),
        "trustZones": convert_generic_objects_to_dict(state.trust_zones),
        "crossingPoints": convert_generic_objects_to_dict(state.crossing_points),
        "trustBoundaries": convert_generic_objects_to_dict(state.trust_boundaries),
        "assets": convert_generic_objects_to_dict(assets),
        "flows": convert_generic_objects_to_dict(flows),
        "residualRiskAssessments": convert_residual_assessments_to_dict(state),
        "softwareProfile": (
            state.software_profile.model_dump(mode="json") if state.software_profile else {}
        ),
        "dataAssetProfiles": convert_generic_objects_to_dict(state.data_asset_profiles),
        "userPersonas": convert_generic_objects_to_dict(state.user_personas),
        "nonFunctionalRequirements": [
            r.model_dump(mode="json") for r in state.nfr_requirements
        ],
        "phaseProgress": {
            "current_phase": state.current_phase,
            "current_phase_name": state.phases.get(state.current_phase, "Unknown"),
            "phase_completion": state.phase_completion,
            "phases": state.phases,
            "overall_completion": (
                sum(state.phase_completion.values()) / len(state.phase_completion)
                if state.phase_completion else 0.0
            ),
        },
        "referenceCatalogue": {
            "description": (
                "Threat actors the server pre-loaded but that were never assessed "
                "for this system. These are NOT part of the threat model."
            ),
            "threatActors": convert_generic_objects_to_dict(unreviewed_actors),
        },
    }


def export_threat_model_files(
    output_path: str,
    include_extended_data: bool = True,
) -> str:
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
    export_fingerprint = model_state_fingerprint(state)
    # A successful write of this snapshot satisfies Phase 9. Use a copied
    # progress mapping so the exported files describe their resulting state
    # without changing live workflow state before both files succeed.
    state.phase_completion = dict(state.phase_completion)
    state.phase_completion[9] = 1.0

    # Normalize the output path to be in .threatmodel directory
    normalized_path = normalize_output_path(output_path)

    # Remove any existing extension to create base path
    base_path = os.path.splitext(normalized_path)[0]
    # Strip a trailing ".tc" so a caller-supplied ".tc.json" path does not
    # produce ".tc.tc.json"
    if base_path.endswith('.tc'):
        base_path = base_path[:-len('.tc')]

    # Create the .threatmodel directory if it doesn't exist
    threatmodel_dir = os.path.join(os.path.dirname(base_path), '.threatmodel')
    os.makedirs(threatmodel_dir, exist_ok=True)

    # Create paths for both formats
    base_filename = os.path.basename(base_path)
    json_path = os.path.join(threatmodel_dir, f"{base_filename}.tc.json")
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
            "assumptionLinks": [],
            "mitigationLinks": [link.dict() for link in state.mitigation_links],
            "threats": convert_threats_to_threat_composer_format(state.threats)
        }

        if include_extended_data:
            threat_model_data.update(build_extended_export_data(state))

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
        global last_successful_export_fingerprint, last_successful_export_paths
        last_successful_export_fingerprint = export_fingerprint
        last_successful_export_paths = {
            "json": json_path,
            "markdown": markdown_path,
        }
        try:
            from threat_modeling_mcp_server.tools.step_orchestrator import (
                detect_phase_completion,
            )
            detect_phase_completion()
        except Exception as e:
            logger.warning(f"Failed to refresh phase completion after export: {e}")
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
- **Threat Actors**: {count_reviewed(state.threat_actors)}
- **Trust Zones**: {len(state.trust_zones)}
- **Data Stores**: {len(state.data_stores)}

## Current Phase
- **Phase**: {state.current_phase} - {state.phases.get(state.current_phase, 'Unknown')}
- **Overall Completion**: {sum(state.phase_completion.values()) / len(state.phase_completion) * 100:.1f}%

## Exported Files"""

    json_format_label = (
        "Threat Composer JSON plus extended taxonomy keys "
        "(softwareProfile, dataAssetProfiles, userPersonas, "
        "nonFunctionalRequirements, residualRiskAssessments, businessContext, "
        "phaseProgress). Threat "
        "Composer ignores unknown keys, so the file still imports."
        if include_extended_data
        else "Threat Composer JSON (standard fields only)"
    )

    if json_success:
        summary += f"""

### JSON Export
- **Path**: {json_path}
- **Format**: {json_format_label}
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
        if include_extended_data:
            summary += (
                "\n\nThe JSON file imports into AWS Threat Composer, which ignores the "
                "extended taxonomy keys. Pass include_extended_data=False for a file "
                "containing standard schema fields only."
            )
        else:
            summary += (
                "\n\nThe JSON file is fully compatible with AWS Threat Composer and "
                "contains only standard schema fields."
            )

    if markdown_success:
        summary += "\nThe Markdown file contains a comprehensive, human-readable threat model report with all sections and data."

    return summary.strip()


def generate_threat_model_markdown(state: ThreatModelState) -> str:
    """Generate comprehensive threat model markdown content.

    Args:
        state: ThreatModelState containing all threat model data

    Returns:
        Markdown formatted threat model content
    """
    md = []

    threat_actors, unreviewed_actors = split_reviewed(state.threat_actors)
    trust_zones = state.trust_zones
    trust_boundaries = state.trust_boundaries
    assets = state.assets
    flows = state.flows

    def node_label(node_id: str) -> str:
        node = state.components.get(node_id) or state.data_stores.get(node_id)
        return f"{node.name} ({node_id})" if node else node_id

    catalogue = [("Threat Actors", unreviewed_actors)] if unreviewed_actors else []

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
    md.append("3. [Classification Profiles](#classification-profiles)")
    md.append("4. [System Architecture](#system-architecture)")
    md.append("5. [Threat Actors](#threat-actors)")
    md.append("6. [Trust Boundaries](#trust-boundaries)")
    md.append("7. [Assets and Flows](#assets-and-flows)")
    md.append("8. [Threats](#threats)")
    md.append("9. [Mitigations](#mitigations)")
    md.append("10. [Assumptions](#assumptions)")
    md.append("11. [Phase Progress](#phase-progress)")
    if catalogue:
        md.append(
            "12. [Appendix: Reference Catalogue (Not Reviewed)]"
            "(#appendix-reference-catalogue-not-reviewed)"
        )
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
    md.append(f"- **Assets**: {len(assets)}")
    md.append(f"- **Threat Actors**: {len(threat_actors)}")
    if catalogue:
        skipped = sum(len(records) for _, records in catalogue)
        md.append(
            f"- **Pre-loaded catalogue entries never assessed**: {skipped} "
            "(listed in the appendix, excluded from the counts above)"
        )
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
        if state.business_context.sensitivity_tier:
            md.append(f"- **Data Sensitivity**: {state.business_context.sensitivity_tier.value}")
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
        if state.business_context.deployment_model:
            md.append(f"- **Deployment Model**: {state.business_context.deployment_model.value}")
        if state.business_context.user_base_metric:
            md.append(f"- **User Base Metric**: {state.business_context.user_base_metric.value}")
        if state.business_context.revenue_band:
            md.append(f"- **Revenue Band**: {state.business_context.revenue_band.value}")
        if state.business_context.geographic_profile:
            for label, field in [
                ("Data Residency", "data_residency"),
                ("Compute Location", "compute_location"),
                ("User Base Location", "user_base_location"),
                ("Organizational HQ", "organizational_headquarters"),
            ]:
                level = getattr(state.business_context.geographic_profile, field)
                if level:
                    md.append(f"- **{label}**: {level.value}")
        md.append("")
    else:
        md.append("*No business context defined.*")
        md.append("")

    # Classification Profiles
    md.append("## Classification Profiles")
    md.append("")

    if state.software_profile:
        profile = state.software_profile
        md.append("### Software Profile")
        md.append("")
        md.append(f"- **Software Type**: {profile.software_type.value}")
        for label, value in [
            ("Deployment Model", profile.deployment_model),
            ("Architecture Style", profile.architecture_style),
            ("Platform / Runtime", profile.platform_runtime),
            ("User Domain", profile.user_domain),
            ("Licensing / Ownership", profile.licensing_ownership),
        ]:
            if value:
                md.append(f"- **{label}**: {value.value}")
        if profile.modern_paradigms:
            md.append(f"- **Modern Paradigms**: {', '.join(p.value for p in profile.modern_paradigms)}")
        if profile.description:
            md.append(f"- **Description**: {profile.description}")
        md.append("")

    if state.data_asset_profiles:
        md.append("### Data Asset Profiles")
        md.append("")
        md.append(
            "| ID | Name | Asset | Category | Content Types | Sensitivity | "
            "Compliance | States | Volume | Lifecycle | Business Domain | Description |"
        )
        md.append("|---|---|---|---|---|---|---|---|---|---|---|---|")
        for profile_id, profile in state.data_asset_profiles.items():
            content = ", ".join(c.value for c in profile.content_types) or "N/A"
            states = ", ".join(d.value for d in profile.data_states) or "N/A"
            compliance = ", ".join(c.value for c in profile.compliance_regimes) or "N/A"
            sensitivity = profile.sensitivity_tier.value if profile.sensitivity_tier else "N/A"
            lifecycle = profile.lifecycle_state.value if profile.lifecycle_state else "N/A"
            volume = profile.volume_tier.value if profile.volume_tier else "N/A"
            domain = profile.business_domain.value if profile.business_domain else "N/A"
            md.append(
                f"| {profile_id} | {profile.name or 'N/A'} | {profile.asset_id or 'N/A'} | "
                f"{profile.structural_category.value} | {content} | {sensitivity} | "
                f"{compliance} | {states} | {volume} | {lifecycle} | {domain} | "
                f"{profile.description or 'N/A'} |"
            )
        md.append("")

    if state.user_personas:
        md.append("### User Personas")
        md.append("")
        md.append(
            "| ID | Persona | Name | Privilege | Affiliation | Roles | Intent | "
            "Entity Type | Authentication | Threat Actor Overlay | In Scope | "
            "Description |"
        )
        md.append("|---|---|---|---|---|---|---|---|---|---|---|---|")
        for persona_id, persona in state.user_personas.items():
            privilege = persona.privilege_level.value if persona.privilege_level else "N/A"
            affiliation = (
                persona.organizational_affiliation.value
                if persona.organizational_affiliation else "N/A"
            )
            entity = persona.entity_type.value if persona.entity_type else "N/A"
            roles = ", ".join(r.value for r in persona.functional_roles) or "N/A"
            auth = (
                persona.authentication_method.value
                if persona.authentication_method else "N/A"
            )
            overlay = ", ".join(persona.threat_actor_overlay) or "N/A"
            md.append(
                f"| {persona_id} | {persona.persona_type.value} | "
                f"{persona.name or 'N/A'} | {privilege} | {affiliation} | {roles} | "
                f"{persona.intent_behavior.value} | {entity} | {auth} | {overlay} | "
                f"{'Yes' if persona.is_relevant else 'No'} | "
                f"{persona.description or 'N/A'} |"
            )
        md.append("")

    if state.nfr_requirements:
        md.append("### Non-Functional Requirements")
        md.append("")
        for requirement in state.nfr_requirements:
            line = f"- **{requirement.quality_class.value}**: {requirement.level}"
            if requirement.rationale:
                line += f" — {requirement.rationale}"
            md.append(line)
        md.append("")

    if not (state.software_profile or state.data_asset_profiles
            or state.user_personas or state.nfr_requirements):
        md.append("*No classification profiles defined.*")
        md.append("")

    # System Architecture
    md.append("## System Architecture")
    md.append("")

    if state.components:
        md.append("### Components")
        md.append("")
        md.append("| ID | Name | Type | Service Provider | Description |")
        md.append("|---|---|---|---|---|")
        for comp in state.components.values():
            provider = comp.service_provider.value if comp.service_provider else "N/A"
            description = comp.description or "N/A"
            md.append(f"| {comp.id} | {comp.name} | {comp.type.value} | {provider} | {description} |")
        md.append("")

    if state.connections:
        md.append("### Connections")
        md.append("")
        md.append("| ID | Source | Destination | Protocol | Port | Encrypted | Description |")
        md.append("|---|---|---|---|---|---|---|")
        for conn in state.connections.values():
            protocol = conn.protocol.value if conn.protocol else "N/A"
            port = str(conn.port) if conn.port else "N/A"
            encrypted = "Yes" if conn.encryption else "No"
            description = conn.description or "N/A"
            md.append(
                f"| {conn.id} | {node_label(conn.source_id)} | "
                f"{node_label(conn.destination_id)} | {protocol} | {port} | "
                f"{encrypted} | {description} |"
            )
        md.append("")

    if state.data_stores:
        md.append("### Data Stores")
        md.append("")
        md.append("| ID | Name | Type | Classification | Encrypted at Rest | Description |")
        md.append("|---|---|---|---|---|---|")
        for ds in state.data_stores.values():
            encrypted = "Yes" if ds.encryption_at_rest else "No"
            description = ds.description or "N/A"
            md.append(f"| {ds.id} | {ds.name} | {ds.type.value} | {ds.classification.value} | {encrypted} | {description} |")
        md.append("")

    # Threat Actors
    md.append("## Threat Actors")
    md.append("")
    if threat_actors:
        for actor in threat_actors.values():
            md.append(f"### {actor.name}")
            md.append("")
            md.append(f"- **Type**: {actor.type.value}")
            md.append(f"- **Motivations**: {', '.join(m.value for m in actor.motivations)}")
            md.append(f"- **Resources**: {actor.resources.value}")
            if actor.relationship_to_target:
                md.append(f"- **Relationship to Target**: {actor.relationship_to_target.value}")
            if actor.sophistication_tier:
                md.append(f"- **Sophistication Tier**: {actor.sophistication_tier.value}")
            if actor.state_nexus:
                md.append(f"- **State Nexus**: {actor.state_nexus.value}")
            if actor.targeting_specificity:
                md.append(f"- **Targeting Specificity**: {actor.targeting_specificity.value}")
            md.append(f"- **Relevant**: {'Yes' if actor.is_relevant else 'No'}")
            if actor.priority > 0:
                md.append(f"- **Priority**: {actor.priority}/10")
            if actor.description:
                md.append(f"- **Description**: {actor.description}")
            md.append("")
    else:
        md.append("*No threat actors reviewed for this system.*")
        md.append("")

    # Trust Boundaries
    md.append("## Trust Boundaries")
    md.append("")

    if trust_zones:
        md.append("### Trust Zones")
        md.append("")
        for zone in trust_zones.values():
            md.append(f"#### {zone.name}")
            md.append("")
            md.append(f"- **Trust Level**: {zone.trust_level.value}")
            if zone.contained_nodes:
                md.append(
                    f"- **Architecture Nodes**: "
                    + ", ".join(node_label(node_id) for node_id in zone.contained_nodes)
                )
            if zone.description:
                md.append(f"- **Description**: {zone.description}")
            md.append("")

    if trust_boundaries:
        md.append("### Trust Boundaries")
        md.append("")
        for boundary in trust_boundaries.values():
            md.append(f"#### {boundary.name}")
            md.append("")
            md.append(f"- **Type**: {boundary.type.value}")
            if boundary.controls:
                md.append(f"- **Controls**: {', '.join(boundary.controls)}")
            if boundary.description:
                md.append(f"- **Description**: {boundary.description}")
            md.append("")

    if not trust_zones and not trust_boundaries:
        md.append("*No trust zones or boundaries defined for this system.*")
        md.append("")

    # Assets and Flows
    md.append("## Assets and Flows")
    md.append("")

    if assets:
        md.append("### Assets")
        md.append("")
        md.append(
            "| ID | Name | Type | Classification | Lifecycle | Data States | "
            "Criticality | Owner |"
        )
        md.append("|---|---|---|---|---|---|---|---|")
        for asset in assets.values():
            criticality = str(asset.criticality) if asset.criticality else "N/A"
            owner = asset.owner or "N/A"
            lifecycle = asset.lifecycle_state.value if asset.lifecycle_state else "N/A"
            data_states = ", ".join(d.value for d in asset.data_states) or "N/A"
            md.append(
                f"| {asset.id} | {asset.name} | {asset.type.value} | "
                f"{asset.classification.value} | {lifecycle} | {data_states} | "
                f"{criticality} | {owner} |"
            )
        md.append("")

    if flows:
        md.append("### Asset Flows")
        md.append("")
        md.append("| ID | Asset | Source | Destination | Protocol | Encrypted | Risk Level |")
        md.append("|---|---|---|---|---|---|---|")
        for flow in flows.values():
            # Find asset name
            asset_name = "Unknown"
            if flow.asset_id in state.assets:
                asset_name = state.assets[flow.asset_id].name

            protocol = flow.protocol or "N/A"
            encrypted = "Yes" if flow.encryption else "No"
            risk_level = str(flow.risk_level) if flow.risk_level else "N/A"
            md.append(
                f"| {flow.id} | {asset_name} | {node_label(flow.source_id)} | "
                f"{node_label(flow.destination_id)} | {protocol} | {encrypted} | "
                f"{risk_level} |"
            )
        md.append("")

    if not assets and not flows:
        md.append("*No assets or flows defined for this system.*")
        md.append("")

    # Threats
    md.append("## Threats")
    md.append("")
    if state.threats:
        # Group threats by status
        threats_by_status = {}
        for threat in state.threats.values():
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
                assessment = state.residual_risk_assessments.get(threat.id)
                if assessment:
                    from threat_modeling_mcp_server.tools.threat_generator import (
                        is_residual_assessment_current,
                    )

                    md.append(
                        f"- **Residual Risk Decision**: {assessment.decision.value}"
                    )
                    if assessment.residual_severity:
                        md.append(
                            "- **Residual Severity**: "
                            f"{assessment.residual_severity.value}"
                        )
                    if assessment.residual_likelihood:
                        md.append(
                            "- **Residual Likelihood**: "
                            f"{assessment.residual_likelihood.value}"
                        )
                    md.append(
                        f"- **Residual Risk Rationale**: {assessment.rationale}"
                    )
                    md.append(
                        "- **Assessment State**: "
                        + (
                            "Current"
                            if is_residual_assessment_current(threat.id)
                            else "Stale"
                        )
                    )
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
        for mitigation in state.mitigations.values():
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
        for assumption in state.assumptions.values():
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

    if catalogue:
        md.append("## Appendix: Reference Catalogue (Not Reviewed)")
        md.append("")
        md.append(
            "The server pre-loads common threat actors as a starting point. "
            "Entries that were never assessed for this system are not part of "
            "the threat model and are listed here only as reference."
        )
        md.append("")
        for label, records in catalogue:
            md.append(f"### {label} ({len(records)} not reviewed)")
            md.append("")
            for record_id, record in records.items():
                entry_summary = (
                    getattr(record, "name", None)
                    or getattr(record, "description", None)
                    or "no description"
                )
                md.append(f"- **{record_id}** - {entry_summary}")
            md.append("")

    # Footer
    md.append("---")
    md.append("")
    md.append("*This threat model report was generated automatically by the Threat Modeling MCP Server.*")
    md.append("")

    return "\n".join(md)
