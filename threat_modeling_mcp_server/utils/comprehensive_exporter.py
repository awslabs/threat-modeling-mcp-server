"""Comprehensive exporter for converting all global variables to Threat Composer JSON format."""

import json
import os
import uuid
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
from threat_modeling_mcp_server.utils.file_utils import resolve_export_paths


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


# Fixed namespace for export ids. It equals
# uuid5(NAMESPACE_URL,
#       "https://github.com/awslabs/threat-modeling-mcp-server/threat-composer-export")
# and must never change, or re-exports would stop matching earlier imports.
THREAT_COMPOSER_ID_NAMESPACE = uuid.UUID("caf6357f-63b2-5e2e-aaf3-d0fbe88ff6cd")
_THREAT_COMPOSER_ENTITY_TYPES = frozenset({"threat", "mitigation", "assumption"})

# The only top-level keys Threat Composer's strict import schema accepts.
THREAT_COMPOSER_TOP_LEVEL_KEYS = frozenset({
    "schema", "applicationInfo", "architecture", "dataflow", "assumptions",
    "mitigations", "assumptionLinks", "mitigationLinks", "threats",
})

# Threat Composer schema length limits.
TEXT_FIELD_LIMIT = 200
STATEMENT_LIMIT = 1400
TAG_LIMIT = 30
CONTENT_LIMIT = 1000
APPLICATION_DESCRIPTION_LIMIT = 100000

MAX_EXPORT_WARNING_LINES = 20


def to_threat_composer_id(entity_type: str, internal_id: str) -> str:
    """Map a readable internal id to a deterministic Threat Composer UUID.

    The entity type is part of the name, so ids that collide across types
    (for example a threat and a mitigation) still map to different UUIDs.

    Args:
        entity_type: One of "threat", "mitigation", or "assumption"
        internal_id: Internal id such as "T001"

    Returns:
        A 36-character UUIDv5 string
    """
    if entity_type not in _THREAT_COMPOSER_ENTITY_TYPES:
        raise ValueError(f"Unknown Threat Composer entity type: {entity_type}")
    return str(uuid.uuid5(THREAT_COMPOSER_ID_NAMESPACE, f"{entity_type}:{internal_id}"))


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


class ExportWarnings:
    """Collect content-free records of fields shortened for the strict export."""

    def __init__(self) -> None:
        self._records: Dict[tuple, tuple] = {}

    def truncate(
        self,
        value: str,
        limit: int,
        entity_type: str,
        internal_id: str,
        field: str,
    ) -> str:
        """Apply a Threat Composer limit and record it if the value changed."""
        result = _truncate(value, limit)
        if result != value:
            self._records[(entity_type, internal_id, field)] = (
                len(value), len(result), limit,
            )
        return result

    def __len__(self) -> int:
        return len(self._records)

    def lines(self) -> List[str]:
        """Bounded warning lines with lengths only, never field contents."""
        lines = [
            f"- {entity_type} {internal_id} {field}: shortened from "
            f"{original} to {result} characters (Threat Composer limit {limit})"
            for (entity_type, internal_id, field), (original, result, limit)
            in list(self._records.items())[:MAX_EXPORT_WARNING_LINES]
        ]
        remaining = len(self._records) - MAX_EXPORT_WARNING_LINES
        if remaining > 0:
            lines.append(f"- … and {remaining} more field(s) shortened")
        return lines


def convert_assumptions_to_threat_composer_format(
    assumptions: Dict[str, Any],
    warnings: Optional[ExportWarnings] = None,
) -> List[Dict[str, Any]]:
    """Convert assumptions to Threat Composer format.

    Args:
        assumptions: Dictionary of assumption objects
        warnings: Collector for fields shortened to schema limits

    Returns:
        List of assumptions in Threat Composer format
    """
    warnings = warnings if warnings is not None else ExportWarnings()
    result = []

    for assumption in assumptions.values():
        assumption_dict = {
            "id": to_threat_composer_id("assumption", assumption.id),
            "numericId": int(assumption.id.replace("A", "")) if assumption.id.startswith("A") else len(result) + 1,
            "content": warnings.truncate(
                assumption.description, CONTENT_LIMIT,
                "assumption", assumption.id, "content",
            ),
            "displayOrder": int(assumption.id.replace("A", "")) if assumption.id.startswith("A") else len(result) + 1,
            "metadata": []  # Keep metadata empty for Threat Composer compatibility
        }
        result.append(assumption_dict)

    return result


def convert_threats_to_threat_composer_format(
    threats: Dict[str, Any],
    warnings: Optional[ExportWarnings] = None,
) -> List[Dict[str, Any]]:
    """Convert threats to Threat Composer format.

    Args:
        threats: Dictionary of threat objects
        warnings: Collector for fields shortened to schema limits

    Returns:
        List of threats in Threat Composer format
    """
    warnings = warnings if warnings is not None else ExportWarnings()
    result = []

    for threat in threats.values():
        # Use our internal status directly (now compatible with Threat Composer)
        threat_status = threat.status.value if threat.status else "threatIdentified"

        def cut(value: str, limit: int, field: str) -> str:
            return warnings.truncate(value, limit, "threat", threat.id, field)

        # Enforce Threat Composer schema maxLength constraints
        threat_source = cut(threat.threatSource, TEXT_FIELD_LIMIT, "threatSource")
        prerequisites = cut(threat.prerequisites, TEXT_FIELD_LIMIT, "prerequisites")
        threat_action = cut(threat.threatAction, TEXT_FIELD_LIMIT, "threatAction")
        threat_impact = cut(threat.threatImpact, TEXT_FIELD_LIMIT, "threatImpact")
        statement = cut(threat.statement, STATEMENT_LIMIT, "statement")
        impacted_goal = [
            cut(goal, TEXT_FIELD_LIMIT, f"impactedGoal[{index}]")
            for index, goal in enumerate(threat.impactedGoal or [])
        ]
        impacted_assets = [
            cut(asset, TEXT_FIELD_LIMIT, f"impactedAssets[{index}]")
            for index, asset in enumerate(threat.impactedAssets or [])
        ]
        tags = [
            cut(tag, TAG_LIMIT, f"tags[{index}]")
            for index, tag in enumerate(threat.tags or [])
        ]

        # Use only fields that are compatible with Threat Composer
        threat_dict = {
            "id": to_threat_composer_id("threat", threat.id),
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


def convert_mitigations_to_threat_composer_format(
    mitigations: Dict[str, Any],
    warnings: Optional[ExportWarnings] = None,
) -> List[Dict[str, Any]]:
    """Convert mitigations to Threat Composer format.

    Args:
        mitigations: Dictionary of mitigation objects
        warnings: Collector for fields shortened to schema limits

    Returns:
        List of mitigations in Threat Composer format
    """
    warnings = warnings if warnings is not None else ExportWarnings()
    result = []

    for mitigation in mitigations.values():
        # Use our internal status directly (now compatible with Threat Composer)
        mitigation_status = mitigation.status.value if mitigation.status else "mitigationIdentified"

        # Use only fields that are compatible with Threat Composer
        mitigation_dict = {
            "id": to_threat_composer_id("mitigation", mitigation.id),
            "numericId": mitigation.numericId,
            "status": mitigation_status,
            "content": warnings.truncate(
                mitigation.content, CONTENT_LIMIT,
                "mitigation", mitigation.id, "content",
            ),
            "displayOrder": mitigation.displayOrder,
            "metadata": []  # Keep metadata empty for Threat Composer compatibility
        }

        result.append(mitigation_dict)

    return result


def convert_mitigation_links_to_threat_composer_format(state) -> List[Dict[str, str]]:
    """Map mitigation links to Threat Composer UUIDs.

    Only links whose mitigation and threat are both exported are kept, so every
    reference resolves to an entity in the same file.
    """
    return [
        {
            "mitigationId": to_threat_composer_id("mitigation", link.mitigationId),
            "linkedId": to_threat_composer_id("threat", link.linkedId),
        }
        for link in state.mitigation_links
        if link.mitigationId in state.mitigations and link.linkedId in state.threats
    ]


def convert_assumption_links_to_threat_composer_format(state) -> List[Dict[str, str]]:
    """Map assumption links to Threat Composer UUIDs.

    The server does not record assumption links yet, so this returns an empty
    list. Any future links must map ``assumptionId`` with
    ``to_threat_composer_id("assumption", ...)`` and ``linkedId`` with the
    linked entity's type, mirroring the mitigation links.
    """
    return []


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

    These keys go only into the separate ``.extended.json`` snapshot, never
    into the strict ``.tc.json``.

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


def build_threat_composer_data(
    state,
    warnings: Optional[ExportWarnings] = None,
) -> Dict[str, Any]:
    """Build the strict Threat Composer import document.

    The result only ever contains THREAT_COMPOSER_TOP_LEVEL_KEYS, uses UUIDv5
    ids, and applies the schema length limits, recording each shortened
    field in ``warnings``.
    """
    warnings = warnings if warnings is not None else ExportWarnings()
    description = (
        state.business_context.description
        if state.business_context and state.business_context.description
        else ""
    )
    data = {
        "schema": 1,
        "applicationInfo": {
            "name": "Threat Model Export",
            "description": warnings.truncate(
                description, APPLICATION_DESCRIPTION_LIMIT,
                "applicationInfo", "-", "description",
            ),
        },
        "architecture": {
            "description": ""
        },
        "dataflow": {
            "description": ""
        },
        "assumptions": convert_assumptions_to_threat_composer_format(
            state.assumptions, warnings
        ),
        "mitigations": convert_mitigations_to_threat_composer_format(
            state.mitigations, warnings
        ),
        "assumptionLinks": convert_assumption_links_to_threat_composer_format(state),
        "mitigationLinks": convert_mitigation_links_to_threat_composer_format(state),
        "threats": convert_threats_to_threat_composer_format(state.threats, warnings),
    }
    unexpected = set(data) - THREAT_COMPOSER_TOP_LEVEL_KEYS
    if unexpected:  # pragma: no cover - guards future edits
        raise ValueError(
            "Threat Composer export has unsupported top-level keys: "
            + ", ".join(sorted(unexpected))
        )
    return data


def build_extended_snapshot_data(state, threat_composer_filename: str) -> Dict[str, Any]:
    """Build the separate full server-state snapshot.

    This document is not a Threat Composer file. It keeps internal ids and the
    full, unshortened text.
    """
    return {
        "exportType": "threat-modeling-mcp-server-extended-snapshot",
        "importableIntoThreatComposer": False,
        "notice": (
            "Full server state snapshot. Not a Threat Composer import file; "
            f"import {threat_composer_filename} instead."
        ),
        "threatComposerFile": threat_composer_filename,
        "threats": [t.model_dump(mode="json") for t in state.threats.values()],
        "mitigations": [m.model_dump(mode="json") for m in state.mitigations.values()],
        "assumptions": [a.model_dump(mode="json") for a in state.assumptions.values()],
        "mitigationLinks": [
            link.model_dump(mode="json") for link in state.mitigation_links
        ],
        **build_extended_export_data(state),
    }


def export_threat_model_files(
    output_path: str,
    project_directory: str,
    include_extended_data: bool = True,
) -> str:
    """Export the threat model to strict Threat Composer JSON and Markdown.

    Args:
        output_path: Requested base filename; directory components are ignored
        project_directory: Authoritative directory being threat modeled
        include_extended_data: Whether to also write a separate
            ``<base>.extended.json`` server-state snapshot. The ``.tc.json``
            is always strict.

    Returns:
        Confirmation message with export details for every artifact
    """
    # Paths and the caller-supplied filename are not logged.
    logger.info(
        "Starting comprehensive threat model export "
        f"(extended snapshot: {include_extended_data})"
    )

    # Update phase completion before collecting state
    try:
        from threat_modeling_mcp_server.tools.step_orchestrator import detect_phase_completion
        detect_phase_completion()
    except Exception as e:
        logger.warning(f"Failed to update phase completion: {type(e).__name__}")

    # Collect all state
    state = collect_all_state()
    export_fingerprint = model_state_fingerprint(state)
    # A successful write of this snapshot satisfies Phase 9. Use a copied
    # progress mapping so the exported files describe their resulting state
    # without changing live workflow state before every requested file succeeds.
    state.phase_completion = dict(state.phase_completion)
    state.phase_completion[9] = 1.0

    json_path, markdown_path, extended_path = resolve_export_paths(
        project_directory,
        output_path,
    )
    warnings = ExportWarnings()

    # Export JSON format
    json_success = False
    json_size = 0
    try:
        threat_model_data = build_threat_composer_data(state, warnings)

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(threat_model_data, f, indent=2, ensure_ascii=False)

        json_size = os.path.getsize(json_path)
        json_success = True
        logger.info(f"Successfully exported JSON threat model ({json_size} bytes)")

    except Exception as e:
        # Log the exception type only so serializer errors cannot leak model text.
        logger.error(f"Failed to export JSON threat model: {type(e).__name__}")

    # Export Markdown format
    markdown_success = False
    markdown_size = 0
    try:
        markdown_content = generate_threat_model_markdown(state)

        with open(markdown_path, "w", encoding="utf-8") as f:
            f.write(markdown_content)

        markdown_size = os.path.getsize(markdown_path)
        markdown_success = True
        logger.info(
            f"Successfully exported Markdown threat model ({markdown_size} bytes)"
        )

    except Exception as e:
        logger.error(f"Failed to export Markdown threat model: {type(e).__name__}")

    # Export the separate, non-importable extended snapshot when requested
    extended_success = False
    extended_size = 0
    if include_extended_data:
        try:
            extended_data = build_extended_snapshot_data(
                state, os.path.basename(json_path)
            )

            with open(extended_path, "w", encoding="utf-8") as f:
                json.dump(extended_data, f, indent=2, ensure_ascii=False)

            extended_size = os.path.getsize(extended_path)
            extended_success = True
            logger.info(
                f"Successfully exported extended snapshot ({extended_size} bytes)"
            )

        except Exception as e:
            logger.error(f"Failed to export extended snapshot: {type(e).__name__}")

    if warnings:
        logger.warning(
            f"Export shortened {len(warnings)} field(s) to Threat Composer limits"
        )

    # Phase 9 needs every requested artifact for this snapshot.
    artifacts = [("JSON", json_success), ("Markdown", markdown_success)]
    if include_extended_data:
        artifacts.append(("Extended snapshot", extended_success))
    failed = [name for name, success in artifacts if not success]

    # Generate comprehensive summary
    if not failed:
        global last_successful_export_fingerprint, last_successful_export_paths
        last_successful_export_fingerprint = export_fingerprint
        last_successful_export_paths = {
            "json": json_path,
            "markdown": markdown_path,
        }
        if include_extended_data:
            last_successful_export_paths["extended"] = extended_path
        try:
            from threat_modeling_mcp_server.tools.step_orchestrator import (
                detect_phase_completion,
            )
            detect_phase_completion()
        except Exception as e:
            logger.warning(
                "Failed to refresh phase completion after export: "
                f"{type(e).__name__}"
            )
        status = "✅ All requested files exported successfully"
    elif len(failed) == len(artifacts):
        status = "❌ All exports failed"
    else:
        status = f"⚠️ Export incomplete; failed: {', '.join(failed)}"

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

    def artifact_status(success: bool) -> str:
        return "✅ Successfully exported" if success else "❌ Failed"

    summary += f"""

### JSON Export
- **Path**: {json_path}
- **Format**: Threat Composer JSON (strict import schema; import this file)
- **Schema Version**: 1
- **File Size**: {json_size} bytes
- **Status**: {artifact_status(json_success)}"""

    summary += f"""

### Markdown Export (Human-Readable Report)
- **Path**: {markdown_path}
- **Format**: Comprehensive Markdown Report
- **File Size**: {markdown_size} bytes
- **Status**: {artifact_status(markdown_success)}"""

    if include_extended_data:
        summary += f"""

### Extended Snapshot Export
- **Path**: {extended_path}
- **Format**: Extended server-state snapshot (NOT importable into Threat Composer)
- **File Size**: {extended_size} bytes
- **Status**: {artifact_status(extended_success)}"""

    if json_success:
        summary += (
            "\n\nOnly the `.tc.json` file is meant for AWS Threat Composer import. "
            "It contains only the standard Threat Composer schema fields."
        )
        if include_extended_data:
            summary += (
                " The `.extended.json` file holds the full server state "
                "(architecture, taxonomy profiles, residual risk, phase progress) "
                "with internal ids and full text; it is not a Threat Composer file. "
                "Pass include_extended_data=False to skip it."
            )

    if markdown_success:
        summary += "\nThe Markdown file contains a comprehensive, human-readable threat model report with all sections and data."

    if warnings:
        full_text_holders = (
            "The stored model, Markdown, and extended snapshot keep the full text."
            if include_extended_data
            else "The stored model and Markdown keep the full text."
        )
        summary += (
            "\n\n## Export Warnings\n\n"
            "The `.tc.json` file shortened these fields to Threat Composer "
            f"limits. {full_text_holders}\n\n"
            + "\n".join(warnings.lines())
        )

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
