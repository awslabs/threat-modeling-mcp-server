"""State Collector utility for gathering all global variables from threat modeling modules."""

import hashlib
import json
from typing import Dict, Any, List, Tuple
from loguru import logger

# Bind the modules, not their globals. Several tools reset state by rebinding a
# module-level name (for example `components = {}`), which would leave a
# from-import pointing at the old object. Reading module attributes at collect
# time always sees current state. `current_phase` is an int, so a from-import of
# it would be permanently stale.
import threat_modeling_mcp_server.tools.business_context as business_context_module
import threat_modeling_mcp_server.tools.assumption_manager as assumption_manager
import threat_modeling_mcp_server.tools.architecture_analyzer as architecture_analyzer
import threat_modeling_mcp_server.tools.threat_actor_analyzer as threat_actor_analyzer
import threat_modeling_mcp_server.tools.trust_boundary_analyzer as trust_boundary_analyzer
import threat_modeling_mcp_server.tools.asset_flow_analyzer as asset_flow_analyzer
import threat_modeling_mcp_server.tools.threat_generator as threat_generator
import threat_modeling_mcp_server.tools.step_orchestrator as step_orchestrator
import threat_modeling_mcp_server.tools.classification_profiles as classification_profiles
import threat_modeling_mcp_server.tools.code_security_validator as code_security_validator
from threat_modeling_mcp_server.tools.business_context import (
    REQUIRED_BUSINESS_CONTEXT_FEATURES,
    has_business_context_description,
    missing_business_context_features,
)


class ThreatModelState:
    """Container for all threat modeling state."""

    def __init__(self):
        self.business_context = None
        self.assumptions = {}
        self.components = {}
        self.connections = {}
        self.data_stores = {}
        self.threat_actors = {}
        self.trust_zones = {}
        self.crossing_points = {}
        self.trust_boundaries = {}
        self.assets = {}
        self.flows = {}
        self.threats = {}
        self.mitigations = {}
        self.mitigation_links = []
        self.residual_risk_assessments = {}
        self.phase_completion = {}
        self.current_phase = 1
        self.phases = {}
        # Taxonomy classification profiles
        self.software_profile = None
        self.data_asset_profiles = {}
        self.user_personas = {}
        self.nfr_requirements = []
        self.code_validation = {}


def collect_all_state() -> ThreatModelState:
    """Collect all global state variables from threat modeling modules.

    Returns:
        ThreatModelState object containing all current state
    """
    logger.debug("Collecting all threat modeling state")

    state = ThreatModelState()

    # Business Context
    state.business_context = business_context_module.business_context

    # Assumptions
    state.assumptions = dict(assumption_manager.assumptions)

    # Architecture
    state.components = dict(architecture_analyzer.components)
    state.connections = dict(architecture_analyzer.connections)
    state.data_stores = dict(architecture_analyzer.data_stores)

    # Threat Actors
    state.threat_actors = dict(threat_actor_analyzer.threat_actors)

    # Trust Boundaries
    state.trust_zones = dict(trust_boundary_analyzer.trust_zones)
    state.crossing_points = dict(trust_boundary_analyzer.crossing_points)
    state.trust_boundaries = dict(trust_boundary_analyzer.trust_boundaries)

    # Asset Flows
    state.assets = dict(asset_flow_analyzer.assets)
    state.flows = dict(asset_flow_analyzer.flows)

    # Threats and Mitigations
    state.threats = dict(threat_generator.threats)
    state.mitigations = dict(threat_generator.mitigations)
    state.mitigation_links = list(threat_generator.mitigation_links)
    state.residual_risk_assessments = dict(
        threat_generator.residual_risk_assessments
    )

    # Phase Progress
    state.phase_completion = dict(step_orchestrator.phase_completion)
    state.current_phase = step_orchestrator.current_phase
    state.phases = dict(step_orchestrator.PHASES)

    # Taxonomy classification profiles
    state.software_profile = classification_profiles.software_profile
    state.data_asset_profiles = dict(classification_profiles.data_asset_profiles)
    state.user_personas = dict(classification_profiles.user_personas)
    state.nfr_requirements = list(classification_profiles.nfr_profile.requirements)

    # Code validation
    state.code_validation = code_security_validator.build_code_validation_export_data()

    logger.info(f"Collected state: {len(state.threats)} threats, {len(state.mitigations)} mitigations, "
                f"{len(state.components)} components, {len(state.assets)} assets")

    return state


def split_reviewed(records: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Split a record store into what the agent assessed and what it never touched.

    A record is reviewed once the agent adds, updates, or otherwise makes a
    decision about it. Records that exist only because a default library was
    pre-loaded are not. Anything without the flag counts as reviewed, so
    collections that have no default library keep their existing counts.

    Args:
        records: Mapping of record ID to record

    Returns:
        (reviewed, unreviewed), each in the same shape as the input
    """
    reviewed: Dict[str, Any] = {}
    unreviewed: Dict[str, Any] = {}

    for record_id, record in records.items():
        if getattr(record, 'reviewed', True):
            reviewed[record_id] = record
        else:
            unreviewed[record_id] = record

    return reviewed, unreviewed


def count_reviewed(records: Dict[str, Any]) -> int:
    """Count records the agent has assessed for this system.

    Args:
        records: Mapping of record ID to record

    Returns:
        The number of reviewed records. See split_reviewed for the definition.
    """
    return sum(1 for record in records.values() if getattr(record, 'reviewed', True))


def model_state_fingerprint(state: ThreatModelState) -> str:
    """Hash export-relevant model state, excluding progress and output paths."""

    def dump(value):
        if hasattr(value, "model_dump"):
            return value.model_dump(mode="json")
        if isinstance(value, dict):
            return {str(key): dump(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [dump(item) for item in value]
        return value

    payload = {
        "business_context": state.business_context,
        "assumptions": state.assumptions,
        "components": state.components,
        "connections": state.connections,
        "data_stores": state.data_stores,
        "threat_actors": state.threat_actors,
        "trust_zones": state.trust_zones,
        "crossing_points": state.crossing_points,
        "trust_boundaries": state.trust_boundaries,
        "assets": state.assets,
        "flows": state.flows,
        "threats": state.threats,
        "mitigations": state.mitigations,
        "mitigation_links": state.mitigation_links,
        "residual_risk_assessments": state.residual_risk_assessments,
        "software_profile": state.software_profile,
        "data_asset_profiles": state.data_asset_profiles,
        "user_personas": state.user_personas,
        "nfr_requirements": state.nfr_requirements,
    }
    encoded = json.dumps(
        dump(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _architecture_readiness(state: ThreatModelState) -> Dict[str, Any]:
    node_ids = set(state.components) | set(state.data_stores)
    connected_node_ids = {
        node_id
        for connection in state.connections.values()
        for node_id in (connection.source_id, connection.destination_id)
        if node_id in node_ids
    }
    unconnected_node_ids = sorted(node_ids - connected_node_ids)
    if len(node_ids) == 1:
        unconnected_node_ids = []

    reasons = []
    if not node_ids:
        reasons.append("Add at least one architecture node.")
    if unconnected_node_ids:
        reasons.append(
            "Architecture nodes without connections: "
            + ", ".join(unconnected_node_ids)
        )

    return {
        "nodes": len(node_ids),
        "node_ids": sorted(node_ids),
        "connected_node_ids": sorted(connected_node_ids),
        "unconnected_node_ids": unconnected_node_ids,
        "is_complete": bool(node_ids) and not unconnected_node_ids,
        "blocking_reasons": reasons,
    }


def _trust_boundary_readiness(state: ThreatModelState) -> Dict[str, Any]:
    node_ids = set(state.components) | set(state.data_stores)
    memberships: Dict[str, List[str]] = {node_id: [] for node_id in node_ids}
    unknown_zone_node_ids = set()
    for zone_id, zone in state.trust_zones.items():
        for node_id in zone.contained_nodes:
            if node_id in memberships:
                memberships[node_id].append(zone_id)
            else:
                unknown_zone_node_ids.add(node_id)

    unassigned_node_ids = sorted(
        node_id for node_id, zones in memberships.items() if not zones
    )
    multiply_assigned_node_ids = sorted(
        node_id for node_id, zones in memberships.items() if len(zones) > 1
    )

    inter_zone_connections: Dict[str, Tuple[str, str]] = {}
    for connection_id, connection in state.connections.items():
        source_zones = memberships.get(connection.source_id, [])
        destination_zones = memberships.get(connection.destination_id, [])
        if (
            len(source_zones) == 1
            and len(destination_zones) == 1
            and source_zones[0] != destination_zones[0]
        ):
            inter_zone_connections[connection_id] = (
                source_zones[0],
                destination_zones[0],
            )

    missing_crossing_connection_ids = []
    duplicate_crossing_connection_ids = []
    invalid_crossing_mappings = []
    crossings_without_connections = []
    for crossing_id, crossing in state.crossing_points.items():
        if not crossing.connection_ids:
            crossings_without_connections.append(crossing_id)
        for connection_id in crossing.connection_ids:
            expected_zones = inter_zone_connections.get(connection_id)
            actual_zones = (
                crossing.source_zone_id,
                crossing.destination_zone_id,
            )
            if expected_zones is None or actual_zones != expected_zones:
                invalid_crossing_mappings.append(
                    f"{crossing_id}:{connection_id}"
                )

    for connection_id, expected_zones in inter_zone_connections.items():
        matches = [
            crossing_id
            for crossing_id, crossing in state.crossing_points.items()
            if connection_id in crossing.connection_ids
            and (
                crossing.source_zone_id,
                crossing.destination_zone_id,
            ) == expected_zones
        ]
        if not matches:
            missing_crossing_connection_ids.append(connection_id)
        elif len(matches) > 1:
            duplicate_crossing_connection_ids.append(connection_id)

    crossing_memberships = {crossing_id: [] for crossing_id in state.crossing_points}
    unknown_boundary_crossing_ids = set()
    for boundary_id, boundary in state.trust_boundaries.items():
        for crossing_id in boundary.crossing_points:
            if crossing_id in crossing_memberships:
                crossing_memberships[crossing_id].append(boundary_id)
            else:
                unknown_boundary_crossing_ids.add(crossing_id)
    unbound_crossing_ids = sorted(
        crossing_id
        for crossing_id, boundaries in crossing_memberships.items()
        if not boundaries
    )

    reasons = []
    if not node_ids:
        reasons.append("Add architecture nodes before assigning trust zones.")
    if unassigned_node_ids:
        reasons.append(
            "Architecture nodes without a trust zone: "
            + ", ".join(unassigned_node_ids)
        )
    if multiply_assigned_node_ids:
        reasons.append(
            "Architecture nodes assigned to multiple trust zones: "
            + ", ".join(multiply_assigned_node_ids)
        )
    if unknown_zone_node_ids:
        reasons.append(
            "Trust zones reference unknown architecture nodes: "
            + ", ".join(sorted(unknown_zone_node_ids))
        )
    if missing_crossing_connection_ids:
        reasons.append(
            "Inter-zone connections without a matching crossing point: "
            + ", ".join(sorted(missing_crossing_connection_ids))
        )
    if duplicate_crossing_connection_ids:
        reasons.append(
            "Inter-zone connections mapped to multiple matching crossing points: "
            + ", ".join(sorted(duplicate_crossing_connection_ids))
        )
    if invalid_crossing_mappings:
        reasons.append(
            "Crossing-point mappings that do not match connection zones: "
            + ", ".join(sorted(invalid_crossing_mappings))
        )
    if crossings_without_connections:
        reasons.append(
            "Crossing points without a connection: "
            + ", ".join(sorted(crossings_without_connections))
        )
    if unbound_crossing_ids:
        reasons.append(
            "Crossing points not assigned to a trust boundary: "
            + ", ".join(unbound_crossing_ids)
        )
    if unknown_boundary_crossing_ids:
        reasons.append(
            "Trust boundaries reference unknown crossing points: "
            + ", ".join(sorted(unknown_boundary_crossing_ids))
        )

    return {
        "unassigned_node_ids": unassigned_node_ids,
        "multiply_assigned_node_ids": multiply_assigned_node_ids,
        "inter_zone_connection_ids": sorted(inter_zone_connections),
        "missing_crossing_connection_ids": sorted(
            missing_crossing_connection_ids
        ),
        "duplicate_crossing_connection_ids": sorted(
            duplicate_crossing_connection_ids
        ),
        "invalid_crossing_mappings": sorted(invalid_crossing_mappings),
        "crossings_without_connections": sorted(crossings_without_connections),
        "unbound_crossing_ids": unbound_crossing_ids,
        "is_complete": bool(node_ids) and not reasons,
        "blocking_reasons": reasons,
    }


def _asset_flow_readiness(state: ThreatModelState) -> Dict[str, Any]:
    assets_with_flows = {
        flow.asset_id for flow in state.flows.values() if flow.asset_id in state.assets
    }
    assets_without_flows = sorted(set(state.assets) - assets_with_flows)
    unknown_asset_flow_ids = sorted(
        flow.id
        for flow in state.flows.values()
        if flow.asset_id not in state.assets
    )
    reasons = []
    if not state.assets:
        reasons.append("Add at least one asset.")
    if not state.flows:
        reasons.append("Add at least one asset flow.")
    if assets_without_flows:
        reasons.append(
            "Assets without a flow: " + ", ".join(assets_without_flows)
        )
    if unknown_asset_flow_ids:
        reasons.append(
            "Flows referencing unknown assets: "
            + ", ".join(unknown_asset_flow_ids)
        )
    return {
        "assets_without_flows": assets_without_flows,
        "flows_with_unknown_assets": unknown_asset_flow_ids,
        "is_complete": bool(state.assets) and bool(state.flows) and not reasons,
        "blocking_reasons": reasons,
    }


def _threat_readiness(state: ThreatModelState) -> Dict[str, Any]:
    valid_links = [
        link
        for link in state.mitigation_links
        if link.linkedId in state.threats and link.mitigationId in state.mitigations
    ]
    threats_with_mitigations = {link.linkedId for link in valid_links}
    threats_without_mitigations = sorted(
        set(state.threats) - threats_with_mitigations
    )

    missing_assessment_ids = []
    stale_assessment_ids = []
    for threat_id in state.threats:
        if threat_id not in state.residual_risk_assessments:
            missing_assessment_ids.append(threat_id)
        elif not threat_generator.is_residual_assessment_current(threat_id):
            stale_assessment_ids.append(threat_id)

    phase_7_reasons = []
    if not state.threats:
        phase_7_reasons.append("Add threats before linking mitigations.")
    if threats_without_mitigations:
        phase_7_reasons.append(
            "Threats without a mitigation link: "
            + ", ".join(threats_without_mitigations)
        )

    phase_8_reasons = []
    if not state.threats:
        phase_8_reasons.append("Add threats before assessing residual risk.")
    if missing_assessment_ids:
        phase_8_reasons.append(
            "Threats without a residual-risk assessment: "
            + ", ".join(missing_assessment_ids)
        )
    if stale_assessment_ids:
        phase_8_reasons.append(
            "Threats with stale residual-risk assessments: "
            + ", ".join(stale_assessment_ids)
        )

    return {
        "valid_mitigation_links": len(valid_links),
        "threats_without_mitigations": threats_without_mitigations,
        "missing_assessment_ids": missing_assessment_ids,
        "stale_assessment_ids": stale_assessment_ids,
        "mitigations_complete": bool(state.threats) and not phase_7_reasons,
        "residual_risk_complete": bool(state.threats) and not phase_8_reasons,
        "phase_7_blocking_reasons": phase_7_reasons,
        "phase_8_blocking_reasons": phase_8_reasons,
    }


def get_state_summary() -> Dict[str, Any]:
    """Get a summary of the current threat modeling state.

    Returns:
        Dictionary with counts and status of each state category
    """
    state = collect_all_state()

    # Delegate to the canonical check rather than re-deriving "set", so rules
    # like "every geographic facet must be present" cannot diverge between the
    # summary and manage_system_context validation.
    missing_features = missing_business_context_features()
    features_total = len(REQUIRED_BUSINESS_CONTEXT_FEATURES)
    features_set = features_total - len(missing_features)
    architecture_readiness = _architecture_readiness(state)
    trust_readiness = _trust_boundary_readiness(state)
    asset_readiness = _asset_flow_readiness(state)
    threat_readiness = _threat_readiness(state)
    current_fingerprint = model_state_fingerprint(state)

    from threat_modeling_mcp_server.utils import comprehensive_exporter

    successful_export_fingerprint = (
        comprehensive_exporter.last_successful_export_fingerprint
    )
    export_is_current = (
        successful_export_fingerprint is not None
        and successful_export_fingerprint == current_fingerprint
    )

    return {
        "business_context": {
            "has_description": has_business_context_description(state.business_context),
            "features_set": features_set,
            "features_total": features_total,
            "missing_features": missing_features,
            "is_complete": (
                has_business_context_description(state.business_context)
                and not missing_features
            ),
        },
        "classification_profiles": {
            "software_profile_set": state.software_profile is not None,
            "data_asset_profiles": len(state.data_asset_profiles),
            "user_personas": len(state.user_personas),
            "nfr_requirements": len(state.nfr_requirements),
        },
        "assumptions": len(state.assumptions),
        "code_validation": state.code_validation,
        "architecture": {
            "components": len(state.components),
            "connections": len(state.connections),
            "data_stores": len(state.data_stores),
            **architecture_readiness,
        },
        "threat_actors": len(state.threat_actors),
        "reviewed_threat_actors": count_reviewed(state.threat_actors),
        "trust_boundaries": {
            "trust_zones": len(state.trust_zones),
            "crossing_points": len(state.crossing_points),
            "trust_boundaries": len(state.trust_boundaries),
            **trust_readiness,
        },
        "asset_flows": {
            "assets": len(state.assets),
            "flows": len(state.flows),
            **asset_readiness,
        },
        "threats_mitigations": {
            "threats": len(state.threats),
            "mitigations": len(state.mitigations),
            "mitigation_links": len(state.mitigation_links),
            "residual_risk_assessments": len(state.residual_risk_assessments),
            "current_residual_risk_assessments": sum(
                threat_generator.is_residual_assessment_current(threat_id)
                for threat_id in state.threats
            ),
            **threat_readiness,
        },
        "export": {
            "has_successful_export": successful_export_fingerprint is not None,
            "is_current": export_is_current,
            "current_model_fingerprint": current_fingerprint,
            "successful_export_fingerprint": successful_export_fingerprint,
            "blocking_reasons": (
                []
                if export_is_current
                else ["Export the current model to both JSON and Markdown."]
            ),
        },
        "phase_readiness": {
            "1": {
                "is_complete": (
                    has_business_context_description(state.business_context)
                    and not missing_features
                ),
                "blocking_reasons": (
                    [
                        "Business context is missing: "
                        + ", ".join(
                            (["description"] if not has_business_context_description(
                                state.business_context
                            ) else [])
                            + missing_features
                        )
                    ]
                    if (
                        not has_business_context_description(state.business_context)
                        or missing_features
                    )
                    else []
                ),
            },
            "2": architecture_readiness,
            "3": {
                "is_complete": count_reviewed(state.threat_actors) > 0,
                "blocking_reasons": (
                    []
                    if count_reviewed(state.threat_actors) > 0
                    else ["Review at least one threat actor."]
                ),
            },
            "4": trust_readiness,
            "5": asset_readiness,
            "6": {
                "is_complete": bool(state.threats),
                "blocking_reasons": (
                    [] if state.threats else ["Add at least one threat."]
                ),
            },
            "7": {
                "is_complete": threat_readiness["mitigations_complete"],
                "blocking_reasons": threat_readiness[
                    "phase_7_blocking_reasons"
                ],
            },
            "8": {
                "is_complete": threat_readiness["residual_risk_complete"],
                "blocking_reasons": threat_readiness[
                    "phase_8_blocking_reasons"
                ],
            },
            "9": {
                "is_complete": export_is_current,
                "blocking_reasons": (
                    []
                    if export_is_current
                    else ["Export the current model to both JSON and Markdown."]
                ),
            },
        },
        "progress": {
            "current_phase": state.current_phase,
            "current_phase_name": state.phases.get(state.current_phase, "Unknown"),
            "overall_completion": (
                sum(state.phase_completion.values()) / len(state.phase_completion)
                if state.phase_completion else 0.0
            )
        }
    }
