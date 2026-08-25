"""State Collector utility for gathering all global variables from threat modeling modules."""

from typing import Dict, Any, Tuple
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
            "data_stores": len(state.data_stores)
        },
        "threat_actors": len(state.threat_actors),
        "reviewed_threat_actors": count_reviewed(state.threat_actors),
        "trust_boundaries": {
            "trust_zones": len(state.trust_zones),
            "crossing_points": len(state.crossing_points),
            "trust_boundaries": len(state.trust_boundaries)
        },
        "asset_flows": {
            "assets": len(state.assets),
            "flows": len(state.flows)
        },
        "threats_mitigations": {
            "threats": len(state.threats),
            "mitigations": len(state.mitigations),
            "mitigation_links": len(state.mitigation_links)
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
