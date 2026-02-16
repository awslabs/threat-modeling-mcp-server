"""State Collector utility for gathering all global variables from threat modeling modules."""

from typing import Dict, List, Any, Optional
from loguru import logger

# Import all the global state variables from each module
from threat_modeling_mcp_server.tools.business_context import business_context
from threat_modeling_mcp_server.tools.assumption_manager import assumptions
from threat_modeling_mcp_server.tools.architecture_analyzer import components, connections, data_stores
from threat_modeling_mcp_server.tools.threat_actor_analyzer import threat_actors
from threat_modeling_mcp_server.tools.trust_boundary_analyzer import trust_zones, crossing_points, trust_boundaries
from threat_modeling_mcp_server.tools.asset_flow_analyzer import assets, flows
from threat_modeling_mcp_server.tools.threat_generator import threats, mitigations, assumption_links, mitigation_links
from threat_modeling_mcp_server.tools.step_orchestrator import phase_completion, current_phase, PHASES


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
        self.assumption_links = []
        self.mitigation_links = []
        self.phase_completion = {}
        self.current_phase = 1
        self.phases = {}


def collect_all_state() -> ThreatModelState:
    """Collect all global state variables from threat modeling modules.
    
    Returns:
        ThreatModelState object containing all current state
    """
    logger.debug("Collecting all threat modeling state")
    
    state = ThreatModelState()
    
    # Business Context
    state.business_context = business_context
    
    # Assumptions
    state.assumptions = dict(assumptions)
    
    # Architecture
    state.components = dict(components)
    state.connections = dict(connections)
    state.data_stores = dict(data_stores)
    
    # Threat Actors
    state.threat_actors = dict(threat_actors)
    
    # Trust Boundaries
    state.trust_zones = dict(trust_zones)
    state.crossing_points = dict(crossing_points)
    state.trust_boundaries = dict(trust_boundaries)
    
    # Asset Flows
    state.assets = dict(assets)
    state.flows = dict(flows)
    
    # Threats and Mitigations
    state.threats = dict(threats)
    state.mitigations = dict(mitigations)
    state.assumption_links = list(assumption_links)
    state.mitigation_links = list(mitigation_links)
    
    # Phase Progress
    state.phase_completion = dict(phase_completion)
    state.current_phase = current_phase
    state.phases = dict(PHASES)
    
    logger.info(f"Collected state: {len(state.threats)} threats, {len(state.mitigations)} mitigations, "
                f"{len(state.components)} components, {len(state.assets)} assets")
    
    return state


def get_state_summary() -> Dict[str, Any]:
    """Get a summary of the current threat modeling state.
    
    Returns:
        Dictionary with counts and status of each state category
    """
    state = collect_all_state()
    
    return {
        "business_context": {
            "has_description": bool(state.business_context.description),
            "features_set": sum(1 for attr in [
                state.business_context.industry_sector,
                state.business_context.data_sensitivity,
                state.business_context.user_base_size,
                state.business_context.geographic_scope,
                state.business_context.regulatory_requirements,
                state.business_context.system_criticality,
                state.business_context.financial_impact,
                state.business_context.authentication_requirement,
                state.business_context.deployment_environment,
                state.business_context.integration_complexity
            ] if attr is not None and (not hasattr(attr, '__len__') or len(attr) > 0))
        },
        "assumptions": len(state.assumptions),
        "architecture": {
            "components": len(state.components),
            "connections": len(state.connections),
            "data_stores": len(state.data_stores)
        },
        "threat_actors": len(state.threat_actors),
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
            "assumption_links": len(state.assumption_links),
            "mitigation_links": len(state.mitigation_links)
        },
        "progress": {
            "current_phase": state.current_phase,
            "current_phase_name": state.phases.get(state.current_phase, "Unknown"),
            "overall_completion": sum(state.phase_completion.values()) / len(state.phase_completion) if state.phase_completion else 0.0
        }
    }
