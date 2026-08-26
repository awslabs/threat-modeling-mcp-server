"""Compact MCP managers for the threat-modeling workflow domains."""

from typing import Any, Dict, List, Literal, Optional

from mcp.server.fastmcp import Context
from pydantic import Field

from threat_modeling_mcp_server.models.architecture_models import (
    BackupFrequency,
    ComponentType,
    DataStoreType,
    Protocol,
    ServiceProvider,
)
from threat_modeling_mcp_server.models.asset_flow_models import (
    AssetType,
    ControlType,
    TransformationType,
)
from threat_modeling_mcp_server.models.data_classification_models import (
    DataLifecycleState,
    DataState,
)
from threat_modeling_mcp_server.models.models import (
    SensitivityTier,
)
from threat_modeling_mcp_server.models.threat_actor_models import (
    Motivation,
    RelationshipToTarget,
    ResourceLevel,
    SophisticationTier,
    StateNexus,
    TargetingSpecificity,
    ThreatActorType,
)
from threat_modeling_mcp_server.models.threat_models import (
    MitigationCost,
    MitigationEffectiveness,
    MitigationStatus,
    MitigationType,
    ResidualRiskDecision,
    ThreatCategory,
    ThreatLikelihood,
    ThreatSeverity,
    ThreatStatus,
)
from threat_modeling_mcp_server.models.trust_boundary_models import (
    AuthenticationMethod,
    AuthorizationMethod,
    BoundaryType,
    TrustLevel,
)
from threat_modeling_mcp_server.tools import architecture_analyzer as architecture
from threat_modeling_mcp_server.tools import asset_flow_analyzer as asset_flows
from threat_modeling_mcp_server.tools import assumption_manager as assumptions
from threat_modeling_mcp_server.tools import threat_actor_analyzer as actors
from threat_modeling_mcp_server.tools import threat_generator as threats
from threat_modeling_mcp_server.tools import trust_boundary_analyzer as boundaries
from threat_modeling_mcp_server.tools import trust_boundary_detector
from threat_modeling_mcp_server.utils.batch_utils import batch_add
from threat_modeling_mcp_server.utils.manager_utils import (
    call_impl,
    dispatch_entity_action,
    format_impl_fields,
    reject_arguments,
)


AssumptionAction = Literal["describe", "add", "update", "list", "get", "delete"]
ArchitectureAction = Literal[
    "describe", "plan", "add", "update", "list", "delete", "clear",
]
ArchitectureSection = Literal["components", "connections", "data_stores", "all"]
ThreatActorAction = Literal[
    "describe", "add", "update", "list", "get", "delete", "analyze", "reset",
    "clear",
]
TrustBoundaryAction = Literal[
    "describe", "analysis_plan", "detection_plan", "add", "update", "list",
    "get", "delete", "link", "unlink", "clear",
]
TrustBoundarySection = Literal[
    "zones", "crossing_points", "boundaries", "all",
]
AssetFlowAction = Literal[
    "describe", "add", "update", "list", "get", "delete", "clear",
]
AssetFlowSection = Literal["assets", "flows", "all"]
ThreatAction = Literal[
    "describe", "add", "update", "list", "get", "delete", "link", "unlink",
    "assess", "clear",
]
ThreatSection = Literal["threats", "mitigations", "all"]


def _entity_guide(
    title: str,
    add_impl,
    update_impl,
    list_impl,
    enum_fields: Optional[Dict[str, Any]] = None,
    notes: str = "",
) -> str:
    """Render add, update, and list payload contracts for one entity."""
    enum_fields = enum_fields or {}
    result = (
        f"# {title}\n\n"
        "Use `values` for one record and `items` for a batch. For one update or "
        "delete, or for get where supported, pass the record ID in `item_id`; "
        "batch updates include `id` in each item and batch deletes use "
        "`item_ids`.\n\n"
        "## Add values\n"
        f"{format_impl_fields(add_impl, enum_fields)}\n\n"
        "## Update values\n"
        f"{format_impl_fields(update_impl, enum_fields, {'id'})}\n\n"
        "## List filters\n"
        f"{format_impl_fields(list_impl, enum_fields)}"
    )
    if notes:
        result += f"\n\n{notes}"
    return result


def assumption_guide() -> str:
    return _entity_guide(
        "Assumption Manager",
        assumptions.add_assumption_impl,
        assumptions.update_assumption_impl,
        assumptions.list_assumptions_impl,
    )


_ARCHITECTURE_SPECS = {
    "components": {
        "label": "component",
        "add": architecture.add_component_impl,
        "update": architecture.update_component_impl,
        "list": architecture.list_components_impl,
        "delete": architecture.delete_component_impl,
        "enums": {
            "type": ComponentType,
            "service_provider": ServiceProvider,
        },
    },
    "connections": {
        "label": "connection",
        "add": architecture.add_connection_impl,
        "update": architecture.update_connection_impl,
        "list": architecture.list_connections_impl,
        "delete": architecture.delete_connection_impl,
        "enums": {"protocol": Protocol},
    },
    "data_stores": {
        "label": "data store",
        "add": architecture.add_data_store_impl,
        "update": architecture.update_data_store_impl,
        "list": architecture.list_data_stores_impl,
        "delete": architecture.delete_data_store_impl,
        "enums": {
            "type": DataStoreType,
            "classification": SensitivityTier,
            "backup_frequency": BackupFrequency,
        },
    },
}


def architecture_guide(section: str) -> str:
    if section == "all":
        return """# Architecture Manager

Sections: `components`, `connections`, `data_stores`, and `all`.

- Entity sections: describe, add, update, list, delete
- `all`: describe, plan, list, clear

Call `describe` for an entity section before writing it. Connections reference
component or data-store node IDs, and architecture cannot be cleared while
asset flows exist.
"""
    spec = _ARCHITECTURE_SPECS[section]
    return _entity_guide(
        f"Architecture: {section.replace('_', ' ').title()}",
        spec["add"],
        spec["update"],
        spec["list"],
        spec["enums"],
    )


_ACTOR_ENUMS = {
    "type": ThreatActorType,
    "sophistication_tier": SophisticationTier,
    "motivations": Motivation,
    "resources": ResourceLevel,
    "relationship_to_target": RelationshipToTarget,
    "state_nexus": StateNexus,
    "targeting_specificity": TargetingSpecificity,
}


def threat_actor_guide() -> str:
    return _entity_guide(
        "Threat Actor Manager",
        actors.add_threat_actor_impl,
        actors.update_threat_actor_impl,
        actors.list_threat_actors_impl,
        _ACTOR_ENUMS,
        "Use update values `priority` and `is_relevant` when assessing default "
        "or custom actors. Priority is 1-10, or 0 for unranked. `analyze`, "
        "`reset`, and `clear` take no payload.",
    )


_TRUST_SPECS = {
    "zones": {
        "label": "trust zone",
        "add": boundaries.add_trust_zone_impl,
        "update": boundaries.update_trust_zone_impl,
        "list": boundaries.list_trust_zones_impl,
        "get": boundaries.get_trust_zone_impl,
        "delete": boundaries.delete_trust_zone_impl,
        "enums": {"trust_level": TrustLevel},
    },
    "crossing_points": {
        "label": "crossing point",
        "add": boundaries.add_crossing_point_impl,
        "update": boundaries.update_crossing_point_impl,
        "list": boundaries.list_crossing_points_impl,
        "get": boundaries.get_crossing_point_impl,
        "delete": boundaries.delete_crossing_point_impl,
        "enums": {
            "authentication_method": AuthenticationMethod,
            "authorization_method": AuthorizationMethod,
        },
    },
    "boundaries": {
        "label": "trust boundary",
        "add": boundaries.add_trust_boundary_impl,
        "update": boundaries.update_trust_boundary_impl,
        "list": boundaries.list_trust_boundaries_impl,
        "get": boundaries.get_trust_boundary_impl,
        "delete": boundaries.delete_trust_boundary_impl,
        "enums": {
            "type": BoundaryType,
        },
    },
}


def trust_boundary_guide(section: str) -> str:
    if section == "all":
        return """# Trust Boundary Manager

Sections: `zones`, `crossing_points`, `boundaries`, and `all`.

- Entity sections: describe, add, update, list, get, delete
- `zones`: link/unlink architecture nodes (components or data stores)
- `crossing_points`: link/unlink architecture connections
- `all`: describe, analysis_plan, detection_plan, list, clear

For link/unlink, pass both IDs in `values`; link also accepts batch `items`.
"""
    spec = _TRUST_SPECS[section]
    relation_note = ""
    if section == "zones":
        relation_note = (
            "Link values: `zone_id`, `node_id`. Unlink accepts one values "
            "object; link also accepts batch items."
        )
    elif section == "crossing_points":
        relation_note = (
            "Link values: `crossing_point_id`, `connection_id`. Unlink accepts "
            "one values object; link also accepts batch items."
        )
    return _entity_guide(
        f"Trust Boundaries: {section.replace('_', ' ').title()}",
        spec["add"],
        spec["update"],
        spec["list"],
        spec["enums"],
        relation_note,
    )


_ASSET_FLOW_SPECS = {
    "assets": {
        "label": "asset",
        "add": asset_flows.add_asset_impl,
        "update": asset_flows.update_asset_impl,
        "list": asset_flows.list_assets_impl,
        "get": asset_flows.get_asset_impl,
        "delete": asset_flows.delete_asset_impl,
        "enums": {
            "type": AssetType,
            "classification": SensitivityTier,
            "lifecycle_state": DataLifecycleState,
            "data_states": DataState,
        },
    },
    "flows": {
        "label": "flow",
        "add": asset_flows.add_flow_impl,
        "update": asset_flows.update_flow_impl,
        "list": asset_flows.list_flows_impl,
        "get": asset_flows.get_flow_impl,
        "delete": asset_flows.delete_flow_impl,
        "enums": {
            "transformation_type": TransformationType,
            "controls": ControlType,
        },
    },
}


def asset_flow_guide(section: str) -> str:
    if section == "all":
        return """# Asset Flow Manager

Sections: `assets`, `flows`, and `all`.

- Entity sections: describe, add, update, list, get, delete
- `all`: describe, list, clear

Flows reference an existing asset and architecture source/destination node.
"""
    spec = _ASSET_FLOW_SPECS[section]
    notes = ""
    if section == "assets":
        notes = (
            "Update supports `clear_fields`: lifecycle_state, description, "
            "owner, criticality, metadata. `criticality` must be from 1 to 5."
        )
    elif section == "flows":
        notes = (
            "Update supports `clear_fields`: transformation_type, description, "
            "protocol, risk_level. `risk_level` must be from 1 to 5."
        )
    return _entity_guide(
        f"Asset Flows: {section.title()}",
        spec["add"],
        spec["update"],
        spec["list"],
        spec["enums"],
        notes,
    )


_THREAT_SPECS = {
    "threats": {
        "label": "threat",
        "add": threats.add_threat_impl,
        "update": threats.update_threat_impl,
        "list": threats.list_threats_impl,
        "get": threats.get_threat_impl,
        "delete": threats.delete_threat_impl,
        "enums": {
            "category": ThreatCategory,
            "severity": ThreatSeverity,
            "likelihood": ThreatLikelihood,
            "status": ThreatStatus,
        },
    },
    "mitigations": {
        "label": "mitigation",
        "add": threats.add_mitigation_impl,
        "update": threats.update_mitigation_impl,
        "list": threats.list_mitigations_impl,
        "get": threats.get_mitigation_impl,
        "delete": threats.delete_mitigation_impl,
        "enums": {
            "type": MitigationType,
            "status": MitigationStatus,
            "cost": MitigationCost,
            "effectiveness": MitigationEffectiveness,
        },
    },
}


def threat_guide(section: str) -> str:
    if section == "all":
        return """# Threat and Mitigation Manager

Sections: `threats`, `mitigations`, and `all`.

- Entity sections: describe, add, update, list, get, delete
- `mitigations`: link/unlink a mitigation and threat
- `threats`: assess residual risk
- `all`: describe, list, clear

For link/unlink, pass `mitigation_id` and `threat_id` in `values`. Link accepts
batch `items`. Residual-risk assessment accepts one `values` object or an atomic
batch in `items`.
"""
    spec = _THREAT_SPECS[section]
    notes = ""
    if section == "threats":
        choices = ", ".join(member.value for member in ResidualRiskDecision)
        notes = (
            "Threat Composer text fields are truncated to their schema limits.\n\n"
            "Residual-risk assessment uses action `assess` with required "
            "`threat_id`, `decision`, and `rationale`; decisions are one of: "
            f"{choices}. `residual_severity` and `residual_likelihood` are "
            "required unless the decision is Not Applicable. Assessment batches "
            "are atomic."
        )
    elif section == "mitigations":
        notes = (
            "Link/unlink values require `mitigation_id` and `threat_id`; these "
            "links accept batch `items`."
        )
    return _entity_guide(
        f"Threats: {section.title()}",
        spec["add"],
        spec["update"],
        spec["list"],
        spec["enums"],
        notes,
    )


async def manage_assumptions_impl(
    ctx: Context,
    action: str,
    values: Optional[Dict[str, Any]] = None,
    items: Optional[List[Dict[str, Any]]] = None,
    item_id: Optional[str] = None,
    item_ids: Optional[List[str]] = None,
) -> str:
    action = action.strip().lower()
    if action == "describe":
        error = reject_arguments(
            action, values=values, items=items, item_id=item_id, item_ids=item_ids,
        )
        return error or assumption_guide()
    if action not in {"add", "update", "list", "get", "delete"}:
        return f"❌ Unknown assumption action '{action}'."
    return await dispatch_entity_action(
        ctx,
        action,
        "assumption",
        values=values,
        items=items,
        item_id=item_id,
        item_ids=item_ids,
        add_impl=assumptions.add_assumption_impl,
        update_impl=assumptions.update_assumption_impl,
        list_impl=assumptions.list_assumptions_impl,
        get_impl=assumptions.get_assumption_impl,
        delete_impl=assumptions.delete_assumption_impl,
    )


async def manage_architecture_impl(
    ctx: Context,
    action: str,
    section: str = "all",
    values: Optional[Dict[str, Any]] = None,
    items: Optional[List[Dict[str, Any]]] = None,
    item_id: Optional[str] = None,
    item_ids: Optional[List[str]] = None,
) -> str:
    action = action.strip().lower()
    section = section.strip().lower()
    if section not in {*_ARCHITECTURE_SPECS, "all"}:
        return f"❌ Unknown architecture section '{section}'."

    if action == "describe":
        error = reject_arguments(
            action, values=values, items=items, item_id=item_id, item_ids=item_ids,
        )
        return error or architecture_guide(section)
    if action in {"plan", "clear"}:
        if section != "all":
            return f"❌ action='{action}' requires section='all'."
        error = reject_arguments(
            action, values=values, items=items, item_id=item_id, item_ids=item_ids,
        )
        if error:
            return error
        if action == "plan":
            return await architecture.get_architecture_analysis_plan_impl(ctx)
        return await architecture.clear_architecture_impl(ctx)
    if action == "list" and section == "all":
        error = reject_arguments(
            action, values=values, items=items, item_id=item_id, item_ids=item_ids,
        )
        if error:
            return error
        results = [
            await architecture.list_components_impl(ctx),
            await architecture.list_connections_impl(ctx),
            await architecture.list_data_stores_impl(ctx),
        ]
        return "# Complete Architecture\n\n" + "\n\n---\n\n".join(results)
    if section == "all":
        return "❌ Choose components, connections, or data_stores for this action."
    if action not in {"add", "update", "list", "delete"}:
        return f"❌ Unknown architecture action '{action}'."

    spec = _ARCHITECTURE_SPECS[section]
    return await dispatch_entity_action(
        ctx,
        action,
        spec["label"],
        values=values,
        items=items,
        item_id=item_id,
        item_ids=item_ids,
        add_impl=spec["add"],
        update_impl=spec["update"],
        list_impl=spec["list"],
        delete_impl=spec["delete"],
    )


async def manage_threat_actors_impl(
    ctx: Context,
    action: str,
    values: Optional[Dict[str, Any]] = None,
    items: Optional[List[Dict[str, Any]]] = None,
    item_id: Optional[str] = None,
    item_ids: Optional[List[str]] = None,
) -> str:
    action = action.strip().lower()
    if action == "describe":
        error = reject_arguments(
            action, values=values, items=items, item_id=item_id, item_ids=item_ids,
        )
        return error or threat_actor_guide()
    if action in {"analyze", "reset", "clear"}:
        error = reject_arguments(
            action, values=values, items=items, item_id=item_id, item_ids=item_ids,
        )
        if error:
            return error
        operations = {
            "analyze": actors.analyze_threat_actors_impl,
            "reset": actors.reset_threat_actors_impl,
            "clear": actors.clear_threat_actors_impl,
        }
        return await operations[action](ctx)
    if action not in {"add", "update", "list", "get", "delete"}:
        return f"❌ Unknown threat-actor action '{action}'."
    return await dispatch_entity_action(
        ctx,
        action,
        "threat actor",
        values=values,
        items=items,
        item_id=item_id,
        item_ids=item_ids,
        add_impl=actors.add_threat_actor_impl,
        update_impl=actors.update_threat_actor_impl,
        list_impl=actors.list_threat_actors_impl,
        get_impl=actors.get_threat_actor_impl,
        delete_impl=actors.delete_threat_actor_impl,
    )


async def _dispatch_relation(
    ctx: Context,
    action: str,
    label: str,
    impl_fn,
    values: Optional[Dict[str, Any]],
    items: Optional[List[Dict[str, Any]]],
    item_id: Optional[str],
    item_ids: Optional[List[str]],
    *,
    batch_supported: bool,
) -> str:
    if item_id is not None or item_ids is not None:
        return f"❌ action='{action}' accepts relationship IDs in values, not item_id."
    if values is not None and items is not None:
        return "❌ Provide values for one relationship or items for a batch, not both."
    if items is not None:
        if not batch_supported:
            return f"❌ Batch {action} is not supported for {label}."
        if not isinstance(items, list):
            return f"❌ {label} items must be a list."
        return await batch_add(ctx, items, {}, impl_fn, label)
    return await call_impl(ctx, impl_fn, values, label)


async def manage_trust_boundaries_impl(
    ctx: Context,
    action: str,
    section: str = "all",
    values: Optional[Dict[str, Any]] = None,
    items: Optional[List[Dict[str, Any]]] = None,
    item_id: Optional[str] = None,
    item_ids: Optional[List[str]] = None,
) -> str:
    action = action.strip().lower()
    section = section.strip().lower()
    if section not in {*_TRUST_SPECS, "all"}:
        return f"❌ Unknown trust-boundary section '{section}'."

    if action == "describe":
        error = reject_arguments(
            action, values=values, items=items, item_id=item_id, item_ids=item_ids,
        )
        return error or trust_boundary_guide(section)
    if action in {"analysis_plan", "detection_plan", "clear"}:
        if section != "all":
            return f"❌ action='{action}' requires section='all'."
        error = reject_arguments(
            action, values=values, items=items, item_id=item_id, item_ids=item_ids,
        )
        if error:
            return error
        if action == "analysis_plan":
            return await boundaries.get_trust_boundary_analysis_plan_impl(ctx)
        if action == "detection_plan":
            return await trust_boundary_detector.get_trust_boundary_detection_plan_impl(
                ctx,
            )
        return await boundaries.clear_trust_boundaries_impl(ctx)
    if action == "list" and section == "all":
        error = reject_arguments(
            action, values=values, items=items, item_id=item_id, item_ids=item_ids,
        )
        if error:
            return error
        results = [
            await boundaries.list_trust_zones_impl(ctx),
            await boundaries.list_crossing_points_impl(ctx),
            await boundaries.list_trust_boundaries_impl(ctx),
        ]
        return "# Complete Trust Boundary Model\n\n" + "\n\n---\n\n".join(results)
    if action in {"link", "unlink"}:
        if section == "zones":
            impl_fn = (
                boundaries.add_node_to_zone_impl
                if action == "link"
                else boundaries.remove_node_from_zone_impl
            )
            label = "node-to-zone assignment"
        elif section == "crossing_points":
            impl_fn = (
                boundaries.add_connection_to_crossing_point_impl
                if action == "link"
                else boundaries.remove_connection_from_crossing_point_impl
            )
            label = "connection-to-crossing-point assignment"
        else:
            return (
                "❌ link/unlink is supported only for zones and crossing_points."
            )
        return await _dispatch_relation(
            ctx,
            action,
            label,
            impl_fn,
            values,
            items,
            item_id,
            item_ids,
            batch_supported=action == "link",
        )
    if section == "all":
        return "❌ Choose zones, crossing_points, or boundaries for this action."
    if action not in {"add", "update", "list", "get", "delete"}:
        return f"❌ Unknown trust-boundary action '{action}'."

    spec = _TRUST_SPECS[section]
    return await dispatch_entity_action(
        ctx,
        action,
        spec["label"],
        values=values,
        items=items,
        item_id=item_id,
        item_ids=item_ids,
        add_impl=spec["add"],
        update_impl=spec["update"],
        list_impl=spec["list"],
        get_impl=spec["get"],
        delete_impl=spec["delete"],
    )


async def manage_asset_flows_impl(
    ctx: Context,
    action: str,
    section: str = "all",
    values: Optional[Dict[str, Any]] = None,
    items: Optional[List[Dict[str, Any]]] = None,
    item_id: Optional[str] = None,
    item_ids: Optional[List[str]] = None,
) -> str:
    action = action.strip().lower()
    section = section.strip().lower()
    if section not in {*_ASSET_FLOW_SPECS, "all"}:
        return f"❌ Unknown asset-flow section '{section}'."

    if action == "describe":
        error = reject_arguments(
            action, values=values, items=items, item_id=item_id, item_ids=item_ids,
        )
        return error or asset_flow_guide(section)
    if action == "clear":
        if section != "all":
            return "❌ action='clear' requires section='all'."
        error = reject_arguments(
            action, values=values, items=items, item_id=item_id, item_ids=item_ids,
        )
        return error or await asset_flows.clear_asset_flows_impl(ctx)
    if action == "list" and section == "all":
        error = reject_arguments(
            action, values=values, items=items, item_id=item_id, item_ids=item_ids,
        )
        if error:
            return error
        results = [
            await asset_flows.list_assets_impl(ctx),
            await asset_flows.list_flows_impl(ctx),
        ]
        return "# Complete Asset Flow Model\n\n" + "\n\n---\n\n".join(results)
    if section == "all":
        return "❌ Choose assets or flows for this action."
    if action not in {"add", "update", "list", "get", "delete"}:
        return f"❌ Unknown asset-flow action '{action}'."

    spec = _ASSET_FLOW_SPECS[section]
    return await dispatch_entity_action(
        ctx,
        action,
        spec["label"],
        values=values,
        items=items,
        item_id=item_id,
        item_ids=item_ids,
        add_impl=spec["add"],
        update_impl=spec["update"],
        list_impl=spec["list"],
        get_impl=spec["get"],
        delete_impl=spec["delete"],
    )


async def manage_threats_impl(
    ctx: Context,
    action: str,
    section: str = "all",
    values: Optional[Dict[str, Any]] = None,
    items: Optional[List[Dict[str, Any]]] = None,
    item_id: Optional[str] = None,
    item_ids: Optional[List[str]] = None,
) -> str:
    action = action.strip().lower()
    section = section.strip().lower()
    if section not in {*_THREAT_SPECS, "all"}:
        return f"❌ Unknown threat section '{section}'."

    if action == "describe":
        error = reject_arguments(
            action, values=values, items=items, item_id=item_id, item_ids=item_ids,
        )
        return error or threat_guide(section)
    if action == "clear":
        if section != "all":
            return "❌ action='clear' requires section='all'."
        error = reject_arguments(
            action, values=values, items=items, item_id=item_id, item_ids=item_ids,
        )
        return error or await threats.clear_threat_model_impl(ctx)
    if action == "assess":
        if section != "threats":
            return "❌ action='assess' requires section='threats'."
        if item_id is not None or item_ids is not None:
            return (
                "❌ action='assess' accepts threat_id in values or items, not "
                "item_id or item_ids."
            )
        if values is not None and items is not None:
            return (
                "❌ Provide values for one assessment or items for an atomic "
                "batch, not both."
            )
        if items is not None:
            if not isinstance(items, list):
                return "❌ residual-risk assessment items must be a list."
            return await threats.assess_threats_atomically_impl(ctx, items)
        return await call_impl(
            ctx,
            threats.assess_threat_impl,
            values,
            "residual-risk assessment",
        )
    if action == "list" and section == "all":
        error = reject_arguments(
            action, values=values, items=items, item_id=item_id, item_ids=item_ids,
        )
        if error:
            return error
        results = [
            await threats.list_threats_impl(ctx),
            await threats.list_mitigations_impl(ctx),
        ]
        return "# Complete Threat and Mitigation Model\n\n" + "\n\n---\n\n".join(
            results,
        )
    if action in {"link", "unlink"}:
        if section != "mitigations":
            return "❌ link/unlink requires section='mitigations'."
        impl_fn = (
            threats.link_mitigation_to_threat_impl
            if action == "link"
            else threats.unlink_mitigation_from_threat_impl
        )
        return await _dispatch_relation(
            ctx,
            action,
            "mitigation-to-threat link",
            impl_fn,
            values,
            items,
            item_id,
            item_ids,
            batch_supported=action == "link",
        )
    if section == "all":
        return "❌ Choose threats or mitigations for this action."
    if action not in {"add", "update", "list", "get", "delete"}:
        return f"❌ Unknown threat action '{action}'."

    spec = _THREAT_SPECS[section]
    return await dispatch_entity_action(
        ctx,
        action,
        spec["label"],
        values=values,
        items=items,
        item_id=item_id,
        item_ids=item_ids,
        add_impl=spec["add"],
        update_impl=spec["update"],
        list_impl=spec["list"],
        get_impl=spec["get"],
        delete_impl=spec["delete"],
    )


def register_tools(mcp):
    """Register the compact workflow-domain managers."""

    @mcp.tool()
    async def manage_assumptions(
        ctx: Context,
        action: AssumptionAction = Field(
            description="Operation: describe, add, update, list, get, or delete",
        ),
        values: Optional[Dict[str, Any]] = Field(
            default=None,
            description="Fields for one assumption or optional list filters",
        ),
        items: Optional[List[Dict[str, Any]]] = Field(
            default=None,
            description="Batch records for add or update",
        ),
        item_id: Optional[str] = Field(
            default=None,
            description="Assumption ID for one get, update, or delete",
        ),
        item_ids: Optional[List[str]] = Field(
            default=None,
            description="Assumption IDs for batch delete",
        ),
    ) -> str:
        """Manage assumptions through one compact action-based tool."""
        return await manage_assumptions_impl(
            ctx, action, values, items, item_id, item_ids,
        )

    @mcp.tool()
    async def manage_architecture(
        ctx: Context,
        action: ArchitectureAction = Field(
            description="Operation: describe, plan, add, update, list, delete, or clear",
        ),
        section: ArchitectureSection = Field(
            default="all",
            description="Architecture section: components, connections, data_stores, or all",
        ),
        values: Optional[Dict[str, Any]] = Field(
            default=None,
            description="Fields for one record or optional list filters",
        ),
        items: Optional[List[Dict[str, Any]]] = Field(
            default=None,
            description="Batch records for add or update",
        ),
        item_id: Optional[str] = Field(
            default=None,
            description="Record ID for one update or delete",
        ),
        item_ids: Optional[List[str]] = Field(
            default=None,
            description="Record IDs for batch delete",
        ),
    ) -> str:
        """Manage architecture components, connections, and data stores."""
        return await manage_architecture_impl(
            ctx, action, section, values, items, item_id, item_ids,
        )

    @mcp.tool()
    async def manage_threat_actors(
        ctx: Context,
        action: ThreatActorAction = Field(
            description="Operation: describe, add, update, list, get, delete, analyze, reset, or clear",
        ),
        values: Optional[Dict[str, Any]] = Field(
            default=None,
            description="Fields for one actor or optional list filters",
        ),
        items: Optional[List[Dict[str, Any]]] = Field(
            default=None,
            description="Batch actor records for add or update",
        ),
        item_id: Optional[str] = Field(
            default=None,
            description="Threat actor ID for one get, update, or delete",
        ),
        item_ids: Optional[List[str]] = Field(
            default=None,
            description="Threat actor IDs for batch delete",
        ),
    ) -> str:
        """Manage threat actors and run the actor analysis."""
        return await manage_threat_actors_impl(
            ctx, action, values, items, item_id, item_ids,
        )

    @mcp.tool()
    async def manage_trust_boundaries(
        ctx: Context,
        action: TrustBoundaryAction = Field(
            description="Operation: describe, analysis_plan, detection_plan, add, update, list, get, delete, link, unlink, or clear",
        ),
        section: TrustBoundarySection = Field(
            default="all",
            description="Trust section: zones, crossing_points, boundaries, or all",
        ),
        values: Optional[Dict[str, Any]] = Field(
            default=None,
            description="Fields for one record, relationship, or optional list filters",
        ),
        items: Optional[List[Dict[str, Any]]] = Field(
            default=None,
            description="Batch records for add, update, or supported link operations",
        ),
        item_id: Optional[str] = Field(
            default=None,
            description="Record ID for one get, update, or delete",
        ),
        item_ids: Optional[List[str]] = Field(
            default=None,
            description="Record IDs for batch delete",
        ),
    ) -> str:
        """Manage zones, crossing points, boundaries, and their relationships."""
        return await manage_trust_boundaries_impl(
            ctx, action, section, values, items, item_id, item_ids,
        )

    @mcp.tool()
    async def manage_asset_flows(
        ctx: Context,
        action: AssetFlowAction = Field(
            description="Operation: describe, add, update, list, get, delete, or clear",
        ),
        section: AssetFlowSection = Field(
            default="all",
            description="Asset-flow section: assets, flows, or all",
        ),
        values: Optional[Dict[str, Any]] = Field(
            default=None,
            description="Fields for one record or optional list filters",
        ),
        items: Optional[List[Dict[str, Any]]] = Field(
            default=None,
            description="Batch records for add or update",
        ),
        item_id: Optional[str] = Field(
            default=None,
            description="Asset or flow ID for one get, update, or delete",
        ),
        item_ids: Optional[List[str]] = Field(
            default=None,
            description="Asset or flow IDs for batch delete",
        ),
    ) -> str:
        """Manage assets and the flows that carry them."""
        return await manage_asset_flows_impl(
            ctx, action, section, values, items, item_id, item_ids,
        )

    @mcp.tool()
    async def manage_threats(
        ctx: Context,
        action: ThreatAction = Field(
            description="Operation: describe, add, update, list, get, delete, link, unlink, assess, or clear",
        ),
        section: ThreatSection = Field(
            default="all",
            description="Threat-model section: threats, mitigations, or all",
        ),
        values: Optional[Dict[str, Any]] = Field(
            default=None,
            description="Fields for one record, relationship, or optional list filters",
        ),
        items: Optional[List[Dict[str, Any]]] = Field(
            default=None,
            description="Batch records for add, update, link, or atomic residual-risk assessment",
        ),
        item_id: Optional[str] = Field(
            default=None,
            description="Threat or mitigation ID for one get, update, or delete",
        ),
        item_ids: Optional[List[str]] = Field(
            default=None,
            description="Threat or mitigation IDs for batch delete",
        ),
    ) -> str:
        """Manage threats, mitigations, and their links."""
        return await manage_threats_impl(
            ctx, action, section, values, items, item_id, item_ids,
        )
