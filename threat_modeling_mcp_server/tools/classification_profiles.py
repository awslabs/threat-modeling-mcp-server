"""Classification profile state and helpers for the Threat Modeling MCP Server.

Software, data assets, user personas, NFRs, and business context are exposed
through manage_system_context.
"""

from typing import Any, Dict, List, Optional

from loguru import logger
from mcp.server.fastmcp import Context

from threat_modeling_mcp_server.utils.id_utils import next_id, reset_id_counters
from threat_modeling_mcp_server.validation.enum_validator import validate_enum_with_enhanced_error
from threat_modeling_mcp_server.models.software_models import SoftwareProfile
from threat_modeling_mcp_server.models.data_classification_models import DataAssetProfile
from threat_modeling_mcp_server.models.user_models import UserPersona
from threat_modeling_mcp_server.models.nfr_models import (
    CLASS_LEVELS,
    NFRProfile,
    NonFunctionalRequirement,
    QualityClass,
)

# Global state
software_profile: Optional[SoftwareProfile] = None
data_asset_profiles: Dict[str, DataAssetProfile] = {}
user_personas: Dict[str, UserPersona] = {}
nfr_profile: NFRProfile = NFRProfile()

DATA_ASSET_CLEARABLE_FIELDS = {
    "name", "asset_id", "sensitivity_tier", "volume_tier",
    "lifecycle_state", "business_domain", "description",
}
USER_PERSONA_CLEARABLE_FIELDS = {
    "name", "privilege_level", "organizational_affiliation", "entity_type",
    "authentication_method", "description",
}


def _merge_profile_update(
    existing: Any,
    updates: Dict[str, Any],
    clear_fields: Optional[List[str]],
    clearable_fields: set[str],
) -> Dict[str, Any]:
    """Build model input for an update without mutating the stored model."""
    if clear_fields is not None and (
        not isinstance(clear_fields, list)
        or any(not isinstance(field, str) for field in clear_fields)
    ):
        raise ValueError("Field 'clear_fields' must be a list of field names")

    fields_to_clear = set(clear_fields or [])
    unknown = fields_to_clear - clearable_fields
    if unknown:
        raise ValueError(
            "Field 'clear_fields': fields cannot be cleared: "
            + ", ".join(sorted(unknown))
        )

    supplied = {field for field, value in updates.items() if value is not None}
    conflicts = fields_to_clear & supplied
    if conflicts:
        raise ValueError(
            "Field 'clear_fields': fields cannot be updated and cleared together: "
            + ", ".join(sorted(conflicts))
        )

    merged = existing.model_dump()
    merged.update({field: value for field, value in updates.items() if value is not None})
    for field in fields_to_clear:
        merged[field] = None
    return merged


def reset_classification_profiles() -> None:
    """Clear every classification profile and reset the id counters.

    Intended for starting a new threat model (and for tests). Because the id
    counters are reset too, ids restart at 001; only call this when the previous
    records are genuinely being discarded.
    """
    global software_profile, nfr_profile

    software_profile = None
    data_asset_profiles.clear()
    user_personas.clear()
    nfr_profile = NFRProfile()
    reset_id_counters("DP")
    reset_id_counters("UP")


async def clear_classification_profiles_impl(ctx: Context) -> str:
    """Clear the software profile, data profiles, personas and NFRs."""
    logger.debug("Clearing all classification profiles")
    reset_classification_profiles()
    return "Cleared the software profile, data asset profiles, user personas and NFRs."


async def set_software_profile_impl(
    ctx: Context,
    software_type: str,
    deployment_model: Optional[str] = None,
    architecture_style: Optional[str] = None,
    platform_runtime: Optional[str] = None,
    user_domain: Optional[str] = None,
    licensing_ownership: Optional[str] = None,
    modern_paradigms: Optional[List[str]] = None,
    description: Optional[str] = None,
) -> str:
    """Set the software classification profile for the system under analysis."""
    global software_profile

    logger.debug(f"Setting software profile: {software_type}")

    software_profile = SoftwareProfile(
        software_type=software_type,
        deployment_model=deployment_model,
        architecture_style=architecture_style,
        platform_runtime=platform_runtime,
        user_domain=user_domain,
        licensing_ownership=licensing_ownership,
        modern_paradigms=modern_paradigms or [],
        description=description,
    )

    from threat_modeling_mcp_server.tools.business_context import (
        business_context,
        deployment_model_conflict_message,
    )
    conflict = deployment_model_conflict_message(business_context, software_profile)

    set_dimensions = sum(
        1 for v in [deployment_model, architecture_style, platform_runtime,
                    user_domain, licensing_ownership] if v
    ) + (1 if modern_paradigms else 0)

    return (
        f"Software profile set: {software_profile.software_type.value} "
        f"({set_dimensions}/6 attribute dimensions configured)"
        + conflict
    )


async def get_software_profile_impl(ctx: Context) -> str:
    """Get the software classification profile."""
    if software_profile is None:
        return "No software profile set. Use manage_system_context with action='set' and section='software'."

    result = "# Software Profile\n\n"
    result += f"**Software Type**: {software_profile.software_type.value}\n\n"
    for label, value in [
        ("Deployment Model", software_profile.deployment_model),
        ("Architecture Style", software_profile.architecture_style),
        ("Platform / Runtime", software_profile.platform_runtime),
        ("User Domain", software_profile.user_domain),
        ("Licensing / Ownership", software_profile.licensing_ownership),
    ]:
        if value:
            result += f"**{label}**: {value.value}\n\n"
    if software_profile.modern_paradigms:
        paradigms = ", ".join(p.value for p in software_profile.modern_paradigms)
        result += f"**Modern Paradigms**: {paradigms}\n\n"
    if software_profile.description:
        result += f"**Description**: {software_profile.description}\n\n"
    return result


async def add_data_asset_profile_impl(
    ctx: Context,
    structural_category: str,
    name: Optional[str] = None,
    asset_id: Optional[str] = None,
    content_types: Optional[List[str]] = None,
    sensitivity_tier: Optional[str] = None,
    compliance_regimes: Optional[List[str]] = None,
    data_states: Optional[List[str]] = None,
    volume_tier: Optional[str] = None,
    lifecycle_state: Optional[str] = None,
    business_domain: Optional[str] = None,
    description: Optional[str] = None,
) -> str:
    """Classify a data asset across the eight Data Classification dimensions."""
    logger.debug(f"Adding data asset profile: {structural_category}")

    # The tool exposes this with a None default so the batch 'items' path can be
    # used on its own; say so plainly rather than failing in model validation.
    if not structural_category:
        return (
            "❌ structural_category is required. Provide it directly for a single "
            "data asset, or include it in each dict passed to 'items'."
        )

    profile_id = next_id(data_asset_profiles, "DP")
    data_asset_profiles[profile_id] = DataAssetProfile(
        id=profile_id,
        name=name,
        asset_id=asset_id,
        structural_category=structural_category,
        content_types=content_types or [],
        sensitivity_tier=sensitivity_tier,
        compliance_regimes=compliance_regimes or [],
        data_states=data_states or [],
        volume_tier=volume_tier,
        lifecycle_state=lifecycle_state,
        business_domain=business_domain,
        description=description,
    )
    return f"Data asset profile added with ID: {profile_id}"


async def list_data_asset_profiles_impl(ctx: Context) -> str:
    """List all data asset classification profiles."""
    if not data_asset_profiles:
        return "No data asset profiles defined."

    result = "# Data Asset Profiles\n\n"
    for profile_id, profile in data_asset_profiles.items():
        title = profile.name or profile.structural_category.value
        result += f"## {profile_id}: {title}\n\n"
        result += f"- **Structural Category**: {profile.structural_category.value}\n"
        if profile.asset_id:
            result += f"- **Asset**: {profile.asset_id}\n"
        if profile.content_types:
            result += f"- **Content Types**: {', '.join(c.value for c in profile.content_types)}\n"
        if profile.sensitivity_tier:
            result += f"- **Sensitivity**: {profile.sensitivity_tier.value}\n"
        if profile.compliance_regimes:
            result += f"- **Compliance**: {', '.join(c.value for c in profile.compliance_regimes)}\n"
        if profile.data_states:
            result += f"- **Data States**: {', '.join(d.value for d in profile.data_states)}\n"
        if profile.volume_tier:
            result += f"- **Volume**: {profile.volume_tier.value}\n"
        if profile.lifecycle_state:
            result += f"- **Lifecycle**: {profile.lifecycle_state.value}\n"
        if profile.business_domain:
            result += f"- **Business Domain**: {profile.business_domain.value}\n"
        if profile.description:
            result += f"- **Description**: {profile.description}\n"
        result += "\n"
    return result


async def update_data_asset_profile_impl(
    ctx: Context,
    id: str,
    name: Optional[str] = None,
    asset_id: Optional[str] = None,
    structural_category: Optional[str] = None,
    content_types: Optional[List[str]] = None,
    sensitivity_tier: Optional[str] = None,
    compliance_regimes: Optional[List[str]] = None,
    data_states: Optional[List[str]] = None,
    volume_tier: Optional[str] = None,
    lifecycle_state: Optional[str] = None,
    business_domain: Optional[str] = None,
    description: Optional[str] = None,
    clear_fields: Optional[List[str]] = None,
) -> str:
    """Update an existing data asset classification profile."""
    if not id:
        return (
            "id is required. Provide it directly for a single update, or include "
            "it in each dict passed to 'items'."
        )
    if id not in data_asset_profiles:
        return f"Data asset profile with ID {id} not found"

    existing = data_asset_profiles[id]
    updates = {
        "name": name,
        "asset_id": asset_id,
        "structural_category": structural_category,
        "content_types": content_types,
        "sensitivity_tier": sensitivity_tier,
        "compliance_regimes": compliance_regimes,
        "data_states": data_states,
        "volume_tier": volume_tier,
        "lifecycle_state": lifecycle_state,
        "business_domain": business_domain,
        "description": description,
    }
    merged = _merge_profile_update(
        existing, updates, clear_fields, DATA_ASSET_CLEARABLE_FIELDS,
    )
    merged["id"] = id
    data_asset_profiles[id] = DataAssetProfile(**merged)

    return f"Data asset profile {id} updated"


async def delete_data_asset_profile_impl(ctx: Context, id: str) -> str:
    """Delete a data asset classification profile."""
    if id not in data_asset_profiles:
        return f"Data asset profile with ID {id} not found"
    del data_asset_profiles[id]
    return f"Data asset profile {id} deleted"


async def update_user_persona_impl(
    ctx: Context,
    id: str,
    persona_type: Optional[str] = None,
    name: Optional[str] = None,
    privilege_level: Optional[str] = None,
    organizational_affiliation: Optional[str] = None,
    functional_roles: Optional[List[str]] = None,
    intent_behavior: Optional[str] = None,
    entity_type: Optional[str] = None,
    authentication_method: Optional[str] = None,
    threat_actor_overlay: Optional[List[str]] = None,
    description: Optional[str] = None,
    is_relevant: Optional[bool] = None,
    clear_fields: Optional[List[str]] = None,
) -> str:
    """Update an existing user persona."""
    if not id:
        return (
            "id is required. Provide it directly for a single update, or include "
            "it in each dict passed to 'items'."
        )
    if id not in user_personas:
        return f"User persona with ID {id} not found"

    existing = user_personas[id]
    updates = {
        "persona_type": persona_type,
        "name": name,
        "privilege_level": privilege_level,
        "organizational_affiliation": organizational_affiliation,
        "functional_roles": functional_roles,
        "intent_behavior": intent_behavior,
        "entity_type": entity_type,
        "authentication_method": authentication_method,
        "threat_actor_overlay": threat_actor_overlay,
        "description": description,
        "is_relevant": is_relevant,
    }
    merged = _merge_profile_update(
        existing, updates, clear_fields, USER_PERSONA_CLEARABLE_FIELDS,
    )
    merged["id"] = id
    user_personas[id] = UserPersona(**merged)

    return f"User persona {id} updated"


async def delete_user_persona_impl(ctx: Context, id: str) -> str:
    """Delete a user persona."""
    if id not in user_personas:
        return f"User persona with ID {id} not found"
    del user_personas[id]
    return f"User persona {id} deleted"


async def delete_nfr_requirement_impl(ctx: Context, quality_class: str) -> str:
    """Remove the recorded level for one quality class."""
    target = validate_enum_with_enhanced_error(
        quality_class, QualityClass, 'quality_class'
    )
    remaining = [r for r in nfr_profile.requirements if r.quality_class != target]
    if len(remaining) == len(nfr_profile.requirements):
        return f"❌ No requirement recorded for {target.value}"
    nfr_profile.requirements = remaining
    return f"Requirement for {target.value} removed"


async def add_user_persona_impl(
    ctx: Context,
    persona_type: str,
    name: Optional[str] = None,
    privilege_level: Optional[str] = None,
    organizational_affiliation: Optional[str] = None,
    functional_roles: Optional[List[str]] = None,
    intent_behavior: Optional[str] = None,
    entity_type: Optional[str] = None,
    authentication_method: Optional[str] = None,
    threat_actor_overlay: Optional[List[str]] = None,
    description: Optional[str] = None,
) -> str:
    """Add a legitimate user persona that interacts with the system."""
    logger.debug(f"Adding user persona: {persona_type}")

    # None default on the tool so 'items' can be used alone; see
    # add_data_asset_profile_impl.
    if not persona_type:
        return (
            "❌ persona_type is required. Provide it directly for a single persona, "
            "or include it in each dict passed to 'items'."
        )

    persona_id = next_id(user_personas, "UP")
    user_personas[persona_id] = UserPersona(
        id=persona_id,
        persona_type=persona_type,
        name=name,
        privilege_level=privilege_level,
        organizational_affiliation=organizational_affiliation,
        functional_roles=functional_roles or [],
        intent_behavior=intent_behavior or "Legitimate",
        entity_type=entity_type,
        authentication_method=authentication_method,
        threat_actor_overlay=threat_actor_overlay or [],
        description=description,
    )
    return f"User persona added with ID: {persona_id}"


async def list_user_personas_impl(ctx: Context) -> str:
    """List all legitimate user personas."""
    if not user_personas:
        return "No user personas defined."

    result = "# User Personas\n\n"
    for persona_id, persona in user_personas.items():
        title = persona.name or persona.persona_type.value
        result += f"## {persona_id}: {title}\n\n"
        result += f"- **Persona Type**: {persona.persona_type.value}\n"
        if persona.privilege_level:
            result += f"- **Privilege Level**: {persona.privilege_level.value}\n"
        if persona.organizational_affiliation:
            result += f"- **Affiliation**: {persona.organizational_affiliation.value}\n"
        if persona.functional_roles:
            result += f"- **Functional Roles**: {', '.join(r.value for r in persona.functional_roles)}\n"
        result += f"- **Intent / Behaviour**: {persona.intent_behavior.value}\n"
        if persona.entity_type:
            result += f"- **Entity Type**: {persona.entity_type.value}\n"
        if persona.authentication_method:
            result += f"- **Authentication**: {persona.authentication_method.value}\n"
        if persona.threat_actor_overlay:
            result += f"- **Threat Actor Overlay**: {', '.join(persona.threat_actor_overlay)}\n"
        result += f"- **In Scope**: {'Yes' if persona.is_relevant else 'No'}\n"
        if persona.description:
            result += f"- **Description**: {persona.description}\n"
        result += "\n"
    return result


async def set_nfr_requirement_impl(
    ctx: Context,
    quality_class: str,
    level: str,
    rationale: Optional[str] = None,
) -> str:
    """Record the required level for one non-functional quality class."""
    logger.debug(f"Setting NFR {quality_class}: {level}")

    requirement = NonFunctionalRequirement(
        quality_class=quality_class, level=level, rationale=rationale
    )

    # One entry per class: setting an existing class replaces its requirement.
    nfr_profile.requirements = [
        r for r in nfr_profile.requirements if r.quality_class != requirement.quality_class
    ] + [requirement]

    return f"NFR set: {requirement.quality_class.value}: {requirement.level}"


async def list_nfr_requirements_impl(ctx: Context) -> str:
    """List the non-functional requirements recorded for the system."""
    if not nfr_profile.requirements:
        return (
            "No non-functional requirements recorded. Use manage_system_context with "
            "action='set', section='nfrs', and quality_class/level values."
        )

    result = "# Non-Functional Requirements\n\n"
    for requirement in nfr_profile.requirements:
        result += f"- **{requirement.quality_class.value}**: {requirement.level}"
        if requirement.rationale:
            result += f" ({requirement.rationale})"
        result += "\n"
    return result


async def get_nfr_classes_impl(ctx: Context) -> str:
    """List every quality class and the levels each one accepts."""
    result = (
        "# NFR Quality Classes and Levels\n\n"
        "Set one requirement with `values={\"quality_class\": \"...\", "
        "\"level\": \"...\", \"rationale\": \"...\"}`. `rationale` is optional.\n\n"
    )
    for quality_class in QualityClass:
        levels = ", ".join(CLASS_LEVELS[quality_class])
        result += f"- **{quality_class.value}**: {levels}\n"
    return result
