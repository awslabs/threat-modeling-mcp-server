"""Unified MCP dispatcher for business context and classification profiles."""

import inspect
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Type, get_args, get_origin

from mcp.server.fastmcp import Context
from pydantic import BaseModel, Field, ValidationError

from threat_modeling_mcp_server.models.models import BusinessContext, GeographicScope
from threat_modeling_mcp_server.models.software_models import SoftwareProfile
from threat_modeling_mcp_server.models.data_classification_models import DataAssetProfile
from threat_modeling_mcp_server.models.user_models import UserPersona
from threat_modeling_mcp_server.tools.business_context import (
    FEATURE_DESCRIPTIONS,
    GEOGRAPHIC_FACETS,
    _BUSINESS_ENUM_FIELDS,
    _build_business_context_candidate,
    _commit_business_context,
    _validation_error_items,
    business_context,
    build_business_context_analysis_plan,
    check_business_context_completeness,
    clear_business_context_impl,
    deployment_model_conflict_message,
    get_business_context_impl,
    has_business_context_description,
    set_business_context_with_features_impl,
    validate_business_context_completeness_impl,
)
from threat_modeling_mcp_server.utils.batch_utils import (
    batch_add,
    batch_delete,
    batch_update,
)
from threat_modeling_mcp_server.utils.manager_utils import (
    call_impl as _call_context_impl,
    payload_error as _payload_error,
)


SYSTEM_CONTEXT_ACTIONS = {
    "describe", "plan", "set", "get", "add", "update", "list", "delete",
    "validate", "clear",
}
SYSTEM_CONTEXT_SECTIONS = {
    "business", "software", "data_assets", "user_personas", "nfrs", "all",
}

SystemContextAction = Literal[
    "describe", "plan", "set", "get", "add", "update", "list", "delete",
    "validate", "clear",
]
SystemContextSection = Literal[
    "business", "software", "data_assets", "user_personas", "nfrs", "all",
]

SECTION_ACTIONS = {
    "business": ("describe", "plan", "set", "get", "validate", "clear"),
    "software": ("describe", "set", "get", "clear"),
    "data_assets": ("describe", "add", "update", "list", "delete", "clear"),
    "user_personas": ("describe", "add", "update", "list", "delete", "clear"),
    "nfrs": ("describe", "set", "list", "delete", "clear"),
    "all": ("describe", "plan", "set", "get", "list", "validate", "clear"),
}

_CONTEXT_SECTION_GUIDES = {
    "business": """# Business Context

Actions: `set`, `get`, `validate`, `plan`, and `clear`. Pass all fields to
`values`; `regulatory_requirements` may be comma-separated text or a list. The
four geographic facet fields are flattened into the same `values` object.
""",
    "software": """# Software Profile

Actions: `set`, `get`, and `clear`. `set` replaces the one system profile.
""",
    "data_assets": """# Data Asset Profiles

Actions: `add`, `update`, `list`, `delete`, and `clear`. Use `values` for one
record or `items` for a batch. For one update/delete, pass the generated profile
ID in `item_id`; batch update items include `id`, and batch deletes use `item_ids`.
""",
    "user_personas": """# User Personas

Actions: `add`, `update`, `list`, `delete`, and `clear`. Use `values` for one
record or `items` for a batch. For one update/delete, pass the generated persona
ID in `item_id`; batch update items include `id`, and batch deletes use `item_ids`.
""",
    "nfrs": """# Non-Functional Requirements

Each requirement is a flat `values` object with `quality_class`, `level`, and an
optional `rationale`. Actions: `set`, `list`, `delete`, and `clear`. Use `items`
for a batch. Setting an existing quality class replaces it. Delete by passing the
quality class in `item_id` or several classes in `item_ids`.
""",
}

def _enum_classes(annotation: Any) -> List[Type[Enum]]:
    """Find enum classes nested in a Pydantic field annotation."""
    if inspect.isclass(annotation) and issubclass(annotation, Enum):
        return [annotation]

    result: List[Type[Enum]] = []
    for argument in get_args(annotation):
        result.extend(_enum_classes(argument))
    return result


def _format_model_fields(
    model: Type[BaseModel],
    excluded: Optional[set[str]] = None,
) -> str:
    """Render exact enum values for a profile model without expanding the schema."""
    excluded = excluded or set()
    lines = ["## Fields"]
    for name, field in model.model_fields.items():
        if name in excluded:
            continue

        requirement = "required" if field.is_required() else "optional"
        enum_classes = _enum_classes(field.annotation)
        if enum_classes:
            choices = ", ".join(
                member.value
                for enum_class in enum_classes
                for member in enum_class
            )
            plurality = "one or more of" if get_origin(field.annotation) is list else "one of"
            hint = f"{plurality}: {choices}"
        elif get_origin(field.annotation) is list:
            hint = "list of strings"
        elif field.annotation is bool:
            hint = "true or false"
        else:
            hint = "free text"
        lines.append(f"- `{name}` ({requirement}): {hint}")
    return "\n".join(lines)


def _business_field_guide() -> str:
    """Render the exact accepted values for business context."""
    lines = ["## Fields", "- `description` (required): free text"]
    for name, enum_class in _BUSINESS_ENUM_FIELDS.items():
        choices = ", ".join(member.value for member in enum_class)
        plurality = "one or more of" if name == "regulatory_requirements" else "one of"
        description = FEATURE_DESCRIPTIONS[name]
        lines.append(
            f"- `{name}` (required): {plurality}: {choices}. {description}"
        )

    lines.append(FEATURE_DESCRIPTIONS["geographic_profile"])
    geographic_choices = ", ".join(member.value for member in GeographicScope)
    for facet in GEOGRAPHIC_FACETS:
        lines.append(f"- `{facet}` (required): one of: {geographic_choices}")
    return "\n".join(lines)


def _system_context_guide(section: str) -> str:
    """Return the on-demand contract for one or every context section."""
    overview = """# System Context Manager

`manage_system_context` is the only MCP tool for business context and taxonomy
profiles. Sections are `business`, `software`, `data_assets`, `user_personas`,
`nfrs`, and `all`.

Supported operations:
- `business`: describe, plan, set, get, validate, clear
- `software`: describe, set, get, clear
- `data_assets`: describe, add, update, list, delete, clear
- `user_personas`: describe, add, update, list, delete, clear
- `nfrs`: describe, set, list, delete, clear
- `all`: describe, plan, set, get, list, validate, clear

For one complete write, use `action="set"`, `section="all"`, and a `values`
object with `business` and `software` objects plus `data_assets`,
`user_personas`, and `nfrs` arrays. Supplied sections are validated together and
replace their existing state, so retrying the same request is safe. Call
`describe` for a specific section to load its exact fields and enum values.
"""
    if section == "all":
        return overview

    guide = _CONTEXT_SECTION_GUIDES[section]
    if section == "business":
        return guide + "\n" + _business_field_guide()
    if section == "software":
        return guide + "\n" + _format_model_fields(SoftwareProfile)
    if section == "data_assets":
        from threat_modeling_mcp_server.tools import classification_profiles as profiles

        fields = _format_model_fields(DataAssetProfile, {"id"})
        clearable = ", ".join(sorted(profiles.DATA_ASSET_CLEARABLE_FIELDS))
        return guide + "\n" + fields + f"\n- `clear_fields` (update only): {clearable}"
    if section == "user_personas":
        from threat_modeling_mcp_server.tools import classification_profiles as profiles

        fields = _format_model_fields(UserPersona, {"id", "is_relevant"})
        clearable = ", ".join(sorted(profiles.USER_PERSONA_CLEARABLE_FIELDS))
        return (
            guide + "\n" + fields
            + "\n- `is_relevant` (update only): true or false"
            + f"\n- `clear_fields` (update only): {clearable}"
        )
    return guide


def _normalize_business_payload(
    values: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Normalize JSON-friendly business values for the existing typed helper."""
    if values is None or not isinstance(values, dict):
        return values

    payload = dict(values)

    # Permit incremental corrections without forcing the caller to resend the
    # unchanged description. A first write still requires one.
    if "description" not in payload and has_business_context_description():
        payload["description"] = business_context.description
    return payload


async def _set_complete_system_context(
    ctx: Context,
    values: Optional[Dict[str, Any]],
) -> str:
    """Validate and atomically replace every supplied Phase 1 section."""
    from threat_modeling_mcp_server.tools import classification_profiles as profiles

    if not isinstance(values, dict) or not values:
        return (
            "❌ section='all' with action='set' requires a values object. Use "
            "action='describe' to see its structure."
        )

    unexpected = sorted(set(values) - (SYSTEM_CONTEXT_SECTIONS - {"all"}))
    if unexpected:
        return (
            "❌ Unexpected section(s) in values: " + ", ".join(unexpected)
            + ". Accepted sections: business, software, data_assets, "
              "user_personas, nfrs."
        )

    errors: List[str] = []
    candidates: Dict[str, Any] = {}

    if "business" in values:
        payload = values["business"]
        if not isinstance(payload, dict):
            errors.append("business: values must be an object")
        else:
            payload_error = _payload_error(set_business_context_with_features_impl, payload)
            if payload_error:
                errors.append(f"business: {payload_error}")
            else:
                candidate, invalid_values = _build_business_context_candidate(
                    payload, BusinessContext(),
                )
                if invalid_values:
                    errors.extend(f"business.{item}" for item in invalid_values)
                else:
                    candidates["business"] = candidate

    if "software" in values:
        payload = values["software"]
        if not isinstance(payload, dict):
            errors.append("software: values must be an object")
        else:
            payload_error = _payload_error(profiles.set_software_profile_impl, payload)
            if payload_error:
                errors.append(f"software: {payload_error}")
            else:
                try:
                    candidates["software"] = SoftwareProfile(**payload)
                except ValidationError as exc:
                    errors.extend(
                        f"software.{item}" for item in _validation_error_items(exc)
                    )

    collection_specs = {
        "data_assets": (
            profiles.add_data_asset_profile_impl,
            DataAssetProfile,
            "DP",
        ),
        "user_personas": (
            profiles.add_user_persona_impl,
            UserPersona,
            "UP",
        ),
    }
    for section, (impl_fn, model, prefix) in collection_specs.items():
        if section not in values:
            continue
        supplied = values[section]
        items = supplied if isinstance(supplied, list) else [supplied]
        if not isinstance(supplied, (dict, list)):
            errors.append(f"{section}: values must be an object or list of objects")
            continue

        records = {}
        for index, item in enumerate(items, start=1):
            label = f"{section}[{index}]"
            if not isinstance(item, dict):
                errors.append(f"{label}: item must be an object")
                continue
            payload_error = _payload_error(impl_fn, item)
            if payload_error:
                errors.append(f"{label}: {payload_error}")
                continue
            record_id = f"{prefix}{index:03d}"
            try:
                records[record_id] = model(id=record_id, **item)
            except ValidationError as exc:
                errors.extend(f"{label}.{error}" for error in _validation_error_items(exc))
        candidates[section] = records

    if "nfrs" in values:
        supplied = values["nfrs"]
        items = supplied if isinstance(supplied, list) else [supplied]
        if not isinstance(supplied, (dict, list)):
            errors.append("nfrs: values must be an object or list of objects")
        else:
            requirements = []
            for index, item in enumerate(items, start=1):
                label = f"nfrs[{index}]"
                if not isinstance(item, dict):
                    errors.append(f"{label}: item must be an object")
                    continue
                payload_error = _payload_error(profiles.set_nfr_requirement_impl, item)
                if payload_error:
                    errors.append(f"{label}: {payload_error}")
                    continue
                try:
                    requirements.append(profiles.NonFunctionalRequirement(**item))
                except ValidationError as exc:
                    errors.extend(
                        f"{label}.{error}" for error in _validation_error_items(exc)
                    )
            try:
                candidates["nfrs"] = profiles.NFRProfile(requirements=requirements)
            except ValidationError as exc:
                errors.extend(f"nfrs.{item}" for item in _validation_error_items(exc))

    if errors:
        return (
            "❌ SYSTEM CONTEXT REJECTED: no changes were applied:\n"
            + "\n".join(f"- {error}" for error in errors)
        )

    results = []
    if "business" in candidates:
        _commit_business_context(candidates["business"])
        complete, missing = check_business_context_completeness(candidates["business"])
        if complete:
            results.append("## Business\nBusiness context complete.")
        else:
            results.append(
                "## Business\nBusiness context updated; still missing: "
                + ", ".join(missing)
            )
    if "software" in candidates:
        profiles.software_profile = candidates["software"]
        results.append("## Software\nSoftware profile replaced.")
    if "data_assets" in candidates:
        profiles.data_asset_profiles.clear()
        profiles.data_asset_profiles.update(candidates["data_assets"])
        profiles.reset_id_counters("DP")
        results.append(
            f"## Data Assets\nReplaced with {len(candidates['data_assets'])} profile(s)."
        )
    if "user_personas" in candidates:
        profiles.user_personas.clear()
        profiles.user_personas.update(candidates["user_personas"])
        profiles.reset_id_counters("UP")
        results.append(
            f"## User Personas\nReplaced with {len(candidates['user_personas'])} persona(s)."
        )
    if "nfrs" in candidates:
        profiles.nfr_profile = candidates["nfrs"]
        results.append(
            f"## NFRs\nReplaced with {len(candidates['nfrs'].requirements)} requirement(s)."
        )

    effective_business = candidates.get("business", business_context)
    effective_software = candidates.get("software", profiles.software_profile)
    conflict = deployment_model_conflict_message(
        effective_business, effective_software,
    )
    return "# System Context Update\n\n" + "\n\n".join(results) + conflict


async def _get_complete_system_context(ctx: Context) -> str:
    """Render every Phase 1 context section."""
    from threat_modeling_mcp_server.tools import classification_profiles as profiles

    sections = [
        await get_business_context_impl(ctx),
        await profiles.get_software_profile_impl(ctx),
        await profiles.list_data_asset_profiles_impl(ctx),
        await profiles.list_user_personas_impl(ctx),
        await profiles.list_nfr_requirements_impl(ctx),
    ]
    return "# Complete System Context\n\n" + "\n\n---\n\n".join(sections)


async def manage_system_context_impl(
    ctx: Context,
    action: str,
    section: str = "all",
    values: Optional[Dict[str, Any]] = None,
    items: Optional[List[Dict[str, Any]]] = None,
    item_id: Optional[str] = None,
    item_ids: Optional[List[str]] = None,
) -> str:
    """Dispatch one compact MCP request to the typed context implementations."""
    from threat_modeling_mcp_server.tools import classification_profiles as profiles

    action = action.strip().lower()
    section = section.strip().lower()
    if action not in SYSTEM_CONTEXT_ACTIONS:
        return (
            f"❌ Unknown action '{action}'. Valid actions: "
            + ", ".join(sorted(SYSTEM_CONTEXT_ACTIONS))
        )
    if section not in SYSTEM_CONTEXT_SECTIONS:
        return (
            f"❌ Unknown section '{section}'. Valid sections: "
            + ", ".join(sorted(SYSTEM_CONTEXT_SECTIONS))
        )

    allowed_actions = SECTION_ACTIONS[section]
    if action not in allowed_actions:
        return (
            f"❌ action='{action}' is not supported for section='{section}'. "
            f"Supported actions: {', '.join(allowed_actions)}."
        )

    if action in {"describe", "plan", "get", "list", "validate", "clear"} and any(
        argument is not None for argument in (values, items, item_id, item_ids)
    ):
        return f"❌ action='{action}' does not accept values, items, item_id, or item_ids."
    if action == "delete" and (values is not None or items is not None):
        return "❌ action='delete' accepts item_id or item_ids, not values or items."
    if action == "add" and (item_id is not None or item_ids is not None):
        return "❌ action='add' accepts values or items, not item_id or item_ids."
    if action == "set" and (item_id is not None or item_ids is not None):
        return "❌ action='set' accepts values or items, not item_id or item_ids."
    if action == "update" and item_ids is not None:
        return "❌ Batch updates belong in items; item_ids is only for delete."

    if action == "describe":
        result = _system_context_guide(section)
        if section == "nfrs":
            result += "\n" + await profiles.get_nfr_classes_impl(ctx)
        return result

    if action == "plan":
        if section not in ("all", "business"):
            return "❌ The analysis plan is available only for section='business' or 'all'."
        return build_business_context_analysis_plan()

    if action == "set" and section == "all":
        if items is not None or item_id is not None or item_ids is not None:
            return "❌ action='set', section='all' accepts only the values parameter."
        return await _set_complete_system_context(ctx, values)

    if action == "set":
        if items is not None and values is not None:
            return "❌ Provide either values for one record or items for a batch, not both."
        if section == "business":
            if items is not None:
                return "❌ Business context does not support batch items."
            payload = _normalize_business_payload(values)
            return await _call_context_impl(
                ctx, set_business_context_with_features_impl, payload, "business context",
            )
        if section == "software":
            if items is not None:
                return "❌ Software context does not support batch items."
            return await _call_context_impl(
                ctx, profiles.set_software_profile_impl, values, "software profile",
            )
        if section == "nfrs":
            if items is not None:
                return await batch_add(
                    ctx, items, {}, profiles.set_nfr_requirement_impl, "NFR requirement",
                )
            return await _call_context_impl(
                ctx, profiles.set_nfr_requirement_impl, values, "NFR requirement",
            )
        return "❌ Use action='add' for data_assets and user_personas."

    if action == "add":
        if section not in ("data_assets", "user_personas"):
            return "❌ action='add' is supported only for data_assets and user_personas."
        if items is not None and values is not None:
            return "❌ Provide either values for one record or items for a batch, not both."
        impl_fn = (
            profiles.add_data_asset_profile_impl
            if section == "data_assets"
            else profiles.add_user_persona_impl
        )
        entity = "data asset profile" if section == "data_assets" else "user persona"
        if items is not None:
            return await batch_add(ctx, items, {}, impl_fn, entity)
        return await _call_context_impl(ctx, impl_fn, values, entity)

    if action == "update":
        if section not in ("data_assets", "user_personas"):
            return "❌ action='update' is supported only for data_assets and user_personas."
        if items is not None and (values is not None or item_id is not None):
            return "❌ Provide items for a batch or item_id plus values for one update, not both."
        impl_fn = (
            profiles.update_data_asset_profile_impl
            if section == "data_assets"
            else profiles.update_user_persona_impl
        )
        entity = "data asset profile" if section == "data_assets" else "user persona"
        if items is not None:
            return await batch_update(ctx, items, {}, impl_fn, entity)
        payload = dict(values or {})
        if item_id is not None:
            if "id" in payload and payload["id"] != item_id:
                return "❌ item_id conflicts with values['id']."
            payload["id"] = item_id
        return await _call_context_impl(ctx, impl_fn, payload, entity)

    if action == "delete":
        if section in ("data_assets", "user_personas"):
            if item_ids is not None and item_id is not None:
                return "❌ Provide item_id or item_ids, not both."
            if item_ids is None and item_id is None:
                return "❌ Delete a profile by passing item_id or item_ids."
            impl_fn = (
                profiles.delete_data_asset_profile_impl
                if section == "data_assets"
                else profiles.delete_user_persona_impl
            )
            entity = "data asset profile" if section == "data_assets" else "user persona"
            return await batch_delete(ctx, item_ids, item_id, impl_fn, entity)
        if section == "nfrs":
            if item_ids is not None and item_id is not None:
                return "❌ Provide item_id or item_ids, not both."
            if item_ids is None and item_id is None:
                return "❌ Delete an NFR by passing its quality class in item_id or item_ids."
            return await batch_delete(
                ctx, item_ids, item_id, profiles.delete_nfr_requirement_impl,
                "NFR requirement",
            )
        return "❌ Use action='clear' for business, software, or all context."

    if action in ("get", "list"):
        if section == "all":
            return await _get_complete_system_context(ctx)
        readers = {
            "business": get_business_context_impl,
            "software": profiles.get_software_profile_impl,
            "data_assets": profiles.list_data_asset_profiles_impl,
            "user_personas": profiles.list_user_personas_impl,
            "nfrs": profiles.list_nfr_requirements_impl,
        }
        return await readers[section](ctx)

    if action == "validate":
        if section not in ("all", "business"):
            return (
                "No separate completeness gate exists for this section; values are "
                "validated when they are written."
            )
        result = await validate_business_context_completeness_impl(ctx)
        if section == "business":
            return result
        profile_status = (
            "\n\n## Classification Profile Coverage\n"
            f"- Software profile: {'set' if profiles.software_profile else 'missing'}\n"
            f"- Data asset profiles: {len(profiles.data_asset_profiles)}\n"
            f"- User personas: {len(profiles.user_personas)}\n"
            f"- NFR requirements: {len(profiles.nfr_profile.requirements)}/"
            f"{len(profiles.QualityClass)} classes\n\n"
            "The Phase 1 server gate is based on business-context completeness; "
            "profile coverage is reported here for workflow quality."
        )
        return result + profile_status

    if action == "clear":
        if section == "business":
            return await clear_business_context_impl(ctx)
        if section == "software":
            profiles.software_profile = None
            return "Software profile cleared."
        if section == "data_assets":
            profiles.data_asset_profiles.clear()
            profiles.reset_id_counters("DP")
            return "Data asset profiles cleared."
        if section == "user_personas":
            profiles.user_personas.clear()
            profiles.reset_id_counters("UP")
            return "User personas cleared."
        if section == "nfrs":
            profiles.nfr_profile = profiles.NFRProfile()
            return "Non-functional requirements cleared."
        business_result = await clear_business_context_impl(ctx)
        profiles_result = await profiles.clear_classification_profiles_impl(ctx)
        return business_result + "\n" + profiles_result

    return "❌ Unsupported system-context operation."


# Register the single compact Phase 1 tool with the MCP server.
def register_tools(mcp):
    """Register unified system-context management with the MCP server."""

    @mcp.tool()
    async def manage_system_context(
        ctx: Context,
        action: SystemContextAction = Field(
            description="Operation: describe, plan, set, get, add, update, list, delete, validate, or clear",
        ),
        section: SystemContextSection = Field(
            default="all",
            description="Context section: business, software, data_assets, user_personas, nfrs, or all",
        ),
        values: Optional[Dict[str, Any]] = Field(
            default=None,
            description="Fields for one record, or section-keyed data when setting section=all",
        ),
        items: Optional[List[Dict[str, Any]]] = Field(
            default=None,
            description="Batch records for data_assets, user_personas, or nfrs",
        ),
        item_id: Optional[str] = Field(
            default=None,
            description="Profile ID for one update/delete, or quality class for an NFR delete",
        ),
        item_ids: Optional[List[str]] = Field(
            default=None,
            description="Profile IDs or NFR quality classes for a batch delete",
        ),
    ) -> str:
        """Manage all Phase 1 business context and classification profiles.

        Start with action="describe" to get the payload contract without loading
        every taxonomy field into this tool schema. A complete Phase 1 context can
        be submitted in one call with action="set", section="all". Values are
        checked by the canonical enum validators and Pydantic profile models.
        """
        return await manage_system_context_impl(
            ctx, action, section, values, items, item_id, item_ids,
        )
