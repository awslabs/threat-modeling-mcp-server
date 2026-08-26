"""Shared helpers for compact MCP domain managers."""

import inspect
from enum import Enum
from types import UnionType
from typing import Any, Callable, Dict, List, Optional, Type, Union, get_args, get_origin

from threat_modeling_mcp_server.utils.batch_utils import (
    batch_add,
    batch_delete,
    batch_update,
)


def payload_error(impl_fn: Callable, payload: Dict[str, Any]) -> Optional[str]:
    """Describe missing or unexpected fields for an implementation call."""
    params = inspect.signature(impl_fn).parameters
    accepted = [
        name
        for name, param in params.items()
        if name != "ctx"
        and param.kind
        in (param.POSITIONAL_OR_KEYWORD, param.KEYWORD_ONLY)
    ]
    missing = [
        name
        for name in accepted
        if params[name].default is inspect.Parameter.empty and name not in payload
    ]
    unexpected = [key for key in payload if key not in accepted]

    problems = []
    if missing:
        problems.append(f"missing required field(s): {', '.join(missing)}")
    if unexpected:
        problems.append(f"unexpected field(s): {', '.join(unexpected)}")
    if not problems:
        return None
    problems.append(f"accepted fields: {', '.join(accepted)}")
    return "; ".join(problems)


async def call_impl(
    ctx: Any,
    impl_fn: Callable,
    payload: Optional[Dict[str, Any]],
    label: str,
) -> str:
    """Validate a generic payload and call one typed implementation."""
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        return f"❌ {label} values must be an object."

    error = payload_error(impl_fn, payload)
    if error:
        return f"❌ {label}: {error}"

    try:
        return await impl_fn(ctx, **payload)
    except Exception as exc:
        return f"❌ {label} failed: {exc}"


async def dispatch_entity_action(
    ctx: Any,
    action: str,
    label: str,
    *,
    values: Optional[Dict[str, Any]] = None,
    items: Optional[List[Dict[str, Any]]] = None,
    item_id: Optional[str] = None,
    item_ids: Optional[List[str]] = None,
    add_impl: Optional[Callable] = None,
    update_impl: Optional[Callable] = None,
    list_impl: Optional[Callable] = None,
    get_impl: Optional[Callable] = None,
    delete_impl: Optional[Callable] = None,
) -> str:
    """Dispatch standard CRUD actions for one entity type."""
    if action == "add":
        if add_impl is None:
            return f"❌ Adding {label}s is not supported."
        if item_id is not None or item_ids is not None:
            return "❌ action='add' accepts values or items, not item_id or item_ids."
        if values is not None and items is not None:
            return "❌ Provide values for one record or items for a batch, not both."
        if items is not None:
            if not isinstance(items, list):
                return f"❌ {label} items must be a list."
            return await batch_add(ctx, items, {}, add_impl, label)
        return await call_impl(ctx, add_impl, values, label)

    if action == "update":
        if update_impl is None:
            return f"❌ Updating {label}s is not supported."
        if item_ids is not None:
            return "❌ Batch updates belong in items; item_ids is only for delete."
        if items is not None and (values is not None or item_id is not None):
            return "❌ Provide items for a batch or item_id plus values for one update, not both."
        if items is not None:
            if not isinstance(items, list):
                return f"❌ {label} items must be a list."
            return await batch_update(ctx, items, {}, update_impl, label)
        if values is not None and not isinstance(values, dict):
            return f"❌ {label} values must be an object."
        payload = dict(values or {})
        if item_id is not None:
            if "id" in payload and payload["id"] != item_id:
                return "❌ item_id conflicts with values['id']."
            payload["id"] = item_id
        return await call_impl(ctx, update_impl, payload, label)

    if action == "list":
        if list_impl is None:
            return f"❌ Listing {label}s is not supported."
        if any(argument is not None for argument in (items, item_id, item_ids)):
            return "❌ action='list' accepts only optional filter fields in values."
        return await call_impl(ctx, list_impl, values, label)

    if action == "get":
        if get_impl is None:
            return f"❌ Getting one {label} is not supported."
        if any(argument is not None for argument in (values, items, item_ids)):
            return "❌ action='get' accepts only item_id."
        if item_id is None:
            return f"❌ action='get' requires the {label} ID in item_id."
        return await call_impl(ctx, get_impl, {"id": item_id}, label)

    if action == "delete":
        if delete_impl is None:
            return f"❌ Deleting {label}s is not supported."
        if values is not None or items is not None:
            return "❌ action='delete' accepts item_id or item_ids, not values or items."
        if item_id is not None and item_ids is not None:
            return "❌ Provide item_id or item_ids, not both."
        if item_id is None and item_ids is None:
            return f"❌ action='delete' requires {label} IDs in item_id or item_ids."
        if item_ids is not None and not isinstance(item_ids, list):
            return f"❌ {label} item_ids must be a list."
        return await batch_delete(ctx, item_ids, item_id, delete_impl, label)

    return f"❌ Unsupported {label} action '{action}'."


def reject_arguments(
    action: str,
    *,
    values: Any = None,
    items: Any = None,
    item_id: Any = None,
    item_ids: Any = None,
) -> Optional[str]:
    """Reject generic payload arguments for actions that take none."""
    if any(argument is not None for argument in (values, items, item_id, item_ids)):
        return (
            f"❌ action='{action}' does not accept values, items, item_id, "
            "or item_ids."
        )
    return None


def _contains_list(annotation: Any) -> bool:
    origin = get_origin(annotation)
    if origin is list:
        return True
    return any(_contains_list(argument) for argument in get_args(annotation))


def _type_hint(annotation: Any) -> str:
    origin = get_origin(annotation)
    arguments = [
        argument
        for argument in get_args(annotation)
        if argument is not type(None)
    ]
    if origin is list:
        return "list"
    if origin is dict:
        return "object"
    if origin in (Union, UnionType) and len(arguments) == 1:
        return _type_hint(arguments[0])
    if annotation is str:
        return "text"
    if annotation is bool:
        return "true or false"
    if annotation is int:
        return "integer"
    if annotation is float:
        return "number"
    return "value"


def format_impl_fields(
    impl_fn: Callable,
    enum_fields: Optional[Dict[str, Type[Enum]]] = None,
    excluded: Optional[set[str]] = None,
) -> str:
    """Render a compact payload contract from a typed implementation."""
    enum_fields = enum_fields or {}
    excluded = (excluded or set()) | {"ctx"}
    lines = []

    for name, parameter in inspect.signature(impl_fn).parameters.items():
        if name in excluded:
            continue
        required = parameter.default is inspect.Parameter.empty
        requirement = "required" if required else "optional"
        if name in enum_fields:
            choices = ", ".join(member.value for member in enum_fields[name])
            plurality = (
                "one or more of" if _contains_list(parameter.annotation) else "one of"
            )
            hint = f"{plurality}: {choices}"
        else:
            hint = _type_hint(parameter.annotation)
        lines.append(f"- `{name}` ({requirement}): {hint}")

    return "\n".join(lines)
