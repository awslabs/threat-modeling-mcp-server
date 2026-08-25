"""Batch operation utilities for the Threat Modeling MCP Server.

This module provides helper functions for batch operations across all tools.
Batch operations allow multiple items to be added, updated, or deleted in a single
tool call while maintaining backwards compatibility with single-item operations.
"""

import inspect
from typing import Any, Callable, Dict, List, Optional
from loguru import logger


# The tool implementations report a refusal by returning prose rather than by
# raising, so a batch has to read the returned message to tell a real change from
# a no-op. Without this, deleting an ID that does not exist was counted as a
# success and the caller was told "Successfully deleted 1". These markers come
# from the failure messages the impls actually produce: "... not found",
# "Cannot delete X because ...", "Invalid control type: ...",
# "Priority must be between 1 and 10.", "... is already linked to ...". Success
# messages are uniform ("added with ID", "updated successfully", "deleted",
# "linked to", "added to", "removed from") and contain none of them.
FAILURE_MARKERS = (
    'not found',
    'cannot ',
    'invalid ',
    'must be ',
    'is already ',
    'is not in ',
    'is required',
    'no requirement recorded',
)


def _is_failure(result: Any) -> bool:
    """Report whether an impl's return value describes a refusal.

    Args:
        result: The value an impl returned

    Returns:
        True when the message indicates nothing was changed
    """
    if not isinstance(result, str):
        return False

    text = result.strip()
    if text.startswith('❌'):
        return True

    lowered = text.lower()
    if lowered.startswith('error') or 'error:' in lowered:
        return True

    return any(marker in lowered for marker in FAILURE_MARKERS)


def _describe_item_error(impl_fn: Callable, item: Dict[str, Any], error: Exception) -> str:
    """Describe a batch item that does not match the impl's signature.

    Calling `impl_fn(ctx, **item)` with a missing or misspelled key raises a bare
    TypeError whose text names the wrapper function, not the field at fault -- for
    example "add_asset_impl() missing 1 required positional argument:
    'classification'" reads as a server bug rather than a malformed item. Name the
    fields instead so the caller can fix the item.

    Args:
        impl_fn: The implementation function that was called
        item: The batch item that was passed as keyword arguments
        error: The TypeError raised by the call

    Returns:
        A message naming the missing, unexpected, and accepted fields, falling
        back to the original error text when the signature cannot be read
    """
    try:
        params = inspect.signature(impl_fn).parameters
    except (TypeError, ValueError):
        return str(error)

    accepted = [
        name for name, param in params.items()
        if name != 'ctx'
        and param.kind in (param.POSITIONAL_OR_KEYWORD, param.KEYWORD_ONLY)
    ]
    takes_extra_keys = any(
        param.kind is param.VAR_KEYWORD for param in params.values()
    )

    missing = [
        name for name in accepted
        if params[name].default is inspect.Parameter.empty and name not in item
    ]
    unexpected = [] if takes_extra_keys else [
        key for key in item if key not in accepted
    ]

    parts = []
    if missing:
        parts.append(f"missing required field(s): {', '.join(missing)}")
    if unexpected:
        parts.append(f"unexpected field(s): {', '.join(unexpected)}")

    if not parts:
        # The TypeError came from somewhere other than the argument list.
        return str(error)

    parts.append(f"accepted fields: {', '.join(accepted)}")
    return "; ".join(parts)


async def _call_one(
    ctx: Any,
    impl_fn: Callable,
    item: Dict[str, Any],
    label: str,
    results: List[str],
    errors: List[str],
) -> None:
    """Call an impl for one batch item and file the outcome as success or failure.

    Args:
        ctx: MCP context
        impl_fn: The implementation function to call
        item: The fields for this item, passed as keyword arguments
        label: How to identify this item in an error message (e.g. "Item 2")
        results: Collects messages from items that changed something
        errors: Collects messages from items that did not
    """
    try:
        result = await impl_fn(ctx, **item)
    except TypeError as e:
        errors.append(f"{label}: {_describe_item_error(impl_fn, item, e)}")
    except Exception as e:
        errors.append(f"{label}: {str(e)}")
    else:
        if _is_failure(result):
            errors.append(f"{label}: {result}")
        else:
            results.append(result)


async def batch_add(
    ctx: Any,
    items: Optional[List[Dict[str, Any]]],
    single_item_kwargs: Dict[str, Any],
    impl_fn: Callable,
    entity_name: str,
) -> str:
    """Handle batch or single add operations.

    If `items` is provided, iterates over the list and calls impl_fn for each item.
    Otherwise, calls impl_fn with the single_item_kwargs (original single-item behavior).

    Args:
        ctx: MCP context
        items: Optional list of dicts, each containing the fields for one item
        single_item_kwargs: The individual field parameters (used when items is None)
        impl_fn: The implementation function to call for each item
        entity_name: Name of the entity type for logging (e.g., "component")

    Returns:
        A confirmation message (single result or batch summary)
    """
    if items is not None:
        if not items:
            return f"No {entity_name}s provided in batch."

        logger.debug(f'Batch adding {len(items)} {entity_name}(s)')
        results: List[str] = []
        errors: List[str] = []

        for i, item in enumerate(items):
            await _call_one(ctx, impl_fn, item, f"Item {i + 1}", results, errors)

        # Build summary
        summary_parts = []
        if results:
            summary_parts.append(f"Successfully added {len(results)} {entity_name}(s):")
            for r in results:
                summary_parts.append(f"  - {r}")
        if errors:
            summary_parts.append(f"\nFailed to add {len(errors)} {entity_name}(s):")
            for e in errors:
                summary_parts.append(f"  - {e}")

        return "\n".join(summary_parts)
    else:
        # Single item mode - original behavior
        return await impl_fn(ctx, **single_item_kwargs)


async def batch_update(
    ctx: Any,
    items: Optional[List[Dict[str, Any]]],
    single_item_kwargs: Dict[str, Any],
    impl_fn: Callable,
    entity_name: str,
) -> str:
    """Handle batch or single update operations.

    If `items` is provided, iterates over the list and calls impl_fn for each item.
    Each item in the list must contain an 'id' field.
    Otherwise, calls impl_fn with the single_item_kwargs (original single-item behavior).

    Args:
        ctx: MCP context
        items: Optional list of dicts, each containing 'id' and fields to update
        single_item_kwargs: The individual field parameters (used when items is None)
        impl_fn: The implementation function to call for each item
        entity_name: Name of the entity type for logging

    Returns:
        A confirmation message (single result or batch summary)
    """
    if items is not None:
        if not items:
            return f"No {entity_name}s provided in batch."

        logger.debug(f'Batch updating {len(items)} {entity_name}(s)')
        results: List[str] = []
        errors: List[str] = []

        for i, item in enumerate(items):
            await _call_one(ctx, impl_fn, item, f"Item {i + 1}", results, errors)

        # Build summary
        summary_parts = []
        if results:
            summary_parts.append(f"Successfully updated {len(results)} {entity_name}(s):")
            for r in results:
                summary_parts.append(f"  - {r}")
        if errors:
            summary_parts.append(f"\nFailed to update {len(errors)} {entity_name}(s):")
            for e in errors:
                summary_parts.append(f"  - {e}")

        return "\n".join(summary_parts)
    else:
        # Single item mode - original behavior
        return await impl_fn(ctx, **single_item_kwargs)


async def batch_delete(
    ctx: Any,
    ids: Optional[List[str]],
    single_id: Optional[str],
    impl_fn: Callable,
    entity_name: str,
) -> str:
    """Handle batch or single delete operations.

    If `ids` is provided, iterates over the list and calls impl_fn for each id.
    Otherwise, calls impl_fn with the single_id (original single-item behavior).

    Args:
        ctx: MCP context
        ids: Optional list of IDs to delete
        single_id: The single ID parameter (used when ids is None)
        impl_fn: The implementation function to call for each id
        entity_name: Name of the entity type for logging

    Returns:
        A confirmation message (single result or batch summary)
    """
    if ids is not None:
        if not ids:
            return f"No {entity_name} IDs provided in batch."

        logger.debug(f'Batch deleting {len(ids)} {entity_name}(s)')
        results: List[str] = []
        errors: List[str] = []

        for item_id in ids:
            try:
                result = await impl_fn(ctx, item_id)
            except Exception as e:
                errors.append(f"ID {item_id}: {str(e)}")
            else:
                # A delete impl returns "... not found" instead of raising, so
                # counting every returned message reported IDs that were never
                # there as deleted.
                if _is_failure(result):
                    errors.append(f"ID {item_id}: {result}")
                else:
                    results.append(result)

        # Build summary
        summary_parts = []
        if results:
            summary_parts.append(f"Successfully deleted {len(results)} {entity_name}(s):")
            for r in results:
                summary_parts.append(f"  - {r}")
        if errors:
            summary_parts.append(f"\nFailed to delete {len(errors)} {entity_name}(s):")
            for e in errors:
                summary_parts.append(f"  - {e}")

        return "\n".join(summary_parts)
    else:
        # Single item mode - original behavior
        if single_id is None:
            return f"No {entity_name} ID provided."
        return await impl_fn(ctx, single_id)
