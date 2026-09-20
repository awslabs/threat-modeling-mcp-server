"""Shared Threat Composer text-length limits and truncation helper.

Threat Composer validates imported models against a Zod schema with strict
per-field length caps. The server must keep its exported values within those
caps or the ``.tc.json`` file is rejected on import. Centralising the limits
and the truncation logic here keeps the threat/mitigation write path (see
``tools/threat_generator.py``) and the exporter (see
``utils/comprehensive_exporter.py``) from drifting apart.

Values mirror ``packages/threat-composer/src/configs/constants.ts`` in
awslabs/threat-composer:

- ``SINGLE_FIELD_INPUT_TAG_MAX_LENGTH`` = 30  -> tags
- ``SINGLE_FIELD_INPUT_MAX_LENGTH``     = 200 -> threat statement elements
- ``statement``                          = 200 * 7 = 1400 (composed statement)
- ``FREE_TEXT_INPUT_SMALL_MAX_LENGTH``  = 1000 -> assumption / mitigation content
"""

# Threat statement elements: threatSource, prerequisites, threatAction,
# threatImpact, customTemplate, and each impactedGoal / impactedAsset item.
SINGLE_FIELD_MAX_LENGTH = 200

# The composed threat statement (schema caps this at SINGLE_FIELD * 7).
STATEMENT_MAX_LENGTH = SINGLE_FIELD_MAX_LENGTH * 7

# Each tag string.
TAG_MAX_LENGTH = 30

# Free-text small: assumption and mitigation content.
FREE_TEXT_SMALL_MAX_LENGTH = 1000


def truncate_field(value: str, max_length: int = SINGLE_FIELD_MAX_LENGTH) -> str:
    """Truncate ``value`` to ``max_length`` for Threat Composer compliance.

    Prefers to break at the last whitespace before the limit so a field is not
    cut mid-word, but only when that break keeps most of the content (past 60%
    of the limit); otherwise it hard-cuts at ``max_length``.
    """
    if not value or len(value) <= max_length:
        return value
    truncated = value[:max_length]
    last_space = truncated.rfind(' ')
    if last_space > max_length * 0.6:
        return truncated[:last_space]
    return truncated


def truncate_tags(tags):
    """Clamp every tag to ``TAG_MAX_LENGTH``, dropping empties.

    Threat Composer rejects tags over 30 characters and treats blank tags as
    invalid, so empty/whitespace-only tags are removed.
    """
    if not tags:
        return []
    result = []
    for tag in tags:
        if tag is None:
            continue
        clamped = truncate_field(tag, TAG_MAX_LENGTH)
        if clamped.strip():
            result.append(clamped)
    return result
