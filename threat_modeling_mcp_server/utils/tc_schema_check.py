"""Lightweight self-validation of an exported Threat Composer model.

The exporter clamps every field it knows about, but a future change could add
a field or miss a limit and silently produce a ``.tc.json`` that Threat
Composer rejects on import. This module re-checks the assembled export payload
against the same constraints just before it is written, so such a regression
fails loudly (and close to the code that caused it) instead of at import time
in a user's browser.

It intentionally avoids a third-party JSON-schema dependency: it encodes only
the constraints Threat Composer actually enforces on the fields this server
emits, mirroring ``packages/threat-composer/src/configs/constants.ts`` and the
``.strict()`` threat schema (which forbids unknown top-level keys).
"""

from typing import Any, Dict, List

from threat_modeling_mcp_server.utils.text_limits import (
    FREE_TEXT_SMALL_MAX_LENGTH,
    SINGLE_FIELD_MAX_LENGTH,
    STATEMENT_MAX_LENGTH,
    TAG_MAX_LENGTH,
)

# Minimum id length Threat Composer requires (UUID string form).
_MIN_ID_LENGTH = 36

# The only keys the strict Threat Composer schema accepts at the top level.
_ALLOWED_TOP_LEVEL_KEYS = {
    "schema",
    "applicationInfo",
    "architecture",
    "dataflow",
    "assumptions",
    "mitigations",
    "assumptionLinks",
    "mitigationLinks",
    "threats",
}

_THREAT_SINGLE_FIELDS = (
    "threatSource",
    "prerequisites",
    "threatAction",
    "threatImpact",
)


class ThreatComposerSchemaError(ValueError):
    """Raised when an assembled export would violate the Threat Composer schema."""


def _check_len(errors: List[str], where: str, value: Any, limit: int) -> None:
    if isinstance(value, str) and len(value) > limit:
        errors.append(f"{where}: {len(value)} chars exceeds limit {limit}")


def validate_threat_composer_payload(data: Dict[str, Any]) -> List[str]:
    """Return a list of schema violations for ``data`` (empty when valid).

    Checks unknown top-level keys, id lengths, per-field length caps, tag caps,
    and that every ``mitigationLinks`` reference resolves to an exported threat
    or mitigation id.
    """
    errors: List[str] = []

    unknown = set(data) - _ALLOWED_TOP_LEVEL_KEYS
    if unknown:
        errors.append(
            "unrecognized top-level keys: " + ", ".join(sorted(unknown))
        )

    threat_ids = set()
    for i, threat in enumerate(data.get("threats", [])):
        tid = threat.get("id", "")
        threat_ids.add(tid)
        if len(str(tid)) < _MIN_ID_LENGTH:
            errors.append(f"threats[{i}].id: '{tid}' shorter than {_MIN_ID_LENGTH}")
        for field in _THREAT_SINGLE_FIELDS:
            _check_len(errors, f"threats[{i}].{field}", threat.get(field), SINGLE_FIELD_MAX_LENGTH)
        _check_len(errors, f"threats[{i}].statement", threat.get("statement"), STATEMENT_MAX_LENGTH)
        for j, tag in enumerate(threat.get("tags", []) or []):
            _check_len(errors, f"threats[{i}].tags[{j}]", tag, TAG_MAX_LENGTH)
        for j, goal in enumerate(threat.get("impactedGoal", []) or []):
            _check_len(errors, f"threats[{i}].impactedGoal[{j}]", goal, SINGLE_FIELD_MAX_LENGTH)
        for j, asset in enumerate(threat.get("impactedAssets", []) or []):
            _check_len(errors, f"threats[{i}].impactedAssets[{j}]", asset, SINGLE_FIELD_MAX_LENGTH)

    mitigation_ids = set()
    for i, mitigation in enumerate(data.get("mitigations", [])):
        mid = mitigation.get("id", "")
        mitigation_ids.add(mid)
        if len(str(mid)) < _MIN_ID_LENGTH:
            errors.append(f"mitigations[{i}].id: '{mid}' shorter than {_MIN_ID_LENGTH}")
        _check_len(errors, f"mitigations[{i}].content", mitigation.get("content"), FREE_TEXT_SMALL_MAX_LENGTH)

    for i, assumption in enumerate(data.get("assumptions", [])):
        _check_len(errors, f"assumptions[{i}].content", assumption.get("content"), FREE_TEXT_SMALL_MAX_LENGTH)

    for i, link in enumerate(data.get("mitigationLinks", [])):
        linked = link.get("linkedId", "")
        mit = link.get("mitigationId", "")
        if len(str(linked)) < _MIN_ID_LENGTH:
            errors.append(f"mitigationLinks[{i}].linkedId: '{linked}' shorter than {_MIN_ID_LENGTH}")
        if len(str(mit)) < _MIN_ID_LENGTH:
            errors.append(f"mitigationLinks[{i}].mitigationId: '{mit}' shorter than {_MIN_ID_LENGTH}")
        if threat_ids and linked not in threat_ids:
            errors.append(f"mitigationLinks[{i}].linkedId: '{linked}' does not resolve to a threat")
        if mitigation_ids and mit not in mitigation_ids:
            errors.append(f"mitigationLinks[{i}].mitigationId: '{mit}' does not resolve to a mitigation")

    return errors
