"""Structured code-validation state and MCP tool."""

import hashlib
import json
from typing import Any, Dict, List, Literal, Optional

from loguru import logger
from mcp.server.fastmcp import Context
from pydantic import Field, ValidationError

from threat_modeling_mcp_server.models.code_validation_models import (
    MitigationCodeFinding,
    MitigationValidationOutcome,
    ThreatCodeFinding,
    ThreatValidationOutcome,
)
from threat_modeling_mcp_server.models.threat_models import (
    MitigationStatus,
    ThreatStatus,
)


CodeValidationAction = Literal[
    "describe", "record", "get", "validate", "report", "clear",
]

validation_project_directory: Optional[str] = None
threat_findings: Dict[str, ThreatCodeFinding] = {}
mitigation_findings: Dict[str, MitigationCodeFinding] = {}
finding_fingerprints: Dict[str, str] = {}
report_fingerprint: Optional[str] = None


THREAT_STATUS_BY_OUTCOME = {
    ThreatValidationOutcome.FULLY_MITIGATED: ThreatStatus.RESOLVED,
    ThreatValidationOutcome.PARTIALLY_MITIGATED: ThreatStatus.IDENTIFIED,
    ThreatValidationOutcome.NOT_MITIGATED: ThreatStatus.IDENTIFIED,
    ThreatValidationOutcome.NOT_APPLICABLE: ThreatStatus.NOT_USEFUL,
}

MITIGATION_STATUS_BY_OUTCOME = {
    MitigationValidationOutcome.IMPLEMENTED: MitigationStatus.RESOLVED,
    MitigationValidationOutcome.PARTIALLY_IMPLEMENTED: MitigationStatus.IN_PROGRESS,
    MitigationValidationOutcome.NOT_IMPLEMENTED: MitigationStatus.IDENTIFIED,
    MitigationValidationOutcome.NOT_APPLICABLE: MitigationStatus.WILL_NOT_ACTION,
}


def _threat_model_state():
    """Return the live threat, mitigation, and link stores."""
    from threat_modeling_mcp_server.tools import threat_generator

    return (
        threat_generator.threats,
        threat_generator.mitigations,
        threat_generator.mitigation_links,
    )


def _project_directory() -> str:
    """Return the project currently selected by the orchestrator."""
    from threat_modeling_mcp_server.tools import step_orchestrator

    return step_orchestrator.project_directory


def _record_fingerprint(kind: str, record_id: str) -> str:
    """Fingerprint validation-relevant record data and mitigation links."""
    threats, mitigations, links = _threat_model_state()
    if kind == "threat":
        record = threats[record_id]
        linked_ids = sorted(
            link.mitigationId for link in links if link.linkedId == record_id
        )
    else:
        record = mitigations[record_id]
        linked_ids = sorted(
            link.linkedId for link in links if link.mitigationId == record_id
        )

    payload = record.model_dump(mode="json", exclude={"status"})
    payload["linked_ids"] = linked_ids
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _finding_key(kind: str, record_id: str) -> str:
    return f"{kind}:{record_id}"


def _snapshot_fingerprint() -> str:
    """Fingerprint the complete, current validation snapshot."""
    threats, mitigations, _ = _threat_model_state()
    payload = {
        "project_directory": validation_project_directory,
        "threats": {
            threat_id: {
                "finding": threat_findings[threat_id].model_dump(mode="json"),
                "record": _record_fingerprint("threat", threat_id),
            }
            for threat_id in sorted(threats)
        },
        "mitigations": {
            mitigation_id: {
                "finding": mitigation_findings[mitigation_id].model_dump(mode="json"),
                "record": _record_fingerprint("mitigation", mitigation_id),
            }
            for mitigation_id in sorted(mitigations)
        },
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _coverage_status() -> Dict[str, Any]:
    """Return the canonical Phase 7.5 coverage and freshness status."""
    threats, mitigations, _ = _threat_model_state()
    project_directory = _project_directory()
    project_matches = validation_project_directory == project_directory

    missing_threats = sorted(set(threats) - set(threat_findings))
    missing_mitigations = sorted(set(mitigations) - set(mitigation_findings))
    orphan_threats = sorted(set(threat_findings) - set(threats))
    orphan_mitigations = sorted(set(mitigation_findings) - set(mitigations))

    stale_threats = sorted(
        threat_id
        for threat_id in set(threats) & set(threat_findings)
        if finding_fingerprints.get(_finding_key("threat", threat_id))
        != _record_fingerprint("threat", threat_id)
    )
    stale_mitigations = sorted(
        mitigation_id
        for mitigation_id in set(mitigations) & set(mitigation_findings)
        if finding_fingerprints.get(_finding_key("mitigation", mitigation_id))
        != _record_fingerprint("mitigation", mitigation_id)
    )

    coverage_complete = (
        bool(threats)
        and bool(mitigations)
        and project_matches
        and not missing_threats
        and not missing_mitigations
        and not stale_threats
        and not stale_mitigations
    )
    snapshot = _snapshot_fingerprint() if coverage_complete else None
    report_current = snapshot is not None and report_fingerprint == snapshot

    return {
        "project_directory": project_directory,
        "validation_project_directory": validation_project_directory,
        "project_matches": project_matches,
        "threats_reviewed": len(set(threats) & set(threat_findings)),
        "threats_total": len(threats),
        "mitigations_reviewed": len(set(mitigations) & set(mitigation_findings)),
        "mitigations_total": len(mitigations),
        "missing_threat_ids": missing_threats,
        "missing_mitigation_ids": missing_mitigations,
        "stale_threat_ids": stale_threats,
        "stale_mitigation_ids": stale_mitigations,
        "orphan_threat_ids": orphan_threats,
        "orphan_mitigation_ids": orphan_mitigations,
        "coverage_complete": coverage_complete,
        "report_current": report_current,
        "is_complete": coverage_complete and report_current,
    }


def code_validation_is_complete() -> bool:
    """Return whether the current code-validation snapshot is complete."""
    return _coverage_status()["is_complete"]


def clear_code_validation_state() -> None:
    """Clear all recorded code-validation state in place."""
    global validation_project_directory, report_fingerprint

    validation_project_directory = None
    report_fingerprint = None
    threat_findings.clear()
    mitigation_findings.clear()
    finding_fingerprints.clear()


def _parse_findings(
    values: Dict[str, Any],
) -> tuple[List[ThreatCodeFinding], List[MitigationCodeFinding], Optional[str]]:
    """Validate one record request without changing model state."""
    allowed = {"threat_findings", "mitigation_findings"}
    unexpected = sorted(set(values) - allowed)
    if unexpected:
        return [], [], f"unexpected field(s): {', '.join(unexpected)}"

    raw_threats = values.get("threat_findings", [])
    raw_mitigations = values.get("mitigation_findings", [])
    if not isinstance(raw_threats, list) or not isinstance(raw_mitigations, list):
        return [], [], "threat_findings and mitigation_findings must be lists"
    if not raw_threats and not raw_mitigations:
        return [], [], "provide at least one threat or mitigation finding"

    try:
        parsed_threats = [ThreatCodeFinding.model_validate(item) for item in raw_threats]
        parsed_mitigations = [
            MitigationCodeFinding.model_validate(item) for item in raw_mitigations
        ]
    except ValidationError as exc:
        return [], [], str(exc)

    threat_ids = [finding.threat_id for finding in parsed_threats]
    mitigation_ids = [finding.mitigation_id for finding in parsed_mitigations]
    duplicate_threats = sorted(
        record_id for record_id in set(threat_ids) if threat_ids.count(record_id) > 1
    )
    duplicate_mitigations = sorted(
        record_id
        for record_id in set(mitigation_ids)
        if mitigation_ids.count(record_id) > 1
    )
    if duplicate_threats or duplicate_mitigations:
        problems = []
        if duplicate_threats:
            problems.append(f"duplicate threat IDs: {', '.join(duplicate_threats)}")
        if duplicate_mitigations:
            problems.append(
                f"duplicate mitigation IDs: {', '.join(duplicate_mitigations)}"
            )
        return [], [], "; ".join(problems)

    threats, mitigations, _ = _threat_model_state()
    unknown_threats = sorted(set(threat_ids) - set(threats))
    unknown_mitigations = sorted(set(mitigation_ids) - set(mitigations))
    if unknown_threats or unknown_mitigations:
        problems = []
        if unknown_threats:
            problems.append(f"unknown threat IDs: {', '.join(unknown_threats)}")
        if unknown_mitigations:
            problems.append(
                f"unknown mitigation IDs: {', '.join(unknown_mitigations)}"
            )
        return [], [], "; ".join(problems)

    return parsed_threats, parsed_mitigations, None


def record_code_validation_findings(values: Optional[Dict[str, Any]]) -> str:
    """Atomically record findings and apply their status transitions."""
    global validation_project_directory, report_fingerprint

    if not isinstance(values, dict):
        return "❌ action='record' requires a values object."

    parsed_threats, parsed_mitigations, error = _parse_findings(values)
    if error:
        return f"❌ Code-validation findings rejected: {error}."

    threats, mitigations, _ = _threat_model_state()
    current_project = _project_directory()
    project_changed = (
        validation_project_directory is not None
        and validation_project_directory != current_project
    )
    if project_changed:
        clear_code_validation_state()
    validation_project_directory = current_project

    for finding in parsed_threats:
        threats[finding.threat_id].status = THREAT_STATUS_BY_OUTCOME[finding.outcome]
        threat_findings[finding.threat_id] = finding
        finding_fingerprints[_finding_key("threat", finding.threat_id)] = (
            _record_fingerprint("threat", finding.threat_id)
        )

    for finding in parsed_mitigations:
        mitigations[finding.mitigation_id].status = MITIGATION_STATUS_BY_OUTCOME[
            finding.outcome
        ]
        mitigation_findings[finding.mitigation_id] = finding
        finding_fingerprints[_finding_key("mitigation", finding.mitigation_id)] = (
            _record_fingerprint("mitigation", finding.mitigation_id)
        )

    report_fingerprint = None
    status = _coverage_status()
    reset_note = (
        " Previous findings were cleared because the project changed."
        if project_changed else ""
    )
    return (
        f"Recorded {len(parsed_threats)} threat finding(s) and "
        f"{len(parsed_mitigations)} mitigation finding(s).{reset_note}\n"
        f"Coverage: {status['threats_reviewed']}/{status['threats_total']} threats, "
        f"{status['mitigations_reviewed']}/{status['mitigations_total']} mitigations."
    )


def build_code_validation_export_data() -> Dict[str, Any]:
    """Build serializable code-validation data for summaries and exports."""
    threats, mitigations, _ = _threat_model_state()
    status = _coverage_status()
    return {
        **status,
        "threat_findings": [
            threat_findings[record_id].model_dump(mode="json")
            for record_id in sorted(set(threats) & set(threat_findings))
        ],
        "mitigation_findings": [
            mitigation_findings[record_id].model_dump(mode="json")
            for record_id in sorted(set(mitigations) & set(mitigation_findings))
        ],
    }


def _format_id_list(values: List[str]) -> str:
    return ", ".join(values) if values else "None"


def format_code_validation_status() -> str:
    """Format current coverage, freshness, and findings."""
    status = _coverage_status()
    lines = [
        "# Code Validation Status",
        "",
        f"- **Project directory**: {status['project_directory']}",
        f"- **Threat coverage**: {status['threats_reviewed']}/{status['threats_total']}",
        (
            f"- **Mitigation coverage**: {status['mitigations_reviewed']}/"
            f"{status['mitigations_total']}"
        ),
        f"- **Coverage complete**: {'Yes' if status['coverage_complete'] else 'No'}",
        f"- **Report current**: {'Yes' if status['report_current'] else 'No'}",
        f"- **Phase complete**: {'Yes' if status['is_complete'] else 'No'}",
        "",
        f"- Missing threats: {_format_id_list(status['missing_threat_ids'])}",
        f"- Missing mitigations: {_format_id_list(status['missing_mitigation_ids'])}",
        f"- Stale threats: {_format_id_list(status['stale_threat_ids'])}",
        f"- Stale mitigations: {_format_id_list(status['stale_mitigation_ids'])}",
    ]
    if not status["project_matches"] and validation_project_directory is not None:
        lines.append(f"- Recorded project differs: {validation_project_directory}")
    return "\n".join(lines)


def generate_code_validation_markdown(
    heading: str = "# Code Validation Report",
) -> str:
    """Render an evidence-based report from current findings."""
    threats, mitigations, links = _threat_model_state()
    status = _coverage_status()
    lines = [
        heading,
        "",
        f"**Project Directory**: {status['project_directory']}",
        (
            f"**Coverage**: {status['threats_reviewed']}/{status['threats_total']} "
            f"threats; {status['mitigations_reviewed']}/"
            f"{status['mitigations_total']} mitigations"
        ),
        "",
        "### Threat Findings",
        "",
    ]

    current_threat_ids = sorted(set(threats) & set(threat_findings))
    if not current_threat_ids:
        lines.extend(["*No threat findings recorded.*", ""])
    for threat_id in current_threat_ids:
        threat = threats[threat_id]
        finding = threat_findings[threat_id]
        linked = sorted(
            link.mitigationId for link in links if link.linkedId == threat_id
        )
        lines.extend([
            f"#### {threat_id}: {threat.threatAction}",
            "",
            f"- **Outcome**: {finding.outcome.value}",
            f"- **Threat status**: {threat.status.value}",
            f"- **Linked mitigations**: {_format_id_list(linked)}",
            "- **Evidence**:",
        ])
        lines.extend(f"  - {item}" for item in finding.evidence)
        if finding.recommendation:
            lines.append(f"- **Recommendation**: {finding.recommendation}")
        lines.append("")

    lines.extend(["### Mitigation Findings", ""])
    current_mitigation_ids = sorted(set(mitigations) & set(mitigation_findings))
    if not current_mitigation_ids:
        lines.extend(["*No mitigation findings recorded.*", ""])
    for mitigation_id in current_mitigation_ids:
        mitigation = mitigations[mitigation_id]
        finding = mitigation_findings[mitigation_id]
        linked = sorted(
            link.linkedId for link in links if link.mitigationId == mitigation_id
        )
        lines.extend([
            f"#### {mitigation_id}: {mitigation.content}",
            "",
            f"- **Outcome**: {finding.outcome.value}",
            f"- **Mitigation status**: {mitigation.status.value}",
            f"- **Linked threats**: {_format_id_list(linked)}",
            "- **Evidence**:",
        ])
        lines.extend(f"  - {item}" for item in finding.evidence)
        if finding.recommendation:
            lines.append(f"- **Recommendation**: {finding.recommendation}")
        lines.append("")

    if not status["coverage_complete"]:
        lines.extend([
            "### Incomplete Coverage",
            "",
            f"- Missing threats: {_format_id_list(status['missing_threat_ids'])}",
            f"- Missing mitigations: {_format_id_list(status['missing_mitigation_ids'])}",
            f"- Stale threats: {_format_id_list(status['stale_threat_ids'])}",
            f"- Stale mitigations: {_format_id_list(status['stale_mitigation_ids'])}",
            "",
        ])

    return "\n".join(lines).rstrip() + "\n"


def validate_code_validation_state() -> str:
    """Validate coverage without marking the report complete."""
    status = _coverage_status()
    if status["coverage_complete"]:
        return (
            "✅ Code-validation coverage is complete. "
            "Call action='report' to finalize Phase 7.5."
        )
    return "❌ Code-validation coverage is incomplete.\n\n" + format_code_validation_status()


def generate_code_validation_report() -> str:
    """Generate the report and mark this exact snapshot as reviewed."""
    global report_fingerprint

    status = _coverage_status()
    if not status["coverage_complete"]:
        return (
            "❌ Cannot generate the final code-validation report until coverage "
            "is complete.\n\n" + format_code_validation_status()
        )

    report = generate_code_validation_markdown()
    report_fingerprint = _snapshot_fingerprint()
    return report


def code_validation_guide() -> str:
    """Return the compact contract for recording validation findings."""
    return """# Code Validation Manager

Use the project directory already recorded with `set_project_directory_tool`.
Inspect the code yourself, then call `action="record"` with a `values` object:

```json
{
  "threat_findings": [
    {
      "threat_id": "THREAT_ID",
      "outcome": "fully_mitigated",
      "evidence": ["src/auth.py:42 verifies signed access tokens"],
      "recommendation": "Optional follow-up"
    }
  ],
  "mitigation_findings": [
    {
      "mitigation_id": "MITIGATION_ID",
      "outcome": "implemented",
      "evidence": ["src/auth.py:42 enforces the planned control"],
      "recommendation": "Optional follow-up"
    }
  ]
}
```

Threat outcomes: `fully_mitigated`, `partially_mitigated`, `not_mitigated`,
`not_applicable`.

Mitigation outcomes: `implemented`, `partially_implemented`, `not_implemented`,
`not_applicable`.

Every current threat and mitigation requires a finding. Use `validate` to check
coverage, then `report` to produce the evidence-based report and complete Phase
7.5. `get` shows current progress and `clear` starts the validation over.
"""


async def manage_code_validation_impl(
    ctx: Context,
    action: CodeValidationAction,
    values: Optional[Dict[str, Any]] = None,
) -> str:
    """Dispatch one code-validation action."""
    logger.info(f"Managing code validation: {action}")

    if action == "describe":
        return code_validation_guide()
    if action == "record":
        return record_code_validation_findings(values)
    if action == "get":
        return format_code_validation_status() + "\n\n" + generate_code_validation_markdown()
    if action == "validate":
        return validate_code_validation_state()
    if action == "report":
        return generate_code_validation_report()
    if action == "clear":
        clear_code_validation_state()
        return "Code-validation findings cleared."
    return "❌ Unsupported code-validation action."


def register_tools(mcp):
    """Register the consolidated code-validation tool."""

    @mcp.tool()
    async def manage_code_validation(
        ctx: Context,
        action: CodeValidationAction = Field(
            description="Operation: describe, record, get, validate, report, or clear",
        ),
        values: Optional[Dict[str, Any]] = Field(
            default=None,
            description="Finding arrays for action='record'; omit for other actions",
        ),
    ) -> str:
        """Record and report evidence-based Phase 7.5 code validation.

        Start with action="describe" for the finding contract. The tool does not
        inspect source code; it validates findings, updates statuses atomically,
        tracks complete coverage, and renders the final report.
        """
        return await manage_code_validation_impl(ctx, action, values)
