"""Threat Generator and Analyzer for the Cline Threat Modeling MCP Server."""

import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple
from loguru import logger
from mcp.server.fastmcp import Context

from threat_modeling_mcp_server.models.threat_models import (
    Threat, Mitigation, ThreatCategory, ThreatSeverity, ThreatLikelihood,
    ThreatStatus, MitigationType, MitigationStatus, MitigationCost,
    MitigationEffectiveness, MetadataItem, MitigationLink,
    ResidualRiskAssessment, ResidualRiskDecision,
)
from threat_modeling_mcp_server.validation.enum_validator import (
    validate_enum_with_enhanced_error,
)
from threat_modeling_mcp_server.utils.id_utils import next_id, reset_id_counters


# Global dictionaries to store threats and mitigations
threats: Dict[str, Threat] = {}
mitigations: Dict[str, Mitigation] = {}
mitigation_links: List[MitigationLink] = []
residual_risk_assessments: Dict[str, ResidualRiskAssessment] = {}

# Counter for numeric IDs
threat_counter = 1
mitigation_counter = 1


THREAT_COMPOSER_MAX_LENGTH = 200
STATEMENT_MAX_LENGTH = 1400


def _truncate_field(value: str, max_length: int = THREAT_COMPOSER_MAX_LENGTH) -> str:
    """Truncate a string to max_length for Threat Composer schema compliance."""
    if not value or len(value) <= max_length:
        return value
    truncated = value[:max_length]
    last_space = truncated.rfind(' ')
    if last_space > max_length * 0.6:
        return truncated[:last_space]
    return truncated


def _validated_update(model, updates: Dict[str, Any]):
    candidate = model.model_dump()
    candidate.update(updates)
    return type(model).model_validate(candidate)


def threat_assessment_fingerprint(
    threat_id: str,
    threat_override: Optional[Threat] = None,
) -> str:
    """Hash the threat and linked mitigations used by a residual assessment."""
    threat = threat_override or threats[threat_id]
    linked_ids = sorted(
        link.mitigationId
        for link in mitigation_links
        if link.linkedId == threat_id and link.mitigationId in mitigations
    )
    payload = {
        "threat": threat.model_dump(mode="json"),
        "linked_mitigations": [
            mitigations[mitigation_id].model_dump(mode="json")
            for mitigation_id in linked_ids
        ],
    }
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def is_residual_assessment_current(threat_id: str) -> bool:
    """Return whether a threat has an assessment for its current model state."""
    assessment = residual_risk_assessments.get(threat_id)
    if assessment is None or threat_id not in threats:
        return False
    return assessment.source_fingerprint == threat_assessment_fingerprint(threat_id)


_ASSESSMENT_STATUS = {
    ResidualRiskDecision.OPEN: ThreatStatus.IDENTIFIED,
    ResidualRiskDecision.ACCEPTED: ThreatStatus.RESOLVED,
    ResidualRiskDecision.MITIGATED: ThreatStatus.RESOLVED,
    ResidualRiskDecision.NOT_APPLICABLE: ThreatStatus.NOT_USEFUL,
}


def _prepare_residual_assessment(
    *,
    threat_id: str,
    decision: str,
    residual_severity: Optional[str],
    residual_likelihood: Optional[str],
    rationale: str,
) -> Tuple[Threat, ResidualRiskAssessment]:
    if threat_id not in threats:
        raise ValueError(f"Threat with ID {threat_id} not found")

    assessment = ResidualRiskAssessment(
        threat_id=threat_id,
        decision=decision,
        residual_severity=residual_severity,
        residual_likelihood=residual_likelihood,
        rationale=rationale,
        source_fingerprint="pending",
    )
    candidate_threat = _validated_update(
        threats[threat_id],
        {"status": _ASSESSMENT_STATUS[assessment.decision]},
    )
    assessment = assessment.model_copy(
        update={
            "source_fingerprint": threat_assessment_fingerprint(
                threat_id, candidate_threat
            )
        }
    )
    return candidate_threat, assessment


def _format_residual_assessment(threat_id: str) -> str:
    assessment = residual_risk_assessments.get(threat_id)
    if assessment is None:
        return "**Residual Risk Assessment:** Not recorded\n\n"

    freshness = "Current" if is_residual_assessment_current(threat_id) else "Stale"
    result = "**Residual Risk Assessment:**\n\n"
    result += f"- Decision: {assessment.decision.value}\n"
    if assessment.residual_severity:
        result += f"- Residual Severity: {assessment.residual_severity.value}\n"
    if assessment.residual_likelihood:
        result += f"- Residual Likelihood: {assessment.residual_likelihood.value}\n"
    result += f"- Rationale: {assessment.rationale}\n"
    result += f"- Assessment State: {freshness}\n\n"
    return result


async def add_threat_impl(
    ctx: Context,
    threat_source: str,
    prerequisites: str,
    threat_action: str,
    threat_impact: str,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    likelihood: Optional[str] = None,
    affected_components: Optional[List[str]] = None,
    affected_assets: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
) -> str:
    """Add a new threat to the model."""
    global threat_counter

    logger.debug(f'Adding threat: {threat_source} {threat_action}')
    
    # Enforce Threat Composer schema maxLength constraints
    threat_source = _truncate_field(threat_source)
    prerequisites = _truncate_field(prerequisites)
    threat_action = _truncate_field(threat_action)
    threat_impact = _truncate_field(threat_impact)
    
    # Generate ID
    threat_id = next_id(threats, "T")
    
    # Create statement from components
    statement = f"A {threat_source} {prerequisites} can {threat_action}, which leads to {threat_impact}"
    statement = _truncate_field(statement, STATEMENT_MAX_LENGTH)
    
    # Create threat
    threat = Threat(
        id=threat_id,
        numericId=threat_counter,
        threatSource=threat_source,
        prerequisites=prerequisites,
        threatAction=threat_action,
        threatImpact=threat_impact,
        statement=statement,
        displayOrder=threat_counter,
        category=category,
        severity=severity,
        likelihood=likelihood,
        impactedAssets=affected_assets or [],
        affected_components=affected_components or [],
        tags=tags or []
    )
    
    # Add to dictionary
    threats[threat_id] = threat
    threat_counter += 1
    
    return f"Threat added with ID: {threat_id}"


async def update_threat_impl(
    ctx: Context,
    id: str,
    threat_source: Optional[str] = None,
    prerequisites: Optional[str] = None,
    threat_action: Optional[str] = None,
    threat_impact: Optional[str] = None,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    likelihood: Optional[str] = None,
    status: Optional[str] = None,
    affected_components: Optional[List[str]] = None,
    affected_assets: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
) -> str:
    """Update an existing threat."""
    logger.debug(f'Updating threat: {id}')
    
    # Check if the threat exists
    if id not in threats:
        return f"Threat with ID {id} not found"
    
    threat = threats[id]
    updates: Dict[str, Any] = {}

    if threat_source is not None:
        updates["threatSource"] = _truncate_field(threat_source)

    if prerequisites is not None:
        updates["prerequisites"] = _truncate_field(prerequisites)

    if threat_action is not None:
        updates["threatAction"] = _truncate_field(threat_action)

    if threat_impact is not None:
        updates["threatImpact"] = _truncate_field(threat_impact)

    if updates.keys() & {
        "threatSource", "prerequisites", "threatAction", "threatImpact",
    }:
        updates["statement"] = _truncate_field(
            f"A {updates.get('threatSource', threat.threatSource)} "
            f"{updates.get('prerequisites', threat.prerequisites)} can "
            f"{updates.get('threatAction', threat.threatAction)}, which leads "
            f"to {updates.get('threatImpact', threat.threatImpact)}",
            STATEMENT_MAX_LENGTH
        )
    
    if category is not None:
        updates["category"] = category
    
    if severity is not None:
        updates["severity"] = severity
    
    if likelihood is not None:
        updates["likelihood"] = likelihood
    
    if status is not None:
        updates["status"] = status
    
    if affected_components is not None:
        updates["affected_components"] = affected_components
    
    if affected_assets is not None:
        updates["impactedAssets"] = affected_assets
    
    if tags is not None:
        updates["tags"] = tags

    threats[id] = _validated_update(threat, updates)
    
    return f"Threat {id} updated successfully"


async def list_threats_impl(
    ctx: Context,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
) -> str:
    """List all threats in the model."""
    logger.debug('Listing threats')
    
    # Filter threats by category, severity, and status if provided
    filtered_threats = threats.values()
    
    if category:
        expected = validate_enum_with_enhanced_error(
            category, ThreatCategory, "category"
        )
        filtered_threats = [t for t in filtered_threats if t.category == expected]
    
    if severity:
        expected = validate_enum_with_enhanced_error(
            severity, ThreatSeverity, "severity"
        )
        filtered_threats = [t for t in filtered_threats if t.severity == expected]
    
    if status:
        expected = validate_enum_with_enhanced_error(status, ThreatStatus, "status")
        filtered_threats = [t for t in filtered_threats if t.status == expected]
    
    # Sort threats by numeric ID
    sorted_threats = sorted(filtered_threats, key=lambda t: t.numericId)
    
    # Generate the markdown output
    result = "# Threats\n\n"
    
    if not sorted_threats:
        result += "No threats found.\n"
        return result
    
    for threat in sorted_threats:
        result += f"## {threat.numericId}: {threat.statement}\n\n"
        result += f"**ID:** {threat.id}\n\n"
        
        if threat.category:
            result += f"**Category:** {threat.category.value}\n\n"
        
        if threat.severity:
            result += f"**Severity:** {threat.severity.value}\n\n"
        
        if threat.likelihood:
            result += f"**Likelihood:** {threat.likelihood.value}\n\n"
        
        result += f"**Status:** {threat.status.value}\n\n"
        result += _format_residual_assessment(threat.id)
        
        if threat.affected_components:
            result += "**Affected Components:**\n\n"
            for comp_id in threat.affected_components:
                result += f"- {comp_id}\n"
            result += "\n"
        
        if threat.impactedAssets:
            result += "**Impacted Assets:**\n\n"
            for asset_id in threat.impactedAssets:
                result += f"- {asset_id}\n"
            result += "\n"
        
        if threat.tags:
            result += "**Tags:**\n\n"
            for tag in threat.tags:
                result += f"- {tag}\n"
            result += "\n"
        
        # Get linked mitigations
        linked_mitigations = [link.mitigationId for link in mitigation_links if link.linkedId == threat.id]
        if linked_mitigations:
            result += "**Mitigations:**\n\n"
            for mitigation_id in linked_mitigations:
                if mitigation_id in mitigations:
                    mitigation = mitigations[mitigation_id]
                    result += f"- {mitigation.content} ({mitigation_id})\n"
            result += "\n"
        
        result += "---\n\n"
    
    return result


async def get_threat_impl(
    ctx: Context,
    id: str,
) -> str:
    """Get details about a specific threat."""
    logger.debug(f'Getting threat: {id}')
    
    # Check if the threat exists
    if id not in threats:
        return f"Threat with ID {id} not found"
    
    # Get the threat
    threat = threats[id]
    
    # Generate the markdown output
    result = f"# Threat {threat.numericId}: {threat.statement}\n\n"
    
    result += f"**ID:** {threat.id}\n\n"
    result += f"**Source:** {threat.threatSource}\n\n"
    result += f"**Prerequisites:** {threat.prerequisites}\n\n"
    result += f"**Action:** {threat.threatAction}\n\n"
    result += f"**Impact:** {threat.threatImpact}\n\n"
    
    if threat.category:
        result += f"**Category:** {threat.category.value}\n\n"
    
    if threat.severity:
        result += f"**Severity:** {threat.severity.value}\n\n"
    
    if threat.likelihood:
        result += f"**Likelihood:** {threat.likelihood.value}\n\n"
    
    result += f"**Status:** {threat.status.value}\n\n"
    result += _format_residual_assessment(threat.id)
    
    if threat.affected_components:
        result += "**Affected Components:**\n\n"
        for comp_id in threat.affected_components:
            result += f"- {comp_id}\n"
        result += "\n"
    
    if threat.impactedAssets:
        result += "**Impacted Assets:**\n\n"
        for asset_id in threat.impactedAssets:
            result += f"- {asset_id}\n"
        result += "\n"
    
    if threat.tags:
        result += "**Tags:**\n\n"
        for tag in threat.tags:
            result += f"- {tag}\n"
        result += "\n"
    
    # Get linked mitigations
    linked_mitigations = [link.mitigationId for link in mitigation_links if link.linkedId == threat.id]
    if linked_mitigations:
        result += "**Mitigations:**\n\n"
        for mitigation_id in linked_mitigations:
            if mitigation_id in mitigations:
                mitigation = mitigations[mitigation_id]
                result += f"- {mitigation.content} ({mitigation_id})\n"
        result += "\n"
    
    return result


async def delete_threat_impl(
    ctx: Context,
    id: str,
) -> str:
    """Delete a threat from the model."""
    logger.debug(f'Deleting threat: {id}')
    
    # Check if the threat exists
    if id not in threats:
        return f"Threat with ID {id} not found"
    
    # Delete the threat
    del threats[id]
    
    # Delete any links to this threat
    global mitigation_links
    mitigation_links = [link for link in mitigation_links if link.linkedId != id]
    residual_risk_assessments.pop(id, None)
    
    return f"Threat {id} deleted successfully"


async def assess_threat_impl(
    ctx: Context,
    threat_id: str,
    decision: str,
    rationale: str,
    residual_severity: Optional[str] = None,
    residual_likelihood: Optional[str] = None,
) -> str:
    """Record a residual-risk decision for one threat."""
    logger.debug(f'Assessing residual risk for threat: {threat_id}')
    candidate_threat, assessment = _prepare_residual_assessment(
        threat_id=threat_id,
        decision=decision,
        residual_severity=residual_severity,
        residual_likelihood=residual_likelihood,
        rationale=rationale,
    )
    threats[threat_id] = candidate_threat
    residual_risk_assessments[threat_id] = assessment
    return f"Residual risk assessed for threat {threat_id}: {assessment.decision.value}"


async def assess_threats_atomically_impl(
    ctx: Context,
    items: List[Dict[str, Any]],
) -> str:
    """Validate and save a batch of residual-risk decisions atomically."""
    if not items:
        return "No residual-risk assessments provided in batch."

    accepted = {
        "threat_id",
        "decision",
        "rationale",
        "residual_severity",
        "residual_likelihood",
    }
    required = {"threat_id", "decision", "rationale"}
    prepared: List[Tuple[str, Threat, ResidualRiskAssessment]] = []
    errors = []
    seen = set()

    for index, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            errors.append(f"Item {index}: assessment must be an object")
            continue
        missing = sorted(required - item.keys())
        unexpected = sorted(item.keys() - accepted)
        if missing or unexpected:
            problems = []
            if missing:
                problems.append(f"missing required field(s): {', '.join(missing)}")
            if unexpected:
                problems.append(
                    f"unexpected field(s): {', '.join(unexpected)}"
                )
            problems.append(f"accepted fields: {', '.join(sorted(accepted))}")
            errors.append(f"Item {index}: {'; '.join(problems)}")
            continue

        threat_id = item["threat_id"]
        if threat_id in seen:
            errors.append(
                f"Item {index}: duplicate threat_id '{threat_id}' in batch"
            )
            continue
        seen.add(threat_id)

        try:
            candidate_threat, assessment = _prepare_residual_assessment(
                threat_id=threat_id,
                decision=item["decision"],
                rationale=item["rationale"],
                residual_severity=item.get("residual_severity"),
                residual_likelihood=item.get("residual_likelihood"),
            )
        except Exception as exc:
            errors.append(f"Item {index}: {exc}")
        else:
            prepared.append((threat_id, candidate_threat, assessment))

    if errors:
        return (
            "❌ No residual-risk assessments were saved because batch validation "
            "failed:\n- "
            + "\n- ".join(errors)
        )

    for threat_id, candidate_threat, assessment in prepared:
        threats[threat_id] = candidate_threat
        residual_risk_assessments[threat_id] = assessment

    return (
        f"Successfully assessed residual risk for {len(prepared)} threat(s):\n"
        + "\n".join(
            f"  - {threat_id}: {assessment.decision.value}"
            for threat_id, _, assessment in prepared
        )
    )


async def clear_threat_model_impl(ctx: Context) -> str:
    """Clear all threats, mitigations, links, and residual assessments."""
    global threat_counter, mitigation_counter

    threats.clear()
    mitigations.clear()
    mitigation_links.clear()
    residual_risk_assessments.clear()
    threat_counter = 1
    mitigation_counter = 1
    reset_id_counters("T")
    reset_id_counters("M")
    return "All threats, mitigations, links, and residual assessments cleared."


async def add_mitigation_impl(
    ctx: Context,
    content: str,
    type: Optional[str] = None,
    status: str = "mitigationIdentified",
    implementation_details: Optional[str] = None,
    cost: Optional[str] = None,
    effectiveness: Optional[str] = None,
    metadata: Optional[List[Dict[str, str]]] = None,
) -> str:
    """Add a new mitigation to the model."""
    global mitigation_counter
    
    logger.debug(f'Adding mitigation: {content}')
    
    # Generate ID
    mitigation_id = next_id(mitigations, "M")
    
    # Create metadata items
    metadata_items = []
    if metadata:
        for item in metadata:
            metadata_items.append(MetadataItem(key=item["key"], value=item["value"]))
    
    # Create mitigation
    mitigation = Mitigation(
        id=mitigation_id,
        numericId=mitigation_counter,
        status=status,
        content=content,
        displayOrder=mitigation_counter,
        metadata=metadata_items,
        type=type,
        cost=cost,
        effectiveness=effectiveness,
        implementation_details=implementation_details
    )
    
    # Add to dictionary
    mitigations[mitigation_id] = mitigation
    mitigation_counter += 1
    
    return f"Mitigation added with ID: {mitigation_id}"


async def list_mitigations_impl(
    ctx: Context,
    type: Optional[str] = None,
    status: Optional[str] = None,
) -> str:
    """List all mitigations in the model."""
    logger.debug('Listing mitigations')
    
    # Filter mitigations by type and status if provided
    filtered_mitigations = mitigations.values()
    
    if type:
        expected = validate_enum_with_enhanced_error(type, MitigationType, "type")
        filtered_mitigations = [
            mitigation
            for mitigation in filtered_mitigations
            if mitigation.type == expected
        ]
    
    if status:
        expected = validate_enum_with_enhanced_error(
            status, MitigationStatus, "status"
        )
        filtered_mitigations = [
            mitigation
            for mitigation in filtered_mitigations
            if mitigation.status == expected
        ]
    
    # Sort mitigations by numeric ID
    sorted_mitigations = sorted(filtered_mitigations, key=lambda m: m.numericId)
    
    # Generate the markdown output
    result = "# Mitigations\n\n"
    
    if not sorted_mitigations:
        result += "No mitigations found.\n"
        return result
    
    for mitigation in sorted_mitigations:
        result += f"## {mitigation.numericId}: {mitigation.content}\n\n"
        
        result += f"**ID:** {mitigation.id}\n\n"
        result += f"**Status:** {mitigation.status.value}\n\n"
        
        if mitigation.type:
            result += f"**Type:** {mitigation.type.value}\n\n"
        
        if mitigation.implementation_details:
            result += f"**Implementation Details:** {mitigation.implementation_details}\n\n"
        
        if mitigation.cost:
            result += f"**Cost:** {mitigation.cost.value}\n\n"
        
        if mitigation.effectiveness:
            result += f"**Effectiveness:** {mitigation.effectiveness.value}\n\n"
        
        if mitigation.metadata:
            result += "**Metadata:**\n\n"
            for item in mitigation.metadata:
                result += f"- {item.key}: {item.value}\n"
            result += "\n"
        
        # Get linked threats
        linked_threats = [link.linkedId for link in mitigation_links if link.mitigationId == mitigation.id]
        if linked_threats:
            result += "**Linked Threats:**\n\n"
            for threat_id in linked_threats:
                if threat_id in threats:
                    threat = threats[threat_id]
                    result += f"- {threat.statement} ({threat_id})\n"
            result += "\n"
        
        result += "---\n\n"
    
    return result


async def get_mitigation_impl(
    ctx: Context,
    id: str,
) -> str:
    """Get details about a specific mitigation."""
    logger.debug(f'Getting mitigation: {id}')
    
    # Check if the mitigation exists
    if id not in mitigations:
        return f"Mitigation with ID {id} not found"
    
    # Get the mitigation
    mitigation = mitigations[id]
    
    # Generate the markdown output
    result = f"# Mitigation {mitigation.numericId}: {mitigation.content}\n\n"
    
    result += f"**ID:** {mitigation.id}\n\n"
    result += f"**Status:** {mitigation.status.value}\n\n"
    
    if mitigation.type:
        result += f"**Type:** {mitigation.type.value}\n\n"
    
    if mitigation.implementation_details:
        result += f"**Implementation Details:** {mitigation.implementation_details}\n\n"
    
    if mitigation.cost:
        result += f"**Cost:** {mitigation.cost.value}\n\n"
    
    if mitigation.effectiveness:
        result += f"**Effectiveness:** {mitigation.effectiveness.value}\n\n"
    
    if mitigation.metadata:
        result += "**Metadata:**\n\n"
        for item in mitigation.metadata:
            result += f"- {item.key}: {item.value}\n"
        result += "\n"
    
    # Get linked threats
    linked_threats = [link.linkedId for link in mitigation_links if link.mitigationId == mitigation.id]
    if linked_threats:
        result += "**Linked Threats:**\n\n"
        for threat_id in linked_threats:
            if threat_id in threats:
                threat = threats[threat_id]
                result += f"- {threat.statement} ({threat_id})\n"
        result += "\n"
    
    return result


async def update_mitigation_impl(
    ctx: Context,
    id: str,
    content: Optional[str] = None,
    type: Optional[str] = None,
    status: Optional[str] = None,
    implementation_details: Optional[str] = None,
    cost: Optional[str] = None,
    effectiveness: Optional[str] = None,
    metadata: Optional[List[Dict[str, str]]] = None,
) -> str:
    """Update an existing mitigation."""
    logger.debug(f'Updating mitigation: {id}')
    
    # Check if the mitigation exists
    if id not in mitigations:
        return f"Mitigation with ID {id} not found"
    
    mitigation = mitigations[id]
    updates: Dict[str, Any] = {}

    if content is not None:
        updates["content"] = content
    
    if type is not None:
        updates["type"] = type
    
    if status is not None:
        updates["status"] = status
    
    if implementation_details is not None:
        updates["implementation_details"] = implementation_details
    
    if cost is not None:
        updates["cost"] = cost
    
    if effectiveness is not None:
        updates["effectiveness"] = effectiveness
    
    if metadata is not None:
        updates["metadata"] = [
            MetadataItem(key=item["key"], value=item["value"])
            for item in metadata
        ]
    
    mitigations[id] = _validated_update(mitigation, updates)
    
    return f"Mitigation {id} updated successfully"


async def delete_mitigation_impl(
    ctx: Context,
    id: str,
) -> str:
    """Delete a mitigation from the model."""
    logger.debug(f'Deleting mitigation: {id}')
    
    # Check if the mitigation exists
    if id not in mitigations:
        return f"Mitigation with ID {id} not found"
    
    # Delete the mitigation
    del mitigations[id]
    
    # Delete any links to this mitigation
    global mitigation_links
    mitigation_links = [link for link in mitigation_links if link.mitigationId != id]
    
    return f"Mitigation {id} deleted successfully"




async def link_mitigation_to_threat_impl(
    ctx: Context,
    mitigation_id: str,
    threat_id: str,
) -> str:
    """Link a mitigation to a threat."""
    logger.debug(f'Linking mitigation {mitigation_id} to threat {threat_id}')
    
    # Check if the mitigation exists
    if mitigation_id not in mitigations:
        return f"Mitigation with ID {mitigation_id} not found"
    
    # Check if the threat exists
    if threat_id not in threats:
        return f"Threat with ID {threat_id} not found"
    
    # Check if the link already exists
    for link in mitigation_links:
        if link.mitigationId == mitigation_id and link.linkedId == threat_id:
            return f"Mitigation {mitigation_id} is already linked to threat {threat_id}"
    
    # Create the link
    link = MitigationLink(
        linkedId=threat_id,
        mitigationId=mitigation_id
    )
    
    # Add the link
    mitigation_links.append(link)
    
    return f"Mitigation {mitigation_id} linked to threat {threat_id}"


async def unlink_mitigation_from_threat_impl(
    ctx: Context,
    mitigation_id: str,
    threat_id: str,
) -> str:
    """Unlink a mitigation from a threat."""
    logger.debug(f'Unlinking mitigation {mitigation_id} from threat {threat_id}')
    
    global mitigation_links
    if not any(
        link.mitigationId == mitigation_id and link.linkedId == threat_id
        for link in mitigation_links
    ):
        return f"Mitigation {mitigation_id} is not linked to threat {threat_id}"
    
    # Remove the link
    mitigation_links = [link for link in mitigation_links if not (link.mitigationId == mitigation_id and link.linkedId == threat_id)]
    
    return f"Mitigation {mitigation_id} unlinked from threat {threat_id}"
