"""Business Context Analysis functionality for the Cline Threat Modeling MCP Server."""

from typing import Any, Dict, List, Optional, Union
from loguru import logger
from mcp.server.fastmcp import Context
from pydantic import ValidationError

from threat_modeling_mcp_server.validation.enum_validator import validate_enum_with_enhanced_error
from threat_modeling_mcp_server.models.models import (
    IndustrySector,
    SensitivityTier,
    UserBaseSize,
    UserBaseMetric,
    GeographicScope,
    RegulatoryRequirement,
    SystemCriticality,
    FinancialImpact,
    RevenueBand,
    AuthenticationRequirement,
    DeploymentModel,
    GeographicProfile,
    BusinessContext,
)
from threat_modeling_mcp_server.models.software_models import SoftwareProfile

# Feature descriptions
FEATURE_DESCRIPTIONS = {
    "industry_sector": "The industry sector in which the system operates, which helps identify industry-specific threats and compliance requirements.",
    "sensitivity_tier": "The sensitivity level of the data handled by the system, which affects security controls and privacy requirements.",
    "user_base_size": "The number of users that will be using the system, which impacts scalability and authentication requirements.",
    "geographic_scope": "The geographic reach of the system's operations, which affects compliance with regional regulations.",
    "regulatory_requirements": "The regulatory frameworks that apply to the system, which dictate specific security and privacy controls.",
    "system_criticality": "How critical the system is to business operations, which determines availability requirements and recovery time objectives.",
    "financial_impact": "The potential financial impact of a security breach, which helps prioritize security investments.",
    "authentication_requirement": "The type of authentication required by the system, which affects user access controls.",
    "deployment_model": "Where the software runs and who is responsible for securing each layer, which influences security architecture and controls.",
    "user_base_metric": "The unit the user base is measured in (monthly active users, seats, organizational customers, etc.), which qualifies what the size tier means.",
    "revenue_band": "The organization's annual revenue band, used to translate the revenue-percentage financial impact tier into absolute dollar ranges.",
    "geographic_profile": "The composite geographic profile: a scope level for each of the four facets (data_residency, compute_location, user_base_location, organizational_headquarters). All four are required for this feature to count as set."
}


# Global state
business_context = BusinessContext()


def build_business_context_analysis_plan() -> str:
    """Get a comprehensive business context analysis plan.

    Returns:
        A markdown-formatted business context analysis plan with prompts for LLM analysis
    """
    result = "# Business Context Analysis Plan\n\n"

    result += """## Overview
This plan provides a structured approach for analyzing business context descriptions using AI-powered analysis to categorize business features.

## Analysis Process

### Step 1: Gather Business Context Description
First, collect the business context description using:
- `manage_system_context(action="set", section="business", values={"description": "..."})` to provide the business context description

### Step 2: LLM Analysis Prompt
Use the following prompt structure with an LLM to analyze the business context:

```
You are a business analyst expert analyzing a business context description to categorize various business features.

BUSINESS CONTEXT DESCRIPTION:
[Insert the business context description here]

ANALYSIS INSTRUCTIONS:
Analyze the description and determine the most appropriate category for each of the following business features. If a feature cannot be determined from the description, indicate "Cannot be determined".

1. **Industry Sector Analysis**:
   Determine which industry sector best matches the description:
   - Finance: Banking, investments, payments, financial services
   - Healthcare: Medical services, patient care, health records
   - Retail: E-commerce, stores, shopping, consumer goods
   - Technology: Software, IT services, tech platforms
   - Manufacturing: Production, factories, industrial processes
   - Government: Public sector, agencies, civic services
   - Education: Schools, universities, learning platforms
   - Energy: Power, utilities, oil and gas
   - Transportation: Logistics, shipping, travel
   - Other: None of the above categories

2. **Data Sensitivity Analysis**:
   Determine the sensitivity level of data handled:
   - Public: Information that can be freely shared with the public
   - Internal: Information for internal use only, not particularly sensitive
   - Confidential: Sensitive information that requires protection
   - Restricted: Highly sensitive information with strict access controls

3. **User Base Size Analysis**:
   Estimate the number of users (logarithmic tiers):
   - Nano: Fewer than 100 users
   - Micro: 100 - 1,000 users
   - Small: 1,000 - 100,000 users
   - Medium: 100,000 - 10 million users
   - Large: 10 million - 100 million users
   - Very Large: 100 million - 1 billion users
   - Hyper-Scale: More than 1 billion users

   Also identify the measurement metric: Monthly Active Users, Daily Active Users,
   Concurrent Users, Seats / licenses, Organizational customers,
   Installs / downloads, or Registered users.

4. **Geographic Scope Analysis**:
   Determine the geographic reach (ordered by increasing reach):
   - Sub-National / Local: Confined to a single city, state, or locality
   - National / Single-Country: Within one sovereign nation
   - Regional / Multi-Country Bloc: Spanning a bloc such as the EU or ASEAN
   - Continental / Macro-Regional: Spanning a continent without unified regulation
   - Multi-Continental / International: Spanning two or more continents
   - Global / Transboundary: No fixed boundary, crossing all jurisdictions

   Then assign a level to each of the four geographic facets, which together form
   the composite geographic profile (all four are required):
   - data_residency: where data is stored, including backups
   - compute_location: where processing happens
   - user_base_location: where the end users are
   - organizational_headquarters: legal domicile of the controlling entity

5. **Regulatory Requirements Analysis**:
   Identify applicable regulatory frameworks:
   - GDPR: General Data Protection Regulation (EU)
   - CCPA / CPRA: California consumer privacy legislation
   - HIPAA: Health Insurance Portability and Accountability Act (US healthcare)
   - PCI-DSS: Payment Card Industry Data Security Standard
   - SOX: Sarbanes-Oxley Act (US financial)
   - FISMA / FedRAMP: US federal information security and cloud authorization
   - None: No specific regulatory requirements
   - Multiple / other: Several regimes apply, or one not listed above

6. **System Criticality Analysis**:
   Assess business criticality:
   - Low: Non-critical, can be down for days
   - Medium: Important, should be up within hours
   - High: Critical, must be up within minutes
   - Mission-Critical: Cannot be down, requires high availability

7. **Financial Impact Analysis**:
   Estimate potential financial impact of a breach as a percentage of annual
   revenue. 0.01% of revenue is the cyber materiality benchmark:
   - Negligible: Less than 0.001% of revenue
   - Low: 0.001% - 0.01% of revenue
   - Moderate: 0.01% - 0.1% of revenue (materiality benchmark)
   - High: 0.1% - 1% of revenue
   - Critical: More than 1% of revenue

   Also identify the revenue band used to convert this to dollars:
   Small business (under $50M), Mid-market ($50M - $1B), or Enterprise (over $1B).

8. **Authentication Requirement Analysis**:
   Determine authentication needs:
   - None: No authentication required
   - Basic: Username/password authentication
   - MFA: Multi-factor authentication
   - Federated: Single sign-on, OAuth, or other federated authentication
   - Biometric: Fingerprint, face recognition, or other biometric authentication

9. **Deployment Model Analysis**:
   Identify where the software runs and who secures each layer:
   - On-premises: Deployed on company-owned infrastructure
   - IaaS: Deployed on rented cloud infrastructure
   - PaaS: Deployed on a managed application platform
   - SaaS: Consumed as a fully managed service
   - Serverless / FaaS: Event-driven managed compute
   - Hybrid cloud: Split across on-premises and cloud
   - Multi-cloud: Spread across multiple cloud providers
   - Edge: Running close to users or devices

   Capture interoperability needs with the `Interoperability` non-functional
   requirement.

OUTPUT FORMAT:
Provide your analysis in the following structured format:

# Business Context Analysis Results

## Industry Sector
**Selected**: [Industry Sector]
**Reasoning**: [Brief explanation of why this sector was selected]

## Data Sensitivity
**Selected**: [Data Sensitivity Level]
**Reasoning**: [Brief explanation of the sensitivity assessment]

## User Base Size
**Selected**: [User Base Size]
**Reasoning**: [Brief explanation of the size estimation]

## Geographic Scope
**Selected**: [Geographic Scope]
**Facets**: data_residency=[level], compute_location=[level], user_base_location=[level], organizational_headquarters=[level]
**Reasoning**: [Brief explanation of the geographic assessment]

## Regulatory Requirements
**Selected**: [Regulatory Requirements]
**Reasoning**: [Brief explanation of regulatory applicability]

## System Criticality
**Selected**: [System Criticality]
**Reasoning**: [Brief explanation of criticality assessment]

## Financial Impact
**Selected**: [Financial Impact Level]
**Reasoning**: [Brief explanation of impact estimation]

## Authentication Requirement
**Selected**: [Authentication Type]
**Reasoning**: [Brief explanation of authentication needs]

## Deployment Model
**Selected**: [Deployment Model]
**Reasoning**: [Brief explanation of deployment model]

## User Base Metric
**Selected**: [User Base Metric]
**Reasoning**: [Brief explanation of which metric fits this software category]

## Revenue Band
**Selected**: [Revenue Band]
**Reasoning**: [Brief explanation of the revenue band assessment]

## Summary
[Brief summary of the overall business context analysis and key findings]
```

### Step 3: Generate Clarification Questions
Based on the LLM analysis results, generate clarification questions for any features that could not be determined or need additional clarification.

### Step 4: Answer Clarification Questions
Use the clarification questions to gather additional information and refine the business context categorization.

## Key Analysis Areas

### 1. Industry Context
- Business domain and sector
- Industry-specific regulations
- Common threat patterns
- Compliance requirements

### 2. Data Characteristics
- Data types and sensitivity
- Privacy requirements
- Retention policies
- Cross-border considerations

### 3. Operational Context
- User base and scale
- Geographic distribution
- System availability needs
- Business impact tolerance

### 4. Technical Context
- Deployment models
- Integration requirements
- Authentication needs
- Infrastructure considerations

## Expected Deliverables

1. **Business Context Categorization**: Structured categorization of all business features
2. **Clarification Questions**: Targeted questions for missing information
3. **Risk Context**: Understanding of business risk tolerance and impact
4. **Compliance Context**: Identification of applicable regulatory requirements

## Tools and Resources

- **System Context Tool**: manage_system_context
- **Analysis Framework**: Industry analysis, risk assessment, compliance mapping
- **Validation**: Cross-reference with industry standards and regulatory requirements

This plan ensures a thorough, AI-powered analysis of business context with structured categorization and validation.
"""

    return result


# The authoritative list of business context features. Everything that reports
# on phase-1 progress (completeness validation, state summary, orchestrator
# progression, guidance text) derives from this one list so the counts cannot
# drift apart.
REQUIRED_BUSINESS_CONTEXT_FEATURES = [
    "industry_sector",
    "sensitivity_tier",
    "user_base_size",
    "user_base_metric",
    "geographic_scope",
    "regulatory_requirements",
    "system_criticality",
    "financial_impact",
    "revenue_band",
    "authentication_requirement",
    "deployment_model",
    # A complete geographic profile assigns a level to every facet.
    "geographic_profile",
]

# Facets that must all be present for "geographic_profile" to count as set.
GEOGRAPHIC_FACETS = [
    "data_residency",
    "compute_location",
    "user_base_location",
    "organizational_headquarters",
]


_BUSINESS_ENUM_FIELDS = {
    "industry_sector": IndustrySector,
    "sensitivity_tier": SensitivityTier,
    "user_base_size": UserBaseSize,
    "geographic_scope": GeographicScope,
    "regulatory_requirements": RegulatoryRequirement,
    "system_criticality": SystemCriticality,
    "financial_impact": FinancialImpact,
    "authentication_requirement": AuthenticationRequirement,
    "deployment_model": DeploymentModel,
    "user_base_metric": UserBaseMetric,
    "revenue_band": RevenueBand,
}


def has_business_context_description(context: Optional[BusinessContext] = None) -> bool:
    """Return whether the context has a non-empty text description."""
    context = context if context is not None else business_context
    return isinstance(context.description, str) and bool(context.description.strip())


def missing_business_context_features(
    context: Optional[BusinessContext] = None,
) -> List[str]:
    """Return the required business context features that are not yet set."""
    context = context if context is not None else business_context

    missing = []
    for feature in REQUIRED_BUSINESS_CONTEXT_FEATURES:
        value = getattr(context, feature, None)

        if feature == "geographic_profile":
            if value is None or any(
                getattr(value, facet, None) is None for facet in GEOGRAPHIC_FACETS
            ):
                missing.append(feature)
            continue

        if value is None or (hasattr(value, "__len__") and len(value) == 0):
            missing.append(feature)
    return missing


def check_business_context_completeness(
    context: Optional[BusinessContext] = None,
) -> tuple[bool, List[str]]:
    """Check if the description and all required features are set."""
    context = context if context is not None else business_context
    missing_features = missing_business_context_features(context)
    if not has_business_context_description(context):
        missing_features = ["description"] + missing_features
    return len(missing_features) == 0, missing_features


def _validation_error_items(exc: ValidationError) -> List[str]:
    """Render Pydantic errors as concise field-specific messages."""
    items = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"]) or "business_context"
        items.append(f"{location}: {error['msg']}")
    return items


def _build_business_context_candidate(
    payload: Dict[str, Any],
    base_context: BusinessContext,
) -> tuple[Optional[BusinessContext], List[str]]:
    """Validate an update against a caller-selected base without mutating state."""
    candidate_values = base_context.model_dump()
    invalid_values: List[str] = []

    description = payload.get("description")
    candidate_values["description"] = description
    if not isinstance(description, str):
        invalid_values.append("description: value must be text")
    elif not description.strip():
        invalid_values.append("description: value must not be empty")

    for field_name, enum_class in _BUSINESS_ENUM_FIELDS.items():
        if field_name == "regulatory_requirements":
            continue
        value = payload.get(field_name)
        if value is None:
            continue
        try:
            candidate_values[field_name] = validate_enum_with_enhanced_error(
                value, enum_class, field_name,
            )
        except (TypeError, ValueError) as exc:
            invalid_values.append(f"{field_name}: {exc}")

    requirements = payload.get("regulatory_requirements")
    if requirements is not None:
        if isinstance(requirements, str):
            tokens = [token.strip() for token in requirements.split(",") if token.strip()]
        elif isinstance(requirements, list):
            tokens = requirements
        else:
            tokens = []
            invalid_values.append(
                "regulatory_requirements: value must be text or a list of text values"
            )

        if not tokens and isinstance(requirements, (str, list)):
            invalid_values.append(
                "regulatory_requirements: at least one requirement is required"
            )

        validated_requirements = set()
        for requirement in tokens:
            try:
                validated_requirements.add(validate_enum_with_enhanced_error(
                    requirement, RegulatoryRequirement, "regulatory_requirements",
                ))
            except (TypeError, ValueError) as exc:
                invalid_values.append(
                    f"regulatory_requirements[{requirement}]: {exc}"
                )

        exclusive = {
            RegulatoryRequirement.NONE,
            RegulatoryRequirement.MULTIPLE,
        }
        selected_exclusive = validated_requirements & exclusive
        if selected_exclusive and len(validated_requirements) > 1:
            labels = ", ".join(sorted(item.value for item in selected_exclusive))
            invalid_values.append(
                "regulatory_requirements: "
                f"{labels} cannot be combined with another requirement"
            )
        candidate_values["regulatory_requirements"] = validated_requirements

    facet_values = {facet: payload.get(facet) for facet in GEOGRAPHIC_FACETS}
    if any(value is not None for value in facet_values.values()):
        current_profile = base_context.geographic_profile
        profile_values = current_profile.model_dump() if current_profile else {}
        for facet, value in facet_values.items():
            if value is None:
                continue
            try:
                profile_values[facet] = validate_enum_with_enhanced_error(
                    value, GeographicScope, facet,
                )
            except (TypeError, ValueError) as exc:
                invalid_values.append(f"{facet}: {exc}")
        try:
            candidate_values["geographic_profile"] = GeographicProfile(**profile_values)
        except ValidationError as exc:
            invalid_values.extend(_validation_error_items(exc))

    if invalid_values:
        return None, invalid_values

    try:
        return BusinessContext.model_validate(candidate_values), []
    except ValidationError as exc:
        return None, _validation_error_items(exc)


def _commit_business_context(candidate: BusinessContext) -> None:
    """Replace fields in place so imported references stay live."""
    for field in BusinessContext.model_fields:
        setattr(business_context, field, getattr(candidate, field))


def _rejected_business_context_result(invalid_values: List[str]) -> str:
    return (
        "❌ BUSINESS CONTEXT REJECTED: no changes were applied:\n"
        + "\n".join(f"- {item}" for item in invalid_values)
    )


def deployment_model_conflict_message(
    context: BusinessContext,
    software_profile: Optional[SoftwareProfile],
) -> str:
    """Return a warning when the two deployment classifications disagree."""
    if (
        context.deployment_model
        and software_profile
        and software_profile.deployment_model
        and context.deployment_model != software_profile.deployment_model
    ):
        return (
            "\n\n⚠️ Deployment model conflict: business context says "
            f"'{context.deployment_model.value}' but the software profile says "
            f"'{software_profile.deployment_model.value}'. Update one so reports "
            "do not disagree."
        )
    return ""


async def set_business_context_with_features_impl(
    ctx: Context,
    description: str,
    industry_sector: Optional[str] = None,
    sensitivity_tier: Optional[str] = None,
    user_base_size: Optional[str] = None,
    geographic_scope: Optional[str] = None,
    regulatory_requirements: Optional[Union[str, List[str]]] = None,
    system_criticality: Optional[str] = None,
    financial_impact: Optional[str] = None,
    authentication_requirement: Optional[str] = None,
    deployment_model: Optional[str] = None,
    user_base_metric: Optional[str] = None,
    revenue_band: Optional[str] = None,
    data_residency: Optional[str] = None,
    compute_location: Optional[str] = None,
    user_base_location: Optional[str] = None,
    organizational_headquarters: Optional[str] = None,
) -> str:
    """Validate and atomically update the business context."""
    logger.debug(f"Setting business context with features: {description}")

    payload = {
        "description": description,
        "industry_sector": industry_sector,
        "sensitivity_tier": sensitivity_tier,
        "user_base_size": user_base_size,
        "geographic_scope": geographic_scope,
        "regulatory_requirements": regulatory_requirements,
        "system_criticality": system_criticality,
        "financial_impact": financial_impact,
        "authentication_requirement": authentication_requirement,
        "deployment_model": deployment_model,
        "user_base_metric": user_base_metric,
        "revenue_band": revenue_band,
        "data_residency": data_residency,
        "compute_location": compute_location,
        "user_base_location": user_base_location,
        "organizational_headquarters": organizational_headquarters,
    }
    candidate, invalid_values = _build_business_context_candidate(
        payload, business_context,
    )
    if invalid_values:
        return _rejected_business_context_result(invalid_values)

    _commit_business_context(candidate)

    from threat_modeling_mcp_server.tools import classification_profiles as profiles
    conflict = deployment_model_conflict_message(candidate, profiles.software_profile)
    is_complete, missing_features = check_business_context_completeness(candidate)

    if is_complete:
        return (
            "✅ BUSINESS CONTEXT COMPLETE: All required business context features "
            "have been set. You may now proceed to the next phase of threat modeling."
            + conflict
        )

    missing_count = len(missing_features)
    missing_list = ", ".join(missing_features)
    return (
        f"⚠️ BUSINESS CONTEXT INCOMPLETE: {missing_count} features still need to be "
        f"set: {missing_list}. Please provide all required features before "
        f"proceeding to the next phase."
        + conflict
    )


async def get_business_context_impl(
    ctx: Context,
) -> str:
    """Get the business context.

    Args:
        ctx: MCP context for logging and error handling

    Returns:
        A markdown-formatted business context
    """
    logger.debug('Getting business context')

    if not has_business_context_description():
        return "No business context available. Please set a business context description first."

    result = "# Business Context\n\n"

    result += f"## Description\n\n{business_context.description}\n\n"

    result += "## Features\n\n"

    if business_context.industry_sector:
        result += f"**Industry Sector**: {business_context.industry_sector.value}\n\n"

    if business_context.sensitivity_tier:
        result += f"**Data Sensitivity**: {business_context.sensitivity_tier.value}\n\n"

    if business_context.user_base_size:
        result += f"**User Base Size**: {business_context.user_base_size.value}\n\n"

    if business_context.geographic_scope:
        result += f"**Geographic Scope**: {business_context.geographic_scope.value}\n\n"

    if business_context.regulatory_requirements:
        reqs = sorted(req.value for req in business_context.regulatory_requirements)
        result += f"**Regulatory Requirements**: {', '.join(reqs)}\n\n"

    if business_context.system_criticality:
        result += f"**System Criticality**: {business_context.system_criticality.value}\n\n"

    if business_context.financial_impact:
        result += f"**Financial Impact of Breach**: {business_context.financial_impact.value}\n\n"

    if business_context.authentication_requirement:
        result += f"**Authentication Requirement**: {business_context.authentication_requirement.value}\n\n"

    if business_context.deployment_model:
        result += f"**Deployment Model**: {business_context.deployment_model.value}\n\n"

    if business_context.user_base_metric:
        result += f"**User Base Metric**: {business_context.user_base_metric.value}\n\n"

    if business_context.revenue_band:
        result += f"**Revenue Band**: {business_context.revenue_band.value}\n\n"

    if business_context.geographic_profile:
        facets = {
            label: getattr(business_context.geographic_profile, field)
            for label, field in [
                ("Data Residency", "data_residency"),
                ("Compute Location", "compute_location"),
                ("User Base Location", "user_base_location"),
                ("Organizational HQ", "organizational_headquarters"),
            ]
        }
        set_facets = {k: v for k, v in facets.items() if v}
        if set_facets:
            result += "**Geographic Facets**:\n"
            for label, level in set_facets.items():
                result += f"- {label}: {level.value}\n"
            result += "\n"


    return result


async def clear_business_context_impl(
    ctx: Context,
) -> str:
    """Clear the business context.

    Args:
        ctx: MCP context for logging and error handling

    Returns:
        A confirmation message
    """
    logger.debug('Clearing business context')

    # Reset in place. Other modules (state_collector) imported this object by
    # reference, so rebinding the module global would leave them looking at the
    # old instance.
    fresh = BusinessContext()
    for field in BusinessContext.model_fields:
        setattr(business_context, field, getattr(fresh, field))

    return "Business context cleared."


async def validate_business_context_completeness_impl(
    ctx: Context,
) -> str:
    """Validate that all business context features are set before proceeding to next phase.

    Args:
        ctx: MCP context for logging and error handling

    Returns:
        A validation message indicating if business context is complete
    """
    logger.debug('Validating business context completeness')

    if not has_business_context_description():
        return "❌ VALIDATION FAILED: No business context description set. Use manage_system_context with action='set' and section='business' to provide a description and all required features."

    is_complete, missing_features = check_business_context_completeness()

    if is_complete:
        return "✅ VALIDATION PASSED: Business context is complete with all required features set. Ready to proceed to next phase."
    else:
        missing_count = len(missing_features)
        missing_list = ", ".join(missing_features)
        return f"❌ VALIDATION FAILED: Business context is incomplete. Missing {missing_count} required features: {missing_list}. Use manage_system_context with action='set' and section='business' to provide all required features before proceeding."
