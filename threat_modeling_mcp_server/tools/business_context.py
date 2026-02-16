"""Business Context Analysis functionality for the Cline Threat Modeling MCP Server."""

from typing import Dict, List, Optional, Set
from loguru import logger
from mcp.server.fastmcp import Context
from pydantic import Field

from threat_modeling_mcp_server.models.models import (
    IndustrySector,
    DataSensitivity,
    UserBaseSize,
    GeographicScope,
    RegulatoryRequirement,
    SystemCriticality,
    FinancialImpact,
    AuthenticationRequirement,
    DeploymentEnvironment,
    IntegrationComplexity,
    ClarificationQuestion,
    BusinessContext,
)

# Feature descriptions
FEATURE_DESCRIPTIONS = {
    "industry_sector": "The industry sector in which the system operates, which helps identify industry-specific threats and compliance requirements.",
    "data_sensitivity": "The sensitivity level of the data handled by the system, which affects security controls and privacy requirements.",
    "user_base_size": "The number of users that will be using the system, which impacts scalability and authentication requirements.",
    "geographic_scope": "The geographic reach of the system's operations, which affects compliance with regional regulations.",
    "regulatory_requirements": "The regulatory frameworks that apply to the system, which dictate specific security and privacy controls.",
    "system_criticality": "How critical the system is to business operations, which determines availability requirements and recovery time objectives.",
    "financial_impact": "The potential financial impact of a security breach, which helps prioritize security investments.",
    "authentication_requirement": "The type of authentication required by the system, which affects user access controls.",
    "deployment_environment": "Where the system will be deployed, which influences security architecture and controls.",
    "integration_complexity": "The complexity of integrations with other systems, which affects security boundaries and trust relationships."
}


# Global state
business_context = BusinessContext()



def get_business_context_analysis_plan() -> str:
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
- `set_business_context(description="...")` to provide the business context description

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
   - Regulated: Information subject to regulatory compliance requirements

3. **User Base Size Analysis**:
   Estimate the number of users:
   - Small: Less than 1,000 users
   - Medium: 1,000 - 100,000 users
   - Large: 100,000 - 1 million users
   - Enterprise: More than 1 million users

4. **Geographic Scope Analysis**:
   Determine the geographic reach:
   - Local: Limited to a specific city or area
   - Regional: Covering multiple cities or a specific region
   - National: Operating within a single country
   - Multinational: Operating in multiple countries
   - Global: Operating worldwide

5. **Regulatory Requirements Analysis**:
   Identify applicable regulatory frameworks:
   - GDPR: General Data Protection Regulation (EU)
   - HIPAA: Health Insurance Portability and Accountability Act (US healthcare)
   - PCI-DSS: Payment Card Industry Data Security Standard
   - SOX: Sarbanes-Oxley Act (US financial)
   - FISMA: Federal Information Security Management Act (US government)
   - CCPA: California Consumer Privacy Act
   - None: No specific regulatory requirements
   - Multiple: Multiple regulatory requirements apply

6. **System Criticality Analysis**:
   Assess business criticality:
   - Low: Non-critical, can be down for days
   - Medium: Important, should be up within hours
   - High: Critical, must be up within minutes
   - Mission-Critical: Cannot be down, requires high availability

7. **Financial Impact Analysis**:
   Estimate potential financial impact of a breach:
   - Minimal: Less than $10,000
   - Low: $10,000 - $100,000
   - Medium: $100,000 - $1 million
   - High: $1 million - $10 million
   - Severe: More than $10 million

8. **Authentication Requirement Analysis**:
   Determine authentication needs:
   - None: No authentication required
   - Basic: Username/password authentication
   - MFA: Multi-factor authentication
   - Federated: Single sign-on, OAuth, or other federated authentication
   - Biometric: Fingerprint, face recognition, or other biometric authentication

9. **Deployment Environment Analysis**:
   Identify deployment model:
   - On-Premises: Deployed on company-owned infrastructure
   - Cloud-Public: Deployed on public cloud (AWS, Azure, GCP, etc.)
   - Cloud-Private: Deployed on private cloud infrastructure
   - Hybrid: Deployed across both on-premises and cloud environments
   - Multi-Cloud: Deployed across multiple cloud providers

10. **Integration Complexity Analysis**:
    Assess integration requirements:
    - Standalone: No integrations with other systems
    - Limited: Few external integrations
    - Moderate: Several integrations with other systems
    - Complex: Many integrations with diverse systems
    - Highly Complex: Extensive ecosystem with numerous integrations

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

## Deployment Environment
**Selected**: [Deployment Environment]
**Reasoning**: [Brief explanation of deployment model]

## Integration Complexity
**Selected**: [Integration Complexity]
**Reasoning**: [Brief explanation of integration assessment]

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

- **Business Context Tools**: set_business_context
- **Analysis Framework**: Industry analysis, risk assessment, compliance mapping
- **Validation**: Cross-reference with industry standards and regulatory requirements

This plan ensures a thorough, AI-powered analysis of business context with structured categorization and validation.
"""
    
    return result


def check_business_context_completeness() -> tuple[bool, List[str]]:
    """Check if all business context features are set.
    
    Returns:
        A tuple of (is_complete, missing_features)
    """
    global business_context
    
    missing_features = []
    
    if not business_context.industry_sector:
        missing_features.append("industry_sector")
    if not business_context.data_sensitivity:
        missing_features.append("data_sensitivity")
    if not business_context.user_base_size:
        missing_features.append("user_base_size")
    if not business_context.geographic_scope:
        missing_features.append("geographic_scope")
    if not business_context.regulatory_requirements:
        missing_features.append("regulatory_requirements")
    if not business_context.system_criticality:
        missing_features.append("system_criticality")
    if not business_context.financial_impact:
        missing_features.append("financial_impact")
    if not business_context.authentication_requirement:
        missing_features.append("authentication_requirement")
    if not business_context.deployment_environment:
        missing_features.append("deployment_environment")
    if not business_context.integration_complexity:
        missing_features.append("integration_complexity")
    
    return len(missing_features) == 0, missing_features


async def set_business_context_with_features_impl(
    ctx: Context,
    description: str,
    industry_sector: Optional[str] = None,
    data_sensitivity: Optional[str] = None,
    user_base_size: Optional[str] = None,
    geographic_scope: Optional[str] = None,
    regulatory_requirements: Optional[str] = None,
    system_criticality: Optional[str] = None,
    financial_impact: Optional[str] = None,
    authentication_requirement: Optional[str] = None,
    deployment_environment: Optional[str] = None,
    integration_complexity: Optional[str] = None,
) -> str:
    """Set the business context description and all features in one call.
    
    Args:
        ctx: MCP context for logging and error handling
        description: Business context description
        industry_sector: Industry sector (Finance, Healthcare, Retail, Technology, Manufacturing, Government, Education, Energy, Transportation, Other)
        data_sensitivity: Data sensitivity level (Public, Internal, Confidential, Restricted, Regulated)
        user_base_size: User base size (Small, Medium, Large, Enterprise)
        geographic_scope: Geographic scope (Local, Regional, National, Multinational, Global)
        regulatory_requirements: Regulatory requirements (GDPR, HIPAA, PCI-DSS, SOX, FISMA, CCPA, None, Multiple)
        system_criticality: System criticality (Low, Medium, High, Mission-Critical)
        financial_impact: Financial impact of breach (Minimal, Low, Medium, High, Severe)
        authentication_requirement: Authentication requirement (None, Basic, MFA, Federated, Biometric)
        deployment_environment: Deployment environment (On-Premises, Cloud-Public, Cloud-Private, Hybrid, Multi-Cloud)
        integration_complexity: Integration complexity (Standalone, Limited, Moderate, Complex, Highly Complex)
        
    Returns:
        A confirmation message indicating completeness status
    """
    global business_context
    
    logger.debug(f'Setting business context with features: {description}')
    
    # Set the description
    business_context.description = description
    
    # Set all the features directly
    if industry_sector:
        try:
            business_context.industry_sector = IndustrySector(industry_sector)
        except ValueError:
            logger.warning(f"Invalid industry sector: {industry_sector}")
    
    if data_sensitivity:
        try:
            business_context.data_sensitivity = DataSensitivity(data_sensitivity)
        except ValueError:
            logger.warning(f"Invalid data sensitivity: {data_sensitivity}")
    
    if user_base_size:
        try:
            business_context.user_base_size = UserBaseSize(user_base_size)
        except ValueError:
            logger.warning(f"Invalid user base size: {user_base_size}")
    
    if geographic_scope:
        try:
            business_context.geographic_scope = GeographicScope(geographic_scope)
        except ValueError:
            logger.warning(f"Invalid geographic scope: {geographic_scope}")
    
    if regulatory_requirements:
        try:
            # Handle multiple requirements separated by commas
            req_list = [req.strip() for req in regulatory_requirements.split(',')]
            reqs = set()
            for req in req_list:
                reqs.add(RegulatoryRequirement(req))
            business_context.regulatory_requirements = reqs
        except ValueError:
            logger.warning(f"Invalid regulatory requirements: {regulatory_requirements}")
    
    if system_criticality:
        try:
            business_context.system_criticality = SystemCriticality(system_criticality)
        except ValueError:
            logger.warning(f"Invalid system criticality: {system_criticality}")
    
    if financial_impact:
        try:
            business_context.financial_impact = FinancialImpact(financial_impact)
        except ValueError:
            logger.warning(f"Invalid financial impact: {financial_impact}")
    
    if authentication_requirement:
        try:
            business_context.authentication_requirement = AuthenticationRequirement(authentication_requirement)
        except ValueError:
            logger.warning(f"Invalid authentication requirement: {authentication_requirement}")
    
    if deployment_environment:
        try:
            business_context.deployment_environment = DeploymentEnvironment(deployment_environment)
        except ValueError:
            logger.warning(f"Invalid deployment environment: {deployment_environment}")
    
    if integration_complexity:
        try:
            business_context.integration_complexity = IntegrationComplexity(integration_complexity)
        except ValueError:
            logger.warning(f"Invalid integration complexity: {integration_complexity}")
    
    # Check completeness and return appropriate message
    is_complete, missing_features = check_business_context_completeness()
    
    if is_complete:
        return "✅ BUSINESS CONTEXT COMPLETE: All required business context features have been set. You may now proceed to the next phase of threat modeling."
    else:
        missing_count = len(missing_features)
        missing_list = ", ".join(missing_features)
        return f"⚠️ BUSINESS CONTEXT INCOMPLETE: {missing_count} features still need to be set: {missing_list}. Please provide all required features before proceeding to the next phase."


async def set_business_context_description_impl(
    ctx: Context,
    description: str,
) -> str:
    """Set the business context description only (legacy method for backward compatibility).
    
    Args:
        ctx: MCP context for logging and error handling
        description: Business context description
        
    Returns:
        A confirmation message
    """
    global business_context
    
    logger.debug(f'Setting business context description: {description}')
    
    # Set the description only
    business_context.description = description
    
    return f"Business context description set. Use set_business_context_with_features for complete setup."




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
    
    if not business_context.description:
        return "No business context available. Please set a business context description first."
    
    result = "# Business Context\n\n"
    
    result += f"## Description\n\n{business_context.description}\n\n"
    
    result += "## Features\n\n"
    
    if business_context.industry_sector:
        result += f"**Industry Sector**: {business_context.industry_sector.value}\n\n"
    
    if business_context.data_sensitivity:
        result += f"**Data Sensitivity**: {business_context.data_sensitivity.value}\n\n"
    
    if business_context.user_base_size:
        result += f"**User Base Size**: {business_context.user_base_size.value}\n\n"
    
    if business_context.geographic_scope:
        result += f"**Geographic Scope**: {business_context.geographic_scope.value}\n\n"
    
    if business_context.regulatory_requirements:
        reqs = [req.value for req in business_context.regulatory_requirements if req != RegulatoryRequirement.MULTIPLE]
        result += f"**Regulatory Requirements**: {', '.join(reqs)}\n\n"
    
    if business_context.system_criticality:
        result += f"**System Criticality**: {business_context.system_criticality.value}\n\n"
    
    if business_context.financial_impact:
        result += f"**Financial Impact of Breach**: {business_context.financial_impact.value}\n\n"
    
    if business_context.authentication_requirement:
        result += f"**Authentication Requirement**: {business_context.authentication_requirement.value}\n\n"
    
    if business_context.deployment_environment:
        result += f"**Deployment Environment**: {business_context.deployment_environment.value}\n\n"
    
    if business_context.integration_complexity:
        result += f"**Integration Complexity**: {business_context.integration_complexity.value}\n\n"
    
    
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
    global business_context
    
    logger.debug('Clearing business context')
    
    business_context = BusinessContext()
    
    return "Business context cleared."


async def get_business_context_features_impl(
    ctx: Context,
) -> str:
    """Get all business context features with descriptions.
    
    Args:
        ctx: MCP context for logging and error handling
        
    Returns:
        A markdown-formatted list of business context features with descriptions
    """
    logger.debug('Getting business context features')
    
    result = "# Business Context Features\n\n"
    
    for feature, description in FEATURE_DESCRIPTIONS.items():
        # Convert snake_case to Title Case for display
        display_name = " ".join(word.capitalize() for word in feature.split("_"))
        result += f"## {display_name}\n\n{description}\n\n"
    
    return result




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
    
    if not business_context.description:
        return "❌ VALIDATION FAILED: No business context description set. Please use set_business_context to provide a description and all required features."
    
    is_complete, missing_features = check_business_context_completeness()
    
    if is_complete:
        return "✅ VALIDATION PASSED: Business context is complete with all required features set. Ready to proceed to next phase."
    else:
        missing_count = len(missing_features)
        missing_list = ", ".join(missing_features)
        return f"❌ VALIDATION FAILED: Business context is incomplete. Missing {missing_count} required features: {missing_list}. Please use set_business_context to provide all required features before proceeding."


async def get_business_context_analysis_plan_impl(
    ctx: Context,
) -> str:
    """Get a comprehensive business context analysis plan.
    
    Args:
        ctx: MCP context for logging and error handling
        
    Returns:
        A markdown-formatted business context analysis plan with prompts for LLM analysis
    """
    logger.debug('Getting business context analysis plan')
    
    return get_business_context_analysis_plan()


# Register tools with the MCP server
def register_tools(mcp):
    """Register business context analysis tools with the MCP server.
    
    Args:
        mcp: The MCP server instance
    """
    @mcp.tool()
    async def set_business_context(
        ctx: Context,
        description: str = Field(description="Business context description"),
        industry_sector: Optional[str] = Field(default=None, description="Industry sector: Finance, Healthcare, Retail, Technology, Manufacturing, Government, Education, Energy, Transportation, Other"),
        data_sensitivity: Optional[str] = Field(default=None, description="Data sensitivity: Public, Internal, Confidential, Restricted, Regulated"),
        user_base_size: Optional[str] = Field(default=None, description="User base size: Small, Medium, Large, Enterprise"),
        geographic_scope: Optional[str] = Field(default=None, description="Geographic scope: Local, Regional, National, Multinational, Global"),
        regulatory_requirements: Optional[str] = Field(default=None, description="Regulatory requirements (comma-separated): GDPR, HIPAA, PCI-DSS, SOX, FISMA, CCPA, None, Multiple"),
        system_criticality: Optional[str] = Field(default=None, description="System criticality: Low, Medium, High, Mission-Critical"),
        financial_impact: Optional[str] = Field(default=None, description="Financial impact: Minimal, Low, Medium, High, Severe"),
        authentication_requirement: Optional[str] = Field(default=None, description="Authentication requirement: None, Basic, MFA, Federated, Biometric"),
        deployment_environment: Optional[str] = Field(default=None, description="Deployment environment: On-Premises, Cloud-Public, Cloud-Private, Hybrid, Multi-Cloud"),
        integration_complexity: Optional[str] = Field(default=None, description="Integration complexity: Standalone, Limited, Moderate, Complex, Highly Complex"),
    ) -> str:
        """Set the business context with description and all features in one call.

        This streamlined tool sets the business context description and all business features 
        in a single call, eliminating the need for the clarification questions workflow.

        Args:
            ctx: MCP context for logging and error handling
            description: Business context description
            industry_sector: Industry sector (optional)
            data_sensitivity: Data sensitivity level (optional)
            user_base_size: User base size (optional)
            geographic_scope: Geographic scope (optional)
            regulatory_requirements: Regulatory requirements, comma-separated (optional)
            system_criticality: System criticality (optional)
            financial_impact: Financial impact of breach (optional)
            authentication_requirement: Authentication requirement (optional)
            deployment_environment: Deployment environment (optional)
            integration_complexity: Integration complexity (optional)

        Returns:
            A confirmation message with the number of features configured
        """
        return await set_business_context_with_features_impl(
            ctx, description, industry_sector, data_sensitivity, user_base_size,
            geographic_scope, regulatory_requirements, system_criticality,
            financial_impact, authentication_requirement, deployment_environment,
            integration_complexity
        )


    @mcp.tool()
    async def get_business_context(
        ctx: Context,
    ) -> str:
        """Get the business context.

        This tool returns the business context created from the answers to the clarification questions.

        Args:
            ctx: MCP context for logging and error handling

        Returns:
            A markdown-formatted business context
        """
        return await get_business_context_impl(ctx)

    @mcp.tool()
    async def clear_business_context(
        ctx: Context,
    ) -> str:
        """Clear the business context.

        This tool clears the business context, description, and clarification questions.

        Args:
            ctx: MCP context for logging and error handling

        Returns:
            A confirmation message
        """
        return await clear_business_context_impl(ctx)
    
    @mcp.tool()
    async def get_business_context_features(
        ctx: Context,
    ) -> str:
        """Get all business context features with descriptions.

        This tool returns all available features of the business context with descriptions of what each feature represents.

        Args:
            ctx: MCP context for logging and error handling

        Returns:
            A markdown-formatted list of business context features with descriptions
        """
        return await get_business_context_features_impl(ctx)
    
    
    @mcp.tool()
    async def validate_business_context_completeness(
        ctx: Context,
    ) -> str:
        """Validate that all business context features are set before proceeding to next phase.

        This tool validates that all required business context features have been set
        and returns a clear message indicating whether the business context is complete
        or what features are still missing.

        Args:
            ctx: MCP context for logging and error handling

        Returns:
            A validation message indicating if business context is complete
        """
        return await validate_business_context_completeness_impl(ctx)

    @mcp.tool()
    async def get_business_context_analysis_plan(
        ctx: Context,
    ) -> str:
        """Get a comprehensive business context analysis plan.

        This tool returns a detailed plan for analyzing business context descriptions
        using AI-powered analysis to categorize business features.

        Args:
            ctx: MCP context for logging and error handling

        Returns:
            A markdown-formatted business context analysis plan with prompts for LLM analysis
        """
        return await get_business_context_analysis_plan_impl(ctx)
