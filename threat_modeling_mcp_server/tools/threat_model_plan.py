"""Threat Model Planning functionality for the Threat Modeling MCP Server."""

import os
import glob
from typing import Dict, List, Optional
from loguru import logger
from mcp.server.fastmcp import Context

async def detect_code_in_directory(directory: str, file_patterns: Optional[List[str]] = None) -> bool:
    """Detect if code files are present in the specified directory.
    
    Args:
        directory: Directory to check for code files
        file_patterns: Optional list of file patterns to look for
        
    Returns:
        True if code files are detected, False otherwise
    """
    if file_patterns is None:
        file_patterns = [
            # Common programming languages
            "*.py", "*.js", "*.ts", "*.java", "*.cs", "*.go", "*.rb", "*.php", "*.html", "*.css", "*.c", "*.cpp", "*.h", "*.hpp",
            # Infrastructure as Code
            "*.yaml", "*.yml", "*.json", "*.tf", "*.hcl", "*.cdk.ts", "*.cdk.js", "*.cfn.yaml", "*.cfn.yml", "*.cfn.json",
            # Database
            "*.sql", "*.graphql", "*.gql",
            # Configuration
            "Dockerfile", "docker-compose.yml", "docker-compose.yaml", "*.config", "*.xml", "*.toml", "*.ini",
            # Shell scripts
            "*.sh", "*.bash", "*.zsh", "*.ps1", "*.bat", "*.cmd"
        ]
    
    for pattern in file_patterns:
        file_paths = glob.glob(os.path.join(directory, "**", pattern), recursive=True)
        if file_paths:
            logger.info(f"Detected code files matching pattern {pattern}: {len(file_paths)} files")
            return True
    
    logger.info("No code files detected in the directory")
    return False


async def generate_threat_modeling_plan(ctx: Context, directory: str = ".", auto_validate_code: bool = True) -> str:
    """Generate a comprehensive threat modeling plan.

    This function returns a detailed threat modeling plan in markdown format,
    covering all phases of the threat modeling process. If code is detected in the
    specified directory and auto_validate_code is True, it will automatically
    run the threat model validation against the code.

    Args:
        ctx: MCP context for logging and error handling
        directory: Directory to check for code files
        auto_validate_code: Whether to automatically validate against code if detected

    Returns:
        A markdown-formatted threat modeling plan
    """
    logger.debug('Generating threat modeling plan')
    
    # Check if code files are present in the directory
    code_detected = await detect_code_in_directory(directory)
    logger.debug(f'Code detected: {code_detected}')
    
    plan = """
# Comprehensive Threat Modeling Plan

## Introduction

This is a practical, step-by-step threat modeling plan that provides specific tool guidance for conducting a thorough security analysis. Each phase includes concrete actions using the available MCP tools, ensuring systematic and comprehensive threat modeling.

## Step-by-Step Guidance Tools

For detailed, focused guidance on each phase, use these new step-specific tools:

- **Phase 1**: `get_phase_1_guidance()` - Business Context Analysis
- **Phase 2**: `get_phase_2_guidance()` - Architecture Analysis  
- **Phase 3**: `get_phase_3_guidance()` - Threat Actor Analysis
- **Phase 4**: `get_phase_4_guidance()` - Trust Boundary Analysis
- **Phase 5**: `get_phase_5_guidance()` - Asset Flow Analysis
- **Phase 6**: `get_phase_6_guidance()` - Threat Identification
- **Phase 7**: `get_phase_7_guidance()` - Mitigation Planning
- **Phase 7.5**: `get_phase_7_5_guidance()` - Code Validation Analysis
- **Phase 8**: `get_phase_8_guidance()` - Residual Risk Analysis
- **Phase 9**: `get_phase_9_guidance()` - Output Generation

## ⚠️ Important: Use Step-Specific Tools

Instead of trying to follow this entire plan at once, **use the step-specific guidance tools above**. They provide focused, actionable instructions for each phase and help prevent context overload.

## 📊 Progress Tracking

- **Progress Tracking**: `get_current_phase_status()` - Check current progress and next steps at any time

## AWS Documentation Integration - MANDATORY REQUIREMENT

**CRITICAL**: This threat modeling process REQUIRES the use of the AWS Documentation MCP server for ALL AWS-related analysis. This is not optional - it is a mandatory validation step that must be completed for each phase involving AWS services.

### AWS Documentation Tools - REQUIRED USAGE
1. **`search_documentation`** - MUST be used to search AWS documentation for security best practices
2. **`read_documentation`** - MUST be used to read specific AWS documentation pages
3. **`recommend`** - MUST be used to get content recommendations for AWS documentation pages

### MANDATORY AWS Documentation Usage
- **Architecture Analysis**: MUST validate ALL AWS service security configurations against official AWS documentation
- **Trust Boundary Analysis**: MUST confirm VPC, security group, and network security best practices using AWS docs
- **Asset Flow Analysis**: MUST verify data protection and encryption recommendations through AWS documentation
- **Threat Identification**: MUST research AWS-specific threat vectors and mitigations using AWS docs
- **Mitigation Planning**: MUST validate ALL security control implementations against AWS best practices

### ENFORCED AWS Documentation Usage Pattern
```
FOR EVERY AWS SERVICE OR SECURITY RECOMMENDATION:
1. MANDATORY: Use search_documentation to find relevant AWS security guidance
2. MANDATORY: Use read_documentation to get detailed implementation guidance  
3. MANDATORY: Use recommend to discover related security documentation
4. MANDATORY: Document AWS documentation references in your analysis
5. MANDATORY: Integrate findings into your threat model analysis with citations
```

### AWS Documentation Validation Requirements
**BEFORE proceeding with any AWS-related analysis, you MUST:**
1. Search for current AWS security best practices using `search_documentation`
2. Read at least one official AWS documentation page using `read_documentation`
3. Include AWS documentation URLs and citations in your analysis
4. Validate ALL recommendations against official AWS guidance

**FAILURE TO USE AWS DOCUMENTATION WILL RESULT IN INCOMPLETE THREAT MODELING**

## Phase 1: Business Context Analysis

### Objectives
- Understand the business value and criticality of the system
- Identify regulatory and compliance requirements
- Establish business impact thresholds

### Step-by-Step Process

#### Step 1.1: Set Complete Business Context (Streamlined Approach)
**Tool:** `set_business_context(description, industry_sector, data_sensitivity, user_base_size, geographic_scope, regulatory_requirements, system_criticality, financial_impact, authentication_requirement, deployment_environment, integration_complexity)`
- **NEW**: Set business context description AND all features in one efficient call
- Provide a comprehensive description of the system and its business purpose
- Include all business context features directly as parameters (all optional except description)
- Example: `set_business_context("Payment processing system for e-commerce", "Finance", "Confidential", "Large", "Global", "PCI-DSS", "High", "High", "MFA", "Cloud-Public", "Complex")`

#### Step 1.2: Review Available Options (Optional)
**Tools (for reference only):** 
- `get_business_context_features()` - See all business context categories
- `get_data_model_types(model_name="IndustrySector")` - Review industry options
- `get_data_model_types(model_name="DataSensitivity")` - Review data sensitivity levels
- `get_data_model_types(model_name="RegulatoryRequirement")` - Review compliance requirements
- `get_data_model_types(model_name="SystemCriticality")` - Review criticality levels

#### Step 1.3: Validate Business Context Completeness
**Tool:** `validate_business_context_completeness()`
- Validate that all required business context features have been set
- Get clear feedback on any missing features
- Ensure readiness to proceed to the next phase

#### Step 1.4: Document Assumptions
**Tool:** `add_assumption(description, category, impact, rationale)`
- Document key business assumptions that affect the threat model
- Examples:
  - "System will only operate in North America" (limits regulatory scope)
  - "Peak load is 10x normal traffic during sales events" (affects availability requirements)
  - "Customer data retention is 7 years" (affects data lifecycle)

#### Step 1.5: Review Complete Business Context
**Tool:** `get_business_context()`
- Review the complete business context generated from your setup
- Ensure all critical business aspects are captured

### Expected Outputs
- Complete business context with categorized features
- Documented assumptions about business scope and requirements
- Clear understanding of regulatory and compliance needs

---

## Phase 2: Architecture Analysis

### Objectives
- Document the system's technical architecture
- Identify components, interfaces, and dependencies
- Understand data flows and processing

### Step-by-Step Process

#### Step 2.1: Add System Components
**Tool:** `add_component(name, type, service_provider, specific_service, version, description, configuration)`
- Add each component of your system with detailed information
- Include cloud services, databases, APIs, microservices, etc.
- Examples:
  - `add_component("API Gateway", "Network", "AWS", "API Gateway", "v2", "Main entry point for all API requests")`
  - `add_component("User Database", "Storage", "AWS", "RDS", "PostgreSQL 13", "Stores user account information")`
  - `add_component("Payment Service", "Compute", "AWS", "Lambda", "Python 3.9", "Processes payment transactions")`

#### Step 2.2: Define Connections Between Components
**Tool:** `add_connection(source_id, destination_id, protocol, port, encryption, description)`
- Map how components communicate with each other
- Include protocol details, ports, and security characteristics
- Examples:
  - `add_connection("C001", "C002", "HTTPS", 443, True, "API Gateway to Payment Service")`
  - `add_connection("C002", "C003", "PostgreSQL", 5432, True, "Payment Service to User Database")`

#### Step 2.3: Add Data Stores
**Tool:** `add_data_store(name, type, classification, encryption_at_rest, backup_frequency, description)`
- Document all data storage locations
- Include classification and protection details
- Examples:
  - `add_data_store("Customer PII", "Relational", "Confidential", True, "Daily", "Personal customer information")`
  - `add_data_store("Transaction Logs", "Object Storage", "Internal", True, "Hourly", "Payment transaction audit logs")`

#### Step 2.4: Get Architecture Analysis Plan
**Tool:** `get_architecture_analysis_plan()`
- Get a comprehensive plan for AI-powered architecture analysis
- Follow the plan to analyze your architecture for security concerns
- Use AWS Documentation MCP server for validation of AWS-specific recommendations

#### Step 2.5: Validate AWS Service Security (if using AWS)
**AWS Documentation Tools:** `search_documentation`, `read_documentation`, `recommend`
- For each AWS service in your architecture, validate security best practices
- Examples:
  - `search_documentation("API Gateway security best practices")`
  - `read_documentation("https://docs.aws.amazon.com/apigateway/latest/developerguide/security.html")`
  - `search_documentation("RDS encryption at rest")`
  - `search_documentation("Lambda security configuration")`
  - `recommend("https://docs.aws.amazon.com/vpc/latest/userguide/security.html")` for VPC security recommendations

#### Step 2.6: Document Architecture Assumptions
**Tool:** `add_assumption(description, category, impact, rationale)`
- Document technical assumptions that affect security
- Include AWS-validated assumptions where applicable
- Examples:
  - "All internal network traffic is encrypted in transit" (reduces network attack surface)
  - "Database backups are encrypted and stored in separate region" (ensures data protection)
  - "Auto-scaling is configured for all compute services" (affects availability analysis)
  - "AWS WAF rules follow OWASP recommendations" (validated against AWS documentation)

### Expected Outputs
- Complete component inventory with detailed specifications
- Connection map showing all inter-component communications
- Data store catalog with classification and protection details
- Architecture security analysis with recommendations

---

## Phase 3: Threat Actor Analysis

### Objectives
- Identify potential adversaries
- Assess their capabilities and motivations
- Prioritize threat actors based on relevance

### Step-by-Step Process

#### Step 3.1: Review Default Threat Actors
**Tool:** `list_threat_actors()`
- Review the comprehensive set of default threat actors
- Understand their capabilities, motivations, and resources
- Default actors include: Script Kiddies, Cybercriminals, Insider Threats, Nation-State Actors, etc.

#### Step 3.2: Add Custom Threat Actors
**Tool:** `add_threat_actor(name, type, capability_level, motivations, resources, description)`
- Add threat actors specific to your business context
- Examples:
  - `add_threat_actor("Competitor", "External", "Medium", ["Espionage", "Disruption"], "Moderate", "Direct business competitor seeking advantage")`
  - `add_threat_actor("Disgruntled Customer", "External", "Low", ["Revenge"], "Limited", "Customer upset about service issues")`

#### Step 3.3: Set Threat Actor Relevance
**Tool:** `set_threat_actor_relevance(id, is_relevant)`
- Mark which threat actors are relevant to your specific system
- Consider your business context, data sensitivity, and exposure
- Examples:
  - Nation-state actors may not be relevant for a local business app
  - Insider threats are always relevant but vary in priority

#### Step 3.4: Prioritize Relevant Threat Actors
**Tool:** `set_threat_actor_priority(id, priority)`
- Rank threat actors by likelihood and potential impact (1-10 scale)
- Consider your specific business context and security posture
- Higher priority actors should be addressed first in threat identification

#### Step 3.5: Analyze Threat Actors
**Tool:** `analyze_threat_actors()`
- Get automated analysis of your threat actor landscape
- Review recommendations for threat actor prioritization
- Adjust priorities based on analysis insights

#### Step 3.6: Document Threat Actor Assumptions
**Tool:** `add_assumption(description, category, impact, rationale)`
- Document assumptions about threat actor capabilities and motivations
- Examples:
  - "Nation-state actors are not interested in our system" (reduces focus on sophisticated attacks)
  - "Insider threats have limited access to production systems" (affects privilege escalation analysis)

### Expected Outputs
- Prioritized list of relevant threat actors
- Detailed threat actor profiles with capabilities and motivations
- Analysis of threat landscape specific to your system

---

## Phase 4: Trust Boundary Analysis

### Objectives
- Identify trust zones within the system
- Document boundary crossings
- Validate security controls at boundaries

### Step-by-Step Process

#### Step 4.1: Get Trust Boundary Detection Plan
**Tool:** `get_trust_boundary_detection_plan()`
- Get a comprehensive plan for AI-powered trust boundary detection
- Follow the detailed 6-step process for intelligent boundary analysis
- Use LLM analysis to identify trust zones, crossing points, and boundaries

#### Step 4.2: Create Trust Zones
**Tool:** `add_trust_zone(name, trust_level, description)`
- Define logical trust zones based on security context
- Trust levels: Untrusted, Low, Medium, High
- Examples:
  - `add_trust_zone("Internet DMZ", "Untrusted", "Public-facing components exposed to internet")`
  - `add_trust_zone("Application Tier", "Medium", "Internal application services with authentication")`
  - `add_trust_zone("Database Tier", "High", "Sensitive data storage with restricted access")`

#### Step 4.3: Assign Components to Trust Zones
**Tool:** `add_component_to_zone(zone_id, component_id)`
- Assign each component to exactly one primary trust zone
- Ensure logical grouping based on security characteristics
- Avoid overlapping assignments

#### Step 4.4: Define Crossing Points
**Tool:** `add_crossing_point(source_zone_id, destination_zone_id, authentication_method, authorization_method, description)`
- Identify where data flows between trust zones
- Specify authentication and authorization mechanisms
- Examples:
  - `add_crossing_point("TZ001", "TZ002", "JWT", "RBAC", "API authentication from DMZ to app tier")`

#### Step 4.5: Map Connections to Crossing Points
**Tool:** `add_conn_to_crossing(crossing_point_id, connection_id)`
- Associate specific connections with crossing points
- Ensures all boundary crossings are properly secured

#### Step 4.6: Create Trust Boundaries
**Tool:** `add_trust_boundary(name, type, crossing_point_ids, controls, description)`
- Define trust boundaries with security controls
- Types: Network, Process, Application, Data
- Examples:
  - `add_trust_boundary("DMZ Firewall", "Network", ["CP001"], ["WAF", "DDoS Protection", "Rate Limiting"], "Network boundary protecting internal systems")`

#### Step 4.7: Get Trust Boundary Analysis Plan
**Tool:** `get_trust_boundary_analysis_plan()`
- Get comprehensive plan for analyzing trust boundaries for security concerns
- Use AI-powered analysis with AWS documentation validation
- Follow the plan to identify security gaps and recommendations

### Expected Outputs
- Complete trust zone map with component assignments
- Crossing point inventory with security controls
- Trust boundary catalog with implemented protections
- Security analysis with recommendations for improvements

---

## Phase 5: Asset Flow Analysis

### Objectives
- Identify critical assets
- Track asset lifecycle through the system
- Document protection requirements

### Step-by-Step Process

#### Step 5.1: Identify and Add Assets
**Tool:** `add_asset(name, type, classification, lifecycle_state, description, owner, sensitivity, criticality, metadata)`
- Identify all valuable assets in your system
- Include data assets, credentials, and intellectual property
- Examples:
  - `add_asset("Credit Card Numbers", "Data", "Restricted", "Active", "Customer payment card data", "Payment Team", 5, 5)`
  - `add_asset("User Passwords", "Credential", "Confidential", "Active", "User authentication credentials", "Security Team", 4, 4)`
  - `add_asset("API Keys", "Credential", "Confidential", "Active", "Third-party service authentication", "DevOps Team", 3, 4)`

#### Step 5.2: Map Asset Flows
**Tool:** `add_flow(asset_id, source_id, destination_id, transformation_type, controls, description, protocol, encryption, authenticated, authorized, validated, risk_level)`
- Document how assets move through the system
- Include security controls and risk assessments
- Examples:
  - `add_flow("A001", "C001", "C002", "Encryption", ["TLS", "Input Validation"], "Credit card data from API to payment service", "HTTPS", True, True, True, True, 2)`

#### Step 5.3: Get Asset Flow Analysis Plan
**Tool:** `get_asset_flow_analysis_plan()`
- Get comprehensive plan for AI-powered asset flow analysis
- Follow the plan to analyze flows for security concerns
- Use AWS documentation validation for cloud-specific recommendations

#### Step 5.4: Document Asset Flow Assumptions
**Tool:** `add_assumption(description, category, impact, rationale)`
- Document assumptions about asset protection and handling
- Examples:
  - "All sensitive data is encrypted at rest using AES-256" (reduces data exposure risk)
  - "Asset retention follows regulatory requirements" (affects data lifecycle threats)

### Expected Outputs
- Complete asset inventory with classification and criticality
- Asset flow map showing movement through the system
- Security analysis of asset protection and potential leakage points

---

## Phase 6: Threat Identification

### Objectives
- Systematically identify potential threats
- Categorize threats by type and impact
- Assess likelihood and potential damage

### Step-by-Step Process

#### Step 6.1: Systematic Threat Discovery
**Tool:** `add_threat(threat_source, prerequisites, threat_action, threat_impact, category, severity, likelihood, affected_components, affected_assets, tags)`
- Apply STRIDE methodology systematically
- Consider each threat actor against each asset and component
- Examples:
  - `add_threat("External Attacker", "with network access", "intercept unencrypted API calls", "exposure of sensitive data", "Information Disclosure", "High", "Possible", ["C001"], ["A001"], ["STRIDE-I", "Network"])`
  - `add_threat("Malicious Insider", "with database access", "exfiltrate customer data", "privacy breach and regulatory fines", "Information Disclosure", "High", "Unlikely", ["C003"], ["A001", "A002"], ["STRIDE-I", "Insider"])`

#### Step 6.2: Research AWS-Specific Threats (if using AWS)
**AWS Documentation Tools:** `search_documentation`, `read_documentation`
- Research AWS service-specific threat vectors and attack patterns
- Examples:
  - `search_documentation("API Gateway security threats")`
  - `search_documentation("RDS security vulnerabilities")`
  - `search_documentation("Lambda security risks")`
  - `search_documentation("S3 bucket security threats")`
  - `read_documentation("https://docs.aws.amazon.com/security/")` for general AWS security threats

#### Step 6.3: Threat Categorization and Review
**Tool:** `list_threats(category, severity, status)`
- Review all identified threats by category
- Ensure comprehensive coverage across STRIDE categories
- Validate threat-to-asset and threat-to-component mappings
- Include AWS-specific threats discovered through documentation research

#### Step 6.4: Document Threat Assumptions
**Tool:** `add_assumption(description, category, impact, rationale)`
- Document assumptions that affect threat likelihood or impact
- Include AWS-validated assumptions where applicable
- Examples:
  - "DDoS attacks are mitigated by CDN provider" (reduces DoS threat focus)
  - "Physical access to servers is controlled" (reduces physical threat vectors)
  - "AWS Shield provides DDoS protection" (validated against AWS documentation)

### Expected Outputs
- Comprehensive threat catalog with STRIDE categorization
- Threat-to-asset and threat-to-component mappings
- Risk-prioritized threat list

---

## Phase 7: Mitigation Planning

### Objectives
- Identify security controls to address threats
- Develop implementation strategies
- Prioritize mitigations

### Step-by-Step Process

#### Step 7.1: Add Mitigations for Each Threat
**Tool:** `add_mitigation(content, type, status, implementation_details, cost, effectiveness, metadata)`
- Create specific mitigations for identified threats
- Include implementation details and effectiveness ratings
- Examples:
  - `add_mitigation("Implement TLS 1.3 for all API communications", "Preventive", "mitigationIdentified", "Configure API Gateway and services for TLS 1.3 minimum", "Low", "High")`
  - `add_mitigation("Deploy Web Application Firewall", "Preventive", "mitigationIdentified", "Configure AWS WAF with OWASP rules", "Medium", "High")`

#### Step 7.2: Validate AWS Security Controls (if using AWS)
**AWS Documentation Tools:** `search_documentation`, `read_documentation`, `recommend`
- For each AWS-based mitigation, validate implementation against AWS best practices
- Examples:
  - `search_documentation("AWS WAF configuration best practices")`
  - `search_documentation("API Gateway security controls")`
  - `read_documentation("https://docs.aws.amazon.com/waf/latest/developerguide/security.html")`
  - `search_documentation("RDS security controls")`
  - `search_documentation("Lambda security best practices")`
  - `recommend("https://docs.aws.amazon.com/security/")` for general AWS security controls

#### Step 7.3: Link Mitigations to Threats
**Tool:** `link_mitigation_to_threat(mitigation_id, threat_id)`
- Associate each mitigation with the threats it addresses
- Ensure all high-priority threats have mitigations
- Some mitigations may address multiple threats

#### Step 7.4: Review Mitigation Coverage and Validate Links
**Tools:** `list_mitigations(type, status)`, `list_threats()`, `get_threat(id)`, `get_mitigation(id)`
- **Critical**: Ensure ALL threats have at least one linked mitigation
- **Critical**: Ensure ALL mitigations are linked to at least one threat
- Identify gaps in mitigation coverage using systematic review:

**Validation Process:**
1. **List all threats**: `list_threats()` - Get complete threat inventory
2. **For each threat**: `get_threat(id)` - Check if it has linked mitigations
3. **List all mitigations**: `list_mitigations()` - Get complete mitigation inventory  
4. **For each mitigation**: `get_mitigation(id)` - Check if it's linked to threats
5. **Identify orphaned threats**: Threats with no mitigations
6. **Identify orphaned mitigations**: Mitigations not linked to any threats
7. **Create additional mitigations**: For unmitigated threats
8. **Link existing mitigations**: To appropriate threats where applicable

**Gap Resolution Examples:**
- If threat T001 has no mitigations: Create and link appropriate mitigations
- If mitigation M001 has no threat links: Link to relevant threats or remove if unnecessary
- Prioritize high-severity threats for mitigation coverage first

#### Step 7.5: Validate Complete Threat-Mitigation Matrix
**Process:** Create a comprehensive validation matrix
- **Matrix Check**: Every threat ID should have at least one mitigation ID
- **Reverse Check**: Every mitigation ID should address at least one threat ID
- **Coverage Analysis**: High-severity threats should have multiple mitigations
- **Effectiveness Review**: Ensure mitigation types match threat categories

**Validation Questions to Answer:**
- Are all STRIDE categories covered by mitigations?
- Do all high-severity threats have preventive AND detective controls?
- Are there any threats marked as "accepted" without proper justification?
- Do all AWS-specific threats have AWS-validated mitigations?

#### Step 7.6: Document Mitigation Assumptions
**Tool:** `add_assumption(description, category, impact, rationale)`
- Document assumptions about mitigation effectiveness
- Include AWS-validated assumptions where applicable
- Examples:
  - "Security team will monitor WAF logs daily" (affects detective control effectiveness)
  - "Developers are trained in secure coding" (affects preventive control reliability)
  - "AWS Config monitors security group changes" (validated against AWS documentation)

### Expected Outputs
- Comprehensive mitigation plan with implementation details
- Threat-to-mitigation mapping
- Prioritized implementation roadmap

---
"""
    
    # Add code validation section between Phase 7 and Phase 8 if code was detected
    if code_detected:
        plan += """
## Phase 7.5: Code Validation Analysis

### Objectives
- Validate threat model against existing code security controls
- Identify threats already mitigated by code implementation
- Update threat and mitigation status based on code analysis

### Step-by-Step Process

#### Step 7.5.1: Get Phase 7.5 Guidance
**Tool:** `get_phase_7_5_guidance()`
- Get detailed guidance for code validation analysis
- Review objectives, steps, and expected outputs

#### Step 7.5.2: Validate Security Controls in Code
**Tool:** `validate_security_controls(directory, file_patterns)`
- Analyze codebase for existing security controls
- Identify implemented security measures
- Document findings

#### Step 7.5.3: Validate Threat Remediation
**Tool:** `validate_threat_remediation(directory, file_patterns)`
- Check which threats are already mitigated by code
- Compare threat model against actual implementation
- Generate remediation status report

#### Step 7.5.4: Generate Comprehensive Report
**Tool:** `generate_remediation_report()`
- Create detailed analysis of code security posture
- Document gaps between threat model and implementation
- Provide recommendations for improvements

#### Step 7.5.5: Update Threat Model Based on Findings
- Review validation results and update threat statuses
- Adjust mitigation priorities based on existing controls
- Document code-based security assumptions using `add_assumption()`

### Expected Outputs
- Security control inventory from code analysis
- Threat remediation status report
- Gap analysis with recommendations
- Updated threat model reflecting actual implementation

---
"""
    
    plan += """
## Phase 8: Residual Risk Analysis

### Objectives
- Assess remaining risks after mitigations are applied
- Determine risk acceptance criteria
- Document accepted risks

### Step-by-Step Process

#### Step 8.1: Get Phase 8 Guidance
**Tool:** `get_phase_8_guidance()`
- Get detailed guidance for residual risk analysis
- Review objectives and methodology

#### Step 8.2: Review All Threats and Mitigations
**Tools:** `list_threats()`, `list_mitigations()`
- Get complete inventory of threats and mitigations
- Review current status of each threat
- Identify unmitigated or partially mitigated threats

#### Step 8.3: Assess Residual Risk for Each Threat
**Tool:** `get_threat(id)` for each threat
- Evaluate remaining risk after mitigations
- Consider likelihood and impact of residual risk
- Document risk assessment rationale

#### Step 8.4: Make Risk Acceptance Decisions
**Tool:** `update_threat(id, status, ...)`
- Update threat status based on risk decisions
- Mark threats as: threatResolved, threatResolvedNotUseful
- Document business justification for each decision

#### Step 8.5: Document Risk Assumptions
**Tool:** `add_assumption(description, category, impact, rationale)`
- Document assumptions about residual risks
- Include business risk tolerance decisions
- Record risk acceptance criteria

### Expected Outputs
- Complete residual risk assessment
- Updated threat statuses with justifications
- Risk acceptance documentation

---

## Phase 9: Output Generation and Documentation

### Objectives
- Generate final documentation and outputs
- Export threat model for integration with development processes
- Create comprehensive threat modeling report

### Step-by-Step Process

#### Step 9.1: Get Phase 9 Guidance
**Tool:** `get_phase_9_guidance()`
- Get detailed guidance for output generation
- Review export options and formats

#### Step 9.2: Export Comprehensive Threat Model
**Tool:** `export_comprehensive_threat_model(output_path)`
- Export complete threat model with all global variables to JSON format
- Include all components, threats, mitigations, business context, assumptions, and phase progress
- Compatible with AWS Threat Composer and includes extended data

#### Step 9.3: Export with Remediation Status
**Tool:** `export_threat_model_with_remediation_status(output_path)`
- Export threat model including code validation results
- Show which threats are mitigated by existing code
- Include remediation recommendations

#### Step 9.4: Generate Summary Reports
**Tools:** `get_threat_model_progress()`, `list_assumptions()`
- Create executive summary of threat modeling process
- Document key findings and recommendations
- Include progress metrics and completion status

### Expected Outputs
- Threat Composer JSON export
- Remediation status report
- Executive summary document
- Implementation recommendations

## 🎯 Recommended Approach: Sequential Phase Execution

**IMPORTANT**: Follow the phases sequentially using the step-specific guidance tools:

### Execution Flow:
1. **`get_phase_1_guidance()`** → Complete Phase 1 → **`get_phase_2_guidance()`** → etc.
2. **`get_current_phase_status()`** - Check progress at any time
3. Use individual tools as guided by each phase

### Phase Transition Checklist:
- ✅ Complete all steps in current phase
- ✅ Verify expected outputs are generated
- ✅ Document any assumptions or decisions
- ✅ Move to next phase guidance tool

### Critical Phases Requiring Extra Attention:
- **Phase 7.5**: Use `validate_security_controls()` and `validate_threat_remediation()`
- **Phase 8**: Use `update_threat()` to set final threat statuses
- **Phase 9**: Use `export_to_threat_composer()` for final output

### Why Use Step-Specific Tools?
- **Reliability**: No dependency on unimplemented orchestrator functions
- **Transparency**: Users see exactly what tools to use at each step
- **Flexibility**: Users can adapt the process to their specific needs
- **Maintainability**: Easier to maintain individual tools than complex orchestrators
- **Debugging**: Easier to troubleshoot when users follow explicit steps

## Conclusion

This comprehensive plan provides the full methodology, and the **step-specific guidance tools** provide the most effective way to execute the threat modeling process. Use them for reliable, consistent results without hitting implementation roadblocks.
"""
    
    return plan


# Register tools with the MCP server
def register_tools(mcp):
    """Register threat model planning tools with the MCP server.
    
    Args:
        mcp: The MCP server instance
    """
    @mcp.tool()
    async def get_threat_modeling_plan(ctx: Context, directory: str = ".", auto_validate_code: bool = True) -> str:
        """Get a comprehensive threat modeling plan.

        This tool returns a detailed threat modeling plan in markdown format,
        covering all phases of the threat modeling process. If code is detected in the
        specified directory, it will automatically run the threat model validation
        against the code.

        Args:
            ctx: MCP context for logging and error handling
            directory: Directory to check for code files (default: current directory)
            auto_validate_code: Whether to automatically validate against code if detected (default: True)

        Returns:
            A markdown-formatted threat modeling plan
        """
        return await generate_threat_modeling_plan(ctx, directory, auto_validate_code)
