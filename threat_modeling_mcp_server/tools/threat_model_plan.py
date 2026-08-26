"""Threat Model Planning functionality for the Threat Modeling MCP Server."""

import os
import glob
from typing import List, Optional
from loguru import logger
from mcp.server.fastmcp import Context

CODE_FILE_PATTERNS = [
    # Common programming languages
    "*.py", "*.js", "*.ts", "*.java", "*.cs", "*.go", "*.rb", "*.php", "*.html",
    "*.css", "*.c", "*.cpp", "*.h", "*.hpp",
    # Infrastructure as Code
    "*.yaml", "*.yml", "*.json", "*.tf", "*.hcl", "*.cdk.ts", "*.cdk.js",
    "*.cfn.yaml", "*.cfn.yml", "*.cfn.json",
    # Database
    "*.sql", "*.graphql", "*.gql",
    # Configuration
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml", "*.config",
    "*.xml", "*.toml", "*.ini",
    # Shell scripts
    "*.sh", "*.bash", "*.zsh", "*.ps1", "*.bat", "*.cmd",
]


def has_code_files(directory: str = ".", file_patterns: Optional[List[str]] = None) -> bool:
    """Synchronously detect whether code files are present in a directory.

    Args:
        directory: Directory to check for code files
        file_patterns: Optional list of file patterns to look for

    Returns:
        True if code files are detected, False otherwise
    """
    for pattern in file_patterns or CODE_FILE_PATTERNS:
        if glob.glob(os.path.join(directory, "**", pattern), recursive=True):
            logger.debug(f"Detected code files matching pattern {pattern}")
            return True

    logger.debug("No code files detected in the directory")
    return False


async def detect_code_in_directory(directory: str, file_patterns: Optional[List[str]] = None) -> bool:
    """Detect if code files are present in the specified directory.

    Args:
        directory: Directory to check for code files
        file_patterns: Optional list of file patterns to look for

    Returns:
        True if code files are detected, False otherwise
    """
    return has_code_files(directory, file_patterns)


async def generate_threat_modeling_plan(ctx: Context, directory: str = ".", auto_validate_code: bool = True) -> str:
    """Generate a comprehensive threat modeling plan.

    This function returns a detailed threat modeling plan in markdown format,
    covering all phases of the threat modeling process. If code is detected in the
    specified directory and auto_validate_code is True, the plan includes the
    conditional code-validation phase.

    Args:
        ctx: MCP context for logging and error handling
        directory: Directory to check for code files
        auto_validate_code: Whether to include code-validation guidance when code is detected

    Returns:
        A markdown-formatted threat modeling plan
    """
    logger.debug('Generating threat modeling plan')
    
    # Check for code only when the caller wants the optional validation phase.
    code_detected = (
        await detect_code_in_directory(directory)
        if auto_validate_code
        else False
    )
    logger.debug(f'Code detected: {code_detected}')
    
    plan = """
# Comprehensive Threat Modeling Plan

## Introduction

This is a practical, step-by-step threat modeling plan that provides specific tool guidance for conducting a thorough security analysis. Each phase includes concrete actions using the available MCP tools, ensuring systematic and comprehensive threat modeling.

## Focused Phase Guidance

Use `manage_workflow(action="guidance", phase=PHASE)` for detailed, focused guidance:

- **Phase 1**: `phase="1"` - Business Context Analysis
- **Phase 2**: `phase="2"` - Architecture Analysis
- **Phase 3**: `phase="3"` - Threat Actor Analysis
- **Phase 4**: `phase="4"` - Trust Boundary Analysis
- **Phase 5**: `phase="5"` - Asset Flow Analysis
- **Phase 6**: `phase="6"` - Threat Identification
- **Phase 7**: `phase="7"` - Mitigation Planning
- **Phase 7.5**: `phase="7.5"` - Code Validation Analysis
- **Phase 8**: `phase="8"` - Residual Risk Analysis
- **Phase 9**: `phase="9"` - Output Generation

## ⚠️ Important: Use Focused Guidance

Instead of trying to follow this entire plan at once, call the consolidated
`manage_workflow` guidance action for the phase at hand. It provides focused,
actionable instructions and helps prevent context overload.

## 📊 Progress Tracking

- **Progress Tracking**: `manage_workflow(action="status")` - Check current progress and next steps at any time

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

#### Step 1.1: Review Context Contracts as Needed
**Tool:** `manage_system_context(action="describe", section=SECTION)`
- Use `business`, `software`, `data_assets`, `user_personas`, or `nfrs` to load
  only that section's fields and exact enum values
- Use `section="all"` for the compact action and payload overview

#### Step 1.2: Set Complete System Context
**Tool:** `manage_system_context(action="set", section="all", values=CONTEXT)`
- Submit one nested object with `business` and `software` objects plus
  `data_assets`, `user_personas`, and `nfrs` arrays
- The business object includes the description, all scalar features, and all four
  geographic facets: `data_residency`, `compute_location`, `user_base_location`,
  and `organizational_headquarters`
- Payload shape: `values={"business": BUSINESS_VALUES, "software": SOFTWARE_VALUES, "data_assets": DATA_ASSET_ITEMS, "user_personas": PERSONA_ITEMS, "nfrs": NFR_ITEMS}`

`inspect_data_models(model_name=...)` remains available when an individual enum
needs to be inspected outside the system-context workflow.

#### Step 1.3: Validate Context Completeness
**Tool:** `manage_system_context(action="validate", section="all")`
- Enforce the business-context completion gate
- Report software, data asset, user persona, and NFR coverage
- Resolve every missing business feature before advancing

#### Step 1.4: Document Assumptions
**Tool:** `manage_assumptions(action="add", values=ASSUMPTION)`
- Document key business assumptions that affect the threat model
- Examples:
  - "System will only operate in North America" (limits regulatory scope)
  - "Peak load is 10x normal traffic during sales events" (affects availability requirements)
  - "Customer data retention is 7 years" (affects data lifecycle)

#### Step 1.5: Review Complete System Context
**Tool:** `manage_system_context(action="get", section="all")`
- Review business context and every classification profile
- Ensure all critical business and classification fields are captured

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
**Tool:** `manage_architecture(action="add", section="components", values=COMPONENT)`
- Add each component of your system with detailed information
- Include cloud services, databases, APIs, microservices, etc.
- Use `manage_architecture(action="describe", section="components")` for exact fields

#### Step 2.2: Add Data Stores
**Tool:** `manage_architecture(action="add", section="data_stores", values=DATA_STORE)`
- Document all data storage locations
- Include classification and protection details

#### Step 2.3: Define Connections Between Architecture Nodes
**Tool:** `manage_architecture(action="add", section="connections", values=CONNECTION)`
- After all components and data stores exist, map how they communicate
- Include protocol details, ports, and security characteristics

#### Step 2.4: Get Architecture Analysis Plan
**Tool:** `manage_architecture(action="plan", section="all")`
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
**Tool:** `manage_assumptions(action="add", values=ASSUMPTION)`
- Document technical assumptions that affect security
- Include AWS-validated assumptions where applicable
- Examples:
  - "All internal network traffic is encrypted in transit" (reduces network attack surface)
  - "Database backups are encrypted and stored in separate region" (ensures data protection)
  - "Auto-scaling is configured for all compute services" (affects availability analysis)
  - "AWS WAF rules follow OWASP recommendations" (validated against AWS documentation)

### Expected Outputs
- Complete component inventory with detailed specifications
- Connection map showing all architecture-node communications
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
**Tool:** `manage_threat_actors(action="list")`
- Review the comprehensive set of default threat actors
- Understand their capabilities, motivations, and resources
- Default actors include: Script Kiddies, Cybercriminals, Insider Threats, Nation-State Actors, etc.
- These are a checklist to work through, not findings. An actor counts toward this phase only
  once you assess it (Step 3.3 or 3.4) or add your own (Step 3.2). Actors left untouched are
  excluded from the exported report and listed in its reference-catalogue appendix instead.

#### Step 3.2: Add Custom Threat Actors
**Tool:** `manage_threat_actors(action="add", values=ACTOR)`
- Add threat actors specific to your business context
- Call `manage_threat_actors(action="describe")` for exact taxonomy fields

#### Step 3.3: Set Threat Actor Relevance
**Tool:** `manage_threat_actors(action="update", item_id=ACTOR_ID, values={"is_relevant": BOOLEAN})`
- Mark which threat actors are relevant to your specific system
- Consider your business context, data sensitivity, and exposure
- Examples:
  - Nation-state actors may not be relevant for a local business app
  - Insider threats are always relevant but vary in priority

#### Step 3.4: Prioritize Relevant Threat Actors
**Tool:** `manage_threat_actors(action="update", item_id=ACTOR_ID, values={"priority": NUMBER})`
- Rank threat actors by likelihood and potential impact (1-10 scale)
- Consider your specific business context and security posture
- Higher priority actors should be addressed first in threat identification

#### Step 3.5: Analyze Threat Actors
**Tool:** `manage_threat_actors(action="analyze")`
- Get automated analysis of your threat actor landscape
- Review recommendations for threat actor prioritization
- Adjust priorities based on analysis insights

#### Step 3.6: Document Threat Actor Assumptions
**Tool:** `manage_assumptions(action="add", values=ASSUMPTION)`
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
**Tool:** `manage_trust_boundaries(action="detection_plan", section="all")`
- Get a comprehensive plan for AI-powered trust boundary detection
- Follow the detailed 6-step process for intelligent boundary analysis
- Use LLM analysis to identify trust zones, crossing points, and boundaries

#### Step 4.2: Create Trust Zones
**Tool:** `manage_trust_boundaries(action="add", section="zones", values=ZONE)`
- Define logical trust zones based on security context
- Trust levels: Untrusted, Low, Medium, High

#### Step 4.3: Assign Architecture Nodes to Trust Zones
**Tool:** `manage_trust_boundaries(action="link", section="zones", values=LINK)`
- Pass `zone_id` and `node_id`
- Assign each component and data store to exactly one primary trust zone
- Ensure logical grouping based on security characteristics
- Avoid overlapping assignments

#### Step 4.4: Define Crossing Points
**Tool:** `manage_trust_boundaries(action="add", section="crossing_points", values=CROSSING)`
- Identify where data flows between trust zones
- Specify authentication and authorization mechanisms

#### Step 4.5: Map Connections to Crossing Points
**Tool:** `manage_trust_boundaries(action="link", section="crossing_points", values=LINK)`
- Associate specific connections with crossing points
- Ensures all boundary crossings are properly secured

#### Step 4.6: Create Trust Boundaries
**Tool:** `manage_trust_boundaries(action="add", section="boundaries", values=BOUNDARY)`
- Define trust boundaries with security controls
- Types: Network, Process, Application, Data

#### Step 4.7: Get Trust Boundary Analysis Plan
**Tool:** `manage_trust_boundaries(action="analysis_plan", section="all")`
- Get comprehensive plan for analyzing trust boundaries for security concerns
- Use AI-powered analysis with AWS documentation validation
- Follow the plan to identify security gaps and recommendations

### Expected Outputs
- Complete trust zone map with architecture-node assignments
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
**Tool:** `manage_asset_flows(action="add", section="assets", values=ASSET)`
- Identify all valuable assets in your system
- Include data assets, credentials, and intellectual property
- Call `manage_asset_flows(action="describe", section="assets")` for exact fields

#### Step 5.2: Map Asset Flows
**Tool:** `manage_asset_flows(action="add", section="flows", values=FLOW)`
- Document how assets move between component and data-store nodes
- Include security controls and risk assessments

#### Step 5.3: Document Asset Flow Assumptions
**Tool:** `manage_assumptions(action="add", values=ASSUMPTION)`
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
**Tool:** `manage_threats(action="add", section="threats", values=THREAT)`
- Apply STRIDE methodology systematically
- Consider each threat actor against each asset and component
- Call `manage_threats(action="describe", section="threats")` for exact fields

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
**Tool:** `manage_threats(action="list", section="threats", values=FILTERS)`
- Review all identified threats by category
- Ensure comprehensive coverage across STRIDE categories
- Validate threat-to-asset and threat-to-component mappings
- Include AWS-specific threats discovered through documentation research

#### Step 6.4: Document Threat Assumptions
**Tool:** `manage_assumptions(action="add", values=ASSUMPTION)`
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
**Tool:** `manage_threats(action="add", section="mitigations", values=MITIGATION)`
- Create specific mitigations for identified threats
- Include implementation details and effectiveness ratings
- Call `manage_threats(action="describe", section="mitigations")` for exact fields

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
**Tool:** `manage_threats(action="link", section="mitigations", values=LINK)`
- Associate each mitigation with the threats it addresses
- Ensure all high-priority threats have mitigations
- Some mitigations may address multiple threats
- Use `items=[LINK, ...]` to create multiple links in one call

#### Step 7.4: Review Mitigation Coverage and Validate Links
**Tool:** `manage_threats` list/get actions for the `threats` and `mitigations` sections
- **Critical**: Ensure ALL threats have at least one linked mitigation
- **Critical**: Ensure ALL mitigations are linked to at least one threat
- Identify gaps in mitigation coverage using systematic review:

**Validation Process:**
1. **List all threats**: `manage_threats(action="list", section="threats")`
2. **For each threat**: `manage_threats(action="get", section="threats", item_id=ID)`
3. **List all mitigations**: `manage_threats(action="list", section="mitigations")`
4. **For each mitigation**: `manage_threats(action="get", section="mitigations", item_id=ID)`
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
**Tool:** `manage_assumptions(action="add", values=ASSUMPTION)`
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
**Tool:** `manage_workflow(action="guidance", phase="7.5")`
- Get detailed guidance for code validation analysis
- Review objectives, steps, and expected outputs

#### Step 7.5.2: Load the Finding Contract
**Tool:** `manage_code_validation(action="describe")`
- Review the accepted threat and mitigation outcomes
- Use the project directory already recorded in Phase 1

#### Step 7.5.3: Inspect and Record Evidence
**Tool:** `manage_code_validation(action="record", values=FINDINGS)`
- Inspect the relevant implementation paths yourself
- Record concrete evidence for every current threat and mitigation
- Status changes are applied atomically from the submitted outcomes

#### Step 7.5.4: Validate Coverage
**Tool:** `manage_code_validation(action="validate")`
- Resolve every missing or stale finding
- Use `action="get"` to review current findings and progress

#### Step 7.5.5: Generate the Report
**Tool:** `manage_code_validation(action="report")`
- Render the deterministic evidence-based report
- This finalizes the current snapshot and completes Phase 7.5

### Expected Outputs
- Evidence-backed findings for every current threat and mitigation
- Explicit code-validation outcomes and matching canonical status updates
- Complete, fresh coverage for the current project snapshot
- Deterministic report with any recorded recommendations

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
**Tool:** `manage_workflow(action="guidance", phase="8")`
- Get detailed guidance for residual risk analysis
- Review objectives and methodology

#### Step 8.2: Review All Threats and Mitigations
**Tool:** `manage_threats(action="list", section="all")`
- Get complete inventory of threats and mitigations
- Review current status of each threat
- Identify unmitigated or partially mitigated threats

#### Step 8.3: Assess Residual Risk for Each Threat
**Tool:** `manage_threats(action="get", section="threats", item_id=ID)`
- Evaluate remaining risk after mitigations
- Choose Open, Accepted, Mitigated, or Not Applicable
- Record residual severity, likelihood, and rationale

#### Step 8.4: Make Risk Acceptance Decisions
**Tool:** `manage_threats(action="assess", section="threats", items=ASSESSMENTS)`
- Save all decisions atomically
- Each item requires `threat_id`, `decision`, and `rationale`
- Residual severity and likelihood are required except for Not Applicable
- The server derives the Threat Composer status from the decision

#### Step 8.5: Document Risk Assumptions
**Tool:** `manage_assumptions(action="add", values=ASSUMPTION)`
- Document assumptions about residual risks
- Include business risk tolerance decisions
- Record risk acceptance criteria

### Expected Outputs
- Complete residual risk assessment
- Current decision, residual ratings, and rationale for every threat
- Risk acceptance documentation

---

## Phase 9: Output Generation and Documentation

### Objectives
- Generate final documentation and outputs
- Export threat model for integration with development processes
- Create comprehensive threat modeling report

### Step-by-Step Process

#### Step 9.1: Get Phase 9 Guidance
**Tool:** `manage_workflow(action="guidance", phase="9")`
- Get detailed guidance for output generation
- Review export options and formats

#### Step 9.2: Export Comprehensive Threat Model
**Tool:** `export_threat_model(output_path="threat_model.json")`
- Export complete threat model with all global variables to JSON format
- Include all components, threats, mitigations, business context, assumptions, and phase progress
- Include current threat and mitigation statuses, including updates from code validation
- Compatible with AWS Threat Composer and includes extended data
- Phase 9 completes only after both files represent the current model

#### Step 9.3: Generate Summary Reports
**Tools:** `manage_workflow(action="progress")`, `manage_assumptions(action="list")`
- Create executive summary of threat modeling process
- Document key findings and recommendations
- Include progress metrics and completion status

### Expected Outputs
- Threat Composer JSON export
- Threat and mitigation statuses captured in the JSON and Markdown exports
- Executive summary document
- Implementation recommendations

## 🎯 Recommended Approach: Sequential Phase Execution

**IMPORTANT**: Follow the phases sequentially using the workflow guidance action:

### Execution Flow:
1. **`manage_workflow(action="guidance", phase="1")`** → Complete Phase 1 → **`manage_workflow(action="guidance", phase="2")`** → etc.
2. **`manage_workflow(action="status")`** - Check progress at any time
3. Use the compact domain managers as guided by each phase

### Phase Transition Checklist:
- ✅ Complete all steps in current phase
- ✅ Verify expected outputs are generated
- ✅ Document any assumptions or decisions
- ✅ Move to next phase guidance tool

### Critical Phases Requiring Extra Attention:
- **Phase 7.5**: Start with `manage_code_validation(action="describe")`, then record implementation evidence for every threat and mitigation, validate coverage, and generate the report
- **Phase 8**: Use `manage_threats(action="assess", section="threats", ...)` to record current residual-risk decisions
- **Phase 9**: Use `export_threat_model()` for final output

### Why Use Focused Phase Guidance?
- **Reliability**: No dependency on unimplemented orchestrator functions
- **Transparency**: Users see exactly what tools to use at each step
- **Flexibility**: Users can adapt the process to their specific needs
- **Maintainability**: Domain managers centralize related operations and payload guidance
- **Debugging**: Easier to troubleshoot when users follow explicit steps

## Conclusion

This comprehensive plan provides the full methodology, and
`manage_workflow(action="guidance", phase=PHASE)` provides the focused
instructions needed to execute one phase at a time without loading every phase
into context.
"""
    
    return plan
