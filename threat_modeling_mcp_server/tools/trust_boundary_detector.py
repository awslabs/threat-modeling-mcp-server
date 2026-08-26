"""Trust Boundary Detection functionality for the Threat Modeling MCP Server."""

from loguru import logger
from mcp.server.fastmcp import Context


async def get_trust_boundary_detection_plan_impl(
    ctx: Context,
) -> str:
    """Get a comprehensive trust boundary detection plan.
    
    Args:
        ctx: MCP context for logging and error handling
        
    Returns:
        A markdown-formatted plan with prompts for LLM-powered trust boundary detection
    """
    logger.debug('Getting trust boundary detection plan')
    
    result = "# Trust Boundary Detection Analysis Plan\n\n"
    
    result += """## Overview
This plan provides a structured approach for detecting trust boundaries from architecture components using AI-powered analysis.

## Analysis Process

### Step 1: Gather Architecture Data
First, collect all architecture information using the following tools:

1. **Get Components**: Use `manage_architecture(action="list", section="components")`
2. **Get Connections**: Use `manage_architecture(action="list", section="connections")`
3. **Get Data Stores**: Use `manage_architecture(action="list", section="data_stores")`

### Step 2: LLM Trust Zone Detection Prompt
Use the following prompt structure with an LLM to detect trust zones:

```
You are a cybersecurity expert analyzing system architecture to detect trust zones for threat modeling.

ARCHITECTURE DATA:
[Insert the output from manage_architecture list calls here]

ANALYSIS INSTRUCTIONS:
Analyze the architecture and identify logical trust zones based on:

1. **Security Context Analysis**:
   - Group components with similar security requirements
   - Consider data sensitivity and protection needs
   - Identify components that should be isolated for security reasons
   - Look for components handling similar types of sensitive data

2. **Service Grouping Analysis**:
   - Group related services that work together as a logical unit
   - Consider service dependencies and communication patterns
   - Identify service boundaries and well-defined interfaces
   - Look for microservice boundaries or application tiers

3. **Network Topology Analysis**:
   - Consider network segmentation and isolation requirements
   - Identify architecture nodes in similar network contexts (DMZ, internal, etc.)
   - Look for natural network boundaries and subnets
   - Consider components and data stores with similar network exposure

4. **Trust Level Assessment**:
   For each identified zone, assess trust level based on:
   - Data sensitivity handled by architecture nodes in the zone
   - Exposure to external networks, internet, or untrusted users
   - Security controls and protections already in place
   - Criticality to business operations and potential impact of compromise

5. **Zone Deduplication and Optimization**:
   - Ensure each component and data store belongs to exactly one primary trust zone
   - Merge overlapping or redundant zones that don't add security value
   - Prioritize security-based groupings over generic technical groupings
   - Avoid over-segmentation that creates management overhead

TRUST LEVEL GUIDELINES:
- **Untrusted**: Internet-facing, public access, no authentication required
- **Low**: Limited trust, basic authentication, some exposure to external users
- **Medium**: Internal systems, authenticated access, standard security controls
- **High**: Sensitive data, strong authentication, restricted access, critical systems

OUTPUT FORMAT:
Provide your analysis in the following structured format:

# Trust Zone Detection Results

## Detected Trust Zones

### Zone 1: [Descriptive Zone Name]
- **Trust Level**: [Untrusted/Low/Medium/High]
- **Architecture Nodes**: [List of component and data-store IDs that belong to this zone]
- **Rationale**: [Detailed explanation of why these nodes belong together]
- **Security Characteristics**: [Key security attributes and requirements]
- **Data Sensitivity**: [Types and sensitivity of data handled]

### Zone 2: [Descriptive Zone Name]
- **Trust Level**: [Untrusted/Low/Medium/High]
- **Architecture Nodes**: [List of component and data-store IDs]
- **Rationale**: [Explanation of grouping logic]
- **Security Characteristics**: [Security attributes]
- **Data Sensitivity**: [Data types and sensitivity]

[Continue for each detected zone...]

## Trust Zone Summary
- **Total zones detected**: [number]
- **Architecture nodes assigned**: [number assigned / total nodes]
- **Unassigned architecture nodes**: [list node IDs if any remain unassigned]
- **Zone distribution**: [brief summary of how nodes are distributed across trust levels]

## Recommendations
- [Any recommendations for zone refinement or additional considerations]
```

### Step 3: LLM Crossing Point Detection Prompt
Based on the trust zones identified above, use this prompt to detect crossing points:

```
You are analyzing trust zone boundaries to identify crossing points where data flows between different trust zones.

TRUST ZONES IDENTIFIED:
[Insert the trust zone results from Step 2 here]

CONNECTION DATA:
[Insert the connection data from manage_architecture(action="list", section="connections") here]

CROSSING POINT ANALYSIS INSTRUCTIONS:
For each connection that crosses trust zone boundaries, analyze:

1. **Connection Analysis**:
   - Identify source and destination trust zones for each connection
   - Analyze protocol, port, and security characteristics
   - Assess data flow direction and communication patterns
   - Consider the purpose and necessity of the connection

2. **Authentication Method Detection**:
   - Analyze connection properties (protocol, encryption, etc.)
   - Consider service types and their typical authentication patterns
   - Determine most appropriate authentication mechanisms
   - Consider industry standards and best practices

3. **Authorization Method Detection**:
   - Consider access control requirements based on trust levels
   - Analyze service-specific authorization patterns
   - Determine appropriate authorization mechanisms
   - Consider principle of least privilege

4. **Security Risk Assessment**:
   - Assess the security risk of each boundary crossing
   - Identify potential attack vectors or vulnerabilities
   - Consider the trust level difference between zones

OUTPUT FORMAT:
# Crossing Point Detection Results

## Detected Crossing Points

### Crossing Point 1: [Source Zone Name] → [Destination Zone Name]
- **Connection IDs**: [List of connection IDs that use this crossing point]
- **Protocol/Port**: [Connection protocols and ports]
- **Authentication Method**: [Recommended method with reasoning]
- **Authorization Method**: [Recommended method with reasoning]
- **Security Concerns**: [Any identified security issues or risks]
- **Data Flow**: [Description of what data flows across this boundary]

### Crossing Point 2: [Source Zone Name] → [Destination Zone Name]
[Continue for each crossing point...]

## Crossing Point Summary
- **Total crossing points**: [number]
- **High-risk crossings**: [number and brief description]
- **Authentication gaps**: [crossings without proper authentication]
- **Authorization gaps**: [crossings without proper authorization]
```

### Step 4: LLM Trust Boundary Classification Prompt
Based on the zones and crossing points, use this prompt to classify trust boundaries:

```
You are classifying trust boundaries based on the trust zones and crossing points identified.

TRUST ZONES:
[Insert trust zone results from Step 2]

CROSSING POINTS:
[Insert crossing point results from Step 3]

TRUST BOUNDARY CLASSIFICATION INSTRUCTIONS:
For each zone-to-zone relationship with crossing points, analyze:

1. **Boundary Type Classification**:
   - **Network boundary**: Different network segments, VPCs, or subnets
   - **Process boundary**: Different processes, services, or applications
   - **Application boundary**: Different applications or application tiers
   - **Data boundary**: Different data classifications or data stores

2. **Security Control Recommendations**:
   - Analyze trust level differences between zones
   - Consider threat landscape and potential attack vectors
   - Recommend appropriate security controls for the boundary
   - Validate against security frameworks and best practices
   - Consider compliance requirements if applicable

3. **Risk Assessment**:
   - Assess the security risk of boundary crossings
   - Identify potential security gaps or vulnerabilities
   - Prioritize security control implementation based on risk
   - Consider business impact of boundary compromise

4. **AWS-Specific Considerations** (if applicable):
   - Leverage AWS security services and best practices
   - Consider VPC security groups, NACLs, and WAF
   - Recommend AWS-native security controls where appropriate

VALIDATION REQUIREMENT:
For any AWS-specific security recommendations, validate against official AWS documentation using the AWS Documentation MCP server.

OUTPUT FORMAT:
# Trust Boundary Classification Results

## Detected Trust Boundaries

### Boundary 1: [Descriptive Boundary Name]
- **Type**: [Network/Process/Application/Data]
- **Source Zone**: [Zone name and trust level]
- **Destination Zone**: [Zone name and trust level]
- **Crossing Points**: [List of crossing point IDs]
- **Recommended Controls**: [List of security controls with reasoning]
- **Risk Level**: [Low/Medium/High with detailed explanation]
- **Implementation Priority**: [High/Medium/Low based on risk and business impact]
- **AWS Services** (if applicable): [Relevant AWS security services]

### Boundary 2: [Descriptive Boundary Name]
[Continue for each boundary...]

## Trust Boundary Summary
- **Total boundaries**: [number]
- **High-risk boundaries**: [number and brief description]
- **Critical controls needed**: [summary of most important security controls]
- **Implementation roadmap**: [suggested order of implementation]

## Validation and Next Steps
- Use manual trust boundary tools to implement the detected boundaries
- Validate security control recommendations against business requirements
- Consider integration with existing security infrastructure
- Plan implementation based on risk priority and resource availability
```

### Step 5: Implementation Guidance
After completing the LLM analysis, use the following tools to implement the results:

1. **Create Trust Zones**: Use `manage_trust_boundaries(action="add", section="zones", values=ZONE)`
2. **Assign Architecture Nodes**: Use `manage_trust_boundaries(action="link", section="zones", values={"zone_id": ZONE_ID, "node_id": NODE_ID})`
3. **Create Crossing Points**: Use `manage_trust_boundaries(action="add", section="crossing_points", values=CROSSING)`
4. **Create Trust Boundaries**: Use `manage_trust_boundaries(action="add", section="boundaries", values=BOUNDARY)`

### Step 6: Validation and Refinement
Use the validation guidance and manual tools to refine the detection results as needed.

## Key Analysis Areas

### 1. Security Context
- Data classification and sensitivity
- Regulatory and compliance requirements
- Existing security controls and protections
- Business criticality and impact assessment

### 2. Network Topology
- Network segmentation and isolation
- Internet exposure and external access points
- Internal network boundaries and subnets
- Cloud provider network constructs (VPCs, security groups)

### 3. Service Architecture
- Microservice boundaries and dependencies
- Application tiers and layers
- Service communication patterns
- API boundaries and interfaces

### 4. Trust Relationships
- Authentication and authorization patterns
- Service-to-service trust relationships
- User access patterns and requirements
- External integration points

## Expected Deliverables

1. **Trust Zone Map**: Complete mapping of components to trust zones
2. **Crossing Point Inventory**: All boundary crossings with security analysis
3. **Trust Boundary Catalog**: Classified boundaries with security controls
4. **Risk Assessment**: Prioritized security risks and mitigation strategies
5. **Implementation Plan**: Step-by-step plan for implementing security controls

## Tools and Resources

- **Architecture Tool**: manage_architecture
- **Trust Boundary Tool**: manage_trust_boundaries
- **AWS Documentation**: AWS Documentation MCP Server for validation
- **Security Frameworks**: NIST Cybersecurity Framework, OWASP, industry standards

This plan ensures a thorough, AI-powered analysis of your architecture to detect meaningful trust boundaries with proper validation and implementation guidance.
"""
    
    return result
