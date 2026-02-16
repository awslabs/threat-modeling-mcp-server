"""Asset Flow Analysis functionality for the Cline Threat Modeling MCP Server."""

from typing import Dict, List, Optional, Any
from loguru import logger
from mcp.server.fastmcp import Context

from threat_modeling_mcp_server.models.asset_flow_models import (
    Asset, AssetFlow, AssetType, AssetClassification, 
    LifecycleState, TransformationType, ControlType, AssetFlowLibrary
)
from threat_modeling_mcp_server.models.architecture_models import Component, Connection


# Global dictionaries to store assets and flows
assets: Dict[str, Asset] = {}
flows: Dict[str, AssetFlow] = {}

# Initialize with default assets and flows
assets.update(AssetFlowLibrary.get_default_assets())
flows.update(AssetFlowLibrary.get_default_flows())


async def add_asset_impl(
    ctx: Context,
    name: str,
    type: str,
    classification: str,
    lifecycle_state: Optional[str] = None,
    description: Optional[str] = None,
    owner: Optional[str] = None,
    sensitivity: Optional[int] = None,
    criticality: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> str:
    """Add a new asset to the system.
    
    Args:
        ctx: MCP context for logging and error handling
        name: Name of the asset
        type: Type of the asset (e.g., 'Data', 'Credential', 'Process')
        classification: Classification of the asset (e.g., 'Public', 'Confidential')
        lifecycle_state: Current lifecycle state of the asset
        description: Description of the asset
        owner: Owner of the asset
        sensitivity: Sensitivity level of the asset (1-5)
        criticality: Criticality level of the asset (1-5)
        metadata: Additional metadata for the asset
        
    Returns:
        A confirmation message with the asset ID
    """
    logger.debug(f'Adding asset: {name}')
    
    # Generate a new asset ID
    asset_id = f"A{len(assets) + 1:03d}"
    
    # Create the asset
    asset = Asset(
        id=asset_id,
        name=name,
        type=AssetType(type),
        classification=AssetClassification(classification),
        lifecycle_state=LifecycleState(lifecycle_state) if lifecycle_state else None,
        description=description,
        owner=owner,
        sensitivity=sensitivity,
        criticality=criticality,
        metadata=metadata or {}
    )
    
    # Add the asset to the dictionary
    assets[asset_id] = asset
    
    return f"Asset added with ID: {asset_id}"


async def update_asset_impl(
    ctx: Context,
    id: str,
    name: Optional[str] = None,
    type: Optional[str] = None,
    classification: Optional[str] = None,
    lifecycle_state: Optional[str] = None,
    description: Optional[str] = None,
    owner: Optional[str] = None,
    sensitivity: Optional[int] = None,
    criticality: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> str:
    """Update an existing asset.
    
    Args:
        ctx: MCP context for logging and error handling
        id: ID of the asset to update
        name: New name of the asset
        type: New type of the asset
        classification: New classification of the asset
        lifecycle_state: New lifecycle state of the asset
        description: New description of the asset
        owner: New owner of the asset
        sensitivity: New sensitivity level of the asset
        criticality: New criticality level of the asset
        metadata: New metadata for the asset
        
    Returns:
        A confirmation message
    """
    logger.debug(f'Updating asset: {id}')
    
    # Check if the asset exists
    if id not in assets:
        return f"Asset with ID {id} not found"
    
    # Get the existing asset
    asset = assets[id]
    
    # Update the asset fields
    if name is not None:
        asset.name = name
    if type is not None:
        asset.type = AssetType(type)
    if classification is not None:
        asset.classification = AssetClassification(classification)
    if lifecycle_state is not None:
        asset.lifecycle_state = LifecycleState(lifecycle_state)
    if description is not None:
        asset.description = description
    if owner is not None:
        asset.owner = owner
    if sensitivity is not None:
        asset.sensitivity = sensitivity
    if criticality is not None:
        asset.criticality = criticality
    if metadata is not None:
        asset.metadata = metadata
    
    # Update the asset in the dictionary
    assets[id] = asset
    
    return f"Asset {id} updated successfully"


async def list_assets_impl(
    ctx: Context,
    type: Optional[str] = None,
    classification: Optional[str] = None,
) -> str:
    """List all assets in the system.
    
    Args:
        ctx: MCP context for logging and error handling
        type: Optional type to filter assets
        classification: Optional classification to filter assets
        
    Returns:
        A markdown-formatted list of assets
    """
    logger.debug('Listing assets')
    
    # Filter assets by type and classification if provided
    filtered_assets = assets.values()
    if type:
        filtered_assets = [a for a in filtered_assets if a.type == AssetType(type)]
    if classification:
        filtered_assets = [a for a in filtered_assets if a.classification == AssetClassification(classification)]
    
    # Sort assets by ID
    sorted_assets = sorted(filtered_assets, key=lambda a: a.id)
    
    # Generate the markdown output
    result = "# Assets\n\n"
    
    if not sorted_assets:
        result += "No assets found.\n"
        return result
    
    for asset in sorted_assets:
        result += f"## {asset.id}: {asset.name}\n\n"
        result += f"**Type:** {asset.type.value}\n\n"
        result += f"**Classification:** {asset.classification.value}\n\n"
        
        if asset.lifecycle_state:
            result += f"**Lifecycle State:** {asset.lifecycle_state.value}\n\n"
        
        if asset.description:
            result += f"**Description:** {asset.description}\n\n"
        
        if asset.owner:
            result += f"**Owner:** {asset.owner}\n\n"
        
        if asset.sensitivity is not None:
            result += f"**Sensitivity:** {asset.sensitivity}/5\n\n"
        
        if asset.criticality is not None:
            result += f"**Criticality:** {asset.criticality}/5\n\n"
        
        if asset.metadata:
            result += "**Metadata:**\n\n"
            for key, value in asset.metadata.items():
                result += f"- {key}: {value}\n"
            result += "\n"
        
        result += "---\n\n"
    
    return result


async def get_asset_impl(
    ctx: Context,
    id: str,
) -> str:
    """Get details about a specific asset.
    
    Args:
        ctx: MCP context for logging and error handling
        id: ID of the asset to retrieve
        
    Returns:
        A markdown-formatted description of the asset
    """
    logger.debug(f'Getting asset: {id}')
    
    # Check if the asset exists
    if id not in assets:
        return f"Asset with ID {id} not found"
    
    # Get the asset
    asset = assets[id]
    
    # Generate the markdown output
    result = f"# Asset {asset.id}: {asset.name}\n\n"
    result += f"**Type:** {asset.type.value}\n\n"
    result += f"**Classification:** {asset.classification.value}\n\n"
    
    if asset.lifecycle_state:
        result += f"**Lifecycle State:** {asset.lifecycle_state.value}\n\n"
    
    if asset.description:
        result += f"**Description:** {asset.description}\n\n"
    
    if asset.owner:
        result += f"**Owner:** {asset.owner}\n\n"
    
    if asset.sensitivity is not None:
        result += f"**Sensitivity:** {asset.sensitivity}/5\n\n"
    
    if asset.criticality is not None:
        result += f"**Criticality:** {asset.criticality}/5\n\n"
    
    if asset.metadata:
        result += "**Metadata:**\n\n"
        for key, value in asset.metadata.items():
            result += f"- {key}: {value}\n"
        result += "\n"
    
    # List flows involving this asset
    asset_flows = [f for f in flows.values() if f.asset_id == id]
    if asset_flows:
        result += "## Asset Flows\n\n"
        for flow in asset_flows:
            result += f"- **{flow.id}**: {flow.description or 'No description'} (From {flow.source_id} to {flow.destination_id})\n"
    
    return result


async def delete_asset_impl(
    ctx: Context,
    id: str,
) -> str:
    """Delete an asset from the system.
    
    Args:
        ctx: MCP context for logging and error handling
        id: ID of the asset to delete
        
    Returns:
        A confirmation message
    """
    logger.debug(f'Deleting asset: {id}')
    
    # Check if the asset exists
    if id not in assets:
        return f"Asset with ID {id} not found"
    
    # Check if the asset is used in any flows
    asset_flows = [f for f in flows.values() if f.asset_id == id]
    if asset_flows:
        flow_ids = [f.id for f in asset_flows]
        return f"Cannot delete asset {id} because it is used in flows: {', '.join(flow_ids)}"
    
    # Delete the asset
    del assets[id]
    
    return f"Asset {id} deleted successfully"


async def add_flow_impl(
    ctx: Context,
    asset_id: str,
    source_id: str,
    destination_id: str,
    transformation_type: Optional[str] = None,
    controls: Optional[List[str]] = None,
    description: Optional[str] = None,
    protocol: Optional[str] = None,
    encryption: bool = False,
    authenticated: bool = False,
    authorized: bool = False,
    validated: bool = False,
    risk_level: Optional[int] = None,
) -> str:
    """Add a new asset flow to the system.
    
    Args:
        ctx: MCP context for logging and error handling
        asset_id: ID of the asset being transferred
        source_id: ID of the source component or trust zone
        destination_id: ID of the destination component or trust zone
        transformation_type: Type of transformation applied to the asset
        controls: List of security controls applied to the flow
        description: Description of the flow
        protocol: Protocol used for the flow
        encryption: Whether the flow is encrypted
        authenticated: Whether the flow is authenticated
        authorized: Whether the flow is authorized
        validated: Whether the flow is validated
        risk_level: Risk level of the flow (1-5)
        
    Returns:
        A confirmation message with the flow ID
    """
    logger.debug(f'Adding flow for asset: {asset_id}')
    
    # Check if the asset exists
    if asset_id not in assets:
        return f"Asset with ID {asset_id} not found"
    
    # Generate a new flow ID
    flow_id = f"F{len(flows) + 1:03d}"
    
    # Convert controls to ControlType enum values
    control_enums = []
    if controls:
        for control in controls:
            try:
                control_enums.append(ControlType(control))
            except ValueError:
                return f"Invalid control type: {control}"
    
    # Create the flow
    flow = AssetFlow(
        id=flow_id,
        asset_id=asset_id,
        source_id=source_id,
        destination_id=destination_id,
        transformation_type=TransformationType(transformation_type) if transformation_type else None,
        controls=control_enums,
        description=description,
        protocol=protocol,
        encryption=encryption,
        authenticated=authenticated,
        authorized=authorized,
        validated=validated,
        risk_level=risk_level
    )
    
    # Add the flow to the dictionary
    flows[flow_id] = flow
    
    return f"Flow added with ID: {flow_id}"


async def update_flow_impl(
    ctx: Context,
    id: str,
    asset_id: Optional[str] = None,
    source_id: Optional[str] = None,
    destination_id: Optional[str] = None,
    transformation_type: Optional[str] = None,
    controls: Optional[List[str]] = None,
    description: Optional[str] = None,
    protocol: Optional[str] = None,
    encryption: Optional[bool] = None,
    authenticated: Optional[bool] = None,
    authorized: Optional[bool] = None,
    validated: Optional[bool] = None,
    risk_level: Optional[int] = None,
) -> str:
    """Update an existing asset flow.
    
    Args:
        ctx: MCP context for logging and error handling
        id: ID of the flow to update
        asset_id: New ID of the asset being transferred
        source_id: New ID of the source component or trust zone
        destination_id: New ID of the destination component or trust zone
        transformation_type: New type of transformation applied to the asset
        controls: New list of security controls applied to the flow
        description: New description of the flow
        protocol: New protocol used for the flow
        encryption: New encryption status
        authenticated: New authentication status
        authorized: New authorization status
        validated: New validation status
        risk_level: New risk level of the flow (1-5)
        
    Returns:
        A confirmation message
    """
    logger.debug(f'Updating flow: {id}')
    
    # Check if the flow exists
    if id not in flows:
        return f"Flow with ID {id} not found"
    
    # Get the existing flow
    flow = flows[id]
    
    # Update the flow fields
    if asset_id is not None:
        if asset_id not in assets:
            return f"Asset with ID {asset_id} not found"
        flow.asset_id = asset_id
    
    if source_id is not None:
        flow.source_id = source_id
    
    if destination_id is not None:
        flow.destination_id = destination_id
    
    if transformation_type is not None:
        flow.transformation_type = TransformationType(transformation_type)
    
    if controls is not None:
        # Convert controls to ControlType enum values
        control_enums = []
        for control in controls:
            try:
                control_enums.append(ControlType(control))
            except ValueError:
                return f"Invalid control type: {control}"
        flow.controls = control_enums
    
    if description is not None:
        flow.description = description
    
    if protocol is not None:
        flow.protocol = protocol
    
    if encryption is not None:
        flow.encryption = encryption
    
    if authenticated is not None:
        flow.authenticated = authenticated
    
    if authorized is not None:
        flow.authorized = authorized
    
    if validated is not None:
        flow.validated = validated
    
    if risk_level is not None:
        flow.risk_level = risk_level
    
    # Update the flow in the dictionary
    flows[id] = flow
    
    return f"Flow {id} updated successfully"


async def list_flows_impl(
    ctx: Context,
    asset_id: Optional[str] = None,
    component_id: Optional[str] = None,
) -> str:
    """List all asset flows in the system.
    
    Args:
        ctx: MCP context for logging and error handling
        asset_id: Optional asset ID to filter flows
        component_id: Optional component ID to filter flows
        
    Returns:
        A markdown-formatted list of flows
    """
    logger.debug('Listing flows')
    
    # Filter flows by asset ID and component ID if provided
    filtered_flows = flows.values()
    if asset_id:
        filtered_flows = [f for f in filtered_flows if f.asset_id == asset_id]
    if component_id:
        filtered_flows = [f for f in filtered_flows if f.source_id == component_id or f.destination_id == component_id]
    
    # Sort flows by ID
    sorted_flows = sorted(filtered_flows, key=lambda f: f.id)
    
    # Generate the markdown output
    result = "# Asset Flows\n\n"
    
    if not sorted_flows:
        result += "No flows found.\n"
        return result
    
    for flow in sorted_flows:
        # Get the asset name
        asset_name = assets[flow.asset_id].name if flow.asset_id in assets else "Unknown Asset"
        
        result += f"## {flow.id}: {asset_name}\n\n"
        result += f"**Source:** {flow.source_id}\n\n"
        result += f"**Destination:** {flow.destination_id}\n\n"
        
        if flow.transformation_type:
            result += f"**Transformation:** {flow.transformation_type.value}\n\n"
        
        if flow.controls:
            result += "**Controls:**\n\n"
            for control in flow.controls:
                result += f"- {control.value}\n"
            result += "\n"
        
        if flow.description:
            result += f"**Description:** {flow.description}\n\n"
        
        if flow.protocol:
            result += f"**Protocol:** {flow.protocol}\n\n"
        
        result += f"**Encryption:** {'Yes' if flow.encryption else 'No'}\n\n"
        result += f"**Authentication:** {'Yes' if flow.authenticated else 'No'}\n\n"
        result += f"**Authorization:** {'Yes' if flow.authorized else 'No'}\n\n"
        result += f"**Validation:** {'Yes' if flow.validated else 'No'}\n\n"
        
        if flow.risk_level is not None:
            result += f"**Risk Level:** {flow.risk_level}/5\n\n"
        
        result += "---\n\n"
    
    return result


async def get_flow_impl(
    ctx: Context,
    id: str,
) -> str:
    """Get details about a specific asset flow.
    
    Args:
        ctx: MCP context for logging and error handling
        id: ID of the flow to retrieve
        
    Returns:
        A markdown-formatted description of the flow
    """
    logger.debug(f'Getting flow: {id}')
    
    # Check if the flow exists
    if id not in flows:
        return f"Flow with ID {id} not found"
    
    # Get the flow
    flow = flows[id]
    
    # Get the asset name
    asset_name = assets[flow.asset_id].name if flow.asset_id in assets else "Unknown Asset"
    
    # Generate the markdown output
    result = f"# Flow {flow.id}: {asset_name}\n\n"
    result += f"**Asset ID:** {flow.asset_id}\n\n"
    result += f"**Source:** {flow.source_id}\n\n"
    result += f"**Destination:** {flow.destination_id}\n\n"
    
    if flow.transformation_type:
        result += f"**Transformation:** {flow.transformation_type.value}\n\n"
    
    if flow.controls:
        result += "**Controls:**\n\n"
        for control in flow.controls:
            result += f"- {control.value}\n"
        result += "\n"
    
    if flow.description:
        result += f"**Description:** {flow.description}\n\n"
    
    if flow.protocol:
        result += f"**Protocol:** {flow.protocol}\n\n"
    
    result += f"**Encryption:** {'Yes' if flow.encryption else 'No'}\n\n"
    result += f"**Authentication:** {'Yes' if flow.authenticated else 'No'}\n\n"
    result += f"**Authorization:** {'Yes' if flow.authorized else 'No'}\n\n"
    result += f"**Validation:** {'Yes' if flow.validated else 'No'}\n\n"
    
    if flow.risk_level is not None:
        result += f"**Risk Level:** {flow.risk_level}/5\n\n"
    
    return result


async def delete_flow_impl(
    ctx: Context,
    id: str,
) -> str:
    """Delete an asset flow from the system.
    
    Args:
        ctx: MCP context for logging and error handling
        id: ID of the flow to delete
        
    Returns:
        A confirmation message
    """
    logger.debug(f'Deleting flow: {id}')
    
    # Check if the flow exists
    if id not in flows:
        return f"Flow with ID {id} not found"
    
    # Delete the flow
    del flows[id]
    
    return f"Flow {id} deleted successfully"


async def get_asset_flow_analysis_plan_impl(
    ctx: Context,
) -> str:
    """Get a comprehensive asset flow analysis plan.
    
    Args:
        ctx: MCP context for logging and error handling
        
    Returns:
        A markdown-formatted asset flow analysis plan with prompts for LLM analysis
    """
    logger.debug('Getting asset flow analysis plan')
    
    result = "# Asset Flow Analysis Plan\n\n"
    
    result += """## Overview
This plan provides a structured approach for analyzing asset flows for security concerns using AI-powered analysis with AWS documentation validation.

## Analysis Process

### Step 1: Gather Asset Flow Data
First, collect all asset flow information using the following tools:

1. **Get Assets**: Use `list_assets()` to retrieve all system assets
2. **Get Flows**: Use `list_flows()` to retrieve all asset flows
3. **Get Asset Details**: Use `get_asset(id)` for detailed information about specific assets
4. **Get Flow Details**: Use `get_flow(id)` for detailed information about specific flows

### Step 2: LLM Analysis Prompt
Use the following prompt structure with an LLM to analyze the asset flows:

```
You are a cybersecurity expert analyzing asset flows for security concerns and data protection risks.

ASSET FLOW DATA:
[Insert the output from list_assets() and list_flows() here]

ANALYSIS INSTRUCTIONS:
1. **Asset Security Analysis**:
   - Identify assets with high sensitivity or criticality levels
   - Check for assets without proper classification
   - Analyze asset lifecycle states for security implications
   - Look for assets with insufficient metadata or ownership information

2. **Flow Security Analysis**:
   - Identify unencrypted flows carrying sensitive or confidential data
   - Check for unauthenticated flows accessing critical assets
   - Analyze unauthorized flows that bypass access controls
   - Look for unvalidated flows that could introduce security risks

3. **Data Protection Analysis**:
   - Check encryption requirements based on data classification
   - Analyze authentication and authorization controls
   - Identify missing input validation for data flows
   - Look for inadequate access controls on sensitive assets

4. **Risk Assessment**:
   - Evaluate risk levels assigned to flows
   - Identify high-risk flows requiring immediate attention
   - Analyze the combination of asset sensitivity and flow security
   - Look for flows that cross trust boundaries without proper controls

5. **Compliance Analysis**:
   - Check compliance with data protection regulations (GDPR, CCPA, etc.)
   - Analyze retention and lifecycle management
   - Identify flows that may violate regulatory requirements
   - Look for missing audit trails and monitoring

6. **AWS-Specific Analysis** (if AWS components are involved):
   - Validate AWS service configurations for data protection
   - Check IAM policies and access controls
   - Analyze encryption in transit and at rest
   - Identify missing AWS security services (KMS, CloudTrail, etc.)

MANDATORY AWS DOCUMENTATION REQUIREMENT:
For ANY AWS-specific security concerns identified, you MUST use the AWS Documentation MCP server:
- MANDATORY: Use `search_documentation` tool for current security best practices
- MANDATORY: Use `read_documentation` tool for specific service security documentation  
- MANDATORY: Validate ALL recommendations against official AWS guidance
- MANDATORY: Include AWS documentation URLs and citations in your analysis
- FAILURE TO USE AWS DOCUMENTATION WILL RESULT IN INCOMPLETE ANALYSIS

OUTPUT FORMAT:
Provide your analysis in the following markdown format:

# Asset Flow Security Analysis

## Executive Summary
[Brief overview of asset flow security posture and critical findings]

## Asset Analysis
[Detailed analysis of asset security issues, classifications, and ownership]

## Flow Analysis
[Detailed analysis of flow security controls, encryption, and authentication]

## Data Protection Assessment
[Analysis of data protection measures and compliance requirements]

## Risk Assessment
[Prioritized list of security risks with severity levels and impact analysis]

## AWS-Specific Findings
[AWS service-specific security concerns with documentation references]

## Recommendations
[Actionable security recommendations with implementation guidance]

## Compliance Considerations
[Relevant compliance requirements and regulatory implications]
```

### Step 3: AWS Documentation Validation
For any AWS-related findings, validate them using:

1. **Search AWS Documentation**: 
   ```
   use_mcp_tool(
     server_name: "github.com/awslabs/mcp/tree/main/src/aws-documentation-mcp-server",
     tool_name: "search_documentation", 
     arguments: {"search_phrase": "[security concern or service name]"}
   )
   ```

2. **Read Specific Documentation**:
   ```
   use_mcp_tool(
     server_name: "github.com/awslabs/mcp/tree/main/src/aws-documentation-mcp-server",
     tool_name: "read_documentation",
     arguments: {"url": "[AWS documentation URL]"}
   )
   ```

### Step 4: Generate Final Report
Combine the LLM analysis with AWS documentation validation to produce a comprehensive asset flow security assessment.

## Key Security Areas to Focus On

### 1. Data Classification and Handling
- Proper asset classification (Public, Internal, Confidential, Restricted)
- Data sensitivity and criticality levels
- Lifecycle state management
- Ownership and accountability

### 2. Encryption and Data Protection
- Encryption in transit for sensitive data flows
- Encryption at rest for stored assets
- Key management and certificate handling
- Protocol security (HTTPS vs HTTP, etc.)

### 3. Access Control and Authentication
- Authentication requirements for asset access
- Authorization controls for sensitive operations
- Multi-factor authentication for critical assets
- Service-to-service authentication

### 4. Flow Security Controls
- Input validation for data flows
- Output encoding and sanitization
- Transformation security during data processing
- Control effectiveness and coverage

### 5. Risk Management
- Risk level assessment and scoring
- High-risk flow identification
- Risk mitigation strategies
- Continuous risk monitoring

### 6. Compliance and Governance
- Regulatory compliance requirements
- Data retention and disposal policies
- Audit trails and logging
- Privacy protection measures

## Analysis Techniques

### 1. Data Flow Mapping
- Trace sensitive data through the system
- Identify data transformation points
- Map trust boundaries and crossing points
- Analyze data aggregation and correlation risks

### 2. Control Gap Analysis
- Compare existing controls with requirements
- Identify missing or inadequate controls
- Analyze control effectiveness
- Prioritize control improvements

### 3. Risk Scoring
- Combine asset sensitivity with flow security
- Calculate composite risk scores
- Identify risk hotspots
- Prioritize remediation efforts

### 4. Compliance Mapping
- Map flows to regulatory requirements
- Identify compliance gaps
- Analyze cross-border data transfers
- Check consent and lawful basis requirements

## Expected Deliverables

1. **Asset Flow Security Assessment**: Comprehensive analysis of all asset flows
2. **Risk Register**: Prioritized list of identified security risks
3. **Control Recommendations**: Specific security controls to implement
4. **Compliance Report**: Assessment against relevant regulations
5. **Remediation Roadmap**: Step-by-step plan for addressing security gaps

## Tools and Resources

- **Asset Flow Tools**: list_assets, list_flows, get_asset, get_flow
- **AWS Documentation**: AWS Documentation MCP Server for validation
- **Security Frameworks**: NIST Privacy Framework, ISO 27001, OWASP
- **Compliance Standards**: GDPR, CCPA, SOX, PCI DSS (as applicable)

This plan ensures a thorough, AI-powered analysis of your asset flows with proper validation against authoritative sources and regulatory requirements.
"""
    
    return result


async def clear_asset_flows_impl(
    ctx: Context,
) -> str:
    """Clear all assets and flows from the system.
    
    Args:
        ctx: MCP context for logging and error handling
        
    Returns:
        A confirmation message
    """
    logger.debug('Clearing asset flows')
    
    # Clear the dictionaries
    assets.clear()
    flows.clear()
    
    return "All assets and flows have been cleared."


async def reset_asset_flows_impl(
    ctx: Context,
) -> str:
    """Reset assets and flows to the default set.
    
    Args:
        ctx: MCP context for logging and error handling
        
    Returns:
        A confirmation message
    """
    logger.debug('Resetting asset flows')
    
    # Clear the dictionaries
    assets.clear()
    flows.clear()
    
    # Initialize with default assets and flows
    assets.update(AssetFlowLibrary.get_default_assets())
    flows.update(AssetFlowLibrary.get_default_flows())
    
    return "Assets and flows have been reset to the default set."


# Register tools with the MCP server
def register_tools(mcp):
    """Register asset flow analysis tools with the MCP server.
    
    Args:
        mcp: The MCP server instance
    """
    @mcp.tool()
    async def add_asset(
        ctx: Context,
        name: str,
        type: str,
        classification: str,
        lifecycle_state: Optional[str] = None,
        description: Optional[str] = None,
        owner: Optional[str] = None,
        sensitivity: Optional[int] = None,
        criticality: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Add a new asset to the system.

        This tool adds a new asset to the system with the specified properties.

        Args:
            ctx: MCP context for logging and error handling
            name: Name of the asset
            type: Type of the asset (e.g., 'Data', 'Credential', 'Process')
            classification: Classification of the asset (e.g., 'Public', 'Confidential')
            lifecycle_state: Current lifecycle state of the asset
            description: Description of the asset
            owner: Owner of the asset
            sensitivity: Sensitivity level of the asset (1-5)
            criticality: Criticality level of the asset (1-5)
            metadata: Additional metadata for the asset

        Returns:
            A confirmation message with the asset ID
        """
        return await add_asset_impl(
            ctx, name, type, classification, lifecycle_state, description,
            owner, sensitivity, criticality, metadata
        )
    
    @mcp.tool()
    async def update_asset(
        ctx: Context,
        id: str,
        name: Optional[str] = None,
        type: Optional[str] = None,
        classification: Optional[str] = None,
        lifecycle_state: Optional[str] = None,
        description: Optional[str] = None,
        owner: Optional[str] = None,
        sensitivity: Optional[int] = None,
        criticality: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Update an existing asset.

        This tool updates an existing asset in the system with the specified properties.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the asset to update
            name: New name of the asset
            type: New type of the asset
            classification: New classification of the asset
            lifecycle_state: New lifecycle state of the asset
            description: New description of the asset
            owner: New owner of the asset
            sensitivity: New sensitivity level of the asset
            criticality: New criticality level of the asset
            metadata: New metadata for the asset

        Returns:
            A confirmation message
        """
        return await update_asset_impl(
            ctx, id, name, type, classification, lifecycle_state,
            description, owner, sensitivity, criticality, metadata
        )
    
    @mcp.tool()
    async def list_assets(
        ctx: Context,
        type: Optional[str] = None,
        classification: Optional[str] = None,
    ) -> str:
        """List all assets in the system.

        This tool lists all assets in the system, optionally filtered by type or classification.

        Args:
            ctx: MCP context for logging and error handling
            type: Optional type to filter assets
            classification: Optional classification to filter assets

        Returns:
            A markdown-formatted list of assets
        """
        return await list_assets_impl(ctx, type, classification)
    
    @mcp.tool()
    async def get_asset(
        ctx: Context,
        id: str,
    ) -> str:
        """Get details about a specific asset.

        This tool retrieves details about a specific asset in the system.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the asset to retrieve

        Returns:
            A markdown-formatted description of the asset
        """
        return await get_asset_impl(ctx, id)
    
    @mcp.tool()
    async def delete_asset(
        ctx: Context,
        id: str,
    ) -> str:
        """Delete an asset from the system.

        This tool deletes an asset from the system. The asset cannot be deleted if it is used in any flows.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the asset to delete

        Returns:
            A confirmation message
        """
        return await delete_asset_impl(ctx, id)
    
    @mcp.tool()
    async def add_flow(
        ctx: Context,
        asset_id: str,
        source_id: str,
        destination_id: str,
        transformation_type: Optional[str] = None,
        controls: Optional[List[str]] = None,
        description: Optional[str] = None,
        protocol: Optional[str] = None,
        encryption: bool = False,
        authenticated: bool = False,
        authorized: bool = False,
        validated: bool = False,
        risk_level: Optional[int] = None,
    ) -> str:
        """Add a new asset flow to the system.

        This tool adds a new asset flow to the system with the specified properties.

        Args:
            ctx: MCP context for logging and error handling
            asset_id: ID of the asset being transferred
            source_id: ID of the source component or trust zone
            destination_id: ID of the destination component or trust zone
            transformation_type: Type of transformation applied to the asset
            controls: List of security controls applied to the flow
            description: Description of the flow
            protocol: Protocol used for the flow
            encryption: Whether the flow is encrypted
            authenticated: Whether the flow is authenticated
            authorized: Whether the flow is authorized
            validated: Whether the flow is validated
            risk_level: Risk level of the flow (1-5)

        Returns:
            A confirmation message with the flow ID
        """
        return await add_flow_impl(
            ctx, asset_id, source_id, destination_id, transformation_type,
            controls, description, protocol, encryption, authenticated,
            authorized, validated, risk_level
        )
    
    @mcp.tool()
    async def update_flow(
        ctx: Context,
        id: str,
        asset_id: Optional[str] = None,
        source_id: Optional[str] = None,
        destination_id: Optional[str] = None,
        transformation_type: Optional[str] = None,
        controls: Optional[List[str]] = None,
        description: Optional[str] = None,
        protocol: Optional[str] = None,
        encryption: Optional[bool] = None,
        authenticated: Optional[bool] = None,
        authorized: Optional[bool] = None,
        validated: Optional[bool] = None,
        risk_level: Optional[int] = None,
    ) -> str:
        """Update an existing asset flow.

        This tool updates an existing asset flow in the system with the specified properties.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the flow to update
            asset_id: New ID of the asset being transferred
            source_id: New ID of the source component or trust zone
            destination_id: New ID of the destination component or trust zone
            transformation_type: New type of transformation applied to the asset
            controls: New list of security controls applied to the flow
            description: New description of the flow
            protocol: New protocol used for the flow
            encryption: New encryption status
            authenticated: New authentication status
            authorized: New authorization status
            validated: New validation status
            risk_level: New risk level of the flow (1-5)

        Returns:
            A confirmation message
        """
        return await update_flow_impl(
            ctx, id, asset_id, source_id, destination_id, transformation_type,
            controls, description, protocol, encryption, authenticated,
            authorized, validated, risk_level
        )
    
    @mcp.tool()
    async def list_flows(
        ctx: Context,
        asset_id: Optional[str] = None,
        component_id: Optional[str] = None,
    ) -> str:
        """List all asset flows in the system.

        This tool lists all asset flows in the system, optionally filtered by asset ID or component ID.

        Args:
            ctx: MCP context for logging and error handling
            asset_id: Optional asset ID to filter flows
            component_id: Optional component ID to filter flows

        Returns:
            A markdown-formatted list of flows
        """
        return await list_flows_impl(ctx, asset_id, component_id)
    
    @mcp.tool()
    async def get_flow(
        ctx: Context,
        id: str,
    ) -> str:
        """Get details about a specific asset flow.

        This tool retrieves details about a specific asset flow in the system.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the flow to retrieve

        Returns:
            A markdown-formatted description of the flow
        """
        return await get_flow_impl(ctx, id)
    
    @mcp.tool()
    async def delete_flow(
        ctx: Context,
        id: str,
    ) -> str:
        """Delete an asset flow from the system.

        This tool deletes an asset flow from the system.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the flow to delete

        Returns:
            A confirmation message
        """
        return await delete_flow_impl(ctx, id)
    
    @mcp.tool()
    async def get_asset_flow_analysis_plan(
        ctx: Context,
    ) -> str:
        """Get a comprehensive asset flow analysis plan.

        This tool returns a detailed plan for analyzing asset flows for security concerns
        using AI-powered analysis with AWS documentation validation.

        Args:
            ctx: MCP context for logging and error handling

        Returns:
            A markdown-formatted asset flow analysis plan with prompts for LLM analysis
        """
        return await get_asset_flow_analysis_plan_impl(ctx)
    
    @mcp.tool()
    async def clear_asset_flows(
        ctx: Context,
    ) -> str:
        """Clear all assets and flows from the system.

        This tool clears all assets and flows from the system.

        Args:
            ctx: MCP context for logging and error handling

        Returns:
            A confirmation message
        """
        return await clear_asset_flows_impl(ctx)
    
    @mcp.tool()
    async def reset_asset_flows(
        ctx: Context,
    ) -> str:
        """Reset assets and flows to the default set.

        This tool resets assets and flows to the default set.

        Args:
            ctx: MCP context for logging and error handling

        Returns:
            A confirmation message
        """
        return await reset_asset_flows_impl(ctx)
