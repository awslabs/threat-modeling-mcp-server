"""Architecture Analysis functionality for the Cline Threat Modeling MCP Server."""

from typing import Dict, List, Optional, Any
from loguru import logger
from mcp.server.fastmcp import Context
from pydantic import Field
import uuid

from threat_modeling_mcp_server.models.architecture_models import (
    Component, Connection, DataStore, Architecture,
    ComponentType, ServiceProvider, Protocol, DataStoreType,
    DataClassification, BackupFrequency, AWSService
)


# Global state
architecture = Architecture()
components: Dict[str, Component] = {}
connections: Dict[str, Connection] = {}
data_stores: Dict[str, DataStore] = {}


async def add_component_impl(
    ctx: Context,
    name: str,
    type: str,
    service_provider: Optional[str] = None,
    specific_service: Optional[str] = None,
    version: Optional[str] = None,
    description: Optional[str] = None,
    configuration: Optional[Dict[str, Any]] = None,
) -> str:
    """Add a new component to the architecture.
    
    Args:
        ctx: MCP context for logging and error handling
        name: Name of the component
        type: Type of the component (e.g., 'Compute', 'Storage', 'Network')
        service_provider: Provider of the service (e.g., 'AWS', 'Azure', 'GCP')
        specific_service: Specific service name (e.g., 'EC2', 'S3', 'Lambda')
        version: Version of the component
        description: Description of the component
        configuration: Configuration details of the component
        
    Returns:
        A confirmation message with the component ID
    """
    logger.debug(f'Adding component: {name}')
    
    # Generate a unique ID
    component_id = f"C{len(components) + 1:03d}"
    
    # Create the component
    component = Component(
        id=component_id,
        name=name,
        type=ComponentType(type),
        service_provider=ServiceProvider(service_provider) if service_provider else None,
        specific_service=specific_service,
        version=version,
        description=description,
        configuration=configuration
    )
    
    # Store the component
    components[component_id] = component
    
    # Update the architecture
    architecture.components = list(components.values())
    
    return f"Component added with ID: {component_id}"


async def update_component_impl(
    ctx: Context,
    id: str,
    name: Optional[str] = None,
    type: Optional[str] = None,
    service_provider: Optional[str] = None,
    specific_service: Optional[str] = None,
    version: Optional[str] = None,
    description: Optional[str] = None,
    configuration: Optional[Dict[str, Any]] = None,
) -> str:
    """Update an existing component in the architecture.
    
    Args:
        ctx: MCP context for logging and error handling
        id: ID of the component to update
        name: New name of the component
        type: New type of the component
        service_provider: New provider of the service
        specific_service: New specific service name
        version: New version of the component
        description: New description of the component
        configuration: New configuration details of the component
        
    Returns:
        A confirmation message
    """
    logger.debug(f'Updating component: {id}')
    
    if id not in components:
        return f"Component with ID {id} not found."
    
    component = components[id]
    
    # Update only the provided fields
    if name is not None:
        component.name = name
    if type is not None:
        component.type = ComponentType(type)
    if service_provider is not None:
        component.service_provider = ServiceProvider(service_provider)
    if specific_service is not None:
        component.specific_service = specific_service
    if version is not None:
        component.version = version
    if description is not None:
        component.description = description
    if configuration is not None:
        component.configuration = configuration
    
    # Store the updated component
    components[id] = component
    
    # Update the architecture
    architecture.components = list(components.values())
    
    return f"Component {id} updated successfully."


async def list_components_impl(
    ctx: Context,
    type: Optional[str] = None,
) -> str:
    """List all components in the architecture.
    
    Args:
        ctx: MCP context for logging and error handling
        type: Optional type to filter components
        
    Returns:
        A markdown-formatted list of components
    """
    logger.debug('Listing components')
    
    if not components:
        return "No components have been added yet."
    
    filtered_components = components.values()
    if type:
        filtered_components = [c for c in filtered_components if c.type == ComponentType(type)]
    
    if not filtered_components:
        return f"No components found with type: {type}"
    
    result = "# Architecture Components\n\n"
    
    for component in filtered_components:
        result += f"## {component.id}: {component.name}\n\n"
        result += f"**Type:** {component.type.value}\n\n"
        
        if component.service_provider:
            result += f"**Service Provider:** {component.service_provider.value}\n\n"
        
        if component.specific_service:
            result += f"**Specific Service:** {component.specific_service}\n\n"
        
        if component.version:
            result += f"**Version:** {component.version}\n\n"
        
        if component.description:
            result += f"**Description:** {component.description}\n\n"
        
        if component.configuration:
            result += "**Configuration:**\n\n```json\n"
            result += str(component.configuration)
            result += "\n```\n\n"
        
        result += "---\n\n"
    
    return result


async def delete_component_impl(
    ctx: Context,
    id: str,
) -> str:
    """Delete a component from the architecture.
    
    Args:
        ctx: MCP context for logging and error handling
        id: ID of the component to delete
        
    Returns:
        A confirmation message
    """
    logger.debug(f'Deleting component: {id}')
    
    if id not in components:
        return f"Component with ID {id} not found."
    
    # Check if the component is used in any connections
    for connection in connections.values():
        if connection.source_id == id or connection.destination_id == id:
            return f"Cannot delete component {id} because it is used in connection {connection.id}."
    
    # Delete the component
    del components[id]
    
    # Update the architecture
    architecture.components = list(components.values())
    
    return f"Component {id} deleted successfully."


async def add_connection_impl(
    ctx: Context,
    source_id: str,
    destination_id: str,
    protocol: Optional[str] = None,
    port: Optional[int] = None,
    encryption: bool = False,
    description: Optional[str] = None,
) -> str:
    """Add a new connection to the architecture.
    
    Args:
        ctx: MCP context for logging and error handling
        source_id: ID of the source component
        destination_id: ID of the destination component
        protocol: Protocol used for the connection
        port: Port used for the connection
        encryption: Whether the connection is encrypted
        description: Description of the connection
        
    Returns:
        A confirmation message with the connection ID
    """
    logger.debug(f'Adding connection from {source_id} to {destination_id}')
    
    # Check if the source and destination components exist
    if source_id not in components:
        return f"Source component with ID {source_id} not found."
    
    if destination_id not in components:
        return f"Destination component with ID {destination_id} not found."
    
    # Generate a unique ID
    connection_id = f"CN{len(connections) + 1:03d}"
    
    # Create the connection
    connection = Connection(
        id=connection_id,
        source_id=source_id,
        destination_id=destination_id,
        protocol=Protocol(protocol) if protocol else None,
        port=port,
        encryption=encryption,
        description=description
    )
    
    # Store the connection
    connections[connection_id] = connection
    
    # Update the architecture
    architecture.connections = list(connections.values())
    
    return f"Connection added with ID: {connection_id}"


async def update_connection_impl(
    ctx: Context,
    id: str,
    source_id: Optional[str] = None,
    destination_id: Optional[str] = None,
    protocol: Optional[str] = None,
    port: Optional[int] = None,
    encryption: Optional[bool] = None,
    description: Optional[str] = None,
) -> str:
    """Update an existing connection in the architecture.
    
    Args:
        ctx: MCP context for logging and error handling
        id: ID of the connection to update
        source_id: New ID of the source component
        destination_id: New ID of the destination component
        protocol: New protocol used for the connection
        port: New port used for the connection
        encryption: New encryption status
        description: New description of the connection
        
    Returns:
        A confirmation message
    """
    logger.debug(f'Updating connection: {id}')
    
    if id not in connections:
        return f"Connection with ID {id} not found."
    
    connection = connections[id]
    
    # Update only the provided fields
    if source_id is not None:
        if source_id not in components:
            return f"Source component with ID {source_id} not found."
        connection.source_id = source_id
    
    if destination_id is not None:
        if destination_id not in components:
            return f"Destination component with ID {destination_id} not found."
        connection.destination_id = destination_id
    
    if protocol is not None:
        connection.protocol = Protocol(protocol)
    
    if port is not None:
        connection.port = port
    
    if encryption is not None:
        connection.encryption = encryption
    
    if description is not None:
        connection.description = description
    
    # Store the updated connection
    connections[id] = connection
    
    # Update the architecture
    architecture.connections = list(connections.values())
    
    return f"Connection {id} updated successfully."


async def list_connections_impl(
    ctx: Context,
    component_id: Optional[str] = None,
) -> str:
    """List all connections in the architecture.
    
    Args:
        ctx: MCP context for logging and error handling
        component_id: Optional component ID to filter connections
        
    Returns:
        A markdown-formatted list of connections
    """
    logger.debug('Listing connections')
    
    if not connections:
        return "No connections have been added yet."
    
    filtered_connections = connections.values()
    if component_id:
        filtered_connections = [c for c in filtered_connections if c.source_id == component_id or c.destination_id == component_id]
    
    if not filtered_connections:
        return f"No connections found for component: {component_id}"
    
    result = "# Architecture Connections\n\n"
    
    for connection in filtered_connections:
        source = components.get(connection.source_id, None)
        destination = components.get(connection.destination_id, None)
        
        source_name = source.name if source else f"Unknown ({connection.source_id})"
        destination_name = destination.name if destination else f"Unknown ({connection.destination_id})"
        
        result += f"## {connection.id}: {source_name} → {destination_name}\n\n"
        
        if connection.protocol:
            result += f"**Protocol:** {connection.protocol.value}\n\n"
        
        if connection.port:
            result += f"**Port:** {connection.port}\n\n"
        
        result += f"**Encryption:** {'Yes' if connection.encryption else 'No'}\n\n"
        
        if connection.description:
            result += f"**Description:** {connection.description}\n\n"
        
        result += "---\n\n"
    
    return result


async def delete_connection_impl(
    ctx: Context,
    id: str,
) -> str:
    """Delete a connection from the architecture.
    
    Args:
        ctx: MCP context for logging and error handling
        id: ID of the connection to delete
        
    Returns:
        A confirmation message
    """
    logger.debug(f'Deleting connection: {id}')
    
    if id not in connections:
        return f"Connection with ID {id} not found."
    
    # Delete the connection
    del connections[id]
    
    # Update the architecture
    architecture.connections = list(connections.values())
    
    return f"Connection {id} deleted successfully."


async def add_data_store_impl(
    ctx: Context,
    name: str,
    type: str,
    classification: str,
    encryption_at_rest: bool = False,
    backup_frequency: Optional[str] = None,
    description: Optional[str] = None,
) -> str:
    """Add a new data store to the architecture.
    
    Args:
        ctx: MCP context for logging and error handling
        name: Name of the data store
        type: Type of the data store (e.g., 'Relational', 'NoSQL', 'Object Storage')
        classification: Classification of the data (e.g., 'Public', 'Internal', 'Confidential')
        encryption_at_rest: Whether the data is encrypted at rest
        backup_frequency: Frequency of backups (e.g., 'Hourly', 'Daily', 'Weekly')
        description: Description of the data store
        
    Returns:
        A confirmation message with the data store ID
    """
    logger.debug(f'Adding data store: {name}')
    
    # Generate a unique ID
    data_store_id = f"D{len(data_stores) + 1:03d}"
    
    # Create the data store
    data_store = DataStore(
        id=data_store_id,
        name=name,
        type=DataStoreType(type),
        classification=DataClassification(classification),
        encryption_at_rest=encryption_at_rest,
        backup_frequency=BackupFrequency(backup_frequency) if backup_frequency else None,
        description=description
    )
    
    # Store the data store
    data_stores[data_store_id] = data_store
    
    # Update the architecture
    architecture.data_stores = list(data_stores.values())
    
    return f"Data store added with ID: {data_store_id}"


async def update_data_store_impl(
    ctx: Context,
    id: str,
    name: Optional[str] = None,
    type: Optional[str] = None,
    classification: Optional[str] = None,
    encryption_at_rest: Optional[bool] = None,
    backup_frequency: Optional[str] = None,
    description: Optional[str] = None,
) -> str:
    """Update an existing data store in the architecture.
    
    Args:
        ctx: MCP context for logging and error handling
        id: ID of the data store to update
        name: New name of the data store
        type: New type of the data store
        classification: New classification of the data
        encryption_at_rest: New encryption status
        backup_frequency: New frequency of backups
        description: New description of the data store
        
    Returns:
        A confirmation message
    """
    logger.debug(f'Updating data store: {id}')
    
    if id not in data_stores:
        return f"Data store with ID {id} not found."
    
    data_store = data_stores[id]
    
    # Update only the provided fields
    if name is not None:
        data_store.name = name
    
    if type is not None:
        data_store.type = DataStoreType(type)
    
    if classification is not None:
        data_store.classification = DataClassification(classification)
    
    if encryption_at_rest is not None:
        data_store.encryption_at_rest = encryption_at_rest
    
    if backup_frequency is not None:
        data_store.backup_frequency = BackupFrequency(backup_frequency)
    
    if description is not None:
        data_store.description = description
    
    # Store the updated data store
    data_stores[id] = data_store
    
    # Update the architecture
    architecture.data_stores = list(data_stores.values())
    
    return f"Data store {id} updated successfully."


async def list_data_stores_impl(
    ctx: Context,
    type: Optional[str] = None,
) -> str:
    """List all data stores in the architecture.
    
    Args:
        ctx: MCP context for logging and error handling
        type: Optional type to filter data stores
        
    Returns:
        A markdown-formatted list of data stores
    """
    logger.debug('Listing data stores')
    
    if not data_stores:
        return "No data stores have been added yet."
    
    filtered_data_stores = data_stores.values()
    if type:
        filtered_data_stores = [d for d in filtered_data_stores if d.type == DataStoreType(type)]
    
    if not filtered_data_stores:
        return f"No data stores found with type: {type}"
    
    result = "# Architecture Data Stores\n\n"
    
    for data_store in filtered_data_stores:
        result += f"## {data_store.id}: {data_store.name}\n\n"
        result += f"**Type:** {data_store.type.value}\n\n"
        result += f"**Classification:** {data_store.classification.value}\n\n"
        result += f"**Encryption at Rest:** {'Yes' if data_store.encryption_at_rest else 'No'}\n\n"
        
        if data_store.backup_frequency:
            result += f"**Backup Frequency:** {data_store.backup_frequency.value}\n\n"
        
        if data_store.description:
            result += f"**Description:** {data_store.description}\n\n"
        
        result += "---\n\n"
    
    return result


async def delete_data_store_impl(
    ctx: Context,
    id: str,
) -> str:
    """Delete a data store from the architecture.
    
    Args:
        ctx: MCP context for logging and error handling
        id: ID of the data store to delete
        
    Returns:
        A confirmation message
    """
    logger.debug(f'Deleting data store: {id}')
    
    if id not in data_stores:
        return f"Data store with ID {id} not found."
    
    # Delete the data store
    del data_stores[id]
    
    # Update the architecture
    architecture.data_stores = list(data_stores.values())
    
    return f"Data store {id} deleted successfully."


async def get_architecture_analysis_plan_impl(
    ctx: Context,
) -> str:
    """Get a comprehensive architecture analysis plan.
    
    Args:
        ctx: MCP context for logging and error handling
        
    Returns:
        A markdown-formatted architecture analysis plan with prompts for LLM analysis
    """
    logger.debug('Getting architecture analysis plan')
    
    result = "# Architecture Analysis Plan\n\n"
    
    result += """## Overview
This plan provides a structured approach for analyzing system architecture for security concerns using AI-powered analysis with AWS documentation validation.

## Analysis Process

### Step 1: Gather Architecture Data
First, collect all architecture components using the following tools:

1. **Get Components**: Use `list_components()` to retrieve all system components
2. **Get Connections**: Use `list_connections()` to retrieve all component connections  
3. **Get Data Stores**: Use `list_data_stores()` to retrieve all data storage elements

### Step 2: LLM Analysis Prompt
Use the following prompt structure with an LLM to analyze the architecture:

```
You are a cybersecurity expert analyzing a system architecture for security concerns. 

ARCHITECTURE DATA:
[Insert the output from list_components(), list_connections(), and list_data_stores() here]

ANALYSIS INSTRUCTIONS:
1. **Component Security Analysis**:
   - Identify components with missing security configurations
   - Check for outdated or unversioned components
   - Analyze service provider security implications
   - Look for components in inappropriate trust zones

2. **Connection Security Analysis**:
   - Identify unencrypted connections, especially for sensitive data
   - Check for insecure protocols (HTTP, FTP, Telnet, etc.)
   - Analyze authentication and authorization gaps
   - Look for unnecessary network exposure

3. **Data Store Security Analysis**:
   - Check encryption at rest for sensitive data classifications
   - Analyze backup and recovery configurations
   - Identify data stores without proper access controls
   - Look for compliance violations based on data classification

4. **AWS-Specific Security Analysis** (if AWS components are present):
   - Validate AWS service configurations against security best practices
   - Check for proper IAM configurations
   - Analyze VPC and network security group configurations
   - Identify missing AWS security services (CloudTrail, GuardDuty, etc.)

MANDATORY AWS DOCUMENTATION REQUIREMENT:
For ANY AWS-specific security concerns identified, you MUST use the AWS Documentation MCP server:
- MANDATORY: Use `search_documentation` tool for current security best practices
- MANDATORY: Use `read_documentation` tool for specific service security documentation  
- MANDATORY: Validate ALL recommendations against official AWS guidance
- MANDATORY: Include AWS documentation URLs and citations in your analysis
- FAILURE TO USE AWS DOCUMENTATION WILL RESULT IN INCOMPLETE ANALYSIS

OUTPUT FORMAT:
Provide your analysis in the following markdown format:

# Architecture Security Analysis

## Executive Summary
[Brief overview of security posture and critical findings]

## Component Analysis
[Detailed analysis of component security issues]

## Connection Analysis  
[Detailed analysis of connection security issues]

## Data Store Analysis
[Detailed analysis of data storage security issues]

## AWS-Specific Findings
[AWS service-specific security concerns with documentation references]

## Risk Assessment
[Prioritized list of security risks with severity levels]

## Recommendations
[Actionable security recommendations with implementation guidance]

## Compliance Considerations
[Relevant compliance requirements based on data classifications]
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
Combine the LLM analysis with AWS documentation validation to produce a comprehensive security assessment.

## Key Security Areas to Focus On

### 1. Encryption and Data Protection
- Data in transit encryption
- Data at rest encryption  
- Key management practices
- Certificate management

### 2. Access Control and Authentication
- Identity and access management
- Multi-factor authentication
- Principle of least privilege
- Service-to-service authentication

### 3. Network Security
- Network segmentation
- Firewall configurations
- VPN and secure connections
- DDoS protection

### 4. Monitoring and Logging
- Security event logging
- Monitoring and alerting
- Incident response capabilities
- Audit trails

### 5. Compliance and Governance
- Regulatory compliance requirements
- Data governance policies
- Security policies and procedures
- Risk management frameworks

## Expected Deliverables

1. **Security Risk Assessment**: Prioritized list of identified security risks
2. **Remediation Plan**: Step-by-step guidance for addressing security gaps
3. **Compliance Report**: Assessment against relevant compliance frameworks
4. **Architecture Recommendations**: Suggestions for improving security posture

## Tools and Resources

- **Architecture Tools**: list_components, list_connections, list_data_stores
- **AWS Documentation**: AWS Documentation MCP Server for validation
- **Analysis Framework**: STRIDE, OWASP, NIST Cybersecurity Framework
- **Compliance Standards**: SOC 2, ISO 27001, PCI DSS, GDPR (as applicable)

This plan ensures a thorough, AI-powered analysis of your architecture with proper validation against authoritative sources.
"""
    
    return result


async def clear_architecture_impl(
    ctx: Context,
) -> str:
    """Clear the architecture.
    
    Args:
        ctx: MCP context for logging and error handling
        
    Returns:
        A confirmation message
    """
    logger.debug('Clearing architecture')
    
    global architecture, components, connections, data_stores
    
    architecture = Architecture()
    components = {}
    connections = {}
    data_stores = {}
    
    return "Architecture cleared."


# Register tools with the MCP server
def register_tools(mcp):
    """Register architecture analysis tools with the MCP server.
    
    Args:
        mcp: The MCP server instance
    """
    # Register component tools
    @mcp.tool()
    async def add_component(
        ctx: Context,
        name: str = Field(description="Name of the component"),
        type: str = Field(description="Type of the component (e.g., 'Compute', 'Storage', 'Network')"),
        service_provider: Optional[str] = Field(default=None, description="Provider of the service (e.g., 'AWS', 'Azure', 'GCP')"),
        specific_service: Optional[str] = Field(default=None, description="Specific service name (e.g., 'EC2', 'S3', 'Lambda')"),
        version: Optional[str] = Field(default=None, description="Version of the component"),
        description: Optional[str] = Field(default=None, description="Description of the component"),
        configuration: Optional[Dict[str, Any]] = Field(default=None, description="Configuration details of the component"),
    ) -> str:
        """Add a new component to the architecture.

        This tool adds a new component to the system architecture.

        Args:
            ctx: MCP context for logging and error handling
            name: Name of the component
            type: Type of the component (e.g., 'Compute', 'Storage', 'Network')
            service_provider: Provider of the service (e.g., 'AWS', 'Azure', 'GCP')
            specific_service: Specific service name (e.g., 'EC2', 'S3', 'Lambda')
            version: Version of the component
            description: Description of the component
            configuration: Configuration details of the component

        Returns:
            A confirmation message with the component ID
        """
        return await add_component_impl(ctx, name, type, service_provider, specific_service, version, description, configuration)

    @mcp.tool()
    async def update_component(
        ctx: Context,
        id: str = Field(description="ID of the component to update"),
        name: Optional[str] = Field(default=None, description="New name of the component"),
        type: Optional[str] = Field(default=None, description="New type of the component"),
        service_provider: Optional[str] = Field(default=None, description="New provider of the service"),
        specific_service: Optional[str] = Field(default=None, description="New specific service name"),
        version: Optional[str] = Field(default=None, description="New version of the component"),
        description: Optional[str] = Field(default=None, description="New description of the component"),
        configuration: Optional[Dict[str, Any]] = Field(default=None, description="New configuration details of the component"),
    ) -> str:
        """Update an existing component in the architecture.

        This tool updates an existing component in the system architecture.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the component to update
            name: New name of the component
            type: New type of the component
            service_provider: New provider of the service
            specific_service: New specific service name
            version: New version of the component
            description: New description of the component
            configuration: New configuration details of the component

        Returns:
            A confirmation message
        """
        return await update_component_impl(ctx, id, name, type, service_provider, specific_service, version, description, configuration)

    @mcp.tool()
    async def list_components(
        ctx: Context,
        type: Optional[str] = Field(default=None, description="Optional type to filter components"),
    ) -> str:
        """List all components in the architecture.

        This tool lists all components in the system architecture.

        Args:
            ctx: MCP context for logging and error handling
            type: Optional type to filter components

        Returns:
            A markdown-formatted list of components
        """
        return await list_components_impl(ctx, type)

    @mcp.tool()
    async def delete_component(
        ctx: Context,
        id: str = Field(description="ID of the component to delete"),
    ) -> str:
        """Delete a component from the architecture.

        This tool deletes a component from the system architecture.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the component to delete

        Returns:
            A confirmation message
        """
        return await delete_component_impl(ctx, id)
    
    @mcp.tool()
    async def add_connection(
        ctx: Context,
        source_id: str = Field(description="ID of the source component"),
        destination_id: str = Field(description="ID of the destination component"),
        protocol: Optional[str] = Field(default=None, description="Protocol used for the connection (e.g., 'HTTP', 'HTTPS', 'TCP')"),
        port: Optional[int] = Field(default=None, description="Port used for the connection"),
        encryption: bool = Field(default=False, description="Whether the connection is encrypted"),
        description: Optional[str] = Field(default=None, description="Description of the connection"),
    ) -> str:
        """Add a new connection to the architecture.

        This tool adds a new connection between two components in the system architecture.

        Args:
            ctx: MCP context for logging and error handling
            source_id: ID of the source component
            destination_id: ID of the destination component
            protocol: Protocol used for the connection (e.g., 'HTTP', 'HTTPS', 'TCP')
            port: Port used for the connection
            encryption: Whether the connection is encrypted
            description: Description of the connection

        Returns:
            A confirmation message with the connection ID
        """
        return await add_connection_impl(ctx, source_id, destination_id, protocol, port, encryption, description)

    @mcp.tool()
    async def update_connection(
        ctx: Context,
        id: str = Field(description="ID of the connection to update"),
        source_id: Optional[str] = Field(default=None, description="New ID of the source component"),
        destination_id: Optional[str] = Field(default=None, description="New ID of the destination component"),
        protocol: Optional[str] = Field(default=None, description="New protocol used for the connection"),
        port: Optional[int] = Field(default=None, description="New port used for the connection"),
        encryption: Optional[bool] = Field(default=None, description="New encryption status"),
        description: Optional[str] = Field(default=None, description="New description of the connection"),
    ) -> str:
        """Update an existing connection in the architecture.

        This tool updates an existing connection in the system architecture.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the connection to update
            source_id: New ID of the source component
            destination_id: New ID of the destination component
            protocol: New protocol used for the connection
            port: New port used for the connection
            encryption: New encryption status
            description: New description of the connection

        Returns:
            A confirmation message
        """
        return await update_connection_impl(ctx, id, source_id, destination_id, protocol, port, encryption, description)

    @mcp.tool()
    async def list_connections(
        ctx: Context,
        component_id: Optional[str] = Field(default=None, description="Optional component ID to filter connections"),
    ) -> str:
        """List all connections in the architecture.

        This tool lists all connections in the system architecture.

        Args:
            ctx: MCP context for logging and error handling
            component_id: Optional component ID to filter connections

        Returns:
            A markdown-formatted list of connections
        """
        return await list_connections_impl(ctx, component_id)

    @mcp.tool()
    async def delete_connection(
        ctx: Context,
        id: str = Field(description="ID of the connection to delete"),
    ) -> str:
        """Delete a connection from the architecture.

        This tool deletes a connection from the system architecture.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the connection to delete

        Returns:
            A confirmation message
        """
        return await delete_connection_impl(ctx, id)

    @mcp.tool()
    async def add_data_store(
        ctx: Context,
        name: str = Field(description="Name of the data store"),
        type: str = Field(description="Type of the data store (e.g., 'Relational', 'NoSQL', 'Object Storage')"),
        classification: str = Field(description="Classification of the data (e.g., 'Public', 'Internal', 'Confidential')"),
        encryption_at_rest: bool = Field(default=False, description="Whether the data is encrypted at rest"),
        backup_frequency: Optional[str] = Field(default=None, description="Frequency of backups (e.g., 'Hourly', 'Daily', 'Weekly')"),
        description: Optional[str] = Field(default=None, description="Description of the data store"),
    ) -> str:
        """Add a new data store to the architecture.

        This tool adds a new data store to the system architecture.

        Args:
            ctx: MCP context for logging and error handling
            name: Name of the data store
            type: Type of the data store (e.g., 'Relational', 'NoSQL', 'Object Storage')
            classification: Classification of the data (e.g., 'Public', 'Internal', 'Confidential')
            encryption_at_rest: Whether the data is encrypted at rest
            backup_frequency: Frequency of backups (e.g., 'Hourly', 'Daily', 'Weekly')
            description: Description of the data store

        Returns:
            A confirmation message with the data store ID
        """
        return await add_data_store_impl(ctx, name, type, classification, encryption_at_rest, backup_frequency, description)

    @mcp.tool()
    async def update_data_store(
        ctx: Context,
        id: str = Field(description="ID of the data store to update"),
        name: Optional[str] = Field(default=None, description="New name of the data store"),
        type: Optional[str] = Field(default=None, description="New type of the data store"),
        classification: Optional[str] = Field(default=None, description="New classification of the data"),
        encryption_at_rest: Optional[bool] = Field(default=None, description="New encryption status"),
        backup_frequency: Optional[str] = Field(default=None, description="New frequency of backups"),
        description: Optional[str] = Field(default=None, description="New description of the data store"),
    ) -> str:
        """Update an existing data store in the architecture.

        This tool updates an existing data store in the system architecture.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the data store to update
            name: New name of the data store
            type: New type of the data store
            classification: New classification of the data
            encryption_at_rest: New encryption status
            backup_frequency: New frequency of backups
            description: New description of the data store

        Returns:
            A confirmation message
        """
        return await update_data_store_impl(ctx, id, name, type, classification, encryption_at_rest, backup_frequency, description)

    @mcp.tool()
    async def list_data_stores(
        ctx: Context,
        type: Optional[str] = Field(default=None, description="Optional type to filter data stores"),
    ) -> str:
        """List all data stores in the architecture.

        This tool lists all data stores in the system architecture.

        Args:
            ctx: MCP context for logging and error handling
            type: Optional type to filter data stores

        Returns:
            A markdown-formatted list of data stores
        """
        return await list_data_stores_impl(ctx, type)

    @mcp.tool()
    async def delete_data_store(
        ctx: Context,
        id: str = Field(description="ID of the data store to delete"),
    ) -> str:
        """Delete a data store from the architecture.

        This tool deletes a data store from the system architecture.

        Args:
            ctx: MCP context for logging and error handling
            id: ID of the data store to delete

        Returns:
            A confirmation message
        """
        return await delete_data_store_impl(ctx, id)

    @mcp.tool()
    async def get_architecture_analysis_plan(
        ctx: Context,
    ) -> str:
        """Get a comprehensive architecture analysis plan.

        This tool returns a detailed plan for analyzing system architecture for security concerns
        using AI-powered analysis with AWS documentation validation.

        Args:
            ctx: MCP context for logging and error handling

        Returns:
            A markdown-formatted architecture analysis plan with prompts for LLM analysis
        """
        return await get_architecture_analysis_plan_impl(ctx)

    @mcp.tool()
    async def clear_architecture(
        ctx: Context,
    ) -> str:
        """Clear the architecture.

        This tool clears all components, connections, and data stores from the architecture.

        Args:
            ctx: MCP context for logging and error handling

        Returns:
            A confirmation message
        """
        return await clear_architecture_impl(ctx)
