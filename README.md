# Threat Modeling MCP Server

A Model Context Protocol (MCP) server for comprehensive threat modeling with automatic code validation.

## Table of Contents

- [Overview](#overview)
- [Quick Start Prompts](#quick-start-prompts-and-examples-on-how-to-threat-model-with-this-mcp-server)
- [Key Features](#key-features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Output File Management](#output-file-management)
- [Quick Reference](#quick-reference)
- [Tools Overview](#tools-overview)
- [Threat Modeling Methodology](#threat-modeling-methodology)
- [Assumptions in Threat Modeling](#assumptions-in-threat-modeling)
- [Development](#development)
- [Roadmap](#roadmap)

## Overview

This server provides tools for threat modeling, including business context analysis, architecture analysis, threat actor analysis, trust boundary analysis, asset flow analysis, code security validation and comprehensive report generation.

### Architecture and Approach
This MCP Server calls the existing agent's LLM instead of making an external API or network call to a different service. It relies on existing client's LLM which could be Amazon-Q, Kiro or Cline.

This Threat Modeling MCP Server has three main functionalities:
1. Threat modeling phase or state management and prompt controlling.
2. Prompts steering, which controls the agent to go through a methodic approach to threat modeling using built in definitions of business risks, exposures, threat actors and use STRIDE in sequential order.
3. Data validation at every state or phase, which in turn produces actionable threat model report.

It also has tools to generate a final report in both Markdown and JSON exportable formats.

### Key Advantages of this approach
- This threat model follows the standard STRIDE approach to threat modeling in phases rather than quick conclusion of assets, boundaries and threats which can lead to hallucination or low quality output.
- There is an effort by LLM to understand the business context of the project and make valid assumptions which can be controlled by the user.
- The main advantage of using this local running threat modeling MCP server is that it leverages the client's existing LLM (Cline, Amazon-Q, Kiro). Any data which is processed or sent is limited to the client or other MCP servers you may have installed and invoked. This server doesn't call any other external APIs or send or receive data beyond calling the client's LLM or additional billing or tokens than what your client is already configured to use.
- This threat modeling approach stores your threat model in the same repository as `.threatmodel` directory and you can evolve your threat model as your code, design and architecture evolves.
- This threat model approach looks at the code if its present and updates the threats if they are already mitigated in the code level controls. You can rerun threat model once you fix your code and it should look at the fix to update the threat model quickly.

## Quick Start Prompts and Examples on how to threat model with this MCP server

> **Note:** Before using these prompts, you must first complete the [Installation](#installation) process to set up the MCP server.

### Start a threat model
```
"Threat model this project using the threat modeling MCP Server"
```
Being specific in the prompt to use the threat modeling MCP Server will make sure the client (Cline/Kiro/etc) will follow the exact phases and methodology rather than taking short cut path and introduce hallucination in results.

### Threat model a subproject or reduce the scope to a sub folder
```
"Threat model this subfolder using the threat modeling MCP Server"
```
Running it on a subfolder will limit the scope of threat model and code to that subfolder and save results as a `.threatmodel` directory within the subfolder.

### Save the result of threat model
```
"Save the threat model report"
```

### Validate the completeness of the threat modeling process
```
"Please complete all the phases in the threat model plan and then generate the final report."
```

### Feed an architecture diagram image as input
```
"Threat model this project using the threat model MCP server and consider this architecture_image.png attached for this review"
```

### Attempt remediating the threats
```
"Can you see if you can implement mitigation controls in the code based on the threats reported in the threat model"
```

### Regenerate threat model based on code fixes
```
"Can you updated the threat model based on the code fixes which mitigated the reported threats"
```

### More examples
```bash
# Set up context
"Set business context for an e-commerce payment system"

# Add architecture
"Add a web server component using AWS EC2"
"Add a database component using AWS RDS"

# Identify threats
"Add a threat where an attacker with network access performs SQL injection"

# Add mitigations
"Add a mitigation for input validation"

# Export results
"Export the threat model to my_model.json"
```

## Key Features

- **Comprehensive Threat Modeling**: Structured approach to identifying, evaluating, and addressing security risks
- **Automatic Code Validation**: Detects code in the project directory and automatically validates the threat model against it
- **Business Context Analysis**: Understand the business value and criticality of the system
- **Architecture Analysis**: Document the system's technical architecture and data flows
- **Threat Actor Analysis**: Identify potential adversaries and assess their capabilities
- **Trust Boundary Analysis**: Identify trust zones and validate security controls at boundaries
- **Asset Flow Analysis**: Track critical assets through the system
- **Threat Identification**: Systematically identify potential threats using STRIDE methodology
- **Mitigation Planning**: Develop strategies to address identified threats
- **Assumption Management**: Tools for adding, listing, updating, and deleting assumptions in the threat model
- **Threat Generator**: Tools for adding and managing threats in the model
- **Mitigation Management**: Tools for managing mitigations and linking them to threats
- **Threat Model Guide**: Step-by-step guidance through the threat modeling process
- **Data Model Types**: Tools for exploring available data model types and enumerations

## Prerequisites

Before installing the Threat Modeling MCP Server, ensure you have the following requirements:

### Installation Requirements

1. Install `uvx` from [Astral](https://docs.astral.sh/uv/getting-started/installation/) or the [GitHub README](https://github.com/astral-sh/uv#installation)
   - uvx is part of the uv package manager
   - Verify installation: `uvx --version`

## Installation

Once you have uvx installed and verified to be working, add the below configuation to your mcp.json config file. Depending on the what type of client your are using (kiro/cline/amazon-q) the location of this mcp.json will be different. Once you add the config and restart your IDE, the Threat Modeling MCP Server will be automatically be installed directly from this GitHub repository using `uvx`.

> **Note:** The tools used by this mcp server for threat modeling are already added to the `autoApprove` for ease of user experience which enables seamless operation without manual approval prompts for each tool call. All tools are internal to the server and do not make external API calls. If you want to review each of the tools and approve it per invocation, then you need to replace the autoApprove array with this: ```"autoApprove": []```

### Configuration

Add the following to your MCP client configuration:

**For Amazon Q** (`~/.aws/amazonq/mcp.json`):
```json
{
  "mcpServers": {
    "threat-modeling-mcp-server": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/awslabs/threat-modeling-mcp-server.git",
        "threat-modeling-mcp-server"
      ],
      "env": {
        "FASTMCP_LOG_LEVEL": "ERROR"
      },
      "disabled": false,
      "autoApprove": ["add_asset","add_assumption","add_component","add_component_to_zone","add_conn_to_crossing","add_connection","add_crossing_point","add_data_store","add_flow","add_mitigation","add_threat","add_threat_actor","add_trust_boundary","add_trust_zone","advance_phase","analyze_threat_actors","clear_architecture","clear_asset_flows","clear_business_context","clear_threat_actors","clear_trust_boundaries","delete_asset","delete_assumption","delete_component","delete_connection","delete_crossing_point","delete_data_store","delete_flow","delete_mitigation","delete_threat","delete_threat_actor","delete_trust_boundary","delete_trust_zone","execute_code_validation_step","execute_final_export_step","export_comprehensive_threat_model","export_threat_model_with_remediation_status","follow_threat_modeling_plan","generate_remediation_report","get_architecture_analysis_plan","get_asset","get_asset_flow_analysis_plan","get_assumption","get_business_context","get_business_context_analysis_plan","get_business_context_features","get_crossing_point","get_current_phase_status","get_data_model_types","get_flow","get_mitigation","get_phase_1_guidance","get_phase_2_guidance","get_phase_3_guidance","get_phase_4_guidance","get_phase_5_guidance","get_phase_6_guidance","get_phase_7_5_guidance","get_phase_7_guidance","get_phase_8_guidance","get_phase_9_guidance","get_threat","get_threat_actor","get_threat_model_progress","get_threat_modeling_plan","get_trust_boundary","get_trust_boundary_analysis_plan","get_trust_boundary_detection_plan","get_trust_zone","link_mitigation_to_threat","list_assets","list_assumptions","list_components","list_connections","list_crossing_points","list_data_models","list_data_stores","list_flows","list_mitigations","list_threat_actors","list_threats","list_trust_boundaries","list_trust_zones","remove_component_from_zone","remove_conn_from_crossing","reset_asset_flows","reset_threat_actors","set_business_context","set_threat_actor_priority","set_threat_actor_relevance","unlink_mitigation_from_threat","update_asset","update_assumption","update_component","update_connection","update_crossing_point","update_data_store","update_flow","update_mitigation","update_threat","update_threat_actor","update_trust_boundary","update_trust_zone","validate_business_context_completeness","validate_security_controls","validate_threat_model_against_code","validate_threat_remediation"]
    }
  }
}
```

**For VSCode Cline**:
```json
{
  "mcpServers": {
    "threat-modeling-mcp-server": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/awslabs/threat-modeling-mcp-server.git",
        "threat-modeling-mcp-server"
      ],
      "env": {
        "FASTMCP_LOG_LEVEL": "ERROR"
      },
      "disabled": false,
      "autoApprove": ["add_asset","add_assumption","add_component","add_component_to_zone","add_conn_to_crossing","add_connection","add_crossing_point","add_data_store","add_flow","add_mitigation","add_threat","add_threat_actor","add_trust_boundary","add_trust_zone","advance_phase","analyze_threat_actors","clear_architecture","clear_asset_flows","clear_business_context","clear_threat_actors","clear_trust_boundaries","delete_asset","delete_assumption","delete_component","delete_connection","delete_crossing_point","delete_data_store","delete_flow","delete_mitigation","delete_threat","delete_threat_actor","delete_trust_boundary","delete_trust_zone","execute_code_validation_step","execute_final_export_step","export_comprehensive_threat_model","export_threat_model_with_remediation_status","follow_threat_modeling_plan","generate_remediation_report","get_architecture_analysis_plan","get_asset","get_asset_flow_analysis_plan","get_assumption","get_business_context","get_business_context_analysis_plan","get_business_context_features","get_crossing_point","get_current_phase_status","get_data_model_types","get_flow","get_mitigation","get_phase_1_guidance","get_phase_2_guidance","get_phase_3_guidance","get_phase_4_guidance","get_phase_5_guidance","get_phase_6_guidance","get_phase_7_5_guidance","get_phase_7_guidance","get_phase_8_guidance","get_phase_9_guidance","get_threat","get_threat_actor","get_threat_model_progress","get_threat_modeling_plan","get_trust_boundary","get_trust_boundary_analysis_plan","get_trust_boundary_detection_plan","get_trust_zone","link_mitigation_to_threat","list_assets","list_assumptions","list_components","list_connections","list_crossing_points","list_data_models","list_data_stores","list_flows","list_mitigations","list_threat_actors","list_threats","list_trust_boundaries","list_trust_zones","remove_component_from_zone","remove_conn_from_crossing","reset_asset_flows","reset_threat_actors","set_business_context","set_threat_actor_priority","set_threat_actor_relevance","unlink_mitigation_from_threat","update_asset","update_assumption","update_component","update_connection","update_crossing_point","update_data_store","update_flow","update_mitigation","update_threat","update_threat_actor","update_trust_boundary","update_trust_zone","validate_business_context_completeness","validate_security_controls","validate_threat_model_against_code","validate_threat_remediation"],
      "timeout": 60,
      "type": "stdio"
    }
  }
}
```

**For Kiro** (`~/.kiro/settings/mcp.json`):
```json
{
  "mcpServers": {
    "threat-modeling-mcp-server": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/awslabs/threat-modeling-mcp-server.git",
        "threat-modeling-mcp-server"
      ],
      "env": {
        "FASTMCP_LOG_LEVEL": "ERROR"
      },
      "disabled": false,
      "autoApprove": ["add_asset","add_assumption","add_component","add_component_to_zone","add_conn_to_crossing","add_connection","add_crossing_point","add_data_store","add_flow","add_mitigation","add_threat","add_threat_actor","add_trust_boundary","add_trust_zone","advance_phase","analyze_threat_actors","clear_architecture","clear_asset_flows","clear_business_context","clear_threat_actors","clear_trust_boundaries","delete_asset","delete_assumption","delete_component","delete_connection","delete_crossing_point","delete_data_store","delete_flow","delete_mitigation","delete_threat","delete_threat_actor","delete_trust_boundary","delete_trust_zone","execute_code_validation_step","execute_final_export_step","export_comprehensive_threat_model","export_threat_model_with_remediation_status","follow_threat_modeling_plan","generate_remediation_report","get_architecture_analysis_plan","get_asset","get_asset_flow_analysis_plan","get_assumption","get_business_context","get_business_context_analysis_plan","get_business_context_features","get_crossing_point","get_current_phase_status","get_data_model_types","get_flow","get_mitigation","get_phase_1_guidance","get_phase_2_guidance","get_phase_3_guidance","get_phase_4_guidance","get_phase_5_guidance","get_phase_6_guidance","get_phase_7_5_guidance","get_phase_7_guidance","get_phase_8_guidance","get_phase_9_guidance","get_threat","get_threat_actor","get_threat_model_progress","get_threat_modeling_plan","get_trust_boundary","get_trust_boundary_analysis_plan","get_trust_boundary_detection_plan","get_trust_zone","link_mitigation_to_threat","list_assets","list_assumptions","list_components","list_connections","list_crossing_points","list_data_models","list_data_stores","list_flows","list_mitigations","list_threat_actors","list_threats","list_trust_boundaries","list_trust_zones","remove_component_from_zone","remove_conn_from_crossing","reset_asset_flows","reset_threat_actors","set_business_context","set_threat_actor_priority","set_threat_actor_relevance","unlink_mitigation_from_threat","update_asset","update_assumption","update_component","update_connection","update_crossing_point","update_data_store","update_flow","update_mitigation","update_threat","update_threat_actor","update_trust_boundary","update_trust_zone","validate_business_context_completeness","validate_security_controls","validate_threat_model_against_code","validate_threat_remediation"]
    }
  }
}
```

## Output File Management

All output files generated by the threat modeling server are automatically saved to a `.threatmodel` directory in your project root. This includes:

- Exported threat models (JSON format)
- Validation reports
- Analysis results

The `.threatmodel` directory is created automatically when needed.

## Quick Reference

### Essential Tools for Getting Started

| Tool | Purpose | Example |
|------|---------|---------|
| `get_threat_modeling_plan()` | Get comprehensive plan | Start here for overview |
| **`get_phase_1_guidance()`** | **Get focused Phase 1 guidance** | **Recommended starting point** |
| `get_current_phase_status()` | Check progress | Track completion status |
| `set_business_context(desc)` | Define system context | "E-commerce payment system" |
| `add_component(name, type)` | Add architecture component | "API Gateway", "Network" |
| `add_threat(source, prereq, action, impact)` | Identify threat | "Attacker", "network access", "SQL injection", "data breach" |
| `add_mitigation(content)` | Add security control | "Input validation and parameterized queries" |
| `link_mitigation_to_threat(m_id, t_id)` | Link controls to threats | Connect mitigations to specific threats |
| **`execute_code_validation_step()`** | **Auto-execute Phase 7.5** | **Ensures code validation completion** |
| **`execute_final_export_step()`** | **Auto-execute Phase 9** | **Generates all required files** |

### 🚀 Step-by-Step Guidance

**Recommended Approach**: Use phase-specific guidance tools instead of the comprehensive plan:

| Phase | Tool | Purpose |
|-------|------|---------|
| 1 | `get_phase_1_guidance()` | Business Context Analysis |
| 2 | `get_phase_2_guidance()` | Architecture Analysis |
| 3 | `get_phase_3_guidance()` | Threat Actor Analysis |
| 4 | `get_phase_4_guidance()` | Trust Boundary Analysis |
| 5 | `get_phase_5_guidance()` | Asset Flow Analysis |
| 6 | `get_phase_6_guidance()` | Threat Identification |
| 7 | `get_phase_7_guidance()` | Mitigation Planning |
| 7.5 | `execute_code_validation_step()` | Code Validation (Auto) |
| 8 | `get_phase_8_guidance()` | Residual Risk Analysis |
| 9 | `execute_final_export_step()` | Final Export (Auto) |

## Tools Overview

The Threat Modeling MCP Server provides **100+ tools** organized into the following categories:

| Category | Tools | Description |
|----------|-------|-------------|
| **Threat Modeling Plan** | 1 tool | Generate comprehensive threat modeling plans |
| **Assumption Management** | 5 tools | Add, list, get, update, and delete assumptions |
| **Business Context Analysis** | 13 tools | Analyze business context and requirements |
| **Architecture Analysis** | 13 tools | Document and analyze system architecture |
| **Threat Actor Analysis** | 10 tools | Identify and analyze potential threat actors |
| **Trust Boundary Analysis** | 18 tools | Analyze trust zones, boundaries, and crossing points |
| **Trust Boundary Detection** | 1 tool | AI-powered trust boundary detection |
| **Asset Flow Analysis** | 12 tools | Track and analyze asset flows through the system |
| **Threat Generation** | 4 tools | Add, list, get, and delete threats |
| **Mitigation Management** | 7 tools | Manage mitigations and link them to threats |
| **Threat Model Guide** | 3 tools | Step-by-step guidance through the process |
| **Data Model Types** | 2 tools | Explore available data model types |
| **Code Security Validation** | 3 tools | Validate security controls in code |
| **Threat Model Validation** | 2 tools | Validate threat models against code |
| **Step Orchestrator** | 12 tools | Phase-specific guidance and step execution |

## Threat Modeling Methodology

### STRIDE Framework

The server uses the STRIDE methodology for systematic threat identification:

| Category | Description | Example Threats |
|----------|-------------|-----------------|
| **Spoofing** | Impersonating someone or something else | Authentication bypass, identity theft |
| **Tampering** | Modifying data or code | Data corruption, code injection |
| **Repudiation** | Claiming to have not performed an action | Log tampering, non-repudiation failures |
| **Information Disclosure** | Exposing information to unauthorized users | Data leaks, privacy breaches |
| **Denial of Service** | Denying or degrading service | Resource exhaustion, availability attacks |
| **Elevation of Privilege** | Gaining capabilities without authorization | Privilege escalation, unauthorized access |

### Threat Modeling Process

The comprehensive threat modeling process includes these phases:

1. **Business Context Analysis**: Understanding the business value and criticality of the system
2. **Architecture Analysis**: Documenting the system's technical architecture
3. **Threat Actor Analysis**: Identifying potential adversaries and their capabilities
4. **Trust Boundary Analysis**: Identifying trust zones and boundary crossings
5. **Asset Flow Analysis**: Tracking critical assets through the system
6. **Threat Identification**: Systematically identifying potential threats using STRIDE
7. **Mitigation Planning**: Developing strategies to address identified threats
8. **Code Validation**: Validating threats against existing security controls
9. **Residual Risk Analysis**: Assessing remaining risks after mitigations

Each phase includes specific objectives, activities, and outputs to guide the threat modeling process.

### Threat Severity Levels

- **Critical**: Immediate action required, system compromise likely
- **High**: Significant risk, should be addressed quickly
- **Medium**: Moderate risk, address in normal development cycle
- **Low**: Minor risk, address when convenient
- **Info**: Informational finding, no immediate action required

### Mitigation Types

- **Preventive**: Controls that prevent threats from occurring
- **Detective**: Controls that detect when threats occur
- **Corrective**: Controls that respond to and correct threats
- **Compensating**: Alternative controls when primary controls aren't feasible

## Assumptions in Threat Modeling

Assumptions are statements that we accept as true without requiring further validation. They help scope the threat model by establishing boundaries and constraints. Common examples include:

- "All network connections in the VPC are encrypted in transit"
- "AWS KMS keys cannot be discovered by brute force"
- "Nation-state threat actors are not a concern for this system"

By documenting assumptions, we can:
- Prevent generating pointless threats
- Avoid recommending unnecessary mitigations
- Focus on relevant security concerns
- Clearly document the scope and limitations of the threat model

## Development

### Contributing

To contribute to this project:

1. Clone the repository
2. Install development dependencies with `uv pip install -e .`
3. Run the server locally with `python run_server.py`
4. Run tests with `python -m pytest`

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License. See the [LICENSE](LICENSE) file for details.

