# Threat Modeling MCP Server

A Model Context Protocol (MCP) server for comprehensive threat modeling with guided code validation.

## Table of Contents

- [Overview](#overview)
- [Quick Start Prompts](#quick-start-prompts-and-examples-on-how-to-threat-model-with-this-mcp-server)
- [Key Features](#key-features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Running with Kiro CLI](#running-with-kiro-cli)
- [Output File Management](#output-file-management)
- [Quick Reference](#quick-reference)
- [Tools Overview](#tools-overview)
- [Threat Modeling Methodology](#threat-modeling-methodology)
- [Assumptions in Threat Modeling](#assumptions-in-threat-modeling)
- [Development](#development)

## Overview

This server provides tools for threat modeling, including business context analysis, architecture analysis, threat actor analysis, trust boundary analysis, asset flow analysis, code security validation and comprehensive report generation.

### Architecture and Approach
This MCP Server calls the existing agent's LLM instead of making an external API or network call to a different service. It relies on existing client's LLM which could be Amazon-Q, Kiro or Cline.

This Threat Modeling MCP Server has three main functionalities:
1. Threat modeling phase or state management and prompt controlling.
2. Prompts steering, which controls the agent to go through a methodic approach to threat modeling using built in definitions of business risks, exposures, threat actors and use STRIDE in sequential order.
3. Structured input validation and phase-completion checks that support an actionable threat model report.

It also has tools to generate a final report in both Markdown and JSON exportable formats.

### Key Advantages of this approach
- This threat model follows the standard STRIDE approach to threat modeling in phases rather than quick conclusion of assets, boundaries and threats which can lead to hallucination or low quality output.
- There is an effort by LLM to understand the business context of the project and make valid assumptions which can be controlled by the user.
- This local server relies on the MCP client's configured LLM (Cline, Amazon Q, Kiro) rather than calling a separate model API. Data exposure depends on the client and any other MCP servers the client invokes.
- The server keeps the working threat model in memory for the current process. Export tools can write JSON and Markdown snapshots to a `.threatmodel` directory, but those snapshots are not automatically loaded in a later session.
- The code-validation tool records evidence supplied by the client after it inspects the implementation, applies status transitions atomically, and fails the phase closed until every current threat and mitigation is covered.

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
Running it on a subfolder limits the intended analysis scope. To save exports there, request an output path inside that subfolder; the export location is not inferred automatically from the analysis scope.

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
"Export the threat model to my_model.tc.json"
```

## Key Features

- **Comprehensive Threat Modeling**: Structured approach to identifying, evaluating, and addressing security risks
- **Evidence-Based Code Validation**: Records implementation evidence, updates statuses, and produces a deterministic report
- **Business Context Analysis**: Understand the business value and criticality of the system
- **Architecture Analysis**: Document the system's technical architecture and data flows
- **Threat Actor Analysis**: Identify potential adversaries and assess their capabilities
- **Trust Boundary Analysis**: Identify trust zones and validate security controls at boundaries
- **Asset Flow Analysis**: Track critical assets through the system
- **Threat Identification**: Systematically identify potential threats using STRIDE methodology
- **Mitigation Planning**: Develop strategies to address identified threats
- **Compact Domain Managers**: Action-based tools for assumptions, architecture, actors, boundaries, assets, threats, and mitigations
- **Threat Model Guide**: Step-by-step guidance through the threat modeling process
- **Data Model Inspection**: One tool for listing enum models and inspecting accepted values

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
      "autoApprove": ["manage_workflow","export_threat_model","manage_system_context","manage_assumptions","manage_architecture","manage_threat_actors","manage_trust_boundaries","manage_asset_flows","manage_threats","inspect_data_models","manage_code_validation"]
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
      "autoApprove": ["manage_workflow","export_threat_model","manage_system_context","manage_assumptions","manage_architecture","manage_threat_actors","manage_trust_boundaries","manage_asset_flows","manage_threats","inspect_data_models","manage_code_validation"],
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
      "autoApprove": ["manage_workflow","export_threat_model","manage_system_context","manage_assumptions","manage_architecture","manage_threat_actors","manage_trust_boundaries","manage_asset_flows","manage_threats","inspect_data_models","manage_code_validation"]
    }
  }
}
```

### Running with Kiro CLI

To run the MCP server via `kiro-cli` with all tools auto-approved:

```bash
kiro-cli chat --trust-tools="@threat-modeling-mcp-server/*"
```

This trusts all tools from the `threat-modeling-mcp-server` MCP server, so you won't be prompted to approve each tool call individually.

### Running with the Custom Kiro CLI Agent

This repository includes a pre-configured Kiro CLI agent that covers nine numbered phases plus the optional Phase 7.5 code-validation step. The agent configuration is in `.kiro/agents/threat-modeler.json`.

**Global install** (available from any directory):

```bash
./install-kiro-agent.sh
```

To uninstall: `./install-kiro-agent.sh --remove`

**Local install** (project-specific):

```bash
cp -r /path/to/threat-modeling-mcp-server/.kiro /path/to/your-project/.kiro
```

**Usage**:

```bash
# Non-interactive: run full threat model and exit
kiro-cli chat --agent threat-modeler --no-interactive "Threat model this project"

# Interactive: start a session with the agent
kiro-cli chat --agent threat-modeler
```

**What the agent includes**:
- **System prompt** (`.kiro/prompts/threat-modeler.md`): Detailed instructions for the phased STRIDE methodology
- **Skills** (`.kiro/skills/`): Per-phase reference materials, including optional Phase 7.5
- **Auto-approved MCP tools**: All threat modeling tools run without manual approval prompts

## Output File Management

The export tool writes JSON and Markdown files to a `.threatmodel`
directory next to the requested output path. The directory is created when an
export runs. `export_threat_model()` uses the server's current working
directory because it supplies a relative output filename.

Validation and analysis tools generally return text through MCP rather than
writing report files. The exported files are snapshots; the server does not
automatically reload them when a new process starts.

## Quick Reference

### Essential Tools for Getting Started

| Tool | Purpose | Example |
|------|---------|---------|
| `manage_workflow(action="plan")` | Get comprehensive plan | Start here for overview |
| **`manage_workflow(action="guidance", phase="1")`** | **Get focused Phase 1 guidance** | **Recommended starting point** |
| `manage_workflow(action="status")` | Check progress | Track completion status |
| `manage_system_context(action, section, ...)` | Define business context and taxonomy profiles | `action="set", section="all"` |
| `manage_assumptions(action, ...)` | Document and maintain assumptions | Start with `action="describe"` |
| `manage_architecture(action, section, ...)` | Manage components, data-store nodes, and connections | Start with `action="describe"` |
| `manage_threat_actors(action, ...)` | Assess and analyze threat actors | Use `action="update"` for relevance and priority |
| `manage_trust_boundaries(action, section, ...)` | Manage zones, crossings, and boundaries | Use `action="detection_plan"` for guidance |
| `manage_asset_flows(action, section, ...)` | Manage assets and flows | Sections are `assets` and `flows` |
| `manage_threats(action, section, ...)` | Manage threats, mitigations, links, and residual-risk decisions | Use `action="assess"` in Phase 8 |
| `manage_code_validation(action, values)` | Record and report code-validation evidence | Start with `action="describe"` |
| **`export_threat_model()`** | **Execute Phase 9 export** | **Generates JSON and Markdown snapshots** |

### 🚀 Step-by-Step Guidance

**Recommended Approach**: Use the consolidated guidance tool for one phase at a time:

| Phase | Tool | Purpose |
|-------|------|---------|
| 1 | `manage_workflow(action="guidance", phase="1")` | Business Context Analysis |
| 2 | `manage_workflow(action="guidance", phase="2")` | Architecture Analysis |
| 3 | `manage_workflow(action="guidance", phase="3")` | Threat Actor Analysis |
| 4 | `manage_workflow(action="guidance", phase="4")` | Trust Boundary Analysis |
| 5 | `manage_workflow(action="guidance", phase="5")` | Asset Flow Analysis |
| 6 | `manage_workflow(action="guidance", phase="6")` | Threat Identification |
| 7 | `manage_workflow(action="guidance", phase="7")` | Mitigation Planning |
| 7.5 | `manage_workflow(action="guidance", phase="7.5")` | Guided Code Validation (Optional) |
| 8 | `manage_workflow(action="guidance", phase="8")` | Residual Risk Analysis |
| 9 | `manage_workflow(action="guidance", phase="9")` | Output Generation and Documentation |

## Tools Overview

The Threat Modeling MCP Server provides **11 tools** organized into the following categories:

| Category | Tools | Description |
|----------|-------|-------------|
| **Workflow** | 2 tools | Plan and guide the workflow, track or advance phases, and export the result |
| **System Context** | 1 tool | Manage business context plus software, data, user, and NFR taxonomy profiles |
| **Domain Managers** | 6 tools | Manage assumptions, architecture, actors, boundaries, asset flows, threats, and mitigations |
| **Data Model Types** | 1 tool | Explore available enum models and accepted values |
| **Code Validation** | 1 tool | Record evidence, apply statuses, validate coverage, and render reports |

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

- **Phase 1 - Business Context Analysis**: Understanding the business value and criticality of the system
- **Phase 2 - Architecture Analysis**: Connecting every component and data-store node
- **Phase 3 - Threat Actor Analysis**: Identifying potential adversaries and their capabilities
- **Phase 4 - Trust Boundary Analysis**: Assigning every node to a zone and mapping inter-zone connections
- **Phase 5 - Asset Flow Analysis**: Tracking every critical asset through at least one flow
- **Phase 6 - Threat Identification**: Systematically identifying potential threats using STRIDE
- **Phase 7 - Mitigation Planning**: Linking at least one mitigation to every threat
- **Phase 7.5 - Code Validation Analysis (optional)**: Recording implementation evidence for every threat and mitigation
- **Phase 8 - Residual Risk Analysis**: Recording a current decision, residual ratings, and rationale for every threat
- **Phase 9 - Output Generation and Documentation**: Exporting current JSON and Markdown snapshots

Each phase includes specific objectives, activities, and outputs to guide the threat modeling process.

### Threat Severity Levels

- **Critical**: Immediate action required, system compromise likely
- **High**: Significant risk, should be addressed quickly
- **Medium**: Moderate risk, address in normal development cycle
- **Low**: Minor risk, address when convenient

### Threat Likelihood Levels

- **Very Likely**: Expected to occur
- **Likely**: More likely than not
- **Possible**: Plausible given the right conditions
- **Unlikely**: Would require unusual circumstances

### Mitigation Types

- **Preventive**: Controls that prevent threats from occurring
- **Detective**: Controls that detect when threats occur
- **Corrective**: Controls that respond to and correct threats
- **Deterrent**: Controls that discourage an attacker from attempting the threat

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
2. Create a virtual environment with `uv venv`
3. Activate it with `source .venv/bin/activate` (Windows PowerShell: `.venv\Scripts\Activate.ps1`)
4. Install the package and test dependencies with `uv pip install -e '.[test]'`
5. Run the server locally with `python run_server.py`
6. Run tests with `python -m pytest`

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License. See the [LICENSE](LICENSE) file for details.
