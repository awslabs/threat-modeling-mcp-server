"""Step Orchestrator for the Threat Modeling MCP Server.

This module provides tools for orchestrating the steps of the threat modeling process,
including detailed guidance for each phase and automated execution of certain steps.
"""

from typing import Dict, List, Optional, Any
from loguru import logger
from mcp.server.fastmcp import Context
from pydantic import Field
from .threat_model_plan import detect_code_in_directory, has_code_files

# Phase status tracking
PHASES = {
    1: "Business Context Analysis",
    2: "Architecture Analysis",
    3: "Threat Actor Analysis",
    4: "Trust Boundary Analysis",
    5: "Asset Flow Analysis",
    6: "Threat Identification",
    7: "Mitigation Planning",
    7.5: "Code Validation Analysis",
    8: "Residual Risk Analysis",
    9: "Output Generation and Documentation"
}

# Track completion status of each phase
phase_completion = {phase: 0.0 for phase in PHASES.keys()}
current_phase = 1

# Whether the last detect_phase_completion() call succeeded. When detection
# fails the recorded completion is a stale snapshot, so gates that depend on it
# must refuse to act rather than trusting it.
last_detection_error: Optional[str] = None

# Directory searched when deciding whether phase 7.5 applies. Defaults to the
# server's working directory; set_project_directory() lets a caller point this at
# the project under review, which need not be the server's CWD.
project_directory = "."


def set_project_directory(directory: str) -> str:
    """Record the directory that holds the project under review.

    Args:
        directory: Path to the project being threat modeled

    Returns:
        A confirmation message
    """
    global project_directory

    project_directory = directory or "."
    applicable = phase_7_5_applicable()
    return (
        f"Project directory set to '{project_directory}'. Code "
        f"{'was' if applicable else 'was not'} detected, so phase 7.5 (Code "
        f"Validation Analysis) {'applies' if applicable else 'will be skipped'}."
    )


def phase_7_5_applicable(directory: Optional[str] = None) -> bool:
    """Whether Code Validation Analysis applies to this engagement.

    Phase 7.5 is optional: it only applies when there is source code to validate
    against. Without code the phase can never be completed, so treating it as
    required would deadlock the workflow.

    Args:
        directory: Directory to search. Defaults to the recorded project
            directory, which is the server's working directory unless
            set_project_directory() was called.

    Returns:
        True if code was detected
    """
    try:
        return has_code_files(directory or project_directory)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning(f"Could not determine whether phase 7.5 applies: {exc}")
        return False


def detect_phase_completion() -> None:
    """Detect and update phase completion based on actual work done.

    Completion is recomputed for every phase on each call and assigned, never
    only set. Removing the work that satisfied a phase therefore reopens it
    instead of leaving it stuck at complete.
    """
    global last_detection_error

    from threat_modeling_mcp_server.utils.state_collector import get_state_summary

    try:
        state = get_state_summary()

        from threat_modeling_mcp_server.tools.threat_generator import threats

        computed = {
            # Phase 1: Business Context Analysis. Same definition as
            # manage_system_context(action="validate", section="business").
            1: state['business_context'].get('is_complete', False),
            # Phase 2: Architecture Analysis
            2: state['architecture']['components'] > 0,
            # Phase 3: Threat Actor Analysis. Counted from actors the agent
            # has reviewed, not every actor present: the default library is
            # pre-loaded at startup, so a plain count reported this phase
            # complete before any analysis had happened.
            3: state['reviewed_threat_actors'] > 0,
            # Phase 4: Trust Boundary Analysis
            4: state['trust_boundaries']['trust_zones'] > 0,
            # Phase 5: Asset Flow Analysis
            5: state['asset_flows']['assets'] > 0,
            # Phase 6: Threat Identification
            6: state['threats_mitigations']['threats'] > 0,
            # Phase 7: Mitigation Planning
            7: (
                state['threats_mitigations']['mitigations'] > 0
                and state['threats_mitigations']['mitigation_links'] > 0
            ),
            # Phase 7.5: Code Validation Analysis (optional)
            7.5: state.get('code_validation', {}).get('is_complete', False) or not phase_7_5_applicable(),
            # Phase 8: Residual Risk Analysis
            8: any(
                threat.status
                and threat.status.value in ('threatResolved', 'threatResolvedNotUseful')
                for threat in threats.values()
            ),
            # Phase 9: Output Generation and Documentation
            9: (
                state['threats_mitigations']['threats'] > 0
                and state['threats_mitigations']['mitigations'] > 0
                and state['architecture']['components'] > 0
                and state['business_context']['has_description']
            ),
        }

        # Commit all phases together so completion always reflects one snapshot.
        for phase, is_complete in computed.items():
            phase_completion[phase] = 1.0 if is_complete else 0.0

        last_detection_error = None

    except Exception as e:
        # Leave the previous snapshot in place rather than reporting a phase
        # complete or incomplete on the strength of a failed collection, and
        # record the failure so callers can refuse to rely on stale values.
        last_detection_error = str(e)
        logger.warning(f"Failed to detect phase completion, keeping last known state: {e}")


def get_current_phase_auto() -> int:
    """Automatically determine the current phase based on completion status.

    Returns:
        The first phase that is not yet complete, or the last phase if all are
    """
    detect_phase_completion()

    for phase in sorted(PHASES.keys()):
        if phase_completion.get(phase, 0.0) < 1.0:
            return phase

    return sorted(PHASES.keys())[-1]


async def advance_phase_impl(ctx) -> str:
    """Advance to the next phase, refusing if any earlier phase is incomplete.

    Args:
        ctx: MCP context for logging and error handling

    Returns:
        A confirmation message and guidance for the new phase, or an explanation
        of why the phase cannot be advanced
    """
    global current_phase, phase_completion

    logger.info(f"Advancing from phase: {current_phase}")

    # Refresh detected completion, then refuse to advance while ANY earlier
    # phase is incomplete. Checking only current_phase would let a reopened
    # earlier phase (for example after clearing the business section through
    # manage_system_context) be skipped by advancing again from a later phase.
    detect_phase_completion()

    if last_detection_error is not None:
        return (
            "❌ Cannot advance: phase completion could not be determined, so the "
            "recorded progress may be out of date.\n\n"
            f"Detection failed with: {last_detection_error}\n\n"
            "Resolve that, then try again."
        )

    blocking = [
        phase for phase in sorted(PHASES.keys())
        if phase <= current_phase and phase_completion.get(phase, 0.0) < 1.0
    ]
    if blocking:
        earliest = blocking[0]
        detail = ", ".join(
            f"phase {phase} ({PHASES.get(phase, 'Unknown')}) at "
            f"{phase_completion.get(phase, 0.0):.0%}"
            for phase in blocking
        )
        return (
            f"❌ Cannot advance: phase {earliest} "
            f"({PHASES.get(earliest, 'Unknown')}) is not complete.\n\n"
            f"Incomplete phases up to the current one: {detail}.\n\n"
            f"Completion is detected from the work recorded so far. Use "
            f"get_current_phase_status() to see what is missing, then complete "
            f"the outstanding items and try again."
        )

    phases = sorted(PHASES.keys())
    current_index = phases.index(current_phase)

    if current_index < len(phases) - 1:
        next_phase = phases[current_index + 1]

        # Phase 7.5 only applies when there is code to validate. Skip straight
        # to phase 8 otherwise, matching the phase 7 guidance.
        skipped_note = ""
        if next_phase == 7.5 and not phase_7_5_applicable():
            next_index = phases.index(next_phase)
            if next_index < len(phases) - 1:
                next_phase = phases[next_index + 1]
                skipped_note = (
                    "Skipped phase 7.5 (Code Validation Analysis): no code files "
                    "were detected, so there is nothing to validate against.\n\n"
                )

        current_phase = next_phase
        return (
            skipped_note
            + f"Advanced to phase: {current_phase} - {PHASES[current_phase]}\n\n"
            + get_phase_guidance(current_phase)
        )

    return (
        "Threat modeling process completed! You have gone through all phases of "
        "the threat modeling process."
    )


def get_phase_guidance(phase_number: float) -> str:
    """Get detailed guidance for a specific phase.

    Args:
        phase_number: The phase number to get guidance for

    Returns:
        Markdown-formatted guidance for the phase
    """
    phase_name = PHASES.get(phase_number, "Unknown Phase")

    # Phase 1: Business Context Analysis
    if phase_number == 1:
        return f"""
# Phase {phase_number}: {phase_name}

## Objective
Understand the business context of the system being modeled to identify what's important to protect.

## Steps
1. **Define the system scope**
   - What is the system's purpose?
   - What are the system boundaries?
   - What is in-scope vs. out-of-scope?

2. **Identify business objectives**
   - What are the key business goals?
   - What would constitute a business failure?

3. **Identify regulatory requirements**
   - What compliance requirements apply?
   - What are the legal implications of a security breach?

4. **Determine data sensitivity**
   - What types of data does the system handle?
   - How sensitive is this data?
   - What would be the impact if this data were compromised?

## Tools to Use
- `manage_system_context`: Manage business context and all taxonomy profiles through
  one tool. Start with `action="describe"` for the section you need.
  - Use `action="set", section="all"` to submit business, software, data asset,
    user persona, and NFR classifications in one nested payload.
  - Use `action="validate", section="all"` to enforce business-context
    completeness and report classification-profile coverage.
  - Use `action="plan", section="business"` for detailed analysis guidance.

Business context covers scale, geography, criticality, and financial impact. The
software, data asset, user persona, and NFR sections cover the remaining taxonomy
dimensions. Capture interoperability needs with the `Interoperability`
non-functional requirement.

## Expected Outputs
- Documented system scope
- List of business objectives
- Regulatory requirements
- Data sensitivity classification

## Next Steps
After completing Phase 1, proceed to Phase 2:
**Use `get_phase_2_guidance()` to continue with Architecture Analysis**
"""

    # Phase 2: Architecture Analysis
    elif phase_number == 2:
        return f"""
# Phase {phase_number}: {phase_name}

## Objective
Document the system architecture to understand what components need to be protected.

## Steps
1. **Identify system components**
   - What are the main components of the system?
   - What technologies are used?
   - What are the interfaces between components?

2. **Document data flows**
   - How does data move through the system?
   - What protocols are used?
   - Where is data stored?

3. **Identify entry points**
   - What are the external interfaces?
   - How do users interact with the system?
   - What APIs are exposed?

4. **Document dependencies**
   - What external systems does this system depend on?
   - What internal dependencies exist?

## Tools to Use
- `add_component`: Add a new component to the architecture
- `add_connection`: Add a new connection between components
- `add_data_store`: Add a new data store
- `get_architecture_analysis_plan`: Get a plan to analyze the architecture

## Expected Outputs
- System component diagram
- Data flow diagram
- Entry point inventory
- Dependency map

## Next Steps
After completing Phase 2, proceed to Phase 3:
**Use `get_phase_3_guidance()` to continue with Threat Actor Analysis**
"""

    # Phase 3: Threat Actor Analysis
    elif phase_number == 3:
        return f"""
# Phase {phase_number}: {phase_name}

## Objective
Identify potential threat actors who might target the system.

## Steps
1. **Identify relevant threat actors**
   - Who might want to attack the system?
   - What are their motivations?
   - What are their capabilities?

2. **Prioritize threat actors**
   - Which threat actors are most likely to target the system?
   - Which threat actors could cause the most damage?

3. **Document threat actor profiles**
   - What methods might each threat actor use?
   - What resources do they have?
   - What are their typical targets?

## Tools to Use
- `add_threat_actor`: Add a new threat actor
- `set_threat_actor_relevance`: Set whether a threat actor is relevant
- `set_threat_actor_priority`: Set the priority of a threat actor
- `analyze_threat_actors`: Analyze the threat actors

## Expected Outputs
- List of relevant threat actors
- Threat actor prioritization
- Threat actor profiles

## Next Steps
After completing Phase 3, proceed to Phase 4:
**Use `get_phase_4_guidance()` to continue with Trust Boundary Analysis**
"""

    # Phase 4: Trust Boundary Analysis
    elif phase_number == 4:
        return f"""
# Phase {phase_number}: {phase_name}

## Objective
Identify trust boundaries within the system where security controls should be applied.

## Steps
1. **Identify trust zones**
   - What are the different security domains?
   - What level of trust exists within each zone?

2. **Document trust boundaries**
   - Where do trust boundaries exist between zones?
   - What data crosses these boundaries?

3. **Identify crossing points**
   - What specific interfaces cross trust boundaries?
   - What security controls exist at these crossing points?

## Tools to Use
- `add_trust_zone`: Add a new trust zone
- `add_component_to_zone`: Add a component to a trust zone
- `add_crossing_point`: Add a new crossing point between trust zones
- `add_trust_boundary`: Add a new trust boundary
- `get_trust_boundary_detection_plan`: Get a plan to detect trust boundaries

## Expected Outputs
- Trust zone diagram
- Trust boundary documentation
- Crossing point inventory

## Next Steps
After completing Phase 4, proceed to Phase 5:
**Use `get_phase_5_guidance()` to continue with Asset Flow Analysis**
"""

    # Phase 5: Asset Flow Analysis
    elif phase_number == 5:
        return f"""
# Phase {phase_number}: {phase_name}

## Objective
Identify and analyze the flow of valuable assets through the system.

## Steps
1. **Identify key assets**
   - What valuable data exists in the system?
   - What functionality is critical?
   - What would attackers want to target?

2. **Document asset flows**
   - How do assets move through the system?
   - Where are assets stored?
   - Where are assets processed?

3. **Identify asset exposure**
   - Where are assets exposed to potential attackers?
   - What protections exist for assets?

## Tools to Use
- `add_asset`: Add a new asset to the system
- `add_flow`: Add a new asset flow

## Expected Outputs
- Asset inventory
- Asset flow diagram
- Asset exposure assessment

## Next Steps
After completing Phase 5, proceed to Phase 6:
**Use `get_phase_6_guidance()` to continue with Threat Identification**
"""

    # Phase 6: Threat Identification
    elif phase_number == 6:
        return f"""
# Phase {phase_number}: {phase_name}

## Objective
Identify potential threats to the system based on the previous analysis.

## Steps
1. **Apply threat modeling methodology**
   - Use STRIDE or other methodology to identify threats
   - Consider each component and data flow

2. **Document threats**
   - What could go wrong?
   - What would the impact be?
   - How likely is the threat?

3. **Prioritize threats**
   - Which threats pose the greatest risk?
   - Which threats are most likely?
   - Which threats would have the highest impact?

## Tools to Use
- `add_threat`: Add a new threat to the model
- `list_threats`: List all threats in the model

## Expected Outputs
- Comprehensive threat list
- Threat prioritization
- Risk assessment

## Next Steps
After completing Phase 6, proceed to Phase 7:
**Use `get_phase_7_guidance()` to continue with Mitigation Planning**
"""

    # Phase 7: Mitigation Planning
    elif phase_number == 7:
        return f"""
# Phase {phase_number}: {phase_name}

## Objective
Develop mitigations for the identified threats.

## Steps
1. **Identify potential mitigations**
   - What security controls could address each threat?
   - What design changes could reduce risk?

2. **Evaluate mitigations**
   - How effective would each mitigation be?
   - What is the cost/effort to implement?
   - What are the tradeoffs?

3. **Document mitigation plan**
   - Which mitigations will be implemented?
   - Who is responsible for implementation?
   - What is the timeline?

## Tools to Use
- `add_mitigation`: Add a new mitigation to the model
- `link_mitigation_to_threat`: Link a mitigation to a threat

## Expected Outputs
- Mitigation strategies for each threat
- Implementation plan
- Responsibility assignments

## Next Steps
After completing Phase 7, proceed to Phase 7.5:
**Use `get_phase_7_5_guidance()` to continue with Code Validation Analysis**
"""

    # Phase 7.5: Code Validation Analysis
    elif phase_number == 7.5:
        return f"""
# Phase {phase_number}: {phase_name}

## Objective
Inspect the code, record concrete evidence for every current threat and mitigation,
and update their statuses from those findings.

## Steps
1. Call `manage_code_validation(action="describe")` for the finding contract.
2. Inspect the relevant implementation paths yourself.
3. Call `manage_code_validation(action="record", values=...)` with threat and
   mitigation findings. Recording is atomic and applies the matching statuses.
4. Repeat until `manage_code_validation(action="validate")` reports complete
   coverage.
5. Call `manage_code_validation(action="report")` to render the evidence-based
   report and complete Phase 7.5.

Use `action="get"` to review progress and `action="clear"` when starting a new
validation. Observed implementation details belong in finding evidence; use
`add_assumption()` only for statements that remain assumptions.

## Tools to Use
- `manage_code_validation()`: Describe, record, review, validate, report, or clear findings

## Expected Outputs
- Evidence for every current threat and mitigation
- Explicit remediation and implementation outcomes
- Updated canonical statuses
- Deterministic code-validation report

## Next Steps
After completing Phase 7.5, proceed to Phase 8:
**Use `get_phase_8_guidance()` to continue with Residual Risk Analysis**
"""

    # Phase 8: Residual Risk Analysis
    elif phase_number == 8:
        return f"""
# Phase {phase_number}: {phase_name}

## Objective
Analyze remaining risks after mitigations are applied and make risk acceptance decisions.

## Steps
1. **Review All Threats and Mitigations**
   - Use `list_threats()` to get complete threat inventory
   - Use `list_mitigations()` to get complete mitigation inventory
   - Review current status of each threat
   - Identify unmitigated or partially mitigated threats

2. **Assess Residual Risk for Each Threat**
   - Use `get_threat(id)` for each threat to evaluate remaining risk
   - Consider likelihood and impact of residual risk after mitigations
   - Document risk assessment rationale

3. **Make Risk Acceptance Decisions**
   - Use `update_threat(id, status, ...)` to update threat status
   - Mark threats as: threatResolved, threatResolvedNotUseful
   - Document business justification for each decision

4. **Document Risk Assumptions**
   - Use `add_assumption()` to document assumptions about residual risks
   - Include business risk tolerance decisions
   - Record risk acceptance criteria

## Tools to Use
- `list_threats()`: Get complete inventory of threats
- `list_mitigations()`: Get complete inventory of mitigations
- `get_threat(id)`: Get detailed information about specific threats
- `update_threat(id, status, ...)`: Update threat status based on risk decisions
- `add_assumption()`: Document risk acceptance assumptions

## Expected Outputs
- Complete residual risk assessment
- Updated threat statuses with justifications
- Risk acceptance documentation
- Business risk tolerance assumptions

## Next Steps
After completing Phase 8, proceed to Phase 9:
**Use `get_phase_9_guidance()` to continue with Output Generation and Documentation**
"""

    # Phase 9: Output Generation and Documentation
    elif phase_number == 9:
        return f"""
# Phase {phase_number}: {phase_name}

## Objective
Generate final documentation and outputs for integration with development processes.

## Steps
1. **Export Comprehensive Threat Model**
   - Use `export_comprehensive_threat_model(output_path)` to export complete threat model with all global variables
   - Include all components, threats, mitigations, business context, assumptions, and phase progress
   - Include current threat and mitigation statuses, including updates made during code validation
   - Compatible with AWS Threat Composer and includes extended data

2. **Generate Summary Reports**
   - Use `get_threat_model_progress()` to create progress summary
   - Use `list_assumptions()` to document all assumptions
   - Create executive summary of threat modeling process
   - Document key findings and recommendations

3. **Create Implementation Documentation**
   - Review all mitigations for implementation guidance
   - Document security requirements derived from threats
   - Create verification criteria for each mitigation

## Tools to Use
- `export_comprehensive_threat_model(output_path)`: Export the complete model, including current threat and mitigation statuses
- `get_threat_model_progress()`: Get progress metrics and completion status
- `list_assumptions()`: Get all documented assumptions
- `list_mitigations()`: Get all mitigations for implementation planning

## Expected Outputs
- Comprehensive Threat Composer JSON export with all global variables
- Threat and mitigation statuses captured in the JSON and Markdown exports
- Executive summary document
- Implementation recommendations
- Security requirements documentation
"""

    # Unknown phase
    else:
        return f"# Phase {phase_number}: {phase_name}\n\nNo detailed guidance available for this phase."


async def execute_final_export(ctx: Context) -> str:
    """Execute the complete final export step.

    Args:
        ctx: MCP context for logging and error handling

    Returns:
        A markdown-formatted report of the export results
    """
    logger.info("Executing final export step")

    from threat_modeling_mcp_server.utils.comprehensive_exporter import export_comprehensive_threat_model
    from threat_modeling_mcp_server.utils.state_collector import get_state_summary
    from datetime import datetime

    try:
        # Generate timestamp for unique filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Export comprehensive threat model
        comprehensive_export_result = export_comprehensive_threat_model(
            f"comprehensive_threat_model_{timestamp}.json",
            include_extended_data=True
        )


        # Get state summary
        state_summary = get_state_summary()

        # Generate final report
        report = f"""
# Final Export Step Complete

**Execution Timestamp**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Export Results

### Comprehensive Export
{comprehensive_export_result}

## State Summary
- **Business Context**: {'✅ Set' if state_summary['business_context']['has_description'] else '❌ Not Set'} ({state_summary['business_context']['features_set']}/{state_summary['business_context'].get('features_total', 'n/a')} features configured)
- **Assumptions**: {state_summary['assumptions']} documented
- **Architecture Components**: {state_summary['architecture']['components']} components, {state_summary['architecture']['connections']} connections, {state_summary['architecture']['data_stores']} data stores
- **Threat Actors**: {state_summary['reviewed_threat_actors']} analyzed (of {state_summary['threat_actors']} in the reference catalogue)
- **Trust Boundaries**: {state_summary['trust_boundaries']['trust_zones']} zones, {state_summary['trust_boundaries']['crossing_points']} crossing points, {state_summary['trust_boundaries']['trust_boundaries']} boundaries
- **Asset Flows**: {state_summary['asset_flows']['assets']} assets, {state_summary['asset_flows']['flows']} flows
- **Threats & Mitigations**: {state_summary['threats_mitigations']['threats']} threats, {state_summary['threats_mitigations']['mitigations']} mitigations

## Current Progress
- **Phase**: {state_summary['progress']['current_phase']} - {state_summary['progress']['current_phase_name']}
- **Overall Completion**: {state_summary['progress']['overall_completion']:.1%}

## Files Generated
The comprehensive threat model file has been generated in the `.threatmodel` directory with all global variables and extended data. The file is compatible with AWS Threat Composer and ready for import into threat modeling tools or for further analysis.
"""

        return report.strip()

    except Exception as e:
        error_msg = f"Failed to execute final export step: {str(e)}"
        logger.error(error_msg)
        return error_msg


# Named with the _impl suffix, like advance_phase_impl below, because
# register_tools defines a `get_current_phase_status` tool closure. Sharing the
# name meant the closure shadowed this function from its own scope, so the tool
# raised "missing 1 required positional argument: 'ctx'" on every call --
# including when an agent followed advance_phase's own advice to call it.
def get_current_phase_status_impl() -> Dict[str, Any]:
    """Get the current phase status and completion progress.

    Returns:
        Dictionary with current phase information and completion percentages
    """
    # Update phase completion based on actual work done
    detect_phase_completion()

    # Get the current phase automatically
    auto_current_phase = get_current_phase_auto()

    return {
        "current_phase": auto_current_phase,
        "current_phase_name": PHASES.get(auto_current_phase, "Unknown"),
        "current_phase_completion": phase_completion.get(auto_current_phase, 0.0),
        "overall_completion": sum(phase_completion.values()) / len(phase_completion),
        "phases": {phase: {"name": name, "completion": phase_completion.get(phase, 0.0)} 
                  for phase, name in PHASES.items()}
    }


# Register tools with the MCP server
def register_tools(mcp):
    """Register step orchestration tools with the MCP server.

    Args:
        mcp: The MCP server instance
    """
    @mcp.tool()
    async def get_phase_1_guidance(ctx: Context) -> str:
        """Get detailed guidance for Phase 1: Business Context Analysis.

        This tool provides step-by-step guidance for conducting business context analysis,
        including objectives, steps, tools to use, and expected outputs.

        Args:
            ctx: MCP context for logging and error handling

        Returns:
            A markdown-formatted guide for Phase 1
        """
        logger.info("Providing guidance for Phase 1: Business Context Analysis")
        return get_phase_guidance(1)

    @mcp.tool()
    async def get_phase_2_guidance(ctx: Context) -> str:
        """Get detailed guidance for Phase 2: Architecture Analysis.

        This tool provides step-by-step guidance for conducting architecture analysis,
        including objectives, steps, tools to use, and expected outputs.

        Args:
            ctx: MCP context for logging and error handling

        Returns:
            A markdown-formatted guide for Phase 2
        """
        logger.info("Providing guidance for Phase 2: Architecture Analysis")
        return get_phase_guidance(2)

    @mcp.tool()
    async def get_phase_3_guidance(ctx: Context) -> str:
        """Get detailed guidance for Phase 3: Threat Actor Analysis.

        This tool provides step-by-step guidance for conducting threat actor analysis,
        including objectives, steps, tools to use, and expected outputs.

        Args:
            ctx: MCP context for logging and error handling

        Returns:
            A markdown-formatted guide for Phase 3
        """
        logger.info("Providing guidance for Phase 3: Threat Actor Analysis")
        return get_phase_guidance(3)

    @mcp.tool()
    async def get_phase_4_guidance(ctx: Context) -> str:
        """Get detailed guidance for Phase 4: Trust Boundary Analysis.

        This tool provides step-by-step guidance for conducting trust boundary analysis,
        including objectives, steps, tools to use, and expected outputs.

        Args:
            ctx: MCP context for logging and error handling

        Returns:
            A markdown-formatted guide for Phase 4
        """
        logger.info("Providing guidance for Phase 4: Trust Boundary Analysis")
        return get_phase_guidance(4)

    @mcp.tool()
    async def get_phase_5_guidance(ctx: Context) -> str:
        """Get detailed guidance for Phase 5: Asset Flow Analysis.

        This tool provides step-by-step guidance for conducting asset flow analysis,
        including objectives, steps, tools to use, and expected outputs.

        Args:
            ctx: MCP context for logging and error handling

        Returns:
            A markdown-formatted guide for Phase 5
        """
        logger.info("Providing guidance for Phase 5: Asset Flow Analysis")
        return get_phase_guidance(5)

    @mcp.tool()
    async def get_phase_6_guidance(ctx: Context) -> str:
        """Get detailed guidance for Phase 6: Threat Identification.

        This tool provides step-by-step guidance for conducting threat identification,
        including objectives, steps, tools to use, and expected outputs.

        Args:
            ctx: MCP context for logging and error handling

        Returns:
            A markdown-formatted guide for Phase 6
        """
        logger.info("Providing guidance for Phase 6: Threat Identification")
        return get_phase_guidance(6)

    @mcp.tool()
    async def get_phase_7_guidance(ctx: Context, directory: str = ".") -> str:
        """Get detailed guidance for Phase 7: Mitigation Planning.

        This tool provides step-by-step guidance for conducting mitigation planning,
        including objectives, steps, tools to use, and expected outputs. The next steps
        are conditional based on whether code is detected in the project.

        Args:
            ctx: MCP context for logging and error handling
            directory: Directory to check for code files (default: current directory)

        Returns:
            A markdown-formatted guide for Phase 7 with conditional next steps
        """
        logger.info("Providing guidance for Phase 7: Mitigation Planning")

        # Check if code exists in the directory
        code_detected = await detect_code_in_directory(directory)
        logger.info(f"Code detected in directory '{directory}': {code_detected}")

        # Get base Phase 7 guidance
        base_guidance = get_phase_guidance(7)

        # Replace the "Next Steps" section with conditional logic
        if code_detected:
            next_steps = """## Next Steps
After completing Phase 7, proceed to Phase 7.5 for code validation:
**Use `get_phase_7_5_guidance()` to continue with Code Validation Analysis**

*Code files were detected in your project, so Phase 7.5 (Code Validation Analysis) will help validate which security controls are already implemented in your codebase and update the threat model accordingly.*"""
        else:
            next_steps = """## Next Steps
After completing Phase 7, proceed directly to Phase 8:
**Use `get_phase_8_guidance()` to continue with Residual Risk Analysis**

*No code files were detected in your project, so Phase 7.5 (Code Validation Analysis) is being skipped. Proceeding directly to residual risk analysis.*"""

        # Replace the existing next steps section
        updated_guidance = base_guidance.replace(
            """## Next Steps
After completing Phase 7, proceed to Phase 7.5:
**Use `get_phase_7_5_guidance()` to continue with Code Validation Analysis**""",
            next_steps
        )

        return updated_guidance

    @mcp.tool()
    async def get_phase_7_5_guidance(ctx: Context) -> str:
        """Get detailed guidance for Phase 7.5: Code Validation Analysis.

        This tool provides step-by-step guidance for conducting code validation analysis,
        including objectives, steps, tools to use, and expected outputs.

        Args:
            ctx: MCP context for logging and error handling

        Returns:
            A markdown-formatted guide for Phase 7.5
        """
        logger.info("Providing guidance for Phase 7.5: Code Validation Analysis")
        return get_phase_guidance(7.5)

    @mcp.tool()
    async def get_phase_8_guidance(ctx: Context) -> str:
        """Get detailed guidance for Phase 8: Residual Risk Analysis.

        This tool provides step-by-step guidance for conducting residual risk analysis,
        including objectives, steps, tools to use, and expected outputs.

        Args:
            ctx: MCP context for logging and error handling

        Returns:
            A markdown-formatted guide for Phase 8
        """
        logger.info("Providing guidance for Phase 8: Residual Risk Analysis")
        return get_phase_guidance(8)

    @mcp.tool()
    async def get_phase_9_guidance(ctx: Context) -> str:
        """Get detailed guidance for Phase 9: Output Generation and Documentation.

        This tool provides step-by-step guidance for generating outputs and documentation,
        including objectives, steps, tools to use, and expected outputs.

        Args:
            ctx: MCP context for logging and error handling

        Returns:
            A markdown-formatted guide for Phase 9
        """
        logger.info("Providing guidance for Phase 9: Output Generation and Documentation")
        return get_phase_guidance(9)

    @mcp.tool()
    async def execute_final_export_step(ctx: Context) -> str:
        """Execute the complete final export step (Phase 9) automatically.

        This tool automates the final export step, generating all required documentation
        and outputs from the threat modeling process.

        Args:
            ctx: MCP context for logging and error handling

        Returns:
            A markdown-formatted report of the export results
        """
        logger.info("Executing final export step (Phase 9)")
        return await execute_final_export(ctx)

    @mcp.tool()
    async def get_current_phase_status(ctx: Context) -> Dict[str, Any]:
        """Get the current phase status and completion progress.

        This tool provides information about the current phase of the threat modeling
        process and the completion progress of each phase.

        Args:
            ctx: MCP context for logging and error handling

        Returns:
            A dictionary with current phase information and completion percentages
        """
        logger.info("Getting current phase status")
        return get_current_phase_status_impl()

    @mcp.tool()
    async def follow_threat_modeling_plan(ctx: Context, phase: str = None) -> str:
        """Follow the threat modeling plan.

        This tool guides the user through the threat modeling process step by step,
        following the plan generated by the get_threat_modeling_plan tool.

        Args:
            ctx: MCP context for logging and error handling
            phase: Optional phase to get guidance for (if not provided, will use current phase)

        Returns:
            A markdown-formatted guide for the current or specified phase
        """
        global current_phase

        logger.info(f"Following threat modeling plan for phase: {phase if phase else current_phase}")

        # If a specific phase is requested, use that
        if phase:
            try:
                requested_phase = float(phase)
                if requested_phase not in PHASES:
                    return f"Invalid phase: {phase}. Please specify one of: {', '.join([str(p) for p in PHASES.keys()])}"
            except ValueError:
                return f"Invalid phase format: {phase}. Please specify a numeric phase like '1', '2', '7.5', etc."
        else:
            requested_phase = current_phase

        return get_phase_guidance(requested_phase)

    @mcp.tool()
    async def set_project_directory_tool(
        ctx: Context,
        directory: str = Field(description="Path to the project being threat modeled, for example '/repos/my-service'"),
    ) -> str:
        """Record which directory holds the project under review.

        Phase 7.5 (Code Validation Analysis) only applies when there is source
        code to validate. That is decided by searching this directory, which
        defaults to the server's working directory. Set it when the project
        lives elsewhere, otherwise phase 7.5 may be skipped incorrectly.
        """
        logger.info(f"Setting project directory: {directory}")
        return set_project_directory(directory)

    @mcp.tool()
    async def advance_phase(ctx: Context) -> str:
        """Advance to the next phase of the threat modeling process.

        Refuses to advance while the current phase is incomplete.

        Args:
            ctx: MCP context for logging and error handling

        Returns:
            A confirmation message and guidance for the new phase
        """
        return await advance_phase_impl(ctx)

    @mcp.tool()
    async def get_threat_model_progress(ctx: Context) -> str:
        """Get the current progress of the threat modeling process.

        This tool returns the current progress of the threat modeling process,
        including completed phases and the current phase.

        Args:
            ctx: MCP context for logging and error handling

        Returns:
            A markdown-formatted progress report
        """
        logger.info("Getting threat modeling progress")

        # Update phase completion based on actual work done
        detect_phase_completion()

        # Get the current phase automatically
        auto_current_phase = get_current_phase_auto()

        result = "# Threat Modeling Progress\n\n"

        # Calculate overall progress
        total_phases = len(PHASES)
        completed_count = sum(1 for completion in phase_completion.values() if completion >= 1.0)
        overall_percentage = int((completed_count / total_phases) * 100)

        result += f"**Overall Progress:** {overall_percentage}% ({completed_count}/{total_phases} phases completed)\n\n"
        result += f"**Current Phase:** {auto_current_phase} - {PHASES.get(auto_current_phase, 'Unknown')}\n\n"

        result += "## Phase Status\n\n"

        for phase_num in sorted(PHASES.keys()):
            phase_name = PHASES[phase_num]
            completion = phase_completion.get(phase_num, 0.0)

            if completion >= 1.0:
                status = "✅ Completed"
            elif phase_num == auto_current_phase:
                status = "🔄 In Progress"
            else:
                status = "⏳ Pending"

            result += f"- **Phase {phase_num}: {phase_name}:** {status}\n"

        return result
