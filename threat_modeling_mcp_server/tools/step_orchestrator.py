"""Step Orchestrator for the Threat Modeling MCP Server.

This module provides tools for orchestrating the steps of the threat modeling process,
including detailed guidance for each phase and automated execution of certain steps.
"""

from typing import Any, Dict, Literal, Optional
from loguru import logger
from mcp.server.fastmcp import Context
from pydantic import Field
from .threat_model_plan import (
    detect_code_in_directory,
    generate_threat_modeling_plan,
    has_code_files,
)

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

PhaseSelection = Literal[
    "current", "1", "2", "3", "4", "5", "6", "7", "7.5", "8", "9",
]
WorkflowAction = Literal[
    "describe", "plan", "guidance", "status", "set_project", "advance",
    "progress",
]

PHASE_BY_SELECTION = {
    "1": 1,
    "2": 2,
    "3": 3,
    "4": 4,
    "5": 5,
    "6": 6,
    "7": 7,
    "7.5": 7.5,
    "8": 8,
    "9": 9,
}

# Track completion status of each phase
phase_completion = {phase: 0.0 for phase in PHASES.keys()}
phase_blocking_reasons = {phase: [] for phase in PHASES.keys()}
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

        readiness = state["phase_readiness"]
        phase_7_5_complete = (
            state.get('code_validation', {}).get('is_complete', False)
            or not phase_7_5_applicable()
        )
        computed = {
            phase: readiness[str(phase)]["is_complete"]
            for phase in (1, 2, 3, 4, 5, 6, 7, 8, 9)
        }
        computed[7.5] = phase_7_5_complete

        # Commit all phases together so completion always reflects one snapshot.
        for phase, is_complete in computed.items():
            phase_completion[phase] = 1.0 if is_complete else 0.0
            if phase == 7.5:
                phase_blocking_reasons[phase] = (
                    []
                    if is_complete
                    else [
                        "Run code validation for the configured project directory."
                    ]
                )
            else:
                phase_blocking_reasons[phase] = list(
                    readiness[str(phase)]["blocking_reasons"]
                )

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
        reasons = phase_blocking_reasons.get(earliest, [])
        missing = (
            "\n\nMissing work:\n- " + "\n- ".join(reasons)
            if reasons
            else ""
        )
        return (
            f"❌ Cannot advance: phase {earliest} "
            f"({PHASES.get(earliest, 'Unknown')}) is not complete.\n\n"
            f"Incomplete phases up to the current one: {detail}."
            f"{missing}\n\n"
            f"Completion is detected from the work recorded so far. Use "
            f'manage_workflow(action="status") to see what is missing, then '
            f"complete the outstanding items and try again."
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
            + await get_phase_guidance_impl(str(current_phase))
        )

    return (
        "Threat modeling process completed! You have gone through all phases of "
        "the threat modeling process."
    )


def build_phase_guidance(phase_number: float) -> str:
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
**Use `manage_workflow(action="guidance", phase="2")` to continue with Architecture Analysis**
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
- `manage_architecture(action="describe", section=SECTION)`: Get exact fields
- `manage_architecture(action="add", section=SECTION, values=RECORD)`: Add records
- `manage_architecture(action="list", section="all")`: Review the architecture
- `manage_architecture(action="plan", section="all")`: Get analysis guidance

## Expected Outputs
- System component diagram
- Data flow diagram
- Entry point inventory
- Dependency map

## Completion Gate
At least one component or data store must exist. Every architecture node must
participate in a connection, except for a valid single-node model.

## Next Steps
After completing Phase 2, proceed to Phase 3:
**Use `manage_workflow(action="guidance", phase="3")` to continue with Threat Actor Analysis**
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
- `manage_threat_actors(action="list")`: Review default and custom actors
- `manage_threat_actors(action="update", item_id=ID, values=ASSESSMENT)`: Set relevance and priority
- `manage_threat_actors(action="add", values=ACTOR)`: Add a custom actor
- `manage_threat_actors(action="analyze")`: Analyze the actors

## Expected Outputs
- List of relevant threat actors
- Threat actor prioritization
- Threat actor profiles

## Next Steps
After completing Phase 3, proceed to Phase 4:
**Use `manage_workflow(action="guidance", phase="4")` to continue with Trust Boundary Analysis**
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
- `manage_trust_boundaries(action="detection_plan", section="all")`: Get detection guidance
- `manage_trust_boundaries(action="add", section=SECTION, values=RECORD)`: Add zones, crossings, or boundaries
- `manage_trust_boundaries(action="link", section="zones", values={{"zone_id": ZONE_ID, "node_id": NODE_ID}})`: Assign component or data-store nodes
- `manage_trust_boundaries(action="link", section="crossing_points", values=LINK)`: Assign connections

## Expected Outputs
- Trust zone diagram
- Trust boundary documentation
- Crossing point inventory

## Completion Gate
Every architecture node belongs to exactly one zone. Each inter-zone connection
maps to exactly one matching crossing point, and every crossing point belongs to
a trust boundary. No crossing is needed for communication within one zone.

## Next Steps
After completing Phase 4, proceed to Phase 5:
**Use `manage_workflow(action="guidance", phase="5")` to continue with Asset Flow Analysis**
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
- `manage_asset_flows(action="add", section="assets", values=ASSET)`: Add an asset
- `manage_asset_flows(action="add", section="flows", values=FLOW)`: Add an asset flow

## Expected Outputs
- Asset inventory
- Asset flow diagram
- Asset exposure assessment

## Completion Gate
Assets and flows must exist, and every asset must participate in a flow.

## Next Steps
After completing Phase 5, proceed to Phase 6:
**Use `manage_workflow(action="guidance", phase="6")` to continue with Threat Identification**
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
- `manage_threats(action="add", section="threats", values=THREAT)`: Add a threat
- `manage_threats(action="list", section="threats")`: List all threats

## Expected Outputs
- Comprehensive threat list
- Threat prioritization
- Risk assessment

## Next Steps
After completing Phase 6, proceed to Phase 7:
**Use `manage_workflow(action="guidance", phase="7")` to continue with Mitigation Planning**
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
- `manage_threats(action="add", section="mitigations", values=MITIGATION)`: Add a mitigation
- `manage_threats(action="link", section="mitigations", items=LINKS)`: Batch mitigation-to-threat links; use `values=LINK` for one

## Expected Outputs
- Mitigation strategies for each threat
- Implementation plan
- Responsibility assignments

## Completion Gate
Every threat has at least one valid mitigation link.

## Next Steps
After completing Phase 7, proceed to Phase 7.5:
**Use `manage_workflow(action="guidance", phase="7.5")` to continue with Code Validation Analysis**
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
`manage_assumptions(action="add", values=ASSUMPTION)` only for statements that
remain assumptions.

## Tools to Use
- `manage_code_validation(action="describe")`: Load the contract, then record, review, validate, report, or clear findings

## Expected Outputs
- Evidence for every current threat and mitigation
- Explicit remediation and implementation outcomes
- Updated canonical statuses
- Deterministic code-validation report

## Next Steps
After completing Phase 7.5, proceed to Phase 8:
**Use `manage_workflow(action="guidance", phase="8")` to continue with Residual Risk Analysis**
"""

    # Phase 8: Residual Risk Analysis
    elif phase_number == 8:
        return f"""
# Phase {phase_number}: {phase_name}

## Objective
Analyze remaining risks after mitigations are applied and make risk acceptance decisions.

## Steps
1. **Review All Threats and Mitigations**
   - Use `manage_threats(action="list", section="all")` for the complete inventory
   - Review current status of each threat
   - Identify unmitigated or partially mitigated threats

2. **Assess Residual Risk for Each Threat**
   - Use `manage_threats(action="get", section="threats", item_id=ID)` for each threat
   - Choose Open, Accepted, Mitigated, or Not Applicable
   - Record residual severity, likelihood, and rationale

3. **Make Risk Acceptance Decisions**
   - Use `manage_threats(action="assess", section="threats", items=ASSESSMENTS)` for an atomic batch
   - Each item requires `threat_id`, `decision`, and `rationale`
   - Residual severity and likelihood are required except for Not Applicable
   - Threat Composer statuses are derived from the decision

4. **Document Risk Assumptions**
   - Use `manage_assumptions(action="add", values=ASSUMPTION)`
   - Include business risk tolerance decisions
   - Record risk acceptance criteria

## Tools to Use
- `manage_threats(action="list", section="all")`: Review threats and mitigations
- `manage_threats(action="assess", section="threats", items=ASSESSMENTS)`: Record residual-risk decisions
- `manage_assumptions(action="add", values=ASSUMPTION)`: Document risk acceptance assumptions

## Expected Outputs
- Complete residual risk assessment
- Current decision, ratings, and rationale for every threat
- Risk acceptance documentation
- Business risk tolerance assumptions

## Completion Gate
Every current threat has a non-stale residual-risk assessment. Changes to the
threat or its linked mitigations require reassessment.

## Next Steps
After completing Phase 8, proceed to Phase 9:
**Use `manage_workflow(action="guidance", phase="9")` to continue with Output Generation and Documentation**
"""

    # Phase 9: Output Generation and Documentation
    elif phase_number == 9:
        return f"""
# Phase {phase_number}: {phase_name}

## Objective
Generate final documentation and outputs for integration with development processes.

## Steps
1. **Export Comprehensive Threat Model**
   - Use `export_threat_model(output_path="threat_model.json")` to choose a filename, or omit `output_path` for a timestamped name
   - Include all components, threats, mitigations, business context, assumptions, and phase progress
   - Include current threat and mitigation statuses, including updates made during code validation
   - Compatible with AWS Threat Composer and includes extended data
   - Both JSON and Markdown must succeed for the current model

2. **Generate Summary Reports**
   - Use `manage_workflow(action="progress")` to create progress summary
   - Use `manage_assumptions(action="list")` to document all assumptions
   - Create executive summary of threat modeling process
   - Document key findings and recommendations

3. **Create Implementation Documentation**
   - Review all mitigations for implementation guidance
   - Document security requirements derived from threats
   - Create verification criteria for each mitigation

## Tools to Use
- `export_threat_model(output_path="threat_model.json")`: Export the complete model, including current threat and mitigation statuses
- `manage_workflow(action="progress")`: Get progress metrics and completion status
- `manage_assumptions(action="list")`: Get all documented assumptions
- `manage_threats(action="list", section="mitigations")`: Get mitigations for implementation planning

## Expected Outputs
- Comprehensive Threat Composer JSON export with all global variables
- Threat and mitigation statuses captured in the JSON and Markdown exports
- Executive summary document
- Implementation recommendations
- Security requirements documentation

## Completion Gate
The most recent successful two-file export matches the current model fingerprint.
Any later model change reopens this phase.
"""

    # Unknown phase
    else:
        return f"# Phase {phase_number}: {phase_name}\n\nNo detailed guidance available for this phase."


async def get_phase_guidance_impl(
    phase: str = "current",
    directory: Optional[str] = None,
) -> str:
    """Return guidance for an explicit phase or the tracked current phase."""
    if phase == "current":
        requested_phase = current_phase
    else:
        requested_phase = PHASE_BY_SELECTION.get(phase)
        if requested_phase is None:
            choices = ", ".join(("current", *PHASE_BY_SELECTION))
            return f"Invalid phase: {phase}. Choose one of: {choices}."

    logger.info(
        f"Providing guidance for Phase {requested_phase}: "
        f"{PHASES[requested_phase]}"
    )
    guidance = build_phase_guidance(requested_phase)

    if requested_phase != 7:
        return guidance

    search_directory = directory or project_directory
    code_detected = await detect_code_in_directory(search_directory)
    logger.info(
        f"Code detected in directory '{search_directory}': {code_detected}"
    )

    if code_detected:
        next_steps = """## Next Steps
After completing Phase 7, proceed to Phase 7.5 for code validation:
**Use `manage_workflow(action="guidance", phase="7.5")` to continue with Code Validation Analysis**

*Code files were detected in your project, so Phase 7.5 (Code Validation Analysis) will help validate which security controls are already implemented in your codebase and update the threat model accordingly.*"""
    else:
        next_steps = """## Next Steps
After completing Phase 7, proceed directly to Phase 8:
**Use `manage_workflow(action="guidance", phase="8")` to continue with Residual Risk Analysis**

*No code files were detected in your project, so Phase 7.5 (Code Validation Analysis) is being skipped. Proceeding directly to residual risk analysis.*"""

    return guidance.replace(
        """## Next Steps
After completing Phase 7, proceed to Phase 7.5:
**Use `manage_workflow(action="guidance", phase="7.5")` to continue with Code Validation Analysis**""",
        next_steps,
    )


async def export_threat_model_impl(
    ctx: Context,
    output_path: Optional[str] = None,
    include_extended_data: bool = True,
) -> str:
    """Export the model and return a state summary."""
    from datetime import datetime

    from threat_modeling_mcp_server.utils.comprehensive_exporter import (
        export_threat_model_files,
    )
    from threat_modeling_mcp_server.utils.state_collector import get_state_summary

    logger.info("Exporting threat model")

    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        requested_path = (
            output_path
            or f"comprehensive_threat_model_{timestamp}.json"
        )
        export_result = export_threat_model_files(
            requested_path,
            include_extended_data=include_extended_data,
        )
        state_summary = get_state_summary()

        report = f"""
# Threat Model Export Complete

**Execution Timestamp**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Export Results

{export_result}

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

The JSON and Markdown files were written to the `.threatmodel` directory
adjacent to the requested output path.
"""
        return report.strip()
    except Exception as exc:
        error_message = f"Failed to export threat model: {exc}"
        logger.error(error_message)
        return error_message


def get_workflow_status() -> Dict[str, Any]:
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
        "blocking_reasons": list(
            phase_blocking_reasons.get(auto_current_phase, [])
        ),
        "phases": {phase: {"name": name, "completion": phase_completion.get(phase, 0.0)} 
                  for phase, name in PHASES.items()}
    }


def format_workflow_status() -> str:
    """Render a compact workflow status."""
    status = get_workflow_status()
    result = "# Workflow Status\n\n"
    result += (
        f"**Current Phase:** {status['current_phase']} - "
        f"{status['current_phase_name']}\n\n"
    )
    result += (
        f"**Current Phase Completion:** "
        f"{status['current_phase_completion']:.0%}\n\n"
    )
    result += f"**Overall Completion:** {status['overall_completion']:.0%}\n"
    if status["blocking_reasons"]:
        result += "\n**Missing Work:**\n"
        for reason in status["blocking_reasons"]:
            result += f"- {reason}\n"
    return result


def build_workflow_progress() -> str:
    """Render detailed progress for every workflow phase."""
    logger.info("Getting threat modeling progress")
    detect_phase_completion()
    auto_current_phase = get_current_phase_auto()
    total_phases = len(PHASES)
    completed_count = sum(
        1 for completion in phase_completion.values() if completion >= 1.0
    )
    overall_percentage = int((completed_count / total_phases) * 100)

    result = "# Threat Modeling Progress\n\n"
    result += (
        f"**Overall Progress:** {overall_percentage}% "
        f"({completed_count}/{total_phases} phases completed)\n\n"
    )
    result += (
        f"**Current Phase:** {auto_current_phase} - "
        f"{PHASES.get(auto_current_phase, 'Unknown')}\n\n"
    )
    result += "## Phase Status\n\n"

    for phase_number in sorted(PHASES):
        phase_name = PHASES[phase_number]
        completion = phase_completion.get(phase_number, 0.0)
        if completion >= 1.0:
            status = "✅ Completed"
        elif phase_number == auto_current_phase:
            status = "🔄 In Progress"
        else:
            status = "⏳ Pending"
        result += f"- **Phase {phase_number}: {phase_name}:** {status}\n"
        if completion < 1.0:
            for reason in phase_blocking_reasons.get(phase_number, []):
                result += f"  - Missing: {reason}\n"

    return result


def workflow_guide() -> str:
    """Describe the consolidated workflow actions."""
    return """# Workflow Manager

Actions:
- `describe`: Show this action guide
- `plan`: Complete methodology; accepts `directory` and `auto_validate_code`
- `guidance`: Focused phase guidance; accepts `phase` and optional `directory`
- `status`: Compact current-phase status
- `set_project`: Record the project path in `directory`
- `advance`: Advance only when all phases through the current phase are complete
- `progress`: Detailed status for every phase

Use `export_threat_model` for JSON and Markdown output.
"""


async def manage_workflow_impl(
    ctx: Context,
    action: str,
    phase: Optional[str] = None,
    directory: Optional[str] = None,
    auto_validate_code: Optional[bool] = None,
) -> str:
    """Dispatch one workflow operation."""
    action = action.strip().lower()
    valid_actions = {
        "describe", "plan", "guidance", "status", "set_project", "advance",
        "progress",
    }
    if action not in valid_actions:
        return (
            f"❌ Unknown workflow action '{action}'. Valid actions: "
            + ", ".join(sorted(valid_actions))
        )

    allowed_arguments = {
        "describe": set(),
        "plan": {"directory", "auto_validate_code"},
        "guidance": {"phase", "directory"},
        "status": set(),
        "set_project": {"directory"},
        "advance": set(),
        "progress": set(),
    }
    supplied_arguments = {
        name for name, value in {
            "phase": phase,
            "directory": directory,
            "auto_validate_code": auto_validate_code,
        }.items()
        if value is not None
    }
    unexpected = supplied_arguments - allowed_arguments[action]
    if unexpected:
        return (
            f"❌ action='{action}' does not accept: "
            + ", ".join(sorted(unexpected))
        )

    if action == "describe":
        return workflow_guide()
    if action == "plan":
        return await generate_threat_modeling_plan(
            ctx,
            directory or project_directory,
            True if auto_validate_code is None else auto_validate_code,
        )
    if action == "guidance":
        return await get_phase_guidance_impl(phase or "current", directory)
    if action == "status":
        return format_workflow_status()
    if action == "set_project":
        if not directory:
            return "❌ action='set_project' requires directory."
        return set_project_directory(directory)
    if action == "advance":
        return await advance_phase_impl(ctx)
    return build_workflow_progress()


def register_tools(mcp):
    """Register the consolidated workflow and export tools."""

    @mcp.tool()
    async def manage_workflow(
        ctx: Context,
        action: WorkflowAction = Field(
            description=(
                "Operation: describe, plan, guidance, status, set_project, "
                "advance, or progress"
            ),
        ),
        phase: Optional[PhaseSelection] = Field(
            default=None,
            description=(
                "Phase for action='guidance': current, 1, 2, 3, 4, 5, 6, "
                "7, 7.5, 8, or 9"
            ),
        ),
        directory: Optional[str] = Field(
            default=None,
            description=(
                "Project directory for plan, guidance, or set_project"
            ),
        ),
        auto_validate_code: Optional[bool] = Field(
            default=None,
            description=(
                "For action='plan', include Phase 7.5 when code is detected; "
                "defaults to true"
            ),
        ),
    ) -> str:
        """Plan, guide, inspect, configure, or advance the workflow."""
        return await manage_workflow_impl(
            ctx,
            action,
            phase,
            directory,
            auto_validate_code,
        )

    @mcp.tool()
    async def export_threat_model(
        ctx: Context,
        output_path: Optional[str] = Field(
            default=None,
            description=(
                "Requested output path; omit for a timestamped filename"
            ),
        ),
        include_extended_data: bool = Field(
            default=True,
            description=(
                "Include architecture, taxonomy profiles, workflow progress, "
                "and other server extensions"
            ),
        ),
    ) -> str:
        """Export Threat Composer JSON and Markdown plus a state summary."""
        return await export_threat_model_impl(
            ctx,
            output_path,
            include_extended_data,
        )
