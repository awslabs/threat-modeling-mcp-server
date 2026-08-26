"""Integration tests for the compact public MCP domain managers."""

import re

import pytest

import threat_modeling_mcp_server.server as srv
from threat_modeling_mcp_server.tools import architecture_analyzer as architecture
from threat_modeling_mcp_server.tools import assumption_manager as assumptions
from threat_modeling_mcp_server.tools import threat_actor_analyzer as actors
from threat_modeling_mcp_server.tools import threat_generator as threats
from threat_modeling_mcp_server.tools import trust_boundary_analyzer as boundaries
from threat_modeling_mcp_server.validation.instruction_validator import (
    validate_instructions_against_tools,
)


pytestmark = pytest.mark.usefixtures("empty_threat_model_state")

RETIRED_DOMAIN_TOOL_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_])(?:"
    r"(?:add|update|list|get|delete|clear)_"
    r"(?:assumptions?|components?|connections?|data_stores?|threat_actors?|"
    r"trust_zones?|crossing_points?|trust_boundaries?|assets?|flows?|threats?|"
    r"mitigations?)|"
    r"(?:add|remove)_component_(?:to|from)_zone|"
    r"(?:add_conn_to|remove_conn_from)_crossing|"
    r"(?:set_threat_actor_(?:priority|relevance)|analyze_threat_actors|"
    r"reset_threat_actors)|"
    r"(?:link|unlink)_mitigation_(?:to|from)_threat|"
    r"get_(?:architecture_analysis|trust_boundary_(?:analysis|detection))_plan"
    r")(?![A-Za-z0-9_])"
)
RETIRED_PHASE_TOOL_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_])(?:follow_threat_modeling_plan|"
    r"get_phase_(?:[1-9]|7_5)_guidance)(?![A-Za-z0-9_])"
)
RETIRED_CONSOLIDATED_TOOL_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_])(?:"
    r"get_threat_modeling_plan|get_phase_guidance|"
    r"execute_final_export_step|get_current_phase_status|"
    r"set_project_directory_tool|advance_phase|get_threat_model_progress|"
    r"export_comprehensive_threat_model|get_data_model_types|list_data_models"
    r")(?![A-Za-z0-9_])"
)


async def call(name, **arguments):
    _, structured = await srv.mcp.call_tool(name, arguments)
    return structured["result"]


def added_id(result):
    return result.rsplit(": ", 1)[1]


def test_registry_exposes_only_compact_domain_tools():
    names = {tool.name for tool in srv.mcp._tool_manager.list_tools()}
    managers = {
        "manage_assumptions",
        "manage_architecture",
        "manage_threat_actors",
        "manage_trust_boundaries",
        "manage_asset_flows",
        "manage_threats",
    }
    assert len(names) == 11
    assert managers <= names
    assert {
        "manage_workflow",
        "export_threat_model",
        "inspect_data_models",
    } <= names
    assert names.isdisjoint({
        "follow_threat_modeling_plan",
        "get_phase_1_guidance",
        "get_phase_2_guidance",
        "get_phase_3_guidance",
        "get_phase_4_guidance",
        "get_phase_5_guidance",
        "get_phase_6_guidance",
        "get_phase_7_guidance",
        "get_phase_7_5_guidance",
        "get_phase_8_guidance",
        "get_phase_9_guidance",
    })
    assert not {
        name for name in names if RETIRED_DOMAIN_TOOL_PATTERN.fullmatch(name)
    }
    valid, issues = validate_instructions_against_tools(
        srv.SERVER_INSTRUCTIONS,
        srv.TOOL_MODULES,
    )
    assert valid, issues


@pytest.mark.asyncio
async def test_describe_returns_section_specific_contracts():
    cases = [
        (
            "manage_assumptions",
            {"action": "describe"},
            ["Assumption Manager", "`description`", "`category`"],
        ),
        (
            "manage_architecture",
            {"action": "describe", "section": "components"},
            ["Architecture: Components", "Compute", "AWS"],
        ),
        (
            "manage_threat_actors",
            {"action": "describe"},
            ["Threat Actor Manager", "Nation-State / APT", "Government"],
        ),
        (
            "manage_trust_boundaries",
            {"action": "describe", "section": "crossing_points"},
            ["Trust Boundaries: Crossing Points", "Multi-factor", "Role-based"],
        ),
        (
            "manage_asset_flows",
            {"action": "describe", "section": "assets"},
            ["Asset Flows: Assets", "Restricted", "At rest"],
        ),
        (
            "manage_threats",
            {"action": "describe", "section": "mitigations"},
            ["Threats: Mitigations", "Preventive", "mitigationResolved"],
        ),
    ]

    for name, arguments, expected in cases:
        result = await call(name, **arguments)
        for text in expected:
            assert text in result


@pytest.mark.asyncio
async def test_assumption_manager_supports_batch_and_crud():
    result = await call(
        "manage_assumptions",
        action="add",
        items=[
            {
                "description": "The IdP is available",
                "category": "Authentication",
                "impact": "Login depends on it",
                "rationale": "Managed service",
            },
            {
                "description": "Traffic uses TLS",
                "category": "Network",
                "impact": "Protects data in transit",
                "rationale": "Platform policy",
            },
        ],
    )
    assert "Successfully added 2 assumption(s)" in result

    assumption_id = next(iter(assumptions.assumptions))
    result = await call(
        "manage_assumptions",
        action="update",
        item_id=assumption_id,
        values={"impact": "Updated impact"},
    )
    assert "updated successfully" in result
    assert "Updated impact" in await call(
        "manage_assumptions",
        action="get",
        item_id=assumption_id,
    )

    result = await call(
        "manage_assumptions",
        action="delete",
        item_ids=list(assumptions.assumptions),
    )
    assert "Successfully deleted 2 assumption(s)" in result


@pytest.mark.asyncio
async def test_architecture_manager_routes_entities_plan_and_clear():
    result = await call(
        "manage_architecture",
        action="add",
        section="components",
        items=[
            {"name": "Client", "type": "Compute"},
            {"name": "API", "type": "Compute", "service_provider": "AWS"},
        ],
    )
    assert "Successfully added 2 component(s)" in result
    source_id, destination_id = architecture.components

    connection_id = added_id(await call(
        "manage_architecture",
        action="add",
        section="connections",
        values={
            "source_id": source_id,
            "destination_id": destination_id,
            "protocol": "HTTPS",
            "encryption": True,
        },
    ))
    await call(
        "manage_architecture",
        action="add",
        section="data_stores",
        values={
            "name": "Records",
            "type": "Relational",
            "classification": "Confidential",
        },
    )

    complete = await call(
        "manage_architecture",
        action="list",
        section="all",
    )
    assert "Client" in complete
    assert connection_id in complete
    assert "Records" in complete

    blocked = await call(
        "manage_architecture",
        action="delete",
        section="components",
        item_id=source_id,
    )
    assert "Cannot delete" in blocked

    plan = await call(
        "manage_architecture",
        action="plan",
        section="all",
    )
    assert "Architecture Analysis Plan" in plan

    result = await call(
        "manage_architecture",
        action="clear",
        section="all",
    )
    assert result == "Architecture cleared."


@pytest.mark.asyncio
async def test_threat_actor_manager_updates_assessment_and_special_actions():
    result = await call(
        "manage_threat_actors",
        action="add",
        values={
            "name": "Targeted criminal group",
            "type": "External Attacker",
            "sophistication_tier": "Tier 3 - Organized cybercrime",
            "motivations": ["Financial gain"],
            "resources": "Team",
        },
    )
    actor_id = added_id(result)

    result = await call(
        "manage_threat_actors",
        action="update",
        item_id=actor_id,
        values={"priority": 2, "is_relevant": False},
    )
    assert "updated successfully" in result
    assert actors.threat_actors[actor_id].priority == 2
    assert actors.threat_actors[actor_id].is_relevant is False

    rejected = await call(
        "manage_threat_actors",
        action="update",
        item_id=actor_id,
        values={"priority": 11},
    )
    assert rejected.startswith("❌ threat actor failed:")
    assert actors.threat_actors[actor_id].priority == 2

    assert actor_id in await call(
        "manage_threat_actors",
        action="get",
        item_id=actor_id,
    )
    assert "Threat Actor Analysis" in await call(
        "manage_threat_actors",
        action="analyze",
    )
    assert await call("manage_threat_actors", action="clear") == (
        "All threat actors cleared."
    )
    assert await call("manage_threat_actors", action="reset") == (
        "Threat actors reset to default set."
    )


@pytest.mark.asyncio
async def test_trust_boundary_manager_routes_crud_relationships_and_plans():
    await call(
        "manage_architecture",
        action="add",
        section="components",
        items=[
            {"name": "Internet", "type": "Network"},
            {"name": "API", "type": "Compute"},
        ],
    )
    source_id, destination_id = architecture.components
    connection_id = added_id(await call(
        "manage_architecture",
        action="add",
        section="connections",
        values={
            "source_id": source_id,
            "destination_id": destination_id,
            "protocol": "HTTPS",
        },
    ))

    zone_ids = []
    for name, level in [("Public", "Untrusted"), ("Service", "High")]:
        zone_ids.append(added_id(await call(
            "manage_trust_boundaries",
            action="add",
            section="zones",
            values={"name": name, "trust_level": level},
        )))

    await call(
        "manage_trust_boundaries",
        action="link",
        section="zones",
        items=[
            {"zone_id": zone_ids[0], "node_id": source_id},
            {"zone_id": zone_ids[1], "node_id": destination_id},
        ],
    )
    crossing_id = added_id(await call(
        "manage_trust_boundaries",
        action="add",
        section="crossing_points",
        values={
            "source_zone_id": zone_ids[0],
            "destination_zone_id": zone_ids[1],
            "authentication_method": "Token",
            "authorization_method": "Role-based",
        },
    ))
    await call(
        "manage_trust_boundaries",
        action="link",
        section="crossing_points",
        values={
            "crossing_point_id": crossing_id,
            "connection_id": connection_id,
        },
    )
    boundary_id = added_id(await call(
        "manage_trust_boundaries",
        action="add",
        section="boundaries",
        values={
            "name": "Internet boundary",
            "type": "Network",
            "crossing_point_ids": [crossing_id],
            "controls": ["WAF"],
        },
    ))

    assert boundary_id in await call(
        "manage_trust_boundaries",
        action="get",
        section="boundaries",
        item_id=boundary_id,
    )
    assert "Trust Boundary Analysis Plan" in await call(
        "manage_trust_boundaries",
        action="analysis_plan",
        section="all",
    )
    assert "Trust Boundary Detection Analysis Plan" in await call(
        "manage_trust_boundaries",
        action="detection_plan",
        section="all",
    )

    await call(
        "manage_trust_boundaries",
        action="unlink",
        section="crossing_points",
        values={
            "crossing_point_id": crossing_id,
            "connection_id": connection_id,
        },
    )
    assert boundaries.crossing_points[crossing_id].connection_ids == []
    assert await call(
        "manage_trust_boundaries",
        action="clear",
        section="all",
    ) == "All trust boundaries, crossing points, and trust zones cleared."


@pytest.mark.asyncio
async def test_architecture_relationships_treat_data_stores_as_nodes():
    component_id = added_id(await call(
        "manage_architecture",
        action="add",
        section="components",
        values={"name": "API", "type": "Compute"},
    ))
    data_store_id = added_id(await call(
        "manage_architecture",
        action="add",
        section="data_stores",
        values={
            "name": "Records",
            "type": "Relational",
            "classification": "Confidential",
        },
    ))
    connection_id = added_id(await call(
        "manage_architecture",
        action="add",
        section="connections",
        values={
            "source_id": component_id,
            "destination_id": data_store_id,
            "protocol": "HTTPS",
        },
    ))

    listed = await call(
        "manage_architecture",
        action="list",
        section="connections",
        values={"node_id": data_store_id},
    )
    assert "API" in listed
    assert "Records" in listed

    zone_id = added_id(await call(
        "manage_trust_boundaries",
        action="add",
        section="zones",
        values={"name": "Data", "trust_level": "High"},
    ))
    linked = await call(
        "manage_trust_boundaries",
        action="link",
        section="zones",
        values={"zone_id": zone_id, "node_id": data_store_id},
    )
    assert "added to trust zone" in linked
    assert boundaries.trust_zones[zone_id].contained_nodes == [data_store_id]

    blocked = await call(
        "manage_architecture",
        action="delete",
        section="data_stores",
        item_id=data_store_id,
    )
    assert connection_id in blocked
    assert zone_id in blocked


@pytest.mark.asyncio
async def test_trust_relationships_reject_unknown_nodes_and_connections():
    zone_id = added_id(await call(
        "manage_trust_boundaries",
        action="add",
        section="zones",
        values={"name": "Service", "trust_level": "Medium"},
    ))
    result = await call(
        "manage_trust_boundaries",
        action="link",
        section="zones",
        values={"zone_id": zone_id, "node_id": "D404"},
    )
    assert result == "Architecture node with ID D404 not found."

    other_zone_id = added_id(await call(
        "manage_trust_boundaries",
        action="add",
        section="zones",
        values={"name": "Data", "trust_level": "High"},
    ))
    crossing_id = added_id(await call(
        "manage_trust_boundaries",
        action="add",
        section="crossing_points",
        values={
            "source_zone_id": zone_id,
            "destination_zone_id": other_zone_id,
        },
    ))
    result = await call(
        "manage_trust_boundaries",
        action="link",
        section="crossing_points",
        values={
            "crossing_point_id": crossing_id,
            "connection_id": "CN404",
        },
    )
    assert result == "Connection with ID CN404 not found."


@pytest.mark.asyncio
async def test_asset_flow_manager_routes_crud_and_clear():
    await call(
        "manage_architecture",
        action="add",
        section="components",
        items=[
            {"name": "Producer", "type": "Compute"},
            {"name": "Consumer", "type": "Compute"},
        ],
    )
    source_id, destination_id = architecture.components
    asset_id = added_id(await call(
        "manage_asset_flows",
        action="add",
        section="assets",
        values={
            "name": "Customer data",
            "type": "Data",
            "classification": "Restricted",
            "data_states": ["In transit"],
        },
    ))
    flow_id = added_id(await call(
        "manage_asset_flows",
        action="add",
        section="flows",
        values={
            "asset_id": asset_id,
            "source_id": source_id,
            "destination_id": destination_id,
            "controls": ["Encryption"],
        },
    ))

    assert flow_id in await call(
        "manage_asset_flows",
        action="get",
        section="flows",
        item_id=flow_id,
    )
    result = await call(
        "manage_asset_flows",
        action="update",
        section="flows",
        item_id=flow_id,
        values={"risk_level": 2, "encryption": True},
    )
    assert "updated successfully" in result
    assert "Customer data" in await call(
        "manage_asset_flows",
        action="list",
        section="all",
    )

    assert await call(
        "manage_asset_flows",
        action="clear",
        section="all",
    ) == "All assets and flows have been cleared."


@pytest.mark.asyncio
async def test_threat_manager_routes_crud_and_links():
    threat_id = added_id(await call(
        "manage_threats",
        action="add",
        section="threats",
        values={
            "threat_source": "An attacker",
            "prerequisites": "with network access",
            "threat_action": "spoof a session",
            "threat_impact": "account compromise",
            "category": "Spoofing",
        },
    ))
    mitigation_id = added_id(await call(
        "manage_threats",
        action="add",
        section="mitigations",
        values={
            "content": "Validate signed session tokens",
            "type": "Preventive",
        },
    ))

    result = await call(
        "manage_threats",
        action="link",
        section="mitigations",
        values={"mitigation_id": mitigation_id, "threat_id": threat_id},
    )
    assert "linked to threat" in result
    assert len(threats.mitigation_links) == 1
    assert mitigation_id in await call(
        "manage_threats",
        action="get",
        section="threats",
        item_id=threat_id,
    )

    result = await call(
        "manage_threats",
        action="unlink",
        section="mitigations",
        values={"mitigation_id": mitigation_id, "threat_id": threat_id},
    )
    assert "unlinked from threat" in result
    assert threats.mitigation_links == []


@pytest.mark.asyncio
async def test_threat_manager_batches_links_and_assesses_residual_risk():
    threat_ids = []
    for action in ["spoof a session", "tamper with a record"]:
        threat_ids.append(added_id(await call(
            "manage_threats",
            action="add",
            section="threats",
            values={
                "threat_source": "An attacker",
                "prerequisites": "with network access",
                "threat_action": action,
                "threat_impact": "account compromise",
            },
        )))
    mitigation_id = added_id(await call(
        "manage_threats",
        action="add",
        section="mitigations",
        values={"content": "Require signed and authorized requests"},
    ))

    linked = await call(
        "manage_threats",
        action="link",
        section="mitigations",
        items=[
            {"mitigation_id": mitigation_id, "threat_id": threat_id}
            for threat_id in threat_ids
        ],
    )
    assert "Successfully added 2 mitigation-to-threat link(s)" in linked

    assessed = await call(
        "manage_threats",
        action="assess",
        section="threats",
        items=[
            {
                "threat_id": threat_ids[0],
                "decision": "Mitigated",
                "residual_severity": "Low",
                "residual_likelihood": "Unlikely",
                "rationale": "The request controls address this path.",
            },
            {
                "threat_id": threat_ids[1],
                "decision": "Open",
                "residual_severity": "Medium",
                "residual_likelihood": "Possible",
                "rationale": "An implementation review is still needed.",
            },
        ],
    )
    assert "Successfully assessed residual risk for 2 threat(s)" in assessed
    assert set(threats.residual_risk_assessments) == set(threat_ids)


@pytest.mark.asyncio
async def test_threat_enum_errors_list_valid_options_without_partial_update():
    threat_id = added_id(await call(
        "manage_threats",
        action="add",
        section="threats",
        values={
            "threat_source": "An attacker",
            "prerequisites": "with access",
            "threat_action": "modify state",
            "threat_impact": "loss of integrity",
            "severity": "High",
        },
    ))

    result = await call(
        "manage_threats",
        action="update",
        section="threats",
        item_id=threat_id,
        values={"threat_source": "Changed", "severity": "Catastrophic"},
    )

    assert result.startswith("❌ threat failed:")
    assert "Valid options are" in result
    assert threats.threats[threat_id].threatSource == "An attacker"
    assert threats.threats[threat_id].severity.value == "High"


@pytest.mark.asyncio
async def test_manager_payload_errors_are_actionable_and_non_mutating():
    result = await call(
        "manage_architecture",
        action="add",
        section="components",
        values={"name": "API", "typo": "Compute"},
    )
    assert result.startswith("❌ component:")
    assert "missing required field(s): type" in result
    assert "unexpected field(s): typo" in result
    assert architecture.components == {}

    result = await call(
        "manage_threats",
        action="add",
        section="all",
        values={},
    )
    assert result == "❌ Choose threats or mitigations for this action."

    result = await call(
        "manage_assumptions",
        action="describe",
        values={"unexpected": True},
    )
    assert "does not accept values" in result


@pytest.mark.asyncio
async def test_agent_guidance_has_no_retired_domain_tool_names():
    from pathlib import Path

    sources = {
        "workflow plan": await call(
            "manage_workflow",
            action="plan",
            directory=".",
            auto_validate_code=False,
        ),
        "architecture plan": await call(
            "manage_architecture",
            action="plan",
            section="all",
        ),
        "trust-boundary analysis plan": await call(
            "manage_trust_boundaries",
            action="analysis_plan",
            section="all",
        ),
        "trust-boundary detection plan": await call(
            "manage_trust_boundaries",
            action="detection_plan",
            section="all",
        ),
    }
    for phase in ["1", "2", "3", "4", "5", "6", "7", "7.5", "8", "9"]:
        sources[f"phase {phase} guidance"] = await call(
            "manage_workflow",
            action="guidance",
            phase=phase,
        )

    root = Path(__file__).resolve().parent.parent
    paths = [root / "README.md", root / "DEVELOPING.md"]
    paths.extend((root / ".kiro").rglob("*.md"))
    sources.update({
        str(path.relative_to(root)): path.read_text()
        for path in paths
    })

    for source, text in sources.items():
        stale = sorted(set(RETIRED_DOMAIN_TOOL_PATTERN.findall(text)))
        assert not stale, f"{source} references {stale}"
        stale_phase_tools = sorted(set(RETIRED_PHASE_TOOL_PATTERN.findall(text)))
        assert not stale_phase_tools, (
            f"{source} references retired phase tools {stale_phase_tools}"
        )
        stale_consolidated_tools = sorted(
            set(RETIRED_CONSOLIDATED_TOOL_PATTERN.findall(text))
        )
        assert not stale_consolidated_tools, (
            f"{source} references retired tools {stale_consolidated_tools}"
        )


@pytest.mark.asyncio
async def test_threat_modeling_plan_honors_code_validation_option(tmp_path):
    (tmp_path / "app.py").write_text("pass", encoding="utf-8")

    included = await call(
        "manage_workflow",
        action="plan",
        directory=str(tmp_path),
        auto_validate_code=True,
    )
    omitted = await call(
        "manage_workflow",
        action="plan",
        directory=str(tmp_path),
        auto_validate_code=False,
    )

    phase_heading = "## Phase 7.5: Code Validation Analysis"
    assert phase_heading in included
    assert phase_heading not in omitted


@pytest.mark.asyncio
async def test_workflow_and_data_model_consolidation(tmp_path):
    guide = await call("manage_workflow", action="describe")
    assert "`plan`" in guide
    assert "`advance`" in guide

    rejected = await call(
        "manage_workflow",
        action="status",
        directory=str(tmp_path),
    )
    assert rejected == "❌ action='status' does not accept: directory"

    models = await call("inspect_data_models")
    assert "SensitivityTier" in models
    values = await call(
        "inspect_data_models",
        model_name="SensitivityTier",
    )
    assert '"Confidential"' in values
