"""Tests for server instructions, live state, and generated guidance."""

import re
import pytest

import threat_modeling_mcp_server.models.models as M


class _Ctx:
    """Minimal MCP context stub."""

    async def error(self, *args, **kwargs):
        pass

    async def info(self, *args, **kwargs):
        pass


class TestServerContract:
    """Every registered tool must be documented in the server instructions."""

    def test_instruction_validator_passes(self):
        import threat_modeling_mcp_server.server as srv
        from threat_modeling_mcp_server.validation.instruction_validator import (
            validate_instructions_against_tools,
        )

        is_valid, issues = validate_instructions_against_tools(
            srv.SERVER_INSTRUCTIONS, srv.TOOL_MODULES
        )
        assert is_valid, f"undocumented or stale tools: {issues}"


class TestStateCollectionIsNotStale:
    """The collector must read live module state, not from-imported values."""

    @pytest.mark.asyncio
    async def test_rebinding_a_module_global_is_visible(self):
        import threat_modeling_mcp_server.tools.architecture_analyzer as arch
        from threat_modeling_mcp_server.utils.state_collector import collect_all_state

        saved = dict(arch.components)
        try:
            await arch.add_component_impl(_Ctx(), "Audit API", "Compute")
            assert len(collect_all_state().components) == len(saved) + 1

            arch.components = {}  # a clear that rebinds rather than mutates
            assert collect_all_state().components == {}
        finally:
            arch.components = saved

    def test_current_phase_is_read_live(self):
        import threat_modeling_mcp_server.tools.step_orchestrator as orch
        from threat_modeling_mcp_server.utils.state_collector import collect_all_state

        saved = orch.current_phase
        try:
            orch.current_phase = 4
            assert collect_all_state().current_phase == 4
        finally:
            orch.current_phase = saved

    @pytest.mark.asyncio
    async def test_actor_and_zone_clears_are_visible(self):
        import threat_modeling_mcp_server.tools.threat_actor_analyzer as taa
        import threat_modeling_mcp_server.tools.trust_boundary_analyzer as tba
        from threat_modeling_mcp_server.utils.state_collector import collect_all_state

        saved_actors, saved_zones = dict(taa.threat_actors), dict(tba.trust_zones)
        try:
            taa.threat_actors = {}
            tba.trust_zones = {}
            state = collect_all_state()
            assert state.threat_actors == {} and state.trust_zones == {}
        finally:
            taa.threat_actors = saved_actors
            tba.trust_zones = saved_zones


class TestAnalysisPlanGuidance:
    """The LLM-facing analysis plan must only name valid literals."""

    def test_plan_uses_current_regulatory_and_deployment_labels(self):
        from threat_modeling_mcp_server.tools.business_context import (
            build_business_context_analysis_plan,
        )

        plan = build_business_context_analysis_plan()

        assert "CCPA / CPRA" in plan and "FISMA / FedRAMP" in plan
        assert "Multiple / other" in plan
        assert "- FISMA: " not in plan and "- CCPA: " not in plan
        assert "Deployment Environment" not in plan
        # geographic facets must be requested
        for facet in ("data_residency", "compute_location", "user_base_location",
                      "organizational_headquarters"):
            assert facet in plan, f"analysis plan does not ask for {facet}"

    def test_every_regulatory_literal_in_the_plan_is_valid(self):
        from threat_modeling_mcp_server.tools.business_context import (
            build_business_context_analysis_plan,
        )

        plan = build_business_context_analysis_plan()
        section = plan.split("5. **Regulatory Requirements Analysis**")[1]
        section = section.split("6. **System Criticality")[0]

        listed = [
            line.strip().lstrip("- ").split(":")[0].strip()
            for line in section.splitlines()
            if line.strip().startswith("- ")
        ]
        valid = {r.value for r in M.RegulatoryRequirement}
        assert set(listed) == valid, (
            f"plan lists {sorted(set(listed))} but the enum is {sorted(valid)}"
        )


class TestNoStaleEnumMemberReferences:
    """Renaming an enum member must not leave dangling references behind."""

    def test_every_enum_member_reference_resolves(self):
        import ast
        import inspect
        from enum import Enum
        from pathlib import Path

        from threat_modeling_mcp_server.tools.data_model_types import DATA_MODELS

        repo_root = Path(__file__).resolve().parent.parent
        dangling = []

        for root in ("threat_modeling_mcp_server", "tests"):
            for path in (repo_root / root).rglob("*.py"):
                tree = ast.parse(path.read_text(encoding="utf-8"))
                for node in ast.walk(tree):
                    if not (isinstance(node, ast.Attribute)
                            and isinstance(node.value, ast.Name)):
                        continue
                    enum_cls = DATA_MODELS.get(node.value.id)
                    if not (enum_cls and inspect.isclass(enum_cls)
                            and issubclass(enum_cls, Enum)):
                        continue
                    if node.attr.startswith("_") or node.attr in ("value", "name"):
                        continue
                    if node.attr not in enum_cls.__members__:
                        dangling.append(
                            f"{path.relative_to(repo_root)}:{node.lineno}: "
                            f"{node.value.id}.{node.attr} does not exist"
                        )

        assert not dangling, "stale enum member references:\n" + "\n".join(dangling)

    @pytest.mark.asyncio
    async def test_threat_actor_analysis_runs(self):
        # Smoke-test enum use throughout actor analysis.
        import threat_modeling_mcp_server.tools.threat_actor_analyzer as taa

        taa.initialize_threat_actors()
        result = await taa.analyze_threat_actors_impl(_Ctx())
        assert "Financial Motivation" in result


class TestGuidanceMentionsGeographicFacets:
    """Agent-facing guidance must ask for all four facets."""

    def test_every_required_feature_has_a_description(self):
        import threat_modeling_mcp_server.tools.business_context as bctx

        undocumented = [
            feature for feature in bctx.REQUIRED_BUSINESS_CONTEXT_FEATURES
            if feature not in bctx.FEATURE_DESCRIPTIONS
        ]
        assert not undocumented, f"features without a description: {undocumented}"

    def test_plan_and_prompt_list_the_facets(self):
        from pathlib import Path

        repo_root = Path(__file__).resolve().parent.parent
        plan_source = (
            repo_root / "threat_modeling_mcp_server" / "tools" / "threat_model_plan.py"
        ).read_text(encoding="utf-8")
        prompt = (repo_root / ".kiro" / "prompts" / "threat-modeler.md").read_text(
            encoding="utf-8"
        )

        for facet in ("data_residency", "compute_location", "user_base_location",
                      "organizational_headquarters"):
            assert facet in plan_source, f"plan does not mention {facet}"
            assert facet in prompt, f"prompt does not mention {facet}"

        assert "11 required features" not in prompt
        assert "12 required features" in prompt


class TestDocumentationTracksToolRegistry:
    """Documentation must remain synchronized with registered tools and enums."""

    @staticmethod
    def _readme():
        from pathlib import Path

        return (Path(__file__).resolve().parent.parent / "README.md").read_text()

    @staticmethod
    def _registered_tool_names():
        import threat_modeling_mcp_server.server as srv

        return {tool.name for tool in srv.mcp._tool_manager.list_tools()}

    def test_every_auto_approve_array_lists_every_tool(self):
        import json

        arrays = re.findall(r'"autoApprove": \[([^\]]*)\]', self._readme())
        populated = [array for array in arrays if array.strip()]
        assert len(populated) == 3

        registered = self._registered_tool_names()
        for index, array in enumerate(populated, start=1):
            listed = set(json.loads("[" + array + "]"))
            assert listed == registered, (
                f"autoApprove array {index} is out of date.\n"
                f"  registered but not approved: {sorted(registered - listed)}\n"
                f"  approved but not registered: {sorted(listed - registered)}"
            )

    def test_tools_overview_counts_add_up(self):
        readme = self._readme()
        table = readme.split("## Tools Overview", 1)[1].split("\n## ", 1)[0]
        counts = [int(number) for number in re.findall(
            r"\|\s*(\d+) tools?\s*\|", table,
        )]
        total = len(self._registered_tool_names())

        assert sum(counts) == total
        assert f"**{total} tools**" in readme

    def test_tools_overview_counts_match_registering_modules(self):
        from mcp.server.fastmcp import FastMCP
        import threat_modeling_mcp_server.server as srv

        per_module = []
        for module in srv.TOOL_MODULES:
            probe = FastMCP("probe")
            module.register_tools(probe)
            per_module.append(len(probe._tool_manager.list_tools()))

        table = self._readme().split("## Tools Overview", 1)[1].split(
            "\n## ", 1,
        )[0]
        documented = [int(number) for number in re.findall(
            r"\|\s*(\d+) tools?\s*\|", table,
        )]

        assert documented == per_module

    @pytest.mark.parametrize(
        "filename", ["README.md", ".kiro/prompts/threat-modeler.md"],
    )
    def test_severity_and_mitigation_vocabularies_are_real(self, filename):
        from pathlib import Path
        from threat_modeling_mcp_server.models.threat_models import (
            MitigationType,
            ThreatLikelihood,
            ThreatSeverity,
        )

        text = (Path(__file__).resolve().parent.parent / filename).read_text()
        for retired in ["Info", "Almost Certain", "Rare", "Compensating"]:
            assert not re.search(rf"\b{re.escape(retired)}\b", text)

        for enum_class in (ThreatSeverity, ThreatLikelihood, MitigationType):
            for member in enum_class:
                assert member.value in text

    def test_kiro_asset_guidance_matches_model_fields(self):
        from pathlib import Path
        from threat_modeling_mcp_server.models.asset_flow_models import Asset
        from threat_modeling_mcp_server.tools.domain_managers import asset_flow_guide

        prompt = (
            Path(__file__).resolve().parent.parent
            / ".kiro/prompts/threat-modeler.md"
        ).read_text()
        assert 'manage_asset_flows(action="describe", section=SECTION)' in prompt

        guide = asset_flow_guide("assets")
        for field in Asset.model_fields:
            if field != "id":
                assert f"`{field}`" in guide
