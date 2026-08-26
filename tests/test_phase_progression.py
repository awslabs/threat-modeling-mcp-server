"""Regression tests for phase completion and advancement."""

import pytest


class _Ctx:
    """Minimal MCP context stub."""

    async def error(self, *args, **kwargs):
        pass

    async def info(self, *args, **kwargs):
        pass


class TestPhaseGatingFailsClosed:
    """advance_phase must not fabricate completion; clearing must reopen phase 1."""

    @pytest.mark.asyncio
    async def test_advance_phase_refuses_when_phase_incomplete(self):
        import threat_modeling_mcp_server.tools.business_context as bctx
        import threat_modeling_mcp_server.tools.step_orchestrator as orch

        await bctx.clear_business_context_impl(_Ctx())
        orch.current_phase = 1
        orch.phase_completion[1] = 0.0

        result = await orch.advance_phase_impl(_Ctx()) if hasattr(orch, "advance_phase_impl") \
            else None
        if result is None:
            pytest.skip("advance_phase is only exposed as a registered tool")
        assert "Cannot advance" in result
        assert orch.phase_completion[1] < 1.0

    @pytest.mark.asyncio
    async def test_clearing_context_reopens_phase_one(self):
        import threat_modeling_mcp_server.tools.business_context as bctx
        import threat_modeling_mcp_server.tools.step_orchestrator as orch
        from threat_modeling_mcp_server.utils.state_collector import get_state_summary

        await bctx.set_business_context_with_features_impl(
            _Ctx(), "portal", industry_sector="Healthcare", sensitivity_tier="Restricted",
            user_base_size="Medium", user_base_metric="Monthly Active Users",
            geographic_scope="National / Single-Country", regulatory_requirements="HIPAA",
            system_criticality="High", financial_impact="Moderate", revenue_band="Mid-market",
            authentication_requirement="MFA", deployment_model="PaaS",
            data_residency="National / Single-Country",
            compute_location="National / Single-Country",
            user_base_location="Global / Transboundary",
            organizational_headquarters="National / Single-Country",
        )
        orch.detect_phase_completion()
        assert orch.phase_completion[1] == 1.0

        # clearing must be visible through the state collector's imported reference
        await bctx.clear_business_context_impl(_Ctx())
        assert get_state_summary()["business_context"]["is_complete"] is False

        orch.detect_phase_completion()
        assert orch.phase_completion[1] == 0.0


class TestAdvancePhaseCannotSkipReopenedPhase:
    """Advancing must check every earlier phase, not just the current one."""

    @pytest.mark.asyncio
    async def test_reopened_phase_one_blocks_advancing_from_phase_two(self):
        import threat_modeling_mcp_server.tools.business_context as bctx
        import threat_modeling_mcp_server.tools.step_orchestrator as orch

        await bctx.set_business_context_with_features_impl(
            _Ctx(), "portal", industry_sector="Healthcare", sensitivity_tier="Restricted",
            user_base_size="Medium", user_base_metric="Monthly Active Users",
            geographic_scope="National / Single-Country", regulatory_requirements="HIPAA",
            system_criticality="High", financial_impact="Moderate", revenue_band="Mid-market",
            authentication_requirement="MFA", deployment_model="PaaS",
            data_residency="National / Single-Country",
            compute_location="National / Single-Country",
            user_base_location="Global / Transboundary",
            organizational_headquarters="National / Single-Country",
        )
        orch.current_phase = 1
        assert "Advanced to phase: 2" in await orch.advance_phase_impl(_Ctx())

        # phase 1 reopens; advancing from phase 2 must not skip it
        await bctx.clear_business_context_impl(_Ctx())
        result = await orch.advance_phase_impl(_Ctx())
        assert "Cannot advance" in result
        assert "phase 1" in result
        assert orch.current_phase == 2


class TestPhaseCompletionIsNotSticky:
    """Removing the work that satisfied a phase must reopen it."""

    @pytest.mark.asyncio
    async def test_removing_architecture_connection_reopens_phase_two(
        self, empty_threat_model_state
    ):
        import threat_modeling_mcp_server.tools.architecture_analyzer as architecture
        import threat_modeling_mcp_server.tools.step_orchestrator as orch

        await architecture.add_component_impl(_Ctx(), "Client", "Compute")
        await architecture.add_component_impl(_Ctx(), "API", "Compute")
        source_id, destination_id = architecture.components
        await architecture.add_connection_impl(
            _Ctx(), source_id, destination_id
        )

        orch.detect_phase_completion()
        assert orch.phase_completion[2] == 1.0

        architecture.connections.clear()
        orch.detect_phase_completion()
        assert orch.phase_completion[2] == 0.0
        assert set(orch.phase_blocking_reasons[2][0].split(": ", 1)[1].split(", ")) == {
            source_id,
            destination_id,
        }

    @pytest.mark.asyncio
    async def test_removing_actor_decision_reopens_phase_three(
        self, empty_threat_model_state
    ):
        import threat_modeling_mcp_server.tools.step_orchestrator as orch
        import threat_modeling_mcp_server.tools.threat_actor_analyzer as actors

        await actors.add_threat_actor_impl(
            _Ctx(),
            name="External attacker",
            type="External Attacker",
            sophistication_tier="Tier 2 - Hacktivist / campaign-driven",
            motivations=["Financial gain"],
            resources="Individual",
        )
        orch.detect_phase_completion()
        assert orch.phase_completion[3] == 1.0

        actors.threat_actors.clear()
        orch.detect_phase_completion()
        assert orch.phase_completion[3] == 0.0

    @pytest.mark.asyncio
    async def test_removing_asset_flow_reopens_phase_five(
        self, empty_threat_model_state
    ):
        import threat_modeling_mcp_server.tools.architecture_analyzer as architecture
        import threat_modeling_mcp_server.tools.asset_flow_analyzer as asset_flows
        import threat_modeling_mcp_server.tools.step_orchestrator as orch

        await architecture.add_component_impl(_Ctx(), "Client", "Compute")
        await architecture.add_component_impl(_Ctx(), "API", "Compute")
        source_id, destination_id = architecture.components
        result = await asset_flows.add_asset_impl(
            _Ctx(), "Session", "Token", "Confidential"
        )
        asset_id = result.rsplit(": ", 1)[1]
        await asset_flows.add_flow_impl(
            _Ctx(), asset_id, source_id, destination_id
        )
        orch.detect_phase_completion()
        assert orch.phase_completion[5] == 1.0

        asset_flows.flows.clear()
        orch.detect_phase_completion()
        assert orch.phase_completion[5] == 0.0

    def test_detection_assigns_every_phase(self):
        import threat_modeling_mcp_server.tools.step_orchestrator as orch

        # poison every phase, then confirm detection overwrites all of them
        for phase in orch.PHASES:
            orch.phase_completion[phase] = 1.0
        orch.detect_phase_completion()
        assert set(orch.phase_completion) == set(orch.PHASES)
        assert any(v == 0.0 for v in orch.phase_completion.values()), (
            "detection did not reset any phase, so it is still write-only"
        )


class TestRelationshipCompletionCriteria:
    """Relationship coverage, rather than record counts, drives completion."""

    @pytest.mark.asyncio
    async def test_inter_zone_connection_requires_one_bound_crossing(
        self, empty_threat_model_state
    ):
        import threat_modeling_mcp_server.tools.architecture_analyzer as architecture
        import threat_modeling_mcp_server.tools.step_orchestrator as orch
        import threat_modeling_mcp_server.tools.trust_boundary_analyzer as boundaries

        component_result = await architecture.add_component_impl(
            _Ctx(), "API", "Compute"
        )
        component_id = component_result.rsplit(": ", 1)[1]
        store_result = await architecture.add_data_store_impl(
            _Ctx(), "Database", "Relational", "Confidential"
        )
        store_id = store_result.rsplit(": ", 1)[1]
        connection_result = await architecture.add_connection_impl(
            _Ctx(), component_id, store_id
        )
        connection_id = connection_result.rsplit(": ", 1)[1]

        source_zone = (
            await boundaries.add_trust_zone_impl(
                _Ctx(), "Service", "Medium"
            )
        ).rsplit(": ", 1)[1]
        destination_zone = (
            await boundaries.add_trust_zone_impl(
                _Ctx(), "Data", "High"
            )
        ).rsplit(": ", 1)[1]
        await boundaries.add_node_to_zone_impl(
            _Ctx(), source_zone, component_id
        )
        await boundaries.add_node_to_zone_impl(
            _Ctx(), destination_zone, store_id
        )

        orch.detect_phase_completion()
        assert orch.phase_completion[4] == 0.0
        assert connection_id in orch.phase_blocking_reasons[4][0]

        crossing_id = (
            await boundaries.add_crossing_point_impl(
                _Ctx(), source_zone, destination_zone
            )
        ).rsplit(": ", 1)[1]
        await boundaries.add_connection_to_crossing_point_impl(
            _Ctx(), crossing_id, connection_id
        )
        orch.detect_phase_completion()
        assert orch.phase_completion[4] == 0.0
        assert crossing_id in " ".join(orch.phase_blocking_reasons[4])

        await boundaries.add_trust_boundary_impl(
            _Ctx(),
            "Service-to-data boundary",
            "Network",
            crossing_point_ids=[crossing_id],
        )
        orch.detect_phase_completion()
        assert orch.phase_completion[4] == 1.0

        await boundaries.remove_connection_from_crossing_point_impl(
            _Ctx(), crossing_id, connection_id
        )
        orch.detect_phase_completion()
        assert orch.phase_completion[4] == 0.0

    @pytest.mark.asyncio
    async def test_same_zone_connections_need_no_crossing(
        self, empty_threat_model_state
    ):
        import threat_modeling_mcp_server.tools.architecture_analyzer as architecture
        import threat_modeling_mcp_server.tools.step_orchestrator as orch
        import threat_modeling_mcp_server.tools.trust_boundary_analyzer as boundaries

        await architecture.add_component_impl(_Ctx(), "Worker", "Compute")
        await architecture.add_data_store_impl(
            _Ctx(), "Cache", "Cache", "Internal"
        )
        component_id = next(iter(architecture.components))
        store_id = next(iter(architecture.data_stores))
        await architecture.add_connection_impl(_Ctx(), component_id, store_id)
        zone_id = (
            await boundaries.add_trust_zone_impl(
                _Ctx(), "Private", "High"
            )
        ).rsplit(": ", 1)[1]
        await boundaries.add_node_to_zone_impl(_Ctx(), zone_id, component_id)
        await boundaries.add_node_to_zone_impl(_Ctx(), zone_id, store_id)

        orch.detect_phase_completion()

        assert orch.phase_completion[4] == 1.0
        assert boundaries.crossing_points == {}
        assert boundaries.trust_boundaries == {}

    @pytest.mark.asyncio
    async def test_every_asset_requires_a_flow(self, empty_threat_model_state):
        import threat_modeling_mcp_server.tools.architecture_analyzer as architecture
        import threat_modeling_mcp_server.tools.asset_flow_analyzer as asset_flows
        import threat_modeling_mcp_server.tools.step_orchestrator as orch

        await architecture.add_component_impl(_Ctx(), "Client", "Compute")
        await architecture.add_component_impl(_Ctx(), "API", "Compute")
        source_id, destination_id = architecture.components
        first_id = (
            await asset_flows.add_asset_impl(
                _Ctx(), "Session", "Token", "Confidential"
            )
        ).rsplit(": ", 1)[1]
        second_id = (
            await asset_flows.add_asset_impl(
                _Ctx(), "Profile", "Data", "Confidential"
            )
        ).rsplit(": ", 1)[1]
        await asset_flows.add_flow_impl(
            _Ctx(), first_id, source_id, destination_id
        )

        orch.detect_phase_completion()
        assert orch.phase_completion[5] == 0.0
        assert second_id in orch.phase_blocking_reasons[5][0]

        await asset_flows.add_flow_impl(
            _Ctx(), second_id, source_id, destination_id
        )
        orch.detect_phase_completion()
        assert orch.phase_completion[5] == 1.0

    @pytest.mark.asyncio
    async def test_every_threat_requires_links_and_current_assessment(
        self, empty_threat_model_state
    ):
        import threat_modeling_mcp_server.tools.step_orchestrator as orch
        import threat_modeling_mcp_server.tools.threat_generator as threats

        threat_ids = []
        for action in ("spoof identity", "tamper with state"):
            threat_ids.append((
                await threats.add_threat_impl(
                    _Ctx(),
                    "attacker",
                    "with access",
                    action,
                    "security impact",
                )
            ).rsplit(": ", 1)[1])
        mitigation_id = (
            await threats.add_mitigation_impl(
                _Ctx(), "Authorize every state-changing request"
            )
        ).rsplit(": ", 1)[1]
        await threats.link_mitigation_to_threat_impl(
            _Ctx(), mitigation_id, threat_ids[0]
        )

        orch.detect_phase_completion()
        assert orch.phase_completion[7] == 0.0
        assert threat_ids[1] in orch.phase_blocking_reasons[7][0]

        await threats.link_mitigation_to_threat_impl(
            _Ctx(), mitigation_id, threat_ids[1]
        )
        orch.detect_phase_completion()
        assert orch.phase_completion[7] == 1.0

        for threat_id in threat_ids:
            await threats.assess_threat_impl(
                _Ctx(),
                threat_id,
                "Mitigated",
                "The authorization control covers this threat.",
                residual_severity="Low",
                residual_likelihood="Unlikely",
            )
        orch.detect_phase_completion()
        assert orch.phase_completion[8] == 1.0

        await threats.update_mitigation_impl(
            _Ctx(), mitigation_id, content="Changed control"
        )
        orch.detect_phase_completion()
        assert orch.phase_completion[8] == 0.0
        assert set(
            orch.phase_blocking_reasons[8][0].split(": ", 1)[1].split(", ")
        ) == set(threat_ids)

    @pytest.mark.asyncio
    async def test_phase_nine_tracks_export_freshness(
        self, empty_threat_model_state, tmp_path
    ):
        import threat_modeling_mcp_server.tools.assumption_manager as assumptions
        import threat_modeling_mcp_server.tools.step_orchestrator as orch
        from threat_modeling_mcp_server.utils.comprehensive_exporter import (
            export_threat_model_files,
        )

        orch.detect_phase_completion()
        assert orch.phase_completion[9] == 0.0

        export_threat_model_files(str(tmp_path / "model"))
        orch.detect_phase_completion()
        assert orch.phase_completion[9] == 1.0

        await assumptions.add_assumption_impl(
            _Ctx(),
            "TLS terminates at the ingress",
            "Network",
            "Transport controls depend on ingress configuration",
            "Observed in deployment manifests",
        )
        orch.detect_phase_completion()
        assert orch.phase_completion[9] == 0.0
        assert "Export the current model" in orch.phase_blocking_reasons[9][0]


class TestOptionalPhase75:
    """Phase 7.5 must not deadlock when there is no code to validate."""

    def test_counts_as_complete_when_not_applicable(self, tmp_path, monkeypatch):
        import threat_modeling_mcp_server.tools.step_orchestrator as orch

        monkeypatch.chdir(tmp_path)
        orch.detect_phase_completion()
        assert orch.phase_completion[7.5] == 1.0

    @pytest.mark.asyncio
    async def test_advance_skips_75_when_no_code(self, tmp_path, monkeypatch):
        import threat_modeling_mcp_server.tools.step_orchestrator as orch

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(orch, "detect_phase_completion", lambda: None)
        for phase in orch.PHASES:
            orch.phase_completion[phase] = 1.0
        orch.current_phase = 7

        result = await orch.advance_phase_impl(_Ctx())
        assert "Skipped phase 7.5" in result
        assert orch.current_phase == 8


class TestProjectDirectoryDrivesPhase75:
    """Phase 7.5 applies to the reviewed project, not the server's CWD."""

    def test_directory_without_code_skips_phase_7_5(self, tmp_path):
        import threat_modeling_mcp_server.tools.step_orchestrator as orch

        (tmp_path / "notes.txt").write_text("no code here")
        message = orch.set_project_directory(str(tmp_path))

        assert "will be skipped" in message
        assert orch.phase_7_5_applicable() is False

    def test_directory_with_code_makes_phase_7_5_apply(self, tmp_path):
        import threat_modeling_mcp_server.tools.step_orchestrator as orch

        (tmp_path / "app.py").write_text("def main():\n    return 1\n")
        message = orch.set_project_directory(str(tmp_path))

        assert "applies" in message
        assert orch.phase_7_5_applicable() is True

    def test_explicit_directory_overrides_recorded_one(self, tmp_path):
        import threat_modeling_mcp_server.tools.step_orchestrator as orch

        empty = tmp_path / "empty"
        empty.mkdir()
        with_code = tmp_path / "code"
        with_code.mkdir()
        (with_code / "app.py").write_text("x = 1\n")

        orch.set_project_directory(str(empty))

        assert orch.phase_7_5_applicable(str(with_code)) is True
        assert orch.phase_7_5_applicable() is False

    def test_empty_directory_argument_falls_back_to_cwd(self):
        import threat_modeling_mcp_server.tools.step_orchestrator as orch

        assert "'.'" in orch.set_project_directory("")
        assert orch.project_directory == "."


class TestDetectionFailureBlocksAdvancement:
    """A failed detection must not let a stale snapshot authorize advancing."""

    @pytest.mark.asyncio
    async def test_advance_refuses_when_detection_fails(self, monkeypatch):
        import threat_modeling_mcp_server.tools.step_orchestrator as orch
        import threat_modeling_mcp_server.utils.state_collector as sc

        for phase in orch.PHASES:
            orch.phase_completion[phase] = 1.0
        orch.current_phase = 1

        def boom():
            raise RuntimeError("collection exploded")

        monkeypatch.setattr(sc, "get_state_summary", boom)

        result = await orch.advance_phase_impl(_Ctx())
        assert "could not be determined" in result
        assert "collection exploded" in result
        assert orch.current_phase == 1
        assert orch.last_detection_error is not None

    def test_error_flag_clears_after_a_good_run(self):
        import threat_modeling_mcp_server.tools.step_orchestrator as orch

        orch.detect_phase_completion()
        assert orch.last_detection_error is None
