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

    @pytest.mark.parametrize("phase,module_name,attr", [
        (2, "architecture_analyzer", "components"),
        (3, "threat_actor_analyzer", "threat_actors"),
        (4, "trust_boundary_analyzer", "trust_zones"),
        (5, "asset_flow_analyzer", "assets"),
    ])
    def test_clearing_state_reopens_its_phase(self, phase, module_name, attr):
        import importlib
        import threat_modeling_mcp_server.tools.step_orchestrator as orch

        module = importlib.import_module(
            f"threat_modeling_mcp_server.tools.{module_name}"
        )
        store = getattr(module, attr)
        saved = dict(store)
        try:
            # Seed one record so the phase is satisfied regardless of test order.
            # Detection only counts entries, so a placeholder is enough.
            store["SEED"] = object()
            orch.detect_phase_completion()
            assert orch.phase_completion[phase] == 1.0

            store.clear()
            orch.detect_phase_completion()
            assert orch.phase_completion[phase] == 0.0, (
                f"phase {phase} stayed complete after clearing {attr}"
            )
        finally:
            store.clear()
            store.update(saved)

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
