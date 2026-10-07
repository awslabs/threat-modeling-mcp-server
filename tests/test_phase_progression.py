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

        export_threat_model_files("model", str(tmp_path))
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

    def test_counts_as_complete_when_not_applicable(self, tmp_path):
        import threat_modeling_mcp_server.tools.step_orchestrator as orch

        orch.set_project_directory(str(tmp_path))
        orch.detect_phase_completion()
        assert orch.phase_completion[7.5] == 1.0

    @pytest.mark.asyncio
    async def test_advance_skips_75_when_no_code(self, tmp_path, monkeypatch):
        import threat_modeling_mcp_server.tools.step_orchestrator as orch

        orch.set_project_directory(str(tmp_path))
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

    def test_empty_directory_argument_does_not_select_cwd(self, monkeypatch):
        import threat_modeling_mcp_server.tools.step_orchestrator as orch

        monkeypatch.setattr(orch, "project_directory", None)
        with pytest.raises(ValueError, match="explicitly selected"):
            orch.set_project_directory("")
        assert orch.project_directory is None

    def test_relative_directory_is_resolved_when_selected(
        self, tmp_path, monkeypatch,
    ):
        import threat_modeling_mcp_server.tools.step_orchestrator as orch

        monkeypatch.chdir(tmp_path)
        (tmp_path / "project").mkdir()

        orch.set_project_directory("project")

        assert orch.project_directory == str((tmp_path / "project").resolve())


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


class TestCodeScanner:
    """One pruned, tri-state walk decides whether code is present."""

    def test_dependency_only_tree_is_not_code(self, tmp_path):
        from threat_modeling_mcp_server.tools.threat_model_plan import (
            CodeApplicability, has_code_files, scan_for_code,
        )

        (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
        (tmp_path / "node_modules" / "pkg" / "vendored.js").write_text("x")
        (tmp_path / "README.md").write_text("docs")

        assert scan_for_code(str(tmp_path)).applicability is CodeApplicability.NO_CODE
        assert has_code_files(str(tmp_path)) is False

    def test_every_skipped_directory_is_pruned(self, tmp_path):
        from threat_modeling_mcp_server.tools.threat_model_plan import (
            SKIP_DIRECTORY_NAMES, CodeApplicability, scan_for_code,
        )

        for name in SKIP_DIRECTORY_NAMES:
            (tmp_path / name).mkdir()
            (tmp_path / name / "x.py").write_text("x = 1\n")

        assert scan_for_code(str(tmp_path)).applicability is CodeApplicability.NO_CODE

    def test_source_file_is_code(self, tmp_path):
        from threat_modeling_mcp_server.tools.threat_model_plan import (
            CodeApplicability, scan_for_code,
        )

        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text("x = 1\n")

        assert (
            scan_for_code(str(tmp_path)).applicability
            is CodeApplicability.CODE_PRESENT
        )

    @pytest.mark.parametrize(
        "pattern, filename",
        [("Dockerfile", "Dockerfile"), ("*.cdk.ts", "stack.cdk.ts")],
    )
    def test_custom_patterns(self, tmp_path, pattern, filename):
        from threat_modeling_mcp_server.tools.threat_model_plan import (
            CodeApplicability, scan_for_code,
        )

        (tmp_path / "infra").mkdir()
        (tmp_path / "infra" / filename).write_text("x")
        (tmp_path / "other.py").write_text("x = 1\n")

        assert (
            scan_for_code(str(tmp_path), [pattern]).applicability
            is CodeApplicability.CODE_PRESENT
        )
        assert (
            scan_for_code(str(tmp_path), ["*.nomatch"]).applicability
            is CodeApplicability.NO_CODE
        )

    def test_directory_symlinks_are_not_followed(self, tmp_path):
        from threat_modeling_mcp_server.tools.threat_model_plan import (
            CodeApplicability, scan_for_code,
        )

        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "a.py").write_text("x = 1\n")
        project = tmp_path / "project"
        project.mkdir()
        (project / "linked").symlink_to(outside, target_is_directory=True)

        assert scan_for_code(str(project)).applicability is CodeApplicability.NO_CODE

    def test_missing_root_is_unknown(self, tmp_path):
        from threat_modeling_mcp_server.tools.threat_model_plan import (
            CodeApplicability, has_code_files, scan_for_code,
        )

        missing = str(tmp_path / "missing")
        assert (
            scan_for_code(missing).applicability
            is CodeApplicability.UNKNOWN_PARTIAL
        )
        assert has_code_files(missing) is True

    def test_walk_errors_fail_closed(self, tmp_path, monkeypatch):
        import threat_modeling_mcp_server.tools.threat_model_plan as plan

        def failing_walk(top, topdown=True, onerror=None, followlinks=False):
            onerror(PermissionError("denied"))
            return iter(())

        monkeypatch.setattr(plan.os, "walk", failing_walk)

        result = plan.scan_for_code(str(tmp_path))
        assert result.applicability is plan.CodeApplicability.UNKNOWN_PARTIAL
        assert result.error_count == 1
        assert plan.has_code_files(str(tmp_path)) is True

    def test_single_walk_short_circuits_on_first_match(self, tmp_path, monkeypatch):
        import threat_modeling_mcp_server.tools.threat_model_plan as plan

        for index in range(5):
            (tmp_path / f"d{index}").mkdir()
            (tmp_path / f"d{index}" / "notes.txt").write_text("x")
        (tmp_path / "app.py").write_text("x = 1\n")

        real_walk = plan.os.walk
        calls = {"walks": 0, "yields": 0}

        def counting_walk(*args, **kwargs):
            calls["walks"] += 1
            for entry in real_walk(*args, **kwargs):
                calls["yields"] += 1
                yield entry

        monkeypatch.setattr(plan.os, "walk", counting_walk)

        assert plan.scan_for_code(str(tmp_path)).applicability is (
            plan.CodeApplicability.CODE_PRESENT
        )
        # The root holds the match, so no subdirectory is visited.
        assert calls == {"walks": 1, "yields": 1}

    def test_no_match_scan_walks_tree_once(self, tmp_path, monkeypatch):
        import threat_modeling_mcp_server.tools.threat_model_plan as plan

        (tmp_path / "docs").mkdir()
        (tmp_path / "docs" / "notes.txt").write_text("x")
        real_walk = plan.os.walk
        calls = {"walks": 0}

        def counting_walk(*args, **kwargs):
            calls["walks"] += 1
            return real_walk(*args, **kwargs)

        monkeypatch.setattr(plan.os, "walk", counting_walk)

        assert plan.scan_for_code(str(tmp_path)).applicability is (
            plan.CodeApplicability.NO_CODE
        )
        assert calls["walks"] == 1

    @pytest.mark.asyncio
    async def test_detection_does_not_block_event_loop(self, tmp_path, monkeypatch):
        import asyncio
        import threading

        import threat_modeling_mcp_server.tools.threat_model_plan as plan

        release = threading.Event()
        fallback = threading.Timer(2.0, release.set)
        fallback.start()

        def blocking_scan(directory, file_patterns=None):
            release.wait()
            return plan.CodeScanResult(directory, plan.CodeApplicability.NO_CODE)

        monkeypatch.setattr(plan, "scan_for_code", blocking_scan)
        ticks = 0

        async def heartbeat():
            nonlocal ticks
            while not release.is_set():
                ticks += 1
                if ticks >= 3:
                    release.set()
                await asyncio.sleep(0.05)

        try:
            detected, _ = await asyncio.gather(
                plan.detect_code_in_directory(str(tmp_path)), heartbeat()
            )
        finally:
            release.set()
            fallback.cancel()

        assert detected is False
        assert ticks >= 2


class TestProjectCodeScanCache:
    """The orchestrator reuses one scan and fails closed on partial scans."""

    @staticmethod
    def _count_scans(monkeypatch, applicability=None):
        import threading

        import threat_modeling_mcp_server.tools.threat_model_plan as plan

        real_scan = plan.scan_for_code
        calls = []

        def counting_scan(directory, file_patterns=None):
            calls.append(threading.get_ident())
            if applicability is not None:
                return plan.CodeScanResult(directory, applicability, 1)
            return real_scan(directory, file_patterns)

        monkeypatch.setattr(plan, "scan_for_code", counting_scan)
        return calls

    def test_completion_checks_reuse_cached_scan(self, tmp_path, monkeypatch):
        import threat_modeling_mcp_server.tools.step_orchestrator as orch

        calls = self._count_scans(monkeypatch)
        orch.set_project_directory(str(tmp_path))
        assert len(calls) == 1

        orch.detect_phase_completion()
        orch.get_workflow_status()
        assert len(calls) == 1

    def test_partial_scan_keeps_phase_7_5_applicable(self, tmp_path, monkeypatch):
        import threat_modeling_mcp_server.tools.step_orchestrator as orch
        from threat_modeling_mcp_server.tools.threat_model_plan import (
            CodeApplicability,
        )

        self._count_scans(monkeypatch, CodeApplicability.UNKNOWN_PARTIAL)
        message = orch.set_project_directory(str(tmp_path))
        orch.detect_phase_completion()

        assert "incomplete" in message and "applies" in message
        assert orch.phase_7_5_applicable() is True
        assert orch.phase_completion[7.5] == 0.0

    @pytest.mark.asyncio
    async def test_set_project_scans_off_event_loop_thread(
        self, tmp_path, monkeypatch,
    ):
        import threading

        import threat_modeling_mcp_server.tools.step_orchestrator as orch

        calls = self._count_scans(monkeypatch)
        message = await orch.manage_workflow_impl(
            _Ctx(), "set_project", directory=str(tmp_path)
        )

        assert "will be skipped" in message
        assert calls and threading.get_ident() not in calls

    @pytest.mark.asyncio
    async def test_export_scans_exactly_once(self, tmp_path, monkeypatch):
        import threading

        import threat_modeling_mcp_server.tools.step_orchestrator as orch

        calls = self._count_scans(monkeypatch)
        orch.set_project_directory(str(tmp_path))
        calls.clear()

        result = await orch.export_threat_model_impl(_Ctx(), "model.json")

        assert "Threat Model Export Complete" in result
        assert len(calls) == 1
        assert threading.get_ident() not in calls
