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

    @pytest.mark.parametrize("kind", ["missing", "file"])
    def test_missing_or_file_directory_is_rejected(self, tmp_path, kind):
        import threat_modeling_mcp_server.tools.step_orchestrator as orch

        selected = tmp_path / "selected"
        orch.set_project_directory(str(tmp_path))
        if kind == "file":
            selected.write_text("not a directory")

        with pytest.raises(ValueError, match="does not exist or is not a directory"):
            orch.set_project_directory(str(selected))
        assert orch.project_directory == str(tmp_path.resolve())
        assert orch.project_code_scan.directory == str(tmp_path.resolve())

    @pytest.mark.asyncio
    async def test_manage_workflow_reports_missing_directory(self, tmp_path):
        import threat_modeling_mcp_server.tools.step_orchestrator as orch

        message = await orch.manage_workflow_impl(
            _Ctx(), "set_project", directory=str(tmp_path / "typo")
        )

        assert message.startswith("❌ Project directory")
        assert "does not exist" in message
        assert not (tmp_path / "typo").exists()

    def test_unfollowed_symlink_is_explained_when_selected(self, tmp_path):
        import threat_modeling_mcp_server.tools.step_orchestrator as orch

        outside = tmp_path / "outside"
        outside.mkdir()
        project = tmp_path / "project"
        project.mkdir()
        (project / "shared").symlink_to(outside, target_is_directory=True)

        message = orch.set_project_directory(str(project))

        assert "1 directory symlink(s) were not followed" in message
        assert "could not be read" not in message
        assert "applies" in message
        assert orch.phase_7_5_applicable() is True


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

    def test_source_under_env_directory_is_code(self, tmp_path):
        """env/ can hold real source when it is not a virtual environment."""
        from threat_modeling_mcp_server.tools.threat_model_plan import (
            CodeApplicability, scan_for_code,
        )

        (tmp_path / "env" / "prod").mkdir(parents=True)
        (tmp_path / "env" / "prod" / "main.tf").write_text("terraform {}\n")
        (tmp_path / "README.md").write_text("docs")

        assert (
            scan_for_code(str(tmp_path)).applicability
            is CodeApplicability.CODE_PRESENT
        )

    def test_source_under_build_directory_is_pruned(self, tmp_path):
        from threat_modeling_mcp_server.tools.threat_model_plan import (
            CodeApplicability, scan_for_code,
        )

        (tmp_path / "build" / "prod").mkdir(parents=True)
        (tmp_path / "build" / "prod" / "main.tf").write_text("terraform {}\n")

        assert (
            scan_for_code(str(tmp_path)).applicability
            is CodeApplicability.NO_CODE
        )

    @pytest.mark.parametrize("name", ["env", "py310-env"])
    def test_virtualenv_under_any_name_is_pruned(self, tmp_path, name):
        from threat_modeling_mcp_server.tools.threat_model_plan import (
            VIRTUALENV_MARKER, CodeApplicability, scan_for_code,
        )

        venv = tmp_path / name
        (venv / "lib" / "site-packages").mkdir(parents=True)
        (venv / VIRTUALENV_MARKER).write_text("home = /usr/bin\n")
        (venv / "lib" / "site-packages" / "dep.py").write_text("x = 1\n")
        (venv / "activate.ps1").write_text("x")
        (tmp_path / "README.md").write_text("docs")

        assert scan_for_code(str(tmp_path)).applicability is CodeApplicability.NO_CODE

    def test_directory_symlinks_are_not_followed(self, tmp_path):
        from threat_modeling_mcp_server.tools.threat_model_plan import (
            CodeApplicability, has_code_files, scan_for_code,
        )

        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "a.py").write_text("x = 1\n")
        project = tmp_path / "project"
        project.mkdir()
        (project / "linked").symlink_to(outside, target_is_directory=True)

        result = scan_for_code(str(project))

        # The unscanned target may hold code, so absence is unproven.
        assert result.applicability is CodeApplicability.UNKNOWN_PARTIAL
        assert result.error_count == 0
        assert result.unfollowed_symlink_count == 1
        assert has_code_files(str(project)) is True

    def test_symlink_into_the_tree_does_not_make_scan_partial(self, tmp_path):
        from threat_modeling_mcp_server.tools.threat_model_plan import (
            CodeApplicability, scan_for_code,
        )

        (tmp_path / "docs" / "guide").mkdir(parents=True)
        (tmp_path / "docs" / "guide" / "notes.txt").write_text("x")
        (tmp_path / "docs" / "up").symlink_to(tmp_path, target_is_directory=True)
        (tmp_path / "guide").symlink_to(
            tmp_path / "docs" / "guide", target_is_directory=True,
        )

        result = scan_for_code(str(tmp_path))

        assert result.applicability is CodeApplicability.NO_CODE
        assert result.unfollowed_symlink_count == 0

    def test_visible_symlink_to_hidden_source_fails_closed(self, tmp_path):
        from threat_modeling_mcp_server.tools.threat_model_plan import (
            CodeApplicability, has_code_files, scan_for_code,
        )

        hidden_source = tmp_path / ".hidden" / "source"
        hidden_source.mkdir(parents=True)
        (hidden_source / "application.py").write_text("x = 1\n")
        (tmp_path / "visible-source").symlink_to(
            hidden_source, target_is_directory=True,
        )

        result = scan_for_code(str(tmp_path))

        assert result.applicability is CodeApplicability.UNKNOWN_PARTIAL
        assert result.unfollowed_symlink_count == 1
        assert has_code_files(str(tmp_path)) is True

    def test_duplicate_links_to_pruned_target_are_deduplicated(self, tmp_path):
        from threat_modeling_mcp_server.tools.threat_model_plan import (
            CodeApplicability, scan_for_code,
        )

        hidden_source = tmp_path / ".hidden" / "source"
        hidden_source.mkdir(parents=True)
        (hidden_source / "notes.txt").write_text("x")
        (tmp_path / "first").symlink_to(hidden_source, target_is_directory=True)
        (tmp_path / "second").symlink_to(hidden_source, target_is_directory=True)

        result = scan_for_code(str(tmp_path))

        assert result.applicability is CodeApplicability.UNKNOWN_PARTIAL
        assert result.unfollowed_symlink_count == 1

    def test_broken_visible_symlink_fails_closed(self, tmp_path):
        from threat_modeling_mcp_server.tools.threat_model_plan import (
            CodeApplicability, has_code_files, scan_for_code,
        )

        (tmp_path / "broken").symlink_to(
            tmp_path / "missing", target_is_directory=True,
        )

        result = scan_for_code(str(tmp_path))

        assert result.applicability is CodeApplicability.UNKNOWN_PARTIAL
        assert result.error_count == 1
        assert result.unfollowed_symlink_count == 1
        assert has_code_files(str(tmp_path)) is True

    def test_symlink_cycle_fails_closed(self, tmp_path):
        from threat_modeling_mcp_server.tools.threat_model_plan import (
            CodeApplicability, scan_for_code,
        )

        (tmp_path / "first").symlink_to(
            tmp_path / "second", target_is_directory=True,
        )
        (tmp_path / "second").symlink_to(
            tmp_path / "first", target_is_directory=True,
        )

        result = scan_for_code(str(tmp_path))

        assert result.applicability is CodeApplicability.UNKNOWN_PARTIAL
        assert result.error_count > 0
        assert result.unfollowed_symlink_count > 0

    def test_symlink_hop_limit_stops_resolution(
        self, tmp_path, monkeypatch,
    ):
        import threat_modeling_mcp_server.tools.threat_model_plan as plan

        (tmp_path / "docs").mkdir()
        (tmp_path / ".second").symlink_to(
            "docs", target_is_directory=True,
        )
        (tmp_path / ".first").symlink_to(
            ".second", target_is_directory=True,
        )
        (tmp_path / "visible").symlink_to(
            ".first", target_is_directory=True,
        )
        real_readlink = plan.os.readlink
        read_links = []

        def counting_readlink(path, *, dir_fd=None):
            read_links.append(path)
            return real_readlink(path, dir_fd=dir_fd)

        monkeypatch.setattr(plan, "MAX_SCAN_SYMLINK_HOPS", 1)
        monkeypatch.setattr(plan.os, "readlink", counting_readlink)

        result = plan.scan_for_code(str(tmp_path))

        assert result.applicability is plan.CodeApplicability.UNKNOWN_PARTIAL
        assert result.error_count > 0
        assert read_links == ["visible"]

    @pytest.mark.parametrize("fail_after_readlinks", [1, 2])
    def test_symlink_descriptor_stat_error_fails_closed(
        self, tmp_path, monkeypatch, fail_after_readlinks,
    ):
        import threat_modeling_mcp_server.tools.threat_model_plan as plan

        hidden_target = tmp_path / ".target"
        hidden_target.mkdir()
        (hidden_target / "notes.txt").write_text("x")
        (tmp_path / ".nested").symlink_to(
            ".target", target_is_directory=True,
        )
        (tmp_path / "visible").symlink_to(
            ".nested", target_is_directory=True,
        )
        real_readlink = plan.os.readlink
        real_fstat = plan.os.fstat
        readlink_count = 0
        failed = False

        def counting_readlink(path, *, dir_fd=None):
            nonlocal readlink_count
            readlink_count += 1
            return real_readlink(path, dir_fd=dir_fd)

        def failing_fstat(fd):
            nonlocal failed
            if readlink_count == fail_after_readlinks and not failed:
                failed = True
                raise PermissionError("descriptor metadata denied")
            return real_fstat(fd)

        monkeypatch.setattr(plan.os, "readlink", counting_readlink)
        monkeypatch.setattr(plan.os, "fstat", failing_fstat)

        result = plan.scan_for_code(str(tmp_path))

        assert failed is True
        assert result.applicability is plan.CodeApplicability.UNKNOWN_PARTIAL
        assert result.error_count == 1
        assert result.unfollowed_symlink_count == 1

    def test_symlinked_skip_directory_is_pruned_without_counting(self, tmp_path):
        from threat_modeling_mcp_server.tools.threat_model_plan import (
            CodeApplicability, scan_for_code,
        )

        store = tmp_path / "store"
        store.mkdir()
        (store / "dep.js").write_text("x")
        project = tmp_path / "project"
        project.mkdir()
        (project / "node_modules").symlink_to(store, target_is_directory=True)

        result = scan_for_code(str(project))

        assert result.applicability is CodeApplicability.NO_CODE
        assert result.unfollowed_symlink_count == 0

    def test_code_found_despite_unfollowed_symlink_is_code(self, tmp_path):
        from threat_modeling_mcp_server.tools.threat_model_plan import (
            CodeApplicability, scan_for_code,
        )

        outside = tmp_path / "outside"
        outside.mkdir()
        project = tmp_path / "project"
        (project / "src").mkdir(parents=True)
        (project / "linked").symlink_to(outside, target_is_directory=True)
        (project / "src" / "app.py").write_text("x = 1\n")

        assert (
            scan_for_code(str(project)).applicability
            is CodeApplicability.CODE_PRESENT
        )

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

    def test_malformed_root_is_unknown(self, tmp_path):
        from threat_modeling_mcp_server.tools.threat_model_plan import (
            CodeApplicability, has_code_files, scan_for_code,
        )

        malformed = f"{tmp_path}{chr(0)}invalid"
        result = scan_for_code(malformed)

        assert result.applicability is CodeApplicability.UNKNOWN_PARTIAL
        assert result.error_count == 1
        assert has_code_files(malformed) is True

    def test_walk_errors_fail_closed(self, tmp_path, monkeypatch):
        import threat_modeling_mcp_server.tools.threat_model_plan as plan

        def failing_scandir(_path):
            raise PermissionError("denied")

        monkeypatch.setattr(plan.os, "scandir", failing_scandir)

        result = plan.scan_for_code(str(tmp_path))
        assert result.applicability is plan.CodeApplicability.UNKNOWN_PARTIAL
        assert result.error_count == 1
        assert plan.has_code_files(str(tmp_path)) is True

    def test_walk_recursion_error_fails_closed(self, tmp_path, monkeypatch):
        import threat_modeling_mcp_server.tools.threat_model_plan as plan

        def recursive_scandir(_path):
            raise RecursionError("tree is too deep")

        monkeypatch.setattr(plan.os, "scandir", recursive_scandir)

        result = plan.scan_for_code(str(tmp_path))
        assert result.applicability is plan.CodeApplicability.UNKNOWN_PARTIAL
        assert result.error_count == 1

    def test_entry_classification_error_fails_closed(
        self, tmp_path, monkeypatch,
    ):
        import threat_modeling_mcp_server.tools.threat_model_plan as plan

        (tmp_path / "docs").mkdir()
        real_stat = plan.os.stat

        def failing_stat(path, *args, **kwargs):
            if (
                path == "docs"
                and kwargs.get("dir_fd") is not None
                and kwargs.get("follow_symlinks") is False
            ):
                raise PermissionError("classification denied")
            return real_stat(path, *args, **kwargs)

        monkeypatch.setattr(plan.os, "stat", failing_stat)

        result = plan.scan_for_code(str(tmp_path))
        assert result.applicability is plan.CodeApplicability.UNKNOWN_PARTIAL
        assert result.error_count == 1

    def test_replaced_root_link_resolution_fails_closed(
        self, tmp_path, monkeypatch,
    ):
        import threat_modeling_mcp_server.tools.threat_model_plan as plan

        project = tmp_path / "project"
        hidden_source = project / ".hidden" / "source"
        hidden_source.mkdir(parents=True)
        (hidden_source / "application.py").write_text("x = 1\n")
        (project / "docs").mkdir()
        (project / "docs" / "notes.txt").write_text("x")
        (project / "visible-source").symlink_to(
            ".hidden/source", target_is_directory=True,
        )
        moved_project = tmp_path / "moved-project"
        real_readlink = plan.os.readlink
        replaced = False

        def replacing_readlink(path, *, dir_fd=None):
            nonlocal replaced
            if path == "visible-source" and not replaced:
                replaced = True
                project.rename(moved_project)
                (project / "docs").mkdir(parents=True)
                (project / "visible-source").symlink_to(
                    "docs", target_is_directory=True,
                )
            return real_readlink(path, dir_fd=dir_fd)

        monkeypatch.setattr(plan.os, "readlink", replacing_readlink)

        result = plan.scan_for_code(str(project))

        assert replaced is True
        assert (moved_project / ".hidden/source/application.py").is_file()
        assert result.applicability is plan.CodeApplicability.UNKNOWN_PARTIAL
        assert result.applicability is not plan.CodeApplicability.NO_CODE

    def test_replaced_child_never_enumerates_outside_root(
        self, tmp_path, monkeypatch,
    ):
        import threat_modeling_mcp_server.tools.threat_model_plan as plan

        project = tmp_path / "project"
        child = project / "child"
        child.mkdir(parents=True)
        (child / "notes.txt").write_text("x")
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "application.py").write_text("x = 1\n")
        outside_stat = outside.stat()

        real_open = plan.os.open
        real_scandir = plan.os.scandir
        replaced = False
        enumerated_outside = False

        def replacing_open(path, flags, *args, **kwargs):
            nonlocal replaced
            if (
                path == "child"
                and kwargs.get("dir_fd") is not None
                and not replaced
            ):
                replaced = True
                child.rename(project / "original-child")
                child.symlink_to(outside, target_is_directory=True)
            return real_open(path, flags, *args, **kwargs)

        def observing_scandir(path):
            nonlocal enumerated_outside
            if isinstance(path, int) and plan.os.path.samestat(
                plan.os.fstat(path), outside_stat
            ):
                enumerated_outside = True
            return real_scandir(path)

        monkeypatch.setattr(plan.os, "open", replacing_open)
        monkeypatch.setattr(plan.os, "scandir", observing_scandir)

        result = plan.scan_for_code(str(project))

        assert replaced is True
        assert result.applicability is plan.CodeApplicability.UNKNOWN_PARTIAL
        assert result.error_count > 0
        assert enumerated_outside is False

    @pytest.mark.parametrize(
        "limit_name",
        [
            "MAX_SCAN_DEPTH",
            "MAX_SCAN_DIRECTORIES",
            "MAX_SCAN_FILES",
            "MAX_SCAN_ENTRIES",
        ],
    )
    def test_scan_bounds_fail_closed(self, tmp_path, monkeypatch, limit_name):
        import threat_modeling_mcp_server.tools.threat_model_plan as plan

        (tmp_path / "docs" / "nested").mkdir(parents=True)
        (tmp_path / "docs" / "notes.txt").write_text("x")
        monkeypatch.setattr(plan, limit_name, 0)

        result = plan.scan_for_code(str(tmp_path))

        assert result.applicability is plan.CodeApplicability.UNKNOWN_PARTIAL
        assert result.error_count > 0

    @pytest.mark.parametrize(
        "limit_name, limit_value, entry_kind, expected_entries",
        [
            ("MAX_SCAN_DEPTH", 0, "directory", 1),
            ("MAX_SCAN_DIRECTORIES", 1, "directory", 1),
            ("MAX_SCAN_FILES", 1, "file", 2),
            ("MAX_SCAN_ENTRIES", 1, "file", 2),
        ],
    )
    def test_scan_bounds_stop_directory_enumeration(
        self,
        tmp_path,
        monkeypatch,
        limit_name,
        limit_value,
        entry_kind,
        expected_entries,
    ):
        import threat_modeling_mcp_server.tools.threat_model_plan as plan

        for index in range(10):
            entry = tmp_path / f"entry-{index}"
            if entry_kind == "directory":
                entry.mkdir()
            else:
                entry.write_text("notes")

        real_scandir = plan.os.scandir
        yielded_entries = 0

        class CountingIterator:
            def __init__(self, iterator):
                self.iterator = iterator

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.iterator.close()

            def __next__(self):
                nonlocal yielded_entries
                entry = next(self.iterator)
                yielded_entries += 1
                return entry

        def counting_scandir(path):
            return CountingIterator(real_scandir(path))

        monkeypatch.setattr(plan, limit_name, limit_value)
        monkeypatch.setattr(plan.os, "scandir", counting_scandir)

        result = plan.scan_for_code(str(tmp_path))

        assert result.applicability is plan.CodeApplicability.UNKNOWN_PARTIAL
        assert result.error_count > 0
        assert yielded_entries == expected_entries

    def test_single_walk_short_circuits_on_first_match(self, tmp_path, monkeypatch):
        import threat_modeling_mcp_server.tools.threat_model_plan as plan

        for index in range(5):
            (tmp_path / f"d{index}").mkdir()
            (tmp_path / f"d{index}" / "notes.txt").write_text("x")
        (tmp_path / "app.py").write_text("x = 1\n")

        real_scandir = plan.os.scandir
        calls = 0

        def counting_scandir(*args, **kwargs):
            nonlocal calls
            calls += 1
            return real_scandir(*args, **kwargs)

        monkeypatch.setattr(plan.os, "scandir", counting_scandir)

        assert plan.scan_for_code(str(tmp_path)).applicability is (
            plan.CodeApplicability.CODE_PRESENT
        )
        # The root holds the match, so no subdirectory is visited.
        assert calls == 1

    def test_no_match_scan_visits_each_directory_once(self, tmp_path, monkeypatch):
        import threat_modeling_mcp_server.tools.threat_model_plan as plan

        (tmp_path / "docs").mkdir()
        (tmp_path / "docs" / "notes.txt").write_text("x")
        real_scandir = plan.os.scandir
        visited = []

        def counting_scandir(path):
            visited.append((plan.os.fstat(path).st_dev, plan.os.fstat(path).st_ino))
            return real_scandir(path)

        monkeypatch.setattr(plan.os, "scandir", counting_scandir)

        assert plan.scan_for_code(str(tmp_path)).applicability is (
            plan.CodeApplicability.NO_CODE
        )
        assert len(visited) == 2
        assert len(set(visited)) == len(visited)

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
