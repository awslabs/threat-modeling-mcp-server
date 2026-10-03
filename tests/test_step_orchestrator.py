"""Unit tests for the step orchestrator module."""

import pytest
from unittest.mock import patch

import threat_modeling_mcp_server.tools.step_orchestrator as orchestrator
from threat_modeling_mcp_server.tools.step_orchestrator import (
    PHASES,
    phase_completion,
    build_phase_guidance,
    get_workflow_status,
    detect_phase_completion,
    get_current_phase_auto,
)


def phase_readiness(*complete_phases):
    """Build the state-summary readiness contract for mocked collector tests."""
    return {
        str(phase): {
            "is_complete": phase in complete_phases,
            "blocking_reasons": (
                [] if phase in complete_phases else [f"phase {phase} incomplete"]
            ),
        }
        for phase in (1, 2, 3, 4, 5, 6, 7, 8, 9)
    }


@pytest.fixture(autouse=True)
def reset_phase_completion():
    """Reset phase completion and project selection before each test."""
    original_project_directory = orchestrator.project_directory
    for phase in phase_completion:
        phase_completion[phase] = 0.0
    yield
    orchestrator.project_directory = original_project_directory
    for phase in phase_completion:
        phase_completion[phase] = 0.0


class TestPhasesConfiguration:
    """Tests for phases configuration."""

    def test_phases_contains_all_phases(self):
        """Test that PHASES dictionary contains all expected phases."""
        expected_phases = [1, 2, 3, 4, 5, 6, 7, 7.5, 8, 9]
        for phase in expected_phases:
            assert phase in PHASES

    def test_phase_1_is_business_context(self):
        """Test that phase 1 is Business Context Analysis."""
        assert PHASES[1] == "Business Context Analysis"

    def test_phase_6_is_threat_identification(self):
        """Test that phase 6 is Threat Identification."""
        assert PHASES[6] == "Threat Identification"

    def test_phase_7_5_is_code_validation(self):
        """Test that phase 7.5 is Code Validation Analysis."""
        assert PHASES[7.5] == "Code Validation Analysis"

    def test_phase_9_is_output_generation(self):
        """Test that phase 9 is Output Generation."""
        assert PHASES[9] == "Output Generation and Documentation"


class TestGetPhaseGuidance:
    """Tests for the phase-guidance text builder."""

    def test_phase_1_guidance_contains_objectives(self):
        """Test that phase 1 guidance contains objectives."""
        guidance = build_phase_guidance(1)
        assert "Objective" in guidance
        assert "Business Context Analysis" in guidance

    def test_phase_1_guidance_contains_tools(self):
        """Test that phase 1 guidance contains tools to use."""
        guidance = build_phase_guidance(1)
        assert "Tools to Use" in guidance
        assert "manage_system_context" in guidance

    def test_phase_1_guidance_contains_next_steps(self):
        """Test that phase 1 guidance contains next steps."""
        guidance = build_phase_guidance(1)
        assert "Next Steps" in guidance
        assert "Phase 2" in guidance

    def test_phase_2_guidance_contains_architecture_info(self):
        """Test that phase 2 guidance contains architecture information."""
        guidance = build_phase_guidance(2)
        assert "Architecture Analysis" in guidance
        assert "manage_architecture" in guidance

    def test_phase_6_guidance_contains_stride(self):
        """Test that phase 6 guidance mentions STRIDE."""
        guidance = build_phase_guidance(6)
        assert "STRIDE" in guidance
        assert "manage_threats" in guidance

    def test_phase_7_guidance_contains_mitigation_info(self):
        """Test that phase 7 guidance contains mitigation information."""
        guidance = build_phase_guidance(7)
        assert "Mitigation" in guidance
        assert "manage_threats" in guidance

    def test_phase_7_5_guidance_contains_code_validation(self):
        """Test that phase 7.5 guidance contains code validation info."""
        guidance = build_phase_guidance(7.5)
        assert "Code Validation" in guidance
        assert "manage_code_validation" in guidance

    def test_phase_9_guidance_contains_export_info(self):
        """Test that phase 9 guidance contains export information."""
        guidance = build_phase_guidance(9)
        assert "Export" in guidance or "export" in guidance
        assert "threat_model" in guidance.lower()

    def test_unknown_phase_returns_no_guidance_message(self):
        """Test that unknown phase returns appropriate message."""
        guidance = build_phase_guidance(99)
        assert "No detailed guidance available" in guidance


class TestGetPhaseGuidanceTool:
    """Tests for the consolidated MCP boundary."""

    @staticmethod
    async def call(**arguments):
        import threat_modeling_mcp_server.server as srv

        _, structured = await srv.mcp.call_tool(
            "manage_workflow",
            {"action": "guidance", **arguments},
        )
        return structured["result"]

    @pytest.mark.asyncio
    async def test_explicit_phase(self):
        guidance = await self.call(phase="2")

        assert "# Phase 2: Architecture Analysis" in guidance

    @pytest.mark.asyncio
    async def test_current_phase(self, monkeypatch):
        monkeypatch.setattr(orchestrator, "current_phase", 4)

        guidance = await self.call(phase="current")

        assert "# Phase 4: Trust Boundary Analysis" in guidance

    @pytest.mark.asyncio
    async def test_phase_7_uses_recorded_project_directory(self, monkeypatch):
        monkeypatch.setattr(orchestrator, "project_directory", "/recorded/project")

        with patch(
            "threat_modeling_mcp_server.tools.step_orchestrator.detect_code_in_directory",
            return_value=True,
        ) as detect_code:
            guidance = await self.call(phase="7")

        detect_code.assert_awaited_once_with("/recorded/project")
        assert 'manage_workflow(action="guidance", phase="7.5")' in guidance

    @pytest.mark.asyncio
    async def test_phase_7_accepts_directory_override(self):
        with patch(
            "threat_modeling_mcp_server.tools.step_orchestrator.detect_code_in_directory",
            return_value=False,
        ) as detect_code:
            guidance = await self.call(
                phase="7",
                directory="/override/project",
            )

        detect_code.assert_awaited_once_with("/override/project")
        assert 'manage_workflow(action="guidance", phase="8")' in guidance


class TestExportPathResolution:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("requested_path", "base_filename", "include_extended_data"),
        [
            ("relative-model.json", "relative-model", True),
            ("../escape.json", "escape", False),
            ("/outside/absolute.tc.json", "absolute", True),
            ("nested/report.md", "report", False),
            (r"C:\outside\windows.json", "windows", True),
        ],
    )
    async def test_all_export_paths_stay_in_selected_project(
        self,
        tmp_path,
        monkeypatch,
        empty_threat_model_state,
        requested_path,
        base_filename,
        include_extended_data,
    ):
        server_cwd = tmp_path / "server-cwd"
        project_directory = tmp_path / "project" / "subproject"
        outside = tmp_path / "outside"
        server_cwd.mkdir()
        project_directory.mkdir(parents=True)
        outside.mkdir()
        monkeypatch.chdir(server_cwd)
        orchestrator.set_project_directory(str(project_directory))

        result = await orchestrator.export_threat_model_impl(
            None,
            requested_path,
            include_extended_data=include_extended_data,
        )

        export_directory = project_directory / ".threatmodel"
        json_path = export_directory / f"{base_filename}.tc.json"
        markdown_path = export_directory / f"{base_filename}.md"
        assert json_path.is_file()
        assert markdown_path.is_file()
        assert str(json_path.resolve()) in result
        assert str(markdown_path.resolve()) in result
        assert not list(project_directory.glob("*.json"))
        assert not list(project_directory.glob("*.md"))
        assert not (server_cwd / ".threatmodel").exists()
        assert not list(outside.rglob("*.json"))
        assert not list(outside.rglob("*.md"))

    @pytest.mark.asyncio
    async def test_omitted_path_uses_timestamped_name_in_selected_project(
        self, tmp_path, monkeypatch, empty_threat_model_state,
    ):
        server_cwd = tmp_path / "server-cwd"
        project_directory = tmp_path / "project"
        server_cwd.mkdir()
        project_directory.mkdir()
        monkeypatch.chdir(server_cwd)
        orchestrator.set_project_directory(str(project_directory))

        result = await orchestrator.export_threat_model_impl(None)

        export_directory = project_directory / ".threatmodel"
        json_files = list(export_directory.glob(
            "comprehensive_threat_model_*.tc.json"
        ))
        markdown_files = list(export_directory.glob(
            "comprehensive_threat_model_*.md"
        ))
        assert len(json_files) == 1
        assert len(markdown_files) == 1
        assert json_files[0].name.removesuffix(".tc.json") == (
            markdown_files[0].name.removesuffix(".md")
        )
        assert str(json_files[0].resolve()) in result
        assert str(markdown_files[0].resolve()) in result
        assert not (server_cwd / ".threatmodel").exists()

    @pytest.mark.asyncio
    async def test_export_requires_an_explicit_project_selection(
        self, tmp_path, monkeypatch, empty_threat_model_state,
    ):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(orchestrator, "project_directory", None)

        result = await orchestrator.export_threat_model_impl(None, "model.json")

        assert "No project directory is selected" in result
        assert not (tmp_path / ".threatmodel").exists()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("invalid_path", ["..", ".md", ".json", ".tc.json", "/"])
    async def test_invalid_base_filename_is_rejected(
        self, tmp_path, empty_threat_model_state, invalid_path,
    ):
        orchestrator.set_project_directory(str(tmp_path))

        result = await orchestrator.export_threat_model_impl(None, invalid_path)

        assert "valid" in result
        assert "filename" in result
        assert not (tmp_path / ".threatmodel").exists()

    @pytest.mark.asyncio
    async def test_escaping_threatmodel_symlink_is_rejected(
        self, tmp_path, empty_threat_model_state,
    ):
        project_directory = tmp_path / "project"
        outside = tmp_path / "outside"
        project_directory.mkdir()
        outside.mkdir()
        (project_directory / ".threatmodel").symlink_to(
            outside, target_is_directory=True,
        )
        orchestrator.set_project_directory(str(project_directory))

        result = await orchestrator.export_threat_model_impl(None, "model.json")

        assert "resolves outside the project directory" in result
        assert not list(outside.iterdir())


class TestGetWorkflowStatus:
    """Tests for the workflow status implementation."""

    def test_status_contains_current_phase(self):
        """Test that status contains current phase information."""
        status = get_workflow_status()
        assert "current_phase" in status
        assert "current_phase_name" in status

    def test_status_contains_completion_info(self):
        """Test that status contains completion information."""
        status = get_workflow_status()
        assert "current_phase_completion" in status
        assert "overall_completion" in status

    def test_status_contains_phases_dict(self):
        """Test that status contains phases dictionary."""
        status = get_workflow_status()
        assert "phases" in status
        assert isinstance(status["phases"], dict)

    def test_phases_in_status_have_name_and_completion(self):
        """Test that each phase in status has name and completion."""
        status = get_workflow_status()
        for phase_num, phase_info in status["phases"].items():
            assert "name" in phase_info
            assert "completion" in phase_info

    def test_initial_overall_completion_is_low(self, empty_threat_model_state):
        """Overall completion is low when no work has been recorded.

        The empty_threat_model_state fixture clears the tool stores first:
        several modules seed a default library on import (assets, threat actors,
        trust zones), and phases 3, 4 and 5 are detected purely from those stores
        being non-empty. Without the fixture this test passes or fails according
        to which other test modules pytest imported first.
        """
        status = get_workflow_status()
        assert status["overall_completion"] <= 0.2


class TestGetCurrentPhaseAuto:
    """Tests for get_current_phase_auto function.

    detect_phase_completion() is stubbed out: it derives completion from real
    state (and resets phases that are no longer complete), which would override
    the phase_completion values these tests set up deliberately.
    """

    @pytest.fixture(autouse=True)
    def no_detection(self):
        with patch('threat_modeling_mcp_server.tools.step_orchestrator.detect_phase_completion'):
            yield

    def test_returns_first_phase_when_all_incomplete(self):
        """Test that function returns phase 1 when all phases are incomplete."""
        phase = get_current_phase_auto()
        assert phase == 1

    def test_returns_next_incomplete_phase(self):
        """Test that function returns next incomplete phase."""
        phase_completion[1] = 1.0
        phase = get_current_phase_auto()
        assert phase == 2

    def test_returns_phase_after_multiple_complete(self):
        """Test that function returns correct phase after multiple complete."""
        phase_completion[1] = 1.0
        phase_completion[2] = 1.0
        phase_completion[3] = 1.0
        phase = get_current_phase_auto()
        assert phase == 4

    def test_returns_last_phase_when_all_complete(self):
        """Test that function returns last phase when all are complete."""
        for phase in phase_completion:
            phase_completion[phase] = 1.0
        phase = get_current_phase_auto()
        # Should return the last phase (9)
        assert phase == 9


class TestDetectPhaseCompletion:
    """Tests for detect_phase_completion function."""

    def test_detect_completion_does_not_raise(self):
        """Test that detect_phase_completion doesn't raise errors."""
        # Should not raise even with empty state
        try:
            detect_phase_completion()
        except Exception as e:
            pytest.fail(f"detect_phase_completion raised {e}")

    @patch('threat_modeling_mcp_server.utils.state_collector.get_state_summary')
    def test_phase_1_complete_when_context_set(self, mock_get_state):
        """Test that phase 1 is marked complete when business context is set."""
        mock_get_state.return_value = {
            'business_context': {
                'has_description': True,
                'features_set': 11,
                'features_total': 11,
                'is_complete': True,
            },
            'assumptions': 0,
            'architecture': {'components': 0, 'connections': 0, 'data_stores': 0},
            'threat_actors': 0,
            'reviewed_threat_actors': 0,
            'trust_boundaries': {
                'trust_zones': 0,
                'crossing_points': 0, 'trust_boundaries': 0,
            },
            'asset_flows': {'assets': 0, 'flows': 0},
            'threats_mitigations': {'threats': 0, 'mitigations': 0, 'mitigation_links': 0},
            'phase_readiness': phase_readiness(1),
            'progress': {'current_phase': 1, 'current_phase_name': 'Test', 'overall_completion': 0.0}
        }
        detect_phase_completion()
        assert phase_completion[1] == 1.0

    @patch('threat_modeling_mcp_server.utils.state_collector.get_state_summary')
    def test_phase_2_complete_when_components_exist(self, mock_get_state):
        """Test that phase 2 is marked complete when components exist."""
        mock_get_state.return_value = {
            'business_context': {'has_description': False, 'features_set': 0,
                                 'features_total': 11, 'is_complete': False},
            'assumptions': 0,
            'architecture': {'components': 3, 'connections': 2, 'data_stores': 1},
            'threat_actors': 0,
            'reviewed_threat_actors': 0,
            'trust_boundaries': {
                'trust_zones': 0,
                'crossing_points': 0, 'trust_boundaries': 0,
            },
            'asset_flows': {'assets': 0, 'flows': 0},
            'threats_mitigations': {'threats': 0, 'mitigations': 0, 'mitigation_links': 0},
            'phase_readiness': phase_readiness(2),
            'progress': {'current_phase': 1, 'current_phase_name': 'Test', 'overall_completion': 0.0}
        }
        detect_phase_completion()
        assert phase_completion[2] == 1.0

    @patch('threat_modeling_mcp_server.utils.state_collector.get_state_summary')
    def test_phase_6_complete_when_threats_exist(self, mock_get_state):
        """Test that phase 6 is marked complete when threats exist."""
        mock_get_state.return_value = {
            'business_context': {'has_description': False, 'features_set': 0,
                                 'features_total': 11, 'is_complete': False},
            'assumptions': 0,
            'architecture': {'components': 0, 'connections': 0, 'data_stores': 0},
            'threat_actors': 0,
            'reviewed_threat_actors': 0,
            'trust_boundaries': {
                'trust_zones': 0,
                'crossing_points': 0, 'trust_boundaries': 0,
            },
            'asset_flows': {'assets': 0, 'flows': 0},
            'threats_mitigations': {'threats': 5, 'mitigations': 0, 'mitigation_links': 0},
            'phase_readiness': phase_readiness(6),
            'progress': {'current_phase': 1, 'current_phase_name': 'Test', 'overall_completion': 0.0}
        }
        detect_phase_completion()
        assert phase_completion[6] == 1.0

    @patch('threat_modeling_mcp_server.utils.state_collector.get_state_summary')
    def test_phase_7_complete_when_mitigations_linked(self, mock_get_state):
        """Test that phase 7 is marked complete when mitigations are linked."""
        mock_get_state.return_value = {
            'business_context': {'has_description': False, 'features_set': 0,
                                 'features_total': 11, 'is_complete': False},
            'assumptions': 0,
            'architecture': {'components': 0, 'connections': 0, 'data_stores': 0},
            'threat_actors': 0,
            'reviewed_threat_actors': 0,
            'trust_boundaries': {
                'trust_zones': 0,
                'crossing_points': 0, 'trust_boundaries': 0,
            },
            'asset_flows': {'assets': 0, 'flows': 0},
            'threats_mitigations': {'threats': 5, 'mitigations': 3, 'mitigation_links': 2},
            'phase_readiness': phase_readiness(7),
            'progress': {'current_phase': 1, 'current_phase_name': 'Test', 'overall_completion': 0.0}
        }
        detect_phase_completion()
        assert phase_completion[7] == 1.0


class TestPhaseGuidanceContent:
    """Tests for phase guidance content quality."""

    def test_all_phases_have_objectives(self):
        """Test that all phases have objectives in their guidance."""
        for phase_num in PHASES.keys():
            guidance = build_phase_guidance(phase_num)
            assert "Objective" in guidance, f"Phase {phase_num} missing Objective section"

    def test_all_phases_have_steps(self):
        """Test that all phases have steps in their guidance."""
        for phase_num in PHASES.keys():
            guidance = build_phase_guidance(phase_num)
            assert "Steps" in guidance or "Step" in guidance, f"Phase {phase_num} missing Steps section"

    def test_all_phases_have_tools(self):
        """Test that all phases have tools listed in their guidance."""
        for phase_num in PHASES.keys():
            guidance = build_phase_guidance(phase_num)
            assert "Tools to Use" in guidance, f"Phase {phase_num} missing Tools section"

    def test_guidance_includes_markdown_headers(self):
        """Test that guidance includes markdown headers."""
        guidance = build_phase_guidance(1)
        assert guidance.startswith("#") or "# Phase" in guidance
