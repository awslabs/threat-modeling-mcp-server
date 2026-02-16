"""Unit tests for the step orchestrator module."""

import pytest
from unittest.mock import MagicMock, patch

from threat_modeling_mcp_server.tools.step_orchestrator import (
    PHASES,
    phase_completion,
    get_phase_guidance,
    get_current_phase_status,
    detect_phase_completion,
    get_current_phase_auto,
)


@pytest.fixture(autouse=True)
def reset_phase_completion():
    """Reset phase completion before each test."""
    for phase in phase_completion:
        phase_completion[phase] = 0.0
    yield
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
    """Tests for get_phase_guidance function."""

    def test_phase_1_guidance_contains_objectives(self):
        """Test that phase 1 guidance contains objectives."""
        guidance = get_phase_guidance(1)
        assert "Objective" in guidance
        assert "Business Context Analysis" in guidance

    def test_phase_1_guidance_contains_tools(self):
        """Test that phase 1 guidance contains tools to use."""
        guidance = get_phase_guidance(1)
        assert "Tools to Use" in guidance
        assert "set_business_context" in guidance

    def test_phase_1_guidance_contains_next_steps(self):
        """Test that phase 1 guidance contains next steps."""
        guidance = get_phase_guidance(1)
        assert "Next Steps" in guidance
        assert "Phase 2" in guidance

    def test_phase_2_guidance_contains_architecture_info(self):
        """Test that phase 2 guidance contains architecture information."""
        guidance = get_phase_guidance(2)
        assert "Architecture Analysis" in guidance
        assert "add_component" in guidance

    def test_phase_6_guidance_contains_stride(self):
        """Test that phase 6 guidance mentions STRIDE."""
        guidance = get_phase_guidance(6)
        assert "STRIDE" in guidance
        assert "add_threat" in guidance

    def test_phase_7_guidance_contains_mitigation_info(self):
        """Test that phase 7 guidance contains mitigation information."""
        guidance = get_phase_guidance(7)
        assert "Mitigation" in guidance
        assert "add_mitigation" in guidance

    def test_phase_7_5_guidance_contains_code_validation(self):
        """Test that phase 7.5 guidance contains code validation info."""
        guidance = get_phase_guidance(7.5)
        assert "Code Validation" in guidance
        assert "validate_security_controls" in guidance

    def test_phase_9_guidance_contains_export_info(self):
        """Test that phase 9 guidance contains export information."""
        guidance = get_phase_guidance(9)
        assert "Export" in guidance or "export" in guidance
        assert "threat_model" in guidance.lower()

    def test_unknown_phase_returns_no_guidance_message(self):
        """Test that unknown phase returns appropriate message."""
        guidance = get_phase_guidance(99)
        assert "No detailed guidance available" in guidance


class TestGetCurrentPhaseStatus:
    """Tests for get_current_phase_status function."""

    def test_status_contains_current_phase(self):
        """Test that status contains current phase information."""
        status = get_current_phase_status()
        assert "current_phase" in status
        assert "current_phase_name" in status

    def test_status_contains_completion_info(self):
        """Test that status contains completion information."""
        status = get_current_phase_status()
        assert "current_phase_completion" in status
        assert "overall_completion" in status

    def test_status_contains_phases_dict(self):
        """Test that status contains phases dictionary."""
        status = get_current_phase_status()
        assert "phases" in status
        assert isinstance(status["phases"], dict)

    def test_phases_in_status_have_name_and_completion(self):
        """Test that each phase in status has name and completion."""
        status = get_current_phase_status()
        for phase_num, phase_info in status["phases"].items():
            assert "name" in phase_info
            assert "completion" in phase_info

    def test_initial_overall_completion_is_low(self):
        """Test that initial overall completion is low (0.0 to 0.1)."""
        status = get_current_phase_status()
        # Note: phase_completion may have some initial values from state detection
        assert status["overall_completion"] <= 0.2


class TestGetCurrentPhaseAuto:
    """Tests for get_current_phase_auto function."""

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
                'features_set': 6,
            },
            'assumptions': 0,
            'architecture': {'components': 0, 'connections': 0, 'data_stores': 0},
            'threat_actors': 0,
            'trust_boundaries': {'trust_zones': 0, 'crossing_points': 0, 'trust_boundaries': 0},
            'asset_flows': {'assets': 0, 'flows': 0},
            'threats_mitigations': {'threats': 0, 'mitigations': 0, 'assumption_links': 0, 'mitigation_links': 0},
            'progress': {'current_phase': 1, 'current_phase_name': 'Test', 'overall_completion': 0.0}
        }
        detect_phase_completion()
        assert phase_completion[1] == 1.0

    @patch('threat_modeling_mcp_server.utils.state_collector.get_state_summary')
    def test_phase_2_complete_when_components_exist(self, mock_get_state):
        """Test that phase 2 is marked complete when components exist."""
        mock_get_state.return_value = {
            'business_context': {'has_description': False, 'features_set': 0},
            'assumptions': 0,
            'architecture': {'components': 3, 'connections': 2, 'data_stores': 1},
            'threat_actors': 0,
            'trust_boundaries': {'trust_zones': 0, 'crossing_points': 0, 'trust_boundaries': 0},
            'asset_flows': {'assets': 0, 'flows': 0},
            'threats_mitigations': {'threats': 0, 'mitigations': 0, 'assumption_links': 0, 'mitigation_links': 0},
            'progress': {'current_phase': 1, 'current_phase_name': 'Test', 'overall_completion': 0.0}
        }
        detect_phase_completion()
        assert phase_completion[2] == 1.0

    @patch('threat_modeling_mcp_server.utils.state_collector.get_state_summary')
    def test_phase_6_complete_when_threats_exist(self, mock_get_state):
        """Test that phase 6 is marked complete when threats exist."""
        mock_get_state.return_value = {
            'business_context': {'has_description': False, 'features_set': 0},
            'assumptions': 0,
            'architecture': {'components': 0, 'connections': 0, 'data_stores': 0},
            'threat_actors': 0,
            'trust_boundaries': {'trust_zones': 0, 'crossing_points': 0, 'trust_boundaries': 0},
            'asset_flows': {'assets': 0, 'flows': 0},
            'threats_mitigations': {'threats': 5, 'mitigations': 0, 'assumption_links': 0, 'mitigation_links': 0},
            'progress': {'current_phase': 1, 'current_phase_name': 'Test', 'overall_completion': 0.0}
        }
        detect_phase_completion()
        assert phase_completion[6] == 1.0

    @patch('threat_modeling_mcp_server.utils.state_collector.get_state_summary')
    def test_phase_7_complete_when_mitigations_linked(self, mock_get_state):
        """Test that phase 7 is marked complete when mitigations are linked."""
        mock_get_state.return_value = {
            'business_context': {'has_description': False, 'features_set': 0},
            'assumptions': 0,
            'architecture': {'components': 0, 'connections': 0, 'data_stores': 0},
            'threat_actors': 0,
            'trust_boundaries': {'trust_zones': 0, 'crossing_points': 0, 'trust_boundaries': 0},
            'asset_flows': {'assets': 0, 'flows': 0},
            'threats_mitigations': {'threats': 5, 'mitigations': 3, 'assumption_links': 0, 'mitigation_links': 2},
            'progress': {'current_phase': 1, 'current_phase_name': 'Test', 'overall_completion': 0.0}
        }
        detect_phase_completion()
        assert phase_completion[7] == 1.0


class TestPhaseGuidanceContent:
    """Tests for phase guidance content quality."""

    def test_all_phases_have_objectives(self):
        """Test that all phases have objectives in their guidance."""
        for phase_num in PHASES.keys():
            guidance = get_phase_guidance(phase_num)
            assert "Objective" in guidance, f"Phase {phase_num} missing Objective section"

    def test_all_phases_have_steps(self):
        """Test that all phases have steps in their guidance."""
        for phase_num in PHASES.keys():
            guidance = get_phase_guidance(phase_num)
            assert "Steps" in guidance or "Step" in guidance, f"Phase {phase_num} missing Steps section"

    def test_all_phases_have_tools(self):
        """Test that all phases have tools listed in their guidance."""
        for phase_num in PHASES.keys():
            guidance = get_phase_guidance(phase_num)
            assert "Tools to Use" in guidance, f"Phase {phase_num} missing Tools section"

    def test_guidance_includes_markdown_headers(self):
        """Test that guidance includes markdown headers."""
        guidance = get_phase_guidance(1)
        assert guidance.startswith("#") or "# Phase" in guidance
