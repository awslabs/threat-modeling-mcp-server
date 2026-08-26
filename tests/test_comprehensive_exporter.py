"""Unit tests for the comprehensive exporter module."""

import json

import pytest

from threat_modeling_mcp_server.utils.comprehensive_exporter import (
    build_extended_export_data,
    export_threat_model_files,
    generate_threat_model_markdown,
)
from threat_modeling_mcp_server.utils.state_collector import collect_all_state


@pytest.fixture
def export_dir(tmp_path):
    """Return the .threatmodel directory the exporter writes into."""
    return tmp_path / ".threatmodel"


class TestExportFilenames:
    """Tests for the filenames produced by export_threat_model_files."""

    @pytest.mark.parametrize(
        "output_path",
        [
            "my_model",
            "my_model.json",
            "my_model.tc.json",
        ],
    )
    def test_json_export_uses_tc_json_extension(self, tmp_path, export_dir, output_path):
        """Test that the JSON export is written as <name>.tc.json."""
        export_threat_model_files(str(tmp_path / output_path))

        assert (export_dir / "my_model.tc.json").is_file()

    @pytest.mark.parametrize(
        "output_path",
        [
            "my_model",
            "my_model.json",
            "my_model.tc.json",
        ],
    )
    def test_markdown_export_uses_md_extension(self, tmp_path, export_dir, output_path):
        """Test that the Markdown export is written as <name>.md."""
        export_threat_model_files(str(tmp_path / output_path))

        assert (export_dir / "my_model.md").is_file()

    def test_tc_json_input_does_not_double_the_extension(self, tmp_path, export_dir):
        """Test that a .tc.json output_path does not produce .tc.tc.json."""
        export_threat_model_files(str(tmp_path / "my_model.tc.json"))

        assert not (export_dir / "my_model.tc.tc.json").exists()
        assert not (export_dir / "my_model.tc.md").exists()

    def test_plain_json_file_is_not_created(self, tmp_path, export_dir):
        """Test that the export no longer writes a plain <name>.json file."""
        export_threat_model_files(str(tmp_path / "my_model.json"))

        assert not (export_dir / "my_model.json").exists()

    def test_exports_only_the_two_expected_files(self, tmp_path, export_dir):
        """Test that exactly the .tc.json and .md files are written."""
        export_threat_model_files(str(tmp_path / "my_model"))

        assert sorted(p.name for p in export_dir.iterdir()) == [
            "my_model.md",
            "my_model.tc.json",
        ]


class TestExportContent:
    """Tests for the content of the exported Threat Composer JSON."""

    def test_json_export_is_valid_json(self, tmp_path, export_dir):
        """Test that the exported .tc.json file contains valid JSON."""
        export_threat_model_files(str(tmp_path / "my_model"))

        with open(export_dir / "my_model.tc.json", encoding="utf-8") as f:
            assert isinstance(json.load(f), dict)

    def test_json_export_is_threat_composer_schema_1(self, tmp_path, export_dir):
        """Test that the exported JSON declares Threat Composer schema version 1."""
        export_threat_model_files(str(tmp_path / "my_model"))

        with open(export_dir / "my_model.tc.json", encoding="utf-8") as f:
            data = json.load(f)

        assert data["schema"] == 1

    def test_json_export_contains_threat_composer_fields(self, tmp_path, export_dir):
        """Test that the exported JSON contains the standard Threat Composer fields."""
        export_threat_model_files(str(tmp_path / "my_model"))

        with open(export_dir / "my_model.tc.json", encoding="utf-8") as f:
            data = json.load(f)

        for field in [
            "applicationInfo",
            "architecture",
            "dataflow",
            "assumptions",
            "mitigations",
            "assumptionLinks",
            "mitigationLinks",
            "threats",
        ]:
            assert field in data

    def test_successful_export_records_completed_phase_nine(
        self, tmp_path, export_dir, empty_threat_model_state
    ):
        import threat_modeling_mcp_server.tools.step_orchestrator as orchestrator

        export_threat_model_files(str(tmp_path / "my_model"))

        with open(export_dir / "my_model.tc.json", encoding="utf-8") as f:
            data = json.load(f)
        markdown = (export_dir / "my_model.md").read_text(encoding="utf-8")

        assert data["phaseProgress"]["phase_completion"]["9"] == 1.0
        assert orchestrator.phase_completion[9] == 1.0
        assert "| 9 | Output Generation and Documentation | 100% ✅ |" in markdown

    def test_standard_export_does_not_add_residual_assessment_field(
        self, tmp_path, export_dir
    ):
        export_threat_model_files(
            str(tmp_path / "standard"),
            include_extended_data=False,
        )

        with open(export_dir / "standard.tc.json", encoding="utf-8") as f:
            data = json.load(f)

        assert "residualRiskAssessments" not in data

    @pytest.mark.asyncio
    async def test_extended_exports_render_residual_assessments(
        self, empty_threat_model_state
    ):
        import threat_modeling_mcp_server.tools.threat_generator as threats

        threat_id = (
            await threats.add_threat_impl(
                None,
                "attacker",
                "with access",
                "read records",
                "data disclosure",
            )
        ).rsplit(": ", 1)[1]
        await threats.assess_threat_impl(
            None,
            threat_id,
            "Accepted",
            "The remaining low-probability exposure is accepted.",
            residual_severity="Low",
            residual_likelihood="Unlikely",
        )
        state = collect_all_state()

        extended = build_extended_export_data(state)
        markdown = generate_threat_model_markdown(state)

        assert extended["residualRiskAssessments"] == [{
            "threat_id": threat_id,
            "decision": "Accepted",
            "residual_severity": "Low",
            "residual_likelihood": "Unlikely",
            "rationale": "The remaining low-probability exposure is accepted.",
            "is_current": True,
        }]
        assert "**Residual Risk Decision**: Accepted" in markdown
