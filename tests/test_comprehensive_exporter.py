"""Unit tests for the comprehensive exporter module."""

import json

import pytest

from threat_modeling_mcp_server.utils.comprehensive_exporter import (
    export_comprehensive_threat_model,
)


@pytest.fixture
def export_dir(tmp_path):
    """Return the .threatmodel directory the exporter writes into."""
    return tmp_path / ".threatmodel"


class TestExportFilenames:
    """Tests for the filenames produced by export_comprehensive_threat_model."""

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
        export_comprehensive_threat_model(str(tmp_path / output_path))

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
        export_comprehensive_threat_model(str(tmp_path / output_path))

        assert (export_dir / "my_model.md").is_file()

    def test_tc_json_input_does_not_double_the_extension(self, tmp_path, export_dir):
        """Test that a .tc.json output_path does not produce .tc.tc.json."""
        export_comprehensive_threat_model(str(tmp_path / "my_model.tc.json"))

        assert not (export_dir / "my_model.tc.tc.json").exists()
        assert not (export_dir / "my_model.tc.md").exists()

    def test_plain_json_file_is_not_created(self, tmp_path, export_dir):
        """Test that the export no longer writes a plain <name>.json file."""
        export_comprehensive_threat_model(str(tmp_path / "my_model.json"))

        assert not (export_dir / "my_model.json").exists()

    def test_exports_only_the_two_expected_files(self, tmp_path, export_dir):
        """Test that exactly the .tc.json and .md files are written."""
        export_comprehensive_threat_model(str(tmp_path / "my_model"))

        assert sorted(p.name for p in export_dir.iterdir()) == [
            "my_model.md",
            "my_model.tc.json",
        ]


class TestExportContent:
    """Tests for the content of the exported Threat Composer JSON."""

    def test_json_export_is_valid_json(self, tmp_path, export_dir):
        """Test that the exported .tc.json file contains valid JSON."""
        export_comprehensive_threat_model(str(tmp_path / "my_model"))

        with open(export_dir / "my_model.tc.json", encoding="utf-8") as f:
            assert isinstance(json.load(f), dict)

    def test_json_export_is_threat_composer_schema_1(self, tmp_path, export_dir):
        """Test that the exported JSON declares Threat Composer schema version 1."""
        export_comprehensive_threat_model(str(tmp_path / "my_model"))

        with open(export_dir / "my_model.tc.json", encoding="utf-8") as f:
            data = json.load(f)

        assert data["schema"] == 1

    def test_json_export_contains_threat_composer_fields(self, tmp_path, export_dir):
        """Test that the exported JSON contains the standard Threat Composer fields."""
        export_comprehensive_threat_model(str(tmp_path / "my_model"))

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
