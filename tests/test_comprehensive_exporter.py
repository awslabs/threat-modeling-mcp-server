"""Unit tests for the comprehensive exporter module."""

import json
import re

import pytest

from threat_modeling_mcp_server.utils.comprehensive_exporter import (
    THREAT_COMPOSER_TOP_LEVEL_KEYS,
    ExportWarnings,
    build_extended_export_data,
    export_threat_model_files,
    generate_threat_model_markdown,
    to_threat_composer_id,
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
            "my_model.md",
        ],
    )
    def test_json_export_uses_tc_json_extension(self, tmp_path, export_dir, output_path):
        """Test that the JSON export is written as <name>.tc.json."""
        export_threat_model_files(
            str(tmp_path / output_path), str(tmp_path),
        )

        assert (export_dir / "my_model.tc.json").is_file()

    @pytest.mark.parametrize(
        "output_path",
        [
            "my_model",
            "my_model.json",
            "my_model.tc.json",
            "my_model.md",
        ],
    )
    def test_markdown_export_uses_md_extension(self, tmp_path, export_dir, output_path):
        """Test that the Markdown export is written as <name>.md."""
        export_threat_model_files(
            str(tmp_path / output_path), str(tmp_path),
        )

        assert (export_dir / "my_model.md").is_file()

    def test_tc_json_input_does_not_double_the_extension(self, tmp_path, export_dir):
        """Test that a .tc.json output_path does not produce .tc.tc.json."""
        export_threat_model_files(
            str(tmp_path / "my_model.tc.json"), str(tmp_path),
        )

        assert not (export_dir / "my_model.tc.tc.json").exists()
        assert not (export_dir / "my_model.tc.md").exists()

    def test_plain_json_file_is_not_created(self, tmp_path, export_dir):
        """Test that the export no longer writes a plain <name>.json file."""
        export_threat_model_files(
            str(tmp_path / "my_model.json"), str(tmp_path),
        )

        assert not (export_dir / "my_model.json").exists()

    def test_default_export_writes_the_three_expected_files(self, tmp_path, export_dir):
        """By default the strict .tc.json, the .md, and the snapshot are written."""
        export_threat_model_files(
            str(tmp_path / "my_model"), str(tmp_path),
        )

        assert sorted(p.name for p in export_dir.iterdir()) == [
            "my_model.extended.json",
            "my_model.md",
            "my_model.tc.json",
        ]

    def test_standard_export_writes_only_two_files(self, tmp_path, export_dir):
        """include_extended_data=False skips the extended snapshot."""
        export_threat_model_files(
            str(tmp_path / "my_model"), str(tmp_path), include_extended_data=False,
        )

        assert sorted(p.name for p in export_dir.iterdir()) == [
            "my_model.md",
            "my_model.tc.json",
        ]

    def test_extended_json_input_selects_the_same_base(self, tmp_path, export_dir):
        export_threat_model_files("my_model.extended.json", str(tmp_path))

        assert (export_dir / "my_model.tc.json").is_file()
        assert (export_dir / "my_model.extended.json").is_file()
        assert not (export_dir / "my_model.extended.tc.json").exists()


class TestExportContent:
    """Tests for the content of the exported Threat Composer JSON."""

    def test_json_export_is_valid_json(self, tmp_path, export_dir):
        """Test that the exported .tc.json file contains valid JSON."""
        export_threat_model_files(
            str(tmp_path / "my_model"), str(tmp_path),
        )

        with open(export_dir / "my_model.tc.json", encoding="utf-8") as f:
            assert isinstance(json.load(f), dict)

    def test_json_export_is_threat_composer_schema_1(self, tmp_path, export_dir):
        """Test that the exported JSON declares Threat Composer schema version 1."""
        export_threat_model_files(
            str(tmp_path / "my_model"), str(tmp_path),
        )

        with open(export_dir / "my_model.tc.json", encoding="utf-8") as f:
            data = json.load(f)

        assert data["schema"] == 1

    def test_json_export_contains_threat_composer_fields(self, tmp_path, export_dir):
        """Test that the exported JSON contains the standard Threat Composer fields."""
        export_threat_model_files(
            str(tmp_path / "my_model"), str(tmp_path),
        )

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

        export_threat_model_files(
            str(tmp_path / "my_model"), str(tmp_path),
        )

        with open(export_dir / "my_model.extended.json", encoding="utf-8") as f:
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
            str(tmp_path),
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


UUID5_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


async def _add_threat(source="attacker", action="read records", tags=None, **kwargs):
    import threat_modeling_mcp_server.tools.threat_generator as threats

    result = await threats.add_threat_impl(
        None,
        source,
        kwargs.pop("prerequisites", "with access"),
        action,
        kwargs.pop("impact", "data disclosure"),
        tags=tags,
        **kwargs,
    )
    return result.rsplit(": ", 1)[1]


async def _add_mitigation(content="Encrypt records"):
    import threat_modeling_mcp_server.tools.threat_generator as threats

    result = await threats.add_mitigation_impl(None, content)
    return result.rsplit(": ", 1)[1]


def _load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


class TestThreatComposerIds:
    """Exported ids are deterministic, type-qualified UUIDv5 values."""

    def test_known_mapping_value(self):
        assert to_threat_composer_id("threat", "T001") == (
            "ba25dd1d-cee0-5e02-a7d7-fde24d6d0f26"
        )

    def test_entity_type_is_part_of_the_name(self):
        assert to_threat_composer_id("threat", "X1") != (
            to_threat_composer_id("mitigation", "X1")
        )
        assert to_threat_composer_id("threat", "T001") != (
            to_threat_composer_id("mitigation", "M001")
        )

    @pytest.mark.asyncio
    async def test_all_ids_and_links_are_uuids_with_integrity(
        self, tmp_path, export_dir, empty_threat_model_state
    ):
        import threat_modeling_mcp_server.tools.assumption_manager as assumptions
        import threat_modeling_mcp_server.tools.threat_generator as threats

        threat_id = await _add_threat()
        mitigation_id = await _add_mitigation()
        await threats.link_mitigation_to_threat_impl(None, mitigation_id, threat_id)
        await assumptions.add_assumption_impl(
            None, "Network is private", "Network", "Low", "Documented",
        )

        export_threat_model_files("ids", str(tmp_path))
        data = _load(export_dir / "ids.tc.json")

        ids = [
            entity["id"]
            for section in ("threats", "mitigations", "assumptions")
            for entity in data[section]
        ]
        assert len(ids) == 3
        for value in ids:
            assert UUID5_PATTERN.match(value), value
        assert data["threats"][0]["id"] == to_threat_composer_id("threat", threat_id)

        threat_ids = {t["id"] for t in data["threats"]}
        mitigation_ids = {m["id"] for m in data["mitigations"]}
        assert data["mitigationLinks"] == [{
            "mitigationId": to_threat_composer_id("mitigation", mitigation_id),
            "linkedId": to_threat_composer_id("threat", threat_id),
        }]
        for link in data["mitigationLinks"]:
            assert len(link["mitigationId"]) == 36 and len(link["linkedId"]) == 36
            assert link["mitigationId"] in mitigation_ids
            assert link["linkedId"] in threat_ids
        assert data["assumptionLinks"] == []

        # Internal ids stay readable everywhere else.
        assert threat_id == "T001" and threat_id in threats.threats
        extended = _load(export_dir / "ids.extended.json")
        assert extended["threats"][0]["id"] == threat_id

    @pytest.mark.asyncio
    async def test_ids_are_stable_across_exports(
        self, tmp_path, export_dir, empty_threat_model_state
    ):
        await _add_threat()
        await _add_mitigation()

        export_threat_model_files("first", str(tmp_path))
        export_threat_model_files("second", str(tmp_path))
        first = _load(export_dir / "first.tc.json")
        second = _load(export_dir / "second.tc.json")

        for section in ("threats", "mitigations"):
            assert [e["id"] for e in first[section]] == (
                [e["id"] for e in second[section]]
            )

    @pytest.mark.asyncio
    async def test_dangling_link_is_omitted(
        self, tmp_path, export_dir, empty_threat_model_state
    ):
        import threat_modeling_mcp_server.tools.threat_generator as threats
        from threat_modeling_mcp_server.models.threat_models import MitigationLink

        threat_id = await _add_threat()
        mitigation_id = await _add_mitigation()
        threats.mitigation_links.append(
            MitigationLink(linkedId="T999", mitigationId=mitigation_id)
        )
        await threats.link_mitigation_to_threat_impl(None, mitigation_id, threat_id)

        export_threat_model_files("dangling", str(tmp_path))
        data = _load(export_dir / "dangling.tc.json")

        assert [link["linkedId"] for link in data["mitigationLinks"]] == [
            to_threat_composer_id("threat", threat_id)
        ]


class TestStrictThreatComposerFile:
    """The .tc.json is always strictly import-shaped."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("include_extended_data", [True, False])
    async def test_tc_json_has_only_allowed_top_level_keys(
        self, tmp_path, export_dir, empty_threat_model_state, include_extended_data
    ):
        await _add_threat()
        export_threat_model_files(
            "strict", str(tmp_path), include_extended_data=include_extended_data,
        )
        data = _load(export_dir / "strict.tc.json")

        assert set(data) == THREAT_COMPOSER_TOP_LEVEL_KEYS
        assert set(data) == {
            "schema", "applicationInfo", "architecture", "dataflow",
            "assumptions", "mitigations", "assumptionLinks",
            "mitigationLinks", "threats",
        }

    @pytest.mark.asyncio
    async def test_extended_snapshot_is_labeled_not_importable(
        self, tmp_path, export_dir, empty_threat_model_state
    ):
        threat_id = await _add_threat()
        result = export_threat_model_files("snap", str(tmp_path))
        snapshot = _load(export_dir / "snap.extended.json")

        assert snapshot["importableIntoThreatComposer"] is False
        assert snapshot["exportType"] == (
            "threat-modeling-mcp-server-extended-snapshot"
        )
        assert snapshot["threatComposerFile"] == "snap.tc.json"
        assert "Not a Threat Composer import file" in snapshot["notice"]
        assert snapshot["threats"][0]["id"] == threat_id
        for key in ("businessContext", "components", "phaseProgress",
                    "residualRiskAssessments", "softwareProfile"):
            assert key in snapshot
        assert "NOT importable into Threat Composer" in result
        assert "ignores" not in result


class TestExportWarnings:
    """Shortening for the strict export is reported without field contents."""

    @pytest.mark.asyncio
    async def test_exact_limit_values_produce_no_warnings(
        self, tmp_path, export_dir, empty_threat_model_state
    ):
        await _add_threat(source="s" * 200, tags=["t" * 30])

        result = export_threat_model_files("exact", str(tmp_path))
        data = _load(export_dir / "exact.tc.json")

        assert "Export Warnings" not in result
        assert data["threats"][0]["threatSource"] == "s" * 200
        assert data["threats"][0]["tags"] == ["t" * 30]

    @pytest.mark.asyncio
    async def test_shortened_fields_are_reported_without_contents(
        self, tmp_path, export_dir, empty_threat_model_state
    ):
        from loguru import logger

        sentinel = "ZQXSENTINEL"
        tag = f"OWASP {sentinel} Sensitive Information Disclosure"  # 49 chars
        action = (f"{sentinel} exfiltrate " * 20)[:250]
        threat_id = await _add_threat(action=action, tags=[tag])

        captured = []
        sink_id = logger.add(captured.append, level="DEBUG")
        try:
            result = export_threat_model_files("warn", str(tmp_path))
        finally:
            logger.remove(sink_id)

        data = _load(export_dir / "warn.tc.json")
        exported_tag = data["threats"][0]["tags"][0]
        exported_action = data["threats"][0]["threatAction"]
        assert len(exported_tag) <= 30
        assert len(exported_action) <= 200

        assert "## Export Warnings" in result
        assert (
            f"- threat {threat_id} tags[0]: shortened from {len(tag)} to "
            f"{len(exported_tag)} characters (Threat Composer limit 30)"
        ) in result
        assert (
            f"- threat {threat_id} threatAction: shortened from 250 to "
            f"{len(exported_action)} characters (Threat Composer limit 200)"
        ) in result
        assert sentinel not in result
        assert exported_tag not in result
        assert not any(sentinel in str(message) for message in captured)

        # Full text survives everywhere except the strict file.
        markdown = (export_dir / "warn.md").read_text(encoding="utf-8")
        snapshot = _load(export_dir / "warn.extended.json")
        assert tag in markdown
        assert snapshot["threats"][0]["tags"] == [tag]
        assert snapshot["threats"][0]["threatAction"] == action

    def test_duplicate_keys_collapse_to_one_line(self):
        warnings = ExportWarnings()
        for _ in range(3):
            warnings.truncate("x" * 50, 30, "threat", "T001", "tags[0]")

        assert len(warnings) == 1
        assert len(warnings.lines()) == 1

    def test_warning_lines_are_bounded(self):
        warnings = ExportWarnings()
        for index in range(25):
            warnings.truncate("x" * 50, 30, "threat", f"T{index:03d}", "tags[0]")

        lines = warnings.lines()
        assert len(lines) == 21
        assert lines[-1] == "- … and 5 more field(s) shortened"

    @pytest.mark.asyncio
    async def test_long_mitigation_content_is_shortened_with_warning(
        self, tmp_path, export_dir, empty_threat_model_state
    ):
        content = "word " * 240  # 1200 chars
        mitigation_id = await _add_mitigation(content)

        result = export_threat_model_files("mit", str(tmp_path))
        data = _load(export_dir / "mit.tc.json")

        assert len(data["mitigations"][0]["content"]) <= 1000
        assert f"- mitigation {mitigation_id} content: shortened from 1200" in result
        snapshot = _load(export_dir / "mit.extended.json")
        assert snapshot["mitigations"][0]["content"] == content

    @pytest.mark.asyncio
    async def test_warning_preamble_omits_snapshot_when_not_written(
        self, tmp_path, export_dir, empty_threat_model_state
    ):
        await _add_threat(tags=["x" * 50])

        result = export_threat_model_files(
            "nosnap", str(tmp_path), include_extended_data=False,
        )

        assert "## Export Warnings" in result
        assert "The stored model and Markdown keep the full text." in result
        assert "extended snapshot keep" not in result
        assert not (export_dir / "nosnap.extended.json").exists()


class TestContentFreeLogging:
    """Model text that the strict export may shorten never reaches the logs."""

    @pytest.mark.asyncio
    async def test_assumption_and_business_context_text_is_not_logged(
        self, tmp_path, empty_threat_model_state
    ):
        from loguru import logger

        from threat_modeling_mcp_server.tools.assumption_manager import (
            add_assumption_impl,
        )
        from threat_modeling_mcp_server.tools.business_context import (
            set_business_context_with_features_impl,
        )

        sentinel = "ZQXLOGSENTINEL"
        captured = []
        sink_id = logger.add(captured.append, level="DEBUG")
        try:
            await add_assumption_impl(
                None, f"{sentinel} assumption " * 60, "Security", "High",
                "Test rationale",
            )
            await set_business_context_with_features_impl(
                None, f"{sentinel} business context description",
            )
            export_threat_model_files("logs", str(tmp_path))
        finally:
            logger.remove(sink_id)

        assert captured, "the DEBUG sink should capture at least one message"
        assert not any(sentinel in str(message) for message in captured)

    @pytest.mark.asyncio
    async def test_export_failure_log_omits_exception_text(
        self, tmp_path, monkeypatch, empty_threat_model_state
    ):
        from loguru import logger

        import threat_modeling_mcp_server.utils.comprehensive_exporter as exporter

        sentinel = "ZQXERRSENTINEL"

        def failing_builder(*_args, **_kwargs):
            raise ValueError(f"bad value {sentinel}")

        monkeypatch.setattr(exporter, "build_threat_composer_data", failing_builder)

        captured = []
        sink_id = logger.add(captured.append, level="DEBUG")
        try:
            result = export_threat_model_files("fail", str(tmp_path))
        finally:
            logger.remove(sink_id)

        assert "Export incomplete; failed: JSON" in result
        assert any(
            "Failed to export JSON threat model: ValueError" in str(message)
            for message in captured
        )
        assert not any(sentinel in str(message) for message in captured)

    @pytest.mark.asyncio
    async def test_entity_names_are_not_logged(self, empty_threat_model_state):
        from loguru import logger

        from threat_modeling_mcp_server.tools.architecture_analyzer import (
            add_component_impl,
            add_data_store_impl,
        )
        from threat_modeling_mcp_server.tools.asset_flow_analyzer import (
            add_asset_impl,
        )
        from threat_modeling_mcp_server.tools.threat_actor_analyzer import (
            add_threat_actor_impl,
        )
        from threat_modeling_mcp_server.tools.trust_boundary_analyzer import (
            add_trust_boundary_impl,
            add_trust_zone_impl,
        )

        sentinel = "ZQXNAMESENTINEL"
        captured = []
        sink_id = logger.add(captured.append, level="DEBUG")
        try:
            results = [
                await add_component_impl(
                    None, f"{sentinel} component", "Compute"
                ),
                await add_data_store_impl(
                    None, f"{sentinel} data store", "Relational", "Confidential"
                ),
                await add_asset_impl(
                    None, f"{sentinel} asset", "Data", "Internal"
                ),
                await add_threat_actor_impl(
                    None,
                    name=f"{sentinel} threat actor",
                    type="External Attacker",
                    sophistication_tier="Tier 2 - Hacktivist / campaign-driven",
                    motivations=["Financial gain"],
                    resources="Individual",
                ),
                await add_trust_zone_impl(None, f"{sentinel} zone", "Untrusted"),
                await add_trust_boundary_impl(
                    None, f"{sentinel} boundary", "Network"
                ),
            ]
        finally:
            logger.remove(sink_id)

        assert all("Error" not in result for result in results), results
        for entity in (
            "Adding component", "Adding data store", "Adding asset",
            "Adding threat actor", "Adding trust zone", "Adding trust boundary",
        ):
            assert any(entity in str(message) for message in captured), entity
        assert not any(sentinel in str(message) for message in captured)

    @pytest.mark.asyncio
    async def test_phase_completion_failure_logs_omit_exception_text(
        self, tmp_path, monkeypatch, empty_threat_model_state
    ):
        from loguru import logger

        import threat_modeling_mcp_server.tools.step_orchestrator as orchestrator

        sentinel = "ZQXPHASESENTINEL"

        def failing_detection():
            raise ValueError(f"bad value {sentinel}")

        monkeypatch.setattr(
            orchestrator, "detect_phase_completion", failing_detection
        )

        captured = []
        sink_id = logger.add(captured.append, level="DEBUG")
        try:
            result = export_threat_model_files("phase", str(tmp_path))
        finally:
            logger.remove(sink_id)

        assert "All requested files exported successfully" in result
        messages = [str(message) for message in captured]
        assert any(
            "Failed to update phase completion: ValueError" in m for m in messages
        )
        assert any(
            "Failed to refresh phase completion after export: ValueError" in m
            for m in messages
        )
        assert not any(sentinel in m for m in messages)

    def test_detect_phase_completion_log_omits_exception_text(
        self, monkeypatch, empty_threat_model_state
    ):
        from loguru import logger

        import threat_modeling_mcp_server.tools.step_orchestrator as orchestrator
        import threat_modeling_mcp_server.utils.state_collector as state_collector

        sentinel = "ZQXDETECTSENTINEL"

        def failing_summary(*_args, **_kwargs):
            raise ValueError(f"bad value {sentinel}")

        monkeypatch.setattr(state_collector, "get_state_summary", failing_summary)

        captured = []
        sink_id = logger.add(captured.append, level="DEBUG")
        try:
            orchestrator.detect_phase_completion()
        finally:
            logger.remove(sink_id)

        messages = [str(message) for message in captured]
        assert any(
            "Failed to detect phase completion, keeping last known state: "
            "ValueError" in m
            for m in messages
        )
        assert not any(sentinel in m for m in messages)

    @pytest.mark.asyncio
    async def test_export_tool_failure_log_omits_exception_text(
        self, tmp_path, monkeypatch, empty_threat_model_state
    ):
        from loguru import logger

        import threat_modeling_mcp_server.tools.step_orchestrator as orchestrator
        import threat_modeling_mcp_server.utils.comprehensive_exporter as exporter

        sentinel = "ZQXTOOLSENTINEL"

        def failing_export(*_args, **_kwargs):
            raise ValueError(f"bad value {sentinel}")

        monkeypatch.setattr(orchestrator, "project_directory", str(tmp_path))
        monkeypatch.setattr(exporter, "export_threat_model_files", failing_export)

        captured = []
        sink_id = logger.add(captured.append, level="DEBUG")
        try:
            result = await orchestrator.export_threat_model_impl(None, "tool")
        finally:
            logger.remove(sink_id)

        # The tool's return text is unchanged; only the log line is content-free.
        assert result == f"Failed to export threat model: bad value {sentinel}"
        messages = [str(message) for message in captured]
        assert any("Failed to export threat model: ValueError" in m for m in messages)
        assert not any(sentinel in m for m in messages)

    def test_export_paths_are_not_logged(self, tmp_path, empty_threat_model_state):
        from loguru import logger

        project = tmp_path / "ZQXDIRSENTINEL"
        project.mkdir()
        output_path = "ZQXPARENTSENTINEL/ZQXOUTSENTINEL_model.json"

        captured = []
        sink_id = logger.add(captured.append, level="DEBUG")
        try:
            result = export_threat_model_files(output_path, str(project))
        finally:
            logger.remove(sink_id)

        # The return text still reports the real written paths to the caller.
        assert "All requested files exported successfully" in result
        assert "ZQXDIRSENTINEL" in result
        assert "ZQXOUTSENTINEL_model.tc.json" in result

        messages = [str(message) for message in captured]
        assert any("Successfully exported JSON threat model" in m for m in messages)
        assert any("Successfully exported Markdown threat model" in m for m in messages)
        assert any("Successfully exported extended snapshot" in m for m in messages)
        for sentinel in (
            "ZQXDIRSENTINEL",
            "ZQXPARENTSENTINEL",
            "ZQXOUTSENTINEL",
            str(tmp_path),
        ):
            assert not any(sentinel in m for m in messages), sentinel

    @pytest.mark.asyncio
    async def test_export_tool_paths_are_not_logged(
        self, tmp_path, monkeypatch, empty_threat_model_state
    ):
        from loguru import logger

        import threat_modeling_mcp_server.tools.step_orchestrator as orchestrator

        project = tmp_path / "ZQXDIRSENTINEL"
        project.mkdir()
        monkeypatch.setattr(orchestrator, "project_directory", str(project))

        captured = []
        sink_id = logger.add(captured.append, level="DEBUG")
        try:
            result = await orchestrator.export_threat_model_impl(
                None, "ZQXOUTSENTINEL_tool.json"
            )
        finally:
            logger.remove(sink_id)

        assert "Threat Model Export Complete" in result
        assert "ZQXOUTSENTINEL_tool.tc.json" in result
        messages = [str(message) for message in captured]
        assert any("Exporting threat model" in m for m in messages)
        assert any("Successfully exported JSON threat model" in m for m in messages)
        for sentinel in ("ZQXDIRSENTINEL", "ZQXOUTSENTINEL", str(tmp_path)):
            assert not any(sentinel in m for m in messages), sentinel

    @pytest.mark.asyncio
    @pytest.mark.parametrize("explicit", [True, False])
    async def test_phase_guidance_does_not_log_scan_directory(
        self, tmp_path, monkeypatch, empty_threat_model_state, explicit
    ):
        from loguru import logger

        import threat_modeling_mcp_server.tools.step_orchestrator as orchestrator

        project = tmp_path / "ZQXSCANSENTINEL"
        project.mkdir()
        (project / "app.py").write_text("print('x')\n")
        if not explicit:
            monkeypatch.setattr(orchestrator, "project_directory", str(project))

        captured = []
        sink_id = logger.add(captured.append, level="DEBUG")
        try:
            if explicit:
                guidance = await orchestrator.get_phase_guidance_impl(
                    "7", directory=str(project)
                )
            else:
                guidance = await orchestrator.get_phase_guidance_impl("7")
        finally:
            logger.remove(sink_id)

        # The code-detected branch was taken.
        assert "Code files were detected" in guidance
        messages = [str(message) for message in captured]
        for sentinel in ("ZQXSCANSENTINEL", str(tmp_path)):
            assert not any(sentinel in m for m in messages), sentinel
        assert any("Code detected in selected directory: True" in m for m in messages)

    @staticmethod
    def _failing_inspect_module(monkeypatch, sentinel):
        """Make instruction_validator's inspect.getsource raise with a sentinel."""
        import types

        import threat_modeling_mcp_server.validation.instruction_validator as iv

        def failing(*_args, **_kwargs):
            raise OSError(f"bad source {sentinel}")

        # Patch only the module-local name, not the stdlib inspect module.
        monkeypatch.setattr(iv, "inspect", types.SimpleNamespace(getsource=failing))
        fake = types.ModuleType("fake_tools_module")
        fake.register_tools = lambda mcp: None
        return iv, fake

    def test_instruction_validator_extract_tools_log_omits_exception_text(
        self, monkeypatch
    ):
        from loguru import logger

        sentinel = "ZQXINSPECTSENTINEL"
        iv, fake = self._failing_inspect_module(monkeypatch, sentinel)

        captured = []
        sink_id = logger.add(captured.append, level="DEBUG")
        try:
            tools = iv.extract_tools_from_module(fake)
        finally:
            logger.remove(sink_id)

        assert tools == set()
        messages = [str(message) for message in captured]
        assert not any(sentinel in m for m in messages)
        assert any(
            "Could not extract tools from module fake_tools_module: OSError" in m
            for m in messages
        )

    def test_instruction_validator_tool_docs_log_omits_exception_text(
        self, monkeypatch
    ):
        from loguru import logger

        sentinel = "ZQXINSPECTSENTINEL"
        iv, fake = self._failing_inspect_module(monkeypatch, sentinel)

        captured = []
        sink_id = logger.add(captured.append, level="DEBUG")
        try:
            docs = iv.generate_tool_documentation([fake])
        finally:
            logger.remove(sink_id)

        assert docs == ""
        messages = [str(message) for message in captured]
        assert not any(sentinel in m for m in messages)
        assert any(
            "Could not extract tool documentation from module fake_tools_module: OSError"
            in m
            for m in messages
        )
        assert any(
            "Could not extract tools from module fake_tools_module: OSError" in m
            for m in messages
        )
