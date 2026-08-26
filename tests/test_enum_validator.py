"""Unit tests for the enum validator module."""

import pytest
from enum import Enum

from threat_modeling_mcp_server.validation.enum_validator import (
    validate_enum_with_enhanced_error,
)
from threat_modeling_mcp_server.models.data_classification_models import (
    InformationContentType,
)
from threat_modeling_mcp_server.models.models import RegulatoryRequirement
from threat_modeling_mcp_server.models.threat_actor_models import ThreatActorType


class SampleEnum(str, Enum):
    """Sample enum for testing."""
    OPTION_A = "Option A"
    OPTION_B = "Option B"
    OPTION_C = "Option C"


class TestValidateEnumWithEnhancedError:
    """Tests for validate_enum_with_enhanced_error function."""

    def test_exact_match_returns_enum_member(self):
        """Test that exact value match returns the enum member."""
        result = validate_enum_with_enhanced_error("Option A", SampleEnum, "test_field")
        assert result == SampleEnum.OPTION_A

    def test_case_insensitive_match_returns_enum_member(self):
        """Test that case-insensitive match returns the enum member."""
        result = validate_enum_with_enhanced_error("option a", SampleEnum, "test_field")
        assert result == SampleEnum.OPTION_A

    def test_case_insensitive_match_uppercase(self):
        """Test case-insensitive matching with uppercase input."""
        result = validate_enum_with_enhanced_error("OPTION B", SampleEnum, "test_field")
        assert result == SampleEnum.OPTION_B

    def test_whitespace_trimming(self):
        """Test that whitespace is trimmed from input."""
        result = validate_enum_with_enhanced_error("  option c  ", SampleEnum, "test_field")
        assert result == SampleEnum.OPTION_C

    def test_none_value_returns_none(self):
        """Test that None value returns None without error."""
        result = validate_enum_with_enhanced_error(None, SampleEnum, "test_field")
        assert result is None

    def test_invalid_value_raises_value_error(self):
        """Test that invalid value raises ValueError."""
        with pytest.raises(ValueError) as exc_info:
            validate_enum_with_enhanced_error("Invalid Option", SampleEnum, "test_field")
        assert "Invalid Option" in str(exc_info.value)
        assert "Option A" in str(exc_info.value)
        assert "Option B" in str(exc_info.value)
        assert "Option C" in str(exc_info.value)

    def test_error_message_includes_field_name(self):
        """Test that error message includes the field name."""
        with pytest.raises(ValueError) as exc_info:
            validate_enum_with_enhanced_error("Invalid", SampleEnum, "my_field")
        assert "my_field" in str(exc_info.value)

    def test_error_message_without_field_name(self):
        """Test that error message works without field name."""
        with pytest.raises(ValueError) as exc_info:
            validate_enum_with_enhanced_error("Invalid", SampleEnum)
        assert "Invalid" in str(exc_info.value)
        assert "SampleEnum" in str(exc_info.value)


class TestCanonicalCombinedLabels:
    """Slash-delimited taxonomy labels must be supplied in full."""

    @pytest.mark.parametrize(("supplied", "enum_class"), [
        ("CPRA", RegulatoryRequirement),
        ("APT", ThreatActorType),
        ("financial data", InformationContentType),
        ("other", RegulatoryRequirement),
    ])
    def test_component_of_a_combined_label_is_rejected(
        self, supplied, enum_class,
    ):
        with pytest.raises(ValueError) as exc:
            validate_enum_with_enhanced_error(
                supplied, enum_class, "taxonomy_value",
            )

        message = str(exc.value)
        assert supplied in message
        assert "Valid options are" in message
        assert "taxonomy_value" in message

    def test_exact_and_case_insensitive_full_labels_are_accepted(self):
        assert validate_enum_with_enhanced_error(
            "CCPA / CPRA", RegulatoryRequirement,
        ) is RegulatoryRequirement.CCPA
        assert validate_enum_with_enhanced_error(
            "ccpa / cpra", RegulatoryRequirement,
        ) is RegulatoryRequirement.CCPA

    def test_unrelated_value_lists_valid_options(self):
        with pytest.raises(ValueError) as exc:
            validate_enum_with_enhanced_error(
                "SOC2", RegulatoryRequirement, "compliance_regimes",
            )
        assert "Valid options are" in str(exc.value)
        assert "PCI-DSS" in str(exc.value)


class TestDataModelRegistry:
    """The one production enum registry exposes unique enum classes."""

    def test_discovers_profile_enums_without_duplicates(self):
        from threat_modeling_mcp_server.tools.data_model_types import DATA_MODELS

        for name in (
            "SoftwareType",
            "DataStructuralCategory",
            "UserPersonaType",
            "QualityClass",
        ):
            assert name in DATA_MODELS
        assert all(issubclass(enum_class, Enum) for enum_class in DATA_MODELS.values())
        assert len(DATA_MODELS) == len(set(DATA_MODELS.values()))
