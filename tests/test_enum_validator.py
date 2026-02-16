"""Unit tests for the enum validator module."""

import pytest
from enum import Enum

from threat_modeling_mcp_server.validation.enum_validator import (
    validate_enum_with_enhanced_error,
    create_enhanced_enum_error,
    get_current_enum_values,
    discover_enum_classes_fresh,
)


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


class TestCreateEnhancedEnumError:
    """Tests for create_enhanced_enum_error function."""

    def test_error_includes_invalid_value(self):
        """Test that error message includes the invalid value."""
        error = create_enhanced_enum_error("BadValue", SampleEnum)
        assert "BadValue" in error

    def test_error_includes_enum_class_name(self):
        """Test that error message includes the enum class name."""
        error = create_enhanced_enum_error("BadValue", SampleEnum)
        assert "SampleEnum" in error


class TestDiscoverEnumClassesFresh:
    """Tests for discover_enum_classes_fresh function."""

    def test_discovers_threat_category_enum(self):
        """Test that ThreatCategory enum is discovered."""
        enums = discover_enum_classes_fresh()
        assert "ThreatCategory" in enums

    def test_discovers_threat_severity_enum(self):
        """Test that ThreatSeverity enum is discovered."""
        enums = discover_enum_classes_fresh()
        assert "ThreatSeverity" in enums

    def test_discovers_component_type_enum(self):
        """Test that ComponentType enum is discovered."""
        enums = discover_enum_classes_fresh()
        assert "ComponentType" in enums

    def test_discovers_service_provider_enum(self):
        """Test that ServiceProvider enum is discovered."""
        enums = discover_enum_classes_fresh()
        assert "ServiceProvider" in enums

    def test_discovered_classes_are_enum_subclasses(self):
        """Test that all discovered classes are Enum subclasses."""
        enums = discover_enum_classes_fresh()
        for name, enum_class in enums.items():
            assert issubclass(enum_class, Enum), f"{name} is not an Enum subclass"


class TestGetCurrentEnumValues:
    """Tests for get_current_enum_values function."""

    def test_returns_values_for_known_enum(self):
        """Test that values are returned for a known enum class."""
        values = get_current_enum_values("ThreatCategory")
        assert len(values) > 0
        assert "Spoofing" in values

    def test_returns_empty_for_unknown_enum(self):
        """Test that empty list is returned for unknown enum class."""
        values = get_current_enum_values("NonExistentEnum")
        assert values == []

    def test_threat_status_values(self):
        """Test ThreatStatus enum values are returned correctly."""
        values = get_current_enum_values("ThreatStatus")
        assert "threatIdentified" in values
        assert "threatResolved" in values

    def test_mitigation_status_values(self):
        """Test MitigationStatus enum values are returned correctly."""
        values = get_current_enum_values("MitigationStatus")
        assert "mitigationIdentified" in values
        assert "mitigationResolved" in values
