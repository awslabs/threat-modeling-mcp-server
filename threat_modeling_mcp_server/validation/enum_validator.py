"""Enhanced enum validation with actionable error messages."""

from enum import Enum
from typing import Type
from loguru import logger


def validate_enum_with_enhanced_error(value, enum_class: Type[Enum], field_name: str = None):
    """Validate an enum value and provide enhanced error messages on failure.
    
    This function provides multiple layers of matching:
    1. Exact match against enum values
    2. Case-insensitive matching
    3. Detailed error message with all valid options if no match found
    
    Args:
        value: The value to validate
        enum_class: The enum class to validate against
        field_name: Optional field name for better error context
        
    Returns:
        The validated enum value
        
    Raises:
        ValueError: With enhanced error message including all valid options
    """
    if value is None:
        return value
    
    # Get all valid values from the enum class dynamically
    valid_values = {member.value: member for member in enum_class}
    
    # Try exact match first
    if value in valid_values:
        return valid_values[value]
    
    # Try case-insensitive matching
    if isinstance(value, str):
        value_lower = value.lower().strip()
        for enum_value, enum_member in valid_values.items():
            if enum_value.lower() == value_lower:
                logger.info(f"Enum value '{value}' matched to '{enum_member.value}' (case-insensitive) for {enum_class.__name__}")
                return enum_member

    # Create enhanced error message with all valid options
    valid_options_str = ', '.join(f'"{v}"' for v in valid_values.keys())
    error_msg = f"'{value}' is not a valid {enum_class.__name__}. Valid options are: {valid_options_str}"
    
    if field_name:
        error_msg = f"Field '{field_name}': {error_msg}"
        
    raise ValueError(error_msg)
