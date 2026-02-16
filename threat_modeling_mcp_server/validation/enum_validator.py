"""Enhanced enum validation with dynamic value discovery for better error messages."""

import inspect
from enum import Enum
from typing import List, Type, Union, get_origin, get_args
from loguru import logger


def discover_enum_classes_fresh():
    """Dynamically discover all Enum classes by re-scanning modules.
    
    This ensures we always get the most current enum definitions.
    
    Returns:
        A dictionary mapping enum class names to enum classes
    """
    # Import all modules that contain Enum classes
    import threat_modeling_mcp_server.models.architecture_models as architecture_models
    import threat_modeling_mcp_server.models.asset_flow_models as asset_flow_models
    import threat_modeling_mcp_server.models.threat_actor_models as threat_actor_models
    import threat_modeling_mcp_server.models.trust_boundary_models as trust_boundary_models
    import threat_modeling_mcp_server.models.threat_models as threat_models
    import threat_modeling_mcp_server.models.models as models
    
    modules = [
        architecture_models,
        asset_flow_models,
        threat_actor_models,
        trust_boundary_models,
        threat_models,
        models
    ]
    
    enum_classes = {}
    
    for module in modules:
        # Get all members of the module
        for name, obj in inspect.getmembers(module):
            # Check if it's a class and a subclass of Enum
            if inspect.isclass(obj) and issubclass(obj, Enum) and obj != Enum:
                enum_classes[name] = obj
    
    return enum_classes


def get_current_enum_values(enum_class_name: str) -> List[str]:
    """Get current enum values dynamically from the enum class.
    
    Args:
        enum_class_name: Name of the enum class
        
    Returns:
        List of current enum values
    """
    try:
        # Re-discover enums to ensure we have the latest definitions
        current_enums = discover_enum_classes_fresh()
        
        if enum_class_name in current_enums:
            enum_class = current_enums[enum_class_name]
            return [enum_value.value for enum_value in enum_class]
        
        logger.warning(f"Enum class {enum_class_name} not found in current definitions")
        return []
        
    except Exception as e:
        logger.error(f"Error getting current enum values for {enum_class_name}: {e}")
        return []


def extract_enum_class_from_annotation(field_type) -> Type[Enum]:
    """Extract the enum class from a type annotation.
    
    Args:
        field_type: The field type annotation
        
    Returns:
        The enum class, or None if not found
    """
    try:
        # Handle Optional[EnumType] case (Union[EnumType, None])
        if get_origin(field_type) is Union:
            args = get_args(field_type)
            for arg in args:
                if arg is not type(None) and inspect.isclass(arg) and issubclass(arg, Enum):
                    return arg
        
        # Handle direct EnumType case
        elif inspect.isclass(field_type) and issubclass(field_type, Enum):
            return field_type
            
        return None
        
    except Exception as e:
        logger.error(f"Error extracting enum class from annotation {field_type}: {e}")
        return None


def create_enhanced_enum_error(invalid_value: str, enum_class: Type[Enum]) -> str:
    """Create an enhanced error message with current valid enum values.
    
    Args:
        invalid_value: The invalid value that was provided
        enum_class: The enum class that was expected
        
    Returns:
        Enhanced error message with valid options
    """
    try:
        enum_class_name = enum_class.__name__
        current_values = get_current_enum_values(enum_class_name)
        
        if current_values:
            values_str = ', '.join(f'"{val}"' for val in current_values)
            return f"'{invalid_value}' is not a valid {enum_class_name}. Valid options are: {values_str}"
        else:
            # Fallback to basic error if we can't get current values
            return f"'{invalid_value}' is not a valid {enum_class_name}"
            
    except Exception as e:
        logger.error(f"Error creating enhanced enum error: {e}")
        return f"'{invalid_value}' is not a valid enum value"


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
