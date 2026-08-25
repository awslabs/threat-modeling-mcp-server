"""Asset Flow models for the Threat Modeling MCP Server."""

from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, field_validator
from threat_modeling_mcp_server.models.models import SensitivityTier
from threat_modeling_mcp_server.models.data_classification_models import (
    DataLifecycleState,
    DataState,
)
from threat_modeling_mcp_server.validation.enum_validator import validate_enum_with_enhanced_error


class AssetType(str, Enum):
    """Asset type enum."""
    DATA = "Data"
    CREDENTIAL = "Credential"
    PROCESS = "Process"
    CONFIG = "Configuration"
    KEY = "Cryptographic Key"
    TOKEN = "Token"
    SESSION = "Session"
    OTHER = "Other"


class TransformationType(str, Enum):
    """Asset transformation type enum."""
    ENCRYPTION = "Encryption"
    DECRYPTION = "Decryption"
    PROCESSING = "Processing"
    AGGREGATION = "Aggregation"
    ANONYMIZATION = "Anonymization"
    PSEUDONYMIZATION = "Pseudonymization"
    TOKENIZATION = "Tokenization"
    HASHING = "Hashing"
    SIGNING = "Signing"
    VERIFICATION = "Verification"
    REDACTION = "Redaction"
    OTHER = "Other"


class ControlType(str, Enum):
    """Control type enum."""
    ENCRYPTION = "Encryption"
    ACCESS_CONTROL = "Access Control"
    AUTHENTICATION = "Authentication"
    AUTHORIZATION = "Authorization"
    AUDIT_LOGGING = "Audit Logging"
    INPUT_VALIDATION = "Input Validation"
    OUTPUT_ENCODING = "Output Encoding"
    INTEGRITY_CHECK = "Integrity Check"
    RATE_LIMITING = "Rate Limiting"
    MONITORING = "Monitoring"
    OTHER = "Other"


class Asset(BaseModel):
    """Model for an asset."""
    id: str
    name: str
    type: AssetType
    classification: SensitivityTier
    lifecycle_state: Optional[DataLifecycleState] = None
    data_states: List[DataState] = []
    description: Optional[str] = None
    owner: Optional[str] = None
    criticality: Optional[int] = Field(default=None, ge=1, le=5)
    metadata: Optional[Dict[str, Any]] = None

    @field_validator('type', mode='before')
    @classmethod
    def validate_asset_type(cls, v):
        return validate_enum_with_enhanced_error(v, AssetType, 'type')

    @field_validator('classification', mode='before')
    @classmethod
    def validate_classification(cls, v):
        return validate_enum_with_enhanced_error(v, SensitivityTier, 'classification')

    @field_validator('lifecycle_state', mode='before')
    @classmethod
    def validate_lifecycle_state(cls, v):
        return validate_enum_with_enhanced_error(v, DataLifecycleState, 'lifecycle_state')

    @field_validator('data_states', mode='before')
    @classmethod
    def validate_data_states(cls, v):
        if v is None:
            return []
        if isinstance(v, str):
            v = [v]
        if isinstance(v, list):
            return [
                validate_enum_with_enhanced_error(i, DataState, 'data_states') for i in v
            ]
        return v


class AssetFlow(BaseModel):
    """Model for an asset flow."""
    id: str
    asset_id: str
    source_id: str
    destination_id: str
    transformation_type: Optional[TransformationType] = None
    controls: List[ControlType] = []
    description: Optional[str] = None
    protocol: Optional[str] = None
    encryption: bool = False
    authenticated: bool = False
    authorized: bool = False
    validated: bool = False
    risk_level: Optional[int] = Field(default=None, ge=1, le=5)

    @field_validator('transformation_type', mode='before')
    @classmethod
    def validate_transformation_type(cls, v):
        return validate_enum_with_enhanced_error(v, TransformationType, 'transformation_type')

    @field_validator('controls', mode='before')
    @classmethod
    def validate_controls(cls, v):
        if v is None:
            return []
        if isinstance(v, list):
            validated_controls = []
            for control in v:
                validated_controls.append(validate_enum_with_enhanced_error(control, ControlType, 'controls'))
            return validated_controls
        return v
