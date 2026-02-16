"""Asset Flow models for the Threat Modeling MCP Server."""

from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, field_validator
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


class AssetClassification(str, Enum):
    """Asset classification enum."""
    PUBLIC = "Public"
    INTERNAL = "Internal"
    CONFIDENTIAL = "Confidential"
    RESTRICTED = "Restricted"
    REGULATED = "Regulated"
    OTHER = "Other"


class LifecycleState(str, Enum):
    """Asset lifecycle state enum."""
    CREATION = "Creation"
    STORAGE = "Storage"
    TRANSMISSION = "Transmission"
    PROCESSING = "Processing"
    DESTRUCTION = "Destruction"
    ARCHIVAL = "Archival"
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
    classification: AssetClassification
    lifecycle_state: Optional[LifecycleState] = None
    description: Optional[str] = None
    owner: Optional[str] = None
    sensitivity: Optional[int] = None  # 1-5 scale
    criticality: Optional[int] = None  # 1-5 scale
    metadata: Optional[Dict[str, Any]] = None
    
    @field_validator('type', mode='before')
    @classmethod
    def validate_asset_type(cls, v):
        return validate_enum_with_enhanced_error(v, AssetType, 'type')
    
    @field_validator('classification', mode='before')
    @classmethod
    def validate_classification(cls, v):
        return validate_enum_with_enhanced_error(v, AssetClassification, 'classification')
    
    @field_validator('lifecycle_state', mode='before')
    @classmethod
    def validate_lifecycle_state(cls, v):
        return validate_enum_with_enhanced_error(v, LifecycleState, 'lifecycle_state')


class AssetFlow(BaseModel):
    """Model for an asset flow."""
    id: str
    asset_id: str
    source_id: str  # Component or trust zone ID
    destination_id: str  # Component or trust zone ID
    transformation_type: Optional[TransformationType] = None
    controls: List[ControlType] = []
    description: Optional[str] = None
    protocol: Optional[str] = None
    encryption: bool = False
    authenticated: bool = False
    authorized: bool = False
    validated: bool = False
    risk_level: Optional[int] = None  # 1-5 scale
    
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


class AssetFlowLibrary:
    """Library of common assets and flows."""

    @staticmethod
    def get_default_assets() -> Dict[str, Asset]:
        """Get default assets."""
        assets = {}
        
        # Common data assets
        assets["A001"] = Asset(
            id="A001",
            name="User Credentials",
            type=AssetType.CREDENTIAL,
            classification=AssetClassification.CONFIDENTIAL,
            lifecycle_state=LifecycleState.TRANSMISSION,
            description="Username and password for authentication",
            sensitivity=5,
            criticality=5
        )
        
        assets["A002"] = Asset(
            id="A002",
            name="Personal Identifiable Information",
            type=AssetType.DATA,
            classification=AssetClassification.CONFIDENTIAL,
            lifecycle_state=LifecycleState.STORAGE,
            description="User personal information like name, address, etc.",
            sensitivity=4,
            criticality=4
        )
        
        assets["A003"] = Asset(
            id="A003",
            name="Session Token",
            type=AssetType.TOKEN,
            classification=AssetClassification.CONFIDENTIAL,
            lifecycle_state=LifecycleState.TRANSMISSION,
            description="Authentication token for user session",
            sensitivity=5,
            criticality=5
        )
        
        assets["A004"] = Asset(
            id="A004",
            name="Configuration Data",
            type=AssetType.CONFIG,
            classification=AssetClassification.INTERNAL,
            lifecycle_state=LifecycleState.STORAGE,
            description="System configuration data",
            sensitivity=3,
            criticality=4
        )
        
        assets["A005"] = Asset(
            id="A005",
            name="Encryption Keys",
            type=AssetType.KEY,
            classification=AssetClassification.RESTRICTED,
            lifecycle_state=LifecycleState.STORAGE,
            description="Keys used for encryption/decryption",
            sensitivity=5,
            criticality=5
        )
        
        assets["A006"] = Asset(
            id="A006",
            name="Public Content",
            type=AssetType.DATA,
            classification=AssetClassification.PUBLIC,
            lifecycle_state=LifecycleState.STORAGE,
            description="Publicly available content",
            sensitivity=1,
            criticality=2
        )
        
        assets["A007"] = Asset(
            id="A007",
            name="Audit Logs",
            type=AssetType.DATA,
            classification=AssetClassification.INTERNAL,
            lifecycle_state=LifecycleState.STORAGE,
            description="System audit logs",
            sensitivity=3,
            criticality=4
        )
        
        return assets

    @staticmethod
    def get_default_flows() -> Dict[str, AssetFlow]:
        """Get default asset flows."""
        flows = {}
        
        # Common flows
        flows["F001"] = AssetFlow(
            id="F001",
            asset_id="A001",
            source_id="C001",  # Assuming C001 is a client component
            destination_id="C002",  # Assuming C002 is an authentication service
            transformation_type=TransformationType.ENCRYPTION,
            controls=[ControlType.ENCRYPTION, ControlType.AUTHENTICATION],
            description="User credentials sent from client to authentication service",
            protocol="HTTPS",
            encryption=True,
            authenticated=False,
            authorized=False,
            validated=True,
            risk_level=4
        )
        
        flows["F002"] = AssetFlow(
            id="F002",
            asset_id="A003",
            source_id="C002",  # Authentication service
            destination_id="C001",  # Client
            transformation_type=TransformationType.ENCRYPTION,
            controls=[ControlType.ENCRYPTION, ControlType.AUTHENTICATION],
            description="Session token sent from authentication service to client",
            protocol="HTTPS",
            encryption=True,
            authenticated=True,
            authorized=True,
            validated=True,
            risk_level=3
        )
        
        flows["F003"] = AssetFlow(
            id="F003",
            asset_id="A002",
            source_id="C003",  # Application server
            destination_id="C004",  # Database
            transformation_type=TransformationType.ENCRYPTION,
            controls=[ControlType.ENCRYPTION, ControlType.ACCESS_CONTROL],
            description="PII stored in database",
            protocol="TLS",
            encryption=True,
            authenticated=True,
            authorized=True,
            validated=True,
            risk_level=3
        )
        
        flows["F004"] = AssetFlow(
            id="F004",
            asset_id="A007",
            source_id="C003",  # Application server
            destination_id="C005",  # Logging service
            transformation_type=TransformationType.AGGREGATION,
            controls=[ControlType.ENCRYPTION, ControlType.INTEGRITY_CHECK],
            description="Audit logs sent to logging service",
            protocol="TLS",
            encryption=True,
            authenticated=True,
            authorized=True,
            validated=True,
            risk_level=2
        )
        
        return flows
