"""Trust Boundary models for the Threat Modeling MCP Server."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, field_validator
from threat_modeling_mcp_server.validation.enum_validator import validate_enum_with_enhanced_error


class BoundaryType(str, Enum):
    """Trust boundary type enum."""
    NETWORK = "Network"
    PROCESS = "Process"
    PHYSICAL = "Physical"
    CONTAINER = "Container"
    VIRTUAL_MACHINE = "Virtual Machine"
    ACCOUNT = "Account"
    OTHER = "Other"


class AuthenticationMethod(str, Enum):
    """Authentication method enum."""
    PASSWORD = "Password"
    MULTI_FACTOR = "Multi-factor"
    CERTIFICATE = "Certificate"
    TOKEN = "Token"
    BIOMETRIC = "Biometric"
    API_KEY = "API Key"
    IAM_ROLE = "IAM Role"
    OAUTH = "OAuth"
    NONE = "None"
    OTHER = "Other"


class AuthorizationMethod(str, Enum):
    """Authorization method enum."""
    ROLE_BASED = "Role-based"
    ATTRIBUTE_BASED = "Attribute-based"
    DISCRETIONARY = "Discretionary"
    MANDATORY = "Mandatory"
    POLICY_BASED = "Policy-based"
    RULE_BASED = "Rule-based"
    NONE = "None"
    OTHER = "Other"


class TrustLevel(str, Enum):
    """Trust level enum."""
    UNTRUSTED = "Untrusted"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    FULL = "Full"


class TrustZone(BaseModel):
    """Model for a trust zone."""
    id: str
    name: str
    trust_level: TrustLevel
    contained_components: List[str] = []  # References to component IDs
    description: Optional[str] = None

    @field_validator('trust_level', mode='before')
    @classmethod
    def validate_trust_level(cls, v):
        return validate_enum_with_enhanced_error(v, TrustLevel, 'trust_level')


class CrossingPoint(BaseModel):
    """Model for a crossing point between trust zones."""
    id: str
    source_zone_id: str
    destination_zone_id: str
    connection_ids: List[str] = []  # References to connection IDs
    authentication_method: Optional[AuthenticationMethod] = None
    authorization_method: Optional[AuthorizationMethod] = None
    description: Optional[str] = None

    @field_validator('authentication_method', mode='before')
    @classmethod
    def validate_authentication_method(cls, v):
        return validate_enum_with_enhanced_error(v, AuthenticationMethod, 'authentication_method')

    @field_validator('authorization_method', mode='before')
    @classmethod
    def validate_authorization_method(cls, v):
        return validate_enum_with_enhanced_error(v, AuthorizationMethod, 'authorization_method')


class TrustBoundary(BaseModel):
    """Model for a trust boundary."""
    id: str
    name: str
    type: BoundaryType
    crossing_points: List[str] = []  # References to crossing point IDs
    controls: List[str] = []  # Security controls at this boundary
    description: Optional[str] = None

    @field_validator('type', mode='before')
    @classmethod
    def validate_boundary_type(cls, v):
        return validate_enum_with_enhanced_error(v, BoundaryType, 'type')
