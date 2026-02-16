"""Trust Boundary models for the Threat Modeling MCP Server."""

from enum import Enum
from typing import Dict, List, Optional, Set, Any, Union
from pydantic import BaseModel, Field, field_validator
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


class TrustBoundaryLibrary(BaseModel):
    """Model for the trust boundary library."""
    trust_zones: Dict[str, TrustZone] = {}
    crossing_points: Dict[str, CrossingPoint] = {}
    trust_boundaries: Dict[str, TrustBoundary] = {}
    
    def get_default_trust_zones(self) -> Dict[str, TrustZone]:
        """Get a set of default trust zones.
        
        Returns:
            A dictionary of default trust zones
        """
        default_zones = {}
        
        # Internet zone
        internet = TrustZone(
            id="TZ001",
            name="Internet",
            trust_level=TrustLevel.UNTRUSTED,
            contained_components=[],
            description="The public internet, considered untrusted"
        )
        default_zones[internet.id] = internet
        
        # DMZ zone
        dmz = TrustZone(
            id="TZ002",
            name="DMZ",
            trust_level=TrustLevel.LOW,
            contained_components=[],
            description="Demilitarized zone for public-facing services"
        )
        default_zones[dmz.id] = dmz
        
        # Application zone
        app = TrustZone(
            id="TZ003",
            name="Application",
            trust_level=TrustLevel.MEDIUM,
            contained_components=[],
            description="Zone containing application servers and services"
        )
        default_zones[app.id] = app
        
        # Data zone
        data = TrustZone(
            id="TZ004",
            name="Data",
            trust_level=TrustLevel.HIGH,
            contained_components=[],
            description="Zone containing databases and data storage"
        )
        default_zones[data.id] = data
        
        # Admin zone
        admin = TrustZone(
            id="TZ005",
            name="Admin",
            trust_level=TrustLevel.FULL,
            contained_components=[],
            description="Administrative zone with highest privileges"
        )
        default_zones[admin.id] = admin
        
        return default_zones
    
    def get_default_crossing_points(self) -> Dict[str, CrossingPoint]:
        """Get a set of default crossing points.
        
        Returns:
            A dictionary of default crossing points
        """
        default_crossing_points = {}
        
        # Internet to DMZ
        internet_to_dmz = CrossingPoint(
            id="CP001",
            source_zone_id="TZ001",
            destination_zone_id="TZ002",
            connection_ids=[],
            authentication_method=AuthenticationMethod.NONE,
            authorization_method=AuthorizationMethod.NONE,
            description="Traffic from the internet to public-facing services"
        )
        default_crossing_points[internet_to_dmz.id] = internet_to_dmz
        
        # DMZ to Application
        dmz_to_app = CrossingPoint(
            id="CP002",
            source_zone_id="TZ002",
            destination_zone_id="TZ003",
            connection_ids=[],
            authentication_method=AuthenticationMethod.API_KEY,
            authorization_method=AuthorizationMethod.ROLE_BASED,
            description="Traffic from public-facing services to application servers"
        )
        default_crossing_points[dmz_to_app.id] = dmz_to_app
        
        # Application to Data
        app_to_data = CrossingPoint(
            id="CP003",
            source_zone_id="TZ003",
            destination_zone_id="TZ004",
            connection_ids=[],
            authentication_method=AuthenticationMethod.IAM_ROLE,
            authorization_method=AuthorizationMethod.POLICY_BASED,
            description="Traffic from application servers to databases"
        )
        default_crossing_points[app_to_data.id] = app_to_data
        
        # Admin to Application
        admin_to_app = CrossingPoint(
            id="CP004",
            source_zone_id="TZ005",
            destination_zone_id="TZ003",
            connection_ids=[],
            authentication_method=AuthenticationMethod.MULTI_FACTOR,
            authorization_method=AuthorizationMethod.ROLE_BASED,
            description="Administrative access to application servers"
        )
        default_crossing_points[admin_to_app.id] = admin_to_app
        
        # Admin to Data
        admin_to_data = CrossingPoint(
            id="CP005",
            source_zone_id="TZ005",
            destination_zone_id="TZ004",
            connection_ids=[],
            authentication_method=AuthenticationMethod.MULTI_FACTOR,
            authorization_method=AuthorizationMethod.ROLE_BASED,
            description="Administrative access to databases"
        )
        default_crossing_points[admin_to_data.id] = admin_to_data
        
        return default_crossing_points
    
    def get_default_trust_boundaries(self) -> Dict[str, TrustBoundary]:
        """Get a set of default trust boundaries.
        
        Returns:
            A dictionary of default trust boundaries
        """
        default_boundaries = {}
        
        # Internet boundary
        internet_boundary = TrustBoundary(
            id="TB001",
            name="Internet Boundary",
            type=BoundaryType.NETWORK,
            crossing_points=["CP001"],
            controls=["Web Application Firewall", "DDoS Protection", "TLS Encryption"],
            description="Boundary between the internet and internal systems"
        )
        default_boundaries[internet_boundary.id] = internet_boundary
        
        # DMZ boundary
        dmz_boundary = TrustBoundary(
            id="TB002",
            name="DMZ Boundary",
            type=BoundaryType.NETWORK,
            crossing_points=["CP002"],
            controls=["Network Firewall", "Intrusion Detection System", "API Gateway"],
            description="Boundary between public-facing services and internal applications"
        )
        default_boundaries[dmz_boundary.id] = dmz_boundary
        
        # Data boundary
        data_boundary = TrustBoundary(
            id="TB003",
            name="Data Boundary",
            type=BoundaryType.NETWORK,
            crossing_points=["CP003"],
            controls=["Database Firewall", "Encryption", "Access Control Lists"],
            description="Boundary protecting data storage systems"
        )
        default_boundaries[data_boundary.id] = data_boundary
        
        # Admin boundary
        admin_boundary = TrustBoundary(
            id="TB004",
            name="Admin Boundary",
            type=BoundaryType.NETWORK,
            crossing_points=["CP004", "CP005"],
            controls=["Privileged Access Management", "Multi-Factor Authentication", "Audit Logging"],
            description="Boundary for administrative access"
        )
        default_boundaries[admin_boundary.id] = admin_boundary
        
        return default_boundaries
