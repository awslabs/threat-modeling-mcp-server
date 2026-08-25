"""Threat and Mitigation models for the Threat Modeling MCP Server."""

from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, field_validator
from threat_modeling_mcp_server.validation.enum_validator import validate_enum_with_enhanced_error


class ThreatCategory(str, Enum):
    """STRIDE threat categories."""
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


class ThreatSeverity(str, Enum):
    """Threat severity levels."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class ThreatLikelihood(str, Enum):
    """Threat likelihood levels."""
    UNLIKELY = "Unlikely"
    POSSIBLE = "Possible"
    LIKELY = "Likely"
    VERY_LIKELY = "Very Likely"


class ThreatStatus(str, Enum):
    """Threat status values."""
    IDENTIFIED = "threatIdentified"
    RESOLVED = "threatResolved"
    NOT_USEFUL = "threatResolvedNotUseful"


class MitigationType(str, Enum):
    """Mitigation type enum."""
    PREVENTIVE = "Preventive"
    DETECTIVE = "Detective"
    CORRECTIVE = "Corrective"
    DETERRENT = "Deterrent"


class MitigationStatus(str, Enum):
    """Mitigation status enum."""
    IDENTIFIED = "mitigationIdentified"
    IN_PROGRESS = "mitigationInProgress"
    RESOLVED = "mitigationResolved"
    WILL_NOT_ACTION = "mitigationResolvedWillNotAction"


class MitigationCost(str, Enum):
    """Mitigation cost enum."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class MitigationEffectiveness(str, Enum):
    """Mitigation effectiveness enum."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class MetadataItem(BaseModel):
    """Model for metadata items."""
    key: str
    value: str


class Threat(BaseModel):
    """Model for a threat."""
    id: str
    numericId: int
    threatSource: str = Field(max_length=200)
    prerequisites: str = Field(max_length=200)
    threatAction: str = Field(max_length=200)
    threatImpact: str = Field(max_length=200)
    impactedGoal: List[str] = []
    impactedAssets: List[str] = []
    metadata: List[MetadataItem] = []
    statement: str = Field(max_length=1400)
    displayOrder: int
    status: ThreatStatus = ThreatStatus.IDENTIFIED
    tags: List[str] = []
    
    category: Optional[ThreatCategory] = None
    severity: Optional[ThreatSeverity] = None
    likelihood: Optional[ThreatLikelihood] = None
    affected_components: List[str] = []
    affected_trust_boundaries: List[str] = []
    residual_risk_level: Optional[int] = None  # 1-5 scale
    
    @field_validator('status', mode='before')
    @classmethod
    def validate_status(cls, v):
        return validate_enum_with_enhanced_error(v, ThreatStatus, 'status')
    
    @field_validator('category', mode='before')
    @classmethod
    def validate_category(cls, v):
        return validate_enum_with_enhanced_error(v, ThreatCategory, 'category')
    
    @field_validator('severity', mode='before')
    @classmethod
    def validate_severity(cls, v):
        return validate_enum_with_enhanced_error(v, ThreatSeverity, 'severity')
    
    @field_validator('likelihood', mode='before')
    @classmethod
    def validate_likelihood(cls, v):
        return validate_enum_with_enhanced_error(v, ThreatLikelihood, 'likelihood')


class Mitigation(BaseModel):
    """Model for a mitigation."""
    id: str
    numericId: int
    status: MitigationStatus = MitigationStatus.IDENTIFIED
    content: str
    displayOrder: int
    metadata: List[MetadataItem] = []
    
    type: Optional[MitigationType] = None
    cost: Optional[MitigationCost] = None
    effectiveness: Optional[MitigationEffectiveness] = None
    implementation_details: Optional[str] = None
    responsible_party: Optional[str] = None
    verification_method: Optional[str] = None
    estimated_time_to_implement: Optional[int] = None  # in days
    risk_reduction: Optional[float] = None  # percentage
    
    @field_validator('status', mode='before')
    @classmethod
    def validate_status(cls, v):
        return validate_enum_with_enhanced_error(v, MitigationStatus, 'status')
    
    @field_validator('type', mode='before')
    @classmethod
    def validate_type(cls, v):
        return validate_enum_with_enhanced_error(v, MitigationType, 'type')
    
    @field_validator('cost', mode='before')
    @classmethod
    def validate_cost(cls, v):
        return validate_enum_with_enhanced_error(v, MitigationCost, 'cost')
    
    @field_validator('effectiveness', mode='before')
    @classmethod
    def validate_effectiveness(cls, v):
        return validate_enum_with_enhanced_error(v, MitigationEffectiveness, 'effectiveness')


class MitigationLink(BaseModel):
    """Model for linking mitigations to threats."""
    linkedId: str
    mitigationId: str


class ThreatModel(BaseModel):
    """Model for a complete threat model."""
    model_config = {"populate_by_name": True}
    
    schema_version: int = Field(default=1, alias="schema")
    applicationInfo: Dict[str, str] = {"name": "", "description": ""}
    architecture: Dict[str, str] = {"description": ""}
    dataflow: Dict[str, str] = {"description": ""}
    assumptions: List[Dict[str, Any]] = []
    mitigations: List[Dict[str, Any]] = []
    assumptionLinks: List[Dict[str, Any]] = []
    mitigationLinks: List[Dict[str, Any]] = []
    threats: List[Dict[str, Any]] = []
    
    businessContext: Dict[str, Any] = {}
    components: List[Dict[str, Any]] = []
    connections: List[Dict[str, Any]] = []
    dataStores: List[Dict[str, Any]] = []
    threatActors: List[Dict[str, Any]] = []
    trustZones: List[Dict[str, Any]] = []
    crossingPoints: List[Dict[str, Any]] = []
    trustBoundaries: List[Dict[str, Any]] = []
    assets: List[Dict[str, Any]] = []
    flows: List[Dict[str, Any]] = []
    softwareProfile: Dict[str, Any] = {}
    dataAssetProfiles: List[Dict[str, Any]] = []
    userPersonas: List[Dict[str, Any]] = []
    nonFunctionalRequirements: List[Dict[str, Any]] = []
    phaseProgress: Dict[str, Any] = {}
    referenceCatalogue: Dict[str, Any] = {}
    metadata: Dict[str, Any] = {}
