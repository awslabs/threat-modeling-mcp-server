"""Threat and Mitigation models for the Threat Modeling MCP Server."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator, model_validator
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


class ResidualRiskDecision(str, Enum):
    """Decision made after considering linked mitigations."""
    OPEN = "Open"
    ACCEPTED = "Accepted"
    MITIGATED = "Mitigated"
    NOT_APPLICABLE = "Not Applicable"


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


class ResidualRiskAssessment(BaseModel):
    """Residual-risk decision for one threat at a specific model state."""
    threat_id: str
    decision: ResidualRiskDecision
    residual_severity: Optional[ThreatSeverity] = None
    residual_likelihood: Optional[ThreatLikelihood] = None
    rationale: str = Field(min_length=1)
    source_fingerprint: str

    @field_validator('decision', mode='before')
    @classmethod
    def validate_decision(cls, v):
        return validate_enum_with_enhanced_error(v, ResidualRiskDecision, 'decision')

    @field_validator('residual_severity', mode='before')
    @classmethod
    def validate_residual_severity(cls, v):
        return validate_enum_with_enhanced_error(
            v, ThreatSeverity, 'residual_severity'
        )

    @field_validator('residual_likelihood', mode='before')
    @classmethod
    def validate_residual_likelihood(cls, v):
        return validate_enum_with_enhanced_error(
            v, ThreatLikelihood, 'residual_likelihood'
        )

    @field_validator('rationale')
    @classmethod
    def validate_rationale(cls, v):
        if not v.strip():
            raise ValueError("Field 'rationale' must not be blank")
        return v.strip()

    @model_validator(mode='after')
    def validate_residual_risk(self):
        if self.decision is not ResidualRiskDecision.NOT_APPLICABLE:
            missing = []
            if self.residual_severity is None:
                missing.append('residual_severity')
            if self.residual_likelihood is None:
                missing.append('residual_likelihood')
            if missing:
                raise ValueError(
                    f"Decision '{self.decision.value}' requires: "
                    + ", ".join(missing)
                )
        return self
