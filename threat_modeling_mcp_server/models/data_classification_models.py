"""Data classification models for the Threat Modeling MCP Server."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, field_validator

from threat_modeling_mcp_server.models.models import (
    BusinessDomain,
    RegulatoryRequirement,
    SensitivityTier,
)
from threat_modeling_mcp_server.validation.enum_validator import (
    validate_enum_with_enhanced_error,
)


class DataStructuralCategory(str, Enum):
    """Primary organization category; mixed assets should be classified separately."""
    STRUCTURED = "Structured Data"
    SEMI_STRUCTURED = "Semi-Structured Data"
    UNSTRUCTURED = "Unstructured Data"
    API_DATA = "API Data"
    CONFIGURATION = "Configuration Data"
    SECRETS_CREDENTIALS = "Secrets and Credentials"
    METADATA = "Metadata"


class InformationContentType(str, Enum):
    """Information content that drives compliance; multiple values may apply."""
    PII = "PII"
    PHI = "PHI"
    PCI = "PCI / financial data"
    INTELLECTUAL_PROPERTY = "Intellectual property / trade secrets"
    AUTHENTICATION_CREDENTIALS = "Authentication credentials"
    SYSTEM_METADATA = "System metadata"
    OPERATIONAL_TELEMETRY = "Operational / telemetry data"
    NON_SENSITIVE = "Non-sensitive / other"


class DataState(str, Enum):
    """Physical state of the data; multiple values may apply."""
    AT_REST = "At rest"
    IN_TRANSIT = "In transit"
    IN_USE = "In use"


class DataVolumeTier(str, Enum):
    """Scale at which the data operates."""
    SMALL = "Small"  # MB to low GB, centralized
    MEDIUM = "Medium"  # GB to low TB, growing distribution
    BIG_DATA = "Big data"  # PB to EB, distributed clusters
    STREAMING = "Streaming"  # continuous real-time events


class DataLifecycleState(str, Enum):
    """Current lifecycle stage of the data."""
    ACTIVE = "Active"
    ARCHIVED = "Archived"
    PENDING_DELETION = "Pending deletion"
    QUARANTINED = "Quarantined"


class DataAssetProfile(BaseModel):
    """Data classification profile for an asset."""
    id: Optional[str] = None
    name: Optional[str] = None
    # Optional link to an Asset id, so a classification can be traced to the
    # asset it describes.
    asset_id: Optional[str] = None
    structural_category: DataStructuralCategory
    content_types: List[InformationContentType] = []
    sensitivity_tier: Optional[SensitivityTier] = None
    compliance_regimes: List[RegulatoryRequirement] = []
    data_states: List[DataState] = []
    volume_tier: Optional[DataVolumeTier] = None
    lifecycle_state: Optional[DataLifecycleState] = None
    business_domain: Optional[BusinessDomain] = None
    description: Optional[str] = None

    @field_validator('structural_category', mode='before')
    @classmethod
    def validate_structural_category(cls, v):
        return validate_enum_with_enhanced_error(
            v, DataStructuralCategory, 'structural_category'
        )

    @field_validator('content_types', mode='before')
    @classmethod
    def validate_content_types(cls, v):
        if v is None:
            return []
        if isinstance(v, list):
            return [
                validate_enum_with_enhanced_error(i, InformationContentType, 'content_types')
                for i in v
            ]
        return v

    @field_validator('sensitivity_tier', mode='before')
    @classmethod
    def validate_sensitivity_tier(cls, v):
        return validate_enum_with_enhanced_error(v, SensitivityTier, 'sensitivity_tier')

    @field_validator('compliance_regimes', mode='before')
    @classmethod
    def validate_compliance_regimes(cls, v):
        if v is None:
            return []
        if isinstance(v, list):
            return [
                validate_enum_with_enhanced_error(i, RegulatoryRequirement, 'compliance_regimes')
                for i in v
            ]
        return v

    @field_validator('data_states', mode='before')
    @classmethod
    def validate_data_states(cls, v):
        if v is None:
            return []
        # Match Asset by accepting either one state string or a list.
        if isinstance(v, str):
            v = [v]
        if isinstance(v, list):
            return [
                validate_enum_with_enhanced_error(i, DataState, 'data_states') for i in v
            ]
        return v

    @field_validator('volume_tier', mode='before')
    @classmethod
    def validate_volume_tier(cls, v):
        return validate_enum_with_enhanced_error(v, DataVolumeTier, 'volume_tier')

    @field_validator('lifecycle_state', mode='before')
    @classmethod
    def validate_lifecycle_state(cls, v):
        return validate_enum_with_enhanced_error(v, DataLifecycleState, 'lifecycle_state')

    @field_validator('business_domain', mode='before')
    @classmethod
    def validate_business_domain(cls, v):
        return validate_enum_with_enhanced_error(v, BusinessDomain, 'business_domain')
