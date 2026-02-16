"""Models for the Threat Modeling MCP Server."""

from enum import Enum
from typing import Dict, List, Optional, Set, Any
from pydantic import BaseModel


class IndustrySector(str, Enum):
    """Industry sector enum."""
    FINANCE = "Finance"
    HEALTHCARE = "Healthcare"
    RETAIL = "Retail"
    TECHNOLOGY = "Technology"
    MANUFACTURING = "Manufacturing"
    GOVERNMENT = "Government"
    EDUCATION = "Education"
    ENERGY = "Energy"
    TRANSPORTATION = "Transportation"
    OTHER = "Other"


class DataSensitivity(str, Enum):
    """Data sensitivity enum."""
    PUBLIC = "Public"
    INTERNAL = "Internal"
    CONFIDENTIAL = "Confidential"
    RESTRICTED = "Restricted"
    REGULATED = "Regulated"


class UserBaseSize(str, Enum):
    """User base size enum."""
    SMALL = "Small"  # < 1,000
    MEDIUM = "Medium"  # 1,000 - 100,000
    LARGE = "Large"  # 100,000 - 1M
    ENTERPRISE = "Enterprise"  # > 1M


class GeographicScope(str, Enum):
    """Geographic scope enum."""
    LOCAL = "Local"
    REGIONAL = "Regional"
    NATIONAL = "National"
    MULTINATIONAL = "Multinational"
    GLOBAL = "Global"


class RegulatoryRequirement(str, Enum):
    """Regulatory requirement enum."""
    GDPR = "GDPR"
    HIPAA = "HIPAA"
    PCI_DSS = "PCI-DSS"
    SOX = "SOX"
    FISMA = "FISMA"
    CCPA = "CCPA"
    NONE = "None"
    MULTIPLE = "Multiple"


class SystemCriticality(str, Enum):
    """System criticality enum."""
    LOW = "Low"  # non-critical, can be down for days
    MEDIUM = "Medium"  # important, should be up within hours
    HIGH = "High"  # critical, must be up within minutes
    MISSION_CRITICAL = "Mission-Critical"  # cannot be down


class FinancialImpact(str, Enum):
    """Financial impact of breach enum."""
    MINIMAL = "Minimal"  # < $10K
    LOW = "Low"  # $10K - $100K
    MEDIUM = "Medium"  # $100K - $1M
    HIGH = "High"  # $1M - $10M
    SEVERE = "Severe"  # > $10M


class AuthenticationRequirement(str, Enum):
    """Authentication requirement enum."""
    NONE = "None"
    BASIC = "Basic"  # username/password
    MFA = "MFA"  # multi-factor
    FEDERATED = "Federated"  # SSO, OAuth
    BIOMETRIC = "Biometric"


class DeploymentEnvironment(str, Enum):
    """Deployment environment enum."""
    ON_PREMISES = "On-Premises"
    CLOUD_PUBLIC = "Cloud-Public"
    CLOUD_PRIVATE = "Cloud-Private"
    HYBRID = "Hybrid"
    MULTI_CLOUD = "Multi-Cloud"


class IntegrationComplexity(str, Enum):
    """Integration complexity enum."""
    STANDALONE = "Standalone"
    LIMITED = "Limited"  # few external integrations
    MODERATE = "Moderate"  # several integrations
    COMPLEX = "Complex"  # many integrations
    HIGHLY_COMPLEX = "Highly Complex"  # extensive ecosystem


class ClarificationQuestion(BaseModel):
    """Model for a clarification question."""
    id: str
    question: str
    feature: str
    enum_values: Optional[Dict[str, str]] = None  # Map of enum value to description
    enum_type: Optional[str] = None  # Name of the enum type
    answered: bool = False
    answer: Optional[str] = None


class BusinessContext(BaseModel):
    """Model for business context."""
    description: str = ""
    industry_sector: Optional[IndustrySector] = None
    data_sensitivity: Optional[DataSensitivity] = None
    user_base_size: Optional[UserBaseSize] = None
    geographic_scope: Optional[GeographicScope] = None
    regulatory_requirements: Set[RegulatoryRequirement] = set()
    system_criticality: Optional[SystemCriticality] = None
    financial_impact: Optional[FinancialImpact] = None
    authentication_requirement: Optional[AuthenticationRequirement] = None
    deployment_environment: Optional[DeploymentEnvironment] = None
    integration_complexity: Optional[IntegrationComplexity] = None


class Assumption(BaseModel):
    """Model for a threat modeling assumption."""
    id: str
    description: str
    category: str
    impact: str
    rationale: str
