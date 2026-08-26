"""Business context models for the Threat Modeling MCP Server.

Shared enums live here so profile modules can import them without creating
circular dependencies.
"""

from enum import Enum
from typing import Optional, Set
from pydantic import BaseModel, Field, model_validator


class IndustrySector(str, Enum):
    """Industry sector of the organization, distinct from a software user domain."""
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


class SensitivityTier(str, Enum):
    """How much protection the data needs across business and asset models."""
    PUBLIC = "Public"
    INTERNAL = "Internal"
    CONFIDENTIAL = "Confidential"
    RESTRICTED = "Restricted"


class BusinessDomain(str, Enum):
    """Internal business area that owns the data, rather than its industry."""
    FINANCE = "Finance"
    HEALTHCARE = "Healthcare"
    HR = "HR"
    ENGINEERING = "Engineering"
    SALES_MARKETING = "Sales / marketing"
    OPERATIONS = "Operations"
    LEGAL = "Legal"
    OTHER = "Other"


class UserBaseSize(str, Enum):
    """Logarithmic user base size tier."""
    NANO = "Nano"  # < 100
    MICRO = "Micro"  # 100 - 1,000
    SMALL = "Small"  # 1,000 - 100,000
    MEDIUM = "Medium"  # 100,000 - 10M
    LARGE = "Large"  # 10M - 100M
    VERY_LARGE = "Very Large"  # 100M - 1B (EU VLOP threshold at 45M EU MAU)
    HYPER_SCALE = "Hyper-Scale"  # > 1B


class UserBaseMetric(str, Enum):
    """Unit used to measure the user base."""
    MAU = "Monthly Active Users"
    DAU = "Daily Active Users"
    CCU = "Concurrent Users"
    SEATS = "Seats / licenses"
    ORGANIZATIONAL_CUSTOMERS = "Organizational customers"
    INSTALLS = "Installs / downloads"
    REGISTERED_USERS = "Registered users"


class GeographicScope(str, Enum):
    """Ordinal geographic reach from sub-national to global."""
    SUB_NATIONAL = "Sub-National / Local"  # L0
    NATIONAL = "National / Single-Country"  # L1
    REGIONAL = "Regional / Multi-Country Bloc"  # L2
    CONTINENTAL = "Continental / Macro-Regional"  # L3
    MULTI_CONTINENTAL = "Multi-Continental / International"  # L4
    GLOBAL = "Global / Transboundary"  # L5


class RegulatoryRequirement(str, Enum):
    """Applicable compliance regime."""
    GDPR = "GDPR"
    CCPA = "CCPA / CPRA"
    HIPAA = "HIPAA"
    PCI_DSS = "PCI-DSS"
    SOX = "SOX"
    FISMA = "FISMA / FedRAMP"
    NONE = "None"
    MULTIPLE = "Multiple / other"


class SystemCriticality(str, Enum):
    """How critical the system is to business operations."""
    LOW = "Low"  # non-critical, can be down for days
    MEDIUM = "Medium"  # important, should be up within hours
    HIGH = "High"  # critical, must be up within minutes
    MISSION_CRITICAL = "Mission-Critical"  # cannot be down


class FinancialImpact(str, Enum):
    """Revenue-relative financial impact tier of a breach or failure."""
    NEGLIGIBLE = "Negligible"  # < 0.001% of revenue
    LOW = "Low"  # 0.001% - 0.01%
    MODERATE = "Moderate"  # 0.01% - 0.1% (materiality benchmark)
    HIGH = "High"  # 0.1% - 1%
    CRITICAL = "Critical"  # > 1% of revenue


class RevenueBand(str, Enum):
    """Annual revenue band used to estimate absolute financial impact."""
    SMALL_BUSINESS = "Small business"  # < $50M revenue
    MID_MARKET = "Mid-market"  # $50M - $1B revenue
    ENTERPRISE = "Enterprise"  # > $1B revenue


class AuthenticationRequirement(str, Enum):
    """Authentication strength required by the system."""
    NONE = "None"
    BASIC = "Basic"  # username/password
    MFA = "MFA"  # multi-factor
    FEDERATED = "Federated"  # SSO, OAuth
    BIOMETRIC = "Biometric"


class DeploymentModel(str, Enum):
    """Where the software runs and who secures each layer."""
    ON_PREMISES = "On-premises"
    IAAS = "IaaS"
    PAAS = "PaaS"
    SAAS = "SaaS"
    SERVERLESS = "Serverless / FaaS"
    HYBRID_CLOUD = "Hybrid cloud"
    MULTI_CLOUD = "Multi-cloud"
    EDGE = "Edge"


class GeographicProfile(BaseModel):
    """Geographic scope for data, compute, users, and headquarters."""
    data_residency: Optional[GeographicScope] = None
    compute_location: Optional[GeographicScope] = None
    user_base_location: Optional[GeographicScope] = None
    organizational_headquarters: Optional[GeographicScope] = None


class BusinessContext(BaseModel):
    """Model for business context."""
    description: str = ""
    industry_sector: Optional[IndustrySector] = None
    sensitivity_tier: Optional[SensitivityTier] = None
    user_base_size: Optional[UserBaseSize] = None
    user_base_metric: Optional[UserBaseMetric] = None
    geographic_scope: Optional[GeographicScope] = None
    geographic_profile: Optional[GeographicProfile] = None
    regulatory_requirements: Set[RegulatoryRequirement] = Field(default_factory=set)
    system_criticality: Optional[SystemCriticality] = None
    financial_impact: Optional[FinancialImpact] = None
    revenue_band: Optional[RevenueBand] = None
    authentication_requirement: Optional[AuthenticationRequirement] = None
    deployment_model: Optional[DeploymentModel] = None

    @model_validator(mode="after")
    def validate_regulatory_requirements(self):
        exclusive = {RegulatoryRequirement.NONE, RegulatoryRequirement.MULTIPLE}
        selected_exclusive = self.regulatory_requirements & exclusive
        if selected_exclusive and len(self.regulatory_requirements) > 1:
            labels = ", ".join(sorted(item.value for item in selected_exclusive))
            raise ValueError(
                f"{labels} cannot be combined with another regulatory requirement"
            )
        return self


class Assumption(BaseModel):
    """Model for a threat modeling assumption."""
    id: str
    description: str
    category: str
    impact: str
    rationale: str
