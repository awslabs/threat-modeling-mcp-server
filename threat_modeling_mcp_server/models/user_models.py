"""Legitimate user persona models for the Threat Modeling MCP Server.

UserPersonaType is the primary classification. Supporting enums are application
vocabularies for privilege, affiliation, role, behavior, and entity type.
Authentication methods are shared with trust-boundary models, and threat actor
overlays store ThreatActor ids.
"""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, field_validator

from threat_modeling_mcp_server.models.trust_boundary_models import AuthenticationMethod
from threat_modeling_mcp_server.validation.enum_validator import (
    validate_enum_with_enhanced_error,
)


class UserPersonaType(str, Enum):
    """Primary classification for legitimate actors rather than attackers."""
    ANONYMOUS = "Anonymous / Unauthenticated User"
    AUTHENTICATED_STANDARD = "Authenticated Standard User"
    PRIVILEGED_BUSINESS = "Privileged Business User"
    SYSTEM_ADMINISTRATOR = "System Administrator"
    SUPPORT_OPERATOR = "Support / Operator User"
    DEVELOPER_DEVOPS = "Developer / DevOps User"
    AUDITOR_COMPLIANCE = "Auditor / Compliance User"
    NON_HUMAN_IDENTITY = "Non-Human Identity / Service Account"
    EXTERNAL_SERVICE = "External Service / Third-Party Integration"
    CONTRACTOR_TEMPORARY = "Contractor / Temporary User"
    DATA_SUBJECT = "Data Subject"
    PARTNER_VENDOR = "Partner / Vendor"


class PrivilegeLevel(str, Enum):
    """Persona privilege, distinct from the trust level of an architectural zone."""
    NONE = "None"
    LOW = "Low"
    MEDIUM = "Medium"
    ELEVATED = "Elevated"
    ADMINISTRATIVE = "Administrative"


class OrganizationalAffiliation(str, Enum):
    """Relationship between the persona and the organization."""
    PUBLIC = "Public / Unknown"
    CUSTOMER = "Customer"
    EMPLOYEE = "Employee"
    CONTRACTOR = "Contractor"
    VENDOR = "Vendor"
    PARTNER = "Partner"
    REGULATOR = "Regulator"


class FunctionalRole(str, Enum):
    """What the persona does in the system."""
    END_USER = "End User"
    APPROVER = "Approver"
    DATA_OWNER = "Data Owner"
    ADMINISTRATOR = "Administrator"
    OPERATOR = "Operator"
    SUPPORT = "Support"
    DEVELOPER = "Developer"
    AUDITOR = "Auditor"
    SERVICE_ACCOUNT = "Service Account"
    INTEGRATION_ENDPOINT = "Integration Endpoint"
    DATA_SUBJECT = "Data Subject"


class IntentBehavior(str, Enum):
    """Intent and behavior of the persona.

    Legitimate personas default to LEGITIMATE; other values capture risky or
    compromised behavior.
    """
    LEGITIMATE = "Legitimate"
    MISTAKEN = "Mistaken"
    NEGLIGENT = "Negligent"
    SOCIALLY_ENGINEERED = "Socially Engineered"
    COMPROMISED = "Compromised"
    MALICIOUS = "Malicious"


class EntityType(str, Enum):
    """Whether the persona is a person, machine, external system, or group.

    Authentication is recorded separately on UserPersona.authentication_method.
    """
    HUMAN = "Human"
    NON_HUMAN = "Non-Human"
    EXTERNAL_SYSTEM = "External System"
    GROUP_SHARED = "Group / Shared Identity"


class UserPersona(BaseModel):
    """A legitimate user persona and its system access characteristics."""
    id: str
    persona_type: UserPersonaType
    name: Optional[str] = None
    privilege_level: Optional[PrivilegeLevel] = None
    organizational_affiliation: Optional[OrganizationalAffiliation] = None
    functional_roles: List[FunctionalRole] = []
    intent_behavior: IntentBehavior = IntentBehavior.LEGITIMATE
    entity_type: Optional[EntityType] = None
    authentication_method: Optional[AuthenticationMethod] = None
    # ThreatActor ids linked to this persona.
    threat_actor_overlay: List[str] = []
    description: Optional[str] = None
    is_relevant: bool = True

    @field_validator('persona_type', mode='before')
    @classmethod
    def validate_persona_type(cls, v):
        return validate_enum_with_enhanced_error(v, UserPersonaType, 'persona_type')

    @field_validator('privilege_level', mode='before')
    @classmethod
    def validate_privilege_level(cls, v):
        return validate_enum_with_enhanced_error(v, PrivilegeLevel, 'privilege_level')

    @field_validator('organizational_affiliation', mode='before')
    @classmethod
    def validate_organizational_affiliation(cls, v):
        return validate_enum_with_enhanced_error(
            v, OrganizationalAffiliation, 'organizational_affiliation'
        )

    @field_validator('functional_roles', mode='before')
    @classmethod
    def validate_functional_roles(cls, v):
        if v is None:
            return []
        if isinstance(v, list):
            return [
                validate_enum_with_enhanced_error(i, FunctionalRole, 'functional_roles')
                for i in v
            ]
        return v

    @field_validator('intent_behavior', mode='before')
    @classmethod
    def validate_intent_behavior(cls, v):
        if v is None:
            return IntentBehavior.LEGITIMATE
        return validate_enum_with_enhanced_error(v, IntentBehavior, 'intent_behavior')

    @field_validator('entity_type', mode='before')
    @classmethod
    def validate_entity_type(cls, v):
        return validate_enum_with_enhanced_error(v, EntityType, 'entity_type')

    @field_validator('authentication_method', mode='before')
    @classmethod
    def validate_authentication_method(cls, v):
        return validate_enum_with_enhanced_error(v, AuthenticationMethod, 'authentication_method')
