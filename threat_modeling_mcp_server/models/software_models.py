"""Software classification models for the Threat Modeling MCP Server."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, field_validator

from threat_modeling_mcp_server.models.models import DeploymentModel
from threat_modeling_mcp_server.validation.enum_validator import (
    validate_enum_with_enhanced_error,
)


class SoftwareType(str, Enum):
    """Primary software purpose and function.

    Choose one type per system or component; classify composite systems by
    component.
    """
    WEB_APPLICATION = "Web Application"
    API_SERVICE = "API Service"
    SAAS_MULTI_TENANT = "SaaS / Multi-Tenant Application"
    MOBILE_APPLICATION = "Mobile Application"
    DESKTOP_APPLICATION = "Desktop Application"
    BACKEND_SERVICE = "Backend Service / Microservice"
    SERVERLESS_FUNCTION = "Serverless Function"
    BATCH_JOB = "Batch Job / Background Worker"
    DATA_PLATFORM = "Data Store / Data Platform"
    MESSAGING_SYSTEM = "Messaging / Event System"
    ADMIN_MANAGEMENT_PLANE = "Admin / Management Plane"
    DEVELOPER_TOOLING = "Developer Tooling / CI-CD System"
    EMBEDDED_IOT_FIRMWARE = "Embedded / IoT / Firmware"
    EDGE_APPLICATION = "Edge Application"
    INDUSTRIAL_OT_SYSTEM = "Industrial / OT System"
    AI_ML_SYSTEM = "AI / ML System"
    THIRD_PARTY_INTEGRATION = "Third-Party Integration"


class ArchitectureStyle(str, Enum):
    """Internal structure affecting boundaries, communication, and blast radius."""
    MONOLITH = "Monolith"
    LAYERED = "Layered / N-tier"
    MICROSERVICES = "Microservices"
    EVENT_DRIVEN = "Event-driven"
    SOA = "Service-oriented architecture"
    SERVERLESS = "Serverless"
    PEER_TO_PEER = "Peer-to-peer"
    PLUGIN_BASED = "Plugin-based"


class PlatformRuntime(str, Enum):
    """Operating environment affecting vulnerabilities and available controls."""
    WEB_BROWSER = "Web browser"
    MOBILE = "Mobile"
    DESKTOP = "Desktop"
    SERVER = "Server"
    CONTAINER = "Container"
    KUBERNETES = "Kubernetes"
    CLOUD_RUNTIME = "Cloud runtime"
    EMBEDDED_DEVICE = "Embedded device"
    FIRMWARE = "Firmware"
    INDUSTRIAL_CONTROLLER = "Industrial controller"


class UserDomain(str, Enum):
    """Usage domain, distinct from the organization's industry sector."""
    CONSUMER = "Consumer"
    ENTERPRISE = "Enterprise"
    HEALTHCARE = "Healthcare"
    FINANCIAL = "Financial"
    GOVERNMENT = "Government"
    EDUCATION = "Education"
    INDUSTRIAL = "Industrial"
    RETAIL = "Retail"
    COLLABORATION = "Collaboration"
    SECURITY = "Security"


class LicensingOwnership(str, Enum):
    """Ownership model affecting patching responsibility and supply-chain visibility."""
    PROPRIETARY = "Proprietary"
    OPEN_SOURCE = "Open source"
    COMMERCIAL_SAAS = "Commercial SaaS"
    INTERNAL_CUSTOM_BUILT = "Internal custom-built"
    THIRD_PARTY_MANAGED = "Third-party managed"
    VENDOR_APPLIANCE = "Vendor appliance"
    COMMUNITY_MAINTAINED = "Community maintained"
    DUAL_LICENSED = "Dual-licensed"


class ModernParadigm(str, Enum):
    """Technology paradigms that introduce distinct threat patterns."""
    CLOUD_NATIVE = "Cloud-native"
    CONTAINERIZED = "Containerized"
    KUBERNETES_BASED = "Kubernetes-based"
    SERVICE_MESH = "Service mesh"
    AI_ML = "AI/ML"
    AGENTIC_AI = "Agentic AI"
    IOT = "IoT"
    EDGE_COMPUTING = "Edge computing"
    ZERO_TRUST = "Zero Trust architecture"
    EVENT_DRIVEN_ARCHITECTURE = "Event-driven architecture"


class SoftwareProfile(BaseModel):
    """Software classification profile; modern paradigms may contain multiple values."""
    software_type: SoftwareType
    deployment_model: Optional[DeploymentModel] = None
    architecture_style: Optional[ArchitectureStyle] = None
    platform_runtime: Optional[PlatformRuntime] = None
    user_domain: Optional[UserDomain] = None
    licensing_ownership: Optional[LicensingOwnership] = None
    modern_paradigms: List[ModernParadigm] = []
    description: Optional[str] = None

    @field_validator('software_type', mode='before')
    @classmethod
    def validate_software_type(cls, v):
        return validate_enum_with_enhanced_error(v, SoftwareType, 'software_type')

    @field_validator('deployment_model', mode='before')
    @classmethod
    def validate_deployment_model(cls, v):
        return validate_enum_with_enhanced_error(v, DeploymentModel, 'deployment_model')

    @field_validator('architecture_style', mode='before')
    @classmethod
    def validate_architecture_style(cls, v):
        return validate_enum_with_enhanced_error(v, ArchitectureStyle, 'architecture_style')

    @field_validator('platform_runtime', mode='before')
    @classmethod
    def validate_platform_runtime(cls, v):
        return validate_enum_with_enhanced_error(v, PlatformRuntime, 'platform_runtime')

    @field_validator('user_domain', mode='before')
    @classmethod
    def validate_user_domain(cls, v):
        return validate_enum_with_enhanced_error(v, UserDomain, 'user_domain')

    @field_validator('licensing_ownership', mode='before')
    @classmethod
    def validate_licensing_ownership(cls, v):
        return validate_enum_with_enhanced_error(v, LicensingOwnership, 'licensing_ownership')

    @field_validator('modern_paradigms', mode='before')
    @classmethod
    def validate_modern_paradigms(cls, v):
        if v is None:
            return []
        if isinstance(v, list):
            return [
                validate_enum_with_enhanced_error(item, ModernParadigm, 'modern_paradigms')
                for item in v
            ]
        return v
