"""Threat and Mitigation models for the Threat Modeling MCP Server."""

from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, field_validator
from uuid import uuid4
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


class AttackVector(str, Enum):
    """Attack vector types."""
    NETWORK = "Network"
    ADJACENT = "Adjacent"
    LOCAL = "Local"
    PHYSICAL = "Physical"


class AttackComplexity(str, Enum):
    """Attack complexity levels."""
    LOW = "Low"
    HIGH = "High"


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
    threatSource: str
    prerequisites: str
    threatAction: str
    threatImpact: str
    impactedGoal: List[str] = []
    impactedAssets: List[str] = []
    metadata: List[MetadataItem] = []
    statement: str
    displayOrder: int
    status: ThreatStatus = ThreatStatus.IDENTIFIED
    tags: List[str] = []
    
    # Additional fields not in Threat Composer but useful for our system
    category: Optional[ThreatCategory] = None
    severity: Optional[ThreatSeverity] = None
    likelihood: Optional[ThreatLikelihood] = None
    attack_vector: Optional[AttackVector] = None
    attack_complexity: Optional[AttackComplexity] = None
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
    
    @field_validator('attack_vector', mode='before')
    @classmethod
    def validate_attack_vector(cls, v):
        return validate_enum_with_enhanced_error(v, AttackVector, 'attack_vector')
    
    @field_validator('attack_complexity', mode='before')
    @classmethod
    def validate_attack_complexity(cls, v):
        return validate_enum_with_enhanced_error(v, AttackComplexity, 'attack_complexity')


class Mitigation(BaseModel):
    """Model for a mitigation."""
    id: str
    numericId: int
    status: MitigationStatus = MitigationStatus.IDENTIFIED
    content: str
    displayOrder: int
    metadata: List[MetadataItem] = []
    
    # Additional fields not in Threat Composer but useful for our system
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


class AssumptionLink(BaseModel):
    """Model for linking assumptions to threats."""
    linkedId: str  # Threat ID
    assumptionId: str
    type: str = "Threat"


class MitigationLink(BaseModel):
    """Model for linking mitigations to threats."""
    linkedId: str  # Threat ID
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
    
    # Extended fields for comprehensive threat model export
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
    phaseProgress: Dict[str, Any] = {}
    metadata: Dict[str, Any] = {}


class ThreatLibrary:
    """Library of common threats."""
    
    @staticmethod
    def get_common_threats() -> Dict[str, Dict[str, Any]]:
        """Get common threats organized by category."""
        return {
            "authentication": {
                "weak_credentials": {
                    "source": "external attacker",
                    "prerequisites": "with access to the authentication endpoint",
                    "action": "use brute force or dictionary attacks to guess weak passwords",
                    "impact": "unauthorized access to user accounts",
                    "category": ThreatCategory.SPOOFING,
                    "severity": ThreatSeverity.HIGH,
                    "likelihood": ThreatLikelihood.LIKELY,
                    "attack_vector": AttackVector.NETWORK
                },
                "credential_theft": {
                    "source": "external attacker",
                    "prerequisites": "with the ability to intercept network traffic",
                    "action": "steal authentication credentials transmitted in clear text",
                    "impact": "unauthorized access to user accounts",
                    "category": ThreatCategory.INFORMATION_DISCLOSURE,
                    "severity": ThreatSeverity.HIGH,
                    "likelihood": ThreatLikelihood.POSSIBLE,
                    "attack_vector": AttackVector.NETWORK
                },
                "session_hijacking": {
                    "source": "external attacker",
                    "prerequisites": "with the ability to intercept network traffic",
                    "action": "steal session tokens to hijack user sessions",
                    "impact": "unauthorized access to user sessions",
                    "category": ThreatCategory.SPOOFING,
                    "severity": ThreatSeverity.HIGH,
                    "likelihood": ThreatLikelihood.POSSIBLE,
                    "attack_vector": AttackVector.NETWORK
                }
            },
            "authorization": {
                "missing_access_control": {
                    "source": "authenticated user",
                    "prerequisites": "with valid credentials",
                    "action": "access resources they are not authorized to access due to missing access controls",
                    "impact": "unauthorized access to sensitive data or functionality",
                    "category": ThreatCategory.ELEVATION_OF_PRIVILEGE,
                    "severity": ThreatSeverity.HIGH,
                    "likelihood": ThreatLikelihood.POSSIBLE,
                    "attack_vector": AttackVector.NETWORK
                },
                "insecure_direct_object_reference": {
                    "source": "authenticated user",
                    "prerequisites": "with valid credentials",
                    "action": "manipulate object references to access unauthorized resources",
                    "impact": "unauthorized access to sensitive data",
                    "category": ThreatCategory.ELEVATION_OF_PRIVILEGE,
                    "severity": ThreatSeverity.MEDIUM,
                    "likelihood": ThreatLikelihood.POSSIBLE,
                    "attack_vector": AttackVector.NETWORK
                }
            },
            "data_validation": {
                "sql_injection": {
                    "source": "external attacker",
                    "prerequisites": "with access to input fields",
                    "action": "inject malicious SQL code into input fields",
                    "impact": "unauthorized access to database data or database corruption",
                    "category": ThreatCategory.TAMPERING,
                    "severity": ThreatSeverity.CRITICAL,
                    "likelihood": ThreatLikelihood.POSSIBLE,
                    "attack_vector": AttackVector.NETWORK
                },
                "xss": {
                    "source": "external attacker",
                    "prerequisites": "with access to input fields",
                    "action": "inject malicious JavaScript code into input fields",
                    "impact": "execution of attacker-controlled code in users' browsers",
                    "category": ThreatCategory.TAMPERING,
                    "severity": ThreatSeverity.HIGH,
                    "likelihood": ThreatLikelihood.LIKELY,
                    "attack_vector": AttackVector.NETWORK
                }
            },
            "encryption": {
                "data_exposure": {
                    "source": "external attacker",
                    "prerequisites": "with access to network traffic",
                    "action": "intercept unencrypted sensitive data",
                    "impact": "exposure of sensitive data",
                    "category": ThreatCategory.INFORMATION_DISCLOSURE,
                    "severity": ThreatSeverity.HIGH,
                    "likelihood": ThreatLikelihood.POSSIBLE,
                    "attack_vector": AttackVector.NETWORK
                },
                "weak_encryption": {
                    "source": "sophisticated attacker",
                    "prerequisites": "with cryptographic expertise",
                    "action": "break weak encryption algorithms",
                    "impact": "exposure of encrypted data",
                    "category": ThreatCategory.INFORMATION_DISCLOSURE,
                    "severity": ThreatSeverity.HIGH,
                    "likelihood": ThreatLikelihood.UNLIKELY,
                    "attack_vector": AttackVector.NETWORK
                }
            },
            "availability": {
                "dos": {
                    "source": "external attacker",
                    "prerequisites": "with sufficient resources",
                    "action": "flood the system with requests",
                    "impact": "denial of service to legitimate users",
                    "category": ThreatCategory.DENIAL_OF_SERVICE,
                    "severity": ThreatSeverity.HIGH,
                    "likelihood": ThreatLikelihood.POSSIBLE,
                    "attack_vector": AttackVector.NETWORK
                },
                "resource_exhaustion": {
                    "source": "external attacker",
                    "prerequisites": "with access to resource-intensive operations",
                    "action": "trigger expensive operations repeatedly",
                    "impact": "system slowdown or crash",
                    "category": ThreatCategory.DENIAL_OF_SERVICE,
                    "severity": ThreatSeverity.MEDIUM,
                    "likelihood": ThreatLikelihood.POSSIBLE,
                    "attack_vector": AttackVector.NETWORK
                }
            },
            "logging_auditing": {
                "log_tampering": {
                    "source": "internal actor",
                    "prerequisites": "with access to log files",
                    "action": "modify or delete log entries",
                    "impact": "inability to detect or investigate security incidents",
                    "category": ThreatCategory.REPUDIATION,
                    "severity": ThreatSeverity.MEDIUM,
                    "likelihood": ThreatLikelihood.POSSIBLE,
                    "attack_vector": AttackVector.LOCAL
                },
                "insufficient_logging": {
                    "source": "internal actor",
                    "prerequisites": "with malicious intent",
                    "action": "perform unauthorized actions that are not logged",
                    "impact": "inability to detect or investigate security incidents",
                    "category": ThreatCategory.REPUDIATION,
                    "severity": ThreatSeverity.MEDIUM,
                    "likelihood": ThreatLikelihood.LIKELY,
                    "attack_vector": AttackVector.LOCAL
                }
            },
            "configuration": {
                "default_credentials": {
                    "source": "external attacker",
                    "prerequisites": "with knowledge of default credentials",
                    "action": "use default credentials to access systems",
                    "impact": "unauthorized access to systems",
                    "category": ThreatCategory.SPOOFING,
                    "severity": ThreatSeverity.HIGH,
                    "likelihood": ThreatLikelihood.LIKELY,
                    "attack_vector": AttackVector.NETWORK
                },
                "misconfiguration": {
                    "source": "external attacker",
                    "prerequisites": "with knowledge of common misconfigurations",
                    "action": "exploit system misconfigurations",
                    "impact": "unauthorized access or system compromise",
                    "category": ThreatCategory.ELEVATION_OF_PRIVILEGE,
                    "severity": ThreatSeverity.HIGH,
                    "likelihood": ThreatLikelihood.LIKELY,
                    "attack_vector": AttackVector.NETWORK
                }
            },
            "aws_specific": {
                "iam_misconfiguration": {
                    "source": "external attacker",
                    "prerequisites": "with access to AWS credentials",
                    "action": "exploit overly permissive IAM policies",
                    "impact": "unauthorized access to AWS resources",
                    "category": ThreatCategory.ELEVATION_OF_PRIVILEGE,
                    "severity": ThreatSeverity.CRITICAL,
                    "likelihood": ThreatLikelihood.POSSIBLE,
                    "attack_vector": AttackVector.NETWORK
                },
                "s3_public_access": {
                    "source": "external attacker",
                    "prerequisites": "with knowledge of S3 bucket names",
                    "action": "access publicly exposed S3 buckets",
                    "impact": "unauthorized access to sensitive data",
                    "category": ThreatCategory.INFORMATION_DISCLOSURE,
                    "severity": ThreatSeverity.HIGH,
                    "likelihood": ThreatLikelihood.LIKELY,
                    "attack_vector": AttackVector.NETWORK
                },
                "lambda_code_injection": {
                    "source": "external attacker",
                    "prerequisites": "with access to Lambda function inputs",
                    "action": "inject malicious code into Lambda functions",
                    "impact": "execution of unauthorized code in AWS environment",
                    "category": ThreatCategory.TAMPERING,
                    "severity": ThreatSeverity.HIGH,
                    "likelihood": ThreatLikelihood.POSSIBLE,
                    "attack_vector": AttackVector.NETWORK
                }
            }
        }


class MitigationLibrary:
    """Library of common mitigations."""
    
    @staticmethod
    def get_common_mitigations() -> Dict[str, Dict[str, Any]]:
        """Get common mitigations organized by category."""
        return {
            "authentication": {
                "strong_password_policy": {
                    "content": "Implement a strong password policy",
                    "type": MitigationType.PREVENTIVE,
                    "cost": MitigationCost.LOW,
                    "effectiveness": MitigationEffectiveness.MEDIUM,
                    "implementation_details": "Require passwords to be at least 12 characters long, contain a mix of uppercase and lowercase letters, numbers, and special characters, and not be based on common words or phrases.",
                    "verification_method": "Automated password policy enforcement and regular audits"
                },
                "mfa": {
                    "content": "Implement multi-factor authentication",
                    "type": MitigationType.PREVENTIVE,
                    "cost": MitigationCost.MEDIUM,
                    "effectiveness": MitigationEffectiveness.HIGH,
                    "implementation_details": "Require users to provide two or more verification factors to gain access to resources, such as something they know (password), something they have (security token), or something they are (biometric verification).",
                    "verification_method": "Verify MFA is enabled for all users and test authentication flows"
                },
                "account_lockout": {
                    "content": "Implement account lockout policies",
                    "type": MitigationType.PREVENTIVE,
                    "cost": MitigationCost.LOW,
                    "effectiveness": MitigationEffectiveness.MEDIUM,
                    "implementation_details": "Lock accounts after a specified number of failed login attempts to prevent brute force attacks.",
                    "verification_method": "Test account lockout functionality with failed login attempts"
                }
            },
            "authorization": {
                "least_privilege": {
                    "content": "Apply the principle of least privilege",
                    "type": MitigationType.PREVENTIVE,
                    "cost": MitigationCost.MEDIUM,
                    "effectiveness": MitigationEffectiveness.HIGH,
                    "implementation_details": "Grant users only the minimum permissions necessary to perform their job functions.",
                    "verification_method": "Regular permission audits and access reviews"
                },
                "rbac": {
                    "content": "Implement role-based access control",
                    "type": MitigationType.PREVENTIVE,
                    "cost": MitigationCost.MEDIUM,
                    "effectiveness": MitigationEffectiveness.HIGH,
                    "implementation_details": "Assign permissions to roles rather than individual users, and assign users to appropriate roles.",
                    "verification_method": "Verify role definitions and assignments through access control testing"
                }
            },
            "data_validation": {
                "input_validation": {
                    "content": "Implement input validation",
                    "type": MitigationType.PREVENTIVE,
                    "cost": MitigationCost.MEDIUM,
                    "effectiveness": MitigationEffectiveness.HIGH,
                    "implementation_details": "Validate all input against a whitelist of allowed characters and formats.",
                    "verification_method": "Automated testing with invalid inputs"
                },
                "parameterized_queries": {
                    "content": "Use parameterized queries",
                    "type": MitigationType.PREVENTIVE,
                    "cost": MitigationCost.LOW,
                    "effectiveness": MitigationEffectiveness.HIGH,
                    "implementation_details": "Use parameterized queries or prepared statements for database access to prevent SQL injection.",
                    "verification_method": "Code review and automated testing for SQL injection vulnerabilities"
                },
                "output_encoding": {
                    "content": "Implement output encoding",
                    "type": MitigationType.PREVENTIVE,
                    "cost": MitigationCost.LOW,
                    "effectiveness": MitigationEffectiveness.HIGH,
                    "implementation_details": "Encode all output to prevent cross-site scripting attacks.",
                    "verification_method": "Automated testing for XSS vulnerabilities"
                }
            },
            "encryption": {
                "tls": {
                    "content": "Use TLS for all communications",
                    "type": MitigationType.PREVENTIVE,
                    "cost": MitigationCost.LOW,
                    "effectiveness": MitigationEffectiveness.HIGH,
                    "implementation_details": "Use TLS 1.2 or higher for all communications to encrypt data in transit.",
                    "verification_method": "Network traffic analysis and TLS configuration review"
                },
                "data_encryption": {
                    "content": "Encrypt sensitive data at rest",
                    "type": MitigationType.PREVENTIVE,
                    "cost": MitigationCost.MEDIUM,
                    "effectiveness": MitigationEffectiveness.HIGH,
                    "implementation_details": "Use strong encryption algorithms to encrypt sensitive data stored in databases or files.",
                    "verification_method": "Database configuration review and data storage audit"
                }
            },
            "availability": {
                "rate_limiting": {
                    "content": "Implement rate limiting",
                    "type": MitigationType.PREVENTIVE,
                    "cost": MitigationCost.MEDIUM,
                    "effectiveness": MitigationEffectiveness.MEDIUM,
                    "implementation_details": "Limit the number of requests a user can make in a given time period to prevent denial of service attacks.",
                    "verification_method": "Load testing and rate limit verification"
                },
                "ddos_protection": {
                    "content": "Use DDoS protection services",
                    "type": MitigationType.PREVENTIVE,
                    "cost": MitigationCost.HIGH,
                    "effectiveness": MitigationEffectiveness.HIGH,
                    "implementation_details": "Use cloud-based DDoS protection services to detect and mitigate DDoS attacks.",
                    "verification_method": "DDoS simulation testing and service configuration review"
                }
            },
            "logging_auditing": {
                "comprehensive_logging": {
                    "content": "Implement comprehensive logging",
                    "type": MitigationType.DETECTIVE,
                    "cost": MitigationCost.MEDIUM,
                    "effectiveness": MitigationEffectiveness.MEDIUM,
                    "implementation_details": "Log all security-relevant events, including authentication attempts, authorization decisions, and data access.",
                    "verification_method": "Log review and completeness testing"
                },
                "log_protection": {
                    "content": "Protect log integrity",
                    "type": MitigationType.PREVENTIVE,
                    "cost": MitigationCost.MEDIUM,
                    "effectiveness": MitigationEffectiveness.MEDIUM,
                    "implementation_details": "Store logs in a secure, tamper-evident manner to prevent unauthorized modification.",
                    "verification_method": "Log integrity verification and access control review"
                }
            },
            "configuration": {
                "secure_configuration": {
                    "content": "Use secure configuration baselines",
                    "type": MitigationType.PREVENTIVE,
                    "cost": MitigationCost.MEDIUM,
                    "effectiveness": MitigationEffectiveness.HIGH,
                    "implementation_details": "Use secure configuration baselines for all systems and applications.",
                    "verification_method": "Configuration review and compliance checking"
                },
                "change_management": {
                    "content": "Implement change management processes",
                    "type": MitigationType.PREVENTIVE,
                    "cost": MitigationCost.MEDIUM,
                    "effectiveness": MitigationEffectiveness.MEDIUM,
                    "implementation_details": "Use formal change management processes to review and approve changes to systems and applications.",
                    "verification_method": "Change management process audit"
                }
            },
            "aws_specific": {
                "iam_best_practices": {
                    "content": "Follow IAM best practices",
                    "type": MitigationType.PREVENTIVE,
                    "cost": MitigationCost.MEDIUM,
                    "effectiveness": MitigationEffectiveness.HIGH,
                    "implementation_details": "Use IAM roles instead of long-term access keys, apply least privilege, and regularly rotate credentials.",
                    "verification_method": "IAM configuration review and AWS Config rules"
                },
                "s3_bucket_policies": {
                    "content": "Secure S3 buckets",
                    "type": MitigationType.PREVENTIVE,
                    "cost": MitigationCost.LOW,
                    "effectiveness": MitigationEffectiveness.HIGH,
                    "implementation_details": "Use bucket policies to restrict access, enable default encryption, and disable public access.",
                    "verification_method": "S3 configuration review and automated scanning"
                },
                "cloudtrail_logging": {
                    "content": "Enable CloudTrail logging",
                    "type": MitigationType.DETECTIVE,
                    "cost": MitigationCost.LOW,
                    "effectiveness": MitigationEffectiveness.MEDIUM,
                    "implementation_details": "Enable CloudTrail logging for all regions and all AWS services.",
                    "verification_method": "CloudTrail configuration review and log analysis"
                }
            }
        }
