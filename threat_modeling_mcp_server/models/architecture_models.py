"""Architecture models for the Threat Modeling MCP Server."""

from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, field_validator
from threat_modeling_mcp_server.validation.enum_validator import validate_enum_with_enhanced_error


class ComponentType(str, Enum):
    """Component type enum."""
    COMPUTE = "Compute"
    STORAGE = "Storage"
    NETWORK = "Network"
    SECURITY = "Security"
    DATABASE = "Database"
    MESSAGING = "Messaging"
    ANALYTICS = "Analytics"
    CONTAINER = "Container"
    SERVERLESS = "Serverless"
    OTHER = "Other"


class ServiceProvider(str, Enum):
    """Service provider enum."""
    AWS = "AWS"
    AZURE = "Azure"
    GCP = "GCP"
    CNCF = "CNCF"
    ON_PREMISE = "On-Premise"
    HYBRID = "Hybrid"
    OTHER = "Other"


class AWSService(str, Enum):
    """AWS service enum."""
    EC2 = "EC2"
    S3 = "S3"
    RDS = "RDS"
    LAMBDA = "Lambda"
    DYNAMODB = "DynamoDB"
    VPC = "VPC"
    API_GATEWAY = "API Gateway"
    CLOUDFRONT = "CloudFront"
    COGNITO = "Cognito"
    IAM = "IAM"
    SQS = "SQS"
    SNS = "SNS"
    KINESIS = "Kinesis"
    CLOUDWATCH = "CloudWatch"
    ROUTE53 = "Route53"
    ECS = "ECS"
    EKS = "EKS"
    FARGATE = "Fargate"
    OTHER = "Other"


class Protocol(str, Enum):
    """Network protocol enum."""
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    TCP = "TCP"
    UDP = "UDP"
    SSH = "SSH"
    FTP = "FTP"
    SMTP = "SMTP"
    WEBSOCKET = "WebSocket"
    GRPC = "gRPC"
    MQTT = "MQTT"
    OTHER = "Other"


class DataStoreType(str, Enum):
    """Data store type enum."""
    RELATIONAL = "Relational"
    NOSQL = "NoSQL"
    OBJECT_STORAGE = "Object Storage"
    FILE_SYSTEM = "File System"
    CACHE = "Cache"
    DATA_WAREHOUSE = "Data Warehouse"
    GRAPH = "Graph"
    TIME_SERIES = "Time Series"
    LEDGER = "Ledger"
    OTHER = "Other"


class DataClassification(str, Enum):
    """Data classification enum."""
    PUBLIC = "Public"
    INTERNAL = "Internal"
    CONFIDENTIAL = "Confidential"
    RESTRICTED = "Restricted"
    REGULATED = "Regulated"


class BackupFrequency(str, Enum):
    """Backup frequency enum."""
    HOURLY = "Hourly"
    DAILY = "Daily"
    WEEKLY = "Weekly"
    MONTHLY = "Monthly"
    CONTINUOUS = "Continuous"
    NONE = "None"


class Component(BaseModel):
    """Model for a system component."""
    id: str
    name: str
    type: ComponentType
    service_provider: Optional[ServiceProvider] = None
    specific_service: Optional[str] = None
    version: Optional[str] = None
    description: Optional[str] = None
    configuration: Optional[Dict[str, Any]] = None
    
    @field_validator('type', mode='before')
    @classmethod
    def validate_component_type(cls, v):
        return validate_enum_with_enhanced_error(v, ComponentType, 'type')
    
    @field_validator('service_provider', mode='before')
    @classmethod
    def validate_service_provider(cls, v):
        return validate_enum_with_enhanced_error(v, ServiceProvider, 'service_provider')


class Connection(BaseModel):
    """Model for a connection between components."""
    id: str
    source_id: str
    destination_id: str
    protocol: Optional[Protocol] = None
    port: Optional[int] = None
    encryption: bool = False
    description: Optional[str] = None
    
    @field_validator('protocol', mode='before')
    @classmethod
    def validate_protocol(cls, v):
        return validate_enum_with_enhanced_error(v, Protocol, 'protocol')


class DataStore(BaseModel):
    """Model for a data store."""
    id: str
    name: str
    type: DataStoreType
    classification: DataClassification
    encryption_at_rest: bool = False
    backup_frequency: Optional[BackupFrequency] = None
    description: Optional[str] = None
    
    @field_validator('type', mode='before')
    @classmethod
    def validate_data_store_type(cls, v):
        return validate_enum_with_enhanced_error(v, DataStoreType, 'type')
    
    @field_validator('classification', mode='before')
    @classmethod
    def validate_classification(cls, v):
        return validate_enum_with_enhanced_error(v, DataClassification, 'classification')
    
    @field_validator('backup_frequency', mode='before')
    @classmethod
    def validate_backup_frequency(cls, v):
        return validate_enum_with_enhanced_error(v, BackupFrequency, 'backup_frequency')


class Architecture(BaseModel):
    """Model for the system architecture."""
    components: List[Component] = []
    connections: List[Connection] = []
    data_stores: List[DataStore] = []
    description: str = ""
