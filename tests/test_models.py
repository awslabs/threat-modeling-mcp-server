"""Unit tests for data models."""

import pytest
from pydantic import ValidationError

from threat_modeling_mcp_server.models.threat_models import (
    Threat,
    Mitigation,
    ThreatCategory,
    ThreatSeverity,
    ThreatLikelihood,
    ThreatStatus,
    MitigationType,
    MitigationStatus,
    MitigationCost,
    MitigationEffectiveness,
    MetadataItem,
    AssumptionLink,
    MitigationLink,
    ThreatModel,
    ThreatLibrary,
    MitigationLibrary,
    AttackVector,
    AttackComplexity,
)
from threat_modeling_mcp_server.models.architecture_models import (
    Component,
    Connection,
    DataStore,
    Architecture,
    ComponentType,
    ServiceProvider,
    Protocol,
    DataStoreType,
    DataClassification,
    BackupFrequency,
)


class TestThreatModel:
    """Tests for the Threat model."""

    def test_create_minimal_threat(self):
        """Test creating a threat with minimal required fields."""
        threat = Threat(
            id="T1",
            numericId=1,
            threatSource="attacker",
            prerequisites="network access",
            threatAction="exploit vulnerability",
            threatImpact="data breach",
            statement="An attacker can exploit vulnerability",
            displayOrder=1,
        )
        assert threat.id == "T1"
        assert threat.numericId == 1
        assert threat.threatSource == "attacker"
        assert threat.status == ThreatStatus.IDENTIFIED

    def test_create_threat_with_all_fields(self):
        """Test creating a threat with all fields populated."""
        threat = Threat(
            id="T2",
            numericId=2,
            threatSource="external attacker",
            prerequisites="with network access",
            threatAction="inject SQL",
            threatImpact="unauthorized data access",
            statement="An external attacker can inject SQL",
            displayOrder=2,
            status="threatIdentified",
            category="Tampering",
            severity="High",
            likelihood="Likely",
            attack_vector="Network",
            attack_complexity="Low",
            affected_components=["comp1", "comp2"],
            impactedAssets=["asset1"],
            tags=["sql", "injection"],
        )
        assert threat.category == ThreatCategory.TAMPERING
        assert threat.severity == ThreatSeverity.HIGH
        assert threat.likelihood == ThreatLikelihood.LIKELY
        assert threat.attack_vector == AttackVector.NETWORK
        assert threat.attack_complexity == AttackComplexity.LOW
        assert "comp1" in threat.affected_components
        assert "sql" in threat.tags

    def test_threat_status_validation_case_insensitive(self):
        """Test that threat status accepts case-insensitive values."""
        threat = Threat(
            id="T3",
            numericId=3,
            threatSource="attacker",
            prerequisites="access",
            threatAction="attack",
            threatImpact="damage",
            statement="Statement",
            displayOrder=3,
            status="THREATIDENTIFIED",  # uppercase
        )
        assert threat.status == ThreatStatus.IDENTIFIED

    def test_threat_category_validation(self):
        """Test threat category enum validation."""
        threat = Threat(
            id="T4",
            numericId=4,
            threatSource="attacker",
            prerequisites="access",
            threatAction="attack",
            threatImpact="damage",
            statement="Statement",
            displayOrder=4,
            category="Spoofing",
        )
        assert threat.category == ThreatCategory.SPOOFING

    def test_threat_invalid_category_raises_error(self):
        """Test that invalid category raises validation error."""
        with pytest.raises(ValidationError):
            Threat(
                id="T5",
                numericId=5,
                threatSource="attacker",
                prerequisites="access",
                threatAction="attack",
                threatImpact="damage",
                statement="Statement",
                displayOrder=5,
                category="InvalidCategory",
            )

    def test_threat_optional_fields_default_to_none(self):
        """Test that optional fields default to None or empty lists."""
        threat = Threat(
            id="T6",
            numericId=6,
            threatSource="attacker",
            prerequisites="access",
            threatAction="attack",
            threatImpact="damage",
            statement="Statement",
            displayOrder=6,
        )
        assert threat.category is None
        assert threat.severity is None
        assert threat.likelihood is None
        assert threat.impactedGoal == []
        assert threat.impactedAssets == []
        assert threat.metadata == []


class TestMitigationModel:
    """Tests for the Mitigation model."""

    def test_create_minimal_mitigation(self):
        """Test creating a mitigation with minimal required fields."""
        mitigation = Mitigation(
            id="M1",
            numericId=1,
            content="Implement input validation",
            displayOrder=1,
        )
        assert mitigation.id == "M1"
        assert mitigation.content == "Implement input validation"
        assert mitigation.status == MitigationStatus.IDENTIFIED

    def test_create_mitigation_with_all_fields(self):
        """Test creating a mitigation with all fields populated."""
        mitigation = Mitigation(
            id="M2",
            numericId=2,
            content="Enable TLS encryption",
            displayOrder=2,
            status="mitigationInProgress",
            type="Preventive",
            cost="Medium",
            effectiveness="High",
            implementation_details="Configure TLS 1.3",
            responsible_party="Security Team",
            verification_method="SSL scan",
            estimated_time_to_implement=5,
            risk_reduction=0.75,
        )
        assert mitigation.status == MitigationStatus.IN_PROGRESS
        assert mitigation.type == MitigationType.PREVENTIVE
        assert mitigation.cost == MitigationCost.MEDIUM
        assert mitigation.effectiveness == MitigationEffectiveness.HIGH
        assert mitigation.estimated_time_to_implement == 5
        assert mitigation.risk_reduction == 0.75

    def test_mitigation_status_case_insensitive(self):
        """Test that mitigation status accepts case-insensitive values."""
        mitigation = Mitigation(
            id="M3",
            numericId=3,
            content="Test mitigation",
            displayOrder=3,
            status="MITIGATIONRESOLVED",
        )
        assert mitigation.status == MitigationStatus.RESOLVED

    def test_mitigation_invalid_type_raises_error(self):
        """Test that invalid type raises validation error."""
        with pytest.raises(ValidationError):
            Mitigation(
                id="M4",
                numericId=4,
                content="Test",
                displayOrder=4,
                type="InvalidType",
            )


class TestMetadataItem:
    """Tests for the MetadataItem model."""

    def test_create_metadata_item(self):
        """Test creating a metadata item."""
        item = MetadataItem(key="priority", value="high")
        assert item.key == "priority"
        assert item.value == "high"


class TestLinkModels:
    """Tests for AssumptionLink and MitigationLink models."""

    def test_create_assumption_link(self):
        """Test creating an assumption link."""
        link = AssumptionLink(
            linkedId="T1",
            assumptionId="A1",
            type="Threat",
        )
        assert link.linkedId == "T1"
        assert link.assumptionId == "A1"
        assert link.type == "Threat"

    def test_create_mitigation_link(self):
        """Test creating a mitigation link."""
        link = MitigationLink(
            linkedId="T1",
            mitigationId="M1",
        )
        assert link.linkedId == "T1"
        assert link.mitigationId == "M1"


class TestThreatModelContainer:
    """Tests for the ThreatModel container model."""

    def test_create_empty_threat_model(self):
        """Test creating an empty threat model."""
        model = ThreatModel()
        assert model.schema_version == 1
        assert model.threats == []
        assert model.mitigations == []
        assert model.assumptions == []

    def test_create_threat_model_with_data(self):
        """Test creating a threat model with data."""
        model = ThreatModel(
            applicationInfo={"name": "Test App", "description": "A test application"},
            threats=[{"id": "T1", "statement": "Test threat"}],
            mitigations=[{"id": "M1", "content": "Test mitigation"}],
        )
        assert model.applicationInfo["name"] == "Test App"
        assert len(model.threats) == 1
        assert len(model.mitigations) == 1


class TestComponentModel:
    """Tests for the Component model."""

    def test_create_minimal_component(self):
        """Test creating a component with minimal required fields."""
        component = Component(
            id="C1",
            name="Web Server",
            type="Compute",
        )
        assert component.id == "C1"
        assert component.name == "Web Server"
        assert component.type == ComponentType.COMPUTE

    def test_create_component_with_all_fields(self):
        """Test creating a component with all fields."""
        component = Component(
            id="C2",
            name="Database",
            type="Database",
            service_provider="AWS",
            specific_service="RDS",
            version="8.0",
            description="MySQL database",
            configuration={"engine": "mysql", "multi_az": True},
        )
        assert component.type == ComponentType.DATABASE
        assert component.service_provider == ServiceProvider.AWS
        assert component.specific_service == "RDS"
        assert component.configuration["multi_az"] is True

    def test_component_type_case_insensitive(self):
        """Test that component type accepts case-insensitive values."""
        component = Component(
            id="C3",
            name="Test",
            type="STORAGE",
        )
        assert component.type == ComponentType.STORAGE

    def test_component_invalid_type_raises_error(self):
        """Test that invalid component type raises validation error."""
        with pytest.raises(ValidationError):
            Component(
                id="C4",
                name="Test",
                type="InvalidType",
            )


class TestConnectionModel:
    """Tests for the Connection model."""

    def test_create_minimal_connection(self):
        """Test creating a connection with minimal required fields."""
        connection = Connection(
            id="CONN1",
            source_id="C1",
            destination_id="C2",
        )
        assert connection.id == "CONN1"
        assert connection.source_id == "C1"
        assert connection.destination_id == "C2"
        assert connection.encryption is False

    def test_create_connection_with_all_fields(self):
        """Test creating a connection with all fields."""
        connection = Connection(
            id="CONN2",
            source_id="C1",
            destination_id="C2",
            protocol="HTTPS",
            port=443,
            encryption=True,
            description="Secure API connection",
        )
        assert connection.protocol == Protocol.HTTPS
        assert connection.port == 443
        assert connection.encryption is True

    def test_connection_protocol_case_insensitive(self):
        """Test that protocol accepts case-insensitive values."""
        connection = Connection(
            id="CONN3",
            source_id="C1",
            destination_id="C2",
            protocol="tcp",
        )
        assert connection.protocol == Protocol.TCP


class TestDataStoreModel:
    """Tests for the DataStore model."""

    def test_create_minimal_data_store(self):
        """Test creating a data store with minimal required fields."""
        data_store = DataStore(
            id="DS1",
            name="User Database",
            type="Relational",
            classification="Confidential",
        )
        assert data_store.id == "DS1"
        assert data_store.type == DataStoreType.RELATIONAL
        assert data_store.classification == DataClassification.CONFIDENTIAL
        assert data_store.encryption_at_rest is False

    def test_create_data_store_with_all_fields(self):
        """Test creating a data store with all fields."""
        data_store = DataStore(
            id="DS2",
            name="Analytics Data",
            type="Data Warehouse",
            classification="Restricted",
            encryption_at_rest=True,
            backup_frequency="Daily",
            description="Data warehouse for analytics",
        )
        assert data_store.type == DataStoreType.DATA_WAREHOUSE
        assert data_store.classification == DataClassification.RESTRICTED
        assert data_store.backup_frequency == BackupFrequency.DAILY
        assert data_store.encryption_at_rest is True

    def test_data_store_type_case_insensitive(self):
        """Test that data store type accepts case-insensitive values."""
        data_store = DataStore(
            id="DS3",
            name="Cache",
            type="CACHE",
            classification="internal",
        )
        assert data_store.type == DataStoreType.CACHE
        assert data_store.classification == DataClassification.INTERNAL


class TestArchitectureModel:
    """Tests for the Architecture container model."""

    def test_create_empty_architecture(self):
        """Test creating an empty architecture."""
        arch = Architecture()
        assert arch.components == []
        assert arch.connections == []
        assert arch.data_stores == []
        assert arch.description == ""

    def test_create_architecture_with_components(self):
        """Test creating an architecture with components."""
        component = Component(id="C1", name="Server", type="Compute")
        arch = Architecture(
            components=[component],
            description="Test architecture",
        )
        assert len(arch.components) == 1
        assert arch.description == "Test architecture"


class TestThreatLibrary:
    """Tests for the ThreatLibrary class."""

    def test_get_common_threats_returns_dict(self):
        """Test that get_common_threats returns a dictionary."""
        threats = ThreatLibrary.get_common_threats()
        assert isinstance(threats, dict)
        assert len(threats) > 0

    def test_common_threats_has_authentication_category(self):
        """Test that common threats include authentication category."""
        threats = ThreatLibrary.get_common_threats()
        assert "authentication" in threats

    def test_common_threats_has_sql_injection(self):
        """Test that common threats include SQL injection."""
        threats = ThreatLibrary.get_common_threats()
        assert "data_validation" in threats
        assert "sql_injection" in threats["data_validation"]

    def test_threat_entries_have_required_fields(self):
        """Test that threat entries have required fields."""
        threats = ThreatLibrary.get_common_threats()
        sql_injection = threats["data_validation"]["sql_injection"]
        assert "source" in sql_injection
        assert "action" in sql_injection
        assert "impact" in sql_injection
        assert "category" in sql_injection


class TestMitigationLibrary:
    """Tests for the MitigationLibrary class."""

    def test_get_common_mitigations_returns_dict(self):
        """Test that get_common_mitigations returns a dictionary."""
        mitigations = MitigationLibrary.get_common_mitigations()
        assert isinstance(mitigations, dict)
        assert len(mitigations) > 0

    def test_common_mitigations_has_authentication_category(self):
        """Test that common mitigations include authentication category."""
        mitigations = MitigationLibrary.get_common_mitigations()
        assert "authentication" in mitigations

    def test_common_mitigations_has_mfa(self):
        """Test that common mitigations include MFA."""
        mitigations = MitigationLibrary.get_common_mitigations()
        assert "mfa" in mitigations["authentication"]

    def test_mitigation_entries_have_required_fields(self):
        """Test that mitigation entries have required fields."""
        mitigations = MitigationLibrary.get_common_mitigations()
        mfa = mitigations["authentication"]["mfa"]
        assert "content" in mfa
        assert "type" in mfa
        assert "cost" in mfa
        assert "effectiveness" in mfa


class TestEnumValues:
    """Tests to verify enum values are correctly defined."""

    def test_threat_category_stride_values(self):
        """Test that ThreatCategory includes all STRIDE categories."""
        assert ThreatCategory.SPOOFING.value == "Spoofing"
        assert ThreatCategory.TAMPERING.value == "Tampering"
        assert ThreatCategory.REPUDIATION.value == "Repudiation"
        assert ThreatCategory.INFORMATION_DISCLOSURE.value == "Information Disclosure"
        assert ThreatCategory.DENIAL_OF_SERVICE.value == "Denial of Service"
        assert ThreatCategory.ELEVATION_OF_PRIVILEGE.value == "Elevation of Privilege"

    def test_threat_severity_levels(self):
        """Test that ThreatSeverity has expected levels."""
        assert ThreatSeverity.LOW.value == "Low"
        assert ThreatSeverity.MEDIUM.value == "Medium"
        assert ThreatSeverity.HIGH.value == "High"
        assert ThreatSeverity.CRITICAL.value == "Critical"

    def test_mitigation_type_values(self):
        """Test that MitigationType has expected values."""
        assert MitigationType.PREVENTIVE.value == "Preventive"
        assert MitigationType.DETECTIVE.value == "Detective"
        assert MitigationType.CORRECTIVE.value == "Corrective"
        assert MitigationType.DETERRENT.value == "Deterrent"

    def test_component_type_values(self):
        """Test that ComponentType has expected values."""
        assert ComponentType.COMPUTE.value == "Compute"
        assert ComponentType.STORAGE.value == "Storage"
        assert ComponentType.NETWORK.value == "Network"
        assert ComponentType.DATABASE.value == "Database"
        assert ComponentType.SERVERLESS.value == "Serverless"
