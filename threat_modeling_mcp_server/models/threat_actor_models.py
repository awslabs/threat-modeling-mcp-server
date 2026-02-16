"""Threat Actor models for the Threat Modeling MCP Server."""

from enum import Enum
from typing import Dict, List, Optional, Set, Any, Union
from pydantic import BaseModel, Field, field_validator
from threat_modeling_mcp_server.validation.enum_validator import validate_enum_with_enhanced_error


class ThreatActorType(str, Enum):
    """Threat actor type enum."""
    INSIDER = "Insider"
    EXTERNAL = "External"
    NATION_STATE = "Nation-state"
    HACKTIVIST = "Hacktivist"
    ORGANIZED_CRIME = "Organized Crime"
    COMPETITOR = "Competitor"
    SCRIPT_KIDDIE = "Script Kiddie"
    DISGRUNTLED_EMPLOYEE = "Disgruntled Employee"
    PRIVILEGED_USER = "Privileged User"
    THIRD_PARTY = "Third Party"
    OTHER = "Other"


class Motivation(str, Enum):
    """Threat actor motivation enum."""
    FINANCIAL = "Financial"
    POLITICAL = "Political"
    ESPIONAGE = "Espionage"
    REPUTATION = "Reputation"
    REVENGE = "Revenge"
    IDEOLOGY = "Ideology"
    CURIOSITY = "Curiosity"
    ACCIDENTAL = "Accidental"
    DISRUPTION = "Disruption"
    OTHER = "Other"


class CapabilityLevel(str, Enum):
    """Threat actor capability level enum."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class ResourceLevel(str, Enum):
    """Threat actor resource level enum."""
    LIMITED = "Limited"
    MODERATE = "Moderate"
    EXTENSIVE = "Extensive"


class ThreatActor(BaseModel):
    """Model for a threat actor."""
    id: str
    type: ThreatActorType
    name: str
    capability_level: CapabilityLevel
    motivations: List[Motivation]
    resources: ResourceLevel
    description: Optional[str] = None
    priority: int = 0  # 1-10 ranking, 0 means not ranked
    relevance_score: float = 0.0  # 0.0-1.0 probability
    is_relevant: bool = True  # Whether this threat actor is relevant to the system
    
    @field_validator('type', mode='before')
    @classmethod
    def validate_type(cls, v):
        return validate_enum_with_enhanced_error(v, ThreatActorType, 'type')
    
    @field_validator('capability_level', mode='before')
    @classmethod
    def validate_capability_level(cls, v):
        return validate_enum_with_enhanced_error(v, CapabilityLevel, 'capability_level')
    
    @field_validator('motivations', mode='before')
    @classmethod
    def validate_motivations(cls, v):
        if isinstance(v, list):
            return [validate_enum_with_enhanced_error(item, Motivation, 'motivations') for item in v]
        return v
    
    @field_validator('resources', mode='before')
    @classmethod
    def validate_resources(cls, v):
        return validate_enum_with_enhanced_error(v, ResourceLevel, 'resources')


class ThreatActorLibrary(BaseModel):
    """Model for the threat actor library."""
    actors: Dict[str, ThreatActor] = {}
    
    def get_default_actors(self) -> Dict[str, ThreatActor]:
        """Get a set of default threat actors.
        
        Returns:
            A dictionary of default threat actors
        """
        default_actors = {}
        
        # Insider threat actor
        insider = ThreatActor(
            id="TA001",
            type=ThreatActorType.INSIDER,
            name="Insider",
            capability_level=CapabilityLevel.MEDIUM,
            motivations=[Motivation.FINANCIAL, Motivation.REVENGE],
            resources=ResourceLevel.LIMITED,
            description="An employee or contractor with legitimate access to the system",
            priority=5,
            relevance_score=0.7,
            is_relevant=True
        )
        default_actors[insider.id] = insider
        
        # External attacker
        external = ThreatActor(
            id="TA002",
            type=ThreatActorType.EXTERNAL,
            name="External Attacker",
            capability_level=CapabilityLevel.MEDIUM,
            motivations=[Motivation.FINANCIAL],
            resources=ResourceLevel.MODERATE,
            description="An external individual or group attempting to gain unauthorized access",
            priority=3,
            relevance_score=0.8,
            is_relevant=True
        )
        default_actors[external.id] = external
        
        # Nation-state actor
        nation_state = ThreatActor(
            id="TA003",
            type=ThreatActorType.NATION_STATE,
            name="Nation-state Actor",
            capability_level=CapabilityLevel.HIGH,
            motivations=[Motivation.ESPIONAGE, Motivation.POLITICAL],
            resources=ResourceLevel.EXTENSIVE,
            description="A government-sponsored group with advanced capabilities",
            priority=1,
            relevance_score=0.3,
            is_relevant=True
        )
        default_actors[nation_state.id] = nation_state
        
        # Hacktivist
        hacktivist = ThreatActor(
            id="TA004",
            type=ThreatActorType.HACKTIVIST,
            name="Hacktivist",
            capability_level=CapabilityLevel.MEDIUM,
            motivations=[Motivation.IDEOLOGY, Motivation.POLITICAL],
            resources=ResourceLevel.MODERATE,
            description="An individual or group motivated by ideological or political beliefs",
            priority=6,
            relevance_score=0.5,
            is_relevant=True
        )
        default_actors[hacktivist.id] = hacktivist
        
        # Organized crime
        organized_crime = ThreatActor(
            id="TA005",
            type=ThreatActorType.ORGANIZED_CRIME,
            name="Organized Crime",
            capability_level=CapabilityLevel.HIGH,
            motivations=[Motivation.FINANCIAL],
            resources=ResourceLevel.EXTENSIVE,
            description="A criminal organization with significant resources",
            priority=2,
            relevance_score=0.6,
            is_relevant=True
        )
        default_actors[organized_crime.id] = organized_crime
        
        # Competitor
        competitor = ThreatActor(
            id="TA006",
            type=ThreatActorType.COMPETITOR,
            name="Competitor",
            capability_level=CapabilityLevel.MEDIUM,
            motivations=[Motivation.FINANCIAL, Motivation.ESPIONAGE],
            resources=ResourceLevel.MODERATE,
            description="A business competitor seeking competitive advantage",
            priority=7,
            relevance_score=0.4,
            is_relevant=True
        )
        default_actors[competitor.id] = competitor
        
        # Script kiddie
        script_kiddie = ThreatActor(
            id="TA007",
            type=ThreatActorType.SCRIPT_KIDDIE,
            name="Script Kiddie",
            capability_level=CapabilityLevel.LOW,
            motivations=[Motivation.CURIOSITY, Motivation.REPUTATION],
            resources=ResourceLevel.LIMITED,
            description="An inexperienced attacker using pre-made tools",
            priority=9,
            relevance_score=0.7,
            is_relevant=True
        )
        default_actors[script_kiddie.id] = script_kiddie
        
        # Disgruntled employee
        disgruntled_employee = ThreatActor(
            id="TA008",
            type=ThreatActorType.DISGRUNTLED_EMPLOYEE,
            name="Disgruntled Employee",
            capability_level=CapabilityLevel.MEDIUM,
            motivations=[Motivation.REVENGE],
            resources=ResourceLevel.LIMITED,
            description="A current or former employee with a grievance",
            priority=4,
            relevance_score=0.5,
            is_relevant=True
        )
        default_actors[disgruntled_employee.id] = disgruntled_employee
        
        # Privileged user
        privileged_user = ThreatActor(
            id="TA009",
            type=ThreatActorType.PRIVILEGED_USER,
            name="Privileged User",
            capability_level=CapabilityLevel.HIGH,
            motivations=[Motivation.FINANCIAL, Motivation.ACCIDENTAL],
            resources=ResourceLevel.MODERATE,
            description="A user with elevated privileges who may abuse them or make mistakes",
            priority=8,
            relevance_score=0.6,
            is_relevant=True
        )
        default_actors[privileged_user.id] = privileged_user
        
        # Third party
        third_party = ThreatActor(
            id="TA010",
            type=ThreatActorType.THIRD_PARTY,
            name="Third Party",
            capability_level=CapabilityLevel.MEDIUM,
            motivations=[Motivation.FINANCIAL, Motivation.ACCIDENTAL],
            resources=ResourceLevel.MODERATE,
            description="A vendor, partner, or service provider with access to the system",
            priority=10,
            relevance_score=0.5,
            is_relevant=True
        )
        default_actors[third_party.id] = third_party
        
        return default_actors
