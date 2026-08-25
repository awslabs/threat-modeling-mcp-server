"""Threat Actor models for the Threat Modeling MCP Server."""

from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, field_validator
from threat_modeling_mcp_server.validation.enum_validator import validate_enum_with_enhanced_error


class ThreatActorType(str, Enum):
    """Threat actor category."""
    NATION_STATE = "Nation-State / APT"
    ORGANIZED_CRIME = "Financially Motivated Cybercriminal / Organized Crime"
    HACKTIVIST = "Hacktivist"
    INSIDER = "Insider Threat"
    TERRORIST = "Terrorist Organization"
    PSOA = "Private Sector Offensive Actor / Cyber Mercenary"
    SCRIPT_KIDDIE = "Script Kiddie / Novice"
    COMPETITOR = "Competitor / Corporate Espionage"
    EXTERNAL = "External Attacker"
    DISGRUNTLED_EMPLOYEE = "Disgruntled Employee"
    PRIVILEGED_USER = "Privileged User"
    THIRD_PARTY = "Third Party"
    OTHER = "Other"


class Motivation(str, Enum):
    """Threat actor motivation; multiple values may apply."""
    FINANCIAL_GAIN = "Financial gain"
    ESPIONAGE = "Espionage / intelligence collection"
    IDEOLOGICAL = "Ideological / hacktivism"
    DISRUPTION = "Disruption / destruction"
    COMPETITIVE_ADVANTAGE = "Competitive advantage"
    THRILL_SEEKING = "Thrill-seeking / notoriety"
    REVENGE = "Revenge / grievance"


class RelationshipToTarget(str, Enum):
    """Whether the actor is internal, external, or a third party."""
    EXTERNAL = "External"
    INTERNAL = "Internal"
    PARTNER = "Partner / third-party"


class SophisticationTier(str, Enum):
    """Threat actor capability tier, ordered from opportunistic to elite."""
    TIER_1_OPPORTUNISTIC = "Tier 1 - Opportunistic / script kiddie"
    TIER_2_CAMPAIGN_DRIVEN = "Tier 2 - Hacktivist / campaign-driven"
    TIER_3_ORGANIZED_CRIME = "Tier 3 - Organized cybercrime"
    TIER_4_STATE_NEXUS = "Tier 4 - State-nexus / advanced"
    TIER_5_ELITE_APT = "Tier 5 - Nation-state APT / elite"


class ResourceLevel(str, Enum):
    """Resources available to the threat actor using the STIX 2.1 vocabulary."""
    INDIVIDUAL = "Individual"
    CLUB = "Club / small group"
    CONTEST = "Contest / crowd"
    TEAM = "Team"
    ORGANIZATION = "Organization"
    GOVERNMENT = "Government"


class StateNexus(str, Enum):
    """The actor's connection to state authority."""
    NONE = "None"
    STATE_ALIGNED = "State-aligned"
    STATE_SPONSORED = "State-sponsored"
    STATE_EXECUTED = "State-executed"


class TargetingSpecificity(str, Enum):
    """How the actor selects targets."""
    OPPORTUNISTIC = "Opportunistic"
    SECTOR_FOCUSED = "Sector-focused"
    TARGETED = "Targeted"


class ThreatActor(BaseModel):
    """Model for a threat actor."""
    id: str
    type: ThreatActorType
    name: str
    sophistication_tier: SophisticationTier
    motivations: List[Motivation]
    resources: ResourceLevel
    description: Optional[str] = None
    priority: int = 0  # 1-10 ranking, 0 means not ranked
    is_relevant: bool = True  # Whether this threat actor is relevant to the system

    # Whether this actor has been assessed for THIS system, as opposed to merely
    # being present because the default library was pre-loaded. `is_relevant`
    # cannot answer that: it defaults to True, so an untouched default actor and
    # one deliberately judged relevant look identical. Phase 3 completion and the
    # exported report both key off this flag, so a pre-loaded catalogue no longer
    # reads as analysis that was never performed.
    reviewed: bool = False

    # Additional actor classification facets.
    relationship_to_target: Optional[RelationshipToTarget] = None
    state_nexus: Optional[StateNexus] = None
    targeting_specificity: Optional[TargetingSpecificity] = None

    @field_validator('relationship_to_target', mode='before')
    @classmethod
    def validate_relationship_to_target(cls, v):
        return validate_enum_with_enhanced_error(v, RelationshipToTarget, 'relationship_to_target')

    @field_validator('sophistication_tier', mode='before')
    @classmethod
    def validate_sophistication_tier(cls, v):
        return validate_enum_with_enhanced_error(v, SophisticationTier, 'sophistication_tier')

    @field_validator('state_nexus', mode='before')
    @classmethod
    def validate_state_nexus(cls, v):
        return validate_enum_with_enhanced_error(v, StateNexus, 'state_nexus')

    @field_validator('targeting_specificity', mode='before')
    @classmethod
    def validate_targeting_specificity(cls, v):
        return validate_enum_with_enhanced_error(v, TargetingSpecificity, 'targeting_specificity')

    @field_validator('type', mode='before')
    @classmethod
    def validate_type(cls, v):
        return validate_enum_with_enhanced_error(v, ThreatActorType, 'type')

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

        Covers twelve of the thirteen taxonomy actor types. OTHER is omitted
        on purpose: it is a fallback for unclassifiable actors, not a default.

        Returns:
            A dictionary of default threat actors
        """
        specs = [
            # (id, type, name, motivations, resources, relationship,
            #  sophistication, state_nexus, targeting, priority,
            #  description)
            (
                "TA001", ThreatActorType.INSIDER, "Insider",
                [Motivation.FINANCIAL_GAIN, Motivation.REVENGE],
                ResourceLevel.INDIVIDUAL,
                RelationshipToTarget.INTERNAL,
                SophisticationTier.TIER_2_CAMPAIGN_DRIVEN,
                StateNexus.NONE, TargetingSpecificity.TARGETED,
                5,
                "An employee or contractor with legitimate access to the system",
            ),
            (
                "TA002", ThreatActorType.EXTERNAL, "External Attacker",
                [Motivation.FINANCIAL_GAIN],
                ResourceLevel.CLUB,
                RelationshipToTarget.EXTERNAL,
                SophisticationTier.TIER_1_OPPORTUNISTIC,
                StateNexus.NONE, TargetingSpecificity.OPPORTUNISTIC,
                3,
                "An external individual or group attempting to gain unauthorized access",
            ),
            (
                "TA003", ThreatActorType.NATION_STATE, "Nation-state Actor",
                [Motivation.ESPIONAGE],
                ResourceLevel.GOVERNMENT,
                RelationshipToTarget.EXTERNAL,
                SophisticationTier.TIER_5_ELITE_APT,
                StateNexus.STATE_EXECUTED, TargetingSpecificity.TARGETED,
                1,
                "A state intelligence or military group operating with advanced capabilities",
            ),
            (
                "TA004", ThreatActorType.HACKTIVIST, "Hacktivist",
                [Motivation.IDEOLOGICAL],
                ResourceLevel.CONTEST,
                RelationshipToTarget.EXTERNAL,
                SophisticationTier.TIER_2_CAMPAIGN_DRIVEN,
                StateNexus.NONE, TargetingSpecificity.SECTOR_FOCUSED,
                6,
                "An individual or group motivated by ideological or political beliefs",
            ),
            (
                "TA005", ThreatActorType.ORGANIZED_CRIME, "Organized Crime",
                [Motivation.FINANCIAL_GAIN],
                ResourceLevel.ORGANIZATION,
                RelationshipToTarget.EXTERNAL,
                SophisticationTier.TIER_3_ORGANIZED_CRIME,
                StateNexus.NONE, TargetingSpecificity.OPPORTUNISTIC,
                2,
                "A criminal organization with significant resources",
            ),
            (
                "TA006", ThreatActorType.COMPETITOR, "Competitor",
                [Motivation.COMPETITIVE_ADVANTAGE, Motivation.ESPIONAGE],
                ResourceLevel.ORGANIZATION,
                RelationshipToTarget.EXTERNAL,
                SophisticationTier.TIER_3_ORGANIZED_CRIME,
                StateNexus.NONE, TargetingSpecificity.TARGETED,
                7,
                "A business competitor seeking competitive advantage",
            ),
            (
                "TA007", ThreatActorType.SCRIPT_KIDDIE, "Script Kiddie",
                [Motivation.THRILL_SEEKING],
                ResourceLevel.INDIVIDUAL,
                RelationshipToTarget.EXTERNAL,
                SophisticationTier.TIER_1_OPPORTUNISTIC,
                StateNexus.NONE, TargetingSpecificity.OPPORTUNISTIC,
                9,
                "An inexperienced attacker using pre-made tools",
            ),
            (
                "TA008", ThreatActorType.DISGRUNTLED_EMPLOYEE, "Disgruntled Employee",
                [Motivation.REVENGE],
                ResourceLevel.INDIVIDUAL,
                RelationshipToTarget.INTERNAL,
                SophisticationTier.TIER_1_OPPORTUNISTIC,
                StateNexus.NONE, TargetingSpecificity.TARGETED,
                4,
                "A current or former employee with a grievance",
            ),
            (
                "TA009", ThreatActorType.PRIVILEGED_USER, "Privileged User",
                [Motivation.FINANCIAL_GAIN],
                ResourceLevel.INDIVIDUAL,
                RelationshipToTarget.INTERNAL,
                SophisticationTier.TIER_2_CAMPAIGN_DRIVEN,
                StateNexus.NONE, TargetingSpecificity.TARGETED,
                8,
                "A user with elevated privileges who may abuse them or make mistakes",
            ),
            (
                "TA010", ThreatActorType.THIRD_PARTY, "Third Party",
                [Motivation.FINANCIAL_GAIN],
                ResourceLevel.ORGANIZATION,
                RelationshipToTarget.PARTNER,
                SophisticationTier.TIER_2_CAMPAIGN_DRIVEN,
                StateNexus.NONE, TargetingSpecificity.OPPORTUNISTIC,
                10,
                "A vendor, partner, or service provider with access to the system",
            ),
            (
                "TA011", ThreatActorType.TERRORIST, "Terrorist Organization",
                [Motivation.IDEOLOGICAL, Motivation.DISRUPTION],
                ResourceLevel.CLUB,
                RelationshipToTarget.EXTERNAL,
                SophisticationTier.TIER_2_CAMPAIGN_DRIVEN,
                StateNexus.NONE, TargetingSpecificity.SECTOR_FOCUSED,
                0,
                "A group with limited offensive cyber capability, primarily using the "
                "internet for propaganda and recruitment",
            ),
            (
                "TA012", ThreatActorType.PSOA, "Private Sector Offensive Actor",
                [Motivation.FINANCIAL_GAIN],
                ResourceLevel.ORGANIZATION,
                RelationshipToTarget.EXTERNAL,
                SophisticationTier.TIER_4_STATE_NEXUS,
                StateNexus.STATE_ALIGNED, TargetingSpecificity.TARGETED,
                0,
                "A commercial vendor developing zero-day exploits and spyware for "
                "client-selected targets",
            ),
        ]

        default_actors: Dict[str, ThreatActor] = {}
        for (
            actor_id, actor_type, name, motivations, resources, relationship,
            sophistication, state_nexus, targeting, priority,
            description,
        ) in specs:
            actor = ThreatActor(
                id=actor_id,
                type=actor_type,
                name=name,
                sophistication_tier=sophistication,
                motivations=motivations,
                resources=resources,
                description=description,
                priority=priority,
                is_relevant=True,
                relationship_to_target=relationship,
                state_nexus=state_nexus,
                targeting_specificity=targeting,
            )
            default_actors[actor.id] = actor

        return default_actors
