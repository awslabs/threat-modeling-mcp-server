"""Flat non-functional requirement models based on ISO/IEC 25010:2023.

Each requirement selects one quality class and one accepted target level.
Security and functional suitability are outside this profile.
"""

from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, field_validator, model_validator

from threat_modeling_mcp_server.validation.enum_validator import (
    validate_enum_with_enhanced_error,
)


class QualityClass(str, Enum):
    """A non-functional quality requirement that can be configured."""
    TIME_BEHAVIOUR = "Time Behaviour"
    RESOURCE_UTILIZATION = "Resource Utilization"
    CAPACITY = "Capacity"
    AVAILABILITY = "Availability"
    RECOVERABILITY = "Recoverability"
    FAULT_TOLERANCE = "Fault Tolerance"
    FAULTLESSNESS = "Faultlessness"
    ACCESSIBILITY = "Accessibility / Inclusivity"
    OPERABILITY = "Operability"
    USER_ERROR_PROTECTION = "User Error Protection"
    SCALABILITY = "Scalability"
    ADAPTABILITY = "Adaptability"
    INSTALLABILITY = "Installability"
    REPLACEABILITY = "Replaceability"
    INTEROPERABILITY = "Interoperability"
    CO_EXISTENCE = "Co-existence"
    MODULARITY = "Modularity"
    TESTABILITY = "Testability"
    ANALYSABILITY = "Analysability"
    SAFETY_CRITICALITY = "Safety Criticality"
    FAIL_SAFE_BEHAVIOUR = "Fail-Safe Behaviour"


# Allowed levels per class, ordered least to most demanding.
CLASS_LEVELS: Dict[QualityClass, List[str]] = {
    QualityClass.TIME_BEHAVIOUR: ["Best-effort", "Standard", "Responsive", "Real-time"],
    QualityClass.RESOURCE_UTILIZATION: ["Unconstrained", "Moderate", "Constrained"],
    QualityClass.CAPACITY: ["Small", "Medium", "Large", "Massive"],
    QualityClass.AVAILABILITY: ["99%", "99.9%", "99.99%", "99.999%"],
    QualityClass.RECOVERABILITY: ["Best-effort", "Hours", "Minutes", "Near-zero"],
    QualityClass.FAULT_TOLERANCE: ["None", "Partial", "Full"],
    QualityClass.FAULTLESSNESS: ["Low", "Medium", "High"],
    QualityClass.ACCESSIBILITY: [
        "None specified", "WCAG Level A", "WCAG Level AA", "WCAG Level AAA",
    ],
    QualityClass.OPERABILITY: ["Basic", "Standard", "Enhanced"],
    QualityClass.USER_ERROR_PROTECTION: ["Minimal", "Standard", "Strong"],
    QualityClass.SCALABILITY: ["Fixed", "Vertical", "Horizontal", "Elastic"],
    QualityClass.ADAPTABILITY: [
        "Single environment", "Multiple environments", "Environment-agnostic",
    ],
    QualityClass.INSTALLABILITY: ["Manual", "Scripted", "Automated"],
    QualityClass.REPLACEABILITY: [
        "Vendor-locked", "Partially substitutable", "Fully substitutable",
    ],
    QualityClass.INTEROPERABILITY: ["Standalone", "Point-to-point", "Standards-based"],
    QualityClass.CO_EXISTENCE: ["Isolated", "Shared environment"],
    QualityClass.MODULARITY: ["Low", "Medium", "High"],
    QualityClass.TESTABILITY: ["Low", "Medium", "High"],
    QualityClass.ANALYSABILITY: ["Low", "Medium", "High"],
    QualityClass.SAFETY_CRITICALITY: [
        "Non-safety-related", "Safety-related", "Safety-critical",
    ],
    QualityClass.FAIL_SAFE_BEHAVIOUR: [
        "Not required", "Graceful degradation", "Revert to safe state",
    ],
}


class NonFunctionalRequirement(BaseModel):
    """A single quality class and its required level."""
    quality_class: QualityClass
    level: str
    rationale: Optional[str] = None

    @field_validator('quality_class', mode='before')
    @classmethod
    def validate_quality_class(cls, v):
        return validate_enum_with_enhanced_error(v, QualityClass, 'quality_class')

    @model_validator(mode='after')
    def validate_level(self):
        """Check that the level is valid for the selected quality class."""
        allowed = CLASS_LEVELS[self.quality_class]
        if self.level not in allowed:
            raise ValueError(
                f"Invalid level '{self.level}' for class "
                f"'{self.quality_class.value}'. Allowed levels: {', '.join(allowed)}"
            )
        return self


class NFRProfile(BaseModel):
    """The set of NFRs inferred for a system.

    Only classes with a signal in the system description are present; anything
    absent is out of scope for that system.
    """
    requirements: List[NonFunctionalRequirement] = []

    @model_validator(mode='after')
    def validate_one_entry_per_class(self):
        """Reject duplicate classes so get_level() has a single answer."""
        seen = [r.quality_class for r in self.requirements]
        duplicates = {c.value for c in seen if seen.count(c) > 1}
        if duplicates:
            raise ValueError(
                "Each quality class may appear at most once in an NFR profile. "
                f"Duplicated: {', '.join(sorted(duplicates))}"
            )
        return self

    def get_level(self, quality_class: QualityClass) -> Optional[str]:
        """Return the assigned level for a class, or None if not in scope."""
        for requirement in self.requirements:
            if requirement.quality_class == quality_class:
                return requirement.level
        return None
