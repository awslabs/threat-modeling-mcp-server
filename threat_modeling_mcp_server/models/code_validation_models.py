"""Models for evidence-based code validation findings."""

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ThreatValidationOutcome(str, Enum):
    """Code-validation outcomes for threats."""

    FULLY_MITIGATED = "fully_mitigated"
    PARTIALLY_MITIGATED = "partially_mitigated"
    NOT_MITIGATED = "not_mitigated"
    NOT_APPLICABLE = "not_applicable"


class MitigationValidationOutcome(str, Enum):
    """Code-validation outcomes for mitigations."""

    IMPLEMENTED = "implemented"
    PARTIALLY_IMPLEMENTED = "partially_implemented"
    NOT_IMPLEMENTED = "not_implemented"
    NOT_APPLICABLE = "not_applicable"


class _EvidenceFinding(BaseModel):
    """Shared evidence fields for one validation finding."""

    model_config = ConfigDict(extra="forbid")

    evidence: List[str] = Field(min_length=1)
    recommendation: Optional[str] = None

    @field_validator("evidence")
    @classmethod
    def validate_evidence(cls, values: List[str]) -> List[str]:
        """Require concrete, non-empty evidence entries."""
        cleaned = [value.strip() for value in values]
        if any(not value for value in cleaned):
            raise ValueError("evidence entries must not be blank")
        return cleaned

    @field_validator("recommendation")
    @classmethod
    def normalize_recommendation(cls, value: Optional[str]) -> Optional[str]:
        """Treat an empty recommendation as absent."""
        if value is None:
            return None
        return value.strip() or None


class ThreatCodeFinding(_EvidenceFinding):
    """Evidence and outcome for one threat."""

    threat_id: str = Field(min_length=1)
    outcome: ThreatValidationOutcome


class MitigationCodeFinding(_EvidenceFinding):
    """Evidence and outcome for one mitigation."""

    mitigation_id: str = Field(min_length=1)
    outcome: MitigationValidationOutcome
