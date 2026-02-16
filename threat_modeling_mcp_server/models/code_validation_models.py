"""Code Validation Models for the Threat Modeling MCP Server.

This module defines models for code security validation and remediation status tracking.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel


class RemediationStatus(str, Enum):
    """Remediation status enum."""
    NOT_REMEDIATED = "Not Remediated"
    PARTIALLY_REMEDIATED = "Partially Remediated"
    FULLY_REMEDIATED = "Fully Remediated"


class SecurityControlDetection(BaseModel):
    """Model for a detected security control in code."""
    control_type: str
    file_path: str
    line_number: int
    matched_pattern: str
    context: str
    language: str


class SecurityControl(BaseModel):
    """Model for a security control."""
    id: str
    name: str
    description: str
    control_type: str
    applicable_threats: List[str]
    implementation_guidance: str


class CodeValidationResult(BaseModel):
    """Model for code validation results."""
    detected_controls: Dict[str, List[Dict[str, Any]]]
    threat_remediation_status: Dict[str, RemediationStatus]
    summary: str


class RemediationReport(BaseModel):
    """Model for a comprehensive remediation report."""
    fully_remediated_threats: List[str]
    partially_remediated_threats: List[str]
    unremediated_threats: List[str]
    detected_controls_summary: Dict[str, int]
    recommendations: List[str]
    overall_security_score: float  # 0.0 to 1.0