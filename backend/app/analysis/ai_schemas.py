"""Structured AI input/output schemas for Gemini integration."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional

from pydantic import BaseModel


class AIFindingSummary(BaseModel):
    """Condensed finding for AI input (not raw data)."""
    title: str
    severity: str
    confidence: str
    vuln_type: str
    location: Optional[str] = None
    remediation: Optional[str] = None


class RepoContextForAI(BaseModel):
    """Optional repo context when scanning GitHub repos."""
    tech_stack: List[str] = []
    primary_language: Optional[str] = None
    complexity: str = "unknown"
    has_ci: bool = False
    has_docker: bool = False
    description: Optional[str] = None


class AIScanInput(BaseModel):
    """Structured input sent to Gemini — no raw logs."""
    target: str
    scan_type: str
    risk_score: float
    posture_rating: str
    total_findings: int

    severity_distribution: Dict[str, int]
    confidence_distribution: Dict[str, int]

    top_findings: List[AIFindingSummary]
    detection_sources: List[str]
    security_observations: List[str]

    repo_context: Optional[RepoContextForAI] = None


class AISummaryOutput(BaseModel):
    """Structured output from Gemini."""
    executive_summary: str
    risk_narrative: str
    prioritized_actions: List[str]
    positive_observations: List[str]
    confidence_notes: str
    use_case_advice: str
    generated_at: str
