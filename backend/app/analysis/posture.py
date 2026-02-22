"""Security posture classification based on aggregated findings."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from app.models.scan import PostureRating

Finding = Dict[str, Any]


def classify_posture(findings: List[Finding]) -> Tuple[float, PostureRating]:
    """Classify overall security posture from a list of scored findings.

    Returns:
        (risk_score, PostureRating) — overall score 0-10 and classification.
    """
    if not findings:
        return 0.0, PostureRating.LOW_RISK

    # Count by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Weighted score calculation
    weighted_score = (
        severity_counts["critical"] * 10.0
        + severity_counts["high"] * 7.0
        + severity_counts["medium"] * 4.0
        + severity_counts["low"] * 1.5
        + severity_counts["info"] * 0.3
    )

    # Normalise to 0-10 scale
    # Use a logarithmic-ish scale so scores don't blow up with many info findings
    total_findings = len(findings)
    if total_findings == 0:
        risk_score = 0.0
    else:
        # Raw per-finding score
        avg = weighted_score / total_findings
        # Boost for volume — more findings = higher risk
        volume_factor = min(2.0, 1.0 + (total_findings / 100))
        risk_score = min(10.0, round(avg * volume_factor, 1))

    # Override: if even one critical exists, floor is 7.0
    if severity_counts["critical"] > 0:
        risk_score = max(risk_score, 7.0)

    # Override: if any high exists, floor is 4.0
    if severity_counts["high"] > 0:
        risk_score = max(risk_score, 4.0)

    # Classification
    if risk_score >= 8.0 or severity_counts["critical"] >= 2:
        posture = PostureRating.CRITICAL_RISK
    elif risk_score >= 5.5 or severity_counts["critical"] >= 1 or severity_counts["high"] >= 3:
        posture = PostureRating.HIGH_RISK
    elif risk_score >= 3.0 or severity_counts["high"] >= 1 or severity_counts["medium"] >= 3:
        posture = PostureRating.MODERATE_RISK
    else:
        posture = PostureRating.LOW_RISK

    return risk_score, posture
