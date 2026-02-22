"""Severity and confidence scoring engine."""

from __future__ import annotations

from typing import Any, Dict, List

Finding = Dict[str, Any]

# CVSS-like scoring weights
_SEVERITY_SCORES = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.5,
}

_CONFIDENCE_MULTIPLIER = {
    "high": 1.0,
    "medium": 0.7,
    "low": 0.4,
}

# Higher exploitability for certain vuln types
_EXPLOITABILITY_BOOST = {
    "xss_reflected": 1.3,
    "sqli_error_based": 1.5,
    "hardcoded_secret": 1.4,
    "cors_wildcard_with_credentials": 1.3,
    "session_cookie_exposed": 1.2,
    "vulnerable_dependency": 1.1,
    "no_https": 1.1,
    "missing_header": 0.9,
    "debug_artifact": 1.0,
    "sensitive_endpoint": 1.1,
}


def compute_severity_scores(findings: List[Finding]) -> List[Finding]:
    """Compute a numeric risk score for each finding and attach it.

    The score combines:
    - Base severity score
    - Confidence multiplier
    - Exploitability factor (vuln-type specific)
    """
    scored = []
    for f in findings:
        severity = f.get("severity", "info").lower()
        confidence = f.get("confidence", "medium").lower()
        vuln_type = f.get("vuln_type", "")

        base = _SEVERITY_SCORES.get(severity, 1.0)
        conf_mult = _CONFIDENCE_MULTIPLIER.get(confidence, 0.7)
        exploit_mult = _EXPLOITABILITY_BOOST.get(vuln_type, 1.0)

        risk_score = round(min(10.0, base * conf_mult * exploit_mult), 2)

        f["risk_score"] = risk_score

        # If we don't have a CVSS score, assign one from our scoring
        if not f.get("cvss_score"):
            f["cvss_score"] = risk_score

        scored.append(f)

    # Sort by risk score descending
    scored.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
    return scored
