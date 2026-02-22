"""Risk correlation engine — combines related findings for elevated risk detection."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Set

logger = logging.getLogger(__name__)
Finding = Dict[str, Any]


# ---------------------------------------------------------------------------
# Correlation rules
# ---------------------------------------------------------------------------
# Each rule is (condition_function, new_finding_generator)
# Rules look for patterns across multiple findings and can create
# new synthetic findings or elevate existing ones.

def correlate_findings(findings: List[Finding]) -> List[Finding]:
    """Apply cross-finding correlation rules to detect compound risks.

    Returns the original findings plus any new correlated findings.
    """
    vuln_types: Set[str] = {f.get("vuln_type", "") for f in findings}
    correlated: List[Finding] = list(findings)

    # Rule 1: Missing CSP + Reflected XSS → Elevated XSS Risk
    has_missing_csp = any(
        f.get("vuln_type") == "missing_header" and "content-security-policy" in f.get("title", "").lower()
        for f in findings
    )
    has_xss = any(f.get("vuln_type", "").startswith("xss_") for f in findings)

    if has_missing_csp and has_xss:
        correlated.append({
            "vuln_type": "correlated:elevated_xss_risk",
            "title": "Elevated XSS Risk — Missing CSP with Reflected Input",
            "description": (
                "Cross-Site Scripting was detected AND no Content-Security-Policy header is set. "
                "Without CSP, inline script execution is unrestricted, making XSS exploitation trivial."
            ),
            "severity": "critical",
            "confidence": "high",
            "detection_source": "analysis:correlation",
            "remediation": (
                "Implement a strict Content-Security-Policy that blocks inline scripts. "
                "Fix the reflected XSS vulnerability by encoding user input."
            ),
        })

    # Rule 2: Login endpoint + No rate limiting → Brute Force Risk
    has_login = any(
        any(kw in f.get("location", "").lower() for kw in ["/login", "/auth", "/signin"])
        for f in findings
        if f.get("vuln_type") == "sensitive_endpoint"
    )
    has_no_rate_limit = "no_rate_limiting" in vuln_types or "login_no_rate_limit" in vuln_types

    if has_login and has_no_rate_limit:
        correlated.append({
            "vuln_type": "correlated:brute_force_risk",
            "title": "Brute Force Risk — Login Endpoint Without Rate Limiting",
            "description": (
                "A login/authentication endpoint was discovered AND no rate limiting is in place. "
                "Attackers can attempt credential stuffing or brute force attacks."
            ),
            "severity": "high",
            "confidence": "high",
            "detection_source": "analysis:correlation",
            "remediation": (
                "Implement rate limiting on authentication endpoints (e.g., 5 attempts per minute). "
                "Add account lockout, CAPTCHA, and multi-factor authentication."
            ),
        })

    # Rule 3: Hardcoded secrets + public repo indicators → Critical Exposure
    has_secrets = any(f.get("vuln_type") in ("hardcoded_secret", "high_entropy_secret") for f in findings)
    has_public_indicators = any(
        f.get("vuln_type") == "sensitive_endpoint" and ".git" in f.get("location", "")
        for f in findings
    )

    if has_secrets and has_public_indicators:
        correlated.append({
            "vuln_type": "correlated:credential_exposure",
            "title": "Critical Credential Exposure — Secrets in Accessible Repository",
            "description": (
                "Hardcoded secrets were found AND the .git directory is publicly accessible. "
                "Credentials may be extractable by anyone."
            ),
            "severity": "critical",
            "confidence": "high",
            "detection_source": "analysis:correlation",
            "remediation": (
                "Rotate all exposed credentials immediately. "
                "Remove .git from public access. "
                "Use environment variables or a secrets manager."
            ),
        })

    # Rule 4: Missing HSTS + Cookie without Secure → Session Hijack Risk
    has_missing_hsts = any(f.get("vuln_type") == "missing_hsts" for f in findings)
    has_insecure_cookie = any(f.get("vuln_type") == "cookie_missing_secure" for f in findings)

    if has_missing_hsts and has_insecure_cookie:
        correlated.append({
            "vuln_type": "correlated:session_hijack_risk",
            "title": "Session Hijack Risk — No HSTS and Insecure Cookies",
            "description": (
                "The server does not set HSTS AND cookies are sent over HTTP. "
                "An attacker on the same network can intercept session cookies via SSL stripping."
            ),
            "severity": "high",
            "confidence": "high",
            "detection_source": "analysis:correlation",
            "remediation": (
                "Enable HSTS with a long max-age. "
                "Set the Secure flag on all cookies."
            ),
        })

    # Rule 5: SQL injection + Debug info → Amplified SQLi
    has_sqli = any(f.get("vuln_type", "").startswith("sqli_") for f in findings)
    has_debug_leak = "debug_info_leak" in vuln_types

    if has_sqli and has_debug_leak:
        correlated.append({
            "vuln_type": "correlated:amplified_sqli",
            "title": "Amplified SQL Injection — Debug Information Leakage",
            "description": (
                "SQL injection signals detected AND the server leaks debug/stack trace information. "
                "Error details help attackers craft more effective injection payloads."
            ),
            "severity": "critical",
            "confidence": "high",
            "detection_source": "analysis:correlation",
            "remediation": (
                "Fix SQL injection by using parameterized queries. "
                "Disable debug mode and use custom error pages."
            ),
        })

    # Rule 6: CORS misconfiguration + Sensitive cookies → Cross-site Data Theft
    has_cors_issue = any(
        f.get("vuln_type", "").startswith("cors_") and f.get("severity") in ("high", "critical")
        for f in findings
    )
    has_sensitive_cookies = any(
        f.get("vuln_type") in ("session_cookie_exposed", "cookie_missing_httponly")
        for f in findings
    )

    if has_cors_issue and has_sensitive_cookies:
        correlated.append({
            "vuln_type": "correlated:cross_site_data_theft",
            "title": "Cross-Site Data Theft Risk — CORS Misconfiguration + Exposed Cookies",
            "description": (
                "CORS policy allows untrusted origins AND session cookies lack proper protection. "
                "Malicious websites can make authenticated requests and steal data."
            ),
            "severity": "critical",
            "confidence": "high",
            "detection_source": "analysis:correlation",
            "remediation": (
                "Restrict CORS to trusted origins only. "
                "Set HttpOnly and SameSite flags on session cookies."
            ),
        })

    # Rule 7: Vulnerable dependencies + Running in debug → Amplified Risk
    has_vuln_deps = any(f.get("vuln_type") == "vulnerable_dependency" for f in findings)
    has_debug = any(f.get("vuln_type") == "debug_artifact" for f in findings)

    if has_vuln_deps and has_debug:
        correlated.append({
            "vuln_type": "correlated:exploitable_dependencies",
            "title": "Exploitable Dependencies — Vulnerable Libraries in Debug Mode",
            "description": (
                "Known vulnerable dependencies detected AND the application runs in debug mode. "
                "Debug mode can make dependency vulnerabilities easier to exploit."
            ),
            "severity": "high",
            "confidence": "medium",
            "detection_source": "analysis:correlation",
            "remediation": (
                "Update vulnerable dependencies. "
                "Disable debug mode in production."
            ),
        })

    new_count = len(correlated) - len(findings)
    if new_count > 0:
        logger.info(f"Correlation engine produced {new_count} new findings")

    return correlated
