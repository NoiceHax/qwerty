"""Security headers analysis module."""

from __future__ import annotations

import logging
from typing import Any, Dict, List

import httpx

logger = logging.getLogger(__name__)
Finding = Dict[str, Any]

# Expected security headers and their ideal values / checks
_HEADER_CHECKS = {
    "content-security-policy": {
        "title": "Content-Security-Policy",
        "severity": "medium",
        "remediation": "Add a Content-Security-Policy header to prevent XSS and data injection. Start with: Content-Security-Policy: default-src 'self'",
        "weak_patterns": ["unsafe-inline", "unsafe-eval", "*"],
    },
    "x-frame-options": {
        "title": "X-Frame-Options",
        "severity": "medium",
        "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.",
        "weak_patterns": ["ALLOWALL"],
    },
    "x-content-type-options": {
        "title": "X-Content-Type-Options",
        "severity": "low",
        "remediation": "Add X-Content-Type-Options: nosniff to prevent MIME-type sniffing.",
        "expected": "nosniff",
    },
    "referrer-policy": {
        "title": "Referrer-Policy",
        "severity": "low",
        "remediation": "Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer.",
        "weak_patterns": ["unsafe-url"],
    },
    "permissions-policy": {
        "title": "Permissions-Policy",
        "severity": "low",
        "remediation": "Add a Permissions-Policy header to restrict browser features (camera, microphone, geolocation).",
    },
    "x-xss-protection": {
        "title": "X-XSS-Protection",
        "severity": "info",
        "remediation": "While deprecated in modern browsers, X-XSS-Protection: 0 is recommended (CSP is the replacement). Setting to 1; mode=block can introduce vulnerabilities.",
    },
}


class HeaderAnalyzer:
    """Checks for missing or weak security headers."""

    async def analyze(self, response: httpx.Response) -> List[Finding]:
        findings: List[Finding] = []
        headers = response.headers

        for header_name, config in _HEADER_CHECKS.items():
            value = headers.get(header_name)

            if not value:
                # Header missing
                findings.append({
                    "vuln_type": "missing_header",
                    "title": f"Missing {config['title']} header",
                    "description": f"The response does not include a {config['title']} header.",
                    "severity": config["severity"],
                    "confidence": "high",
                    "detection_source": "dynamic:header_analyzer",
                    "remediation": config["remediation"],
                    "location": str(response.url),
                    "evidence": f"Response headers: {dict(headers)}",
                })
            else:
                # Check for weak configurations
                weak = config.get("weak_patterns", [])
                for pat in weak:
                    if pat.lower() in value.lower():
                        findings.append({
                            "vuln_type": "weak_header",
                            "title": f"Weak {config['title']} configuration",
                            "description": f"{config['title']} contains '{pat}' which weakens the protection.",
                            "severity": config["severity"],
                            "confidence": "high",
                            "detection_source": "dynamic:header_analyzer",
                            "remediation": config["remediation"],
                            "location": str(response.url),
                            "evidence": f"{header_name}: {value}",
                        })
                        break

                # Check expected value
                expected = config.get("expected")
                if expected and value.lower().strip() != expected.lower():
                    findings.append({
                        "vuln_type": "misconfigured_header",
                        "title": f"Misconfigured {config['title']}",
                        "description": f"Expected '{expected}' but found '{value}'.",
                        "severity": config["severity"],
                        "confidence": "high",
                        "detection_source": "dynamic:header_analyzer",
                        "remediation": config["remediation"],
                        "location": str(response.url),
                        "evidence": f"{header_name}: {value}",
                    })

        # Server information disclosure
        server = headers.get("server")
        if server:
            findings.append({
                "vuln_type": "server_info_disclosure",
                "title": "Server header reveals software version",
                "description": f"Server header: {server}",
                "severity": "info",
                "confidence": "high",
                "detection_source": "dynamic:header_analyzer",
                "remediation": "Remove or obfuscate the Server header to avoid revealing tech stack details.",
                "location": str(response.url),
                "evidence": f"server: {server}",
            })

        x_powered = headers.get("x-powered-by")
        if x_powered:
            findings.append({
                "vuln_type": "tech_disclosure",
                "title": "X-Powered-By header reveals technology",
                "description": f"X-Powered-By: {x_powered}",
                "severity": "low",
                "confidence": "high",
                "detection_source": "dynamic:header_analyzer",
                "remediation": "Remove the X-Powered-By header.",
                "location": str(response.url),
                "evidence": f"x-powered-by: {x_powered}",
            })

        return findings
