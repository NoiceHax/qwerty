"""Cookie security analysis module."""

from __future__ import annotations

import logging
from typing import Any, Dict, List

import httpx

logger = logging.getLogger(__name__)
Finding = Dict[str, Any]


class CookieAnalyzer:
    """Evaluates the security attributes of response cookies."""

    async def analyze(self, response: httpx.Response) -> List[Finding]:
        findings: List[Finding] = []
        cookies = response.cookies

        if not cookies:
            return findings

        for name in cookies:
            cookie_header = self._find_raw_set_cookie(response, name)

            # HttpOnly
            if cookie_header and "httponly" not in cookie_header.lower():
                findings.append(self._finding(
                    "cookie_missing_httponly",
                    f"Cookie '{name}' missing HttpOnly flag",
                    f"Cookie '{name}' does not have the HttpOnly flag, making it accessible via JavaScript.",
                    severity="medium",
                    remediation=f"Set HttpOnly flag on cookie '{name}' to prevent client-side script access.",
                    evidence=cookie_header,
                    location=str(response.url),
                ))

            # Secure
            if cookie_header and "secure" not in cookie_header.lower():
                findings.append(self._finding(
                    "cookie_missing_secure",
                    f"Cookie '{name}' missing Secure flag",
                    f"Cookie '{name}' does not have the Secure flag, allowing transmission over HTTP.",
                    severity="medium",
                    remediation=f"Set Secure flag on cookie '{name}' to ensure HTTPS-only transmission.",
                    evidence=cookie_header,
                    location=str(response.url),
                ))

            # SameSite
            if cookie_header and "samesite" not in cookie_header.lower():
                findings.append(self._finding(
                    "cookie_missing_samesite",
                    f"Cookie '{name}' missing SameSite attribute",
                    f"Cookie '{name}' does not set SameSite, leaving it vulnerable to CSRF.",
                    severity="medium",
                    remediation=f"Set SameSite=Lax or SameSite=Strict on cookie '{name}'.",
                    evidence=cookie_header,
                    location=str(response.url),
                ))
            elif cookie_header and "samesite=none" in cookie_header.lower():
                findings.append(self._finding(
                    "cookie_samesite_none",
                    f"Cookie '{name}' uses SameSite=None",
                    f"Cookie '{name}' is sent on all cross-site requests. Ensure Secure flag is also set.",
                    severity="low",
                    remediation=f"Use SameSite=Lax or Strict unless cross-site cookie delivery is required.",
                    evidence=cookie_header,
                    location=str(response.url),
                ))

            # Session-looking cookies with weak flags
            if any(kw in name.lower() for kw in ("session", "sid", "token", "auth", "jwt")):
                if cookie_header and "httponly" not in cookie_header.lower():
                    findings.append(self._finding(
                        "session_cookie_exposed",
                        f"Session cookie '{name}' is accessible to JavaScript",
                        "Session or authentication cookies should always have HttpOnly set.",
                        severity="high",
                        remediation=f"Set HttpOnly and Secure flags on session cookie '{name}'.",
                        evidence=cookie_header,
                        location=str(response.url),
                    ))

        return findings

    @staticmethod
    def _find_raw_set_cookie(response: httpx.Response, cookie_name: str) -> str | None:
        """Find the raw Set-Cookie header for a given cookie name."""
        for header_val in response.headers.get_list("set-cookie"):
            if header_val.lower().startswith(cookie_name.lower() + "="):
                return header_val
        return None

    @staticmethod
    def _finding(vuln_type: str, title: str, description: str,
                 severity: str = "info", confidence: str = "high",
                 remediation: str = "", evidence: str = "",
                 location: str = "") -> Finding:
        return {
            "vuln_type": vuln_type,
            "title": title,
            "description": description,
            "severity": severity,
            "confidence": confidence,
            "detection_source": "dynamic:cookie_analyzer",
            "remediation": remediation,
            "evidence": evidence,
            "location": location,
        }
