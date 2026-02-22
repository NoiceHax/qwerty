"""CORS misconfiguration detection module."""

from __future__ import annotations

import logging
from typing import Any, Dict, List
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)
Finding = Dict[str, Any]

# Crafted origins to test CORS behaviour
_TEST_ORIGINS = [
    "https://evil-attacker.com",
    "https://null",
    "null",
]


class CORSAnalyzer:
    """Tests CORS policy by sending requests with crafted Origin headers."""

    async def analyze(self, target_url: str, client: httpx.AsyncClient) -> List[Finding]:
        findings: List[Finding] = []

        try:
            # 1. Check base CORS headers
            resp = await client.get(target_url)
            acao = resp.headers.get("access-control-allow-origin")
            acac = resp.headers.get("access-control-allow-credentials")

            # Wildcard origin
            if acao == "*":
                findings.append(self._finding(
                    "cors_wildcard",
                    "CORS allows all origins (wildcard *)",
                    "Access-Control-Allow-Origin is set to *, allowing any website to make requests.",
                    severity="medium",
                    evidence=f"access-control-allow-origin: {acao}",
                    remediation="Restrict Access-Control-Allow-Origin to specific trusted domains.",
                ))

                if acac and acac.lower() == "true":
                    findings.append(self._finding(
                        "cors_wildcard_with_credentials",
                        "CORS wildcard with credentials enabled",
                        "Wildcard origin combined with Access-Control-Allow-Credentials: true is a critical misconfiguration.",
                        severity="critical",
                        evidence=f"ACAO: {acao}, ACAC: {acac}",
                        remediation="Never combine wildcard origin with credentials. Specify exact origins.",
                    ))

            # 2. Test with crafted origins
            for test_origin in _TEST_ORIGINS:
                try:
                    resp = await client.get(
                        target_url,
                        headers={"Origin": test_origin},
                    )
                    reflected_origin = resp.headers.get("access-control-allow-origin", "")
                    creds = resp.headers.get("access-control-allow-credentials", "")

                    if reflected_origin == test_origin:
                        sev = "high" if creds.lower() == "true" else "medium"
                        findings.append(self._finding(
                            "cors_origin_reflection",
                            f"CORS reflects arbitrary origin: {test_origin}",
                            (
                                f"The server reflects the Origin header value '{test_origin}' in "
                                f"Access-Control-Allow-Origin, effectively allowing any site."
                            ),
                            severity=sev,
                            evidence=f"Origin: {test_origin} → ACAO: {reflected_origin}, ACAC: {creds}",
                            remediation="Validate the Origin header against a whitelist of trusted domains.",
                        ))

                    # Null origin accepted
                    if test_origin in ("null", "https://null") and reflected_origin in ("null", test_origin):
                        findings.append(self._finding(
                            "cors_null_origin",
                            "CORS accepts null origin",
                            "The server allows 'null' origin, exploitable via sandboxed iframes.",
                            severity="medium",
                            evidence=f"Origin: {test_origin} → ACAO: {reflected_origin}",
                            remediation="Do not allow 'null' as a valid origin in CORS configuration.",
                        ))

                except httpx.RequestError:
                    continue

            # 3. Preflight check
            try:
                preflight = await client.options(
                    target_url,
                    headers={
                        "Origin": _TEST_ORIGINS[0],
                        "Access-Control-Request-Method": "DELETE",
                        "Access-Control-Request-Headers": "X-Custom-Header",
                    },
                )
                methods = preflight.headers.get("access-control-allow-methods", "")
                if "DELETE" in methods.upper() or "*" in methods:
                    findings.append(self._finding(
                        "cors_dangerous_methods",
                        "CORS allows dangerous HTTP methods",
                        f"Allowed methods: {methods}",
                        severity="medium",
                        evidence=f"Access-Control-Allow-Methods: {methods}",
                        remediation="Restrict CORS allowed methods to only those needed (GET, POST).",
                    ))
            except httpx.RequestError:
                pass

        except httpx.RequestError as exc:
            logger.debug(f"CORS check failed: {exc}")

        return findings

    @staticmethod
    def _finding(vuln_type: str, title: str, description: str,
                 severity: str = "info", confidence: str = "high",
                 remediation: str = "", evidence: str = "") -> Finding:
        return {
            "vuln_type": vuln_type,
            "title": title,
            "description": description,
            "severity": severity,
            "confidence": confidence,
            "detection_source": "dynamic:cors_analyzer",
            "remediation": remediation,
            "evidence": evidence,
        }
