"""TLS / HTTPS analysis module."""

from __future__ import annotations

import ssl
import socket
import logging
from typing import Any, Dict, List
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)
Finding = Dict[str, Any]


class TLSAnalyzer:
    """Checks HTTPS enforcement, redirects, HSTS, and TLS certificate details."""

    async def analyze(self, target_url: str, client: httpx.AsyncClient) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # 1. HTTPS enforcement ------------------------------------------
        if parsed.scheme == "http":
            findings.append(self._finding(
                "no_https",
                "Site does not use HTTPS",
                "The target URL uses plain HTTP, which is vulnerable to man-in-the-middle attacks.",
                severity="high",
                remediation="Enforce HTTPS for all traffic. Obtain a TLS certificate (e.g., Let's Encrypt) and redirect HTTP to HTTPS.",
            ))

            # Check if HTTPS redirect exists
            try:
                resp = await client.get(target_url, follow_redirects=False)
                location = resp.headers.get("location", "")
                if resp.status_code in (301, 302, 307, 308) and location.startswith("https://"):
                    findings.append(self._finding(
                        "http_redirect_to_https",
                        "HTTP redirects to HTTPS",
                        f"HTTP request redirects to {location}.",
                        severity="info",
                        confidence="high",
                        remediation="Good practice. Consider using 301 permanent redirect and HSTS.",
                    ))
            except Exception:
                pass

        # 2. TLS certificate inspection ---------------------------------
        if parsed.scheme == "https" or True:
            https_url = target_url.replace("http://", "https://", 1)
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=10) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        protocol = ssock.version()

                        # Weak protocol
                        if protocol and protocol in ("TLSv1", "TLSv1.1"):
                            findings.append(self._finding(
                                "weak_tls_version",
                                f"Weak TLS version: {protocol}",
                                f"The server supports {protocol}, which is deprecated and insecure.",
                                severity="medium",
                                remediation="Disable TLSv1.0 and TLSv1.1. Use TLSv1.2 or TLSv1.3 only.",
                            ))

                        # Certificate expiry
                        if cert:
                            not_after = cert.get("notAfter")
                            if not_after:
                                import datetime
                                from email.utils import parsedate_to_datetime
                                try:
                                    expiry = ssl.cert_time_to_seconds(not_after)
                                    import time
                                    days_left = (expiry - time.time()) / 86400
                                    if days_left < 0:
                                        findings.append(self._finding(
                                            "expired_certificate",
                                            "TLS certificate has expired",
                                            f"Certificate expired on {not_after}.",
                                            severity="critical",
                                            remediation="Renew the TLS certificate immediately.",
                                        ))
                                    elif days_left < 30:
                                        findings.append(self._finding(
                                            "certificate_expiring_soon",
                                            f"TLS certificate expires in {int(days_left)} days",
                                            f"Certificate expires on {not_after}.",
                                            severity="medium",
                                            remediation="Renew the TLS certificate soon. Consider automated renewal.",
                                        ))
                                except Exception:
                                    pass

            except ssl.SSLCertVerificationError as exc:
                findings.append(self._finding(
                    "ssl_cert_error",
                    "SSL certificate verification failed",
                    str(exc),
                    severity="high",
                    remediation="Ensure the certificate is valid, not self-signed, and matches the hostname.",
                ))
            except Exception as exc:
                logger.debug(f"TLS inspection error for {hostname}: {exc}")

        # 3. HSTS header ------------------------------------------------
        try:
            resp = await client.get(target_url)
            hsts = resp.headers.get("strict-transport-security")
            if not hsts:
                findings.append(self._finding(
                    "missing_hsts",
                    "Missing Strict-Transport-Security header",
                    "The server does not send an HSTS header, leaving users vulnerable to SSL stripping.",
                    severity="medium",
                    remediation="Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                ))
            else:
                if "max-age=0" in hsts:
                    findings.append(self._finding(
                        "weak_hsts",
                        "HSTS max-age is set to 0",
                        "HSTS with max-age=0 effectively disables HSTS.",
                        severity="medium",
                        remediation="Set max-age to at least 31536000 (1 year).",
                    ))
                elif "includesubdomains" not in hsts.lower():
                    findings.append(self._finding(
                        "hsts_no_subdomains",
                        "HSTS does not include subdomains",
                        "Subdomains are not protected by HSTS.",
                        severity="low",
                        remediation="Add 'includeSubDomains' to the HSTS header.",
                    ))
        except Exception:
            pass

        return findings

    @staticmethod
    def _finding(vuln_type: str, title: str, description: str,
                 severity: str = "info", confidence: str = "high",
                 remediation: str = "") -> Finding:
        return {
            "vuln_type": vuln_type,
            "title": title,
            "description": description,
            "severity": severity,
            "confidence": confidence,
            "detection_source": "dynamic:tls_analyzer",
            "remediation": remediation,
        }
