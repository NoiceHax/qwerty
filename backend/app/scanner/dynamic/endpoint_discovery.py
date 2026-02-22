"""Sensitive endpoint discovery module with multi-signal validation.

Uses advanced response fingerprinting, soft404 detection, content similarity analysis,
and multi-signal decision logic to reduce false positives from SPA fallbacks,
catch-all routers, and soft error pages.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import httpx

from app.scanner.dynamic.endpoint_validator import (
    EndpointValidator,
    FingerprintBuilder,
    SeverityConfidenceMapper,
)

logger = logging.getLogger(__name__)
Finding = Dict[str, Any]

# High-risk paths to probe (admin panels, config, debug, backups, etc.)
_SENSITIVE_PATHS = [
    # Admin panels
    "/admin", "/admin/", "/administrator", "/admin/login",
    "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/pma",
    "/cpanel",
    "/manager", "/management",
    "/dashboard", "/admin/dashboard",

    # Debug & development
    "/debug", "/debug/",
    "/_debug", "/__debug__",
    "/devtools", "/dev",
    "/test", "/testing",
    "/phpinfo.php",
    "/server-status", "/server-info",
    "/elmah.axd",
    "/_profiler",

    # Configuration & environment
    "/.env", "/.env.local", "/.env.production",
    "/config", "/config.json", "/config.yml", "/config.xml",
    "/settings.json", "/settings.py",
    "/web.config",
    "/application.yml", "/application.properties",

    # Version control
    "/.git/HEAD", "/.git/config",
    "/.svn/entries",
    "/.hg/",

    # API documentation
    "/api", "/api/v1", "/api/docs",
    "/swagger", "/swagger.json", "/swagger-ui.html",
    "/openapi.json",
    "/graphql", "/graphiql",

    # Backup files
    "/backup", "/backups",
    "/db.sql", "/database.sql",
    "/dump.sql",
    "/.bak",

    # Sensitive files
    "/robots.txt",
    "/sitemap.xml",
    "/.htaccess",
    "/.htpasswd",
    "/crossdomain.xml",
    "/security.txt", "/.well-known/security.txt",
    "/package.json",
    "/composer.json",
    "/Gemfile",
    "/requirements.txt",
]


class EndpointDiscovery:
    """Probes for sensitive endpoints using multi-signal validation to reduce false positives."""

    MAX_CONCURRENT = 10

    async def analyze(self, target_url: str, client: httpx.AsyncClient) -> List[Finding]:
        """Discover sensitive endpoints with multi-signal validation.

        Args:
            target_url: Base URL to scan
            client: httpx AsyncClient instance

        Returns:
            List of vulnerability findings
        """
        findings: List[Finding] = []
        semaphore = asyncio.Semaphore(self.MAX_CONCURRENT)

        # Step 1: Get baseline fingerprint from root endpoint
        baseline_fp = await self._get_baseline(target_url, client)
        if baseline_fp is None:
            logger.warning(f"Could not establish baseline for {target_url}")
            return findings

        # Step 2: Probe sensitive endpoints with validation
        async def probe(path: str):
            async with semaphore:
                url = urljoin(target_url.rstrip("/") + "/", path.lstrip("/"))
                try:
                    resp = await client.get(url, follow_redirects=False, timeout=15.0)
                    # Only analyze "interesting" responses
                    if resp.status_code < 500:
                        return await self._validate_and_classify(
                            path, url, resp, baseline_fp
                        )
                except httpx.RequestError as e:
                    logger.debug(f"Request error for {url}: {e}")
                except httpx.TimeoutException:
                    logger.debug(f"Timeout probing {url}")
                return None

        tasks = [probe(p) for p in _SENSITIVE_PATHS]
        results = await asyncio.gather(*tasks)

        for result in results:
            if result:
                findings.append(result)

        return findings

    async def _get_baseline(
        self, target_url: str, client: httpx.AsyncClient
    ) -> Optional[Any]:
        """Fetch and fingerprint the root endpoint as baseline.

        Args:
            target_url: Base URL
            client: httpx AsyncClient

        Returns:
            ResponseFingerprint or None if failed
        """
        try:
            resp = await client.get(target_url, follow_redirects=True, timeout=15.0)
            baseline_fp = FingerprintBuilder.build(resp)
            logger.debug(
                f"Baseline established: {resp.status_code}, "
                f"size={baseline_fp.content_length}, "
                f"hash={baseline_fp.content_hash[:8]}..."
            )
            return baseline_fp
        except httpx.RequestError as e:
            logger.warning(f"Failed to establish baseline for {target_url}: {e}")
            return None

    async def _validate_and_classify(
        self,
        path: str,
        url: str,
        resp: httpx.Response,
        baseline_fp: Any,
    ) -> Optional[Finding]:
        """Validate endpoint existence and generate finding if real.

        Args:
            path: Endpoint path
            url: Full URL
            resp: HTTP response
            baseline_fp: Baseline response fingerprint

        Returns:
            Finding dict if endpoint confirmed, None otherwise
        """
        # Use multi-signal validation
        validation_result = EndpointValidator.validate(path, baseline_fp, resp)

        logger.debug(
            f"Validated {path}: exists={validation_result.exists}, "
            f"confidence={validation_result.confidence}, "
            f"reason={validation_result.reason}"
        )

        # Only report if endpoint is confirmed to exist
        if not validation_result.exists:
            return None

        # Determine severity and confidence
        severity = SeverityConfidenceMapper.get_severity(
            path, validation_result.exists, validation_result.status_code
        )
        confidence = SeverityConfidenceMapper.get_confidence_from_signals(
            validation_result
        )

        # Generate finding
        title = self._generate_title(path, validation_result)
        description = self._generate_description(path, validation_result)
        remediation = self._generate_remediation(path, severity)

        return {
            "vuln_type": "sensitive_endpoint",
            "title": title,
            "description": description,
            "severity": severity,
            "confidence": confidence,
            "detection_source": "dynamic:endpoint_discovery",
            "remediation": remediation,
            "evidence": self._generate_evidence(path, url, validation_result),
            "location": url,
        }

    @staticmethod
    def _generate_title(path: str, validation_result: Any) -> str:
        """Generate finding title based on endpoint characteristics."""
        if any(
            kw in path.lower() for kw in [".env", ".git", "htpasswd", "db.sql", "dump.sql"]
        ):
            return f"Sensitive file exposed: {path}"
        elif any(kw in path.lower() for kw in ["admin", "phpmyadmin", "cpanel", "manager"]):
            return f"Admin/management panel accessible: {path}"
        elif any(kw in path.lower() for kw in ["debug", "profiler", "phpinfo"]):
            return f"Debug endpoint exposed: {path}"
        elif any(kw in path.lower() for kw in ["swagger", "graphql", "api/docs"]):
            return f"API documentation endpoint: {path}"
        elif any(kw in path.lower() for kw in ["package.json", "composer.json", "requirements.txt"]):
            return f"Dependency manifest exposed: {path}"
        else:
            return f"Sensitive endpoint discovered: {path}"

    @staticmethod
    def _generate_description(path: str, validation_result: Any) -> str:
        """Generate detailed finding description with signal analysis."""
        lines = [f"Endpoint {path} exists - HTTP {validation_result.status_code}"]

        if validation_result.is_soft_error:
            lines.append(
                f"Note: Response contains soft error indicators: "
                f"{', '.join(validation_result.soft_error_indicators['error_keywords'][:3])}"
            )

        lines.append(f"Validation reason: {validation_result.reason}")
        lines.append(f"Confidence: {validation_result.confidence.upper()}")

        # Add signal details
        sim = validation_result.similarity_details
        lines.append(
            f"\nSignal Analysis:\n"
            f"  - Status Code Signal: {validation_result.status_code_signal:.2f}\n"
            f"  - Content Similarity: {sim['composite']:.2%}\n"
            f"  - Soft Error Indicator: {validation_result.soft_error_signal:.2f}"
        )

        return "\n".join(lines)

    @staticmethod
    def _generate_remediation(path: str, severity: str) -> str:
        """Generate remediation recommendation based on endpoint type."""
        if any(kw in path.lower() for kw in [".env", ".git", "htpasswd"]):
            return (
                f"CRITICAL: {path} must not be accessible from the internet. "
                f"Remove it entirely or use web server rules to deny access. "
                f"This file likely contains secrets, credentials, or VCS metadata."
            )
        elif any(kw in path.lower() for kw in ["admin", "phpmyadmin", "cpanel"]):
            return (
                f"Restrict access to {path} using IP allowlisting, "
                f"authentication, and network segmentation. Consider moving to non-standard URL."
            )
        elif any(kw in path.lower() for kw in ["debug", "profiler", "phpinfo"]):
            return (
                f"Disable {path} in production. Debug endpoints leak sensitive system information, "
                f"execution paths, and internal configuration."
            )
        elif severity == "info":
            return f"Review if {path} should be publicly accessible."
        else:
            return (
                f"Investigate why {path} is accessible. Determine if it should be public "
                f"and apply appropriate access controls."
            )

    @staticmethod
    def _generate_evidence(path: str, url: str, validation_result: Any) -> str:
        """Generate evidence details for finding."""
        lines = [
            f"URL: {url}",
            f"Status: {validation_result.status_code}",
            f"Validation Confidence: {validation_result.confidence}",
            f"Decision Reason: {validation_result.reason}",
        ]

        sim = validation_result.similarity_details
        lines.append(
            f"\nContent Analysis:\n"
            f"  Hash Match: {sim['hash_similarity']:.2f}\n"
            f"  Length Match: {sim['length_similarity']:.2%}\n"
            f"  Body Similarity: {sim['body_similarity']:.2%}\n"
            f"  Title Match: {sim['title_similarity']:.2f}"
        )

        if validation_result.is_soft_error:
            if validation_result.soft_error_indicators["error_keywords"]:
                lines.append(
                    f"\nError Indicators: "
                    f"{', '.join(validation_result.soft_error_indicators['error_keywords'][:5])}"
                )
            if validation_result.soft_error_indicators["framework_hints"]:
                lines.append(
                    f"Framework Hints: "
                    f"{', '.join(validation_result.soft_error_indicators['framework_hints'])}"
                )

        return "\n".join(lines)
