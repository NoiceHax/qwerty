"""Attack surface mapping module."""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Set
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)
Finding = Dict[str, Any]


class SurfaceMapper:
    """Discovers external attack surface: robots.txt, sitemap, links, forms."""

    async def analyze(self, target_url: str, client: httpx.AsyncClient) -> List[Finding]:
        findings: List[Finding] = []
        discovered_paths: Set[str] = set()

        # 1. Robots.txt analysis
        robots_findings, robot_paths = await self._check_robots(target_url, client)
        findings.extend(robots_findings)
        discovered_paths.update(robot_paths)

        # 2. Sitemap analysis
        sitemap_paths = await self._check_sitemap(target_url, client)
        discovered_paths.update(sitemap_paths)

        # 3. Link extraction from main page
        try:
            resp = await client.get(target_url)
            page_paths = self._extract_links(resp.text, target_url)
            discovered_paths.update(page_paths)

            # Check for forms (potential input vectors)
            forms = self._extract_forms(resp.text)
            if forms:
                findings.append({
                    "vuln_type": "attack_surface",
                    "title": f"Found {len(forms)} form(s) on the page",
                    "description": "Forms are potential input vectors for injection attacks.",
                    "severity": "info",
                    "confidence": "high",
                    "detection_source": "dynamic:surface_mapper",
                    "remediation": "Ensure all form inputs are properly validated and sanitized.",
                    "evidence": f"Forms: {forms[:5]}",  # limit output
                    "location": target_url,
                })
        except httpx.RequestError:
            pass

        # 4. Summarise discovered surface
        if discovered_paths:
            api_paths = [p for p in discovered_paths if "/api" in p.lower()]
            if api_paths:
                findings.append({
                    "vuln_type": "api_endpoints_discovered",
                    "title": f"Discovered {len(api_paths)} API endpoint(s)",
                    "description": "API endpoints were found during surface mapping.",
                    "severity": "info",
                    "confidence": "high",
                    "detection_source": "dynamic:surface_mapper",
                    "remediation": "Ensure all API endpoints require proper authentication and authorization.",
                    "evidence": "\n".join(sorted(api_paths)[:20]),
                    "location": target_url,
                })

            findings.append({
                "vuln_type": "surface_map",
                "title": f"Attack surface: {len(discovered_paths)} unique paths discovered",
                "description": "Paths discovered via robots.txt, sitemap, and link extraction.",
                "severity": "info",
                "confidence": "high",
                "detection_source": "dynamic:surface_mapper",
                "evidence": "\n".join(sorted(discovered_paths)[:30]),
                "location": target_url,
            })

        return findings

    async def _check_robots(
        self, target_url: str, client: httpx.AsyncClient
    ) -> tuple[List[Finding], Set[str]]:
        findings: List[Finding] = []
        paths: Set[str] = set()

        robots_url = urljoin(target_url, "/robots.txt")
        try:
            resp = await client.get(robots_url)
            if resp.status_code == 200 and "user-agent" in resp.text.lower():
                # Parse disallowed paths
                disallowed = []
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            disallowed.append(path)
                            paths.add(path)
                    elif line.lower().startswith("allow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            paths.add(path)

                if disallowed:
                    # Disallowed paths can reveal hidden areas
                    sensitive = [
                        p for p in disallowed
                        if any(kw in p.lower() for kw in [
                            "admin", "private", "secret", "internal",
                            "api", "config", "backup", "debug",
                        ])
                    ]
                    if sensitive:
                        findings.append({
                            "vuln_type": "robots_sensitive_paths",
                            "title": "robots.txt reveals sensitive paths",
                            "description": (
                                "The robots.txt file disallows access to paths that suggest "
                                "sensitive areas of the application."
                            ),
                            "severity": "low",
                            "confidence": "medium",
                            "detection_source": "dynamic:surface_mapper",
                            "remediation": "While robots.txt is standard, sensitive paths should not rely solely on it for protection.",
                            "evidence": f"Sensitive disallowed paths:\n" + "\n".join(sensitive),
                            "location": robots_url,
                        })
        except httpx.RequestError:
            pass

        return findings, paths

    async def _check_sitemap(
        self, target_url: str, client: httpx.AsyncClient
    ) -> Set[str]:
        paths: Set[str] = set()
        sitemap_url = urljoin(target_url, "/sitemap.xml")
        try:
            resp = await client.get(sitemap_url)
            if resp.status_code == 200 and "<url>" in resp.text.lower():
                # Simple XML parsing for <loc> tags
                locs = re.findall(r"<loc>(.*?)</loc>", resp.text, re.IGNORECASE)
                for loc in locs:
                    parsed = urlparse(loc)
                    paths.add(parsed.path)
        except httpx.RequestError:
            pass
        return paths

    @staticmethod
    def _extract_links(html: str, base_url: str) -> Set[str]:
        paths: Set[str] = set()
        base_parsed = urlparse(base_url)

        href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
        src_pattern = re.compile(r'src=["\']([^"\']+)["\']', re.IGNORECASE)
        action_pattern = re.compile(r'action=["\']([^"\']+)["\']', re.IGNORECASE)

        for pattern in (href_pattern, src_pattern, action_pattern):
            for match in pattern.finditer(html):
                url = match.group(1)
                if url.startswith("/"):
                    paths.add(url)
                elif url.startswith(("http://", "https://")):
                    parsed = urlparse(url)
                    if parsed.netloc == base_parsed.netloc:
                        paths.add(parsed.path)

        return paths

    @staticmethod
    def _extract_forms(html: str) -> List[Dict[str, str]]:
        forms = []
        form_pattern = re.compile(
            r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\']',
            re.IGNORECASE,
        )
        for match in form_pattern.finditer(html):
            forms.append({"action": match.group(1), "method": match.group(2)})
        return forms
