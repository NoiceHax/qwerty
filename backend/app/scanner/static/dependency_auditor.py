"""Dependency vulnerability auditing via OSV API and file parsing."""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)
Finding = Dict[str, Any]

OSV_API = "https://api.osv.dev/v1/query"


class DependencyAuditor:
    """Checks project dependencies against the OSV vulnerability database."""

    async def analyze(self, repo_path: str) -> List[Finding]:
        findings: List[Finding] = []

        # Python dependencies
        req_file = os.path.join(repo_path, "requirements.txt")
        if os.path.exists(req_file):
            deps = self._parse_requirements(req_file)
            for name, version in deps:
                vulns = await self._check_osv(name, version, "PyPI")
                findings.extend(vulns)

        # Pipfile
        pipfile = os.path.join(repo_path, "Pipfile.lock")
        if os.path.exists(pipfile):
            deps = self._parse_pipfile_lock(pipfile)
            for name, version in deps:
                vulns = await self._check_osv(name, version, "PyPI")
                findings.extend(vulns)

        # Node.js dependencies
        pkg_file = os.path.join(repo_path, "package.json")
        if os.path.exists(pkg_file):
            deps = self._parse_package_json(pkg_file)
            for name, version in deps:
                vulns = await self._check_osv(name, version, "npm")
                findings.extend(vulns)

        # package-lock.json for more precise versions
        lock_file = os.path.join(repo_path, "package-lock.json")
        if os.path.exists(lock_file):
            deps = self._parse_package_lock(lock_file)
            for name, version in deps:
                vulns = await self._check_osv(name, version, "npm")
                findings.extend(vulns)

        # Go modules
        go_sum = os.path.join(repo_path, "go.sum")
        if os.path.exists(go_sum):
            deps = self._parse_go_sum(go_sum)
            for name, version in deps:
                vulns = await self._check_osv(name, version, "Go")
                findings.extend(vulns)

        return findings

    async def _check_osv(
        self, package: str, version: str, ecosystem: str
    ) -> List[Finding]:
        """Query OSV API for known vulnerabilities."""
        if not version:
            return []

        findings: List[Finding] = []

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                payload = {
                    "package": {
                        "name": package,
                        "ecosystem": ecosystem,
                    },
                    "version": version,
                }
                resp = await client.post(OSV_API, json=payload)

                if resp.status_code == 200:
                    data = resp.json()
                    vulns = data.get("vulns", [])

                    for vuln in vulns:
                        vuln_id = vuln.get("id", "Unknown")
                        summary = vuln.get("summary", "No description available")
                        severity_list = vuln.get("severity", [])

                        # Extract CVSS score
                        cvss = None
                        for sev in severity_list:
                            if sev.get("type") == "CVSS_V3":
                                try:
                                    score_str = sev.get("score", "")
                                    # Extract base score from CVSS vector
                                    cvss = float(score_str) if score_str else None
                                except (ValueError, TypeError):
                                    pass

                        # Map CVSS to severity
                        severity = self._cvss_to_severity(cvss)

                        # Get aliases (CVE IDs)
                        aliases = vuln.get("aliases", [])
                        cve_ids = [a for a in aliases if a.startswith("CVE-")]

                        findings.append({
                            "vuln_type": "vulnerable_dependency",
                            "title": f"Vulnerable dependency: {package}@{version} ({vuln_id})",
                            "description": summary,
                            "severity": severity,
                            "confidence": "high",
                            "cvss_score": cvss,
                            "detection_source": "static:dependency_auditor",
                            "remediation": (
                                f"Update {package} to a patched version. "
                                f"See https://osv.dev/vulnerability/{vuln_id} for details."
                            ),
                            "evidence": (
                                f"Package: {package}@{version}\n"
                                f"Vulnerability: {vuln_id}\n"
                                f"CVEs: {', '.join(cve_ids) if cve_ids else 'N/A'}\n"
                                f"Ecosystem: {ecosystem}"
                            ),
                            "location": f"{ecosystem}:{package}@{version}",
                        })

        except httpx.RequestError as exc:
            logger.warning(f"OSV API query failed for {package}: {exc}")
        except Exception as exc:
            logger.warning(f"Dependency check error for {package}: {exc}")

        return findings

    # ---------------------------------------------------------------
    # File parsers
    # ---------------------------------------------------------------

    @staticmethod
    def _parse_requirements(filepath: str) -> List[tuple]:
        """Parse requirements.txt into [(name, version)] pairs."""
        deps = []
        try:
            with open(filepath, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    # Handle ==, >=, ~=, etc.
                    match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*[=~!<>]=?\s*([0-9][^\s;#]*)", line)
                    if match:
                        deps.append((match.group(1), match.group(2)))
                    else:
                        # Package without version
                        match = re.match(r"^([A-Za-z0-9_\-\.]+)", line)
                        if match:
                            deps.append((match.group(1), ""))
        except Exception:
            pass
        return deps

    @staticmethod
    def _parse_package_json(filepath: str) -> List[tuple]:
        deps = []
        try:
            with open(filepath) as f:
                data = json.load(f)
            for section in ("dependencies", "devDependencies"):
                for name, version in data.get(section, {}).items():
                    # Strip ^ ~ >= etc.
                    clean_v = re.sub(r"^[\^~>=<]+", "", version)
                    deps.append((name, clean_v))
        except Exception:
            pass
        return deps

    @staticmethod
    def _parse_package_lock(filepath: str) -> List[tuple]:
        deps = []
        try:
            with open(filepath) as f:
                data = json.load(f)
            packages = data.get("packages", data.get("dependencies", {}))
            for name, info in packages.items():
                if isinstance(info, dict):
                    version = info.get("version", "")
                    clean_name = name.replace("node_modules/", "")
                    if clean_name and version:
                        deps.append((clean_name, version))
        except Exception:
            pass
        return deps

    @staticmethod
    def _parse_pipfile_lock(filepath: str) -> List[tuple]:
        deps = []
        try:
            with open(filepath) as f:
                data = json.load(f)
            for section in ("default", "develop"):
                for name, info in data.get(section, {}).items():
                    version = info.get("version", "").lstrip("=")
                    deps.append((name, version))
        except Exception:
            pass
        return deps

    @staticmethod
    def _parse_go_sum(filepath: str) -> List[tuple]:
        deps = []
        try:
            with open(filepath) as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        name = parts[0]
                        version = parts[1].split("/")[0].lstrip("v")
                        deps.append((name, version))
        except Exception:
            pass
        return deps

    @staticmethod
    def _cvss_to_severity(cvss: float | None) -> str:
        if cvss is None:
            return "medium"
        if cvss >= 9.0:
            return "critical"
        if cvss >= 7.0:
            return "high"
        if cvss >= 4.0:
            return "medium"
        return "low"
