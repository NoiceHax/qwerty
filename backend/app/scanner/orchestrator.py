"""Tool orchestration layer — runs external security tools (Nuclei primary)."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tempfile
from typing import Any, Dict, List

logger = logging.getLogger(__name__)
Finding = Dict[str, Any]


class ToolOrchestrator:
    """Executes external security tools and normalises their output."""

    NUCLEI_TIMEOUT = 120  # seconds

    # ------------------------------------------------------------------
    # Nuclei
    # ------------------------------------------------------------------

    async def run_nuclei(self, target_url: str) -> List[Finding]:
        """Run Nuclei scanner against target and return normalised findings."""
        nuclei_path = shutil.which("nuclei")
        if not nuclei_path:
            logger.info("Nuclei not found on PATH — skipping.")
            raise FileNotFoundError("Nuclei binary not found. Install from https://github.com/projectdiscovery/nuclei")

        output_file = tempfile.mktemp(suffix=".json")

        cmd = [
            nuclei_path,
            "-u", target_url,
            "-jsonl",                    # JSON Lines output
            "-o", output_file,
            "-silent",
            "-nc",                       # no colour
            "-timeout", "10",            # per-request timeout
            "-retries", "1",
            "-rate-limit", "50",         # requests per second
            "-severity", "info,low,medium,high,critical",
            "-stats",                    # show stats
            "-no-interactsh",            # no external interaction
        ]

        logger.info(f"Running Nuclei: {' '.join(cmd)}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.NUCLEI_TIMEOUT
            )

            if proc.returncode != 0:
                logger.warning(
                    f"Nuclei exited with code {proc.returncode}: "
                    f"{stderr.decode(errors='ignore')[:500]}"
                )

            return self._parse_nuclei_output(output_file)

        except asyncio.TimeoutError:
            logger.warning("Nuclei scan timed out")
            try:
                proc.kill()  # type: ignore
            except Exception:
                pass
            return [{
                "vuln_type": "tool_timeout",
                "title": "Nuclei scan timed out",
                "description": f"Nuclei did not complete within {self.NUCLEI_TIMEOUT}s.",
                "severity": "info",
                "confidence": "high",
                "detection_source": "tool:nuclei",
            }]

        except Exception as exc:
            logger.error(f"Nuclei execution failed: {exc}")
            return []

        finally:
            # Cleanup temp file
            import os
            try:
                os.unlink(output_file)
            except Exception:
                pass

    def _parse_nuclei_output(self, output_file: str) -> List[Finding]:
        """Parse Nuclei's JSON Lines output into unified findings."""
        findings: List[Finding] = []

        try:
            with open(output_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        finding = self._normalise_nuclei_entry(entry)
                        if finding:
                            findings.append(finding)
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            logger.debug("Nuclei output file not found (scan may have produced no results)")

        return findings

    def _normalise_nuclei_entry(self, entry: dict) -> Finding | None:
        """Convert a single Nuclei JSON result to our finding format."""
        info = entry.get("info", {})
        template_id = entry.get("template-id", "unknown")
        matched_at = entry.get("matched-at", "")
        host = entry.get("host", "")

        # Map Nuclei severity to ours
        nuclei_severity = info.get("severity", "info").lower()
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info",
        }
        severity = severity_map.get(nuclei_severity, "info")

        # Extract metadata
        name = info.get("name", template_id)
        description = info.get("description", "")
        tags = info.get("tags", [])
        if isinstance(tags, list):
            tags = ", ".join(tags)
        reference = info.get("reference", [])
        if isinstance(reference, list):
            reference = "\n".join(reference)

        # Classification
        classification = info.get("classification", {})
        cvss_score = classification.get("cvss-score")
        cve_id = classification.get("cve-id", "")

        # Build remediation from metadata
        remediation_text = info.get("remediation", "")
        if not remediation_text and reference:
            remediation_text = f"See references for remediation guidance:\n{reference}"

        # Extract matcher name for more specific findings
        matcher_name = entry.get("matcher-name", "")
        extracted = entry.get("extracted-results", [])

        evidence_parts = []
        if matched_at:
            evidence_parts.append(f"Matched at: {matched_at}")
        if matcher_name:
            evidence_parts.append(f"Matcher: {matcher_name}")
        if extracted:
            evidence_parts.append(f"Extracted: {', '.join(str(e) for e in extracted[:5])}")
        if cve_id:
            evidence_parts.append(f"CVE: {cve_id}")

        return {
            "vuln_type": f"nuclei:{template_id}",
            "title": f"[Nuclei] {name}",
            "description": description or f"Nuclei template {template_id} matched.",
            "severity": severity,
            "confidence": "high",  # Nuclei templates are curated
            "cvss_score": float(cvss_score) if cvss_score else None,
            "detection_source": "tool:nuclei",
            "remediation": remediation_text or "Refer to the Nuclei template for remediation guidance.",
            "evidence": "\n".join(evidence_parts),
            "location": matched_at or host,
            "raw_data": {
                "template_id": template_id,
                "tags": tags,
                "reference": reference,
            },
        }

    # ------------------------------------------------------------------
    # Extensibility stubs
    # ------------------------------------------------------------------

    async def run_semgrep(self, repo_path: str) -> List[Finding]:
        """Run Semgrep on a repository (optional, gracefully skips if unavailable)."""
        semgrep_path = shutil.which("semgrep")
        if not semgrep_path:
            logger.info("Semgrep not found — skipping.")
            return []

        # Semgrep integration can be added here
        # Similar pattern: run subprocess, parse JSON output, normalise
        return []

    async def run_zap(self, target_url: str) -> List[Finding]:
        """Run OWASP ZAP baseline scan (optional)."""
        # ZAP integration stub — can be added based on requirement
        logger.info("ZAP integration not yet implemented — skipping.")
        return []
