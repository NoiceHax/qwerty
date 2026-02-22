"""AI Summarizer — orchestrates Gemini analysis pipeline.

1. Collects scan results + repo intel → builds AIScanInput
2. Formats prompt from template
3. Calls GeminiService
4. Returns structured AISummaryOutput
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.analysis.ai_schemas import (
    AIScanInput,
    AISummaryOutput,
    AIFindingSummary,
    RepoContextForAI,
)
from app.analysis.ai_prompts import SYSTEM_PROMPT, build_summary_prompt
from app.services.gemini_service import GeminiService, GeminiServiceError
from app.services.repo_intelligence import RepoIntelReport

logger = logging.getLogger(__name__)


class AISummarizer:
    """Orchestrates the Gemini AI summary pipeline."""

    def __init__(self):
        self._gemini = GeminiService()

    async def summarize(
        self,
        target_url: str,
        scan_type: str,
        risk_score: float,
        posture_rating: str,
        findings: List[Dict[str, Any]],
        intel: Optional[RepoIntelReport] = None,
    ) -> Optional[AISummaryOutput]:
        """Build structured input, call Gemini, parse response."""

        try:
            scan_input = self._build_input(
                target_url, scan_type, risk_score, posture_rating, findings, intel
            )

            prompt = build_summary_prompt(scan_input)
            logger.info(f"AISummarizer: sending {len(prompt)}-char prompt to Gemini")

            response_text = await self._gemini.generate(prompt, SYSTEM_PROMPT)

            output = self._parse_response(response_text)
            logger.info("AISummarizer: Gemini summary generated successfully")
            return output

        except GeminiServiceError as exc:
            logger.error(f"AISummarizer: Gemini failed: {exc}")
            return None
        except Exception as exc:
            logger.exception(f"AISummarizer: unexpected error: {exc}")
            return None

    def _build_input(
        self,
        target_url: str,
        scan_type: str,
        risk_score: float,
        posture_rating: str,
        findings: List[Dict[str, Any]],
        intel: Optional[RepoIntelReport],
    ) -> AIScanInput:
        """Build structured AI input from scan results."""
        # Severity distribution
        sev_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        conf_dist = {"high": 0, "medium": 0, "low": 0}
        sources = set()
        observations = []

        for f in findings:
            sev = f.get("severity", "info").lower()
            sev_dist[sev] = sev_dist.get(sev, 0) + 1

            conf = f.get("confidence", "medium").lower()
            conf_dist[conf] = conf_dist.get(conf, 0) + 1

            src = f.get("detection_source", "")
            if src:
                sources.add(src)

        # Top 10 findings (already sorted by risk_score from scoring engine)
        top_findings = []
        for f in findings[:10]:
            top_findings.append(AIFindingSummary(
                title=f.get("title", "Unknown"),
                severity=f.get("severity", "info"),
                confidence=f.get("confidence", "medium"),
                vuln_type=f.get("vuln_type", "unknown"),
                location=f.get("location"),
                remediation=f.get("remediation"),
            ))

        # Security observations from findings
        if sev_dist["critical"] > 0:
            observations.append(f"{sev_dist['critical']} critical vulnerabilities detected")
        if any(f.get("vuln_type") == "hardcoded_secret" for f in findings):
            observations.append("Hardcoded secrets found in source code")
        if any(f.get("vuln_type", "").startswith("cors_") for f in findings):
            observations.append("CORS misconfiguration detected")
        if any("debug" in f.get("vuln_type", "") for f in findings):
            observations.append("Debug artifacts or information leakage found")

        # Repo context
        repo_ctx = None
        if intel:
            repo_ctx = RepoContextForAI(
                tech_stack=intel.tech_stack,
                primary_language=intel.primary_language,
                complexity=intel.complexity,
                has_ci=intel.has_ci,
                has_docker=intel.has_docker,
                description=intel.description,
            )

        return AIScanInput(
            target=target_url,
            scan_type=scan_type,
            risk_score=risk_score,
            posture_rating=posture_rating,
            total_findings=len(findings),
            severity_distribution=sev_dist,
            confidence_distribution=conf_dist,
            top_findings=top_findings,
            detection_sources=sorted(sources),
            security_observations=observations,
            repo_context=repo_ctx,
        )

    def _parse_response(self, text: str) -> AISummaryOutput:
        """Parse Gemini's markdown response into structured output."""
        sections = {
            "executive_summary": "",
            "risk_narrative": "",
            "prioritized_actions": [],
            "positive_observations": [],
            "confidence_notes": "",
            "use_case_advice": "",
        }

        current_section = None
        lines = text.split("\n")

        section_map = {
            "executive summary": "executive_summary",
            "risk narrative": "risk_narrative",
            "prioritized remediation": "prioritized_actions",
            "prioritized actions": "prioritized_actions",
            "positive observations": "positive_observations",
            "confidence notes": "confidence_notes",
            "use-case advice": "use_case_advice",
            "use case advice": "use_case_advice",
        }

        for line in lines:
            stripped = line.strip()

            # Detect section headers
            if stripped.startswith("#"):
                header_text = stripped.lstrip("#").strip().lower()
                for key, section_name in section_map.items():
                    if key in header_text:
                        current_section = section_name
                        break
                continue

            if not current_section or not stripped:
                continue

            # For list sections, collect items
            if current_section in ("prioritized_actions", "positive_observations"):
                if stripped.startswith(("-", "*", "•")) or (stripped[0].isdigit() and "." in stripped[:4]):
                    clean = stripped.lstrip("-*•0123456789. ").strip()
                    if clean:
                        sections[current_section].append(clean)
            else:
                # For text sections, accumulate
                sections[current_section] += stripped + " "

        return AISummaryOutput(
            executive_summary=sections["executive_summary"].strip() or "Summary not available.",
            risk_narrative=sections["risk_narrative"].strip() or "No risk narrative generated.",
            prioritized_actions=sections["prioritized_actions"] or ["No specific actions recommended."],
            positive_observations=sections["positive_observations"] or ["No positive observations noted."],
            confidence_notes=sections["confidence_notes"].strip() or "Standard automated scan confidence.",
            use_case_advice=sections["use_case_advice"].strip() or "No specific use-case advice generated.",
            generated_at=datetime.now(timezone.utc).isoformat(),
        )
