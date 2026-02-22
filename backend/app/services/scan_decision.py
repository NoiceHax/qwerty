"""Scan decision engine — determines whether cloning is required.

Based on scan type, target type, and repo intelligence data.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from pydantic import BaseModel

from app.services.repo_intelligence import RepoIntelReport
from app.config import settings

logger = logging.getLogger(__name__)


class ScanDecision(BaseModel):
    """Output of the decision engine."""
    needs_clone: bool = False
    clone_reason: Optional[str] = None
    scan_modules: List[str] = []          # which modules to run
    skip_reasons: Dict[str, str] = {}     # module → reason skipped
    estimated_duration: str = "fast"      # fast | moderate | deep


class ScanDecisionEngine:
    """Decides clone-vs-API-only and which scan modules to activate."""

    def decide(
        self,
        scan_type: str,
        target_type: str,
        intel: Optional[RepoIntelReport] = None,
    ) -> ScanDecision:
        modules: List[str] = []
        skip: Dict[str, str] = {}
        needs_clone = False
        clone_reason = None

        is_repo = target_type == "repo"
        is_url = target_type == "url"

        # ---- Dynamic scan (always runs for URLs / repos with homepage) ----
        if scan_type in ("dynamic", "full"):
            modules.append("dynamic")

        # ---- Static scan (needs cloned source code) ----
        if scan_type in ("static", "full") and is_repo:
            # Check repo size
            if intel and intel.size_kb > settings.max_repo_size_mb * 1024:
                skip["static"] = f"Repo too large ({intel.size_kb}KB > {settings.max_repo_size_mb}MB)"
                logger.warning(skip["static"])
            elif intel and intel.file_count == 0:
                skip["static"] = "No code files detected in repository"
            else:
                modules.append("static")
                needs_clone = True
                clone_reason = "Static analysis requires source code access"

        # If target is URL-only but static requested, skip static
        if scan_type in ("static", "full") and is_url:
            skip["static"] = "Static analysis requires a repository target, not a URL"

        # ---- Nuclei (always for URLs / repos with homepage) ----
        if scan_type in ("dynamic", "full"):
            modules.append("nuclei")

        # ---- Dependency audit (needs clone) ----
        if scan_type in ("static", "full") and is_repo and "static" in modules:
            modules.append("dependency_audit")

        # ---- AI summary (always if Gemini is configured) ----
        if settings.gemini_api_key:
            modules.append("ai_summary")

        # ---- Duration estimate ----
        if needs_clone:
            duration = "deep" if (intel and intel.complexity == "high") else "moderate"
        else:
            duration = "fast"

        decision = ScanDecision(
            needs_clone=needs_clone,
            clone_reason=clone_reason,
            scan_modules=modules,
            skip_reasons=skip,
            estimated_duration=duration,
        )

        logger.info(
            f"ScanDecision: clone={needs_clone}, "
            f"modules={modules}, skipped={list(skip.keys())}, "
            f"duration={duration}"
        )
        return decision
