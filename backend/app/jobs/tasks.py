"""Background scan tasks executed by RQ workers.

Two-phase pipeline:
  Phase 1 — GitHub API Intelligence (no clone)
  Phase 2 — Selective Clone + Deep Analysis
  Phase 3 — Gemini AI Summary
"""

from __future__ import annotations

import asyncio
import json
import logging
import platform
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.scan import Scan, ScanLog, ScanStatus, ScanType
from app.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


def execute_scan(scan_id: str, scan_type: str) -> dict:
    """Entry point called by the RQ worker.

    RQ workers run in a synchronous context, so we create an event loop
    to drive the async scanner engines.
    """
    if platform.system() == "Windows":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(_run_scan(scan_id, scan_type))
    finally:
        loop.close()


async def _run_scan(scan_id: str, scan_type: str) -> dict:
    """Orchestrates the full two-phase scan pipeline."""
    async with async_session_factory() as db:
        scan = await db.get(Scan, scan_id)
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return {"error": "scan_not_found"}

        # Mark as running
        scan.status = ScanStatus.RUNNING
        scan.updated_at = datetime.now(timezone.utc)
        await db.flush()
        await _add_log(db, scan_id, "Scan started")

        findings: List[Dict[str, Any]] = []
        intel_report = None
        clone_path = None

        try:
            # ============================================================
            # PHASE 1: GitHub API Intelligence (no clone needed)
            # ============================================================
            intel_report = await _phase1_github_intel(db, scan_id, scan.target_url)

            # ============================================================
            # SCAN DECISION ENGINE
            # ============================================================
            from app.services.scan_decision import ScanDecisionEngine
            decision_engine = ScanDecisionEngine()
            decision = decision_engine.decide(
                scan_type=scan_type,
                target_type=scan.target_type.value,
                intel=intel_report,
            )
            await _add_log(
                db, scan_id,
                f"Decision: clone={decision.needs_clone}, modules={decision.scan_modules}, "
                f"duration={decision.estimated_duration}",
            )

            # ============================================================
            # PHASE 2: Conditional Clone + Scan Modules
            # ============================================================
            from app.services.clone_manager import CloneManager
            clone_mgr = CloneManager()

            if decision.needs_clone:
                await _add_log(db, scan_id, f"Cloning repository: {decision.clone_reason}")
                clone_path = await clone_mgr.clone_if_needed(scan.target_url, True)
                if clone_path:
                    await _add_log(db, scan_id, "Repository cloned successfully")
                else:
                    await _add_log(db, scan_id, "Clone failed — continuing with API-only analysis", level="warning")

            # --- Dynamic scan ---
            if "dynamic" in decision.scan_modules:
                await _add_log(db, scan_id, "Starting dynamic analysis...")
                from app.scanner.dynamic.engine import DynamicScanEngine

                dynamic_engine = DynamicScanEngine()
                target = scan.target_url
                # If we have a homepage from intel, use that for dynamic scan
                if intel_report and intel_report.homepage_url:
                    target = intel_report.homepage_url
                    await _add_log(db, scan_id, f"Using homepage URL for dynamic scan: {target}")

                dynamic_findings = await dynamic_engine.run(target)
                findings.extend(dynamic_findings)
                await _add_log(
                    db, scan_id,
                    f"Dynamic analysis complete — {len(dynamic_findings)} findings",
                )

            # --- Static scan (requires clone) ---
            if "static" in decision.scan_modules and clone_path:
                await _add_log(db, scan_id, "Starting static analysis...")
                from app.scanner.static.engine import StaticScanEngine

                static_engine = StaticScanEngine()
                static_findings = await static_engine.run_on_path(clone_path)
                findings.extend(static_findings)
                await _add_log(
                    db, scan_id,
                    f"Static analysis complete — {len(static_findings)} findings",
                )

            # --- Nuclei ---
            if "nuclei" in decision.scan_modules:
                try:
                    await _add_log(db, scan_id, "Running Nuclei scanner...")
                    from app.scanner.orchestrator import ToolOrchestrator

                    orchestrator = ToolOrchestrator()
                    nuclei_findings = await orchestrator.run_nuclei(scan.target_url)
                    findings.extend(nuclei_findings)
                    await _add_log(
                        db, scan_id,
                        f"Nuclei scan complete — {len(nuclei_findings)} findings",
                    )
                except Exception as exc:
                    await _add_log(
                        db, scan_id,
                        f"Nuclei scan skipped: {exc}",
                        level="warning",
                    )

            # Log skipped modules
            for mod, reason in decision.skip_reasons.items():
                await _add_log(db, scan_id, f"Module '{mod}' skipped: {reason}", level="warning")

            # ============================================================
            # ANALYSIS + CORRELATION
            # ============================================================
            await _add_log(db, scan_id, "Running analysis and correlation...")
            from app.analysis.scoring import compute_severity_scores
            from app.analysis.correlation import correlate_findings
            from app.analysis.posture import classify_posture

            scored = compute_severity_scores(findings)
            correlated = correlate_findings(scored)
            risk_score, posture = classify_posture(correlated)

            # ============================================================
            # PERSIST FINDINGS
            # ============================================================
            for f in correlated:
                vuln = Vulnerability(
                    scan_id=scan_id,
                    vuln_type=f.get("vuln_type", "unknown"),
                    title=f.get("title", "Untitled"),
                    description=f.get("description"),
                    severity=f.get("severity", "info"),
                    confidence=f.get("confidence", "medium"),
                    cvss_score=f.get("cvss_score"),
                    evidence=f.get("evidence"),
                    location=f.get("location"),
                    detection_source=f.get("detection_source"),
                    remediation=f.get("remediation"),
                    raw_data=str(f.get("raw_data")) if f.get("raw_data") else None,
                )
                db.add(vuln)

            # ============================================================
            # PHASE 3: GEMINI AI SUMMARY
            # ============================================================
            ai_summary_json = None
            if "ai_summary" in decision.scan_modules:
                ai_summary_json = await _phase3_ai_summary(
                    db, scan_id, scan.target_url, scan_type,
                    risk_score, posture.value, correlated, intel_report,
                )

            # ============================================================
            # FINALISE
            # ============================================================
            scan.status = ScanStatus.COMPLETED
            scan.risk_score = risk_score
            scan.posture_rating = posture
            scan.completed_at = datetime.now(timezone.utc)
            scan.updated_at = datetime.now(timezone.utc)
            if ai_summary_json:
                scan.ai_summary = ai_summary_json
            if intel_report:
                scan.repo_intel = intel_report.model_dump_json()
            await db.flush()
            await _add_log(
                db, scan_id,
                f"Scan completed — risk score: {risk_score}, posture: {posture.value}",
            )
            await db.commit()

            return {
                "scan_id": scan_id,
                "total_findings": len(correlated),
                "risk_score": risk_score,
                "posture": posture.value,
                "has_ai_summary": ai_summary_json is not None,
            }

        except Exception as exc:
            logger.exception(f"Scan {scan_id} failed: {exc}")
            scan.status = ScanStatus.FAILED
            scan.completed_at = datetime.now(timezone.utc)
            scan.updated_at = datetime.now(timezone.utc)
            await db.flush()
            await _add_log(db, scan_id, f"Scan failed: {exc}", level="error")
            await db.commit()
            return {"error": str(exc)}

        finally:
            if clone_path:
                from app.services.clone_manager import CloneManager
                await CloneManager().cleanup(clone_path)


# ---------------------------------------------------------------------------
# Phase helpers
# ---------------------------------------------------------------------------

async def _phase1_github_intel(db, scan_id: str, target_url: str):
    """Phase 1: Fetch GitHub API intelligence if target is a GitHub repo."""
    from app.services.github_api import GitHubAPIService, parse_github_url, GitHubAPIError
    from app.services.repo_intelligence import RepoIntelligence

    parsed = parse_github_url(target_url)
    if not parsed:
        await _add_log(db, scan_id, "Target is not a GitHub repo — skipping API intelligence")
        return None

    owner, repo = parsed
    await _add_log(db, scan_id, f"Phase 1: Fetching GitHub intelligence for {owner}/{repo}...")

    github = GitHubAPIService()
    try:
        data = await github.get_full_intelligence(owner, repo)
        intel_engine = RepoIntelligence()
        report = await intel_engine.analyze(
            metadata=data["metadata"],
            tree=data["tree"],
            languages=data["languages"],
            readme=data["readme"],
        )
        await _add_log(
            db, scan_id,
            f"GitHub Intel: {report.file_count} files, "
            f"stack={report.tech_stack}, complexity={report.complexity}",
        )
        return report
    except GitHubAPIError as exc:
        await _add_log(db, scan_id, f"GitHub API error: {exc}", level="warning")
        return None
    except Exception as exc:
        await _add_log(db, scan_id, f"GitHub intelligence failed: {exc}", level="warning")
        return None
    finally:
        await github.close()


async def _phase3_ai_summary(
    db, scan_id: str, target_url: str, scan_type: str,
    risk_score: float, posture: str,
    findings: list, intel_report,
) -> Optional[str]:
    """Phase 3: Generate Gemini AI summary."""
    try:
        await _add_log(db, scan_id, "Phase 3: Generating Gemini AI security summary...")
        from app.analysis.ai_summarizer import AISummarizer

        summarizer = AISummarizer()
        result = await summarizer.summarize(
            target_url=target_url,
            scan_type=scan_type,
            risk_score=risk_score,
            posture_rating=posture,
            findings=findings,
            intel=intel_report,
        )
        if result:
            await _add_log(db, scan_id, "AI summary generated successfully")
            return result.model_dump_json()
        else:
            await _add_log(db, scan_id, "AI summary generation returned empty", level="warning")
            return None
    except Exception as exc:
        await _add_log(db, scan_id, f"AI summary failed: {exc}", level="warning")
        return None


async def _add_log(db: AsyncSession, scan_id: str, message: str, level: str = "info"):
    log = ScanLog(scan_id=scan_id, message=message, level=level)
    db.add(log)
    await db.flush()
