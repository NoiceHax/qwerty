"""Report generation service."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Scan
from app.models.vulnerability import Vulnerability


class ReportService:
    """Generates structured security assessment reports."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def generate_report(self, scan_id: str) -> Dict[str, Any]:
        scan = await self.db.get(Scan, scan_id)
        if not scan:
            return {"error": "Scan not found"}

        result = await self.db.execute(
            select(Vulnerability)
            .where(Vulnerability.scan_id == scan_id)
            .order_by(Vulnerability.severity)
        )
        vulns = result.scalars().all()

        # Group by severity
        by_severity: Dict[str, list] = {}
        for v in vulns:
            key = v.severity.value
            by_severity.setdefault(key, []).append(self._vuln_to_dict(v))

        # Confidence breakdown
        confidence_stats = {"high": 0, "medium": 0, "low": 0}
        for v in vulns:
            confidence_stats[v.confidence.value] = (
                confidence_stats.get(v.confidence.value, 0) + 1
            )

        return {
            "report": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "scan_id": scan_id,

                # Executive summary
                "executive_summary": {
                    "target": scan.target_url,
                    "scan_type": scan.scan_type.value,
                    "overall_risk_score": scan.risk_score,
                    "posture_rating": (
                        scan.posture_rating.value if scan.posture_rating else None
                    ),
                    "total_findings": len(vulns),
                    "critical_count": len(by_severity.get("critical", [])),
                    "high_count": len(by_severity.get("high", [])),
                    "medium_count": len(by_severity.get("medium", [])),
                    "low_count": len(by_severity.get("low", [])),
                    "info_count": len(by_severity.get("info", [])),
                },

                # Vulnerability breakdown
                "vulnerability_breakdown": by_severity,

                # Confidence indicators
                "confidence_overview": confidence_stats,

                # Remediation summary
                "remediation_summary": self._build_remediation_summary(vulns),
            }
        }

    def _vuln_to_dict(self, v: Vulnerability) -> Dict[str, Any]:
        return {
            "id": v.id,
            "type": v.vuln_type,
            "title": v.title,
            "description": v.description,
            "severity": v.severity.value,
            "confidence": v.confidence.value,
            "cvss_score": v.cvss_score,
            "evidence": v.evidence,
            "location": v.location,
            "detection_source": v.detection_source,
            "remediation": v.remediation,
        }

    def _build_remediation_summary(self, vulns) -> list:
        """Group unique remediation suggestions by priority."""
        seen = set()
        items = []
        for v in vulns:
            if v.remediation and v.remediation not in seen:
                seen.add(v.remediation)
                items.append(
                    {
                        "severity": v.severity.value,
                        "vulnerability": v.title,
                        "action": v.remediation,
                    }
                )
        return items
