"""Scan lifecycle management service."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Scan, ScanLog, ScanStatus, ScanType, TargetType

logger = logging.getLogger(__name__)


class ScanService:
    """Handles scan creation, status updates, and cancellation."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    async def create_scan(
        self,
        target_url: str,
        scan_type: ScanType,
        target_type: TargetType,
    ) -> Scan:
        scan = Scan(
            target_url=target_url,
            scan_type=scan_type,
            target_type=target_type,
            status=ScanStatus.QUEUED,
        )
        self.db.add(scan)
        await self.db.flush()
        await self.db.refresh(scan)

        # Try to enqueue the background job
        try:
            from app.jobs.manager import JobManager

            job_manager = JobManager()
            job_id = job_manager.enqueue_scan(scan.id, scan_type.value)
            scan.job_id = job_id
            await self.db.flush()
        except Exception as exc:
            logger.warning(
                f"Could not enqueue job (Redis may be unavailable): {exc}. "
                f"Scan {scan.id} is queued but will need manual processing."
            )

        return scan

    # ------------------------------------------------------------------
    # Status management
    # ------------------------------------------------------------------

    async def update_status(
        self,
        scan_id: str,
        status: ScanStatus,
        risk_score: float | None = None,
        posture_rating=None,
    ) -> Scan | None:
        scan = await self.db.get(Scan, scan_id)
        if not scan:
            return None

        scan.status = status
        scan.updated_at = datetime.now(timezone.utc)

        if status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
            scan.completed_at = datetime.now(timezone.utc)

        if risk_score is not None:
            scan.risk_score = risk_score
        if posture_rating is not None:
            scan.posture_rating = posture_rating

        await self.db.flush()
        return scan

    # ------------------------------------------------------------------
    # Cancel
    # ------------------------------------------------------------------

    async def cancel_scan(self, scan_id: str) -> Scan | None:
        scan = await self.db.get(Scan, scan_id)
        if not scan:
            return None

        if scan.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
            return scan  # Already terminal

        scan.status = ScanStatus.CANCELLED
        scan.updated_at = datetime.now(timezone.utc)
        scan.completed_at = datetime.now(timezone.utc)

        # Try to cancel background job
        try:
            from app.jobs.manager import JobManager

            JobManager().cancel_job(scan.job_id)
        except Exception:
            pass

        await self.db.flush()
        return scan

    # ------------------------------------------------------------------
    # Logging helper
    # ------------------------------------------------------------------

    async def add_log(
        self, scan_id: str, message: str, level: str = "info"
    ) -> None:
        log_entry = ScanLog(scan_id=scan_id, message=message, level=level)
        self.db.add(log_entry)
        await self.db.flush()
