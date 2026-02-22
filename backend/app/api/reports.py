"""Report generation API endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.scan import Scan
from app.services.report_service import ReportService

router = APIRouter(prefix="/api/scans", tags=["reports"])


@router.get("/{scan_id}/report")
async def generate_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Generate a structured security report for a completed scan."""
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    service = ReportService(db)
    report = await service.generate_report(scan_id)
    return report
