"""Scan management API endpoints."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.scan import Scan, ScanStatus
from app.models.vulnerability import Vulnerability
from app.schemas.scan import (
    ScanCreateRequest,
    ScanListResponse,
    ScanResponse,
)
from app.schemas.vulnerability import (
    ScanResultsResponse,
    VulnerabilityResponse,
)
from app.safety.validators import (
    ValidationError as TargetValidationError,
    is_github_url,
    validate_github_url,
    validate_target_url,
)
from app.services.scan_service import ScanService

router = APIRouter(prefix="/api/scans", tags=["scans"])


# ---------------------------------------------------------------------------
# POST  /api/scans  — start a new scan
# ---------------------------------------------------------------------------

@router.post("", response_model=ScanResponse, status_code=201)
async def create_scan(
    body: ScanCreateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Queue a new security scan for the given target."""
    # Validate target
    try:
        if is_github_url(body.target_url):
            validate_github_url(body.target_url)
        else:
            validate_target_url(body.target_url)
    except TargetValidationError as exc:
        raise HTTPException(status_code=400, detail=exc.message)

    service = ScanService(db)
    scan = await service.create_scan(
        target_url=body.target_url,
        scan_type=body.scan_type,
        target_type=body.target_type,
    )
    return scan


# ---------------------------------------------------------------------------
# GET  /api/scans  — list scans (paginated)
# ---------------------------------------------------------------------------

@router.get("", response_model=ScanListResponse)
async def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    status: Optional[ScanStatus] = None,
    db: AsyncSession = Depends(get_db),
):
    """Retrieve a paginated list of scans."""
    query = select(Scan).order_by(Scan.created_at.desc())
    count_query = select(func.count(Scan.id))

    if status:
        query = query.where(Scan.status == status)
        count_query = count_query.where(Scan.status == status)

    total = (await db.execute(count_query)).scalar() or 0
    result = await db.execute(query.offset(skip).limit(limit))
    scans = result.scalars().all()

    return ScanListResponse(scans=scans, total=total)


# ---------------------------------------------------------------------------
# GET  /api/scans/{scan_id}  — get scan details
# ---------------------------------------------------------------------------

@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Fetch a single scan by ID."""
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


# ---------------------------------------------------------------------------
# GET  /api/scans/{scan_id}/results  — get scan findings
# ---------------------------------------------------------------------------

@router.get("/{scan_id}/results", response_model=ScanResultsResponse)
async def get_scan_results(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Return all vulnerability findings for a completed scan."""
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    result = await db.execute(
        select(Vulnerability)
        .where(Vulnerability.scan_id == scan_id)
        .order_by(Vulnerability.severity)
    )
    vulns = result.scalars().all()

    # Build severity summary
    by_severity: dict[str, int] = {}
    for v in vulns:
        key = v.severity.value if v.severity else "unknown"
        by_severity[key] = by_severity.get(key, 0) + 1

    return ScanResultsResponse(
        scan_id=scan_id,
        status=scan.status.value,
        risk_score=scan.risk_score,
        posture_rating=scan.posture_rating.value if scan.posture_rating else None,
        vulnerabilities=vulns,
        summary={
            "total_findings": len(vulns),
            "by_severity": by_severity,
        },
    )


# ---------------------------------------------------------------------------
# POST  /api/scans/{scan_id}/cancel  — cancel a running scan
# ---------------------------------------------------------------------------

@router.post("/{scan_id}/cancel", response_model=ScanResponse)
async def cancel_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Cancel a queued or running scan."""
    service = ScanService(db)
    scan = await service.cancel_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


# ---------------------------------------------------------------------------
# GET  /api/scans/{scan_id}/intelligence  — repo intel data
# ---------------------------------------------------------------------------

@router.get("/{scan_id}/intelligence")
async def get_scan_intelligence(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Return GitHub repo intelligence data for a scan."""
    import json as _json
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    if not scan.repo_intel:
        raise HTTPException(status_code=404, detail="No repo intelligence available for this scan.")
    return _json.loads(scan.repo_intel)


# ---------------------------------------------------------------------------
# GET  /api/scans/{scan_id}/ai-summary  — Gemini AI analysis
# ---------------------------------------------------------------------------

@router.get("/{scan_id}/ai-summary")
async def get_ai_summary(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Return the Gemini AI security summary for a scan."""
    import json as _json
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    if not scan.ai_summary:
        raise HTTPException(status_code=404, detail="No AI summary available. Scan may still be running or Gemini is not configured.")
    return _json.loads(scan.ai_summary)

