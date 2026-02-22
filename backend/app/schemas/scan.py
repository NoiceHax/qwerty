"""Pydantic request / response schemas for scans."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field, HttpUrl

from app.models.scan import PostureRating, ScanStatus, ScanType, TargetType


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------

class ScanCreateRequest(BaseModel):
    """Body for POST /api/scans."""
    target_url: str = Field(..., max_length=2048, description="URL or GitHub repo link")
    scan_type: ScanType = Field(ScanType.DYNAMIC, description="dynamic / static / full")
    target_type: TargetType = Field(TargetType.URL, description="url / repo / zip")


class ScanCancelRequest(BaseModel):
    reason: Optional[str] = None


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------

class ScanResponse(BaseModel):
    id: str
    target_url: str
    target_type: TargetType
    scan_type: ScanType
    status: ScanStatus
    risk_score: Optional[float] = None
    posture_rating: Optional[PostureRating] = None
    ai_summary: Optional[str] = None
    repo_intel: Optional[str] = None
    job_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    scans: List[ScanResponse]
    total: int


class ScanLogResponse(BaseModel):
    id: str
    message: str
    level: str
    timestamp: datetime

    model_config = {"from_attributes": True}
