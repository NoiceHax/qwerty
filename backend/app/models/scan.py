"""Scan & ScanLog ORM models."""

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    Float,
    Index,
    String,
    Text,
    ForeignKey,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import relationship

from app.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


def _new_uuid():
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(str, enum.Enum):
    DYNAMIC = "dynamic"
    STATIC = "static"
    FULL = "full"


class TargetType(str, enum.Enum):
    URL = "url"
    REPO = "repo"
    ZIP = "zip"


class PostureRating(str, enum.Enum):
    LOW_RISK = "low_risk"
    MODERATE_RISK = "moderate_risk"
    HIGH_RISK = "high_risk"
    CRITICAL_RISK = "critical_risk"


# ---------------------------------------------------------------------------
# Scan model
# ---------------------------------------------------------------------------

class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    target_url = Column(String(2048), nullable=False)
    target_type = Column(Enum(TargetType), nullable=False, default=TargetType.URL)
    scan_type = Column(Enum(ScanType), nullable=False, default=ScanType.DYNAMIC)
    status = Column(
        Enum(ScanStatus), nullable=False, default=ScanStatus.QUEUED, index=True
    )

    # Scores (populated after analysis)
    risk_score = Column(Float, nullable=True)
    posture_rating = Column(Enum(PostureRating), nullable=True)

    # AI & intelligence (populated after scan)
    ai_summary = Column(Text, nullable=True)    # JSON of AISummaryOutput
    repo_intel = Column(Text, nullable=True)     # JSON of RepoIntelReport

    # Job tracking
    job_id = Column(String(128), nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    vulnerabilities = relationship(
        "Vulnerability", back_populates="scan", cascade="all, delete-orphan"
    )
    logs = relationship(
        "ScanLog", back_populates="scan", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_scans_created_at", "created_at"),
    )


# ---------------------------------------------------------------------------
# ScanLog model  (used for real-time progress streaming)
# ---------------------------------------------------------------------------

class ScanLog(Base):
    __tablename__ = "scan_logs"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    scan_id = Column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    message = Column(Text, nullable=False)
    level = Column(String(16), nullable=False, default="info")  # info / warning / error
    timestamp = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    scan = relationship("Scan", back_populates="logs")
