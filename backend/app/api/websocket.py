"""WebSocket endpoint for realtime scan progress streaming."""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.scan import Scan, ScanLog, ScanStatus

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/scans/{scan_id}")
async def scan_progress_ws(websocket: WebSocket, scan_id: str):
    """Stream scan logs & status updates over WebSocket.

    The client connects and receives JSON messages:
        {"type": "status", "data": {"status": "running", ...}}
        {"type": "log",    "data": {"message": "...", "level": "info", ...}}
        {"type": "done",   "data": {"status": "completed", "risk_score": 7.2}}
    """
    await websocket.accept()

    last_log_id: str | None = None

    try:
        while True:
            async with async_session_factory() as db:
                # Fetch current scan state
                scan = await db.get(Scan, scan_id)
                if not scan:
                    await websocket.send_json(
                        {"type": "error", "data": {"message": "Scan not found"}}
                    )
                    break

                # Send status update
                await websocket.send_json(
                    {
                        "type": "status",
                        "data": {
                            "status": scan.status.value,
                            "risk_score": scan.risk_score,
                            "posture_rating": (
                                scan.posture_rating.value
                                if scan.posture_rating
                                else None
                            ),
                        },
                    }
                )

                # Stream new logs
                log_query = (
                    select(ScanLog)
                    .where(ScanLog.scan_id == scan_id)
                    .order_by(ScanLog.timestamp)
                )
                if last_log_id:
                    log_query = log_query.where(ScanLog.id > last_log_id)

                result = await db.execute(log_query)
                logs = result.scalars().all()

                for log in logs:
                    await websocket.send_json(
                        {
                            "type": "log",
                            "data": {
                                "message": log.message,
                                "level": log.level,
                                "timestamp": log.timestamp.isoformat(),
                            },
                        }
                    )
                    last_log_id = log.id

                # If scan finished, send done and close
                if scan.status in (
                    ScanStatus.COMPLETED,
                    ScanStatus.FAILED,
                    ScanStatus.CANCELLED,
                ):
                    await websocket.send_json(
                        {
                            "type": "done",
                            "data": {
                                "status": scan.status.value,
                                "risk_score": scan.risk_score,
                            },
                        }
                    )
                    break

            # Poll interval
            await asyncio.sleep(2)

    except WebSocketDisconnect:
        pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
