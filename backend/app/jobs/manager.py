"""Background job manager — Redis + RQ integration."""

from __future__ import annotations

import logging
from typing import Optional

from app.config import settings

logger = logging.getLogger(__name__)

# Lazy-init to avoid import-time crashes when Redis is unavailable
_redis_conn = None
_queue = None


def _get_redis():
    global _redis_conn
    if _redis_conn is None:
        import redis as redis_lib
        _redis_conn = redis_lib.Redis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=5,
        )
    return _redis_conn


def _get_queue():
    global _queue
    if _queue is None:
        from rq import Queue
        _queue = Queue("scans", connection=_get_redis())
    return _queue


class JobManager:
    """Thin wrapper around RQ for scan job lifecycle."""

    def enqueue_scan(self, scan_id: str, scan_type: str) -> str:
        """Enqueue a scan task and return the RQ job ID."""
        q = _get_queue()
        job = q.enqueue(
            "app.jobs.tasks.execute_scan",
            scan_id,
            scan_type,
            job_timeout=settings.scan_timeout_seconds,
            result_ttl=86400,  # keep results for 24 h
            failure_ttl=86400,
            retry=None,  # we handle retries inside the task
        )
        logger.info(f"Enqueued scan {scan_id} as job {job.id}")
        return job.id

    def get_job_status(self, job_id: str) -> Optional[str]:
        """Return current job status string or None."""
        if not job_id:
            return None
        try:
            from rq.job import Job
            job = Job.fetch(job_id, connection=_get_redis())
            return job.get_status()
        except Exception:
            return None

    def cancel_job(self, job_id: str) -> bool:
        """Attempt to cancel a running / queued job."""
        if not job_id:
            return False
        try:
            from rq.job import Job
            job = Job.fetch(job_id, connection=_get_redis())
            job.cancel()
            logger.info(f"Cancelled job {job_id}")
            return True
        except Exception as exc:
            logger.warning(f"Could not cancel job {job_id}: {exc}")
            return False

    def get_queue_size(self) -> int:
        try:
            return len(_get_queue())
        except Exception:
            return -1
