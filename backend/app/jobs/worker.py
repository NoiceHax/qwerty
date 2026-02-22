"""RQ worker bootstrap script.

Usage:
    python -m app.jobs.worker
"""

import logging
import platform
import sys

from redis import Redis
from rq import Worker, SimpleWorker
from rq.timeouts import BaseDeathPenalty

from app.config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class WindowsDeathPenalty(BaseDeathPenalty):
    """No-op timeout for Windows (SIGALRM doesn't exist)."""

    def setup_death_penalty(self):
        pass

    def cancel_death_penalty(self):
        pass


class WindowsSimpleWorker(SimpleWorker):
    """SimpleWorker with no-op timeout for Windows."""
    death_penalty_class = WindowsDeathPenalty


def main():
    redis_conn = Redis.from_url(settings.redis_url, decode_responses=False)
    queues = ["scans"]

    logger.info(f"Starting RQ worker on queues: {queues}")
    logger.info(f"Redis: {settings.redis_url}")

    # Windows doesn't support os.fork() or SIGALRM
    if platform.system() == "Windows":
        logger.info("Windows detected — using SimpleWorker (no fork, no SIGALRM)")
        worker = WindowsSimpleWorker(queues, connection=redis_conn)
    else:
        worker = Worker(queues, connection=redis_conn)

    worker.work(with_scheduler=False)


if __name__ == "__main__":
    main()
