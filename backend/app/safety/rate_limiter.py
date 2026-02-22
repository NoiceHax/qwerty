"""API rate limiter middleware using in-memory + optional Redis backing."""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Dict, Tuple

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse

from app.config import settings


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple sliding-window rate limiter per client IP."""

    def __init__(self, app, max_requests: int | None = None, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests or settings.rate_limit_per_minute
        self.window = window_seconds
        # In-memory store: ip -> list of request timestamps
        self._hits: Dict[str, list] = defaultdict(list)

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Skip rate limiting for docs, health, static files, GETs, and WebSockets
        skip_paths = ("/docs", "/redoc", "/openapi.json", "/api/health", "/ws/")
        if any(request.url.path.startswith(p) for p in skip_paths):
            return await call_next(request)

        # Only rate-limit mutations (POST/PUT/DELETE), not reads
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return await call_next(request)

        # Skip static files
        if not request.url.path.startswith("/api"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        window_start = now - self.window

        # Prune old hits
        self._hits[client_ip] = [
            t for t in self._hits[client_ip] if t > window_start
        ]

        if len(self._hits[client_ip]) >= self.max_requests:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded. Try again later.",
                    "retry_after": self.window,
                },
                headers={"Retry-After": str(self.window)},
            )

        self._hits[client_ip].append(now)
        response = await call_next(request)
        remaining = max(0, self.max_requests - len(self._hits[client_ip]))
        response.headers["X-RateLimit-Limit"] = str(self.max_requests)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response
