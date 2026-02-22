"""Rate limiting detection module."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List

import httpx

logger = logging.getLogger(__name__)
Finding = Dict[str, Any]


class RateLimitDetector:
    """Simulates burst requests to detect absence of rate limiting."""

    BURST_SIZE = 20
    BURST_DELAY = 0.05  # seconds between requests

    async def analyze(self, target_url: str, client: httpx.AsyncClient) -> List[Finding]:
        findings: List[Finding] = []

        statuses: List[int] = []
        response_times: List[float] = []

        for i in range(self.BURST_SIZE):
            try:
                start = time.monotonic()
                resp = await client.get(target_url)
                elapsed = time.monotonic() - start
                statuses.append(resp.status_code)
                response_times.append(elapsed)

                # Early exit if rate limited
                if resp.status_code == 429:
                    break

                await asyncio.sleep(self.BURST_DELAY)
            except httpx.RequestError:
                break

        # Analyse results
        rate_limited = any(s == 429 for s in statuses)
        has_rate_headers = False

        # Check last response for rate limit headers
        try:
            resp = await client.get(target_url)
            rate_headers = [
                "x-ratelimit-limit",
                "x-ratelimit-remaining",
                "x-ratelimit-reset",
                "retry-after",
                "ratelimit-limit",
                "ratelimit-remaining",
            ]
            has_rate_headers = any(h in resp.headers for h in rate_headers)
        except Exception:
            pass

        if not rate_limited and not has_rate_headers:
            findings.append({
                "vuln_type": "no_rate_limiting",
                "title": "No rate limiting detected",
                "description": (
                    f"Sent {len(statuses)} rapid requests without receiving a 429 response "
                    f"or rate limit headers. The endpoint may be vulnerable to brute force "
                    f"or denial-of-service attacks."
                ),
                "severity": "medium",
                "confidence": "medium",
                "detection_source": "dynamic:rate_limit_detector",
                "remediation": (
                    "Implement rate limiting (e.g., 100 requests/minute per IP). "
                    "Use tools like nginx rate limiting, API gateways, or middleware. "
                    "Return 429 status with Retry-After header when limits are exceeded."
                ),
                "evidence": (
                    f"Burst size: {len(statuses)} requests\n"
                    f"Status codes: {statuses}\n"
                    f"Avg response time: {sum(response_times)/len(response_times):.3f}s"
                    if response_times else "No responses received"
                ),
                "location": target_url,
            })
        elif rate_limited:
            findings.append({
                "vuln_type": "rate_limiting_present",
                "title": "Rate limiting detected",
                "description": f"Server returned 429 after {statuses.index(429) + 1} requests.",
                "severity": "info",
                "confidence": "high",
                "detection_source": "dynamic:rate_limit_detector",
                "remediation": "Rate limiting is properly configured.",
                "location": target_url,
            })

        # Check specifically for login/auth endpoints
        login_paths = ["/login", "/auth", "/signin", "/api/auth", "/api/login"]
        for path in login_paths:
            try:
                full_url = target_url.rstrip("/") + path
                resp = await client.get(full_url)
                if resp.status_code in (200, 401, 405):
                    # This is a login-like endpoint — check rate limiting
                    limited = False
                    for _ in range(10):
                        r = await client.post(
                            full_url,
                            data={"username": "test", "password": "test"},
                        )
                        if r.status_code == 429:
                            limited = True
                            break

                    if not limited:
                        findings.append({
                            "vuln_type": "login_no_rate_limit",
                            "title": f"Login endpoint '{path}' lacks rate limiting",
                            "description": (
                                f"Authentication endpoint {path} does not enforce rate limiting, "
                                f"making it susceptible to brute force attacks."
                            ),
                            "severity": "high",
                            "confidence": "medium",
                            "detection_source": "dynamic:rate_limit_detector",
                            "remediation": (
                                "Implement strict rate limiting on authentication endpoints. "
                                "Consider account lockout after failed attempts and CAPTCHA."
                            ),
                            "location": full_url,
                        })
            except httpx.RequestError:
                continue

        return findings
