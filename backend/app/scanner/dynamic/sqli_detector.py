"""SQL Injection signal detection module."""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List
from urllib.parse import urlencode, urlparse, parse_qs

import httpx

logger = logging.getLogger(__name__)
Finding = Dict[str, Any]

# Harmless SQL injection test patterns
_SQLI_PAYLOADS = [
    "'",
    "''",
    "1' OR '1'='1",
    "1 OR 1=1",
    "1' OR '1'='1' --",
    "1; SELECT 1--",
    "1 UNION SELECT NULL--",
    "' UNION SELECT NULL, NULL--",
    "1' AND '1'='1",
    "admin'--",
]

# Error patterns indicating SQL injection vulnerability
_SQL_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning.*mysql", re.I),
    re.compile(r"unclosed quotation mark", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"pg_query.*error", re.I),
    re.compile(r"syntax error at or near", re.I),
    re.compile(r"microsoft.*odbc.*sql.*server", re.I),
    re.compile(r"oracle.*error", re.I),
    re.compile(r"sqlite3?\.OperationalError", re.I),
    re.compile(r"PostgreSQL.*ERROR", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"mysql_fetch", re.I),
    re.compile(r"mysqli_", re.I),
    re.compile(r"com\.mysql\.jdbc", re.I),
    re.compile(r"Traceback \(most recent call last\)", re.I),
    re.compile(r"PDOException", re.I),
    re.compile(r"SqlException", re.I),
    re.compile(r"System\.Data\.SqlClient", re.I),
    re.compile(r"SQLSTATE\[", re.I),
    re.compile(r"unrecognized token", re.I),
]

# Stack trace / debug patterns
_DEBUG_PATTERNS = [
    re.compile(r"stack trace:", re.I),
    re.compile(r"at [\w\.]+\([\w\.]+:\d+\)", re.I),
    re.compile(r"File \".*\", line \d+", re.I),
]

_TEST_PARAMS = ["id", "q", "search", "user", "name", "page", "category", "item", "product"]


class SQLiDetector:
    """Injects harmless SQL test patterns and detects error-based SQLi signals."""

    async def analyze(self, target_url: str, client: httpx.AsyncClient) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(target_url)
        existing_params = parse_qs(parsed.query)
        params_to_test = list(existing_params.keys()) or _TEST_PARAMS[:4]

        # Get baseline response for comparison
        try:
            baseline = await client.get(target_url)
            baseline_length = len(baseline.text)
        except Exception:
            baseline_length = 0

        for param in params_to_test:
            for payload in _SQLI_PAYLOADS[:5]:  # limit for speed
                try:
                    test_url = self._build_url(target_url, param, payload)
                    resp = await client.get(test_url)
                    body = resp.text

                    # Check for SQL error messages
                    for pattern in _SQL_ERROR_PATTERNS:
                        match = pattern.search(body)
                        if match:
                            findings.append({
                                "vuln_type": "sqli_error_based",
                                "title": f"SQL Injection signal via parameter '{param}'",
                                "description": (
                                    f"SQL error message detected in response when injecting "
                                    f"test payload into parameter '{param}'."
                                ),
                                "severity": "critical",
                                "confidence": "high",
                                "detection_source": "dynamic:sqli_detector",
                                "remediation": (
                                    f"Use parameterized queries (prepared statements) for all database operations. "
                                    f"Never concatenate user input into SQL strings. "
                                    f"Review parameter '{param}' handling."
                                ),
                                "evidence": (
                                    f"Payload: {payload}\n"
                                    f"SQL error pattern: {match.group()}\n"
                                    f"Response snippet: {self._snippet(body, match.start())}"
                                ),
                                "location": test_url,
                            })
                            break

                    # Check for stack trace / debug info leakage
                    for pattern in _DEBUG_PATTERNS:
                        match = pattern.search(body)
                        if match:
                            findings.append({
                                "vuln_type": "debug_info_leak",
                                "title": f"Stack trace exposed via parameter '{param}'",
                                "description": "Debug information leaked in response.",
                                "severity": "medium",
                                "confidence": "high",
                                "detection_source": "dynamic:sqli_detector",
                                "remediation": (
                                    "Disable debug mode in production. "
                                    "Use custom error pages that don't expose internals."
                                ),
                                "evidence": f"Payload: {payload}\nTrace: {self._snippet(body, match.start())}",
                                "location": test_url,
                            })
                            break

                    # Response size anomaly (potential boolean-based SQLi)
                    if baseline_length > 0:
                        change = abs(len(body) - baseline_length) / baseline_length
                        if change > 0.5 and resp.status_code == 200:
                            findings.append({
                                "vuln_type": "sqli_potential",
                                "title": f"Potential SQL injection via parameter '{param}'",
                                "description": (
                                    f"Response size changed significantly ({int(change*100)}%) "
                                    f"with SQL test payload. May indicate boolean-based SQLi."
                                ),
                                "severity": "medium",
                                "confidence": "low",
                                "detection_source": "dynamic:sqli_detector",
                                "remediation": "Investigate parameter handling and use parameterized queries.",
                                "evidence": f"Payload: {payload}\nBaseline size: {baseline_length}, Response size: {len(body)}",
                                "location": test_url,
                            })

                except httpx.RequestError:
                    continue

        return findings

    @staticmethod
    def _build_url(base_url: str, param: str, value: str) -> str:
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)
        params[param] = [value]
        flat = {k: v[0] for k, v in params.items()}
        return f"{base}?{urlencode(flat)}"

    @staticmethod
    def _snippet(body: str, pos: int, context: int = 150) -> str:
        start = max(0, pos - 50)
        end = min(len(body), pos + context)
        return body[start:end].strip()
