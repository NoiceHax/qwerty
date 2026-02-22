"""Cross-Site Scripting (XSS) detection module."""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

import httpx

logger = logging.getLogger(__name__)
Finding = Dict[str, Any]

# Safe test payloads — designed to detect reflection without causing harm
_XSS_PAYLOADS = [
    '<script>xss_probe_1</script>',
    '"><img src=x onerror=xss_probe_2>',
    "';alert('xss_probe_3');//",
    '<svg onload=xss_probe_4>',
    '{{xss_probe_5}}',               # template injection
    '${xss_probe_6}',                # template literal injection
    '<iframe src="javascript:xss_probe_7">',
    'javascript:xss_probe_8',
    '" onfocus="xss_probe_9" autofocus="',
    '<details open ontoggle=xss_probe_10>',
]

# Patterns indicating the payload was reflected without encoding
_REFLECTION_PATTERNS = [
    re.compile(r'<script>xss_probe_1</script>', re.IGNORECASE),
    re.compile(r'onerror=xss_probe_2', re.IGNORECASE),
    re.compile(r"alert\('xss_probe_3'\)", re.IGNORECASE),
    re.compile(r'onload=xss_probe_4', re.IGNORECASE),
    re.compile(r'\{\{xss_probe_5\}\}'),
    re.compile(r'\$\{xss_probe_6\}'),
    re.compile(r'javascript:xss_probe_7', re.IGNORECASE),
    re.compile(r'javascript:xss_probe_8', re.IGNORECASE),
    re.compile(r'onfocus="xss_probe_9"', re.IGNORECASE),
    re.compile(r'ontoggle=xss_probe_10', re.IGNORECASE),
]

# Test parameter names to inject into
_TEST_PARAMS = ["q", "search", "query", "s", "keyword", "input", "name", "id", "page", "url", "redirect", "callback"]


class XSSDetector:
    """Injects harmless XSS payloads and detects reflected input."""

    async def analyze(self, target_url: str, client: httpx.AsyncClient) -> List[Finding]:
        findings: List[Finding] = []

        # Parse existing query params
        parsed = urlparse(target_url)
        existing_params = parse_qs(parsed.query)

        # Build list of params to test
        params_to_test = list(existing_params.keys()) or _TEST_PARAMS[:5]

        for param in params_to_test:
            for i, payload in enumerate(_XSS_PAYLOADS[:5]):  # limit for speed
                try:
                    test_url = self._build_url(target_url, param, payload)
                    resp = await client.get(test_url)
                    body = resp.text

                    # Check for reflection
                    if i < len(_REFLECTION_PATTERNS) and _REFLECTION_PATTERNS[i].search(body):
                        # Extract snippet around the reflection
                        snippet = self._extract_snippet(body, payload)
                        findings.append({
                            "vuln_type": "xss_reflected",
                            "title": f"Reflected XSS via parameter '{param}'",
                            "description": (
                                f"The payload was reflected in the response without proper encoding. "
                                f"Parameter: {param}"
                            ),
                            "severity": "high",
                            "confidence": "high",
                            "detection_source": "dynamic:xss_detector",
                            "remediation": (
                                f"Sanitize and encode all user input before rendering. "
                                f"Use context-appropriate output encoding for parameter '{param}'. "
                                f"Implement Content-Security-Policy header."
                            ),
                            "evidence": f"Payload: {payload}\nReflected in response:\n{snippet}",
                            "location": test_url,
                        })
                        break  # Found reflection in this param, move to next

                    # Check for raw payload presence (weaker signal)
                    elif payload in body:
                        findings.append({
                            "vuln_type": "xss_potential",
                            "title": f"Potential XSS via parameter '{param}'",
                            "description": (
                                f"Input was reflected in the response. Manual verification recommended."
                            ),
                            "severity": "medium",
                            "confidence": "medium",
                            "detection_source": "dynamic:xss_detector",
                            "remediation": (
                                f"Review input handling for parameter '{param}'. "
                                f"Apply output encoding and CSP headers."
                            ),
                            "evidence": f"Payload: {payload}",
                            "location": test_url,
                        })
                        break

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
    def _extract_snippet(body: str, payload: str, context: int = 100) -> str:
        idx = body.find(payload)
        if idx == -1:
            return ""
        start = max(0, idx - context)
        end = min(len(body), idx + len(payload) + context)
        return body[start:end]
