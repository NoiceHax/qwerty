"""Multi-signal endpoint validation system for reducing false positives.

This module implements a sophisticated endpoint existence verification system that
combines multiple heuristics to distinguish real endpoints from SPA fallbacks,
soft 404 pages, and catch-all routers.

Signals used:
  1. HTTP status code
  2. Response length similarity
  3. Content hash/similarity
  4. HTML structural similarity
  5. Soft 404 detection
  6. Redirect behavior
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Optional, Tuple

import httpx

logger = logging.getLogger(__name__)


# ============================================================================
# Soft Error Detection
# ============================================================================

class SoftErrorDetector:
    """Detects soft error pages and generic fallback responses."""

    # Common error keywords that appear in soft 404s
    ERROR_KEYWORDS = {
        # Generic error messages
        "not found", "page not found", "404", "error", "invalid",
        "doesn't exist", "do not exist", "not exist", "no such",
        "not available", "unavailable", "discontinued", "removed",
        # Framework-specific
        "application error", "server error", "internal error",
        "unhandled exception", "caught exception", "exception occurred",
        # Router fallbacks
        "route not found", "no route", "catch all", "fallback",
        "default page", "home page", "index page",
    }

    # Framework signatures in error pages/titles
    FRAMEWORK_SIGNATURES = {
        "Symfony": r"Symfony.*Exception|SymfonyComponents",
        "Laravel": r"Laravel|Illuminate|Handler\.php",
        "Django": r"Django Version|TemplateDoesNotExist|Page not found",
        "Rails": r"Rails|ActionController::|ActiveRecord::",
        "Express": r"Cannot GET|Express|nodejs",
        "Flask": r"Flask|werkzeug|traceback",
        "ASP.NET": r"ASP\.NET|web\.config|App_\w+",
        "Spring": r"Spring|Whitelabel Error|Spring Framework",
        "Java": r"java\..*Exception|tomcat|apache",
    }

    @staticmethod
    def is_soft_error(content: str, status_code: int) -> bool:
        """Detect if response is a soft error page.

        Args:
            content: Response body
            status_code: HTTP status code

        Returns:
            True if classified as soft error, False otherwise
        """
        if not content:
            return False

        content_lower = content.lower()

        # Check for error keywords (case-insensitive)
        error_keyword_count = sum(
            1 for keyword in SoftErrorDetector.ERROR_KEYWORDS
            if keyword in content_lower
        )

        if error_keyword_count >= 2:  # 2+ error keywords = likely soft error
            return True

        # Check for framework signatures
        for framework, pattern in SoftErrorDetector.FRAMEWORK_SIGNATURES.items():
            if re.search(pattern, content, re.IGNORECASE):
                return True

        # Status 200 with large amount of error keywords is suspicious
        if status_code == 200 and error_keyword_count >= 1:
            return True

        return False

    @staticmethod
    def extract_error_indicators(content: str) -> dict:
        """Extract error indicators from response.

        Returns:
            Dict with 'error_keywords', 'framework_hints', 'is_error_page'
        """
        error_keywords = [
            kw for kw in SoftErrorDetector.ERROR_KEYWORDS
            if kw in content.lower()
        ]

        framework_hints = [
            fw for fw, pattern in SoftErrorDetector.FRAMEWORK_SIGNATURES.items()
            if re.search(pattern, content, re.IGNORECASE)
        ]

        return {
            "error_keywords": error_keywords,
            "framework_hints": framework_hints,
            "is_error_page": len(error_keywords) >= 2 or len(framework_hints) > 0,
        }


# ============================================================================
# Response Fingerprinting
# ============================================================================

class HTMLTitleExtractor(HTMLParser):
    """Extract <title> from HTML safely."""

    def __init__(self):
        super().__init__()
        self.title = None
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "title":
            self.in_title = True

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title = data.strip()


@dataclass
class ResponseFingerprint:
    """Fingerprint of an HTTP response for comparison."""

    status_code: int
    content_length: int
    content_hash: str  # SHA256 of body
    body_sample: str  # First 1000 chars for inspection
    html_title: Optional[str]
    headers_dict: dict
    has_redirect_meta: bool


class FingerprintBuilder:
    """Build response fingerprints for comparison."""

    @staticmethod
    def build(resp: httpx.Response) -> ResponseFingerprint:
        """Create fingerprint from HTTP response."""
        body = resp.text or ""
        body_bytes = resp.content

        # Hash the response body
        content_hash = hashlib.sha256(body_bytes).hexdigest()

        # Extract title from HTML
        html_title = None
        try:
            extractor = HTMLTitleExtractor()
            extractor.feed(body[:5000])  # Only parse first 5KB
            html_title = extractor.title
        except Exception:
            pass

        # Check for redirect meta tags
        has_redirect_meta = bool(
            re.search(
                r'<meta\s+http-equiv\s*=\s*["\']refresh["\']',
                body,
                re.IGNORECASE
            )
        )

        return ResponseFingerprint(
            status_code=resp.status_code,
            content_length=len(body_bytes),
            content_hash=content_hash,
            body_sample=body[:1000],
            html_title=html_title,
            headers_dict=dict(resp.headers),
            has_redirect_meta=has_redirect_meta,
        )


# ============================================================================
# Content Similarity Analysis
# ============================================================================

class SimilarityAnalyzer:
    """Analyze similarity between two responses using multiple heuristics."""

    @staticmethod
    def length_similarity(fp1: ResponseFingerprint, fp2: ResponseFingerprint) -> float:
        """Calculate similarity based on response length.

        Returns:
            Float 0.0-1.0 where 1.0 = identical length
        """
        if fp1.content_length == 0 and fp2.content_length == 0:
            return 1.0

        max_len = max(fp1.content_length, fp2.content_length)
        if max_len == 0:
            return 1.0

        min_len = min(fp1.content_length, fp2.content_length)
        return min_len / max_len

    @staticmethod
    def hash_similarity(fp1: ResponseFingerprint, fp2: ResponseFingerprint) -> float:
        """Calculate similarity based on content hash.

        Returns:
            1.0 if identical, 0.0 if different
        """
        return 1.0 if fp1.content_hash == fp2.content_hash else 0.0

    @staticmethod
    def title_similarity(fp1: ResponseFingerprint, fp2: ResponseFingerprint) -> float:
        """Calculate similarity based on HTML title.

        Returns:
            1.0 if same title, 0.0 if different/missing
        """
        if not fp1.html_title or not fp2.html_title:
            return 0.0

        if fp1.html_title.lower() == fp2.html_title.lower():
            return 1.0

        return 0.0

    @staticmethod
    def levenshtein_distance(s1: str, s2: str) -> int:
        """Calculate Levenshtein distance (edit distance)."""
        if len(s1) < len(s2):
            return SimilarityAnalyzer.levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    @staticmethod
    def body_sample_similarity(fp1: ResponseFingerprint, fp2: ResponseFingerprint) -> float:
        """Calculate string similarity using Levenshtein distance.

        Returns:
            Float 0.0-1.0 where 1.0 = identical
        """
        s1 = fp1.body_sample
        s2 = fp2.body_sample

        if not s1 or not s2:
            return 0.0

        max_len = max(len(s1), len(s2))
        distance = SimilarityAnalyzer.levenshtein_distance(s1, s2)

        return 1.0 - (distance / max_len)

    @staticmethod
    def compute_composite_similarity(
        baseline: ResponseFingerprint,
        endpoint: ResponseFingerprint,
    ) -> Tuple[float, dict]:
        """Compute overall similarity score using all heuristics.

        Returns:
            Tuple of (composite_score: 0.0-1.0, details: dict)
        """
        length_sim = SimilarityAnalyzer.length_similarity(baseline, endpoint)
        hash_sim = SimilarityAnalyzer.hash_similarity(baseline, endpoint)
        title_sim = SimilarityAnalyzer.title_similarity(baseline, endpoint)
        body_sim = SimilarityAnalyzer.body_sample_similarity(baseline, endpoint)

        # Weighted composite score
        # Hash match is strongest signal, title match is weaker
        weights = {
            "hash": 0.35,
            "length": 0.30,
            "body_sample": 0.20,
            "title": 0.15,
        }

        composite = (
            hash_sim * weights["hash"]
            + length_sim * weights["length"]
            + body_sim * weights["body_sample"]
            + title_sim * weights["title"]
        )

        return composite, {
            "hash_similarity": hash_sim,
            "length_similarity": length_sim,
            "body_similarity": body_sim,
            "title_similarity": title_sim,
            "composite": composite,
        }


# ============================================================================
# Multi-Signal Endpoint Validator
# ============================================================================

@dataclass
class EndpointValidationResult:
    """Result of endpoint validation with all signal details."""

    exists: bool  # Final determination: endpoint exists or not
    status_code: int
    confidence: str  # "high", "medium", "low"
    severity: str  # "critical", "high", "medium", "low", "info"

    # Signal scores (each 0.0-1.0)
    status_code_signal: float
    similarity_signal: float
    soft_error_signal: float
    redirect_signal: float

    # Detailed info
    is_soft_error: bool
    soft_error_indicators: dict
    similarity_details: dict
    reason: str  # Explanation of decision


class EndpointValidator:
    """Multi-signal endpoint existence validator."""

    # Status codes that definitely indicate endpoint existence
    EXISTENCE_STATUS_CODES = {200, 201, 202, 204, 206}

    # Status codes that indicate authentication/authorization (endpoint likely exists)
    AUTH_STATUS_CODES = {401, 403}

    # Status codes that indicate endpoint not found (need other signals)
    NOT_FOUND_STATUS_CODES = {404}

    # Status codes that indicate redirect
    REDIRECT_STATUS_CODES = {301, 302, 307, 308}

    @staticmethod
    def validate(
        endpoint_path: str,
        baseline_fp: ResponseFingerprint,
        endpoint_response: httpx.Response,
    ) -> EndpointValidationResult:
        """Validate if endpoint truly exists using multi-signal approach.

        Args:
            endpoint_path: The endpoint path being probed
            baseline_fp: Fingerprint of root (/) response
            endpoint_response: The response from probing endpoint

        Returns:
            EndpointValidationResult with detailed validation info
        """
        endpoint_fp = FingerprintBuilder.build(endpoint_response)
        status = endpoint_response.status_code
        body = endpoint_response.text or ""

        # Signal 1: Status Code Analysis
        status_code_signal, status_reason = EndpointValidator._analyze_status_code(
            status
        )

        # Signal 2: Soft Error Detection
        is_soft_error = SoftErrorDetector.is_soft_error(body, status)
        soft_error_indicators = SoftErrorDetector.extract_error_indicators(body)
        soft_error_signal = 1.0 if is_soft_error else 0.0

        # Signal 3: Content Similarity (comparing to baseline)
        similarity_score, similarity_details = (
            SimilarityAnalyzer.compute_composite_similarity(baseline_fp, endpoint_fp)
        )
        # High similarity = likely falling back to baseline (not real endpoint)
        similarity_signal = similarity_score

        # Signal 4: Redirect Detection
        has_redirect_meta = endpoint_fp.has_redirect_meta
        redirect_signal = 0.0
        redirect_reason = "no redirect"
        if status in EndpointValidator.REDIRECT_STATUS_CODES:
            redirect_signal = 0.2  # Redirects are inconclusive
            redirect_reason = "HTTP redirect detected"
        elif has_redirect_meta:
            redirect_signal = 0.2
            redirect_reason = "Meta refresh detected"

        # Multi-Signal Decision Logic
        exists, confidence, severity, reason = EndpointValidator._make_decision(
            status=status,
            endpoint_path=endpoint_path,
            status_code_signal=status_code_signal,
            similarity_signal=similarity_signal,
            soft_error_signal=soft_error_signal,
            redirect_signal=redirect_signal,
            baseline_fp=baseline_fp,
            endpoint_fp=endpoint_fp,
            is_soft_error=is_soft_error,
            soft_error_indicators=soft_error_indicators,
            similarity_details=similarity_details,
        )

        return EndpointValidationResult(
            exists=exists,
            status_code=status,
            confidence=confidence,
            severity=severity,
            status_code_signal=status_code_signal,
            similarity_signal=similarity_signal,
            soft_error_signal=soft_error_signal,
            redirect_signal=redirect_signal,
            is_soft_error=is_soft_error,
            soft_error_indicators=soft_error_indicators,
            similarity_details=similarity_details,
            reason=reason,
        )

    @staticmethod
    def _analyze_status_code(status_code: int) -> Tuple[float, str]:
        """Analyze status code signal.

        Returns:
            Tuple of (signal_strength: 0.0-1.0, reasoning: str)
        """
        if status_code in EndpointValidator.EXISTENCE_STATUS_CODES:
            return 0.9, f"Status {status_code} indicates endpoint exists"

        if status_code in EndpointValidator.AUTH_STATUS_CODES:
            return 0.7, f"Status {status_code} suggests auth/protected endpoint"

        if status_code in EndpointValidator.NOT_FOUND_STATUS_CODES:
            return 0.1, "Status 404 indicates endpoint not found"

        if status_code in EndpointValidator.REDIRECT_STATUS_CODES:
            return 0.5, f"Status {status_code} is a redirect (inconclusive)"

        # Unknown status codes
        return 0.3, f"Status {status_code} is inconclusive"

    @staticmethod
    def _make_decision(
        status: int,
        endpoint_path: str,
        status_code_signal: float,
        similarity_signal: float,
        soft_error_signal: float,
        redirect_signal: float,
        baseline_fp: ResponseFingerprint,
        endpoint_fp: ResponseFingerprint,
        is_soft_error: bool,
        soft_error_indicators: dict,
        similarity_details: dict,
    ) -> Tuple[bool, str, str, str]:
        """Make final determination using multi-signal logic.

        Returns:
            Tuple of (exists: bool, confidence: str, severity: str, reason: str)
        """

        # Rule 1: Soft error pages are NOT real endpoints
        if is_soft_error:
            return (
                False,
                "high",
                "info",
                f"Soft 404 detected: {', '.join(soft_error_indicators['error_keywords'][:3])}",
            )

        # Rule 2: Very high similarity to baseline + 200 status = likely SPA fallback
        if similarity_details["composite"] >= 0.85 and status == 200:
            return (
                False,
                "high",
                "info",
                f"SPA/Catch-all fallback: 85%+ similarity to baseline",
            )

        # Rule 3: High similarity + equal length = almost certainly baseline
        if (
            similarity_details["length_similarity"] > 0.95
            and similarity_details["hash_similarity"] > 0.8
        ):
            return (
                False,
                "high",
                "info",
                "Response identical to baseline (hash match)",
            )

        # Rule 4: Protected endpoints (401/403) are real endpoints
        if status in {401, 403}:
            confidence = "high" if status == 401 else "medium"
            return (
                True,
                confidence,
                "high",
                f"Protected endpoint: HTTP {status} indicates authentication required",
            )

        # Rule 5: Status 200 with very different content = likely real endpoint
        if status == 200 and similarity_details["composite"] < 0.5:
            return (
                True,
                "high",
                "high",
                "Status 200 with distinct content signature",
            )

        # Rule 6: Redirects are inconclusive but suspicious
        if status in {301, 302, 307, 308}:
            return (
                True,
                "medium",
                "medium",
                f"Redirect endpoint: HTTP {status}",
            )

        # Rule 7: Status 200 with moderate similarity + no soft error = likely real
        if status == 200 and similarity_details["composite"] < 0.65:
            return (
                True,
                "medium",
                "medium",
                "Status 200 with moderate content differences",
            )

        # Rule 8: Fallback case - be conservative
        if status == 200:
            return (
                False,
                "low",
                "info",
                "Insufficient evidence: likely fallback (conservative classification)",
            )

        # Rule 9: 404 with evidence of structure = still not an endpoint
        if status == 404:
            return (
                False,
                "high",
                "info",
                "HTTP 404 indicates endpoint not found",
            )

        # Catch-all: conservative approach
        return (
            False,
            "low",
            "info",
            "Uncertain result: classified as non-existent (conservative)",
        )


# ============================================================================
# Severity & Confidence Mapper
# ============================================================================

class SeverityConfidenceMapper:
    """Map endpoint characteristics to severity and confidence scores."""

    # Severity mapping by endpoint type and validation result
    SEVERITY_MAP = {
        # Critical files/paths
        "/.env": "critical",
        "/.env.local": "critical",
        "/.env.production": "critical",
        "/.git/HEAD": "critical",
        "/.git/config": "critical",
        "/.htpasswd": "critical",
        "/db.sql": "critical",
        "/database.sql": "critical",
        "/dump.sql": "critical",

        # High-risk admin/debug endpoints
        "/admin": "high",
        "/wp-admin": "high",
        "/phpmyadmin": "high",
        "/cpanel": "high",
        "/debug": "high",
        "/phpinfo.php": "high",
        "/_profiler": "high",

        # Medium-risk config/management
        "/config": "medium",
        "/settings.json": "medium",
        "/manager": "medium",
        "/dashboard": "medium",

        # Low-risk info disclosure
        "/api/docs": "low",
        "/swagger": "low",
        "/package.json": "low",
        "/robots.txt": "low",
    }

    @staticmethod
    def get_severity(endpoint_path: str, exists: bool, status_code: int) -> str:
        """Determine severity based on endpoint characteristics.

        Args:
            endpoint_path: The endpoint path
            exists: Whether endpoint was validated as existing
            status_code: HTTP response status

        Returns:
            Severity level: "critical", "high", "medium", "low", "info"
        """
        if not exists:
            return "info"

        # Check direct mapping
        path_lower = endpoint_path.lower()
        for pattern, severity in SeverityConfidenceMapper.SEVERITY_MAP.items():
            if pattern.lower() in path_lower:
                return severity

        # Protected endpoints are lower severity than unprotected
        if status_code in {401, 403}:
            return "medium"

        # Default for confirmed real endpoints
        if status_code == 200:
            return "high"

        return "medium"

    @staticmethod
    def get_confidence_from_signals(
        validation_result: EndpointValidationResult,
    ) -> str:
        """Determine confidence score from validation signals.

        Args:
            validation_result: The validation result

        Returns:
            Confidence level: "high", "medium", "low"
        """
        if not validation_result.exists:
            # Non-existent endpoints don't need high confidence reporting
            return "high"  # High confidence it's NOT an endpoint

        # For existing endpoints, assess confidence
        status_signal = validation_result.status_code_signal
        soft_error = validation_result.soft_error_signal

        # If marked as soft error, confidence is high (that it's NOT real)
        if soft_error > 0.5:
            return "high"

        # Status codes 401/403 are high confidence
        if validation_result.status_code in {401, 403}:
            return "high"

        # Status 200 with low similarity = high confidence
        if (
            validation_result.status_code == 200
            and validation_result.similarity_signal < 0.5
        ):
            return "high"

        # Redirects = medium confidence
        if validation_result.status_code in {301, 302, 307, 308}:
            return "medium"

        # Default = medium
        return "medium"
