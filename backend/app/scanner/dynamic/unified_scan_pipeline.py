"""
Unified Security Scan Pipeline
==============================

Integrated three-phase workflow:
  PHASE 1: Attack Surface Discovery (crawling + endpoint extraction)
  PHASE 2: Multi-Signal Endpoint Validation (confidence scoring)
  PHASE 3: Targeted Vulnerability Testing (category-specific checks)

Replaces blind endpoint guessing with intelligent reconnaissance.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

import httpx

from app.scanner.dynamic.endpoint_validator import (
    EndpointValidator,
    FingerprintBuilder,
    ResponseFingerprint,
)
from app.scanner.discovery import DiscoveryWorkflow, CrawlStrategy
from app.scanner.discovery.endpoint_classifier import (
    EndpointClassifier,
    EndpointCategory,
    RiskLevel,
    InputType,
)

logger = logging.getLogger(__name__)

Finding = Dict


# ============================================================================
# Confidence & Severity Models
# ============================================================================

@dataclass
class ValidatedEndpoint:
    """Endpoint that has passed multi-signal validation."""

    url: str
    method: str
    status_code: int
    confidence: float  # 0.0-1.0 (higher = more certain it exists)
    severity: str  # critical, high, medium, low, info
    reason: str
    source: str  # html_link, js_api, form_action, guessed
    input_types: List[InputType]
    category: Optional[EndpointCategory] = None
    testing_priority: int = 5  # 1-10 (lower = test first)
    auth_required: bool = False


@dataclass
class PipelineResult:
    """Result of unified scan pipeline."""

    target_url: str
    total_endpoints_discovered: int
    endpoints_validated: int
    endpoints_tested: int
    high_priority_count: int
    findings: List[Finding]
    phase_timings: Dict[str, float]  # phase_name -> duration_ms
    discovery_stats: Dict


# ============================================================================
# Phase 1: Discovery Engine Integration
# ============================================================================

class DiscoveryPhase:
    """Execute discovery using attack surface discovery engine."""

    @staticmethod
    async def execute(target_url: str) -> Dict:
        """Discover application endpoints through crawling.

        Returns:
            Dict with discovered_endpoints and stats
        """
        logger.info(f"[DISCOVERY] Starting attack surface reconnaissance for {target_url}")

        strategy = CrawlStrategy(
            max_depth=3,
            max_urls=250,
            max_requests_per_second=10.0,
            timeout_seconds=15.0,
            follow_redirects=True,
            max_redirects=5,
        )

        workflow = DiscoveryWorkflow(crawl_strategy=strategy)

        try:
            report = await workflow.discover_and_map(target_url)

            logger.info(
                f"[DISCOVERY] Found {len(report.discovered_endpoints)} endpoints, "
                f"{report.discovery_stats.urls_crawled} URLs crawled"
            )

            return {
                "discovered_endpoints": report.discovered_endpoints,
                "stats": report.discovery_stats,
                "error": None,
            }

        except Exception as e:
            logger.error(f"[DISCOVERY] Failed: {e}")
            return {
                "discovered_endpoints": [],
                "stats": None,
                "error": str(e),
            }


# ============================================================================
# Phase 2: Multi-Signal Validation
# ============================================================================

class ValidationPhase:
    """Validate endpoints using multi-signal approach."""

    @staticmethod
    async def execute(
        target_url: str,
        discovered_endpoints: List,
        http_client: httpx.AsyncClient,
    ) -> List[ValidatedEndpoint]:
        """Validate discovered endpoints with multi-signal logic.

        Returns:
            List of ValidatedEndpoint with confidence scores
        """
        logger.info(f"[VALIDATION] Starting multi-signal validation")

        # Capture baseline for comparison
        baseline_fp = await ValidationPhase._capture_baseline(target_url, http_client)

        validated = []

        # Validate each discovered endpoint
        for endpoint in discovered_endpoints:
            try:
                response = await http_client.get(
                    endpoint.url,
                    timeout=10.0,
                    follow_redirects=False,
                )

                # Multi-signal validation
                validation = EndpointValidator.validate(
                    endpoint_path=endpoint.url,
                    baseline_fp=baseline_fp,
                    endpoint_response=response,
                )

                # Calculate confidence (0.0-1.0)
                confidence = ValidationPhase._calculate_confidence(
                    validation, endpoint
                )

                # Map confidence to severity
                severity = ValidationPhase._confidence_to_severity(confidence)

                # Skip very low confidence (wild guesses)
                if confidence < 0.4:
                    logger.debug(
                        f"[VALIDATION] Skipping {endpoint.url} "
                        f"(confidence {confidence:.2f})"
                    )
                    continue

                validated_ep = ValidatedEndpoint(
                    url=endpoint.url,
                    method=endpoint.method,
                    status_code=response.status_code,
                    confidence=confidence,
                    severity=severity,
                    reason=validation.reason,
                    source=endpoint.source,
                    input_types=getattr(endpoint, "input_types", []),
                    auth_required=(response.status_code in [401, 403]),
                )

                validated.append(validated_ep)
                logger.debug(
                    f"[VALIDATION] ✓ {endpoint.url} "
                    f"(conf={confidence:.2f}, sev={severity})"
                )

            except asyncio.TimeoutError:
                logger.debug(f"[VALIDATION] Timeout: {endpoint.url}")
                continue
            except Exception as e:
                logger.debug(f"[VALIDATION] Error validating {endpoint.url}: {e}")
                continue

        logger.info(
            f"[VALIDATION] Validated {len(validated)} / {len(discovered_endpoints)} endpoints"
        )
        return validated

    @staticmethod
    async def _capture_baseline(target_url: str, client: httpx.AsyncClient):
        """Capture baseline response fingerprint from root."""
        try:
            response = await client.get(target_url, timeout=10.0)
            return FingerprintBuilder.build(response)
        except Exception as e:
            logger.warning(f"Cannot capture baseline: {e}")
            # Return dummy baseline if root is unreachable
            return ResponseFingerprint(
                status_code=500,
                content_length=0,
                content_hash="unknown",
                body_sample="",
                html_title=None,
                headers_dict={},
                has_redirect_meta=False,
            )

    @staticmethod
    def _calculate_confidence(validation, endpoint) -> float:
        """Calculate confidence score (0.0-1.0) from validation signals.

        FORMULA:
            base = 0.5 (neutral)
            + source_weight (0.05-0.35)
            + status_weight (0.05-0.25)
            + similarity_weight (-0.25 to +0.10)
            + error_penalty (-0.25)
        """
        base_confidence = 0.5

        # Source weighting
        source_weights = {
            "form_action": 0.35,
            "html_link": 0.30,
            "javascript": 0.15,
            "guessed": 0.05,
        }
        source_weight = source_weights.get(endpoint.source, 0.10)

        # Status code weighting
        status = validation.status_code
        if status in [200, 201, 202]:
            status_weight = 0.20
        elif status in [401, 403]:
            status_weight = 0.25  # Auth = confirms endpoint exists
        elif status in [301, 302]:
            status_weight = 0.10
        else:
            status_weight = 0.05

        # Similarity penalty (high similarity = likely fallback)
        similarity = validation.similarity_details.get("composite", 0.5)
        if similarity > 0.85:
            similarity_weight = -0.20  # Major penalty
        elif similarity > 0.65:
            similarity_weight = -0.10
        else:
            similarity_weight = 0.05

        # Soft error penalty
        error_penalty = -0.25 if validation.is_soft_error else 0.0

        confidence = (
            base_confidence
            + source_weight
            + status_weight
            + similarity_weight
            + error_penalty
        )

        # Clamp to 0.0-1.0
        return max(0.0, min(1.0, confidence))

    @staticmethod
    def _confidence_to_severity(confidence: float) -> str:
        """Map confidence to severity level."""
        if confidence > 0.85:
            return "critical"
        elif confidence > 0.70:
            return "high"
        elif confidence > 0.50:
            return "medium"
        elif confidence > 0.30:
            return "low"
        else:
            return "info"


# ============================================================================
# Phase 3: Classification & Prioritization
# ============================================================================

class ClassificationPhase:
    """Classify endpoints and calculate testing priority."""

    @staticmethod
    def execute(validated_endpoints: List[ValidatedEndpoint]) -> List[ValidatedEndpoint]:
        """Classify endpoints and set testing priorities.

        Returns:
            Endpoints with category, risk, and priority set
        """
        logger.info(f"[CLASSIFICATION] Classifying {len(validated_endpoints)} endpoints")

        classifier = EndpointClassifier()

        classified = []

        for endpoint in validated_endpoints:
            # Get classification
            profile = classifier.classify_endpoint(
                url=endpoint.url,
                method=endpoint.method,
                auth_required=endpoint.auth_required,
            )

            # Update endpoint with classification
            endpoint.category = profile.category
            endpoint.testing_priority = profile.testing_priority

            # Adjust severity based on category + confidence
            endpoint.severity = ClassificationPhase._adjust_severity(
                endpoint, profile
            )

            classified.append(endpoint)

        # Sort by priority (lower = higher priority)
        classified.sort(key=lambda e: e.testing_priority)

        logger.info(
            f"[CLASSIFICATION] Sorted {len(classified)} endpoints by priority"
        )

        return classified

    @staticmethod
    def _adjust_severity(endpoint: ValidatedEndpoint, profile) -> str:
        """Adjust severity based on category and confidence."""

        # CRITICAL: Real unprotected admin/secrets
        if (
            profile.category
            in [EndpointCategory.ADMIN_PANEL, EndpointCategory.CONFIGURATION]
        ):
            if not endpoint.auth_required:
                return "critical"
            return "high"

        # HIGH: Auth/file handling endpoints
        if profile.category in [
            EndpointCategory.AUTHENTICATION,
            EndpointCategory.FILE_HANDLING,
        ]:
            return "high"

        # MEDIUM: API data, protected resources
        if profile.category in [
            EndpointCategory.API_DATA,
            EndpointCategory.AUTHORIZATION,
            EndpointCategory.USER_MANAGEMENT,
        ]:
            if endpoint.confidence > 0.75:
                return "medium"
            return "low"

        # LOW: Static, search, debug
        if profile.category in [
            EndpointCategory.STATIC_ASSET,
            EndpointCategory.SEARCH,
            EndpointCategory.DEBUG_INFO,
        ]:
            return "low"

        # Default
        return endpoint.severity


# ============================================================================
# Phase 4: Targeted Vulnerability Testing
# ============================================================================

class TargetedTestingPhase:
    """Execute category-specific vulnerability tests."""

    @staticmethod
    async def execute(
        classified_endpoints: List[ValidatedEndpoint],
        http_client: httpx.AsyncClient,
        test_modules: Dict,  # name -> test_module
    ) -> List[Finding]:
        """Run targeted tests on discovered endpoints.

        Args:
            classified_endpoints: Classified and prioritized endpoints
            http_client: HTTP client for testing
            test_modules: Dict of available test modules

        Returns:
            List of vulnerability findings
        """
        logger.info(
            f"[TESTING] Starting targeted testing on {len(classified_endpoints)} endpoints"
        )

        findings = []

        # High-priority endpoints (1-3)
        high_priority = [e for e in classified_endpoints if e.testing_priority <= 3]

        logger.info(f"[TESTING] Testing {len(high_priority)} high-priority endpoints")

        # Create testing tasks
        tasks = []

        for endpoint in high_priority[:50]:  # Limit to top 50
            # Determine applicable tests
            tests = TargetedTestingPhase._determine_tests(
                endpoint, test_modules
            )

            # Run tests concurrently
            for test_func in tests:
                tasks.append(test_func(endpoint, http_client))

        # Execute all tests
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    logger.debug(f"Test error: {result}")
                    continue
                if isinstance(result, list):
                    findings.extend(result)
                elif isinstance(result, dict):
                    findings.append(result)

        logger.info(f"[TESTING] Found {len(findings)} vulnerabilities")
        return findings

    @staticmethod
    def _determine_tests(endpoint: ValidatedEndpoint, test_modules: Dict) -> List:
        """Determine which tests to run based on endpoint characteristics."""

        tests = []

        if not endpoint.category:
            return tests

        # By category
        if endpoint.category == EndpointCategory.AUTHENTICATION:
            if "xss_detector" in test_modules:
                tests.append(
                    lambda ep, client: test_modules["xss_detector"].test_endpoint(ep)
                )

        elif endpoint.category == EndpointCategory.FILE_HANDLING:
            if "file_upload_tester" in test_modules:
                tests.append(
                    lambda ep, client: test_modules["file_upload_tester"].test_endpoint(
                        ep
                    )
                )

        elif endpoint.category == EndpointCategory.API_DATA:
            if "sqli_detector" in test_modules:
                tests.append(
                    lambda ep, client: test_modules["sqli_detector"].test_endpoint(ep)
                )
            if "xss_detector" in test_modules:
                tests.append(
                    lambda ep, client: test_modules["xss_detector"].test_endpoint(ep)
                )

        # By input type
        if InputType.QUERY_PARAM in endpoint.input_types:
            if "xss_detector" in test_modules:
                tests.append(
                    lambda ep, client: test_modules["xss_detector"].test_endpoint(ep)
                )

        if InputType.FILE_UPLOAD in endpoint.input_types:
            if "file_upload_tester" in test_modules:
                tests.append(
                    lambda ep, client: test_modules["file_upload_tester"].test_endpoint(
                        ep
                    )
                )

        if InputType.JSON_BODY in endpoint.input_types:
            if "sqli_detector" in test_modules:
                tests.append(
                    lambda ep, client: test_modules["sqli_detector"].test_endpoint(ep)
                )

        return tests


# ============================================================================
# Unified Pipeline Orchestrator
# ============================================================================

class UnifiedScanPipeline:
    """Orchestrates complete three-phase scan workflow."""

    TIMEOUT = 30

    async def execute(self, target_url: str, test_modules: Dict) -> PipelineResult:
        """Execute complete scan pipeline.

        PHASE 1: Discovery
        PHASE 2: Multi-Signal Validation
        PHASE 3: Classification & Prioritization
        PHASE 4: Targeted Testing

        Args:
            target_url: Target URL to scan
            test_modules: Available test modules {name -> module}

        Returns:
            PipelineResult with all findings and stats
        """
        import time

        timings = {}

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.TIMEOUT),
            follow_redirects=True,
            verify=False,
            headers={
                "User-Agent": "HybridSecurityScanner/1.0 (Ethical Assessment)",
            },
        ) as client:

            # PHASE 1: Discovery
            start = time.time()
            discovery_result = await DiscoveryPhase.execute(target_url)
            timings["discovery"] = (time.time() - start) * 1000

            if discovery_result["error"]:
                logger.error(f"Discovery failed: {discovery_result['error']}")
                return PipelineResult(
                    target_url=target_url,
                    total_endpoints_discovered=0,
                    endpoints_validated=0,
                    endpoints_tested=0,
                    high_priority_count=0,
                    findings=[],
                    phase_timings=timings,
                    discovery_stats=None,
                )

            # PHASE 2: Validation
            start = time.time()
            validated = await ValidationPhase.execute(
                target_url,
                discovery_result["discovered_endpoints"],
                client,
            )
            timings["validation"] = (time.time() - start) * 1000

            # PHASE 3: Classification
            start = time.time()
            classified = ClassificationPhase.execute(validated)
            timings["classification"] = (time.time() - start) * 1000

            high_priority_count = sum(
                1 for e in classified if e.testing_priority <= 3
            )

            # PHASE 4: Targeted Testing
            start = time.time()
            findings = await TargetedTestingPhase.execute(
                classified, client, test_modules
            )
            timings["testing"] = (time.time() - start) * 1000

            return PipelineResult(
                target_url=target_url,
                total_endpoints_discovered=len(discovery_result["discovered_endpoints"]),
                endpoints_validated=len(validated),
                endpoints_tested=high_priority_count,
                high_priority_count=high_priority_count,
                findings=findings,
                phase_timings=timings,
                discovery_stats={
                    "urls_crawled": discovery_result["stats"].urls_crawled
                    if discovery_result["stats"]
                    else 0,
                    "endpoints_discovered": discovery_result["stats"].endpoints_discovered
                    if discovery_result["stats"]
                    else 0,
                    "js_analyzed": discovery_result["stats"].js_files_analyzed
                    if discovery_result["stats"]
                    else 0,
                },
            )
