"""
Discovery Orchestrator - Coordinates multi-phase attack surface discovery.

Manages the reconnaissance workflow: discovery → mapping → classification → testing prioritization.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import List, Optional

import httpx

from app.scanner.discovery.attack_surface_discovery import (
    AttackSurfaceDiscovery,
    CrawlStrategy,
    DiscoveredEndpoint,
    DiscoveryStats,
)
from app.scanner.discovery.endpoint_classifier import (
    ClassificationReport,
    ClassificationReportGenerator,
    EndpointClassifier,
    EndpointProfile,
)

logger = logging.getLogger(__name__)


# ============================================================================
# Multi-Phase Discovery Workflow
# ============================================================================

@dataclass
class DiscoveryPhaseResults:
    """Results from multi-phase discovery workflow."""

    phase: str
    duration_ms: float
    endpoints_found: int
    details: dict = field(default_factory=dict)


@dataclass
class AttackSurfaceReport:
    """Complete report from attack surface discovery."""

    target_url: str
    discovered_endpoints: List[DiscoveredEndpoint]
    classified_endpoints: List[EndpointProfile]
    classification_report: ClassificationReport
    discovery_stats: DiscoveryStats
    phase_results: List[DiscoveryPhaseResults] = field(default_factory=list)


# ============================================================================
# Discovery Orchestrator
# ============================================================================

class DiscoveryOrchestrator:
    """Orchestrates multi-phase attack surface discovery and endpoint mapping."""

    def __init__(self, strategy: Optional[CrawlStrategy] = None):
        self.strategy = strategy or CrawlStrategy()
        self.discovery_engine = AttackSurfaceDiscovery(self.strategy)
        self.classifier = EndpointClassifier()

    async def execute_discovery_workflow(
        self, target_url: str
    ) -> AttackSurfaceReport:
        """Execute complete discovery workflow.

        Workflow:
          PHASE 1: Attack Surface Discovery
            - Crawl application
            - Extract links, forms, scripts
            - Analyze JavaScript
            - Track redirects
            
          PHASE 2: Endpoint Mapping & Classification
            - Classify discovered endpoints
            - Assign risk levels
            - Detect input vectors
            - Calculate testing priorities
            
          PHASE 3: Report Generation (for targeted testing)
            - Generate classification report
            - Prioritize high-risk endpoints
            - Identify testing targets

        Args:
            target_url: Target application URL

        Returns:
            AttackSurfaceReport
        """
        phase_results: List[DiscoveryPhaseResults] = []

        logger.info(f"Starting attack surface discovery for {target_url}")

        # Create HTTP client
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.strategy.timeout_seconds),
            follow_redirects=False,
            verify=False,
            headers={
                "User-Agent": self.strategy.user_agent,
            },
        ) as client:
            # PHASE 1: Attack Surface Discovery
            logger.info("Phase 1: Attack Surface Discovery...")
            discovery_results = await self._phase_1_discovery(
                target_url, client
            )
            phase_results.append(discovery_results)

            discovered_endpoints = self.discovery_engine.discovered_endpoints.values()

            # PHASE 2: Endpoint Mapping & Classification
            logger.info("Phase 2: Endpoint Mapping & Classification...")
            classification_results = await self._phase_2_classification(
                discovered_endpoints
            )
            phase_results.append(classification_results)

            classified_endpoints = classification_results.details.get(
                "classified_endpoints", []
            )

            # PHASE 3: Report Generation
            logger.info("Phase 3: Report Generation...")
            report_results = await self._phase_3_reporting(
                classified_endpoints
            )
            phase_results.append(report_results)

            classification_report = report_results.details.get(
                "classification_report"
            )

        # Build comprehensive report
        report = AttackSurfaceReport(
            target_url=target_url,
            discovered_endpoints=list(discovered_endpoints),
            classified_endpoints=classified_endpoints,
            classification_report=classification_report,
            discovery_stats=self.discovery_engine.stats,
            phase_results=phase_results,
        )

        logger.info(
            f"Discovery workflow complete: {len(discovered_endpoints)} endpoints discovered, "
            f"{len(classified_endpoints)} classified"
        )

        return report

    async def _phase_1_discovery(
        self,
        target_url: str,
        client: httpx.AsyncClient,
    ) -> DiscoveryPhaseResults:
        """PHASE 1: Attack Surface Discovery.

        Discovers reachable application routes through:
        - HTML link crawling
        - JavaScript analysis
        - Form extraction
        - Redirect following
        """
        import time

        start_time = time.time()

        # Execute discovery
        await self.discovery_engine.discover(target_url, client)

        duration_ms = (time.time() - start_time) * 1000

        logger.info(
            f"Phase 1 complete: {self.discovery_engine.stats.endpoints_discovered} endpoints, "
            f"{self.discovery_engine.stats.urls_crawled} URLs crawled, "
            f"{self.discovery_engine.stats.js_files_analyzed} JS files analyzed"
        )

        return DiscoveryPhaseResults(
            phase="1_attack_surface_discovery",
            duration_ms=duration_ms,
            endpoints_found=self.discovery_engine.stats.endpoints_discovered,
            details={
                "urls_crawled": self.discovery_engine.stats.urls_crawled,
                "js_analyzed": self.discovery_engine.stats.js_files_analyzed,
                "forms_found": self.discovery_engine.stats.forms_found,
                "redirects_followed": self.discovery_engine.stats.redirects_followed,
                "errors": self.discovery_engine.stats.errors_encountered,
            },
        )

    async def _phase_2_classification(
        self,
        discovered_endpoints: List[DiscoveredEndpoint],
    ) -> DiscoveryPhaseResults:
        """PHASE 2: Endpoint Mapping & Classification.

        Classifies endpoints by:
        - Category (auth, admin, API, file handling, etc.)
        - Risk level (critical, high, medium, low)
        - Input vectors (query params, form data, JSON, file upload)
        - Testing priority
        """
        import time

        start_time = time.time()

        # Classify endpoints
        classified = self.classifier.classify_batch(
            list(discovered_endpoints)
        )

        duration_ms = (time.time() - start_time) * 1000

        # Statistics by category
        category_stats = {}
        for ep in classified:
            category_stats[ep.category] = category_stats.get(ep.category, 0) + 1

        logger.info(
            f"Phase 2 complete: {len(classified)} endpoints classified, "
            f"categories: {category_stats}"
        )

        return DiscoveryPhaseResults(
            phase="2_endpoint_mapping_classification",
            duration_ms=duration_ms,
            endpoints_found=len(classified),
            details={
                "classified_endpoints": classified,
                "category_distribution": category_stats,
            },
        )

    async def _phase_3_reporting(
        self,
        classified_endpoints: List[EndpointProfile],
    ) -> DiscoveryPhaseResults:
        """PHASE 3: Report Generation.

        Generates comprehensive report for targeted testing:
        - High-priority endpoints
        - Auth-required endpoints
        - Potentially vulnerable surfaces
        - Testing recommendations
        """
        import time

        start_time = time.time()

        # Generate report
        report = ClassificationReportGenerator.generate(
            classified_endpoints
        )

        duration_ms = (time.time() - start_time) * 1000

        logger.info(
            f"Phase 3 complete: {len(report.high_priority_endpoints)} high-priority, "
            f"{len(report.potentially_vulnerable_endpoints)} vulnerable endpoints identified"
        )

        return DiscoveryPhaseResults(
            phase="3_report_generation",
            duration_ms=duration_ms,
            endpoints_found=len(classified_endpoints),
            details={
                "classification_report": report,
                "high_priority_count": len(report.high_priority_endpoints),
                "vulnerable_count": len(report.potentially_vulnerable_endpoints),
                "risk_summary": dict(report.by_risk),
            },
        )


# ============================================================================
# Discovery Workflow Helper
# ============================================================================

class DiscoveryWorkflow:
    """High-level discovery workflow wrapper."""

    def __init__(self, strategy: Optional[CrawlStrategy] = None):
        self.orchestrator = DiscoveryOrchestrator(strategy)

    async def discover_and_map(
        self, target_url: str
    ) -> AttackSurfaceReport:
        """Execute complete discovery workflow.

        Args:
            target_url: Target URL

        Returns:
            AttackSurfaceReport
        """
        return await self.orchestrator.execute_discovery_workflow(target_url)

    def get_high_priority_endpoints(
        self, report: AttackSurfaceReport
    ) -> List[EndpointProfile]:
        """Get high-priority endpoints for testing.

        Args:
            report: AttackSurfaceReport

        Returns:
            List of high-priority EndpointProfile
        """
        return report.classification_report.high_priority_endpoints

    def get_vulnerable_surfaces(
        self, report: AttackSurfaceReport
    ) -> List[EndpointProfile]:
        """Get potentially vulnerable endpoints.

        Args:
            report: AttackSurfaceReport

        Returns:
            List of vulnerable EndpointProfile
        """
        return report.classification_report.potentially_vulnerable_endpoints
