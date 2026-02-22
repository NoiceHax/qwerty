"""
Discovery Module - Attack Surface Discovery & Endpoint Mapping

Provides multi-phase reconnaissance workflow for discovering and classifying
application endpoints.
"""

from app.scanner.discovery.attack_surface_discovery import (
    AttackSurfaceDiscovery,
    CrawlStrategy,
    DiscoveredEndpoint,
    DiscoveryStats,
)
from app.scanner.discovery.endpoint_classifier import (
    ClassificationReport,
    ClassificationReportGenerator,
    EndpointCategory,
    EndpointClassifier,
    EndpointProfile,
    InputType,
    RiskLevel,
)
from app.scanner.discovery.orchestrator import (
    AttackSurfaceReport,
    DiscoveryOrchestrator,
    DiscoveryWorkflow,
    DiscoveryPhaseResults,
)

__all__ = [
    # Discovery Engine
    "AttackSurfaceDiscovery",
    "CrawlStrategy",
    "DiscoveredEndpoint",
    "DiscoveryStats",
    # Classification
    "EndpointClassifier",
    "EndpointProfile",
    "EndpointCategory",
    "RiskLevel",
    "InputType",
    "ClassificationReport",
    "ClassificationReportGenerator",
    # Orchestration
    "DiscoveryOrchestrator",
    "DiscoveryWorkflow",
    "AttackSurfaceReport",
    "DiscoveryPhaseResults",
]
