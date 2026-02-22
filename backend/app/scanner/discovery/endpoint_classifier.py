"""
Endpoint Classification Engine - Categorizes discovered routes by risk level and type.

Implements intelligent classification for targeting vulnerability testing.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set

from app.scanner.discovery.attack_surface_discovery import DiscoveredEndpoint

logger = logging.getLogger(__name__)


# ============================================================================
# Classification Enums
# ============================================================================

class EndpointCategory(str, Enum):
    """Classification category for endpoints."""

    AUTHENTICATION = "authentication"  # Login, logout, register
    AUTHORIZATION = "authorization"  # Permission/role checks
    USER_MGMT = "user_management"  # User profile, settings
    API_DATA = "api_data"  # Data retrieval/modification
    FILE_HANDLING = "file_handling"  # Upload, download
    ADMIN_PANEL = "admin_panel"  # Admin dashboard
    DEBUG_INFO = "debug_info"  # Debug/diagnostic endpoints
    STATIC_ASSET = "static_asset"  # CSS, JS, images
    CONFIG = "configuration"  # Config endpoints
    SEARCH = "search"  # Search/filter endpoints
    UNKNOWN = "unknown"  # Unclassified


class RiskLevel(str, Enum):
    """Risk classification for endpoints."""

    CRITICAL = "critical"  # Exposed admin/auth/secrets
    HIGH = "high"  # Input-heavy, unprotected
    MEDIUM = "medium"  # API endpoints, form handlers
    LOW = "low"  # Static assets, public info
    INFO = "info"  # Non-security relevant


class InputType(str, Enum):
    """Types of input vectors found on endpoint."""

    QUERY_PARAM = "query_parameter"
    PATH_PARAM = "path_parameter"
    FORM_DATA = "form_data"
    JSON_BODY = "json_body"
    FILE_UPLOAD = "file_upload"
    NONE = "none"


# ============================================================================
# Endpoint Classification Data
# ============================================================================

@dataclass
class EndpointProfile:
    """Complete classification profile for endpoint."""

    url: str
    method: str
    category: EndpointCategory
    risk_level: RiskLevel
    input_types: List[InputType] = field(default_factory=list)
    auth_required: bool = False
    potentially_vulnerable: bool = False
    testing_priority: int = 1  # 1=highest, 10=lowest
    reason: str = ""  # Why classified this way


# ============================================================================
# Classification Patterns
# ============================================================================

AUTHENTICATION_PATTERNS = [
    r"/(auth|login|signin|signup|register|logout|password)",
    r"/user/(login|auth|register)",
    r"/api/(auth|login|oauth)",
    r"/(forgot.*password|reset.*password|change.*password)",
]

AUTHORIZATION_PATTERNS = [
    r"/(admin|dashboard|management|console)",
    r"/user/(roles|permissions|groups)",
    r"/api/(roles|permissions|acl)",
]

USER_MGMT_PATTERNS = [
    r"/user(s)?/?$",
    r"/profile",
    r"/account",
    r"/settings",
    r"/me$",
]

API_DATA_PATTERNS = [
    r"/api/[a-z]+/?$",
    r"/api/v\d+/",
    r"/data/",
    r"/rest/",
]

FILE_HANDLING_PATTERNS = [
    r"/(upload|download|file|media|assets)",
    r"/api/(upload|download|files)",
]

ADMIN_PATTERNS = [
    r"/(admin|administrator)",
    r"/(dashboard|control.*panel)",
    r"/management",
    r"/superadmin",
]

DEBUG_PATTERNS = [
    r"/(debug|test|development)",
    r"/healthcheck",
    r"/status",
    r"/metrics",
    r"/_debug",
]

STATIC_PATTERNS = [
    r"\.(js|css|jpg|png|gif|ico|woff|svg|ttf|eot|webp)$",
    r"/(assets|static|public|fonts|images)",
]

SEARCH_PATTERNS = [
    r"/(search|query|find)",
    r"/api/(search|query)",
]

CONFIG_PATTERNS = [
    r"/(config|configuration|settings)",
    r"/.env",
    r"/api/config",
]


# ============================================================================
# Endpoint Classifier
# ============================================================================

class EndpointClassifier:
    """Intelligently classifies discovered endpoints."""

    def __init__(self):
        self.patterns: Dict[EndpointCategory, List[str]] = {
            EndpointCategory.AUTHENTICATION: AUTHENTICATION_PATTERNS,
            EndpointCategory.AUTHORIZATION: AUTHORIZATION_PATTERNS,
            EndpointCategory.USER_MGMT: USER_MGMT_PATTERNS,
            EndpointCategory.API_DATA: API_DATA_PATTERNS,
            EndpointCategory.FILE_HANDLING: FILE_HANDLING_PATTERNS,
            EndpointCategory.ADMIN_PANEL: ADMIN_PATTERNS,
            EndpointCategory.DEBUG_INFO: DEBUG_PATTERNS,
            EndpointCategory.STATIC_ASSET: STATIC_PATTERNS,
            EndpointCategory.SEARCH: SEARCH_PATTERNS,
            EndpointCategory.CONFIG: CONFIG_PATTERNS,
        }

    def classify(
        self, endpoint: DiscoveredEndpoint
    ) -> EndpointProfile:
        """Classify discovered endpoint into category.

        Args:
            endpoint: DiscoveredEndpoint to classify

        Returns:
            EndpointProfile with classification
        """
        url_lower = endpoint.url.lower()

        # Match categories (in priority order)
        category = self._match_category(url_lower)

        # Determine risk level
        risk_level = self._assess_risk(
            endpoint, category, url_lower
        )

        # Detect input types
        input_types = self._detect_input_types(endpoint)

        # Determine testing priority
        priority = self._calculate_priority(
            category, risk_level, input_types
        )

        # Check if potentially vulnerable
        potentially_vulnerable = risk_level in {
            RiskLevel.CRITICAL, RiskLevel.HIGH
        }

        reason = self._generate_classification_reason(
            url_lower, category, risk_level
        )

        return EndpointProfile(
            url=endpoint.url,
            method=endpoint.method,
            category=category,
            risk_level=risk_level,
            input_types=input_types,
            auth_required=endpoint.auth_required,
            potentially_vulnerable=potentially_vulnerable,
            testing_priority=priority,
            reason=reason,
        )

    def classify_batch(
        self, endpoints: List[DiscoveredEndpoint]
    ) -> List[EndpointProfile]:
        """Classify multiple endpoints.

        Args:
            endpoints: List of endpoints to classify

        Returns:
            List of EndpointProfile objects
        """
        return [self.classify(ep) for ep in endpoints]

    @staticmethod
    def _match_category(url_lower: str) -> EndpointCategory:
        """Match URL to category using patterns.

        Args:
            url_lower: Lowercase URL

        Returns:
            EndpointCategory match
        """
        # Static assets first (lowest priority)
        for pattern in STATIC_PATTERNS:
            if re.search(pattern, url_lower):
                return EndpointCategory.STATIC_ASSET

        # Check other categories
        category_patterns = [
            (EndpointCategory.ADMIN_PANEL, ADMIN_PATTERNS),
            (EndpointCategory.AUTHENTICATION, AUTHENTICATION_PATTERNS),
            (EndpointCategory.AUTHORIZATION, AUTHORIZATION_PATTERNS),
            (EndpointCategory.DEBUG_INFO, DEBUG_PATTERNS),
            (EndpointCategory.FILE_HANDLING, FILE_HANDLING_PATTERNS),
            (EndpointCategory.CONFIG, CONFIG_PATTERNS),
            (EndpointCategory.USER_MGMT, USER_MGMT_PATTERNS),
            (EndpointCategory.SEARCH, SEARCH_PATTERNS),
            (EndpointCategory.API_DATA, API_DATA_PATTERNS),
        ]

        for category, patterns in category_patterns:
            for pattern in patterns:
                if re.search(pattern, url_lower, re.IGNORECASE):
                    return category

        return EndpointCategory.UNKNOWN

    @staticmethod
    def _assess_risk(
        endpoint: DiscoveredEndpoint,
        category: EndpointCategory,
        url_lower: str,
    ) -> RiskLevel:
        """Assess risk level based on characteristics.

        Args:
            endpoint: Endpoint to assess
            category: Endpoint category
            url_lower: Lowercase URL

        Returns:
            RiskLevel assessment
        """
        # Critical: Admin/Auth without auth, or config files
        if category in {
            EndpointCategory.ADMIN_PANEL,
            EndpointCategory.CONFIG,
        }:
            if not endpoint.auth_required:
                return RiskLevel.CRITICAL
            return RiskLevel.HIGH

        # High: Authentication endpoints, debug endpoints
        if category in {
            EndpointCategory.AUTHENTICATION,
            EndpointCategory.DEBUG_INFO,
        }:
            return RiskLevel.HIGH

        # High: Unauthenticated authorization/user mgmt
        if category in {
            EndpointCategory.AUTHORIZATION,
            EndpointCategory.USER_MGMT,
        }:
            if not endpoint.auth_required:
                return RiskLevel.HIGH
            return RiskLevel.MEDIUM

        # Medium: File handling, form submissions
        if category == EndpointCategory.FILE_HANDLING:
            return RiskLevel.HIGH

        # Medium: API endpoints
        if category == EndpointCategory.API_DATA:
            return RiskLevel.MEDIUM

        # Low: Search, static assets
        if category in {
            EndpointCategory.SEARCH,
            EndpointCategory.STATIC_ASSET,
        }:
            return RiskLevel.LOW

        return RiskLevel.INFO

    @staticmethod
    def _detect_input_types(endpoint: DiscoveredEndpoint) -> List[InputType]:
        """Detect input vector types.

        Args:
            endpoint: Endpoint to analyze

        Returns:
            List of detected input types
        """
        inputs: List[InputType] = []

        url_lower = endpoint.url.lower()

        # Query parameters
        if "?" in url_lower:
            inputs.append(InputType.QUERY_PARAM)

        # Form data if POST/PUT/PATCH
        if endpoint.method in {"POST", "PUT", "PATCH"}:
            inputs.append(InputType.FORM_DATA)

            # Likely JSON if API endpoint
            if "/api/" in url_lower:
                inputs.append(InputType.JSON_BODY)

        # File upload hints
        if any(word in url_lower for word in ["upload", "file", "media"]):
            inputs.append(InputType.FILE_UPLOAD)

        # Path parameters (e.g., /user/{id})
        if "{" in endpoint.url or any(
            f"/{seg}/" in url_lower
            for seg in ["users", "posts", "items", "products"]
        ):
            inputs.append(InputType.PATH_PARAM)

        return inputs if inputs else [InputType.NONE]

    @staticmethod
    def _calculate_priority(
        category: EndpointCategory,
        risk_level: RiskLevel,
        input_types: List[InputType],
    ) -> int:
        """Calculate testing priority (1=highest).

        Args:
            category: Endpoint category
            risk_level: Assessed risk level
            input_types: Detected input types

        Returns:
            Priority score (1-10, lower=higher priority)
        """
        priority = 5  # Base priority

        # Risk level adjustment
        risk_priority = {
            RiskLevel.CRITICAL: -3,
            RiskLevel.HIGH: -2,
            RiskLevel.MEDIUM: -1,
            RiskLevel.LOW: 1,
            RiskLevel.INFO: 2,
        }
        priority += risk_priority.get(risk_level, 0)

        # Category adjustment
        category_priority = {
            EndpointCategory.AUTHENTICATION: -2,
            EndpointCategory.FILE_HANDLING: -2,
            EndpointCategory.ADMIN_PANEL: -2,
            EndpointCategory.API_DATA: -1,
            EndpointCategory.USER_MGMT: -1,
            EndpointCategory.SEARCH: 1,
            EndpointCategory.STATIC_ASSET: 3,
        }
        priority += category_priority.get(category, 0)

        # Input vector adjustment
        if InputType.FILE_UPLOAD in input_types:
            priority -= 2
        elif InputType.JSON_BODY in input_types:
            priority -= 1
        elif InputType.NONE in input_types:
            priority += 2

        # Clamp to 1-10
        return max(1, min(10, priority))

    @staticmethod
    def _generate_classification_reason(
        url_lower: str, category: EndpointCategory, risk_level: RiskLevel
    ) -> str:
        """Generate human-readable classification reason.

        Args:
            url_lower: Lowercase URL
            category: Classification category
            risk_level: Risk level

        Returns:
            Reason string
        """
        reasons = []

        # Category reason
        category_reasons = {
            EndpointCategory.AUTHENTICATION: "Authentication endpoint",
            EndpointCategory.ADMIN_PANEL: "Administrative interface",
            EndpointCategory.FILE_HANDLING: "File handling endpoint",
            EndpointCategory.DEBUG_INFO: "Debug/diagnostic endpoint",
            EndpointCategory.CONFIG: "Configuration endpoint",
            EndpointCategory.API_DATA: "API data endpoint",
            EndpointCategory.STATIC_ASSET: "Static asset",
        }

        reasons.append(
            category_reasons.get(category, "Endpoint")
        )

        # Risk reason
        risk_reasons = {
            RiskLevel.CRITICAL: "no authentication required",
            RiskLevel.HIGH: "high-risk functionality",
            RiskLevel.MEDIUM: "moderate risk profile",
            RiskLevel.LOW: "low risk",
        }

        if risk_level in risk_reasons:
            reasons.append(risk_reasons[risk_level])

        return " - ".join(reasons)


# ============================================================================
# Classification Report Generator
# ============================================================================

@dataclass
class ClassificationReport:
    """Report summarizing endpoint classification."""

    total_endpoints: int
    by_category: Dict[EndpointCategory, int]
    by_risk: Dict[RiskLevel, int]
    high_priority_endpoints: List[EndpointProfile]
    auth_required_endpoints: List[EndpointProfile]
    potentially_vulnerable_endpoints: List[EndpointProfile]


class ClassificationReportGenerator:
    """Generates reports from classified endpoints."""

    @staticmethod
    def generate(
        profiles: List[EndpointProfile],
    ) -> ClassificationReport:
        """Generate classification report.

        Args:
            profiles: List of classified endpoints

        Returns:
            ClassificationReport
        """
        # Category statistics
        by_category: Dict[EndpointCategory, int] = {}
        for profile in profiles:
            by_category[profile.category] = by_category.get(profile.category, 0) + 1

        # Risk statistics
        by_risk: Dict[RiskLevel, int] = {}
        for profile in profiles:
            by_risk[profile.risk_level] = by_risk.get(profile.risk_level, 0) + 1

        # High priority endpoints
        high_priority = sorted(
            [p for p in profiles if p.testing_priority <= 3],
            key=lambda x: x.testing_priority,
        )

        # Auth-required endpoints
        auth_required = [p for p in profiles if p.auth_required]

        # Potentially vulnerable
        vulnerable = [p for p in profiles if p.potentially_vulnerable]

        return ClassificationReport(
            total_endpoints=len(profiles),
            by_category=by_category,
            by_risk=by_risk,
            high_priority_endpoints=high_priority,
            auth_required_endpoints=auth_required,
            potentially_vulnerable_endpoints=vulnerable,
        )
