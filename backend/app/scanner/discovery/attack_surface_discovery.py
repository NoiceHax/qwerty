"""
Attack Surface Discovery Engine - Core Implementation

Manages the reconnaissance phase: crawling, link extraction, and route discovery.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser
import re

import httpx

logger = logging.getLogger(__name__)


# ============================================================================
# Data Structures
# ============================================================================

@dataclass
class DiscoveredEndpoint:
    """Represents a discovered application endpoint."""

    url: str
    method: str = "GET"  # GET, POST, etc.
    source: str = "html_link"  # html_link, js_api, form_action, redirect
    parameters: List[str] = field(default_factory=list)
    status_code: Optional[int] = None
    response_type: Optional[str] = None  # "html", "json", "redirect", etc.
    auth_required: bool = False
    redirect_target: Optional[str] = None
    confidence: float = 1.0  # 0.0-1.0, lower = suspicious/guessed


@dataclass
class DiscoveryStats:
    """Statistics from discovery phase."""

    urls_crawled: int = 0
    endpoints_discovered: int = 0
    js_files_analyzed: int = 0
    forms_found: int = 0
    parameters_found: int = 0
    redirects_followed: int = 0
    errors_encountered: int = 0
    crawl_duration_ms: float = 0.0


# ============================================================================
# HTML Parser for Link Extraction
# ============================================================================

class LinkExtractor(HTMLParser):
    """Extract links, forms, scripts, and images from HTML."""

    def __init__(self):
        super().__init__()
        self.links: Set[str] = set()
        self.form_actions: Set[Tuple[str, str]] = set()  # (action, method)
        self.scripts: Set[str] = set()
        self.images: Set[str] = set()
        self.current_form_method = "GET"

    def handle_starttag(self, tag, attrs):
        """Extract URLs from various HTML tags."""
        attrs_dict = dict(attrs)

        if tag == "a" and "href" in attrs_dict:
            href = attrs_dict["href"]
            if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                self.links.add(href)

        elif tag == "form":
            self.current_form_method = attrs_dict.get("method", "GET").upper()
            if "action" in attrs_dict:
                action = attrs_dict["action"]
                if action:
                    self.form_actions.add((action, self.current_form_method))

        elif tag == "script" and "src" in attrs_dict:
            src = attrs_dict["src"]
            if src:
                self.scripts.add(src)

        elif tag == "img" and "src" in attrs_dict:
            src = attrs_dict["src"]
            if src:
                self.images.add(src)

        elif tag == "link" and attrs_dict.get("rel") == "stylesheet":
            if "href" in attrs_dict:
                href = attrs_dict["href"]
                if href:
                    self.scripts.add(href)  # CSS might contain URL references


# ============================================================================
# Crawl Strategy & Controls
# ============================================================================

@dataclass
class CrawlStrategy:
    """Configuration for crawl behavior."""

    max_depth: int = 3
    max_urls: int = 200
    max_requests_per_second: float = 10.0
    follow_redirects: bool = True
    max_redirects: int = 5
    timeout_seconds: float = 15.0
    user_agent: str = "HybridScanner/2.0 (Security Assessment)"
    respect_robots_txt: bool = False  # Disabled for security assessment


class CrawlStateManager:
    """Manages crawl state to prevent loops and excessive requests."""

    def __init__(self, strategy: CrawlStrategy):
        self.strategy = strategy
        self.visited_urls: Set[str] = set()
        self.queued_urls: Set[str] = set()
        self.depth_map: Dict[str, int] = {}
        self.redirect_chains: Dict[str, List[str]] = {}
        self.requests_made: int = 0
        self.start_time: Optional[float] = None

    def should_crawl(self, url: str, current_depth: int) -> bool:
        """Determine if URL should be crawled."""
        # Already visited
        if url in self.visited_urls:
            return False

        # Over max depth
        if current_depth > self.strategy.max_depth:
            return False

        # Over max URLs
        if len(self.visited_urls) >= self.strategy.max_urls:
            return False

        # Invalid URL structure
        try:
            urlparse(url)
        except Exception:
            return False

        return True

    def mark_visited(self, url: str, depth: int):
        """Mark URL as visited."""
        self.visited_urls.add(url)
        self.depth_map[url] = depth
        self.requests_made += 1

    def add_redirect_chain(self, from_url: str, to_url: str):
        """Track redirect chain."""
        if from_url not in self.redirect_chains:
            self.redirect_chains[from_url] = [from_url]
        self.redirect_chains[from_url].append(to_url)

        # Detect loops
        if len(self.redirect_chains[from_url]) > self.strategy.max_redirects:
            logger.warning(f"Redirect loop detected for {from_url}")
            return False

        return True


# ============================================================================
# Attack Surface Discovery Engine
# ============================================================================

class AttackSurfaceDiscovery:
    """Discovers and maps application attack surface."""

    def __init__(self, strategy: Optional[CrawlStrategy] = None):
        self.strategy = strategy or CrawlStrategy()
        self.discovered_endpoints: Dict[str, DiscoveredEndpoint] = {}
        self.state_manager = CrawlStateManager(self.strategy)
        self.stats = DiscoveryStats()

    async def discover(
        self,
        target_url: str,
        client: httpx.AsyncClient,
    ) -> List[DiscoveredEndpoint]:
        """Execute attack surface discovery.

        Args:
            target_url: Starting URL for discovery
            client: httpx AsyncClient

        Returns:
            List of discovered endpoints
        """
        import time

        start_time = time.time()

        # Normalize target URL
        target_url = target_url.rstrip("/")

        # BFS crawl starting from target
        await self._crawl_recursive(target_url, client, depth=0)

        self.stats.crawl_duration_ms = (time.time() - start_time) * 1000
        self.stats.endpoints_discovered = len(self.discovered_endpoints)

        logger.info(
            f"Discovery complete: {self.stats.endpoints_discovered} endpoints, "
            f"{self.stats.urls_crawled} URLs crawled, "
            f"{self.stats.js_files_analyzed} JS files analyzed"
        )

        return list(self.discovered_endpoints.values())

    async def _crawl_recursive(
        self,
        url: str,
        client: httpx.AsyncClient,
        depth: int,
    ) -> None:
        """Recursively crawl and discover endpoints.

        Args:
            url: URL to crawl
            client: httpx AsyncClient
            depth: Current crawl depth
        """
        # Check if should crawl
        if not self.state_manager.should_crawl(url, depth):
            return

        self.state_manager.mark_visited(url, depth)
        self.stats.urls_crawled += 1

        try:
            # Fetch response
            response = await client.get(
                url,
                follow_redirects=False,
                timeout=self.strategy.timeout_seconds,
            )

            # Record endpoint
            await self._record_endpoint(url, response)

            # Handle redirects
            if response.status_code in {301, 302, 303, 307, 308}:
                location = response.headers.get("location")
                if location:
                    redirect_url = urljoin(url, location)
                    if self.state_manager.add_redirect_chain(url, redirect_url):
                        await self._crawl_recursive(
                            redirect_url, client, depth
                        )
                return  # Don't process body of redirect

            # Extract and crawl links if HTML
            if "text/html" in response.headers.get("content-type", ""):
                await self._extract_and_crawl_html(
                    url, response.text, client, depth
                )

            # Analyze JavaScript files
            if "javascript" in response.headers.get("content-type", ""):
                await self._analyze_javascript(url, response.text)

        except httpx.TimeoutException:
            logger.debug(f"Timeout crawling {url}")
            self.stats.errors_encountered += 1
        except httpx.RequestError as e:
            logger.debug(f"Error crawling {url}: {e}")
            self.stats.errors_encountered += 1
        except Exception as e:
            logger.debug(f"Unexpected error crawling {url}: {e}")
            self.stats.errors_encountered += 1

    async def _record_endpoint(
        self, url: str, response: httpx.Response
    ) -> None:
        """Record discovered endpoint."""
        # Create canonical URL (remove fragments, normalize)
        parsed = urlparse(url)
        canonical = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            canonical += f"?{parsed.query}"

        if canonical not in self.discovered_endpoints:
            # Detect if auth required (heuristic)
            auth_required = response.status_code in {
                401, 403
            } or "401" in response.text[:500]

            endpoint = DiscoveredEndpoint(
                url=canonical,
                status_code=response.status_code,
                response_type=self._get_response_type(response),
                auth_required=auth_required,
            )
            self.discovered_endpoints[canonical] = endpoint

    async def _extract_and_crawl_html(
        self,
        base_url: str,
        html_content: str,
        client: httpx.AsyncClient,
        depth: int,
    ) -> None:
        """Extract links from HTML and recursively crawl."""
        try:
            extractor = LinkExtractor()
            extractor.feed(html_content[:100000])  # Limit parsing to 100KB

            # Process links
            for link in extractor.links:
                abs_url = urljoin(base_url, link)

                # Only crawl same-origin URLs
                if not self._is_same_origin(base_url, abs_url):
                    continue

                # Record as discover source
                if self.state_manager.should_crawl(abs_url, depth + 1):
                    if abs_url not in self.discovered_endpoints:
                        self.discovered_endpoints[abs_url] = DiscoveredEndpoint(
                            url=abs_url,
                            source="html_link",
                            confidence=0.9,
                        )

                    # Recursively crawl
                    await self._crawl_recursive(abs_url, client, depth + 1)

            # Process form actions
            for action_url, method in extractor.form_actions:
                abs_url = urljoin(base_url, action_url)

                if self._is_same_origin(base_url, abs_url):
                    self.stats.forms_found += 1
                    if abs_url not in self.discovered_endpoints:
                        self.discovered_endpoints[abs_url] = DiscoveredEndpoint(
                            url=abs_url,
                            method=method,
                            source="form_action",
                            confidence=0.95,
                        )

            # Process script sources (for JS analysis)
            for script_url in extractor.scripts:
                abs_url = urljoin(base_url, script_url)

                if self._is_same_origin(base_url, abs_url):
                    if abs_url not in self.discovered_endpoints:
                        self.discovered_endpoints[abs_url] = DiscoveredEndpoint(
                            url=abs_url,
                            source="script_ref",
                            confidence=0.7,
                        )

        except Exception as e:
            logger.debug(f"Error extracting HTML from {base_url}: {e}")

    async def _analyze_javascript(
        self, url: str, js_content: str
    ) -> None:
        """Analyze JavaScript for API endpoints and URLs.

        Args:
            url: URL of JS file
            js_content: Content of JS file
        """
        self.stats.js_files_analyzed += 1

        # Extract API endpoints from common patterns
        patterns = [
            r'(?:fetch|axios|XMLHttpRequest)\s*\(\s*["\']([^"\']+)["\']',  # API calls
            r'/api/[a-zA-Z0-9/_-]+',  # API paths
            r'https?://[^\s"\']+',  # Full URLs
            r'endpoint\s*:\s*["\'](/[^"\']+)["\']',  # config endpoints
        ]

        for pattern in patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                # Normalize
                if match.startswith("http"):
                    if not match.startswith(urlparse(url).scheme):
                        continue
                    endpoint_url = match
                else:
                    endpoint_url = urljoin(urlparse(url).scheme + "://" + urlparse(url).netloc, match)

                if (
                    self._is_same_origin(urlparse(url).scheme + "://" + urlparse(url).netloc, endpoint_url)
                    and endpoint_url not in self.discovered_endpoints
                ):
                    self.discovered_endpoints[endpoint_url] = DiscoveredEndpoint(
                        url=endpoint_url,
                        source="js_api",
                        confidence=0.7,
                    )

    @staticmethod
    def _is_same_origin(base_url: str, target_url: str) -> bool:
        """Check if target URL is same origin as base URL."""
        base_parsed = urlparse(base_url)
        target_parsed = urlparse(target_url)

        return (
            base_parsed.scheme == target_parsed.scheme
            and base_parsed.netloc == target_parsed.netloc
        )

    @staticmethod
    def _get_response_type(response: httpx.Response) -> str:
        """Determine response type from content-type header."""
        content_type = response.headers.get("content-type", "").lower()

        if "json" in content_type:
            return "json"
        elif "html" in content_type:
            return "html"
        elif "xml" in content_type:
            return "xml"
        elif "text" in content_type:
            return "text"
        elif "redirect" or response.status_code in {301, 302, 307, 308}:
            return "redirect"

        return "unknown"
