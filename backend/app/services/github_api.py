"""GitHub REST API service layer.

Fetches repository intelligence without cloning:
- Repo metadata, file tree, README, language breakdown
- Rate limit tracking and structured error handling
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

import httpx

from app.config import settings

logger = logging.getLogger(__name__)


class GitHubAPIError(Exception):
    """Base error for GitHub API issues."""
    def __init__(self, message: str, status_code: int = 0):
        super().__init__(message)
        self.status_code = status_code


class RepoNotFound(GitHubAPIError):
    pass


class RateLimited(GitHubAPIError):
    pass


class AuthError(GitHubAPIError):
    pass


def parse_github_url(url: str) -> Optional[Tuple[str, str]]:
    """Extract (owner, repo) from a GitHub URL.

    Handles:
        https://github.com/owner/repo
        https://github.com/owner/repo.git
        https://github.com/owner/repo/tree/branch
        github.com/owner/repo
    """
    url = url.strip().rstrip("/")
    # Remove .git suffix
    if url.endswith(".git"):
        url = url[:-4]

    patterns = [
        r"github\.com/([^/]+)/([^/]+)",
    ]
    for pat in patterns:
        m = re.search(pat, url)
        if m:
            return m.group(1), m.group(2)
    return None


class GitHubAPIService:
    """Lightweight GitHub REST API client."""

    BASE = "https://api.github.com"

    def __init__(self):
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if settings.github_token:
            headers["Authorization"] = f"Bearer {settings.github_token}"

        self._client = httpx.AsyncClient(
            base_url=self.BASE,
            headers=headers,
            timeout=settings.github_api_timeout,
        )
        self._rate_remaining: Optional[int] = None

    async def close(self):
        await self._client.aclose()

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _track_rate_limit(self, resp: httpx.Response):
        remaining = resp.headers.get("X-RateLimit-Remaining")
        if remaining is not None:
            self._rate_remaining = int(remaining)
            if self._rate_remaining < 10:
                logger.warning(f"GitHub API rate limit low: {self._rate_remaining} remaining")

    def _handle_error(self, resp: httpx.Response, context: str):
        if resp.status_code == 404:
            raise RepoNotFound(f"{context}: repository not found", 404)
        if resp.status_code == 403:
            raise RateLimited(f"{context}: rate limited or forbidden", 403)
        if resp.status_code == 401:
            raise AuthError(f"{context}: authentication failed", 401)
        if resp.status_code >= 400:
            raise GitHubAPIError(f"{context}: HTTP {resp.status_code}", resp.status_code)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    async def get_repo_metadata(self, owner: str, repo: str) -> Dict[str, Any]:
        """GET /repos/{owner}/{repo}"""
        resp = await self._client.get(f"/repos/{owner}/{repo}")
        self._track_rate_limit(resp)
        self._handle_error(resp, f"get_repo_metadata({owner}/{repo})")
        data = resp.json()
        logger.info(f"GitHub API: fetched metadata for {owner}/{repo} (size={data.get('size')}KB)")
        return data

    async def get_file_tree(self, owner: str, repo: str, branch: str = "main") -> List[Dict[str, Any]]:
        """GET /repos/{owner}/{repo}/git/trees/{branch}?recursive=1"""
        resp = await self._client.get(
            f"/repos/{owner}/{repo}/git/trees/{branch}",
            params={"recursive": "1"},
        )
        self._track_rate_limit(resp)
        self._handle_error(resp, f"get_file_tree({owner}/{repo})")
        data = resp.json()
        tree = data.get("tree", [])
        logger.info(f"GitHub API: file tree has {len(tree)} entries")
        return tree

    async def get_readme(self, owner: str, repo: str) -> Optional[str]:
        """GET /repos/{owner}/{repo}/readme (decoded content)."""
        try:
            resp = await self._client.get(
                f"/repos/{owner}/{repo}/readme",
                headers={"Accept": "application/vnd.github.raw+json"},
            )
            self._track_rate_limit(resp)
            if resp.status_code == 404:
                return None
            self._handle_error(resp, f"get_readme({owner}/{repo})")
            return resp.text[:2000]  # cap at 2000 chars
        except GitHubAPIError:
            return None

    async def get_languages(self, owner: str, repo: str) -> Dict[str, int]:
        """GET /repos/{owner}/{repo}/languages → {language: bytes}"""
        resp = await self._client.get(f"/repos/{owner}/{repo}/languages")
        self._track_rate_limit(resp)
        self._handle_error(resp, f"get_languages({owner}/{repo})")
        return resp.json()

    async def get_full_intelligence(self, owner: str, repo: str) -> Dict[str, Any]:
        """Fetch all intelligence in parallel-ish calls."""
        metadata = await self.get_repo_metadata(owner, repo)
        default_branch = metadata.get("default_branch", "main")

        # These can fail independently
        tree = []
        readme = None
        languages = {}

        try:
            tree = await self.get_file_tree(owner, repo, default_branch)
        except GitHubAPIError as e:
            logger.warning(f"File tree fetch failed: {e}")

        try:
            readme = await self.get_readme(owner, repo)
        except Exception as e:
            logger.warning(f"README fetch failed: {e}")

        try:
            languages = await self.get_languages(owner, repo)
        except GitHubAPIError as e:
            logger.warning(f"Languages fetch failed: {e}")

        return {
            "metadata": metadata,
            "default_branch": default_branch,
            "tree": tree,
            "readme": readme,
            "languages": languages,
        }
