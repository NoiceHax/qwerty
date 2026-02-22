"""Clone manager — handles selective repository cloning.

Only clones when the scan decision engine says it's needed.
Uses shallow clone, temp dirs, and cleanup.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
from typing import Optional

from app.config import settings
from app.safety.validators import is_github_url

logger = logging.getLogger(__name__)


class CloneManager:
    """Manages conditional git cloning with cleanup."""

    async def clone_if_needed(self, repo_url: str, needs_clone: bool) -> Optional[str]:
        """Clone the repo if required; return local path or None."""
        if not needs_clone:
            logger.info("CloneManager: cloning not required, skipping")
            return None

        return await self._do_clone(repo_url)

    async def _do_clone(self, repo_url: str) -> Optional[str]:
        import git

        # Normalise GitHub URLs
        if is_github_url(repo_url):
            if not repo_url.endswith(".git"):
                repo_url = repo_url.rstrip("/") + ".git"

        tmp_dir = tempfile.mkdtemp(prefix="scanner_repo_")

        try:
            logger.info(f"CloneManager: cloning {repo_url} → {tmp_dir}")
            git.Repo.clone_from(
                repo_url,
                tmp_dir,
                depth=settings.clone_depth,
                single_branch=True,
            )
            logger.info(f"CloneManager: clone successful → {tmp_dir}")
            return tmp_dir
        except git.exc.GitCommandError as exc:
            logger.error(f"CloneManager: git clone failed: {exc}")
            shutil.rmtree(tmp_dir, ignore_errors=True)
            return None
        except Exception as exc:
            logger.error(f"CloneManager: clone error: {exc}")
            shutil.rmtree(tmp_dir, ignore_errors=True)
            return None

    async def cleanup(self, path: str) -> None:
        """Remove cloned repo directory."""
        try:
            shutil.rmtree(path, ignore_errors=True)
            logger.debug(f"CloneManager: cleaned up {path}")
        except Exception as exc:
            logger.warning(f"CloneManager: cleanup failed for {path}: {exc}")
