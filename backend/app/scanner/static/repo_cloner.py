"""Repository cloning via git."""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
from typing import Optional

from app.config import settings
from app.safety.validators import is_github_url

logger = logging.getLogger(__name__)


class RepoCloner:
    """Clones a git repository to a temporary directory."""

    async def clone(self, repo_url: str) -> Optional[str]:
        """Clone ``repo_url`` and return the local path, or None on failure."""
        import git  # gitpython

        # Normalise GitHub URLs
        if is_github_url(repo_url):
            if not repo_url.endswith(".git"):
                repo_url = repo_url.rstrip("/") + ".git"

        tmp_dir = tempfile.mkdtemp(prefix="scanner_repo_")

        try:
            logger.info(f"Cloning {repo_url} → {tmp_dir}")
            git.Repo.clone_from(
                repo_url,
                tmp_dir,
                depth=settings.clone_depth,
                single_branch=True,
            )
            return tmp_dir
        except git.exc.GitCommandError as exc:
            logger.error(f"Git clone failed: {exc}")
            shutil.rmtree(tmp_dir, ignore_errors=True)
            return None
        except Exception as exc:
            logger.error(f"Clone error: {exc}")
            shutil.rmtree(tmp_dir, ignore_errors=True)
            return None

    async def cleanup(self, path: str) -> None:
        """Remove the cloned repo directory."""
        try:
            shutil.rmtree(path, ignore_errors=True)
            logger.debug(f"Cleaned up {path}")
        except Exception as exc:
            logger.warning(f"Cleanup failed for {path}: {exc}")
