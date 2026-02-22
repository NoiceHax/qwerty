"""Static scan engine — orchestrates repository-level security checks."""

from __future__ import annotations

import logging
import os
import tempfile
from typing import Any, Dict, List

from app.scanner.static.repo_cloner import RepoCloner
from app.scanner.static.secret_detector import SecretDetector
from app.scanner.static.sql_analyzer import SQLAnalyzer
from app.scanner.static.dangerous_functions import DangerousFunctionDetector
from app.scanner.static.debug_detector import DebugDetector
from app.scanner.static.dependency_auditor import DependencyAuditor
from app.scanner.static.misconfig_detector import MisconfigDetector

logger = logging.getLogger(__name__)
Finding = Dict[str, Any]

# File extensions to scan
_CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".rb", ".php", ".go", ".rs",
    ".c", ".cpp", ".cs", ".swift", ".kt",
    ".yml", ".yaml", ".json", ".xml", ".toml",
    ".env", ".cfg", ".ini", ".conf",
    ".sh", ".bash", ".zsh",
    ".html", ".htm",
    ".sql",
    ".dockerfile", ".tf",  # Dockerfile, Terraform
}

_SKIP_DIRS = {
    "node_modules", ".git", ".svn", "__pycache__",
    "venv", ".venv", "env", ".env",
    "dist", "build", ".next", ".nuxt",
    "vendor", "bower_components",
    ".tox", ".pytest_cache", ".mypy_cache",
    "coverage", ".coverage",
}

MAX_FILE_SIZE = 1_000_000  # 1 MB


class StaticScanEngine:
    """Scans a cloned repository for security issues."""

    async def run(self, repo_url: str) -> List[Finding]:
        """Clone the repo and run all static analysers."""
        findings: List[Finding] = []

        cloner = RepoCloner()
        repo_path = None

        try:
            repo_path = await cloner.clone(repo_url)
            if not repo_path:
                findings.append({
                    "vuln_type": "clone_error",
                    "title": "Failed to clone repository",
                    "description": f"Could not clone {repo_url}",
                    "severity": "info",
                    "confidence": "high",
                    "detection_source": "static:engine",
                })
                return findings

            findings = await self.run_on_path(repo_path)

        finally:
            if repo_path:
                await cloner.cleanup(repo_path)

        return findings

    async def run_on_path(self, repo_path: str) -> List[Finding]:
        """Run all static analysers on an already-cloned repo path."""
        findings: List[Finding] = []

        # Walk file tree and collect code files
        code_files = self._collect_files(repo_path)
        logger.info(f"Static scan: {len(code_files)} files to analyse in {repo_path}")

        # Read file contents
        file_contents: Dict[str, str] = {}
        for fpath in code_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    file_contents[fpath] = f.read()
            except Exception:
                continue

        # Run analysers
        analysers = [
            SecretDetector(),
            SQLAnalyzer(),
            DangerousFunctionDetector(),
            DebugDetector(),
            MisconfigDetector(),
        ]

        for analyser in analysers:
            try:
                result = analyser.analyze(file_contents, repo_path)
                findings.extend(result)
            except Exception as exc:
                logger.warning(f"Analyser {analyser.__class__.__name__} failed: {exc}")

        # Dependency audit (needs repo path, not file contents)
        try:
            dep_auditor = DependencyAuditor()
            dep_findings = await dep_auditor.analyze(repo_path)
            findings.extend(dep_findings)
        except Exception as exc:
            logger.warning(f"Dependency audit failed: {exc}")

        logger.info(f"Static scan produced {len(findings)} findings")
        return findings

    def _collect_files(self, root: str) -> List[str]:
        """Walk directory tree, collecting code files."""
        files: List[str] = []
        for dirpath, dirnames, filenames in os.walk(root):
            # Skip uninteresting directories
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]

            for fname in filenames:
                ext = os.path.splitext(fname)[1].lower()
                if ext in _CODE_EXTENSIONS or fname in (".env", "Dockerfile", "Makefile"):
                    fpath = os.path.join(dirpath, fname)
                    try:
                        if os.path.getsize(fpath) <= MAX_FILE_SIZE:
                            files.append(fpath)
                    except OSError:
                        continue
        return files
