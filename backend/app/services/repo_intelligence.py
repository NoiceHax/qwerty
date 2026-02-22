"""Repository intelligence — analyses GitHub API data without cloning.

Produces tech stack detection, complexity estimation, and security surface hints.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Output schema
# ---------------------------------------------------------------------------

class RepoIntelReport(BaseModel):
    owner: str
    repo_name: str
    default_branch: str
    size_kb: int
    stars: int
    forks: int
    language_breakdown: Dict[str, float]      # percentages
    primary_language: Optional[str] = None
    tech_stack: List[str] = []
    complexity: str = "low"                    # low | medium | high
    file_count: int = 0
    has_ci: bool = False
    has_docker: bool = False
    has_env_example: bool = False
    has_lockfile: bool = False
    homepage_url: Optional[str] = None
    readme_preview: Optional[str] = None
    security_signals: List[str] = []
    description: Optional[str] = None


# ---------------------------------------------------------------------------
# Tech stack heuristics
# ---------------------------------------------------------------------------

_FILE_TECH_MAP = {
    "package.json": "Node.js",
    "requirements.txt": "Python",
    "Pipfile": "Python",
    "pyproject.toml": "Python",
    "Gemfile": "Ruby",
    "go.mod": "Go",
    "Cargo.toml": "Rust",
    "pom.xml": "Java/Maven",
    "build.gradle": "Java/Gradle",
    "composer.json": "PHP",
    "Dockerfile": "Docker",
    "docker-compose.yml": "Docker Compose",
    "docker-compose.yaml": "Docker Compose",
    ".github/workflows": "GitHub Actions CI",
    ".gitlab-ci.yml": "GitLab CI",
    "Jenkinsfile": "Jenkins CI",
    "netlify.toml": "Netlify",
    "vercel.json": "Vercel",
    "next.config.js": "Next.js",
    "next.config.mjs": "Next.js",
    "nuxt.config.ts": "Nuxt.js",
    "vite.config.ts": "Vite",
    "vite.config.js": "Vite",
    "angular.json": "Angular",
    "tsconfig.json": "TypeScript",
    "webpack.config.js": "Webpack",
    "tailwind.config.js": "TailwindCSS",
    "prisma/schema.prisma": "Prisma ORM",
    "alembic.ini": "Alembic (SQLAlchemy)",
    "manage.py": "Django",
    "app.py": "Flask/FastAPI",
    "main.py": "Python App",
    ".env.example": "Environment Config",
    "terraform": "Terraform",
}

_LOCKFILE_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Pipfile.lock", "poetry.lock",
    "Gemfile.lock", "go.sum", "Cargo.lock",
    "composer.lock",
}

_CI_PATHS = {".github/workflows", ".gitlab-ci.yml", "Jenkinsfile", ".circleci"}


class RepoIntelligence:
    """Analyses GitHub API data to produce intelligence report."""

    async def analyze(
        self,
        metadata: Dict[str, Any],
        tree: List[Dict[str, Any]],
        languages: Dict[str, int],
        readme: Optional[str] = None,
    ) -> RepoIntelReport:
        owner = metadata.get("owner", {}).get("login", "unknown")
        repo_name = metadata.get("name", "unknown")
        default_branch = metadata.get("default_branch", "main")

        # --- Language breakdown ---
        total_bytes = sum(languages.values()) or 1
        lang_breakdown = {
            lang: round(bytes_count / total_bytes * 100, 1)
            for lang, bytes_count in sorted(languages.items(), key=lambda x: -x[1])
        }
        primary_lang = next(iter(lang_breakdown), None)

        # --- File tree analysis ---
        file_paths = [n.get("path", "") for n in tree if n.get("type") == "blob"]
        file_count = len(file_paths)
        dir_paths = [n.get("path", "") for n in tree if n.get("type") == "tree"]

        # --- Tech stack detection ---
        tech_stack = set()
        for fpath in file_paths:
            basename = fpath.split("/")[-1]
            if basename in _FILE_TECH_MAP:
                tech_stack.add(_FILE_TECH_MAP[basename])
            # Check path-based patterns
            for pattern, tech in _FILE_TECH_MAP.items():
                if "/" in pattern and fpath.startswith(pattern):
                    tech_stack.add(tech)

        # Add language-based techs
        for lang in languages:
            if lang == "Python":
                tech_stack.add("Python")
            elif lang == "JavaScript":
                tech_stack.add("JavaScript")
            elif lang == "TypeScript":
                tech_stack.add("TypeScript")

        # --- Security signals ---
        signals = []
        has_lockfile = any(fp.split("/")[-1] in _LOCKFILE_NAMES for fp in file_paths)
        if not has_lockfile:
            signals.append("no_lockfile")

        has_env = any(fp.split("/")[-1] == ".env" for fp in file_paths)
        if has_env:
            signals.append("env_file_in_repo")

        has_env_example = any(".env.example" in fp or ".env.sample" in fp for fp in file_paths)

        has_docker = any("Dockerfile" in fp.split("/")[-1] or "docker-compose" in fp for fp in file_paths)

        has_ci = any(
            any(fp.startswith(ci) or fp.split("/")[-1] == ci for ci in _CI_PATHS)
            for fp in file_paths + dir_paths
        )

        if not has_ci:
            signals.append("no_ci_pipeline")

        # --- Complexity ---
        if file_count > 500 or len(languages) > 5:
            complexity = "high"
        elif file_count > 100 or len(languages) > 3:
            complexity = "medium"
        else:
            complexity = "low"

        # --- Homepage ---
        homepage = metadata.get("homepage") or None

        report = RepoIntelReport(
            owner=owner,
            repo_name=repo_name,
            default_branch=default_branch,
            size_kb=metadata.get("size", 0),
            stars=metadata.get("stargazers_count", 0),
            forks=metadata.get("forks_count", 0),
            language_breakdown=lang_breakdown,
            primary_language=primary_lang,
            tech_stack=sorted(tech_stack),
            complexity=complexity,
            file_count=file_count,
            has_ci=has_ci,
            has_docker=has_docker,
            has_env_example=has_env_example,
            has_lockfile=has_lockfile,
            homepage_url=homepage,
            readme_preview=readme[:500] if readme else None,
            security_signals=signals,
            description=metadata.get("description"),
        )

        logger.info(
            f"RepoIntel: {owner}/{repo_name} — "
            f"{file_count} files, {complexity} complexity, "
            f"stack={report.tech_stack}"
        )
        return report
