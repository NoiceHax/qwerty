"""Debug and development artifact detection."""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List

Finding = Dict[str, Any]

_DEBUG_PATTERNS = [
    # Python
    (re.compile(r"""DEBUG\s*=\s*(True|1|'True'|"True")""", re.I),
     "Debug mode enabled", "high",
     "Set DEBUG = False in production. Debug mode exposes sensitive information."),

    (re.compile(r"""app\.run\s*\(.*debug\s*=\s*True""", re.I),
     "Flask debug mode enabled", "high",
     "Remove debug=True from app.run() in production. Use environment variables."),

    (re.compile(r"""FLASK_DEBUG\s*=\s*(1|True|true)""", re.I),
     "FLASK_DEBUG enabled", "high",
     "Set FLASK_DEBUG=0 in production."),

    (re.compile(r"""DJANGO_DEBUG\s*=\s*(True|1)""", re.I),
     "Django debug mode enabled", "high",
     "Set DJANGO_DEBUG=False in production settings."),

    # Verbose logging of sensitive data
    (re.compile(r"""(log|print|console\.log)\s*\(.*(?:password|token|secret|key|credential)""", re.I),
     "Sensitive data logging", "medium",
     "Remove logging of sensitive data (passwords, tokens, keys) in production code."),

    # TODO/FIXME security notes
    (re.compile(r"""#\s*(TODO|FIXME|HACK|XXX).*(?:security|vuln|auth|password|inject)""", re.I),
     "Security-related TODO/FIXME found", "low",
     "Address security-related TODO/FIXME comments before production deployment."),

    # Test/stub routes
    (re.compile(r"""@(app|router)\.(get|post|put|delete)\s*\(\s*['"](/test|/debug|/dev)['"]\s*\)""", re.I),
     "Test/debug route defined", "medium",
     "Remove test and debug routes before production deployment."),

    # JS/TS debug
    (re.compile(r"""console\.(log|debug|trace)\s*\(""", re.I),
     "Console debug output", "info",
     "Remove console.log/debug statements in production. Use a proper logging library."),

    # Source maps
    (re.compile(r"""sourceMappingURL""", re.I),
     "Source map reference found", "low",
     "Remove source maps in production to prevent source code exposure."),

    # Express/Node debug
    (re.compile(r"""app\.use\s*\(\s*(?:errorHandler|morgan\s*\(\s*['"]dev['"])""", re.I),
     "Development middleware in use", "medium",
     "Remove development middleware (errorHandler, morgan 'dev') in production."),
]

# Files that shouldn't exist in production
_DEBUG_FILES = [
    ".env", ".env.local", ".env.development",
    "debug.py", "debug.js",
    "test_server.py",
    "docker-compose.dev.yml",
    "Dockerfile.dev",
    ".vscode/launch.json",
]


class DebugDetector:
    """Detects debug configurations and development artifacts."""

    def analyze(self, file_contents: Dict[str, str], repo_root: str) -> List[Finding]:
        findings: List[Finding] = []

        for filepath, content in file_contents.items():
            rel_path = os.path.relpath(filepath, repo_root)

            # Check for debug patterns in code
            for line_num, line in enumerate(content.splitlines(), 1):
                for pattern, title, severity, remediation in _DEBUG_PATTERNS:
                    if pattern.search(line):
                        findings.append({
                            "vuln_type": "debug_artifact",
                            "title": f"{title} in {rel_path}",
                            "description": f"Debug/development artifact detected at line {line_num}.",
                            "severity": severity,
                            "confidence": "high",
                            "detection_source": "static:debug_detector",
                            "remediation": remediation,
                            "evidence": line.strip()[:200],
                            "location": f"{rel_path}:{line_num}",
                        })
                        break

            # Check for debug-related files
            basename = os.path.basename(filepath)
            if basename in _DEBUG_FILES:
                findings.append({
                    "vuln_type": "debug_file",
                    "title": f"Development file found: {basename}",
                    "description": f"File '{rel_path}' is typically a development artifact.",
                    "severity": "low",
                    "confidence": "medium",
                    "detection_source": "static:debug_detector",
                    "remediation": f"Remove or exclude '{basename}' from production deployments.",
                    "location": rel_path,
                })

        return findings
