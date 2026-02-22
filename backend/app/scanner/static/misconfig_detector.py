"""Security misconfiguration detection in source code."""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List

Finding = Dict[str, Any]

_MISCONFIG_PATTERNS = [
    # CSRF disabled
    (re.compile(r"""(?:csrf_enabled|WTF_CSRF_ENABLED|CSRF_ENABLED)\s*=\s*(False|0|false)""", re.I),
     "CSRF protection disabled", "high",
     "Re-enable CSRF protection. It prevents cross-site request forgery attacks."),

    # Wildcard CORS
    (re.compile(r"""CORS\s*\(\s*\w+\s*,?\s*(?:origins?\s*=\s*['"]\*['"]|resources\s*=.*['"]\*['"])""", re.I),
     "CORS allows all origins", "medium",
     "Restrict CORS origins to specific trusted domains instead of wildcard '*'."),

    (re.compile(r"""allow_origins\s*=\s*\[?\s*['"]\*['"]\s*\]?""", re.I),
     "FastAPI CORS allows all origins", "medium",
     "Specify exact allowed origins instead of '*'."),

    (re.compile(r"""Access-Control-Allow-Origin['"]\s*:\s*['"]\*['"]""", re.I),
     "Hardcoded wildcard CORS header", "medium",
     "Set specific origins in Access-Control-Allow-Origin."),

    # No authentication
    (re.compile(r"""@(app|router)\.(get|post|put|delete|patch)\s*\(\s*['"]/(?:api/)?(?:users|admin|settings|config)""", re.I),
     "Sensitive endpoint may lack authentication", "medium",
     "Ensure authentication/authorization middleware is applied to sensitive endpoints."),

    # Weak password requirements
    (re.compile(r"""(?:min_length|minlength|MIN_PASSWORD|password_min)\s*=\s*([1-5])\b""", re.I),
     "Weak password minimum length", "medium",
     "Set minimum password length to at least 8 characters, preferably 12+."),

    # Insecure session configuration
    (re.compile(r"""SESSION_COOKIE_SECURE\s*=\s*(False|0)""", re.I),
     "Session cookie not marked Secure", "medium",
     "Set SESSION_COOKIE_SECURE = True to prevent session hijacking over HTTP."),

    (re.compile(r"""SESSION_COOKIE_HTTPONLY\s*=\s*(False|0)""", re.I),
     "Session cookie missing HttpOnly", "medium",
     "Set SESSION_COOKIE_HTTPONLY = True to prevent JavaScript access to session cookies."),

    # SSL verification disabled
    (re.compile(r"""verify\s*=\s*False""", re.I),
     "SSL verification disabled", "high",
     "Enable SSL certificate verification. Disabling it allows man-in-the-middle attacks."),

    (re.compile(r"""VERIFY_SSL\s*=\s*(False|0)""", re.I),
     "SSL verification disabled via config", "high",
     "Enable SSL verification in production."),

    # JWT with none algorithm
    (re.compile(r"""algorithms?\s*=\s*\[.*['"]none['"]""", re.I),
     "JWT allows 'none' algorithm", "critical",
     "Remove 'none' from allowed JWT algorithms. It allows token forgery."),

    (re.compile(r"""algorithm\s*=\s*['"]none['"]""", re.I),
     "JWT using 'none' algorithm", "critical",
     "Never use 'none' JWT algorithm. Use RS256 or HS256 with a strong secret."),

    # Hardcoded JWT secret
    (re.compile(r"""JWT_SECRET\s*=\s*['"](?:secret|password|changeme|12345)['"]""", re.I),
     "Weak/default JWT secret", "critical",
     "Use a strong, random JWT secret. Load from environment variables."),

    # Permissive file permissions
    (re.compile(r"""os\.chmod\s*\(\s*\w+\s*,\s*0o?777""", re.I),
     "World-writable file permissions (777)", "high",
     "Use restrictive file permissions (e.g., 0o644 or 0o600)."),

    # SQL AUTOCOMMIT
    (re.compile(r"""AUTOCOMMIT\s*=\s*True""", re.I),
     "Database autocommit enabled", "low",
     "Consider using explicit transactions for data consistency."),

    # AllowAny permission (Django REST)
    (re.compile(r"""permission_classes\s*=\s*\[?\s*AllowAny""", re.I),
     "AllowAny permission on endpoint", "medium",
     "Use IsAuthenticated or more restrictive permissions for sensitive endpoints."),
]


class MisconfigDetector:
    """Detects security misconfigurations in application code and config files."""

    def analyze(self, file_contents: Dict[str, str], repo_root: str) -> List[Finding]:
        findings: List[Finding] = []

        for filepath, content in file_contents.items():
            rel_path = os.path.relpath(filepath, repo_root)

            for line_num, line in enumerate(content.splitlines(), 1):
                for pattern, title, severity, remediation in _MISCONFIG_PATTERNS:
                    if pattern.search(line):
                        findings.append({
                            "vuln_type": "security_misconfiguration",
                            "title": f"{title} in {rel_path}",
                            "description": f"Security misconfiguration detected at line {line_num}.",
                            "severity": severity,
                            "confidence": "high",
                            "detection_source": "static:misconfig_detector",
                            "remediation": remediation,
                            "evidence": line.strip()[:200],
                            "location": f"{rel_path}:{line_num}",
                        })
                        break  # One finding per line

        return findings
