"""Hardcoded secrets detection via regex + entropy analysis."""

from __future__ import annotations

import math
import os
import re
from typing import Any, Dict, List

Finding = Dict[str, Any]

# Known secret patterns
_SECRET_PATTERNS = [
    # AWS
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID", "critical"),
    (re.compile(r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"), "AWS Secret Access Key", "critical"),

    # GitHub
    (re.compile(r"gh[ps]_[A-Za-z0-9_]{36,}"), "GitHub Token", "critical"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{22,}"), "GitHub Personal Access Token", "critical"),

    # Generic API keys
    (re.compile(r"(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?", re.I), "API Key", "high"),
    (re.compile(r"(?:secret[_-]?key|secretkey)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?", re.I), "Secret Key", "high"),
    (re.compile(r"(?:access[_-]?token|accesstoken)\s*[=:]\s*['\"]?([A-Za-z0-9_\-\.]{20,})['\"]?", re.I), "Access Token", "high"),

    # JWT
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "JWT Token", "high"),

    # Private keys
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "Private Key", "critical"),

    # Database URLs
    (re.compile(r"(?:mysql|postgres|postgresql|mongodb|redis)://[^\s'\"]{10,}", re.I), "Database Connection String", "critical"),

    # Slack
    (re.compile(r"xox[bpas]-[A-Za-z0-9-]{10,}"), "Slack Token", "high"),

    # Stripe
    (re.compile(r"sk_live_[A-Za-z0-9]{24,}"), "Stripe Live Secret Key", "critical"),
    (re.compile(r"pk_live_[A-Za-z0-9]{24,}"), "Stripe Live Publishable Key", "medium"),

    # Google
    (re.compile(r"AIza[A-Za-z0-9_\-]{35}"), "Google API Key", "high"),

    # Heroku
    (re.compile(r"heroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", re.I), "Heroku API Key", "high"),

    # Twilio
    (re.compile(r"SK[0-9a-fA-F]{32}"), "Twilio API Key", "high"),

    # SendGrid
    (re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"), "SendGrid API Key", "high"),

    # Password in config
    (re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]", re.I), "Hardcoded Password", "high"),
]

# Files to skip (test fixtures, examples, docs)
_SKIP_PATTERNS = [
    re.compile(r"test[_s]?.*\.py$", re.I),
    re.compile(r"\.example$", re.I),
    re.compile(r"\.sample$", re.I),
    re.compile(r"\.md$", re.I),
    re.compile(r"\.lock$", re.I),
]


class SecretDetector:
    """Detects hardcoded secrets using regex and entropy analysis."""

    ENTROPY_THRESHOLD = 4.5  # Shannon entropy threshold for random strings
    MIN_SECRET_LENGTH = 16

    def analyze(self, file_contents: Dict[str, str], repo_root: str) -> List[Finding]:
        findings: List[Finding] = []
        seen: set = set()  # deduplicate

        for filepath, content in file_contents.items():
            rel_path = os.path.relpath(filepath, repo_root)

            # Skip non-interesting files
            if any(p.search(rel_path) for p in _SKIP_PATTERNS):
                continue

            for line_num, line in enumerate(content.splitlines(), 1):
                # Skip comments
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("//"):
                    continue

                for pattern, name, severity in _SECRET_PATTERNS:
                    match = pattern.search(line)
                    if match:
                        secret_val = match.group(0)[:8] + "..." if len(match.group(0)) > 8 else match.group(0)
                        key = f"{rel_path}:{line_num}:{name}"
                        if key in seen:
                            continue
                        seen.add(key)

                        findings.append({
                            "vuln_type": "hardcoded_secret",
                            "title": f"{name} found in {rel_path}",
                            "description": f"Potential {name} detected at line {line_num}.",
                            "severity": severity,
                            "confidence": "high",
                            "detection_source": "static:secret_detector",
                            "remediation": (
                                f"Remove the {name.lower()} from source code. "
                                f"Use environment variables or a secrets manager. "
                                f"Rotate the exposed credential immediately."
                            ),
                            "evidence": f"File: {rel_path}\nLine {line_num}: {self._mask(line.strip())}",
                            "location": f"{rel_path}:{line_num}",
                        })

            # Entropy-based detection for high-entropy strings
            entropy_findings = self._entropy_scan(content, rel_path)
            for ef in entropy_findings:
                key = f"{rel_path}:{ef['location']}"
                if key not in seen:
                    seen.add(key)
                    findings.append(ef)

        return findings

    def _entropy_scan(self, content: str, rel_path: str) -> List[Finding]:
        """Find high-entropy strings that might be secrets."""
        findings: List[Finding] = []
        assignment_pattern = re.compile(
            r"""(?:key|secret|token|password|credential|auth)\s*[=:]\s*['"]([A-Za-z0-9+/=_\-]{20,})['"]""",
            re.I,
        )

        for line_num, line in enumerate(content.splitlines(), 1):
            for match in assignment_pattern.finditer(line):
                value = match.group(1)
                entropy = self._shannon_entropy(value)
                if entropy >= self.ENTROPY_THRESHOLD and len(value) >= self.MIN_SECRET_LENGTH:
                    findings.append({
                        "vuln_type": "high_entropy_secret",
                        "title": f"High-entropy string in {rel_path}",
                        "description": f"Suspicious high-entropy value (entropy: {entropy:.2f}) at line {line_num}.",
                        "severity": "medium",
                        "confidence": "medium",
                        "detection_source": "static:secret_detector",
                        "remediation": "Verify if this is a secret. If so, use environment variables.",
                        "evidence": f"File: {rel_path}\nLine {line_num}: {self._mask(line.strip())}",
                        "location": f"{rel_path}:{line_num}",
                    })
        return findings

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        freq: Dict[str, int] = {}
        for c in data:
            freq[c] = freq.get(c, 0) + 1
        length = len(data)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    @staticmethod
    def _mask(line: str, max_len: int = 120) -> str:
        """Mask potential secrets in the line for reporting."""
        if len(line) > max_len:
            return line[:max_len] + "..."
        return line
