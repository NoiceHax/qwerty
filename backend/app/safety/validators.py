"""Input validation & abuse prevention for scan targets."""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Optional, Tuple
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Blocked network ranges
# ---------------------------------------------------------------------------

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),       # loopback
    ipaddress.ip_network("10.0.0.0/8"),         # private A
    ipaddress.ip_network("172.16.0.0/12"),      # private B
    ipaddress.ip_network("192.168.0.0/16"),     # private C
    ipaddress.ip_network("169.254.0.0/16"),     # link-local
    ipaddress.ip_network("0.0.0.0/8"),          # unspecified
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
]

_BLOCKED_HOSTNAMES = {"localhost", "localhost.localdomain", "ip6-localhost"}

_GITHUB_URL_PATTERN = re.compile(
    r"^https?://github\.com/(?P<owner>[\w\-\.]+)/(?P<repo>[\w\-\.]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)


class ValidationError(Exception):
    """Raised when input validation fails."""
    def __init__(self, message: str, field: str = "target_url"):
        self.message = message
        self.field = field
        super().__init__(message)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate_target_url(url: str) -> str:
    """Validate & normalise a target URL. Returns the clean URL.

    Raises ``ValidationError`` on any problem.
    """
    url = url.strip()
    if not url:
        raise ValidationError("Target URL cannot be empty.")

    parsed = urlparse(url)

    # Scheme check
    if parsed.scheme not in ("http", "https"):
        raise ValidationError(
            f"Unsupported scheme '{parsed.scheme}'. Only http and https are allowed."
        )

    hostname = parsed.hostname
    if not hostname:
        raise ValidationError("Could not extract hostname from the URL.")

    # Blocked hostname check
    if hostname.lower() in _BLOCKED_HOSTNAMES:
        raise ValidationError(f"Scanning '{hostname}' is not allowed.")

    # IP literal check
    try:
        ip = ipaddress.ip_address(hostname)
        if any(ip in net for net in _BLOCKED_NETWORKS):
            raise ValidationError(
                f"Scanning private/reserved IP address '{hostname}' is not allowed."
            )
    except ValueError:
        # Not an IP literal — resolve DNS and check
        _check_resolved_ips(hostname)

    return url


def validate_github_url(url: str) -> Tuple[str, str]:
    """Validate a GitHub repo URL and return (owner, repo)."""
    url = url.strip()
    match = _GITHUB_URL_PATTERN.match(url)
    if not match:
        raise ValidationError(
            "Invalid GitHub URL. Expected format: https://github.com/owner/repo"
        )
    return match.group("owner"), match.group("repo")


def is_github_url(url: str) -> bool:
    return bool(_GITHUB_URL_PATTERN.match(url.strip()))


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _check_resolved_ips(hostname: str) -> None:
    """Resolve hostname and verify none of its IPs are blocked."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
    except socket.gaierror:
        raise ValidationError(f"Could not resolve hostname '{hostname}'.")

    for _family, _type, _proto, _canonname, sockaddr in results:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
            if any(ip in net for net in _BLOCKED_NETWORKS):
                raise ValidationError(
                    f"Hostname '{hostname}' resolves to a blocked address ({ip_str})."
                )
        except ValueError:
            continue
