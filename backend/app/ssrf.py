"""SSRF protection helpers.

Control: API-001 (SSRF prevention)

Provides a small whitelist-check helper to avoid allowing user-supplied outbound URLs.
In this repository the helper is used to validate configured redirect URLs and any
future user-supplied outbound URL inputs.
"""
from __future__ import annotations

from urllib.parse import urlparse
from typing import Iterable

from .config import get_settings


def _default_whitelist() -> list[str]:
    s = get_settings()
    # include only the configured frontend URL by default (avoid broad localhost/127.0.0.1 allowances)
    whitelist = [s.frontend_url]
    return whitelist


def is_url_allowed(url: str, allowed: Iterable[str] | None = None) -> bool:
    """Return True if the url's netloc is in the allowed list.

    Implemented: API-001 (SSRF whitelist helper).
    """
    if allowed is None:
        allowed = _default_whitelist()

    try:
        p = urlparse(url)
    except Exception:
        return False

    host = f"{p.scheme}://{p.netloc}" if p.scheme and p.netloc else p.netloc
    for a in allowed:
        if a and host.startswith(a):
            return True
    return False
