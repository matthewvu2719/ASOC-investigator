"""Entity types and detection patterns for PII masking.

Patterns are intentionally regex-based (not an NER model) for v0.1 — see
docs/ARCHITECTURE.md "Open design questions" for when that stops being
enough. Order matters: more specific patterns (hashes, emails) must be
tried before looser ones (generic hostnames) to avoid a hash being
half-swallowed by a hostname match.
"""

from __future__ import annotations

import re
from enum import Enum


class EntityType(str, Enum):
    IP_ADDRESS = "IP"
    DOMAIN = "DOMAIN"
    EMAIL = "EMAIL"
    URL = "URL"
    HASH_SHA256 = "SHA256"
    HASH_SHA1 = "SHA1"
    HASH_MD5 = "MD5"
    MAC_ADDRESS = "MAC"
    USERNAME = "USER"
    HOSTNAME = "HOST"
    FILE_PATH = "PATH"


# Ordered: first match wins for a given span. Longer/more specific patterns
# first so e.g. a SHA256 hex string isn't mistaken for a hostname fragment.
_PATTERNS: list[tuple[EntityType, re.Pattern[str]]] = [
    (EntityType.EMAIL, re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")),
    (EntityType.URL, re.compile(r"\bhttps?://[^\s\"'<>]+")),
    (EntityType.HASH_SHA256, re.compile(r"\b[a-fA-F0-9]{64}\b")),
    (EntityType.HASH_SHA1, re.compile(r"\b[a-fA-F0-9]{40}\b")),
    (EntityType.HASH_MD5, re.compile(r"\b[a-fA-F0-9]{32}\b")),
    (EntityType.MAC_ADDRESS, re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")),
    (
        EntityType.IP_ADDRESS,
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
        ),
    ),
    # Windows-style file paths, e.g. C:\Users\alice\Downloads\payload.exe
    (EntityType.FILE_PATH, re.compile(r"\b[A-Za-z]:\\(?:[^\\\s]+\\)*[^\\\s]+")),
    # Unix-style absolute paths with at least two segments
    (EntityType.FILE_PATH, re.compile(r"(?<![\w/])/(?:[\w.\-]+/)+[\w.\-]+")),
    # DOMAIN\username (Active Directory style) — captured as USERNAME whole
    (EntityType.USERNAME, re.compile(r"\b[A-Za-z0-9_-]+\\[A-Za-z0-9_.-]+\b")),
    # Bare hostnames with a known internal-ish TLD-less pattern, e.g. WKSTN-042
    (EntityType.HOSTNAME, re.compile(r"\b(?:[A-Z]{2,}-[A-Z0-9]+|[a-z0-9]+\.corp\.local)\b")),
    # Generic domain (kept last among name-like patterns; deliberately does
    # NOT match bare IPs since those are matched above first)
    (
        EntityType.DOMAIN,
        re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE),
    ),
]


def iter_matches(text: str) -> list[tuple[EntityType, str, int, int]]:
    """Find all entity matches in text, resolving overlaps by earliest-start
    then longest-match-wins, in pattern-priority order."""
    candidates: list[tuple[EntityType, str, int, int]] = []
    for entity_type, pattern in _PATTERNS:
        for m in pattern.finditer(text):
            candidates.append((entity_type, m.group(0), m.start(), m.end()))

    # Sort by start ascending, then by length descending (prefer longer
    # match at the same start position — e.g. a SHA256 fully contains
    # shorter false hex runs).
    candidates.sort(key=lambda c: (c[2], -(c[3] - c[2])))

    selected: list[tuple[EntityType, str, int, int]] = []
    last_end = -1
    for entity_type, value, start, end in candidates:
        if start >= last_end:
            selected.append((entity_type, value, start, end))
            last_end = end
    return selected
