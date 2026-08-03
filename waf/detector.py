"""
detector.py
------------
Signature/pattern-based detection engine for SentinelShield.

This module inspects a normalized "inspection surface" (URL path, query
string, form body, and headers) built from an incoming HTTP request and
checks it against a set of well-known, textbook attack signatures for:

    - SQL Injection (SQLi)
    - Cross-Site Scripting (XSS)
    - Local File Inclusion / Directory Traversal (LFI)
    - OS Command Injection

The patterns below are the same class of generic, publicly documented
indicators used in introductory WAF/IDS teaching material (e.g. OWASP
cheat sheets) — they exist purely to demonstrate *how rule-based
detection works*, not to serve as an exploitation toolkit.
"""

import re
from urllib.parse import unquote_plus

# ---------------------------------------------------------------------------
# Signature definitions
# ---------------------------------------------------------------------------
# Each category maps to a list of compiled regexes. Patterns are intentionally
# simple/generic (matching the style of a "Level 1" teaching WAF) rather than
# an exhaustive evasion-proof rule set.

SIGNATURES = {
    "SQL_INJECTION": [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",                 # quote / comment markers
        r"(\bor\b|\band\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",  # OR 1=1 style
        r"union\s+select",
        r"select\s+.*\s+from",
        r"drop\s+table",
        r"information_schema",
        r";\s*shutdown",
    ],
    "XSS": [
        r"<\s*script.*?>",
        r"javascript\s*:",
        r"on(error|load|click|mouseover)\s*=",
        r"<\s*img[^>]+src\s*=\s*['\"]?javascript:",
        r"document\.cookie",
        r"<\s*iframe",
    ],
    "DIRECTORY_TRAVERSAL_LFI": [
        r"\.\./",
        r"\.\.\\",
        r"/etc/passwd",
        r"boot\.ini",
        r"win\.ini",
        r"php://filter",
        r"file\s*=\s*\.\./",
    ],
    "COMMAND_INJECTION": [
        r";\s*(cat|ls|whoami|id|uname|curl|wget|nc)\b",
        r"\|\s*(cat|ls|whoami|id|uname)\b",
        r"`.*`",
        r"\$\(.*\)",
        r"&&\s*(cat|ls|whoami|id)\b",
    ],
}

_COMPILED = {
    category: [re.compile(p, re.IGNORECASE) for p in patterns]
    for category, patterns in SIGNATURES.items()
}


def build_inspection_surface(path: str, query_string: str, body: str, headers: dict) -> str:
    """
    Combine every attacker-controllable part of a request into a single
    normalized (URL-decoded, lowercased) string for pattern matching.
    """
    header_blob = " ".join(f"{k}:{v}" for k, v in (headers or {}).items())
    raw = " ".join([path or "", query_string or "", body or "", header_blob])
    # URL-decode twice (and treat '+' as a space, as query strings do) to
    # catch simple encoding evasion attempts, matching what a basic
    # teaching-grade WAF would do.
    decoded = unquote_plus(unquote_plus(raw))
    return decoded


def inspect(path: str, query_string: str = "", body: str = "", headers: dict = None):
    """
    Run all signature categories against the request.

    Returns a dict:
        {
            "malicious": bool,
            "category": str | None,   # first category that matched
            "matches": [ {category, pattern}, ... ]  # all matches found
        }
    """
    surface = build_inspection_surface(path, query_string, body, headers or {})

    matches = []
    for category, patterns in _COMPILED.items():
        for pattern in patterns:
            if pattern.search(surface):
                matches.append({"category": category, "pattern": pattern.pattern})

    if matches:
        return {
            "malicious": True,
            "category": matches[0]["category"],
            "matches": matches,
        }
    return {"malicious": False, "category": None, "matches": []}
