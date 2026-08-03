"""
middleware.py
--------------
Ties the detector, rate limiter, and logger together into a single
Flask `before_request` hook — this is the "WAF" itself.

Decision sequence (mirrors the documentation's Alert Decisions section):
    1. Is this IP currently abusive / rate-limited?  -> block + log
    2. Does the request match an attack signature?    -> block + log
    3. Otherwise                                      -> allow + log
"""

from flask import request, jsonify
from waf.detector import inspect
from waf.rate_limiter import rate_limiter
from waf.logger import log_event


def get_client_ip():
    # Respect X-Forwarded-For if present (e.g. behind a proxy), else remote_addr
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def sentinelshield_before_request():
    # The dashboard/reporting routes are the WAF's own admin console, not
    # part of the protected demo site — they must stay reachable even when
    # the requester's IP has just been flagged, otherwise a student could
    # never view the results of the attacks they just simulated.
    if request.path.startswith("/dashboard"):
        return None

    ip = get_client_ip()

    # --- 1. Traffic / behavior check -----------------------------------
    rl_result = rate_limiter.check(ip)
    if not rl_result["allowed"]:
        log_event(
            ip=ip,
            method=request.method,
            path=request.path,
            action="BLOCKED",
            reason=rl_result["reason"],
            category="RATE_ABUSE",
            details={"request_count": rl_result["request_count"],
                     "retry_after": rl_result["retry_after"]},
        )
        return jsonify({
            "blocked": True,
            "reason": rl_result["reason"],
            "retry_after_seconds": rl_result["retry_after"],
        }), 429

    # --- 2. Signature-based inspection ----------------------------------
    body_text = ""
    if request.form:
        body_text = "&".join(f"{k}={v}" for k, v in request.form.items())
    elif request.data:
        try:
            body_text = request.data.decode("utf-8", errors="ignore")
        except Exception:
            body_text = ""

    result = inspect(
        path=request.path,
        query_string=request.query_string.decode("utf-8", errors="ignore"),
        body=body_text,
        headers=dict(request.headers),
    )

    if result["malicious"]:
        log_event(
            ip=ip,
            method=request.method,
            path=request.path,
            action="BLOCKED",
            reason="SIGNATURE_MATCH",
            category=result["category"],
            details={"matches": result["matches"][:5]},  # cap for readability
        )
        return jsonify({
            "blocked": True,
            "reason": "SIGNATURE_MATCH",
            "category": result["category"],
        }), 403

    # --- 3. Allowed --------------------------------------------------------
    log_event(
        ip=ip,
        method=request.method,
        path=request.path,
        action="ALLOWED",
        reason="OK",
        category=None,
        details={},
    )
    return None  # None => Flask continues to the actual view function
