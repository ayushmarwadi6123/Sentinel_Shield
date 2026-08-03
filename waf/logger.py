"""
logger.py
----------
Logging & alert-record component of SentinelShield.

Every inspected request produces one structured JSON-line log entry in
logs/waf.log. This is the file students will open during "Step 5: Log
File Examination" of the practical workflow, and it's also what
dashboard.py reads to build the summary dashboard.

Log record schema:
{
    "timestamp": ISO-8601 string,
    "ip": source IP,
    "method": HTTP method,
    "path": request path,
    "action": "ALLOWED" | "BLOCKED",
    "reason": short machine reason code,
    "category": attack category if malicious, else null,
    "details": free-form extra info (matched pattern, rate info, etc.)
}
"""

import json
import os
import threading
from datetime import datetime, timezone

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
LOG_FILE = os.path.join(LOG_DIR, "waf.log")

_lock = threading.Lock()


def _ensure_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "a").close()


def log_event(ip, method, path, action, reason, category=None, details=None):
    _ensure_log_dir()
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip": ip,
        "method": method,
        "path": path,
        "action": action,          # ALLOWED / BLOCKED
        "reason": reason,          # e.g. OK, SIGNATURE_MATCH, RATE_LIMIT_EXCEEDED
        "category": category,      # e.g. SQL_INJECTION, XSS, None
        "details": details or {},
    }
    with _lock:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(record) + "\n")
    return record


def read_events(limit=None):
    """Read all logged events (optionally only the most recent `limit`)."""
    _ensure_log_dir()
    events = []
    with open(LOG_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if limit:
        return events[-limit:]
    return events


def clear_events():
    """Wipe the log file (handy for starting a fresh practical session)."""
    _ensure_log_dir()
    with _lock:
        open(LOG_FILE, "w").close()
