"""
dashboard.py
-------------
Builds the summary statistics shown on the /dashboard page, and used
for the final student report (Step 6: Reporting and Analysis).
"""

from collections import Counter
from waf.logger import read_events
from waf.rate_limiter import rate_limiter


def build_summary():
    events = read_events()

    total_requests = len(events)
    blocked_events = [e for e in events if e["action"] == "BLOCKED"]
    allowed_events = [e for e in events if e["action"] == "ALLOWED"]

    category_counts = Counter(e["category"] for e in blocked_events if e["category"])
    ip_counts = Counter(e["ip"] for e in events)
    flagged_ip_counts = Counter(e["ip"] for e in blocked_events)

    recent = list(reversed(events))[:25]  # most recent 25 for the live feed

    return {
        "total_requests": total_requests,
        "total_allowed": len(allowed_events),
        "total_blocked": len(blocked_events),
        "category_counts": dict(category_counts.most_common()),
        "top_ips": ip_counts.most_common(10),
        "top_flagged_ips": flagged_ip_counts.most_common(10),
        "live_rate_state": rate_limiter.snapshot(),
        "recent_events": recent,
    }
