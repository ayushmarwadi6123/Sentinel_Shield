# SentinelShield — Advanced Intrusion Detection & Web Protection System

A working, runnable teaching WAF/IDS built to satisfy the practical work
documentation: it inspects HTTP requests, detects attack signatures,
monitors traffic behavior, logs every decision, and visualizes results
on a live dashboard.

## 1. What's in this project

```
sentinelshield/
├── app.py                 # Flask app: demo "protected site" + WAF wiring + dashboard routes
├── waf/
│   ├── detector.py         # Signature engine: SQLi, XSS, LFI/traversal, command injection
│   ├── rate_limiter.py      # Sliding-window per-IP traffic monitor / brute-force blocker
│   ├── logger.py            # Structured JSON-line logging to logs/waf.log
│   ├── middleware.py        # Decision sequence: rate-limit check -> signature check -> log
│   └── dashboard.py         # Aggregates logs into dashboard statistics
├── templates/
│   └── dashboard.html       # Live operations console (auto-refreshes every 5s)
├── test_client.py           # Traffic simulator: normal / malicious / brute-force requests
├── logs/waf.log             # Generated at runtime — this is what you'll analyze
├── requirements.txt
└── README.md
```

## 2. How the pieces map to the documentation

| Documentation concept | Where it lives |
|---|---|
| HTTP Request Inspection | `detector.build_inspection_surface()` — normalizes path, query, body, headers |
| Attack Signature Identification | `detector.SIGNATURES` — SQLi, XSS, LFI/traversal, command injection |
| Behavior Monitoring & Rate Limiting | `rate_limiter.RateLimiter` — sliding window + temporary IP block |
| Alert Decisions (block → log → flag → alert) | `middleware.sentinelshield_before_request()` |
| Logging & Dashboard Visibility | `logger.py` (writes) + `dashboard.py` (aggregates) + `templates/dashboard.html` (displays) |

## 3. Setup

```bash
cd sentinelshield
pip install -r requirements.txt
python app.py
```

The demo protected site runs at `http://127.0.0.1:5000/`, with sample
endpoints: `/search?q=...`, `/login` (POST), `/profile?id=...`, `/file?name=...`.

Open the live console at **http://127.0.0.1:5000/dashboard** — it auto-refreshes
every 5 seconds and stays reachable even while your IP is rate-limited (it's
the WAF's own admin view, not part of the protected site).

## 4. Running the practical workflow

This directly follows the "Practical Workflow for Students" section of the
documentation:

**Step 1–2 (Architecture & rules):** Read `waf/detector.py` (signatures) and
`waf/middleware.py` (decision flow) before running anything.

**Step 3 (Simulate requests):** With the server running, in a second terminal:

```bash
python test_client.py normal    # harmless traffic only
python test_client.py attacks   # one payload per attack category
python test_client.py flood     # 30 rapid requests to trigger rate limiting
python test_client.py all       # everything, in sequence
```

You can also hand-craft your own requests with `curl`, e.g.:

```bash
curl "http://127.0.0.1:5000/search?q=<script>alert(1)</script>"
curl "http://127.0.0.1:5000/file?name=../../../../etc/passwd"
```

**Step 4 (Observe detection):** Each response tells you what happened:
- `200` — allowed
- `403` with `{"blocked": true, "category": "..."}` — signature match
- `429` with `{"blocked": true, "reason": "RATE_LIMIT_EXCEEDED"}` — traffic abuse

**Step 5 (Log examination):** Open `logs/waf.log` directly (one JSON object
per line), or browse `http://127.0.0.1:5000/dashboard/raw-logs` for the same
data pretty-printed in the browser.

**Step 6 (Reporting):** `http://127.0.0.1:5000/dashboard/export` returns a
single JSON summary — total requests, allowed/blocked counts, attack category
distribution, and top flagged IPs — ready to paste into your final report
alongside your own written interpretation.

To start a clean session (e.g. for a fresh practical run), reset logs with:

```bash
curl -X POST http://127.0.0.1:5000/dashboard/reset
```

## 5. Suggested student report structure

Using the assignment requirements as a checklist:

1. **Purpose of the experiment** — one paragraph, in your own words.
2. **Tools used** — Python, Flask, `requests`, this repo.
3. **Step-by-step execution** — what commands you ran, in order.
4. **Observations** — screenshot the dashboard after each test phase
   (normal / attacks / flood) so you can compare states.
5. **Log interpretation** — pick 3–5 entries from `logs/waf.log` and explain
   why each was allowed or blocked, citing the specific pattern or threshold
   that triggered the decision.
6. **Detection accuracy discussion** — using the export JSON: how many
   attacks were correctly detected? Try payloads not in `test_client.py`
   (e.g. encoded variants) — did they slip through? That's your
   false-negative discussion. Note any legitimate-looking input that got
   blocked — that's your false-positive discussion.
7. **Suggested improvements** — e.g. additional signatures, adjusting
   `MAX_REQUESTS`/`WINDOW_SECONDS` in `rate_limiter.py`, handling encoded
   evasion more robustly.

## 6. Configuration knobs worth experimenting with

- `waf/rate_limiter.py`: `MAX_REQUESTS`, `WINDOW_SECONDS`, `BLOCK_SECONDS`
- `waf/detector.py`: `SIGNATURES` dict — add your own patterns and re-test
  with `test_client.py` to see detection change in real time.

## 7. Scope note

This is a teaching-grade system: signatures are simple regexes (not a full
rule engine like ModSecurity/CRS), and rate limiting is in-memory (resets on
restart, single-process only). That's intentional — the goal is to make the
detect → decide → log → dashboard pipeline transparent and easy to reason
about, not to be production-ready.
