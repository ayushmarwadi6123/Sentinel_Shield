"""
app.py
-------
SentinelShield: Advanced Intrusion Detection & Web Protection System
Entry point.

This file:
  1. Defines a tiny "protected" demo web application (a handful of routes
     that behave like a real site: search, login, profile) — this is the
     thing SentinelShield is defending, so students have something
     realistic to attack during Step 3 of the practical workflow.
  2. Registers the SentinelShield WAF as a `before_request` hook so every
     request passes through detection + rate limiting first.
  3. Exposes the /dashboard route (Step 5/6: log analysis + reporting).

Run with:  python app.py
Then visit http://127.0.0.1:5000/dashboard
"""

from flask import Flask, request, jsonify, render_template

from waf.middleware import sentinelshield_before_request
from waf.dashboard import build_summary
from waf.logger import read_events, clear_events

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Register the WAF. Flask calls this before every request; if it returns a
# response, Flask serves that immediately without running the real view.
# ---------------------------------------------------------------------------
app.before_request(sentinelshield_before_request)


# ---------------------------------------------------------------------------
# Demo "protected" application — deliberately simple sample endpoints that
# accept user input, standing in for a real website.
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    return jsonify({
        "app": "SentinelShield demo site",
        "endpoints": ["/search?q=...", "/login (POST username/password)",
                      "/profile?id=...", "/dashboard"],
    })


@app.route("/search")
def search():
    query = request.args.get("q", "")
    return jsonify({"query": query, "results": [f"Result for '{query}' #1", f"Result for '{query}' #2"]})


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    # Intentionally naive demo logic — this app exists only to be a target.
    if username == "admin" and password == "admin123":
        return jsonify({"status": "success", "user": username})
    return jsonify({"status": "invalid credentials"}), 401


@app.route("/profile")
def profile():
    user_id = request.args.get("id", "")
    return jsonify({"profile_id": user_id, "note": "Demo profile endpoint"})


@app.route("/file")
def file_view():
    filename = request.args.get("name", "welcome.txt")
    return jsonify({"requested_file": filename, "note": "Demo file-view endpoint"})


# ---------------------------------------------------------------------------
# Dashboard / reporting routes
# ---------------------------------------------------------------------------
@app.route("/dashboard")
def dashboard():
    summary = build_summary()
    return render_template("dashboard.html", summary=summary)


@app.route("/dashboard/export")
def dashboard_export():
    """Raw JSON summary — useful for pasting into the student's final report."""
    return jsonify(build_summary())


@app.route("/dashboard/reset", methods=["POST"])
def dashboard_reset():
    """Clears logs to start a fresh practical session."""
    clear_events()
    return jsonify({"status": "logs cleared"})


@app.route("/dashboard/raw-logs")
def raw_logs():
    """All raw log entries, for manual log-file examination (Step 5)."""
    return jsonify(read_events())


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)
