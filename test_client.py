"""
test_client.py
----------------
Traffic simulator for SentinelShield practical sessions.

Covers Step 3 of the practical workflow ("Simulating HTTP Requests"):
    - Normal, harmless requests
    - Malicious test payloads (one per attack category)
    - Repeated requests to simulate brute-force / flooding behavior

Usage:
    python test_client.py               # run all scenarios
    python test_client.py normal        # only normal traffic
    python test_client.py attacks       # only malicious payloads
    python test_client.py flood         # only brute-force simulation

Make sure app.py is already running (python app.py) before using this.
"""

import sys
import time
import requests

BASE_URL = "http://127.0.0.1:5000"


def show(label, resp):
    try:
        body = resp.json()
    except ValueError:
        body = resp.text
    print(f"[{resp.status_code}] {label} -> {body}")


def run_normal_traffic():
    print("\n=== Normal traffic ===")
    show("Home page", requests.get(f"{BASE_URL}/"))
    show("Search: laptops", requests.get(f"{BASE_URL}/search", params={"q": "laptops"}))
    show("Profile 1024", requests.get(f"{BASE_URL}/profile", params={"id": "1024"}))
    show("Login (valid-looking)", requests.post(f"{BASE_URL}/login",
         data={"username": "alice", "password": "hunter2"}))
    show("File view", requests.get(f"{BASE_URL}/file", params={"name": "welcome.txt"}))


def run_attack_payloads():
    print("\n=== Malicious payloads (one per category) ===")

    # SQL Injection
    show("SQLi via search", requests.get(f"{BASE_URL}/search",
         params={"q": "' OR '1'='1' -- "}))
    show("SQLi via login", requests.post(f"{BASE_URL}/login",
         data={"username": "admin' -- ", "password": "x"}))

    # XSS
    show("XSS via search", requests.get(f"{BASE_URL}/search",
         params={"q": "<script>alert(document.cookie)</script>"}))

    # Directory traversal / LFI
    show("LFI via file endpoint", requests.get(f"{BASE_URL}/file",
         params={"name": "../../../../etc/passwd"}))

    # Command injection
    show("Command injection via search", requests.get(f"{BASE_URL}/search",
         params={"q": "test; whoami && id"}))


def run_flood_simulation(n=30, delay=0.05):
    print(f"\n=== Brute-force / flood simulation ({n} rapid requests) ===")
    for i in range(n):
        resp = requests.get(f"{BASE_URL}/profile", params={"id": str(i)})
        if resp.status_code == 429:
            print(f"  request #{i+1}: BLOCKED (rate limited)")
        else:
            print(f"  request #{i+1}: {resp.status_code}")
        time.sleep(delay)


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"

    if mode in ("all", "normal"):
        run_normal_traffic()
    if mode in ("all", "attacks"):
        run_attack_payloads()
    if mode in ("all", "flood"):
        run_flood_simulation()

    print("\nDone. Visit http://127.0.0.1:5000/dashboard to see the results,")
    print("or http://127.0.0.1:5000/dashboard/raw-logs for the raw log entries.")
