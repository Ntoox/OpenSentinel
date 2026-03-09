"""
OpenSentinel — Phone Simulator

Polls the broker's HTTP API and lets you approve/deny pending requests
from the terminal — mimicking what the real phone app does via FaceID.

Usage:
  python tools/phone_sim.py

Requirements:
  - Broker must be running (python packages/broker/src/sacred_gatekeeper_broker/broker.py)
  - phone_private.pem must exist (auto-created by broker on first run)
"""

import json
import time
import urllib.request
import urllib.error
import os
import sys

from cryptography.hazmat.primitives import serialization

BROKER_HTTP       = os.environ.get("SG_BROKER_HTTP", "http://127.0.0.1:9998")
PHONE_PRIV_PATH   = os.environ.get("SG_PHONE_PRIV",  "phone_private.pem")

GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

RISK_COLOR = {
    "LOW":      "\033[32m",
    "MEDIUM":   "\033[33m",
    "HIGH":     "\033[91m",
    "CRITICAL": "\033[31m",
}


def load_key():
    if not os.path.exists(PHONE_PRIV_PATH):
        print(f"{RED}[phone-sim] Private key not found at {PHONE_PRIV_PATH}{RESET}")
        print("Start the broker first to generate keys, then re-run this.")
        sys.exit(1)
    with open(PHONE_PRIV_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def http_get(path: str):
    try:
        with urllib.request.urlopen(f"{BROKER_HTTP}{path}", timeout=3) as r:
            return json.loads(r.read())
    except urllib.error.URLError:
        return None


def http_post(path: str, data: dict):
    body = json.dumps(data).encode()
    req  = urllib.request.Request(
        f"{BROKER_HTTP}{path}",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


def main():
    print(f"\n{BOLD}Sacred Gatekeeper — Phone Simulator{RESET}")
    print(f"Broker: {BROKER_HTTP}   Key: {PHONE_PRIV_PATH}\n")

    key  = load_key()
    seen = set()

    while True:
        pending = http_get("/pending")

        if pending is None:
            print(f"\r{YELLOW}[phone-sim] Waiting for broker...{RESET}", end="", flush=True)
            time.sleep(2)
            continue

        for item in pending:
            rid = item["id"]
            if rid in seen:
                continue
            seen.add(rid)

            risk_color = RISK_COLOR.get(item.get("risk", ""), "")
            print(f"\n{'─'*55}")
            print(f"  {BOLD}Sacred Gatekeeper — Action Request{RESET}")
            print(f"  {item['summary']}")
            print(f"  Risk: {risk_color}{item.get('risk', '?')}{RESET}")
            print(f"  ID  : {rid[:8]}…")
            print(f"{'─'*55}")

            while True:
                choice = input("  [A]pprove  [D]eny → ").strip().lower()
                if choice in ("a", "d"):
                    break

            if choice == "a":
                sig    = key.sign(rid.encode())
                result = http_post(f"/approve/{rid}", {"signature": sig.hex()})
                status = f"{GREEN}✓ Approved{RESET}" if result.get("ok") else f"{RED}Failed{RESET}"
            else:
                result = http_post(f"/deny/{rid}", {})
                status = f"{RED}✗ Denied{RESET}" if result.get("ok") else f"{RED}Failed{RESET}"

            print(f"  → {status}\n")

        time.sleep(0.5)


if __name__ == "__main__":
    main()
