"""
auto_phone_sim.py — Automated phone simulator for Sacred Gatekeeper

Polls the broker HTTP server and automatically approves or denies requests
based on configurable rules.  Useful for integration tests and demos where
you don't want to run the interactive phone_sim.

Usage:
    python tools/auto_phone_sim.py --mode approve   # approve everything
    python tools/auto_phone_sim.py --mode deny       # deny everything
    python tools/auto_phone_sim.py --mode smart      # approve LOW/MED, deny HIGH/CRITICAL
    python tools/auto_phone_sim.py --mode interactive  # ask per request

Options:
    --broker  http://127.0.0.1:9998   broker base URL
    --delay   0.5                     seconds to wait before acting (simulate human)
    --mode    smart                   approve|deny|smart|interactive
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

# ── Key loading (same logic as broker; used to sign approvals) ────────────────

_DEFAULT_PRIV = Path(os.environ.get("SG_PHONE_PRIV", "phone_private.pem"))

def _load_private_key():
    from cryptography.hazmat.primitives import serialization
    path = Path(str(_DEFAULT_PRIV))
    if not path.exists():
        print(f"[auto_sim] Key file not found: {path}. Run broker once to generate keys.")
        sys.exit(1)
    with open(path, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)
        return priv_key


def _sign(private_key, rid: str) -> str:
    sig = private_key.sign(rid.encode())
    return sig.hex()


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _get(url: str) -> list | dict | None:
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return json.loads(r.read())
    except Exception:
        return None


def _post(url: str, data: dict) -> dict | None:
    body = json.dumps(data).encode()
    req  = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())
    except Exception:
        return None


def _decision_recorded(broker: str, rid: str) -> bool:
    pending = _get(f"{broker}/pending")
    if pending is None:
        return False
    return all(item.get("id") != rid for item in pending)


# ── Decision logic ────────────────────────────────────────────────────────────

_RISK_COLOR = {
    "LOW":      "\033[92m",
    "MEDIUM":   "\033[93m",
    "HIGH":     "\033[91m",
    "CRITICAL": "\033[95m",
}
_RESET = "\033[0m"

def _risk_str(risk: str) -> str:
    color = _RISK_COLOR.get(risk.upper(), "")
    return f"{color}{risk}{_RESET}"


def _decide(mode: str, request: dict, private_key) -> tuple[str, str]:
    """Return (action, signature_if_approve)."""
    rid     = request["id"]
    risk    = request.get("risk", "UNKNOWN").upper()
    summary = request.get("summary", "?")

    if mode == "approve":
        return "approve", _sign(private_key, rid)
    if mode == "deny":
        return "deny", ""
    if mode == "smart":
        # Approve LOW and MEDIUM, deny HIGH and CRITICAL
        if risk in ("LOW", "MEDIUM"):
            return "approve", _sign(private_key, rid)
        return "deny", ""
    if mode == "interactive":
        color = _RISK_COLOR.get(risk, "")
        print(f"\n{color}{'─'*60}{_RESET}")
        print(f"  Summary : {summary}")
        print(f"  Risk    : {_risk_str(risk)}")
        print(f"  ID      : {rid[:12]}...")
        while True:
            choice = input("  Approve? [y/n]: ").strip().lower()
            if choice == "y":
                return "approve", _sign(private_key, rid)
            if choice == "n":
                return "deny", ""
    return "deny", ""


# ── Main polling loop ─────────────────────────────────────────────────────────

def run(broker: str, mode: str, delay: float):
    private_key = _load_private_key()
    seen: set[str] = set()

    print(f"[auto_sim] Connected to {broker}  |  mode={mode}  |  delay={delay}s")
    print("[auto_sim] Waiting for requests... (Ctrl-C to stop)\n")

    while True:
        pending = _get(f"{broker}/pending")
        if pending is None:
            print("[auto_sim] Broker unreachable, retrying in 2s...")
            time.sleep(2)
            continue

        for req in pending:
            rid = req["id"]
            if rid in seen:
                continue
            seen.add(rid)

            risk    = req.get("risk", "?")
            summary = req.get("summary", "?")
            print(f"[auto_sim] \u25ba  [{_risk_str(risk)}]  {summary}  ({rid[:8]})")

            if mode != "interactive" and delay > 0:
                time.sleep(delay)

            action, sig = _decide(mode, req, private_key)

            if action == "approve":
                url  = f"{broker}/approve/{rid}"
                resp = _post(url, {"signature": sig})
                symbol = "\u2713"
            else:
                url  = f"{broker}/deny/{rid}"
                resp = _post(url, {})
                symbol = "\u2717"

            ok = resp.get("ok", False) if resp else False
            if not ok:
                time.sleep(0.1)
                ok = _decision_recorded(broker, rid)
            print(f"[auto_sim] {symbol}  {action.upper()}  \u2192  {'OK' if ok else 'FAILED'}")

        time.sleep(0.5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sacred Gatekeeper — Automated Phone Simulator")
    parser.add_argument("--broker", default="http://127.0.0.1:9998", help="Broker base URL")
    parser.add_argument("--delay",  type=float, default=0.5, help="Seconds before acting")
    parser.add_argument("--mode",   default="smart",
                        choices=["approve", "deny", "smart", "interactive"],
                        help="Decision mode")
    args = parser.parse_args()
    try:
        run(args.broker, args.mode, args.delay)
    except KeyboardInterrupt:
        print("\n[auto_sim] Stopped.")
