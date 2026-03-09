"""
Sacred Gatekeeper — Audit Log Viewer

Reads the SQLite ledger and prints a colour-coded table of every
approved / denied / timed-out action.

Usage:
  python tools/audit_log.py
  python tools/audit_log.py --since 1h
  python tools/audit_log.py --risk CRITICAL
  python tools/audit_log.py --decision deny
  python tools/audit_log.py --action send_email --limit 20
"""

import sqlite3
import time
import argparse
import os

LEDGER = os.environ.get("SG_LEDGER", "ledger.db")

GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

DECISION_COLOR = {"approve": GREEN, "deny": RED, "timeout": YELLOW}
RISK_COLOR     = {"LOW": GREEN, "MEDIUM": YELLOW, "HIGH": "\033[91m", "CRITICAL": RED}


def parse_since(s: str) -> float:
    unit    = s[-1].lower()
    value   = int(s[:-1])
    seconds = {"m": 60, "h": 3600, "d": 86400}.get(unit)
    if not seconds:
        raise ValueError(f"Unknown time unit '{unit}'. Use m / h / d.")
    return time.time() - value * seconds


def main():
    parser = argparse.ArgumentParser(description="Sacred Gatekeeper audit log")
    parser.add_argument("--since",    help="Time window e.g. 30m, 2h, 1d")
    parser.add_argument("--risk",     help="LOW / MEDIUM / HIGH / CRITICAL")
    parser.add_argument("--action",   help="Filter by action name")
    parser.add_argument("--decision", help="approve / deny / timeout")
    parser.add_argument("--limit",    type=int, default=50)
    args = parser.parse_args()

    if not os.path.exists(LEDGER):
        print(f"No ledger found at {LEDGER}. Run the broker first.")
        return

    sql    = "SELECT id, timestamp, action, risk, summary, decision FROM ledger WHERE 1=1"
    params = []

    if args.since:
        sql += " AND timestamp >= ?"
        params.append(parse_since(args.since))
    if args.risk:
        sql += " AND risk = ?"
        params.append(args.risk.upper())
    if args.action:
        sql += " AND action = ?"
        params.append(args.action)
    if args.decision:
        sql += " AND decision = ?"
        params.append(args.decision.lower())

    sql += " ORDER BY timestamp DESC LIMIT ?"
    params.append(args.limit)

    with sqlite3.connect(LEDGER) as conn:
        rows = conn.execute(sql, params).fetchall()

    if not rows:
        print("No matching entries.")
        return

    print(f"\n{BOLD}{'TIME':<22} {'DECISION':<10} {'RISK':<10} {'ACTION':<26} SUMMARY{RESET}")
    print("─" * 95)

    for rid, ts, action, risk, summary, decision in rows:
        dc = DECISION_COLOR.get(decision, "")
        rc = RISK_COLOR.get(risk, "")
        t  = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        print(f"{t:<22} {dc}{decision:<10}{RESET} {rc}{risk:<10}{RESET} {action:<26} {summary}")

    print(f"\n{len(rows)} record(s)\n")


if __name__ == "__main__":
    main()
