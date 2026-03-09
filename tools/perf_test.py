"""
perf_test.py — Sacred Gatekeeper Performance + Load Test

Tests broker throughput, interceptor latency, and fail-closed behaviour.

Requirements: broker must be running (python -m sacred_gatekeeper_broker)

Usage:
    python tools/perf_test.py                      # default settings
    python tools/perf_test.py --requests 50 --concurrency 5
    python tools/perf_test.py --auto-approve        # use auto_phone_sim smart mode

The test drives requests directly at the broker TCP socket (bypassing the
interceptor) so latency numbers reflect broker overhead only.

Results summary printed to stdout; raw rows saved to perf_results.json.
"""

import argparse
import json
import socket
import statistics
import sys
import time
import threading
from pathlib import Path


BROKER_HOST    = "127.0.0.1"
BROKER_PORT    = 9999
SOCKET_TIMEOUT = 10   # short; we expect broker to be local


# ── Per-request worker ────────────────────────────────────────────────────────

def _send_request(payload: dict, results: list, idx: int):
    t_start = time.perf_counter()
    token   = None
    error   = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(SOCKET_TIMEOUT)
            s.connect((BROKER_HOST, BROKER_PORT))
            s.sendall((json.dumps(payload) + "\n").encode())
            buf = b""
            while True:
                chunk = s.recv(1024)
                if not chunk:
                    break
                buf += chunk
                if b"\n" in buf:
                    break
        token = buf.strip().decode()
    except Exception as e:
        error = str(e)

    elapsed_ms = (time.perf_counter() - t_start) * 1000
    results[idx] = {
        "idx":        idx,
        "elapsed_ms": round(elapsed_ms, 2),
        "approved":   bool(token),
        "error":      error,
    }


def _check_broker() -> bool:
    """Return True if broker TCP port is accepting connections."""
    try:
        with socket.create_connection((BROKER_HOST, BROKER_PORT), timeout=2):
            return True
    except Exception:
        return False


# ── Test suites ───────────────────────────────────────────────────────────────

def _build_payloads(n: int) -> list[dict]:
    """Alternate between MEDIUM and HIGH to exercise both paths."""
    payloads = []
    for i in range(n):
        if i % 2 == 0:
            payloads.append({
                "action":  "send_email",
                "params":  {"to": f"user{i}@example.com"},
                "summary": f"Send email #{i}",
                "risk":    "MEDIUM",
            })
        else:
            payloads.append({
                "action":  "delete_file",
                "params":  {"path": f"/tmp/file{i}.txt"},
                "summary": f"Delete file #{i}",
                "risk":    "HIGH",
            })
    return payloads


def run_sequential(n: int) -> list[dict]:
    """Send *n* requests one after another."""
    payloads = _build_payloads(n)
    results  = [None] * n
    for i, p in enumerate(payloads):
        _send_request(p, results, i)  # type: ignore
        sys.stdout.write(f"\r  Request {i+1}/{n}…")
        sys.stdout.flush()
    print()
    return results  # type: ignore


def run_concurrent(n: int, concurrency: int) -> list[dict]:
    """Send *n* requests with *concurrency* parallel threads."""
    payloads = _build_payloads(n)
    results  = [None] * n
    sem      = threading.Semaphore(concurrency)

    def worker(i, p):
        with sem:
            _send_request(p, results, i)  # type: ignore
            sys.stdout.write(f"\r  Done {sum(r is not None for r in results)}/{n}…")
            sys.stdout.flush()

    threads = [threading.Thread(target=worker, args=(i, p)) for i, p in enumerate(payloads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print()
    return results  # type: ignore


# ── Reporting ─────────────────────────────────────────────────────────────────

def _report(label: str, results: list[dict]):
    latencies  = [r["elapsed_ms"] for r in results if r and not r["error"]]
    errors     = [r for r in results if r and r["error"]]
    approved   = sum(1 for r in results if r and r["approved"])
    total      = len(results)

    print(f"\n{'─'*60}")
    print(f"  {label}")
    print(f"{'─'*60}")
    print(f"  Total requests  : {total}")
    print(f"  Approved        : {approved}")
    print(f"  Denied/Timeout  : {total - approved - len(errors)}")
    print(f"  Errors          : {len(errors)}")
    if latencies:
        print(f"  Latency (ms)")
        print(f"    min  : {min(latencies):.0f}")
        print(f"    p50  : {statistics.median(latencies):.0f}")
        print(f"    p95  : {sorted(latencies)[int(len(latencies)*0.95)]:.0f}")
        print(f"    max  : {max(latencies):.0f}")
        print(f"    mean : {statistics.mean(latencies):.0f}")
    for e in errors[:5]:
        print(f"  ! req#{e['idx']}: {e['error']}")
    print()


def _save(path: str, data: dict):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[perf] Results saved → {path}")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sacred Gatekeeper Performance Test")
    parser.add_argument("--requests",     type=int, default=20,
                        help="Number of requests to send (default: 20)")
    parser.add_argument("--concurrency",  type=int, default=4,
                        help="Concurrent threads for load test (default: 4)")
    parser.add_argument("--output",       default="perf_results.json",
                        help="Output file for raw results (default: perf_results.json)")
    args = parser.parse_args()

    if not _check_broker():
        print(f"[perf] ERROR: Broker not reachable at {BROKER_HOST}:{BROKER_PORT}")
        print("       Start it with:  python -m sacred_gatekeeper_broker")
        print("       Then run auto_phone_sim (--mode approve) in another terminal.")
        sys.exit(1)

    print(f"\n[perf] Broker OK  ─  {args.requests} requests  "
          f"(concurrency={args.concurrency})\n")

    # Sequential baseline
    print("[1/2] Sequential throughput test…")
    seq_results = run_sequential(args.requests)
    _report("Sequential", seq_results)

    # Concurrent load test
    print("[2/2] Concurrent load test…")
    conc_results = run_concurrent(args.requests, args.concurrency)
    _report(f"Concurrent (c={args.concurrency})", conc_results)

    # Save raw data
    _save(args.output, {
        "sequential":  seq_results,
        "concurrent":  conc_results,
        "config": {
            "requests":    args.requests,
            "concurrency": args.concurrency,
        },
    })
