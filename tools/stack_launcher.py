"""Supervised launcher for the local OpenSentinel stack.

Starts the broker, waits for readiness, optionally starts the automated phone
simulator, and then runs the demo against the live broker.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHON = Path(sys.executable)


def _abs(path: str) -> str:
    return str((ROOT / path).resolve())


def build_env() -> dict:
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join([
        _abs("packages/interceptor/src"),
        _abs("packages/broker/src"),
    ])
    env.setdefault("SG_LEDGER", _abs("ledger.db"))
    env.setdefault("SG_PHONE_PUB", _abs("phone_public.pem"))
    env.setdefault("SG_PHONE_PRIV", _abs("phone_private.pem"))
    env.setdefault("SG_TCP_HOST", "127.0.0.1")
    env.setdefault("SG_TCP_PORT", "9999")
    env.setdefault("SG_HTTP_HOST", "127.0.0.1")
    env.setdefault("SG_HTTP_PORT", "9998")
    return env


def broker_base_url(env: dict) -> str:
    host = env.get("SG_HTTP_HOST", "127.0.0.1")
    if host == "0.0.0.0":
        host = "127.0.0.1"
    return f"http://{host}:{env.get('SG_HTTP_PORT', '9998')}"


def stream_output(prefix: str, proc: subprocess.Popen[str]):
    assert proc.stdout is not None
    for line in proc.stdout:
        print(f"[{prefix}] {line.rstrip()}")


def start_process(prefix: str, args: list[str], env: dict) -> subprocess.Popen[str]:
    proc = subprocess.Popen(
        args,
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    threading.Thread(target=stream_output, args=(prefix, proc), daemon=True).start()
    return proc


def wait_for_health(health_url: str, timeout_s: float = 20.0) -> dict:
    deadline = time.time() + timeout_s
    last_error = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(health_url, timeout=2) as response:
                return json.loads(response.read())
        except Exception as exc:
            last_error = exc
            time.sleep(0.5)
    raise RuntimeError(f"broker did not become ready: {last_error}")


def post_json(url: str, payload: dict) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as response:
        return json.loads(response.read())


def terminate_processes(processes: list[subprocess.Popen[str]]):
    for proc in processes:
        if proc.poll() is None:
            proc.terminate()
    deadline = time.time() + 5
    for proc in processes:
        while proc.poll() is None and time.time() < deadline:
            time.sleep(0.1)
        if proc.poll() is None:
            proc.kill()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run OpenSentinel local stack")
    parser.add_argument("--phone", choices=["auto", "interactive", "none"], default="auto")
    parser.add_argument("--skip-demo", action="store_true")
    parser.add_argument("--keep-running", action="store_true")
    parser.add_argument("--pair-device-name", default="My Phone")
    args = parser.parse_args()

    env = build_env()
    processes: list[subprocess.Popen[str]] = []

    def _shutdown(*_args):
        terminate_processes(processes)
        raise SystemExit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    try:
        base_url = broker_base_url(env)
        broker = start_process(
            "broker",
            [str(PYTHON), "-m", "open_sentinel_broker.broker"],
            env,
        )
        processes.append(broker)

        health = wait_for_health(f"{base_url}/health")
        print("\n[launcher] broker ready")
        tcp = health.get("tcp", {"host": "127.0.0.1", "port": 9999})
        http = health.get("http", {"host": "127.0.0.1", "port": 9998})
        print(f"[launcher] tcp={tcp.get('host')}:{tcp.get('port')} http={http.get('host')}:{http.get('port')}")

        pairing = post_json(f"{base_url}/pairing/start", {"device_name": args.pair_device_name})
        print(f"[launcher] pairing code for {args.pair_device_name}: {pairing['code']} (expires in {pairing['expires_in_s']}s)")

        if args.phone != "none":
            phone_args = [str(PYTHON), _abs("tools/auto_phone_sim.py"), "--broker", base_url]
            if args.phone == "interactive":
                phone_args.extend(["--mode", "interactive", "--delay", "0"])
            else:
                phone_args.extend(["--mode", "smart", "--delay", "1"])
            phone = start_process("phone", phone_args, env)
            processes.append(phone)
            time.sleep(1.0)

        demo_code = 0
        if not args.skip_demo:
            demo = subprocess.run(
                [str(PYTHON), _abs("examples/openclaw-demo/demo.py")],
                cwd=str(ROOT),
                env=env,
                text=True,
                check=False,
            )
            demo_code = demo.returncode

        if args.keep_running:
            print("[launcher] stack is running. Press Ctrl+C to stop.")
            while True:
                time.sleep(1)

        terminate_processes(processes)
        return demo_code
    except Exception as exc:
        terminate_processes(processes)
        print(f"[launcher] failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())