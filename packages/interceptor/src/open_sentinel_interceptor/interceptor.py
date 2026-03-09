"""
OpenSentinel — Interceptor Middleware

Wraps every agent tool call before it runs.
LOW risk  → auto-approve (no latency)
MED/HIGH/CRITICAL → send JSON payload to broker, block until phone responds.

Fails closed: if broker is unreachable, the action is DENIED.
"""

import json
import re
import socket
import os
try:
    import tomllib
except ImportError:
    import tomli as tomllib
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Any, Callable

import time

BROKER_HOST    = os.environ.get("SG_BROKER_HOST", "127.0.0.1")
BROKER_PORT    = int(os.environ.get("SG_BROKER_PORT", 9999))
CONFIG_PATH    = os.environ.get("SG_CONFIG", "rules.toml")
SOCKET_TIMEOUT = 70   # Must exceed broker's 60 s timeout
BROKER_RETRIES = int(os.environ.get("SG_BROKER_RETRIES", 3))
RETRY_BASE_S   = float(os.environ.get("SG_RETRY_BASE_S", 0.3))


class RiskLevel(Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class InterceptionResult:
    allowed: bool
    risk: RiskLevel
    reason: str
    elapsed_ms: float


# ── Risk Classifier ───────────────────────────────────────────────────────────

_DEFAULT_RULES = {
    "critical": {
        "actions": ["run_shell", "execute_code", "write_arbitrary_file", "curl", "wget"],
    },
    "high": {
        "actions":        ["delete_file", "git_push", "deploy", "drop_table", "purge"],
        "param_patterns": [r"evil\.com", r"malware", r"\.sh\b", r"curl.*\|.*sh", r"rm\s+-rf"],
    },
    "medium": {
        "actions": ["send_email", "upload_file", "create_pull_request",
                    "post_message", "commit"],
    },
}


class RiskClassifier:
    def __init__(self, config_path: str = CONFIG_PATH):
        self.rules = self._load(config_path)

    def _load(self, path: str) -> dict:
        if path and os.path.exists(path):
            with open(path, "rb") as f:
                return tomllib.load(f)
        return _DEFAULT_RULES

    def classify(self, action: str, params: Dict[str, Any]) -> RiskLevel:
        r = self.rules
        if action in r.get("critical", {}).get("actions", []):
            return RiskLevel.CRITICAL
        if action in r.get("high", {}).get("actions", []):
            return RiskLevel.HIGH
        param_str = json.dumps(params).lower()
        for pattern in r.get("high", {}).get("param_patterns", []):
            if re.search(pattern, param_str):
                return RiskLevel.HIGH
        if action in r.get("medium", {}).get("actions", []):
            return RiskLevel.MEDIUM
        return RiskLevel.LOW


# ── Summary generator ─────────────────────────────────────────────────────────

_TEMPLATES: Dict[str, Callable] = {
    "send_email":          lambda p: f"Send email to {p.get('to', '?')}",
    "upload_file":         lambda p: f"Upload {p.get('filename','?')} → {p.get('destination','?')}",
    "run_shell":           lambda p: f"Run: {str(p.get('command','?'))[:40]}",
    "delete_file":         lambda p: f"Delete {p.get('path','?')}",
    "git_push":            lambda p: f"Push branch {p.get('branch','?')}",
    "deploy":              lambda p: f"Deploy to {p.get('environment','?')}",
    "create_pull_request": lambda p: f"Open PR: {p.get('title','?')[:30]}",
    "post_message":        lambda p: f"Post message to {p.get('channel','?')}",
}

def _summarize(action: str, params: Dict[str, Any]) -> str:
    fn = _TEMPLATES.get(action)
    return fn(params) if fn else f"Execute {action}"


# ── Interceptor ───────────────────────────────────────────────────────────────

class Interceptor:
    def __init__(self):
        self.classifier = RiskClassifier()
        self.broker_host = BROKER_HOST
        self.broker_port = BROKER_PORT
        self.socket_timeout = SOCKET_TIMEOUT
        self.broker_retries = BROKER_RETRIES
        self.retry_base_s = RETRY_BASE_S

    def _connect_and_ask(self, payload: Dict[str, Any]) -> bool:
        """Single attempt: connect to broker, send payload, receive token."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(self.socket_timeout)
            s.connect((self.broker_host, self.broker_port))
            s.sendall((json.dumps(payload) + "\n").encode())
            token = b""
            while True:
                chunk = s.recv(1024)
                if not chunk:
                    break
                token += chunk
                if b"\n" in token:
                    break
        return bool(token.strip())

    def _ask_broker(self, payload: Dict[str, Any]) -> tuple[bool, str]:
        """Send payload to broker with retry. Fails closed on all errors."""
        for attempt in range(self.broker_retries):
            try:
                approved = self._connect_and_ask(payload)
                return approved, "approved" if approved else "denied_or_timeout"
            except Exception as e:
                delay = self.retry_base_s * (2 ** attempt)
                print(f"[interceptor] Broker attempt {attempt+1}/{self.broker_retries} "
                      f"failed: {e}. "
                      f"{f'Retrying in {delay:.1f}s...' if attempt < self.broker_retries-1 else 'Failing closed.'}")
                if attempt < self.broker_retries - 1:
                    time.sleep(delay)
        return False, "broker_unavailable"

    def evaluate(self, action: str, params: Dict[str, Any]) -> InterceptionResult:
        t_start = time.perf_counter()
        risk = self.classifier.classify(action, params)
        if risk == RiskLevel.LOW:
            elapsed = (time.perf_counter() - t_start) * 1000
            return InterceptionResult(True, risk, "auto_approved", elapsed)

        payload = {
            "action":  action,
            "params":  params,
            "summary": _summarize(action, params),
            "risk":    risk.value,
        }
        allowed, reason = self._ask_broker(payload)
        elapsed = (time.perf_counter() - t_start) * 1000
        status = "APPROVED" if allowed else "DENIED"
        print(f"[interceptor] {status} {action} [{risk.value}] in {elapsed:.0f}ms ({reason})")
        return InterceptionResult(allowed, risk, reason, elapsed)

    def intercept(self, action: str, params: Dict[str, Any]) -> bool:
        return self.evaluate(action, params).allowed


# ── @gated decorator ──────────────────────────────────────────────────────────

_interceptor = Interceptor()

def gated(func: Callable) -> Callable:
    """Decorator: wraps an agent tool function with OpenSentinel."""
    def wrapper(*args, **kwargs):
        params = {"args": list(args), **kwargs}
        result = _interceptor.evaluate(func.__name__, params)
        if result.allowed:
            return func(*args, **kwargs)
        if result.reason == "broker_unavailable":
            detail = "broker unavailable"
        elif result.reason == "denied_or_timeout":
            detail = "approval denied or timed out"
        else:
            detail = result.reason.replace("_", " ")
        raise PermissionError(
            f"[OpenSentinel] '{func.__name__}' was blocked: {detail}."
        )
    wrapper.__name__ = func.__name__
    return wrapper