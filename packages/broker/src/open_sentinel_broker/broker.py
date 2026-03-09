"""
OpenSentinel — Local Auth Broker v2

TCP  :9999  — interceptor sends JSON payload, blocks for token response
HTTP :9998  — phone (or phone_sim/real app) GETs /pending, POSTs /approve|deny

Decision sources (first wins):
  1. Direct HTTP from phone on local network
  2. Supabase polling (if SG_SUPABASE_* env vars are set)
  3. 60-second timeout → auto-deny

Append-only SQLite ledger in WAL mode. Keys are persistent across restarts.
"""

import json
import os
import secrets
import socket
import sqlite3
import threading
import time
import ipaddress
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib import import_module

import uuid
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

LEDGER_DB        = os.environ.get("SG_LEDGER",      "ledger.db")
PHONE_PUB_PATH   = os.environ.get("SG_PHONE_PUB",   "phone_public.pem")
PHONE_PRIV_PATH  = os.environ.get("SG_PHONE_PRIV",  "phone_private.pem")
TCP_HOST         = os.environ.get("SG_TCP_HOST",    "127.0.0.1")
TCP_PORT         = int(os.environ.get("SG_TCP_PORT",  "9999"))
HTTP_HOST        = os.environ.get("SG_HTTP_HOST",   "0.0.0.0")
HTTP_PORT        = int(os.environ.get("SG_HTTP_PORT", "9998"))
REQUEST_TIMEOUT  = 60
SUPABASE_POLL_INTERVAL = 0.5
START_TIME = time.time()
ALLOW_REMOTE_PAIRING = os.environ.get("SG_ALLOW_REMOTE_PAIRING", "false").lower() in {"1", "true", "yes", "on"}
PAIRING_RATE_LIMIT = int(os.environ.get("SG_PAIRING_RATE_LIMIT", "5"))
PAIRING_WINDOW_S = int(os.environ.get("SG_PAIRING_WINDOW_S", "300"))
REGISTER_RATE_LIMIT = int(os.environ.get("SG_REGISTER_RATE_LIMIT", "20"))
REGISTER_WINDOW_S = int(os.environ.get("SG_REGISTER_WINDOW_S", "300"))
DECISION_RATE_LIMIT = int(os.environ.get("SG_DECISION_RATE_LIMIT", "120"))
DECISION_WINDOW_S = int(os.environ.get("SG_DECISION_WINDOW_S", "60"))
REVOKE_RATE_LIMIT = int(os.environ.get("SG_REVOKE_RATE_LIMIT", "10"))
REVOKE_WINDOW_S = int(os.environ.get("SG_REVOKE_WINDOW_S", "300"))
DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{3,80}$")


def _ensure_parent_dir(path: str):
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)


def _broker_log(event: str, **fields):
    record = {"ts": round(time.time(), 3), "event": event, **fields}
    print(f"[broker] {json.dumps(record, sort_keys=True)}")


def _get_push_module():
    try:
        return import_module(".push", package=__package__)
    except Exception:
        return import_module("push")


class Broker:
    def __init__(self):
        self.pending: dict[str, dict] = {}
        self.lock = threading.Lock()
        self.rate_limit_lock = threading.Lock()
        self.rate_limits: dict[tuple[str, str], list[float]] = {}
        self.started_at = START_TIME
        self.allow_remote_pairing = ALLOW_REMOTE_PAIRING
        self.phone_public_key = self._load_or_create_keys()
        self._init_db()
        self._start_cleanup_thread()

    # ── Keys ──────────────────────────────────────────────────────────────────

    def _load_or_create_keys(self):
        """Load existing key pair or generate a new one (first run only)."""
        if os.path.exists(PHONE_PUB_PATH):
            with open(PHONE_PUB_PATH, "rb") as f:
                return serialization.load_pem_public_key(f.read())
        _ensure_parent_dir(PHONE_PUB_PATH)
        _ensure_parent_dir(PHONE_PRIV_PATH)
        priv = ed25519.Ed25519PrivateKey.generate()
        pub  = priv.public_key()
        with open(PHONE_PRIV_PATH, "wb") as f:
            f.write(priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(PHONE_PUB_PATH, "wb") as f:
            f.write(pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
        _broker_log("keys_generated", phone_public_key=PHONE_PUB_PATH)
        return pub

    # ── Database ──────────────────────────────────────────────────────────────

    def _init_db(self):
        _ensure_parent_dir(LEDGER_DB)
        with sqlite3.connect(LEDGER_DB) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ledger (
                    id         TEXT PRIMARY KEY,
                    timestamp  REAL NOT NULL,
                    action     TEXT NOT NULL,
                    risk       TEXT NOT NULL,
                    summary    TEXT NOT NULL,
                    decision   TEXT NOT NULL,
                    token      TEXT,
                    latency_ms REAL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    device_id     TEXT PRIMARY KEY,
                    device_name   TEXT NOT NULL,
                    public_key    TEXT NOT NULL,
                    push_token    TEXT,
                    platform      TEXT,
                    active        INTEGER NOT NULL DEFAULT 1,
                    registered_at REAL NOT NULL,
                    last_seen_at  REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS pairing_codes (
                    code        TEXT PRIMARY KEY,
                    device_name TEXT NOT NULL,
                    created_at  REAL NOT NULL,
                    expires_at  REAL NOT NULL,
                    claimed_at  REAL
                )
            """)
            columns = {
                row[1] for row in conn.execute("PRAGMA table_info(ledger)")
            }
            if "token" not in columns:
                conn.execute("ALTER TABLE ledger ADD COLUMN token TEXT")
            if "latency_ms" not in columns:
                conn.execute("ALTER TABLE ledger ADD COLUMN latency_ms REAL")
            conn.commit()

    def _db_connect(self):
        conn = sqlite3.connect(LEDGER_DB)
        conn.row_factory = sqlite3.Row
        return conn

    def _is_loopback(self, client_ip: str) -> bool:
        try:
            return ipaddress.ip_address(client_ip).is_loopback
        except ValueError:
            return False

    def _consume_rate_limit(self, bucket: str, subject: str, limit: int, window_s: int) -> bool:
        now = time.time()
        key = (bucket, subject)
        with self.rate_limit_lock:
            history = self.rate_limits.get(key, [])
            history = [stamp for stamp in history if now - stamp < window_s]
            if len(history) >= limit:
                self.rate_limits[key] = history
                return False
            history.append(now)
            self.rate_limits[key] = history
            return True

    def check_pairing_access(self, client_ip: str) -> tuple[bool, str]:
        if not self.allow_remote_pairing and not self._is_loopback(client_ip):
            return False, "remote pairing is disabled"
        if not self._consume_rate_limit("pairing", client_ip, PAIRING_RATE_LIMIT, PAIRING_WINDOW_S):
            return False, "pairing rate limit exceeded"
        return True, "ok"

    def check_registration_access(self, client_ip: str) -> tuple[bool, str]:
        if not self._consume_rate_limit("register", client_ip, REGISTER_RATE_LIMIT, REGISTER_WINDOW_S):
            return False, "registration rate limit exceeded"
        return True, "ok"

    def check_decision_access(self, client_ip: str) -> tuple[bool, str]:
        if not self._consume_rate_limit("decision", client_ip, DECISION_RATE_LIMIT, DECISION_WINDOW_S):
            return False, "decision rate limit exceeded"
        return True, "ok"

    def check_revoke_access(self, client_ip: str) -> tuple[bool, str]:
        if not self._consume_rate_limit("revoke", client_ip, REVOKE_RATE_LIMIT, REVOKE_WINDOW_S):
            return False, "revoke rate limit exceeded"
        return True, "ok"

    def _validate_device_fields(self, device_id: str, device_name: str, public_key: str, push_token: str | None) -> tuple[bool, str]:
        if not DEVICE_ID_RE.fullmatch(device_id):
            return False, "invalid device id"
        if not (1 <= len(device_name) <= 80):
            return False, "invalid device name"
        if len(public_key) != 64:
            return False, "invalid public key"
        try:
            bytes.fromhex(public_key)
        except ValueError:
            return False, "invalid public key"
        if push_token and len(push_token) > 512:
            return False, "invalid push token"
        return True, "ok"

    def get_devices(self) -> list[dict]:
        with self._db_connect() as conn:
            rows = conn.execute(
                """
                SELECT device_id, device_name, push_token, platform, active,
                       registered_at, last_seen_at
                FROM devices
                ORDER BY registered_at ASC
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def get_active_devices(self) -> list[dict]:
        with self._db_connect() as conn:
            rows = conn.execute(
                """
                SELECT device_id, device_name, public_key, push_token, platform,
                       registered_at, last_seen_at
                FROM devices
                WHERE active = 1
                ORDER BY registered_at ASC
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def start_pairing(self, device_name: str = "Phone", ttl_s: int = 600) -> dict:
        code = f"{secrets.randbelow(1_000_000):06d}"
        now = time.time()
        payload = {
            "code": code,
            "device_name": device_name,
            "created_at": now,
            "expires_at": now + ttl_s,
            "claimed_at": None,
        }
        with self._db_connect() as conn:
            conn.execute(
                "DELETE FROM pairing_codes WHERE expires_at < ? OR claimed_at IS NOT NULL",
                (now,),
            )
            conn.execute(
                """
                INSERT INTO pairing_codes (code, device_name, created_at, expires_at, claimed_at)
                VALUES (:code, :device_name, :created_at, :expires_at, :claimed_at)
                """,
                payload,
            )
            conn.commit()
        _broker_log("pairing_started", code=code, device_name=device_name)
        return {
            "ok": True,
            "code": code,
            "device_name": device_name,
            "expires_in_s": ttl_s,
            "expires_at": payload["expires_at"],
        }

    def get_pairing_status(self, code: str) -> dict:
        now = time.time()
        with self._db_connect() as conn:
            row = conn.execute(
                "SELECT code, device_name, expires_at, claimed_at FROM pairing_codes WHERE code = ?",
                (code,),
            ).fetchone()
        if not row:
            return {"ok": False, "status": "missing"}
        if row["claimed_at"]:
            return {"ok": True, "status": "claimed", "device_name": row["device_name"]}
        if row["expires_at"] < now:
            return {"ok": True, "status": "expired", "device_name": row["device_name"]}
        return {
            "ok": True,
            "status": "pending",
            "device_name": row["device_name"],
            "expires_in_s": max(0, int(row["expires_at"] - now)),
        }

    def _validate_pairing_code(self, code: str) -> tuple[bool, str]:
        status = self.get_pairing_status(code)
        if not status.get("ok"):
            return False, "pairing code not found"
        if status["status"] == "claimed":
            return False, "pairing code already claimed"
        if status["status"] == "expired":
            return False, "pairing code expired"
        return True, "ok"

    def _load_registered_public_key(self, public_key_b64: str):
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(public_key_b64)
        )
        return public_key

    def register_device(self, payload: dict) -> tuple[bool, dict]:
        pairing_code = str(payload.get("pairing_code", "")).strip()
        device_id = str(payload.get("device_id", "")).strip()
        device_name = str(payload.get("device_name", "Phone")).strip() or "Phone"
        public_key = str(payload.get("public_key", "")).strip()
        push_token = str(payload.get("push_token", "")).strip() or None
        platform = str(payload.get("platform", "unknown")).strip() or "unknown"

        if not pairing_code or not device_id or not public_key:
            return False, {"ok": False, "error": "missing required registration fields"}

        valid_fields, field_error = self._validate_device_fields(device_id, device_name, public_key, push_token)
        if not valid_fields:
            return False, {"ok": False, "error": field_error}

        valid, error = self._validate_pairing_code(pairing_code)
        if not valid:
            return False, {"ok": False, "error": error}

        try:
            self._load_registered_public_key(public_key)
        except Exception:
            return False, {"ok": False, "error": "invalid public key"}

        now = time.time()
        with self._db_connect() as conn:
            conn.execute(
                """
                INSERT INTO devices (
                    device_id, device_name, public_key, push_token, platform,
                    active, registered_at, last_seen_at
                ) VALUES (?, ?, ?, ?, ?, 1, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    device_name = excluded.device_name,
                    public_key = excluded.public_key,
                    push_token = excluded.push_token,
                    platform = excluded.platform,
                    active = 1,
                    last_seen_at = excluded.last_seen_at
                """,
                (device_id, device_name, public_key, push_token, platform, now, now),
            )
            conn.execute(
                "UPDATE pairing_codes SET claimed_at = ? WHERE code = ?",
                (now, pairing_code),
            )
            conn.commit()

        _broker_log("device_registered", device_id=device_id, device_name=device_name)
        return True, {
            "ok": True,
            "device": {
                "device_id": device_id,
                "device_name": device_name,
                "platform": platform,
                "push_enabled": bool(push_token),
            },
        }

    def refresh_device(self, payload: dict) -> tuple[bool, dict]:
        device_id = str(payload.get("device_id", "")).strip()
        public_key = str(payload.get("public_key", "")).strip()
        device_name = str(payload.get("device_name", "Phone")).strip() or "Phone"
        push_token = str(payload.get("push_token", "")).strip() or None
        platform = str(payload.get("platform", "unknown")).strip() or "unknown"

        if not device_id or not public_key:
            return False, {"ok": False, "error": "missing device identity"}

        valid_fields, field_error = self._validate_device_fields(device_id, device_name, public_key, push_token)
        if not valid_fields:
            return False, {"ok": False, "error": field_error}

        with self._db_connect() as conn:
            row = conn.execute(
                "SELECT public_key FROM devices WHERE device_id = ? AND active = 1",
                (device_id,),
            ).fetchone()
            if not row:
                return False, {"ok": False, "error": "device not registered"}
            if row["public_key"] != public_key:
                return False, {"ok": False, "error": "public key mismatch"}
            conn.execute(
                """
                UPDATE devices
                SET device_name = ?, push_token = ?, platform = ?, last_seen_at = ?
                WHERE device_id = ?
                """,
                (device_name, push_token, platform, time.time(), device_id),
            )
            conn.commit()
        return True, {"ok": True}

    def revoke_device(self, device_id: str) -> tuple[bool, dict]:
        device_id = str(device_id).strip()
        if not device_id:
            return False, {"ok": False, "error": "missing device id"}

        with self._db_connect() as conn:
            row = conn.execute(
                "SELECT device_id, device_name, active FROM devices WHERE device_id = ?",
                (device_id,),
            ).fetchone()
            if not row:
                return False, {"ok": False, "error": "device not found"}
            if not row["active"]:
                return True, {"ok": True, "device_id": device_id, "already_revoked": True}
            conn.execute(
                """
                UPDATE devices
                SET active = 0, push_token = NULL, last_seen_at = ?
                WHERE device_id = ?
                """,
                (time.time(), device_id),
            )
            conn.commit()

        _broker_log("device_revoked", device_id=device_id, device_name=row["device_name"])
        return True, {"ok": True, "device_id": device_id, "already_revoked": False}

    def _verify_signature(self, rid: str, signature_hex: str) -> tuple[bool, str | None]:
        signature = bytes.fromhex(signature_hex)
        for device in self.get_active_devices():
            try:
                self._load_registered_public_key(device["public_key"]).verify(signature, rid.encode())
                return True, device["device_id"]
            except Exception:
                continue
        try:
            self.phone_public_key.verify(signature, rid.encode())
            return True, "legacy_local_key"
        except Exception:
            return False, None

    def status_snapshot(self) -> dict:
        devices = self.get_devices()
        with self.lock:
            pending_count = sum(
                1 for entry in self.pending.values() if entry.get("decision") is None
            )
        return {
            "status": "ok",
            "uptime_s": round(time.time() - self.started_at, 3),
            "pending_count": pending_count,
            "ledger_db": os.path.abspath(LEDGER_DB),
            "phone_public_key": os.path.abspath(PHONE_PUB_PATH),
            "push_relay_configured": _get_push_module().is_configured(),
            "registered_devices": [
                {
                    "device_id": device["device_id"],
                    "device_name": device["device_name"],
                    "platform": device["platform"],
                    "push_enabled": bool(device["push_token"]),
                    "active": bool(device["active"]),
                }
                for device in devices
            ],
            "tcp": {"host": TCP_HOST, "port": TCP_PORT},
            "http": {"host": HTTP_HOST, "port": HTTP_PORT},
        }

    def _log(self, rid: str, payload: dict, decision: str,
             token: str = "", latency_ms: float = 0.0):
        with sqlite3.connect(LEDGER_DB) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                """
                INSERT OR IGNORE INTO ledger (
                    id, timestamp, action, risk, summary, decision, token, latency_ms
                ) VALUES (?,?,?,?,?,?,?,?)
                """,
                (rid, time.time(), payload["action"], payload["risk"],
                 payload.get("summary", ""), decision, token, latency_ms),
            )
            conn.commit()

    # ── Cleanup ───────────────────────────────────────────────────────────────

    def _start_cleanup_thread(self):
        def cleanup():
            while True:
                time.sleep(10)
                now = time.time()
                with self.lock:
                    expired = [
                        rid for rid, e in self.pending.items()
                        if now - e.get("created_at", now) > REQUEST_TIMEOUT + 5
                    ]
                for rid in expired:
                    with self.lock:
                        entry = self.pending.pop(rid, None)
                    if entry:
                        self._log(rid, entry["payload"], "timeout_cleanup")
                        _broker_log("pending_expired", request_id=rid)
        threading.Thread(target=cleanup, daemon=True).start()

    # ── Core request flow ─────────────────────────────────────────────────────

    def handle_interceptor_request(self, payload: dict) -> str:
        rid     = str(uuid.uuid4())
        event   = threading.Event()
        t_start = time.perf_counter()

        with self.lock:
            self.pending[rid] = {
                "payload":    payload,
                "event":      event,
                "decision":   None,
                "token":      "",
                "created_at": time.time(),
            }

        self._dispatch_push(rid, payload)

        approved   = event.wait(timeout=REQUEST_TIMEOUT)
        latency    = (time.perf_counter() - t_start) * 1000

        with self.lock:
            entry = self.pending.pop(rid, {})

        decision = entry.get("decision") or "timeout"
        token    = entry.get("token", "")
        self._log(rid, payload, decision, token, latency)

        push_mod = _get_push_module()
        push_mod.delete_notification(rid)

        result = token if decision == "approve" else ""
        _broker_log(
            "request_resolved",
            request_id=rid,
            action=payload["action"],
            risk=payload["risk"],
            decision=decision,
            latency_ms=round(latency, 3),
        )
        return result

    def _dispatch_push(self, rid: str, payload: dict):
        push_mod = _get_push_module()
        devices = self.get_active_devices()
        push_sent = push_mod.notify(rid, payload["summary"], payload["risk"], devices=devices)
        if push_mod.is_configured():
            threading.Thread(
                target=self._poll_supabase,
                args=(rid, {device["device_id"] for device in devices}),
                daemon=True,
            ).start()
        _broker_log(
            "request_created",
            request_id=rid,
            action=payload["action"],
            risk=payload["risk"],
            summary=payload.get("summary", ""),
            push_relay_configured=push_mod.is_configured(),
            push_sent=push_sent,
            target_devices=len(devices),
        )

    def _poll_supabase(self, rid: str, allowed_device_ids: set[str]):
        push_mod = _get_push_module()
        deadline = time.time() + REQUEST_TIMEOUT
        while time.time() < deadline:
            with self.lock:
                if rid not in self.pending:
                    return
            result = push_mod.poll_decision(rid, allowed_device_ids=allowed_device_ids)
            if result:
                self._apply_decision(
                    rid,
                    result.get("action", "deny"),
                    result.get("signature", "")
                )
                return
            time.sleep(SUPABASE_POLL_INTERVAL)

    # ── Phone callbacks ───────────────────────────────────────────────────────

    def _apply_decision(self, rid: str, action: str, signature_hex: str) -> bool:
        with self.lock:
            if rid not in self.pending:
                return False
            if action == "approve" and signature_hex:
                try:
                    verified, device_id = self._verify_signature(rid, signature_hex)
                    if not verified:
                        raise ValueError("signature verification failed")
                    self.pending[rid]["decision"] = "approve"
                    self.pending[rid]["token"]    = signature_hex
                    self.pending[rid]["device_id"] = device_id
                except Exception:
                    self.pending[rid]["decision"] = "deny"
                    _broker_log("invalid_signature", request_id=rid)
            else:
                self.pending[rid]["decision"] = "deny"
            self.pending[rid]["event"].set()
            _broker_log("decision_applied", request_id=rid, action=action)
        return True

    def phone_approve(self, rid: str, signature_hex: str) -> bool:
        return self._apply_decision(rid, "approve", signature_hex)

    def phone_deny(self, rid: str) -> bool:
        return self._apply_decision(rid, "deny", "")

    def get_pending(self) -> list:
        with self.lock:
            return [
                {"id": rid, "summary": e["payload"].get("summary"),
                 "risk": e["payload"].get("risk")}
                for rid, e in self.pending.items()
                if e.get("decision") is None
            ]


# ── HTTP handler ──────────────────────────────────────────────────────────────

_broker: Broker = None


class PhoneHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def _json(self, code: int, data: dict):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        if self.path == "/pending":
            self._json(200, _broker.get_pending())
        elif self.path == "/health":
            self._json(200, _broker.status_snapshot())
        elif self.path == "/devices":
            self._json(200, {"devices": _broker.get_devices()})
        elif self.path.startswith("/pairing/status/"):
            code = self.path.rsplit("/", 1)[-1]
            self._json(200, _broker.get_pairing_status(code))
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        parts  = self.path.strip("/").split("/")
        length = int(self.headers.get("Content-Length", 0))
        body   = json.loads(self.rfile.read(length) or b"{}")
        if self.path == "/pairing/start":
            ok, message = _broker.check_pairing_access(self.client_address[0])
            if not ok:
                self._json(429 if "rate limit" in message else 403, {"ok": False, "error": message})
                return
            self._json(200, _broker.start_pairing(body.get("device_name", "Phone")))
        elif self.path == "/devices/register":
            ok, message = _broker.check_registration_access(self.client_address[0])
            if not ok:
                self._json(429, {"ok": False, "error": message})
                return
            ok, result = _broker.register_device(body)
            self._json(200 if ok else 400, result)
        elif self.path == "/devices/refresh":
            ok, message = _broker.check_registration_access(self.client_address[0])
            if not ok:
                self._json(429, {"ok": False, "error": message})
                return
            ok, result = _broker.refresh_device(body)
            self._json(200 if ok else 400, result)
        elif self.path == "/devices/revoke":
            ok, message = _broker.check_revoke_access(self.client_address[0])
            if not ok:
                self._json(429, {"ok": False, "error": message})
                return
            ok, result = _broker.revoke_device(body.get("device_id", ""))
            self._json(200 if ok else 400, result)
        elif len(parts) == 2 and parts[0] == "approve":
            ok, message = _broker.check_decision_access(self.client_address[0])
            if not ok:
                self._json(429, {"ok": False, "error": message})
                return
            ok = _broker.phone_approve(parts[1], body.get("signature", ""))
            self._json(200 if ok else 400, {"ok": ok})
        elif len(parts) == 2 and parts[0] == "deny":
            ok, message = _broker.check_decision_access(self.client_address[0])
            if not ok:
                self._json(429, {"ok": False, "error": message})
                return
            ok = _broker.phone_deny(parts[1])
            self._json(200 if ok else 400, {"ok": ok})
        else:
            self._json(404, {"error": "not found"})


# ── TCP server ────────────────────────────────────────────────────────────────

def _tcp_client(broker: Broker, client: socket.socket):
    try:
        f    = client.makefile("r")
        line = f.readline()
        if not line.strip():
            return
        payload = json.loads(line)
        token   = broker.handle_interceptor_request(payload)
        client.sendall((token + "\n").encode())
    except Exception as e:
        _broker_log("tcp_client_error", error=str(e))
        try:
            client.sendall(b"\n")
        except Exception:
            pass
    finally:
        client.close()


def _run_tcp(broker: Broker):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((TCP_HOST, TCP_PORT))
    srv.listen(10)
    _broker_log("tcp_listening", host=TCP_HOST, port=TCP_PORT)
    while True:
        try:
            client, _ = srv.accept()
            threading.Thread(
                target=_tcp_client, args=(broker, client), daemon=True
            ).start()
        except Exception as e:
            _broker_log("tcp_accept_error", error=str(e))


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    global _broker
    _broker = Broker()
    http = HTTPServer((HTTP_HOST, HTTP_PORT), PhoneHandler)
    threading.Thread(target=http.serve_forever, daemon=True).start()
    _broker_log("http_listening", host=HTTP_HOST, port=HTTP_PORT)
    _run_tcp(_broker)


if __name__ == "__main__":
    main()