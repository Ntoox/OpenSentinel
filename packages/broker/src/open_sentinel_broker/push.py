"""Push helpers for Sacred Gatekeeper.

Supports two channels:
  1. Direct Expo push notifications to registered device push tokens.
  2. Optional Supabase relay rows for remote/mobile decision polling.
"""

import json
import os
import urllib.request
import urllib.error

SUPABASE_URL = os.environ.get("SG_SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = (
    os.environ.get("SG_SUPABASE_SERVICE_KEY", "")
    or os.environ.get("SG_SUPABASE_KEY", "")
)
EXPO_PUSH_URL = "https://exp.host/--/api/v2/push/send"


def is_configured() -> bool:
    return bool(SUPABASE_URL and SUPABASE_KEY)


def can_send_push(devices: list[dict] | None) -> bool:
    return any(device.get("push_token") for device in (devices or []))


def _headers() -> dict:
    return {
        "Content-Type":  "application/json",
        "apikey":        SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
    }


def _post(path: str, data: dict) -> bool:
    if not is_configured():
        return False
    req = urllib.request.Request(
        f"{SUPABASE_URL}/rest/v1/{path}",
        data=json.dumps(data).encode(),
        headers={**_headers(), "Prefer": "return=minimal"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status in (200, 201)
    except Exception as e:
        print(f"[push] Supabase POST error: {e}")
        return False


def _post_json(url: str, data: object, headers: dict | None = None) -> bool:
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return 200 <= r.status < 300
    except Exception as e:
        print(f"[push] POST error: {e}")
        return False


def _send_expo_push(devices: list[dict], request_id: str, summary: str, risk: str) -> bool:
    tokens = [device.get("push_token") for device in devices if device.get("push_token")]
    if not tokens:
        return False
    payload = [
        {
            "to": token,
            "title": f"Sacred Gatekeeper: {risk}",
            "body": summary,
            "sound": "default",
            "priority": "high",
            "data": {"request_id": request_id, "risk": risk},
        }
        for token in tokens
    ]
    return _post_json(EXPO_PUSH_URL, payload)


def notify(request_id: str, summary: str, risk: str, devices: list[dict] | None = None) -> bool:
    """Fan out request notifications to registered devices."""
    devices = devices or []
    sent_push = _send_expo_push(devices, request_id, summary, risk)

    if is_configured() and devices:
        rows = [
            {
                "device_id": device["device_id"],
                "request_id": request_id,
                "summary": summary,
                "risk": risk,
            }
            for device in devices
        ]
        _post("sg_notifications", rows)

    return sent_push or is_configured()


def poll_decision(request_id: str, allowed_device_ids: set[str] | None = None) -> dict | None:
    """Check sg_decisions table for a response. Returns {action, signature} or None."""
    if not is_configured():
        return None
    url = (f"{SUPABASE_URL}/rest/v1/sg_decisions"
           f"?request_id=eq.{request_id}&select=action,signature,device_id&order=created_at.asc&limit=20")
    req = urllib.request.Request(url, headers=_headers())
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read())
            if not data:
                return None
            if not allowed_device_ids:
                return data[0]
            for row in data:
                if row.get("device_id") in allowed_device_ids:
                    return row
            return None
    except Exception:
        return None


def delete_notification(request_id: str):
    """Clean up notification row after decision received."""
    if not is_configured():
        return
    url = f"{SUPABASE_URL}/rest/v1/sg_notifications?request_id=eq.{request_id}"
    req = urllib.request.Request(url, headers=_headers(), method="DELETE")
    try:
        urllib.request.urlopen(req, timeout=3)
    except Exception:
        pass
