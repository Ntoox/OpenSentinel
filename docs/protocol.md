# Sacred Gatekeeper Protocol (SGP) — v0.1

Open specification for AI agent action authorization.
Any agent, any language, any platform can implement this.

---

## Overview

SGP defines how an AI agent's tool calls are intercepted, classified, and authorized by a human via a cryptographic approval flow.

---

## Roles

| Role | Description |
|---|---|
| **Agent** | The AI (OpenClaw, Claude Code, etc.) making tool calls |
| **Interceptor** | Middleware that wraps every tool call before execution |
| **Broker** | Local service that holds pending requests and verifies approvals |
| **Kernel** | The human-controlled device (phone) that issues signed approvals |

---

## Risk Levels

```
LOW       → auto-approve, no human in loop
MEDIUM    → pause, notify Kernel, wait for approval
HIGH      → pause, notify Kernel, wait for approval
CRITICAL  → pause, notify Kernel, wait for approval
```

Interceptors MUST fail closed: if the Broker is unreachable, any non-LOW action MUST be denied.

---

## Payload Format

The Interceptor sends a JSON payload to the Broker over a local TCP connection (newline-delimited):

```json
{
  "action":  "send_email",
  "params":  { "to": "boss@company.com", "subject": "Q3 report" },
  "summary": "Send email to boss@company.com",
  "risk":    "MEDIUM"
}
```

Fields:
- `action` — Name of the tool being called (string)
- `params` — Full parameter map (object)
- `summary` — Human-readable summary ≤ 60 characters
- `risk`    — One of `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

---

## Broker API

### TCP (Interceptor → Broker)

- Interceptor connects to `127.0.0.1:9999` (default)
- Sends one newline-terminated JSON payload
- Blocks until Broker responds
- Broker responds with a newline-terminated token string, or empty string if denied/timed out

### HTTP (Kernel → Broker)

**GET /pending**
Returns list of pending requests:
```json
[
  { "id": "uuid", "summary": "Send email to boss@company.com", "risk": "MEDIUM" }
]
```

**POST /approve/{request_id}**
Body: `{ "signature": "<hex Ed25519 signature of request_id>" }`
Response: `{ "ok": true }`

**POST /deny/{request_id}**
Body: `{}`
Response: `{ "ok": true }`

---

## Token Format

The approval token is the hex-encoded Ed25519 signature of the `request_id` (UUID string, UTF-8 encoded), signed with the Kernel's private key.

Properties:
- Single-use (Broker deletes the pending entry on first valid token)
- Scoped to exact `request_id` (cannot be replayed for other actions)
- 60-second TTL (Broker times out if no approval within 60 s)

---

## Key Management

- The Kernel generates an Ed25519 key pair on first launch
- Private key lives exclusively in the device's secure enclave (iOS Keychain / Android Keystore)
- Public key is registered with the Broker once (out of band, e.g. QR code scan)
- The Broker stores only the public key; it is never sent back to any service

---

## Ledger

The Broker MUST maintain an append-only ledger of every decision:

```
id        TEXT PRIMARY KEY
timestamp REAL
action    TEXT
risk      TEXT
summary   TEXT
decision  TEXT   -- "approve" | "deny" | "timeout"
token     TEXT   -- hex signature, or empty
```

The ledger MUST use SQLite WAL mode. Rows MUST never be deleted or modified.

---

## Security Requirements

1. Interceptor MUST build payload from the action schema, never from LLM-generated text
2. Broker MUST verify Ed25519 signature before setting `decision = approve`
3. Broker MUST run on localhost only (no external network)
4. Push relay (e.g. Supabase) MUST receive only `device_id` and `request_id` — never action data, params, or tokens
5. Interceptor MUST fail closed when Broker is unreachable
