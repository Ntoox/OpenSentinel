# OpenSentinel

Every tool call an AI agent makes is intercepted, risk-classified, and — for anything above LOW risk — paused until you approve it on your phone with FaceID / TouchID.

No cloud required. No new hardware. Runs on your laptop + your existing phone.

```
AI Agent  →  Interceptor  →  Local Broker  →  Your Phone (biometric)
```

- **LOW** → auto-approved
- **MEDIUM / HIGH / CRITICAL** → push notification, you approve or deny
- Broker unreachable → **fail closed** (denied, never silently passed)

---

## Install & Run

**Requirements:** Python 3.10+, Node 18+ (for the mobile app)

```bash
git clone https://github.com/your-org/sacred-gatekeeper
cd sacred-gatekeeper
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e packages/interceptor -e packages/broker
cp .env.example .env
```

**Start everything (one command):**
```bash
python tools/stack_launcher.py
```
Starts the broker, runs the OpenClaw demo with a phone simulator, and prints a pairing code for a real device.

**Manual startup:**
```bash
# Terminal 1
python -m sacred_gatekeeper_broker.broker

# Terminal 2 — phone simulator (dev only)
python tools/phone_sim.py

# Terminal 3 — demo
python examples/openclaw-demo/demo.py
```

---

## Hook Your Agent

```python
from sacred_gatekeeper_interceptor.interceptor import gated

@gated
def send_email(to: str, subject: str, body: str): ...

@gated
def run_shell(command: str): ...
```

Every decorated call now requires phone approval if it exceeds LOW risk.

---

## Risk Classification

| Level    | Examples                                      | Behaviour       |
|----------|-----------------------------------------------|-----------------|
| LOW      | read-only, safe lookups                       | Auto-approved   |
| MEDIUM   | `send_email`, `upload_file`, `commit`         | Phone required  |
| HIGH     | `delete_file`, `git_push`, suspicious params  | Phone required  |
| CRITICAL | `run_shell`, `execute_code`                   | Phone required  |

Edit `rules.toml` to customise classification.

---

## Mobile App

React Native / Expo app in `apps/kernel/`. Pair once over LAN; thereafter it receives push notifications and works over any network.

```bash
cd apps/kernel
npm install && npx expo start   # Expo Go for dev
npm run build:android:dev       # installable APK with push support
```

Supabase relay (`EXPO_PUBLIC_SUPABASE_URL`) is optional — enables approval flow when the broker is not directly reachable.

---

## Audit Log

```bash
python tools/audit_log.py              # last 50 entries
python tools/audit_log.py --since 1h
python tools/audit_log.py --risk CRITICAL --decision deny
```

---

## Security

| Threat | Mitigation |
|---|---|
| AI agent takeover | Agent controls code, not the approval token. CRITICAL actions require signed phone approval. |
| Prompt injection | Payload built from action schema, not LLM text. |
| Compromised middleware | Broker only accepts Ed25519 tokens signed by the phone's key. |
| Broker offline | Interceptor fails closed — action denied, never silently passed. |

---

## Environment Variables

Copy `.env.example` to `.env`. Key variables:

| Variable | Default | Description |
|---|---|---|
| `SG_BROKER_HOST` | `127.0.0.1` | Broker TCP host |
| `SG_BROKER_PORT` | `9999` | Broker TCP port |
| `SG_HTTP_PORT` | `9998` | Broker HTTP port |
| `SG_CONFIG` | `rules.toml` | Risk rules path |
| `SG_LEDGER` | `ledger.db` | SQLite ledger path |
| `SG_ALLOW_REMOTE_PAIRING` | `false` | Allow pairing from non-localhost |
| `EXPO_PUBLIC_BROKER_HTTP` | — | Phone app → broker URL (LAN IP) |
| `EXPO_PUBLIC_SUPABASE_URL` | — | Optional Supabase relay URL |

---

## Status

Alpha — local stack is functional and tested. Mobile app APK build in progress. Not yet validated on a physical device.

See [docs/roadmap.md](docs/roadmap.md) for what's next.

---

## License

MIT
