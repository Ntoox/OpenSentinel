-- OpenSentinel — Supabase schema
-- Run once via the Supabase SQL editor or `supabase db reset`

CREATE TABLE IF NOT EXISTS sg_devices (
    device_id     TEXT PRIMARY KEY,
    device_name   TEXT NOT NULL,
    public_key    TEXT NOT NULL,
    push_token    TEXT,
    platform      TEXT,
    active        BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sg_notifications (
    id            BIGSERIAL PRIMARY KEY,
    device_id     TEXT NOT NULL,
    request_id    TEXT NOT NULL,
    summary       TEXT NOT NULL,
    risk          TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at   TIMESTAMPTZ,
    UNIQUE(device_id, request_id)
);

CREATE INDEX IF NOT EXISTS sg_notifications_device_idx ON sg_notifications (device_id, created_at DESC);

CREATE TABLE IF NOT EXISTS sg_decisions (
    id            BIGSERIAL PRIMARY KEY,
    request_id    TEXT NOT NULL,
    device_id     TEXT NOT NULL,
    action        TEXT NOT NULL,
    signature     TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sg_decisions_request_idx ON sg_decisions (request_id, created_at DESC);

CREATE TABLE IF NOT EXISTS sg_audit (
    id          TEXT PRIMARY KEY,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT now(),
    action      TEXT NOT NULL,
    risk        TEXT NOT NULL,
    summary     TEXT NOT NULL,
    decision    TEXT NOT NULL,
    latency_ms  REAL
);

ALTER TABLE sg_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE sg_notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE sg_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sg_audit ENABLE ROW LEVEL SECURITY;

CREATE POLICY "service_devices_all" ON sg_devices
    FOR ALL
    USING     (auth.role() = 'service_role')
    WITH CHECK (auth.role() = 'service_role');

CREATE POLICY "service_notifications_all" ON sg_notifications
    FOR ALL
    USING     (auth.role() = 'service_role')
    WITH CHECK (auth.role() = 'service_role');

CREATE POLICY "service_decisions_all" ON sg_decisions
    FOR ALL
    USING     (auth.role() = 'service_role')
    WITH CHECK (auth.role() = 'service_role');

CREATE POLICY "phone_notifications_read" ON sg_notifications
    FOR SELECT
    USING (true);

CREATE POLICY "phone_decisions_insert" ON sg_decisions
    FOR INSERT
    WITH CHECK (action IN ('approve', 'deny'));

CREATE POLICY "service_audit_all" ON sg_audit
    FOR ALL
    USING     (auth.role() = 'service_role')
    WITH CHECK (auth.role() = 'service_role');
