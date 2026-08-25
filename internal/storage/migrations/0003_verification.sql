-- Verification: identity addresses, one-time codes, and the Courier outbox.

ALTER TABLE flows ADD COLUMN context jsonb NOT NULL DEFAULT '{}';

CREATE TABLE identity_addresses (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    identity_id uuid NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    channel     text NOT NULL, -- 'email' | 'sms'
    value       text NOT NULL, -- normalized
    verified    boolean NOT NULL DEFAULT false,
    verified_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (identity_id, channel, value)
);

-- One active code per flow; resend replaces the row.
CREATE TABLE one_time_codes (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    flow_id    uuid NOT NULL UNIQUE REFERENCES flows(id) ON DELETE CASCADE,
    code_hash  bytea NOT NULL,
    attempts   int NOT NULL DEFAULT 0,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- The Courier outbox is deliberately NOT under RLS: rows are written
-- inside tenant transactions (outbox pattern) but drained cross-tenant by
-- the platform-level Courier worker, which sends with platform
-- credentials. tenant_id remains for auditing.
CREATE TABLE courier_messages (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    channel         text NOT NULL, -- 'email' | 'sms'
    recipient       text NOT NULL,
    template        text NOT NULL, -- e.g. 'verification_code'
    payload         jsonb NOT NULL DEFAULT '{}',
    status          text NOT NULL DEFAULT 'pending', -- pending | sent | abandoned
    attempts        int NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error      text,
    sent_at         timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX courier_messages_pending_idx
    ON courier_messages (next_attempt_at) WHERE status = 'pending';

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['identity_addresses', 'one_time_codes'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I USING '
            || '(tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid) '
            || 'WITH CHECK '
            || '(tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)',
            t);
    END LOOP;
END $$;
