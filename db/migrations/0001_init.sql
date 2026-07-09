CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS schema_migrations (
    filename   text PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS messages (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    direction            text NOT NULL CHECK (direction IN ('inbound', 'outbound')),
    partner_name         text NOT NULL,
    content_digest       text NOT NULL,
    transaction_set      text,
    input_format         text,
    status               text NOT NULL,
    error_code           integer,
    receipt_verified     boolean,
    sinks_status         jsonb NOT NULL DEFAULT '{}',
    raw_headers          jsonb,
    received_at          timestamptz,
    sent_at              timestamptz,
    receipt_sent_at      timestamptz,
    receipt_received_at  timestamptz,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    UNIQUE (partner_name, content_digest, direction)
);

CREATE INDEX IF NOT EXISTS idx_messages_partner ON messages (partner_name);
CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages (created_at);
