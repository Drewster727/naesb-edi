-- Outbound delivery moves to a DB-backed job queue so retries can span the
-- spec's 30-120 minute Exchange Failure window (standards 12.3.10/12.3.11)
-- without blocking the HTTP request that enqueued them, and so retry state
-- survives an app/worker restart mid-window.

CREATE TABLE IF NOT EXISTS outbound_jobs (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    partner_name            text NOT NULL,
    from_id                 text NOT NULL,
    to_id                   text NOT NULL,
    version                 text NOT NULL,
    input_format            text NOT NULL,
    transaction_set         text,
    refnum                  text,
    refnum_orig             text,
    payload_ciphertext      bytea NOT NULL,
    content_digest          text NOT NULL,
    status                  text NOT NULL DEFAULT 'queued'
                                CHECK (status IN (
                                    'queued', 'in_progress', 'delivered', 'failed_nack', 'exchange_failure'
                                )),
    attempt_count           integer NOT NULL DEFAULT 0,
    next_attempt_at         timestamptz NOT NULL DEFAULT now(),
    last_error_code         text,
    last_error_description  text,
    receipt_trans_id        text,
    receipt_server_id       text,
    receipt_time_c          text,
    message_id              uuid REFERENCES messages(id),
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_outbound_jobs_due
    ON outbound_jobs (next_attempt_at)
    WHERE status IN ('queued', 'in_progress');
