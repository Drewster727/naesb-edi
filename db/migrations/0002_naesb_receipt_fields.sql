-- Real NAESB gisb-acknowledgement-receipt fields: trans-id is a sequential
-- integer assigned by the server, and refnum/refnum-orig are the spec's own
-- (mutually agreed) message-tracking data elements. error_code moves from
-- integer to text to hold real EEDM###/WEDM###/GWX-... codes.

CREATE SEQUENCE IF NOT EXISTS trans_id_seq;

ALTER TABLE messages
    ALTER COLUMN error_code TYPE text USING error_code::text;

ALTER TABLE messages
    ADD COLUMN IF NOT EXISTS trans_id     bigint,
    ADD COLUMN IF NOT EXISTS refnum       text,
    ADD COLUMN IF NOT EXISTS refnum_orig  text;

CREATE INDEX IF NOT EXISTS idx_messages_partner_refnum
    ON messages (partner_name, refnum)
    WHERE refnum IS NOT NULL;
