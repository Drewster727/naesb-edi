-- The digest-dedup path has a real backstop: UNIQUE (partner_name,
-- content_digest, direction) from 0001_init.sql. The refnum-dedup path
-- (app/tracking/repository.py::find_refnum_reuse(), used for partners with
-- envelope_overrides.use_refnum) only had a non-unique index
-- (idx_messages_partner_refnum), so two concurrent inbound requests with the
-- same (partner, refnum) but different ciphertext could both pass the
-- pre-check and both insert successfully -- silently violating the spec's
-- "first send/resend" refnum semantics this mechanism exists to enforce.
--
-- This closes that race the same way the digest path is already closed: a
-- real unique constraint, backstopping the racy find-then-insert check in
-- app/inbound/routes.py.

DROP INDEX IF EXISTS idx_messages_partner_refnum;

CREATE UNIQUE INDEX IF NOT EXISTS uq_messages_partner_refnum
    ON messages (partner_name, refnum, direction)
    WHERE refnum IS NOT NULL;
