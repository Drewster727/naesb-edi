-- The file-drop outbound poller (app/poller.py) has no API caller to supply
-- a refnum for partners configured with envelope_overrides.use_refnum: true,
-- so the gateway assigns one itself. This is a simple per-partner monotonic
-- counter, incremented atomically the same way MessageTracker.next_trans_id()
-- already does for the global trans-id sequence
-- (app/tracking/repository.py), just scoped per partner_name instead of
-- global.

CREATE TABLE IF NOT EXISTS partner_refnum_counters (
    partner_name  text PRIMARY KEY,
    next_refnum   bigint NOT NULL DEFAULT 1
);
