# Outbound EDI flow — detailed walkthrough

This walks through exactly what happens when *we're* the sender — enqueueing a
transmission to an already-configured trading partner and getting it delivered — end to
end, referencing the actual code that does each step. It's the outbound companion to
`docs/inbound-flow.md`: read this when you need to know *why* a step exists or *which line
of code* to change, not just what the shape of the pipeline is.

Unlike inbound, outbound is deliberately **two-phase**: a synchronous HTTP call that
enqueues the job, and a separate background worker process that actually delivers it and
owns the retry/Exchange-Failure lifecycle (standards 12.3.10/12.3.11 — 3 delivery attempts
spanning 30-120 minutes before the trading partner must be notified of an Exchange
Failure). Splitting these means a retry window that can span up to two hours never blocks
the caller's HTTP request, and retry state survives a worker restart mid-window because
it's persisted in `outbound_jobs`, not held in memory (`app/worker.py:1-13`).

## 0. Alternative entry point: file-drop via `app/poller.py`

Besides `POST /outbound/send` (§1 below), a raw, unencrypted EDI file can be handed to
this gateway by simply writing it to disk. `app/poller.py` (the `poller` service in
`docker-compose.yml`, `python -m app.poller`) watches `settings.poller.base_dir` for
files dropped into partner-DUNS-named subfolders:

```
<base_dir>/<duns>/                 -- drop a raw, unencrypted EDI file here
<base_dir>/<duns>/processed/       -- moved here once handed to outbound_jobs
<base_dir>/<duns>/error/           -- moved here if pickup fails repeatedly
```

Each poll cycle (`settings.poller.poll_interval_seconds`), for every DUNS subfolder that
matches a configured partner (`app/partners.py::PartnerRegistry.get_by_duns()`), any file
that hasn't been modified for at least `settings.poller.quiet_period_seconds` (default
60s -- long enough that a writer still streaming the file to disk is never read mid-write)
is picked up and passed through `app/outbound/enqueue.py::enqueue_outbound()` -- the exact
same encrypt-and-enqueue logic `trigger_send()` uses (see §1). `input_format` is always
`X12`; `transaction_set` is left unset; `refnum` is auto-assigned from a new per-partner
counter (`partner_refnum_counters`, via `PartnerRefnumRepository`) for any partner with
`envelope_overrides.use_refnum: true` -- there's no API caller here to supply one.

**`processed/` means "enqueued", not "delivered".** The file moves the moment
`enqueue_outbound()` returns a job ID -- mirroring `POST /outbound/send`'s own
fire-and-forget `202` semantics (§1). The job's actual delivery outcome, including the
existing 3-attempt Exchange-Failure window (§5), is tracked purely in
`outbound_jobs`/`messages` and structured logs (`poller_file_enqueued`, and later
`outbound_delivered`/`outbound_rejected_by_partner`/`outbound_exchange_failure` from
`app/worker.py`) -- it is **never** reflected back onto the filesystem. A file in
`processed/` can still end up an Exchange Failure; check `outbound_jobs`/logs for the
real outcome, not folder placement.

`error/` is reserved for failures *before* a file reaches `outbound_jobs` at all --
unreadable file, unrecognized/misconfigured partner crypto (e.g. missing PGP key),
Postgres unavailable. These are retried up to `settings.poller.max_pickup_attempts` times
(in-memory count, per poller process lifetime) before the file moves to `error/` and a
`poller_file_errored` event is logged at `ERROR`.

A DUNS subfolder that doesn't match any configured partner is left untouched, with a
rate-limited `poller_unknown_duns` warning -- it self-heals once the partner is added to
`partners.yaml`.

## 1. Enqueue: `POST /outbound/send`

`app/api/send.py::trigger_send()` (lines 52-119). Request body (`SendRequest`, lines
27-33): `partner_name`, `input_format` (only `X12` is supported —
`app/envelope/fields.py:26-36`; `FF`/`error` belong to a separate "Internet Flat File EDM"
mechanism this gateway doesn't implement), optional `transaction_set`/`refnum`/
`refnum_orig`, and `payload_base64`.

Steps, in order:

1. **Partner lookup.** `partners.get_by_name(body.partner_name)` — unknown partner is a
   plain `HTTP 404` (there's no envelope yet to carry a NAESB error code in, unlike an
   inbound rejection).
2. **Decode the payload.** Invalid base64 is `HTTP 400`.
3. **Resolve the envelope version** — partner's `envelope_overrides.version` if set, else
   `settings.envelope.default_version`.
4. **Encrypt + sign once.** `gpg.encrypt_and_sign()` (`app/crypto/gpg_wrapper.py`) signs
   with our private key and encrypts to the partner's public key (the same operation a
   partner performs on their side before sending to us — see `docs/inbound-flow.md` §1).
   This happens exactly once at enqueue time; the resulting ciphertext is persisted on the
   job and **reused for every retry attempt**, specifically so a partner's own content-digest
   dedup still recognizes repeated deliveries as the same message (`app/api/send.py:79-81`).
5. **Record it.** A `MessageRecord` (`direction="outbound"`, `status="queued"`) is created
   via `tracker.create()` for the audit trail, and an `OutboundJob` (`app/tracking/models.py:27-47`)
   is persisted via `jobs.create()` — this is the actual work item the worker will pick up.
6. **Respond `202`** with `{"job_id": ..., "status": "queued"}` (`SendAcceptedResponse`,
   lines 36-38).

Poll `GET /outbound/jobs/{job_id}` (`get_job_status()`, lines 122-138) for the outcome:
`JobStatusResponse` (lines 41-49) reports `status`
(`queued`/`in_progress`/`delivered`/`failed_nack`/`exchange_failure`), `attempt_count`,
`last_error_code`/`last_error_description` on failure, or the decoded receipt fields
(`receipt_trans_id`, `receipt_server_id`, `receipt_time_c`) once delivered.

## 2. The worker must be running

Enqueueing a job does not deliver it. Delivery happens in a **separate process**,
`python -m app.worker` (`app/worker.py:154-161` — this is the `worker` service in
`docker-compose.yml`, run alongside the `app` service). If the worker isn't running, jobs
sit in `queued` indefinitely. `run_worker()` (lines 113-151) loops forever (or a bounded
count in tests), each cycle calling `jobs.claim_due_jobs(limit=10)`
(`app/tracking/repository.py:195-230` — `SELECT ... FOR UPDATE SKIP LOCKED` so multiple
worker instances can run safely) and processing whatever comes back, then sleeping
`settings.outbound.worker_poll_interval_seconds`.

## 3. One delivery attempt: `send_once()`

`app/outbound/client.py::send_once()` (lines 59-115) performs exactly one attempt and
raises `DeliveryAttemptError` on any failure — retry/Exchange-Failure decisions belong to
the caller (`app/worker.py`), not this function.

1. **Build the envelope.** `envelope_fields_from_job()` (lines 44-56) maps the job onto
   `EnvelopeFields` (`from`, `to`, `version`, `receipt-disposition-to` = our own ID,
   `receipt-report-type` = the literal `gisb-acknowledgement-receipt`, `input-format`,
   `receipt-security-selection`, `transaction-set`, `refnum`, `refnum-orig`).
   `build_multipart_body()` (`app/envelope/multipart_codec.py`) assembles the outer
   `multipart/form-data` request in the spec-mandated field order, with the ciphertext
   wrapped as an inner `multipart/encrypted` PGP-MIME part — the exact structure
   `docs/inbound-flow.md` §1 describes a partner building on their side.
2. **Auth header.** `_auth_header()` (lines 37-41) builds `Authorization: Basic ...` or
   `Bearer ...` from `partner.outbound_auth` — see `docs/authentication.md` for the
   credential model.
3. **Transport.** `_build_transport()` (lines 26-34) pins TLS to 1.2 or 1.3 per
   `settings.crypto.tls_min_version`, and optionally binds a specific local address via
   `settings.server.outbound_source_address` (relevant when a partner requires delivery
   from a known static egress IP). The POST itself goes to `partner.endpoint_url`
   (`settings.outbound.timeout_seconds` timeout). A non-2xx or transport-level failure
   raises `DeliveryAttemptError` immediately (lines 84-85).
4. **Parse the response as a signed receipt.** The partner's synchronous response is
   expected to be `multipart/signed` (RFC 1847), the same structure we build ourselves
   when we're the *receiver* (`docs/inbound-flow.md` §7). `parse_signed_mime()`
   (`app/envelope/receipt.py`) splits it into the report body and detached signature; a
   response that isn't in this shape is a `DeliveryAttemptError`, not a crash.
5. **Verify the signature.** `gpg.verify_detached()` against the partner's known
   fingerprint — missing or invalid signature is a `DeliveryAttemptError`.
6. **Enforce digest policy.** `enforce_digest_policy()` (`app/crypto/policy.py:113-120`)
   checks the receipt's signature hash algorithm against
   `partner.crypto_overrides.allowed_digests` if set, else `settings.crypto.allowed_digests`
   — this is the sign-only counterpart to `enforce_policy()`, which additionally checks a
   symmetric cipher on the inbound (encrypted) side. Like inbound, this is the gateway's own
   local security policy, not a NAESB mandate (standard 12.3.26 explicitly disclaims
   site-level algorithm requirements beyond RSA ≥ 2048 bits, Appendix A).
7. **Decode the receipt.** `NaesbReceipt.decode_report_part()` extracts `request-status`,
   `trans-id`, `server-id`, `time-c` from the verified report body.

## 4. Outcome handling: `app/worker.py::_process_job()` (lines 35-74)

- **Unknown partner** (removed from config between enqueue and delivery) →
  `mark_exchange_failure()` immediately, no retry.
- **`DeliveryAttemptError`** → `_handle_failure()` (lines 77-110).
- **`receipt.is_ok`** → `mark_delivered()` persists the receipt's `trans_id`/`server_id`/
  `time_c` on the job, and the corresponding `MessageRecord` is updated to
  `status="delivered"`.
- **Receipt decoded but `request-status` isn't `ok`** (a NAESB error/warning code, e.g.
  the partner rejected the transmission) → `mark_failed_nack()` with the parsed error code
  and description — this is a *terminal* outcome, not retried, because the partner
  actively rejected the message rather than failing to respond at all.

## 5. Retry / Exchange Failure: `_handle_failure()` (lines 77-110)

Only reached for `DeliveryAttemptError` (network failure, bad/unverifiable receipt) — never
for an explicit partner rejection, which is terminal (§4).

- If `job.attempt_count >= len(settings.outbound.retry_schedule_seconds)` (default
  schedule `[0, 900, 2700]` seconds — i.e. immediate, then +15min, then +45min, three
  attempts total, matching the spec's 3-attempts language): `mark_exchange_failure()`, and
  the `messages` row moves to `status="exchange_failure"`. Logged as a distinct
  `outbound_exchange_failure` structured event — this is the spec's Exchange Failure
  notification trigger, not just an ordinary failure log line.
- Otherwise: `reschedule()` sets `next_attempt_at = now() + schedule[attempt_count]` and
  moves the job back to `status="queued"` so `claim_due_jobs()` picks it up again once due.

## Job lifecycle (`outbound_jobs` table, `db/migrations/0003_outbound_jobs.sql`)

```
queued --(claim_due_jobs)--> in_progress --+--> delivered
                                            +--> failed_nack        (terminal, partner rejected)
                                            +--> queued (reschedule) (retry pending)
                                            +--> exchange_failure    (terminal, retries exhausted)
```

`claim_due_jobs()` only claims `status='queued'` rows with `next_attempt_at <= now()`,
using `FOR UPDATE SKIP LOCKED` — deliberately excluding `in_progress` so a job in flight
can't be claimed twice by concurrent worker instances.

## Relevant partner config fields

Schema in `app/partners.py:66-85`, real values in `config/partners.yaml` (example in
`config/partners.example.yaml`):

- `endpoint_url` — where `send_once()` POSTs.
- `pgp_public_key_path` — the partner's public key, used to encrypt the outbound payload
  (imported into the shared GnuPG keyring at worker startup by `bootstrap_keyring()`).
- `outbound_auth` — credentials *we* present to the partner (`docs/authentication.md`).
- `envelope_overrides` — per-partner `version`/`agreed_transaction_sets`/`use_refnum`.
- `crypto_overrides` — per-partner `allowed_ciphers`/`allowed_digests`/`min_rsa_key_bits`,
  for legacy partners whose receipts use weaker algorithms than the global default.
- `require_signature` — not consulted on the outbound path itself (it gates the inbound
  `enforce_policy()` call); a partner's *receipt* is always signature-verified regardless.

## See also

- `app/outbound/client.py`, `app/worker.py` — the pipeline implementation this document
  describes.
- `app/api/send.py` — the enqueue endpoint.
- `app/poller.py`, `app/outbound/filewatch.py`, `app/outbound/enqueue.py` — the file-drop
  entry point described in §0.
- `tests/test_poller.py`, `tests/test_filewatch.py` — worked examples for the file-drop
  path (pickup success, pickup failure/retry/error, unknown DUNS, quiet-period gating).
- `docs/inbound-flow.md` — the mirror-image flow when we're the receiver; several steps
  here (envelope construction, PGP-MIME wrapping, signed-receipt parsing) reuse the exact
  same code either side uses when playing the other role.
- `docs/authentication.md` — the `outbound_auth`/`inbound_auth` credential model.
- `tests/test_outbound_client.py` — a full worked example of `send_once()` (success,
  partner rejection, HTTP failure, unverifiable receipt, wrong-signer-key), good template
  for a manual smoke test.
- `docs/PLAN.md` — architecture rationale for the queue-based retry design.
