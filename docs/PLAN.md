# NAESB WGQ 4.0 Internet ET EDI Gateway

## Context

The existing EDI setup is a fork of OpenAS2, which only speaks AS2. NAESB
4.0 (Wholesale Gas Quadrant Business Practice Standards) does not use AS2 --
it uses NAESB's own **Internet Electronic Transport (Internet ET)**
protocol: PGP-encrypted payloads exchanged over HTTP(S) as a
`multipart/form-data` POST, where each trading partner supplies the other
with their PGP public key. This project (`naesb-edi-gateway`) replaces/supplements
the AS2 gateway with a purpose-built Internet ET gateway. No UI -- purely an
HTTP/API service, intended to sit between internal systems and external
NAESB trading partners (interstate pipeline operators).

**Spec provenance note (revised):** an earlier version of this plan was
built against `docs/naesb4.md`, a document that turned out to be
**fabricated** -- it invented a wire format (raw `application/octet-stream`
body, custom lowercase HTTP headers), a receipt format (line-delimited
`receipt-status: ...` text), and a numeric `101/102/103` error-code scheme,
none of which exist in the real standard. The user subsequently supplied
the official **NAESB WGQ Cybersecurity Related Standards Manual, Version
4.0** (Sept 29, 2023; `docs/NAESB-cyber0923-2026-0709.pdf`), and this plan
was rewritten against that real text. `docs/naesb4.md` is quarantined (see
the warning banner at its top) and kept only for historical reference. Two
things the real manual leaves genuinely open, confirmed with the project
owner rather than guessed: the exact `version` protocol-version default
(no safe default -- required config, per-TPA) and the `transaction-set`
8-character code table (treated as an opaque, length-validated string).

## Architecture Overview

Python 3.12, FastAPI (inbound HTTP server) + httpx (outbound client,
single-attempt), a separate worker process for outbound retry scheduling,
Pydantic v2 for all config/schema validation, `python-gnupg` wrapping
system GnuPG for OpenPGP. Config follows OpenAS2's split (central config +
partner directory), reimagined as YAML:

- `config/config.yaml` -- our identity, envelope defaults, server/crypto/db/
  sink defaults, outbound retry schedule, logging (equivalent of OpenAS2's
  `config.xml`).
- `config/partners.yaml` -- one entry per trading partner: name, DUNS
  number, endpoint URL, PGP public key reference, inbound/outbound auth
  credentials, per-partner envelope overrides (protocol version, agreed
  transaction sets, refnum usage) (equivalent of `partnerships.xml`).

### Directory tree

```
naesb-edi-gateway/
├── pyproject.toml
├── README.md
├── Dockerfile
├── docker-compose.yml            # app + worker + postgres + minio, for local dev/manual verification
├── .dockerignore
├── .gitignore                    # excludes config/keys, .env, real config.yaml/partners.yaml
├── config/
│   ├── config.example.yaml
│   └── partners.example.yaml
├── db/
│   └── migrations/
│       ├── 0001_init.sql          # messages + schema_migrations tables
│       ├── 0002_naesb_receipt_fields.sql  # trans_id/refnum/refnum_orig, error_code -> text
│       └── 0003_outbound_jobs.sql # DB-backed outbound retry job queue
├── samples/
│   └── request-ssc-{1,2,3,4}.txt  # real captured trading-partner inbound transmissions
│                                   # -- fixtures for test_sample_request.py
├── app/
│   ├── main.py                    # FastAPI app factory + lifespan startup (config, gpg, db, sinks)
│   ├── worker.py                  # separate process: polls outbound_jobs, executes/reschedules attempts
│   ├── dependencies.py            # FastAPI Depends() providers
│   ├── settings.py                # Pydantic models + loader for config.yaml (env-var secret resolution)
│   ├── partners.py                # Pydantic models + loader for partners.yaml, override-merge logic
│   ├── logging_config.py          # structlog JSON logging, request-scoped context (partner, digest)
│   ├── errors.py                  # exception types + FastAPI exception handlers
│   ├── message.py                 # InboundMessage dataclass passed to sinks
│   ├── envelope/
│   │   ├── fields.py               # EnvelopeField enum (literal spec field names), EnvelopeFields model
│   │   ├── mime_split.py           # manual byte-level MIME multipart splitter (no re-serialization)
│   │   ├── pgp_mime.py              # multipart/encrypted wrap/unwrap for input-data's inner payload
│   │   ├── multipart_codec.py      # build_multipart_body() / parse_multipart_form(), EnvelopeError
│   │   ├── receipt.py              # NaesbReceipt model, multipart/report + multipart/signed build/parse
│   │   └── error_codes.py          # NaesbErrorCode (real EEDM###/WEDM###), GatewayExtensionCode (GWX-...)
│   ├── crypto/
│   │   ├── gpg_wrapper.py          # encrypt_and_sign(), decrypt_and_verify(), detached_sign(), verify_detached()
│   │   ├── policy.py               # AlgorithmInfo, parse_status(), enforce_policy(), key-length checks
│   │   └── keyring.py              # startup import of our private key + all partner public keys, RSA length validation
│   ├── sinks/
│   │   ├── base.py                 # Sink protocol, SinkResult
│   │   ├── filesystem_sink.py
│   │   ├── s3_sink.py               # boto3, S3-compatible endpoint_url (AWS/MinIO/Wasabi)
│   │   ├── webhook_sink.py          # httpx POST, best-effort/non-durable
│   │   └── dispatcher.py            # fan_out(): concurrent, isolated failures
│   ├── tracking/
│   │   ├── models.py                 # MessageRecord, OutboundJob
│   │   ├── db.py                     # psycopg pool + migration runner
│   │   └── repository.py              # MessageTracker (messages table), OutboundJobRepository (outbound_jobs)
│   ├── inbound/
│   │   ├── routes.py                  # POST /inbound — full receive pipeline
│   │   └── auth.py                     # per-partner inbound auth (Basic -- the spec's own scheme; api_key extension)
│   ├── outbound/
│   │   └── client.py                   # send_once(): single delivery attempt, envelope build, verify receipt
│   └── api/
│       ├── send.py                     # POST /outbound/send (enqueue, 202) + GET /outbound/jobs/{id}
│       ├── partners.py                  # GET /api/partners
│       └── health.py                   # GET /healthz, /readyz
└── tests/
    ├── conftest.py                     # ephemeral GPG keypairs (tmp GNUPGHOME), gpg_service fixture
    ├── test_gpg_policy.py              # roundtrip + detached sign/verify + weak-algorithm/short-key rejection
    ├── test_pgp_mime.py                # multipart/encrypted wrap/unwrap round trip
    ├── test_multipart_codec.py         # outer multipart/form-data build -> Starlette parse round trip
    ├── test_receipt.py                 # multipart/report + multipart/signed build/parse, full real-GPG round trip
    ├── test_inbound_route.py           # auth failure / bad sig / weak algo / duplicate / refnum / happy path
    ├── test_outbound_client.py         # respx-mocked partner endpoint, single-attempt send_once()
    ├── test_worker.py                  # retry-scheduling / Exchange Failure declaration logic
    ├── test_sinks_filesystem.py
    ├── test_sinks_s3.py                # moto, in-process, no Docker
    ├── test_sinks_webhook.py
    ├── test_sinks_dispatcher.py
    ├── test_tracking_repository.py     # testcontainers[postgres], marked @pytest.mark.integration
    ├── test_api_partners.py
    ├── test_config_loader.py
    └── test_sample_request.py          # parses real captured samples/request-ssc-*.txt transmissions
```

## Key design decisions

| Area | Decision | Why |
|---|---|---|
| Request transport | `POST`, `Content-Type: multipart/form-data`, ordered fields `from`/`to`/`version`/`receipt-disposition-to`/`receipt-report-type`/`input-format`/`input-data`/`receipt-security-selection`/(optional)`transaction-set`/`refnum`/`refnum-orig`. Outer envelope is hand-built byte-for-byte (`multipart_codec.py`) for exact field order; inbound parsing trusts Starlette's `request.form()` (`python-multipart`) for the untrusted outer envelope. | Matches the real Envelope Data Dictionary and "Sender HTTP Request Data Elements" exactly. |
| Payload nesting | The `input-data` field's content is itself `multipart/encrypted` (RFC 1847/3156): an `application/pgp-encrypted` control part ("Version: 1") + the raw armor-less OpenPGP message. Hand-rolled build/parse (`pgp_mime.py`), not a generic MIME library, for byte-exact control. | Matches "Anatomy of an Internet ET Package" / "Payload" exactly. |
| MIME byte-exactness | All MIME construction (outer envelope, inner `multipart/encrypted`, the receipt's `multipart/signed`/`multipart/report`) is hand-rolled with explicit boundary strings and a manual splitter (`mime_split.py`) rather than Python's `email.generator`, which is not guaranteed to reproduce byte-identical output on re-serialization -- and PGP signatures are byte-exact. | Verified in `test_receipt.py::test_full_signed_receipt_round_trip_with_real_gpg`: sign, wrap, parse, and verify against real GnuPG without ever re-serializing the signed bytes. |
| Payload crypto pipeline | Compress (ZIP/ZLIB) -> sign with sender's private key -> encrypt to recipient's public key -> armor-less binary, via a single `python-gnupg` `encrypt()` call with `sign=` set. | Matches "Encryption / Digital Signature". Cipher/digest choice (AES256/SHA256 default) is this gateway's own local policy, not a NAESB mandate (12.3.26). |
| Key strength | RSA only; reject/refuse to load any key (ours or a partner's) under 2048 bits at startup; 4096-bit recommended. | A real NAESB requirement (Appendix A), enforced in `keyring.py` via `gpg.list_keys()`. |
| Inbound decrypt-policy accept-list | `crypto.allowed_ciphers`/`crypto.allowed_digests` (lists, default `[AES256, AES192, AES128]`/`[SHA256, SHA384, SHA512, SHA1]`) -- separate from `cipher_algo`/`digest_algo` above, which are only what *we* use outbound. Checked in `enforce_policy()` (inbound decrypt) and `enforce_digest_policy()` (verifying a partner's returned receipt signature, `outbound/client.py`). Per-partner `crypto_overrides.allowed_ciphers`/`allowed_digests` (`partners.yaml`, `app/partners.py::CryptoOverrides`) replaces the global list for that partner only. | Broadened past our own outbound default because real partners' PGP libraries are often older than what we'd choose ourselves -- confirmed against real captures (`samples/request-ssc-*.txt`), whose sender requests `sha1` receipt signatures. NAESB itself sets no cipher/digest mandate (12.3.26), so this remains a local policy knob, not a spec requirement. |
| TLS | Outbound `httpx` client pinned to TLS 1.2 minimum; inbound TLS termination stays at a reverse proxy. | Matches standards 12.3.14/12.3.23/Appendix A. |
| Receipt | `Content-Type: multipart/signed` (detached PGP signature, `application/pgp-signature`) wrapping `multipart/report; report-type="gisb-acknowledgement-receipt"`, whose sub-parts contain `key=value*`-delimited lines (`time-c`, `request-status`, `server-id`, `trans-id`) in that required order. `time-c` is `yyyymmddhhmmss`, captured immediately on last byte received (standard 12.3.5), before auth/parsing/decryption. `trans-id` is a DB-sequence-backed monotonic integer. | Matches "Receiving Internet ET Packages" / "Acknowledgement Receipt" exactly -- supersedes the earlier fabricated line-delimited JSON-like design. |
| Error codes | Real `EEDM###`/`WEDM###` codes (`error_codes.py::NaesbErrorCode`) for spec-documented failure modes (missing/invalid fields, decryption failures 601-604/699, unknown partner 701, duplicate refnum 121, ...). Gateway-only extensions (`GatewayExtensionCode`, `GWX-...` prefix) for guarantees the spec doesn't cover (content-digest dedup, local weak-algorithm policy, sink delivery failure) -- explicitly namespaced so they can never collide with a real code. | The spec's own Table 1 is authoritative and far more specific than the earlier fabricated 3-code scheme; extensions are clearly marked as non-NAESB. |
| Authentication | HTTP Basic Authentication over TLS is the spec-compliant default (`type: basic`, standards 12.3.14/12.3.28/12.3.29). `type: api_key` (Bearer) is a clearly-labeled gateway-only convenience extension. | Matches the standard directly, rather than treating both as equally-spec-defined (neither was, previously). |
| Dedup / idempotency key | Primarily `(partner, refnum)` when a partner is configured `use_refnum: true` (the spec's own tracking mechanism, standards around `refnum`/`refnum-orig`); otherwise a SHA-256 digest of the extracted ciphertext bytes (not the raw multipart body, whose boundary/whitespace can differ between byte-identical resends). | Prefers the spec's real tracking mechanism where a partner supports it; content-digest is a documented gateway extension, not a spec concept, for partners who don't use refnum. |
| Transaction-set metadata | `transaction-set` is an opaque, length-8-validated string (per the data dictionary's "8 character code" description) -- not derived from a 3-digit ANSI X12 transaction set number. The real WGQ 8-character code table wasn't available; treat as caller/TPA-supplied. | Avoids inventing a code-derivation formula the spec doesn't define. |
| `version` field | Required config field (`envelope.default_version`, per-partner overridable), no default value. | The manual's own "4.0" is the *document* revision, not necessarily the wire `version` field (historically small decimals like "1.9"); guessing a value and shipping it to a real partner is worse than forcing an explicit operator decision. |
| Scope: input-format | `InputFormat` enum is `X12` only (confirmed with project owner). The spec's `FF` value belongs to a separate "Internet Flat File EDM" / Interactive-Browser HTML-upload mechanism (Appendix B/C) that's out of scope for this pure HTTP/API gateway; `error` is only meaningful for the Error Notification flow (also out of scope, see below). Both are trivial to add back as enum values later. | Keeps this gateway a single, pure "Batch Browser" (automated) implementation rather than also building a human-facing web upload flow. |
| Scope: Error Notification | Not implemented. This gateway decrypts synchronously before sending the receipt (a fully spec-compliant choice per "Parties may choose to decrypt file before or after Receipt is sent") so decryption errors are always reported directly in that same receipt, never via a later async POST-back. | Confirmed with project owner: avoids building a second inbound-notification surface for a scenario this gateway's architecture doesn't produce. |
| Outbound retry / Exchange Failure | DB-backed job queue: `POST /outbound/send` enqueues a row in `outbound_jobs` and returns `202` immediately (never blocks). A separate `app/worker.py` process polls for due jobs (`SELECT ... FOR UPDATE SKIP LOCKED`), executes `outbound/client.py::send_once()`, and reschedules per `outbound.retry_schedule_seconds` (default `[0, 900, 2700]` -- T+0/+15min/+45min) or marks `exchange_failure` once exhausted. | Standards 12.3.10/12.3.11 require 3 attempts over a 30-120 minute window -- far too long to hold open an HTTP request; a DB-backed queue also survives an app/worker restart mid-window, per project owner's explicit choice over a simpler-but-blocking design. |
| Sinks | Filesystem, S3-compatible, webhook -- independently configurable, each tagged `durable: bool` (fs/S3 default true, webhook default false). ACK requires >=1 durable sink success (configurable), never depends on webhook success. | Unchanged from the original design -- prevents ACKing content we didn't actually retain anywhere. |
| Message tracking | Postgres, `messages` table for inbound/outbound message lifecycle, separate `outbound_jobs` table for retry-schedule state (attempt count, next attempt time, last error). | Retry scheduling has different query/locking needs (claim-and-lock semantics) than the audit-trail `messages` table, so it's a separate table rather than overloading one schema. |
| DB migrations | Numbered idempotent SQL files (`0001_init.sql`, `0002_naesb_receipt_fields.sql`, `0003_outbound_jobs.sql`) + a small custom runner tracking applied filenames in `schema_migrations`. | Unchanged -- still simpler than Alembic for a handful of tables. |
| PGP library | `python-gnupg` wrapping system GnuPG -- needs `gnupg` apt-installed in the Dockerfile. | Unchanged -- maximum interop compatibility with whatever PGP tool partners run. |
| Allowed TCP ports / static egress IP / TPW | Not code -- documented as operational prerequisites in the README (NAESB Appendix C's specific allowed-port list; interstate pipelines' fixed whitelisted outbound IP requirement; a bilateral Technical/Trading Partner Worksheet before certification testing). | Infrastructure/onboarding process, not something the app enforces internally. |

## Config schema (illustrative)

See `config/config.example.yaml` and `config/partners.example.yaml` in the
repo for the full, current, commented schema (envelope `server_id` /
`default_version` / `receipt_security_selection`, outbound
`retry_schedule_seconds` / `worker_poll_interval_seconds`, per-partner
`envelope_overrides.version` / `agreed_transaction_sets` / `use_refnum`).
Those files are the source of truth; this document doesn't duplicate them
to avoid drift.

## Request/response wire format

**Outbound request** (built by `app/envelope/multipart_codec.py::build_multipart_body()`,
used by `app/outbound/client.py::send_once()`, parsed on the receiving end
by `app/envelope/multipart_codec.py::parse_multipart_form()` in
`app/inbound/routes.py`):
```
POST {endpoint_url} HTTP/1.1
Content-Type: multipart/form-data; boundary="----naesb-form-<random>"

------naesb-form-<random>
content-disposition: form-data; name="from"

123456789
------naesb-form-<random>
content-disposition: form-data; name="to"

987654321
------naesb-form-<random>
content-disposition: form-data; name="version"

1.9
------naesb-form-<random>
content-disposition: form-data; name="receipt-disposition-to"

123456789
------naesb-form-<random>
content-disposition: form-data; name="receipt-report-type"

gisb-acknowledgement-receipt
------naesb-form-<random>
content-disposition: form-data; name="input-format"

X12
------naesb-form-<random>
content-disposition: form-data; name="input-data"; filename="payload.pgp"
content-type: multipart/encrypted; boundary="----naesb-pgp-<random>"; protocol="application/pgp-encrypted"

------naesb-pgp-<random>
content-type: application/pgp-encrypted

Version: 1
------naesb-pgp-<random>
content-type: application/octet-stream
content-transfer-encoding: binary

<raw binary: ZIP-compressed, signed, encrypted OpenPGP message, no armor>
------naesb-pgp-<random>--
------naesb-form-<random>
content-disposition: form-data; name="receipt-security-selection"

signed-receipt-protocol=required,pgp-signature;signed-receipt-micalg=required,sha256
------naesb-form-<random>
content-disposition: form-data; name="transaction-set"

NOM00001
------naesb-form-<random>--
```

**Synchronous response** -- HTTP 200 body is `multipart/signed` (RFC 1847),
built/parsed by `app/envelope/receipt.py`:
```
Content-Type: multipart/signed; micalg="pgp-sha256"; protocol="application/pgp-signature"; boundary="----naesb-signed-<random>"

------naesb-signed-<random>
content-type: multipart/report; report-type="gisb-acknowledgement-receipt"; boundary="----naesb-report-<random>"

------naesb-report-<random>
content-type: text/html

<HTML>...time-c=20260710120000*request-status=ok*server-id=gateway.example.com*trans-id=42*...</HTML>
------naesb-report-<random>
content-type: text/plain

time-c=20260710120000*
request-status=ok*
server-id=gateway.example.com*
trans-id=42*
------naesb-report-<random>--
------naesb-signed-<random>
content-type: application/pgp-signature

-----BEGIN PGP SIGNATURE-----
...
-----END PGP SIGNATURE-----
------naesb-signed-<random>--
```
On rejection, `request-status` is instead e.g. `EEDM604: Encrypted file not
signed or signature not matched*` or a `GWX-...` extension code.

## Inbound/outbound pipeline flow

Inbound (`app/inbound/routes.py`), every path past transport-level auth
returns **HTTP 200** with a signed `multipart/signed` receipt body;
`request-status` is the actual protocol-level ACK/NACK:
1. Read body; capture `time_c` immediately (standard 12.3.5) -- before size
   check, auth, or parsing.
2. Enforce `max_body_size_bytes` -- fail with plain HTTP 413.
3. Per-partner inbound auth (Basic, or gateway-extension Bearer) -- fail
   closed with a plain (unsigned) HTTP 401, no GPG/parsing work done.
4. Assign a sequential `trans_id` (DB sequence) -- used in every receipt
   from this point on, success or failure.
5. Parse the `multipart/form-data` envelope + unwrap `input-data`'s
   `multipart/encrypted` payload; malformed/missing fields map to the exact
   `EEDM1xx` code via `error_codes.py::error_code_for_field()`.
6. Verify the envelope's `from` matches the authenticated partner's DUNS
   (else `EEDM701`); check refnum presence if the partner requires it
   (`EEDM119`).
7. Dedupe: `(partner, refnum)` if in use, else content-digest of the
   extracted ciphertext (`GWX-DUPLICATE-DIGEST`; `EEDM121` for refnum
   reuse).
8. `decrypt_and_verify()` -- decryption failure -> `EEDM699`; signature
   mismatch -> `EEDM604`.
9. `enforce_policy()` on parsed algorithm info + partner key length;
   violation -> `GWX-WEAK-ALGO`.
10. Sink fan-out; zero durable sinks succeed -> `GWX-SINK-FAILURE`.
11. Track every step in Postgres. Build the receipt, `detached_sign()` it,
    wrap in `multipart/signed`, return as the HTTP 200 body.

Outbound (`app/outbound/client.py::send_once()` + `app/worker.py`):
`POST /outbound/send` encrypts the payload once, enqueues an `outbound_jobs`
row, returns `202`. The worker claims due jobs, calls `send_once()` (builds
the multipart body, POSTs, parses the `multipart/signed` response,
`verify_detached()`s it against the partner's public key *before* trusting
`request-status* -- never re-serializes the signed bytes before verifying),
and either marks the job `delivered`/`failed_nack` or reschedules per
`outbound.retry_schedule_seconds`, marking `exchange_failure` once that
schedule is exhausted.

## Modern-OpenPGP and key-strength enforcement

On encrypt: `gpg.encrypt(data, recipients=[partner_key], sign=our_key,
extra_args=["--compress-algo","ZIP","--cipher-algo","AES256","--digest-algo","SHA256", ...])`,
armor-less. On sign (receipt): `gpg.sign(data, detach=True, clearsign=False,
binary=False)` -- an ASCII-armored **detached** signature (`app/crypto/gpg_wrapper.py::detached_sign()`),
matching the receipt's `application/pgp-signature` body part. Verification
uses `gpg.verify_data()` (`verify_detached()`), since python-gnupg needs the
detached signature on disk.

On decrypt/verify: `python-gnupg` doesn't expose the negotiated algorithm as
a named attribute -- parse it from GnuPG's status-fd lines in
`result.stderr`: `DECRYPTION_INFO <mdc_method> <sym_algo>` for the cipher,
`VALIDSIG ... <pubkey_algo> <hash_algo> ...` for the signature digest.
`test_gpg_policy.py` asserts this against a real ephemeral-keypair roundtrip
(not a hardcoded string) so GnuPG version drift fails loudly rather than
silently accepting weak crypto.

On startup (`keyring.py`): import our private key and every partner's
public key into the managed keyring, then call `gpg.list_keys()` and reject
startup if our key or any partner key reports `algo` outside RSA or
`length` < `crypto.min_rsa_key_bits` (default 2048; a real NAESB
requirement, Appendix A), logging a warning if below
`recommended_rsa_key_bits` (4096).

**Inbound decrypt-policy accept-list vs. our own outbound crypto default:**
`crypto.cipher_algo`/`crypto.digest_algo` (singular) are what *this gateway*
uses when *it* encrypts/signs (outbound payloads, receipt detached-sign).
Separately, `crypto.allowed_ciphers`/`crypto.allowed_digests` (lists,
default `[AES256, AES192, AES128]` / `[SHA256, SHA384, SHA512, SHA1]`) are
the accept-list `app/crypto/policy.py::enforce_policy()` checks a decrypted
*inbound* message's negotiated algorithms against (`app/inbound/routes.py`),
and what `app/outbound/client.py` checks a partner's *returned receipt*
signature digest against. This is deliberately broader than our own
outbound default: NAESB doesn't mandate a specific cipher/digest (standard
12.3.26), and real trading partners' PGP libraries are often older --
confirmed against real captures (`samples/request-ssc-*.txt`, from an older
trading-partner PGP implementation), whose `receipt-security-selection`
field requests `sha1`. A partner whose real
traffic needs something outside even this broadened default (e.g. 3DES) can
get a `crypto_overrides.allowed_ciphers`/`allowed_digests` entry in
`partners.yaml` (`app/partners.py::CryptoOverrides`) that replaces the
global list for that partner only, rather than widening the default for
everyone.

## Database

`db/migrations/0001_init.sql` creates `schema_migrations` and `messages`.
`0002_naesb_receipt_fields.sql` adds `trans_id`/`refnum`/`refnum_orig` and
converts `error_code` from `integer` to `text` (to hold `EEDM###`/`GWX-...`
strings) plus a `trans_id_seq` sequence. `0003_outbound_jobs.sql` adds the
`outbound_jobs` table (envelope fields, ciphertext, status, attempt count,
`next_attempt_at`, last error, receipt details) with an index for the
worker's due-job claim query. `app/tracking/db.py` applies un-applied
migration files in filename order at startup (both app and worker).

## Testing strategy

- `test_gpg_policy.py`: compress->sign->encrypt/decrypt->verify roundtrip
  plus detached-sign/verify, using ephemeral keypairs; explicit
  weak-cipher/weak-digest/short-RSA-key rejection cases.
- `test_pgp_mime.py`: `multipart/encrypted` wrap/unwrap round trip.
- `test_multipart_codec.py`: outer envelope build -> real Starlette/
  `python-multipart` parse round trip, including the nested
  `multipart/encrypted` payload; field-order assertion; missing/invalid
  field error mapping.
- `test_receipt.py`: `multipart/report`/`multipart/signed` build/parse
  round trip, including a full real-GnuPG detached-sign + verify pass over
  the exact bytes the manual MIME splitter extracts (proves no
  re-serialization mutates signed bytes).
- `test_inbound_route.py`: FastAPI `TestClient` against real multipart
  bodies -- auth failure (401, unsigned), signature failure (`EEDM604`),
  decryption failure (`EEDM699`), sender mismatch (`EEDM701`), duplicate
  digest/refnum (`GWX-DUPLICATE-DIGEST`/`EEDM121`), missing refnum
  (`EEDM119`), weak algorithm (`GWX-WEAK-ALGO`), sink failure
  (`GWX-SINK-FAILURE`), missing field (exact `EEDM1xx`), sequential
  `trans-id`, happy path, and a synthetic test reproducing a real partner's
  structural shape (SHA1 digest, armored ciphertext, dash-containing inner
  boundary, no CTE header, `input-data` last) end to end.
- `test_sample_request.py`: parses the real captured
  `samples/request-ssc-{1,2,3,4}.txt` trading-partner transmissions through
  `parse_multipart_form()`/`unwrap_pgp_encrypted()` directly -- confirms the
  envelope fields and exact armored ciphertext bytes are recovered
  untouched from real-world traffic, not just this gateway's own synthetic
  `build_multipart_body()` output.
- `test_outbound_client.py`: `respx`-mocked partner endpoint, asserts
  request shape (multipart body, ordered fields, ciphertext-not-plaintext)
  and receipt-signature verification logic for `send_once()`.
- `test_worker.py`: retry-scheduling and Exchange Failure declaration logic
  against fake job/tracker repositories.
- `test_sinks_*.py`: filesystem (real temp dir), S3 (`moto`, in-process),
  webhook, dispatcher fan-out.
- `test_tracking_repository.py`: `testcontainers[postgres]`, marked
  `@pytest.mark.integration`, covering both `MessageTracker` and
  `OutboundJobRepository` (including the claim/reschedule/exchange-failure
  state machine) against a real Postgres instance.
- `test_config_loader.py`, `test_api_partners.py`: config/partner loading,
  env-var secret resolution, override-merge behavior, internal-API auth.

## Docker

`Dockerfile`: `python:3.12-slim`, `apt-get install gnupg ca-certificates`,
non-root user, `pip install .`, default `CMD` runs `uvicorn app.main:app`.
`docker-compose.yml` adds a `worker` service (same image,
`command: ["python", "-m", "app.worker"]`), Postgres, and MinIO for local
dev/manual verification -- CI tests don't depend on compose being up (moto
+ testcontainers are self-contained).

## Verification (end-to-end, manual)

1. `docker-compose up --build`; `GET /healthz` -> 200.
2. Generate two ephemeral RSA-4096 GPG keypairs locally ("gateway" = us,
   "test-partner"); export public keys; import gateway's private key into
   the running container's `GNUPGHOME` volume out-of-band; reference
   `test-partner`'s public key from `partners.yaml`.
3. Build a sample X12 873 nomination payload; encrypt+sign it to the
   gateway's key using the test-partner's key (`compress -> sign ->
   encrypt`, armor-less); wrap it as `multipart/encrypted`
   (`app/envelope/pgp_mime.py::wrap_pgp_encrypted()`), then assemble the
   full ordered `multipart/form-data` body
   (`app/envelope/multipart_codec.py::build_multipart_body()`).
4. `POST /inbound` with HTTP Basic Auth. Confirm: HTTP 200;
   `Content-Type: multipart/signed`; the detached signature verifies with
   `gpg --verify` against the gateway's public key; the decoded
   `multipart/report` shows `request-status=ok*`, a sequential `trans-id`,
   and `time-c` in `yyyymmddhhmmss`.
5. Confirm the decrypted file landed in the filesystem sink dir and (if
   enabled) in MinIO; confirm a webhook listener received the notification
   (if enabled).
6. `psql ... -c "select * from messages;"` shows one row with
   `status=accepted` and populated `sinks_status`/`trans_id`.
7. Negative paths: resend the identical payload -> `GWX-DUPLICATE-DIGEST`
   (or `EEDM121` if the partner uses refnum); re-encrypt with
   `--cipher-algo 3DES` -> `GWX-WEAK-ALGO`; omit the inbound Basic-Auth
   header -> plain HTTP 401 with no signed body; use a 1024-bit test key ->
   startup rejects it.
8. `POST /outbound/send` -> confirm `202` + job id; confirm an
   `outbound_jobs` row appears; `GET /outbound/jobs/{id}` shows
   `queued` -> `delivered` once the worker processes it. Kill/restart the
   `worker` service mid-retry-window and confirm it resumes from DB state.
   Force the partner endpoint to fail across the full retry schedule and
   confirm `exchange_failure` plus the distinct `outbound_exchange_failure`
   log event.
9. Automated equivalent of all of the above lives in the `tests/` suite (no
   Docker needed except `test_tracking_repository.py`, integration-marked).
   Run `pytest -m "not integration"` for the fast suite and
   `pytest -m integration` for the DB-backed suite.
