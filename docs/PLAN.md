# NAESB WGQ 4.0 Internet ET EDI Gateway

## Context

The existing EDI setup is a fork of OpenAS2, which only speaks AS2. NAESB 4.0 (Wholesale Gas Quadrant Business Practice Standards) does not use AS2 — it uses NAESB's own **Internet Electronic Transport (Internet ET)** protocol: PGP-encrypted payloads exchanged over HTTP(S), where each trading partner supplies the other with their PGP public key. This new project (`naesb-edi`) replaces/supplements the AS2 gateway with a purpose-built Internet ET gateway. No UI — purely an HTTP/API service, intended to sit between internal systems and external NAESB trading partners (interstate pipeline operators).

**Spec provenance note:** the official NAESB WGQ Internet ET v4.0 manual is copyright/DRM-gated and not publicly fetchable — confirmed by reading the FERC filing summary PDF (describes *what changed* in v4.0, no wire-format detail) and public secondary sources (ERCOT/TIBCO), which only cover the older, wrong-quadrant (retail electric) v1.6 multipart baseline you've rejected. You provided `naesb4.md`, a technical implementation guide with concrete wire-format detail (headers, crypto pipeline, response format, error codes, X12 transaction sets) that this plan now builds to directly. That document itself still cuts off mid-sentence in its final section (Technical Exchange Worksheet/network topology) — everything before that point is complete and is what this plan uses. As before, the exact header names remain in one small config-driven mapping (not hardcoded) so they can still be corrected in minutes against your actual Trading Partner Agreements if any partner deviates.

## Architecture Overview

Python 3.12, FastAPI (inbound HTTP server) + httpx (outbound client), Pydantic v2 for all config/schema validation, `python-gnupg` wrapping system GnuPG for OpenPGP. Config follows OpenAS2's split (central config + partner directory), reimagined as YAML:

- `config/config.yaml` — our identity, server/crypto/db/sink defaults, retry policy, logging (equivalent of OpenAS2's `config.xml`).
- `config/partners.yaml` — one entry per trading partner: name, DUNS number, endpoint URL, PGP public key reference, inbound/outbound auth credentials, per-partner envelope overrides (equivalent of `partnerships.xml`).

### Directory tree

```
naesb-edi/
├── pyproject.toml
├── README.md
├── Dockerfile
├── docker-compose.yml            # app + postgres + minio, for local dev/manual verification only
├── .dockerignore
├── .gitignore                    # excludes config/keys, .env, real config.yaml/partners.yaml
├── config/
│   ├── config.example.yaml
│   └── partners.example.yaml
├── db/
│   └── migrations/
│       └── 0001_init.sql         # messages + schema_migrations tables
├── app/
│   ├── main.py                   # FastAPI app factory + lifespan startup (config, gpg, db, sinks)
│   ├── dependencies.py           # FastAPI Depends() providers
│   ├── settings.py               # Pydantic models + loader for config.yaml (env-var secret resolution)
│   ├── partners.py                # Pydantic models + loader for partners.yaml, override-merge logic
│   ├── logging_config.py          # structlog JSON logging, request-scoped context (partner, digest)
│   ├── errors.py                  # exception types + FastAPI exception handlers
│   ├── envelope/
│   │   ├── fields.py               # CanonicalField enum, EnvelopeFields pydantic model
│   │   ├── mapping.py              # HeaderMapping model + merge(default, partner_override)
│   │   ├── codec.py                # build_headers()/parse_headers(), EnvelopeError
│   │   └── receipt.py              # Receipt model, line-delimited encode/decode, ReasonCode enum
│   ├── crypto/
│   │   ├── gpg_wrapper.py          # encrypt_and_sign(), decrypt_and_verify(), sign_message(), verify_message()
│   │   ├── policy.py               # AlgorithmInfo, parse_status(), enforce_policy(), key-length checks
│   │   └── keyring.py              # startup import of our private key + all partner public keys, RSA length validation
│   ├── sinks/
│   │   ├── base.py                 # Sink protocol, SinkResult
│   │   ├── filesystem_sink.py
│   │   ├── s3_sink.py               # boto3, S3-compatible endpoint_url (AWS/MinIO/Wasabi)
│   │   ├── webhook_sink.py          # httpx POST, best-effort/non-durable
│   │   └── dispatcher.py            # fan_out(): concurrent, isolated failures
│   ├── tracking/
│   │   ├── models.py                 # MessageRecord
│   │   ├── db.py                     # psycopg pool + migration runner
│   │   └── repository.py              # create/update message rows, dedupe-by-digest check
│   ├── inbound/
│   │   ├── routes.py                  # POST /inbound — full receive pipeline
│   │   └── auth.py                     # per-partner inbound auth (api key / basic) before GPG work
│   ├── outbound/
│   │   └── client.py                   # send_message(): envelope, compress+sign+encrypt, POST, verify receipt, tenacity retry
│   └── api/
│       ├── send.py                     # POST /outbound/send — internal trigger for an outbound transmission
│       └── health.py                   # GET /healthz, /readyz
└── tests/
    ├── conftest.py                     # ephemeral GPG keypairs (tmp GNUPGHOME), test config/partners, TestClient
    ├── test_gpg_policy.py              # roundtrip + weak-algorithm/short-key rejection
    ├── test_envelope_codec.py
    ├── test_receipt.py                 # line-delimited encode/decode + signed-message roundtrip
    ├── test_inbound_route.py           # auth failure / bad sig / weak algo / duplicate / happy path
    ├── test_outbound_client.py         # respx-mocked partner endpoint, receipt verification
    ├── test_sinks_filesystem.py
    ├── test_sinks_s3.py                # moto, in-process, no Docker
    ├── test_tracking_repository.py     # testcontainers[postgres], marked @pytest.mark.integration
    └── test_config_loader.py
```

## Key design decisions

| Area | Decision | Why |
|---|---|---|
| Request transport | `POST`, `Content-Type: application/octet-stream`, raw (armor-less) binary OpenPGP blob as body. Metadata carried in separate, **strictly lowercase** literal HTTP headers: `version`, `from-id`, `to-id`, `input-format`, `transaction-set`. | Matches `naesb4.md` §3 exactly. Header *names* still live in one config-driven mapping (not hardcoded) so a partner-specific TPA deviation is a config change. |
| Payload crypto pipeline | Compress (ZIP/ZLIB) → sign with sender's private key (SHA-256) → encrypt to recipient's public key (AES-256) → armor-less binary, in that order, via a single `python-gnupg` `encrypt()` call with `sign=` set and explicit `extra_args`. | Matches `naesb4.md` §2's mandated sequence. |
| Key strength | RSA only; reject/refuse to load any key (ours or a partner's) under 2048 bits at startup; default key-generation guidance is 4096-bit. | Matches `naesb4.md` §2. Enforced in `keyring.py` via `gpg.list_keys()`'s `length`/`algo` fields, not just documented. |
| TLS | Outbound `httpx` client pinned to TLS 1.2 minimum; inbound TLS termination stays at a reverse proxy (documented requirement: proxy must reject TLS < 1.2). | Matches `naesb4.md` §3. The app itself doesn't terminate TLS (consistent with "keep it simple" — that's infra's job either way). |
| Response/receipt format | The HTTP 200 response body is **line-delimited `key: value` text** (`receipt-status`, `receipt-timestamp`, `error-code`, `error-description`), and that whole body **is itself an OpenPGP-signed message** (`gpg --sign`, not `--clearsign`, to avoid ASCII clearsign's dash-escaping/line-ending fragility) using our private key. No JSON, no separate signature header. | Matches `naesb4.md` §4 directly — this supersedes my earlier draft's JSON+detached-signature-header design. |
| Error codes | Adopt `naesb4.md`'s documented codes (101 decryption failed, 102 signature verification failed, 103 invalid header parameters) as the base `error-code` enum; extend upward (104 unknown partner, 105 duplicate message, 106 weak algorithm/short key, 107 sink failure, 108 invalid transaction-set) since the doc's list is explicitly "e.g." and not exhaustive. Document the extension range as gateway-specific, not officially NAESB-assigned. | The doc gives 3 example codes for a protocol that clearly needs more failure modes than that; we need codes for our own extra guarantees (dedup, sinks, key policy) without colliding with the documented ones. |
| Dedup / idempotency key | **No message-id header exists in this transport spec** — dedupe inbound transmissions on a SHA-256 digest of the raw encrypted request body per `(partner, digest)`, not an invented message-id. | `naesb4.md`'s mandated header set has no message/transaction identifier at all (X12 interchange control numbers, if needed, live *inside* the encrypted payload, which this gateway treats as an opaque blob). Content-digest dedup is protocol-agnostic and doesn't require inventing a field the spec doesn't define. |
| Transaction-set metadata | `transaction-set` header (3-digit X12 code) is passed through as opaque metadata the internal caller supplies on outbound send and that we record/log on inbound — not interpreted. Known WGQ-relevant codes documented for reference: 873 (Nomination), 861 (Scheduled Quantity), 811 (Consolidated Invoice), 824 (Application Advice). | Matches `naesb4.md` §5. Gateway stays transport-only; X12 content interpretation is a downstream concern. |
| Sinks | Filesystem, S3-compatible, webhook — independently configurable, each tagged `durable: bool` (fs/S3 default true, webhook default false). ACK requires ≥1 durable sink success (configurable), never depends on webhook success. | Prevents ACKing content we didn't actually retain anywhere, and prevents a flaky webhook from causing spurious rejections against a partner who delivered valid data. |
| Message tracking | Postgres, modeled as a cross-cutting concern updated at each pipeline checkpoint, *not* a fourth "sink." | It's an audit trail over the whole lifecycle (including auth/crypto/dedupe failures that never reach the sink stage), not "deliver a copy of the file." |
| Inbound auth | Per-partner shared API key or Basic auth, checked *before* any GPG decryption work — fails closed with a plain (non-signed) HTTP 401. | Cheap rejection of unauthenticated traffic before spending CPU on GPG; this is a transport-level concern the spec doesn't cover, layered on top. |
| DB migrations | Numbered idempotent SQL files (`0001_init.sql`, ...) + a small custom runner tracking applied filenames in `schema_migrations`. Not Alembic, not a single `schema.sql`. | A single `schema.sql` can't express a later `ALTER TABLE` idempotently; Alembic's autogeneration/branching is unneeded for 1-2 tables. |
| Outbound retry | `tenacity`; same encrypted payload/digest reused across retry attempts so partner-side dedup (if any) still works. | Small, well-tested dependency; matches "keep it simple." |
| Message size | `server.max_body_size_bytes` cap enforced before buffering into memory. | Basic DoS protection on an internet-facing endpoint that must fully buffer the body to run GPG. |
| PGP library | `python-gnupg` wrapping system GnuPG — needs `gnupg` apt-installed in the Dockerfile. | Your choice; maximum interop compatibility with whatever PGP tool partners run. |
| Static egress IP / TEW | Not code — documented as an operational prerequisite in the README (interstate pipelines require a fixed, whitelisted outbound IP and a bilateral Technical Exchange Worksheet before certification testing). Optional config knob to bind the outbound `httpx` client to a specific local source address if your infra needs it. | Matches `naesb4.md` §6. This is infrastructure/onboarding process, not something the app can solve internally. |

## Config schema (illustrative)

`config/config.example.yaml`:
```yaml
identity:
  name: "MyCompany"
  duns: "123456789"
server:
  host: 0.0.0.0
  port: 8000
  inbound_path: /inbound
  max_body_size_bytes: 26214400
  outbound_source_address: null   # optional: bind egress to a specific static IP
crypto:
  private_key_path: /data/gnupg/private_key.asc
  passphrase_env: NAESB_GPG_PASSPHRASE
  min_rsa_key_bits: 2048
  recommended_rsa_key_bits: 4096
  cipher_algo: AES256
  digest_algo: SHA256
  compress_algo: ZIP
  tls_min_version: "1.2"
envelope:
  header_mapping:
    version: version
    from_id: from-id
    to_id: to-id
    input_format: input-format
    transaction_set: transaction-set
  default_version: "4.0"
sinks:
  require_at_least_one_durable_success: true
  filesystem:
    enabled: true
    durable: true
    base_dir: /data/inbound
  s3:
    enabled: false
    durable: true
    endpoint_url: null          # set for MinIO/Wasabi; omit for AWS
    bucket: naesb-inbound
    access_key_env: NAESB_S3_ACCESS_KEY
    secret_key_env: NAESB_S3_SECRET_KEY
  webhook:
    enabled: false
    durable: false
    url: null
database:
  url_env: NAESB_DATABASE_URL
outbound:
  timeout_seconds: 30
  retry_max_attempts: 3
  retry_backoff_seconds: 5
logging:
  level: INFO
  format: json
partners_file: /app/config/partners.yaml
```

`config/partners.example.yaml`:
```yaml
partners:
  - name: acme-pipeline
    duns: "987654321"
    endpoint_url: "https://secure-transport.acme-pipeline.example.com/edi/receiver-endpoint"
    pgp_public_key_path: /data/gnupg/partners/acme-pipeline.pub.asc
    outbound_auth:
      type: basic
      username: myuid
      password_env: NAESB_ACME_PASSWORD
    inbound_auth:
      type: api_key
      key_env: NAESB_ACME_INBOUND_KEY
    envelope_overrides:
      header_mapping:
        transaction_set: x-transaction-set   # example of a partner-specific TPA deviation
```

## Request/response wire format

**Outbound request** (built by `app/outbound/client.py`, parsed on the receiving end by `app/inbound/routes.py`):
```
POST {endpoint_url} HTTP/1.1
Content-Type: application/octet-stream
version: 4.0
from-id: 123456789
to-id: 987654321
input-format: X12
transaction-set: 873

<raw binary: ZIP-compressed, SHA-256-signed, AES-256-encrypted OpenPGP blob, no armor>
```

**Synchronous response** — HTTP 200 body is a single OpenPGP-signed message (via `app/crypto/gpg_wrapper.sign_message()`, using `gpg --sign` not `--clearsign`) whose inner plaintext is line-delimited key/value text:
```
receipt-status: success
receipt-timestamp: 2026-07-08T19:30:00Z
error-code:
error-description:
```
or, on rejection:
```
receipt-status: validation-failed
receipt-timestamp: 2026-07-08T19:30:05Z
error-code: 102
error-description: Signature Verification Failed
```

## Signed synchronous receipt flow

Inbound pipeline (`app/inbound/routes.py`) — every path past transport-level auth returns **HTTP 200** with a signed line-delimited receipt body; `receipt-status`/`error-code` is the actual protocol-level ACK/NACK:
1. Enforce `max_body_size_bytes`; per-partner inbound auth check — fail closed with a plain (unsigned) HTTP 401, no GPG work done.
2. `parse_headers()` → `EnvelopeFields` (`version`, `from-id`, `to-id`, `input-format`, `transaction-set`); malformed/missing → `error-code: 103`.
3. Look up partner by `from-id`; unknown → `error-code: 104`.
4. Compute SHA-256 digest of the raw request body; dedupe check (`partner`, `digest`, `inbound`) in Postgres; duplicate → `error-code: 105`, skip reprocessing.
5. `decrypt_and_verify()` — decryption failure → `error-code: 101`; signature verification failure → `error-code: 102`.
6. `enforce_policy()` on parsed algorithm info + partner key length; violation → `error-code: 106`.
7. Sink fan-out; if zero durable sinks succeed → `error-code: 107`.
8. Track every step in Postgres (keyed on the content digest).
9. Build the line-delimited receipt text, `sign_message()` it with our private key, return as the HTTP 200 body.

Outbound client (`app/outbound/client.py`) mirrors this: builds headers, `compress→sign→encrypt`, POSTs, captures the raw response body, `verify_message()` against the partner's public key *before* trusting `receipt-status`. Unverifiable/missing signature → treated as no receipt received (retried per `tenacity` policy). Verified `validation-failed` → marked failed; only retried automatically for codes that suggest a transient/our-side issue (e.g. none currently — 101-108 are all deterministic failures), otherwise surfaced for manual attention.

## Modern-OpenPGP and key-strength enforcement

On encrypt: `gpg.encrypt(data, recipients=[partner_key], sign=our_key, extra_args=["--compress-algo","ZIP","--cipher-algo","AES256","--digest-algo","SHA256","--s2k-digest-algo","SHA256","--personal-cipher-preferences","AES256","--personal-digest-preferences","SHA256"])`, plus harden the managed `GNUPGHOME`'s `gpg.conf` (`disable-cipher-algo 3DES/CAST5/IDEA`, `weak-digest SHA1`, `cert-digest-algo SHA256`) as a second line of defense.

On decrypt: `python-gnupg` doesn't expose the negotiated algorithm as a named attribute — parse it from GnuPG's status-fd lines in `result.stderr`: `DECRYPTION_INFO <mdc_method> <sym_algo>` for the cipher, `VALIDSIG ... <pubkey_algo> <hash_algo> ...` for the signature digest. `test_gpg_policy.py` must assert this against a real ephemeral-keypair roundtrip (not a hardcoded string) so GnuPG version drift fails loudly in CI rather than silently accepting weak crypto.

On startup (`keyring.py`): import our private key and every partner's public key into the managed keyring, then call `gpg.list_keys()` and reject startup if our key or any partner key reports `algo` outside RSA or `length` < `crypto.min_rsa_key_bits` (default 2048), logging a warning if below `recommended_rsa_key_bits` (4096).

## Database

`db/migrations/0001_init.sql` creates `schema_migrations` (tracks applied filenames) and `messages`: `id`, `direction`, `partner_name`, `content_digest`, `transaction_set`, `input_format`, `status`, `error_code`, `receipt_verified`, `sinks_status jsonb`, `raw_headers jsonb`, timestamps, `UNIQUE(partner_name, content_digest, direction)`. `app/tracking/db.py` applies un-applied migration files in filename order at startup.

## Testing strategy

- `test_gpg_policy.py`: compress→sign→encrypt/decrypt→verify roundtrip using ephemeral keypairs generated per-test into a `tmp_path` `GNUPGHOME`; explicit weak-cipher, weak-digest, and short-RSA-key rejection cases.
- `test_envelope_codec.py`: header build/parse against the literal lowercase names, including a partner override case.
- `test_receipt.py`: line-delimited encode/decode round trip, plus the signed-message wrap/verify.
- `test_inbound_route.py`: FastAPI `TestClient` — auth failure (401, unsigned), bad signature (102), decryption failure (101), unknown partner (104), duplicate digest (105), weak algorithm (106), sink failure (107), happy path (success) with all sinks mocked.
- `test_outbound_client.py`: `respx`-mocked partner endpoint, asserts request header/body shape and receipt-signature verification logic.
- `test_sinks_filesystem.py`: real temp dir.
- `test_sinks_s3.py`: `moto` (`@mock_aws`), in-process, no Docker.
- `test_tracking_repository.py`: `testcontainers[postgres]`, marked `@pytest.mark.integration` so the default fast `pytest` run skips it; run as a separate step when Docker is available.
- `test_config_loader.py`: valid/invalid config and partner files, env-var secret resolution, override-merge behavior.

## Docker

Single `Dockerfile`: `python:3.12-slim`, `apt-get install gnupg ca-certificates`, non-root user, `pip install .`, `uvicorn app.main:app`. `docker-compose.yml` adds Postgres and MinIO for local dev/manual verification only — CI tests don't depend on compose being up (moto + testcontainers are self-contained).

## Verification (end-to-end, manual)

1. `docker-compose up --build`; `GET /healthz` → 200.
2. Generate two ephemeral RSA-4096 GPG keypairs locally ("gateway" = us, "test-partner"); export public keys; import gateway's private key into the running container's `GNUPGHOME` volume out-of-band (never baked into the image or committed); reference `test-partner`'s public key from `partners.yaml`.
3. Build a sample X12 873 nomination file; run it through `compress (ZIP) → sign (SHA-256) → encrypt (AES-256)` to the gateway's public key using the test-partner's key, armor-less.
4. `curl -X POST http://localhost:8000/inbound -H "version: 4.0" -H "from-id: <test-partner DUNS>" -H "to-id: <our DUNS>" -H "input-format: X12" -H "transaction-set: 873" --data-binary @payload.pgp`. Confirm: HTTP 200; body verifies with `gpg --verify` against the gateway's public key; decrypted inner text shows `receipt-status: success`.
5. Confirm the decrypted file landed in the filesystem sink dir and (if enabled) in MinIO; confirm a webhook listener received the notification (if enabled).
6. `psql ... -c "select * from messages;"` shows one row with `status=success` and populated `sinks_status`.
7. Negative paths: resend the identical payload → `error-code: 105`; re-encrypt with `--cipher-algo 3DES` → `error-code: 106`; omit the inbound API key → plain HTTP 401 with no signed body; use a 1024-bit test key → startup rejects it / runtime returns `error-code: 106`.
8. Automated equivalent of all of the above lives in `tests/test_inbound_route.py` (no Docker needed) plus `tests/test_tracking_repository.py` (Docker/testcontainers, integration-marked). Run `pytest` for the fast suite and `pytest -m integration` for the DB-backed suite.
