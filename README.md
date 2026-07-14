# naesb-edi-gateway

A NAESB Wholesale Gas Quadrant (WGQ) Version 4.0 Internet Electronic Transport
(Internet ET) gateway: exchanges PGP-encrypted EDI transmissions with trading
partners over HTTPS. No UI -- purely an HTTP/API service, meant to sit
between internal systems and external NAESB trading partners (interstate
pipeline operators).

This implements NAESB's own transport as described in the official **NAESB
WGQ Cybersecurity Related Standards Manual, Version 4.0** (Sept 29, 2023;
see `docs/NAESB-cyber0923-2026-0709.pdf`): a `multipart/form-data` HTTP POST
carrying named envelope fields plus a PGP-encrypted payload, answered
synchronously with a `multipart/signed` "gisb-acknowledgement-receipt".

## A note on `docs/naesb4.md`

An earlier version of this project was built against `docs/naesb4.md`, a
document that turned out to be **fabricated** -- it invents a wire format,
receipt structure, and error-code scheme that don't exist in the real NAESB
standard. The entire transport layer was reworked from scratch against the
real manual. `docs/naesb4.md` is quarantined (see the warning banner at its
top) and kept only for historical reference. Do not use it.

## Spec provenance -- read before connecting a real trading partner

- **Transport**: `POST` with `Content-Type: multipart/form-data`. Envelope
  fields are ordered multipart form fields, not HTTP headers: `from`, `to`,
  `version`, `receipt-disposition-to`, `receipt-report-type`
  (`gisb-acknowledgement-receipt`), `input-format` (`X12` -- this gateway
  scopes to X12 only, see below), `input-data` (the file),
  `receipt-security-selection`, then optional `transaction-set` / `refnum` /
  `refnum-orig`.
- **Payload**: the PGP-encrypted message lives inside `input-data`, itself
  wrapped in a `multipart/encrypted` MIME structure (RFC 1847/3156):
  an `application/pgp-encrypted` control part ("Version: 1") plus the raw
  (armor-less) OpenPGP message as `application/octet-stream`.
  `app/envelope/pgp_mime.py` builds/parses this.
- **Crypto**: OpenPGP, RSA keys >= 2048 bits (4096 recommended) -- this part
  *is* a real NAESB requirement (Appendix A). The specific symmetric cipher
  and digest (`AES256`/`SHA256` by default) are this gateway's own local
  security policy, not a NAESB mandate (standard 12.3.26 explicitly
  disclaims setting site-level crypto-algorithm standards beyond the RSA key
  length).
- **Authentication**: HTTP Basic Authentication over TLS is a real NAESB
  requirement (standards 12.3.14/12.3.28/12.3.29) -- `type: basic` in
  `partners.yaml` is the spec-compliant default. `type: api_key` (Bearer
  token) is a gateway-only convenience extension with no basis in the
  standard.
- **Receipt** (`gisb-acknowledgement-receipt`): the HTTP 200 response is
  `multipart/signed` (a detached PGP signature over a `multipart/report`
  part), containing `time-c`/`request-status`/`server-id`/`trans-id` as
  `key=value*`-delimited lines (not JSON, not `key: value` text).
  `request-status` is literally `ok` on success, or `EEDM###: description` /
  `WEDM###: description` on error/warning. `app/envelope/receipt.py` builds
  and parses this.
- **Error codes**: real, spec-documented `EEDM###`/`WEDM###` codes (see
  `app/envelope/error_codes.py::NaesbErrorCode`) for the failure modes the
  standard actually defines (missing/invalid envelope fields, decryption
  failures, unknown partner, duplicate refnum, ...). This gateway adds a
  handful of `GWX-...`-prefixed extension codes for guarantees the standard
  doesn't cover (content-digest dedup when a partner doesn't use refnum,
  local weak-algorithm policy, sink delivery failure) -- these are
  explicitly **not** NAESB-assigned codes and are namespaced so they can
  never collide with a real `EEDM###`/`WEDM###`.
- **Retries / Exchange Failure**: standards 12.3.10/12.3.11 require 3
  delivery attempts spread over a 30-120 minute window before declaring an
  "Exchange Failure" to the partner. Outbound delivery is therefore a
  DB-backed job queue (`outbound_jobs` table + `app/worker.py`, a separate
  process) rather than a blocking HTTP call -- see "Outbound delivery" below.
- **`version` and `transaction-set` have no safe guessed defaults.**
  `version` is the NAESB Internet ET *protocol* version (a small decimal
  like `1.9`, historically -- not this manual's "4.0" revision number) and
  is a required config field with no default; confirm the correct value per
  Trading Partner Agreement. `transaction-set` is documented as an "8
  character code" but the real WGQ code table wasn't available when this was
  built -- it's treated as an opaque, length-8-validated string. Both need
  real values confirmed with each partner before going live.
- **Scope**: this gateway only implements the automated, HTTP/API "Batch
  Browser" path. It does not implement the separate "Internet Flat File
  EDM" / Interactive Browser HTML-upload mechanism (Appendix B/C), and it
  decrypts synchronously before sending the receipt (a valid spec choice),
  so it does not implement the asynchronous "Error Notification" flow for
  post-receipt decryption errors.

**Before onboarding a real trading partner**, confirm all of the above
against your actual Trading Partner Agreement (TPA) and the licensed NAESB
WGQ Cybersecurity Related Standards manual.

## Architecture

- **FastAPI** inbound HTTP server (`app/inbound/routes.py`) + **httpx**
  outbound client (`app/outbound/client.py`, single delivery attempt per
  call).
- **`app/worker.py`**: a separate process that polls the `outbound_jobs`
  table for due delivery attempts and executes them, rescheduling per
  `outbound.retry_schedule_seconds` or declaring an `exchange_failure` once
  that schedule is exhausted. Run it alongside the main app (see
  `docker-compose.yml`'s `worker` service) -- `POST /outbound/send` only
  enqueues a job and returns `202`; it never blocks on delivery.
- **python-gnupg** (wraps system `gpg`) for all OpenPGP operations
  (`app/crypto/`), including detached-signature support for the receipt.
- MIME construction/parsing is hand-rolled (`app/envelope/mime_split.py`,
  `pgp_mime.py`, `multipart_codec.py`, `receipt.py`) for byte-exact control
  over what gets PGP-signed/verified, rather than relying on re-serializing
  through Python's `email` package. Parsing the untrusted outer
  `multipart/form-data` envelope on inbound requests uses Starlette's
  `request.form()` (backed by `python-multipart`) instead.
- Config is split like OpenAS2's `config.xml`/`partnerships.xml`, as YAML:
  `config/config.yaml` (global identity, crypto, envelope, server, sinks,
  DB, logging, outbound retry schedule) and `config/partners.yaml`
  (per-partner endpoint, keys, auth, envelope overrides).
- Inbound delivery fans out to any combination of: local filesystem, an
  S3-compatible bucket (AWS/MinIO/Wasabi), and a webhook. Filesystem and S3
  are "durable" by default; at least one durable sink must succeed for the
  transmission to be acknowledged. Both are keyed by the sending partner's
  DUNS (`{base_dir|prefix}/{duns}/{timestamp}_{digest[:16]}_{transaction_set}.edi`).
- Every inbound and outbound transmission is tracked in Postgres (`messages`
  table) in addition to structured JSON logs; outbound jobs get their own
  `outbound_jobs` table for retry-schedule state.
- Dedup/idempotency: primarily by `(partner, refnum)` for partners
  configured with `use_refnum: true` (the spec's own tracking mechanism);
  otherwise by a SHA-256 digest of the extracted (decrypted-ciphertext-level)
  payload bytes.

## Setup

1. Copy the example config files and fill in your identity, endpoints, and
   key paths:
   ```
   cp config/config.example.yaml config/config.yaml
   cp config/partners.example.yaml config/partners.yaml
   cp config/.env.example config/.env
   ```
2. Generate your own OpenPGP keypair (RSA, 4096-bit recommended, 2048-bit
   minimum):
   ```
   gpg --homedir <gnupg_home> --full-generate-key
   gpg --homedir <gnupg_home> --armor --export-secret-keys <your-key-id> > private_key.asc
   gpg --homedir <gnupg_home> --armor --export <your-key-id> > public_key.asc
   ```
   Point `crypto.private_key_path` at `private_key.asc` and set the
   `crypto.passphrase_env` environment variable. Send `public_key.asc` to
   each trading partner; import each partner's public key file and
   reference its path from `partners.yaml`.
3. Fill in `config/.env` with real values for every `*_env` field referenced
   in `config.yaml`/`partners.yaml` (GPG passphrase, database URL, S3
   credentials, per-partner auth secrets). `config/.env` is gitignored and
   is loaded automatically by `docker-compose.yml`; outside Docker,
   `source`/export it yourself before starting the app or worker.
4. Provision a Postgres database; migrations in `db/migrations/` are applied
   automatically on startup by both the app and the worker.
5. Set `envelope.server_id` (this gateway's `server-id` receipt field) and
   `envelope.default_version` (the NAESB Internet ET protocol version --
   confirm the correct value with your Trading Partner Agreement; there is
   no safe guessed default).

## Running locally

```
docker-compose up --build
```

This starts the app, the outbound worker, a local Postgres, and a MinIO
instance (for testing the S3 sink). Both `app` and `worker` expect
`config/config.yaml` and `config/partners.yaml` to exist (step 1 above) --
they're mounted read-only into the containers.

Without Docker:
```
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
set -a && source config/.env && set +a
export NAESB_CONFIG_PATH=config/config.yaml
uvicorn app.main:app --reload &
python -m app.worker &
```

## API

- `POST {server.inbound_path}` (default `/inbound`) -- receives a
  transmission from a trading partner. Returns a `multipart/signed`
  `gisb-acknowledgement-receipt` (HTTP 200 in all cases past transport-level
  auth; the signed `request-status` -- `ok` or `EEDM###`/`WEDM###` -- is the
  actual accept/reject signal).
- `POST /outbound/send` -- enqueues an outbound transmission and returns
  `202` immediately with a job id; delivery (including retries spanning the
  Exchange Failure window) happens asynchronously via the worker. Body:
  `{"partner_name": ..., "input_format": "X12", "transaction_set": "...",
  "refnum": "...", "payload_base64": "..."}`.
- `GET /outbound/jobs/{job_id}` -- polls an outbound job's status
  (`queued` / `in_progress` / `delivered` / `failed_nack` /
  `exchange_failure`), attempt count, and receipt details once delivered.
- `GET /api/partners` -- lists configured trading partners (`name`, `duns`,
  `endpoint_url`, `has_envelope_overrides`); never returns auth credentials
  or key paths. Protected by HTTP Basic auth against
  `internal_api.username_env`/`password_env` in `config.yaml`.
- `GET /healthz`, `GET /readyz`.

## Testing

```
pytest -m "not integration"    # fast suite -- no Docker required
pytest -m integration          # Postgres-backed tracking tests, requires Docker (testcontainers)
```

The fast suite generates ephemeral RSA-2048 test keypairs (module-scoped,
not committed) and exercises the full pipeline -- multipart envelope
build/parse, nested `multipart/encrypted` payload wrapping, the
compress/sign/encrypt and detached-sign/verify crypto pipeline, receipt
MIME construction/parsing, the complete inbound HTTP flow (auth through
sink delivery), the outbound single-attempt client, and the worker's
retry/Exchange-Failure scheduling logic -- against a real `gpg` binary;
nothing is mocked at the crypto or MIME layer.

## Operational prerequisites

- **Allowed TCP ports**: NAESB Appendix C restricts Internet ET to a
  specific TCP port list (443, 5713, 6112, 6304, 6874, 7403, or a mutually
  agreed alternate). This app doesn't enforce this itself -- whatever
  reverse proxy terminates TLS in front of it must be reachable on one of
  those ports (or a mutually agreed one).
- **Static egress IP**: interstate pipelines typically require outbound
  connections from a fixed, whitelisted IP, not an elastic cloud IP range.
  Set `server.outbound_source_address` in `config.yaml` if your
  infrastructure needs to bind egress to a specific address.
- **Trading Partner Worksheet (TPW)**: before certification testing with a
  real pipeline partner, expect to complete a bilateral document exchanging
  endpoint URLs, DUNS numbers, PGP public keys, the Internet ET protocol
  `version`, transaction-set codes, and whether refnum/refnum-orig tracking
  is in use.
- **Clock synchronization**: standard 12.3.7 requires +/- 5 second
  synchronization with an atomic clock (NIST/USNO); make sure NTP is
  running wherever this app and worker are deployed.
- **TLS**: this service does not terminate inbound TLS itself -- put it
  behind a reverse proxy that enforces TLS 1.2+. Outbound connections
  (`app/outbound/client.py`) enforce a minimum TLS version themselves
  (`crypto.tls_min_version`, default 1.2).
