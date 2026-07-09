# naesb-edi

A NAESB Wholesale Gas Quadrant (WGQ) Version 4.0 Internet Electronic Transport (Internet ET) gateway: exchanges PGP-encrypted EDI transmissions with trading partners over HTTPS. No UI -- purely an HTTP/API service, meant to sit between internal systems and external NAESB trading partners (interstate pipeline operators).

This replaces an AS2-based gateway (AS2 is not what NAESB 4.0 uses) with a purpose-built implementation of NAESB's own transport: custom lowercase HTTP headers carry the transaction metadata, and the HTTP body is a compressed, signed, and encrypted OpenPGP message. See [`PLAN.md`](PLAN.md) for the full design rationale.

## Spec provenance -- read before connecting a real trading partner

The official NAESB WGQ Internet ET v4.0 technical manual is copyright/DRM-gated and was not available during development. This implementation is built from `naesb4.md` (a technical implementation guide provided during development, itself incomplete -- it cuts off mid-sentence in its final section). The wire-format specifics that came from that document:

- Lowercase literal HTTP headers: `version`, `from-id`, `to-id`, `input-format`, `transaction-set`.
- `Content-Type: application/octet-stream`, armor-less binary OpenPGP body.
- Crypto pipeline: compress (ZIP) -> sign (SHA-256) -> encrypt (AES-256), RSA keys >= 2048 bits (4096 recommended).
- Synchronous response: an OpenPGP-signed, line-delimited `key: value` text body (`receipt-status`, `receipt-timestamp`, `error-code`, `error-description`).
- Error codes 101-103 are as documented; 104-108 are gateway-specific extensions (see `app/envelope/receipt.py`) since the source document only gave three examples, not an exhaustive list.

**Before onboarding a real trading partner**, confirm all of the above against your actual Trading Partner Agreement (TPA) or a licensed copy of the NAESB WGQ Internet Electronic Transport / Cybersecurity Related Standards manual. Header *names* don't require a code change to fix -- see `envelope.header_mapping` in `config.yaml` and `envelope_overrides` per partner in `partners.yaml`.

## Architecture

- **FastAPI** inbound HTTP server (`app/inbound/routes.py`) + **httpx** outbound client (`app/outbound/client.py`).
- **python-gnupg** (wraps system `gpg`) for all OpenPGP operations (`app/crypto/`).
- Config is split like OpenAS2's `config.xml`/`partnerships.xml`, as YAML: `config/config.yaml` (global identity, crypto, server, sinks, DB, logging) and `config/partners.yaml` (per-partner endpoint, keys, auth, envelope overrides).
- Inbound delivery fans out to any combination of: local filesystem, an S3-compatible bucket (AWS/MinIO/Wasabi), and a webhook. Filesystem and S3 are "durable" by default; at least one durable sink must succeed for the transmission to be acknowledged.
- Every inbound and outbound transmission is tracked in Postgres (`messages` table) in addition to structured JSON logs.
- Dedup/idempotency keys off a SHA-256 digest of the raw (encrypted) request body -- the transport defines no message-id header.

## Setup

1. Copy the example config files and fill in your identity, endpoints, and key paths:
   ```
   cp config/config.example.yaml config/config.yaml
   cp config/partners.example.yaml config/partners.yaml
   ```
2. Generate your own OpenPGP keypair (RSA, 4096-bit recommended, 2048-bit minimum):
   ```
   gpg --homedir <gnupg_home> --full-generate-key
   gpg --homedir <gnupg_home> --armor --export-secret-keys <your-key-id> > private_key.asc
   gpg --homedir <gnupg_home> --armor --export <your-key-id> > public_key.asc
   ```
   Point `crypto.private_key_path` at `private_key.asc` and set the `crypto.passphrase_env` environment variable. Send `public_key.asc` to each trading partner; import each partner's public key file and reference its path from `partners.yaml`.
3. Set the environment variables referenced by `config.yaml`/`partners.yaml` (`*_env` fields): GPG passphrase, database URL, S3 credentials, per-partner auth secrets.
4. Provision a Postgres database; migrations in `db/migrations/` are applied automatically on startup.

## Running locally

```
docker-compose up --build
```

This starts the app, a local Postgres, and a MinIO instance (for testing the S3 sink). The app expects `config/config.yaml` and `config/partners.yaml` to exist (step 1 above) -- they're mounted read-only into the container.

Without Docker:
```
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
export NAESB_CONFIG_PATH=config/config.yaml
uvicorn app.main:app --reload
```

## API

- `POST {server.inbound_path}` (default `/inbound`) -- receives a transmission from a trading partner. Returns an OpenPGP-signed receipt body (HTTP 200 in all cases past transport-level auth; the signed `receipt-status`/`error-code` is the actual accept/reject signal).
- `POST /outbound/send` -- internal trigger to send a transmission to a partner. Body: `{"partner_name": ..., "input_format": "X12"|"XML"|"FLATFILE", "transaction_set": "873", "payload_base64": "..."}`.
- `GET /healthz`, `GET /readyz`.

## Testing

```
pytest                    # fast suite -- no Docker required
pytest -m integration     # Postgres-backed tracking tests, requires Docker (testcontainers)
```

The fast suite generates ephemeral RSA-2048 test keypairs (module-scoped, not committed) and exercises the full crypto pipeline, envelope parsing, receipt signing, all sinks, and the complete inbound/outbound request flow against a real `gpg` binary -- nothing is mocked at the crypto layer.

## Operational prerequisites

- **Static egress IP**: interstate pipelines typically require outbound connections from a fixed, whitelisted IP, not an elastic cloud IP range. Set `server.outbound_source_address` in `config.yaml` if your infrastructure needs to bind egress to a specific address.
- **Technical Exchange Worksheet (TEW)**: before certification testing with a real pipeline partner, expect to complete a bilateral document exchanging endpoint URLs, DUNS numbers, and PGP public keys.
- **TLS**: this service does not terminate inbound TLS itself -- put it behind a reverse proxy that enforces TLS 1.2+. Outbound connections (`app/outbound/client.py`) enforce a minimum TLS version themselves (`crypto.tls_min_version`, default 1.2).
