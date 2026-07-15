# Partner authentication

How this gateway authenticates HTTP transport for each trading partner --
two independent credential sets per partner, one per direction. Not to be
confused with PGP keys (message-level encryption/signing), which are a
separate mechanism -- see the last section.

## Inbound: partner -> us

Credentials **we issue to the partner** so they can authenticate when they
`POST` to our `/inbound` endpoint.

- Configured per partner in `partners.yaml`'s `inbound_auth`.
- Checked in `app/inbound/auth.py::authenticate_inbound()` against the raw
  `Authorization` header -- before any GPG/parsing work, so an
  unauthenticated caller can't make us spend CPU decrypting garbage. No
  match -> plain `HTTP 401`.
- Two schemes (`app/partners.py`):
  - `type: basic` -- HTTP Basic (`username` + `password_env`). The
    NAESB-spec-compliant default (standards 12.3.14/12.3.28/12.3.29).
  - `type: api_key` -- Bearer token (`key_env`). A gateway-only convenience
    extension with no basis in the spec; prefer Basic unless a partner
    specifically requires it.

## Outbound: us -> partner

Credentials **the partner issues to us** so we can authenticate when we
`POST` to their endpoint.

- Configured per partner in `partners.yaml`'s `outbound_auth`, same
  `type: basic`/`type: api_key` shape as inbound.
- Used in `app/outbound/client.py::_auth_header()` to build the
  `Authorization` header on every `send_once()` delivery attempt.

## Where the actual secret values live

`partners.yaml` **never stores a literal password or API key** -- only a
`username` (Basic) and an *environment variable name*
(`password_env`/`key_env`). The real secret value must exist in the process
environment at runtime:

- `app/settings.py::resolve_env()` reads it via `os.environ`, raising
  `MissingEnvVarError` if it's unset. Resolution happens on every use (a
  `@property`), not cached at config-load time.
- In Docker Compose, that environment is populated by `config/.env`
  (`env_file:` on both the `app` and `worker` services).
- `config/.env`, `config/partners.yaml`, and `config/config.yaml` are all
  gitignored -- only the `.example.yaml` templates are committed. No
  credential, ours or a partner's, ever enters git.

## Example (`partners.yaml`, real file -- not committed)

```yaml
partners:
  - name: acme-pipeline
    duns: "987654321"
    endpoint_url: "https://secure-transport.acme-pipeline.example.com/edi/receiver-endpoint"
    outbound_auth:
      type: basic
      username: myuid                      # they gave us this
      password_env: NAESB_ACME_PASSWORD     # ...and this, via config/.env
    inbound_auth:
      type: api_key
      key_env: NAESB_ACME_INBOUND_KEY       # we generated this, gave it to them
```

## Not covered here: PGP keys

Message-level encryption/signing uses a completely separate mechanism: our
private key plus every partner's public key are imported into a GnuPG
keyring volume at startup (`app/crypto/keyring.py`), referenced per partner
by `pgp_public_key_path` in `partners.yaml`. That's what proves *who sent
the payload*; the credentials above only govern *who's allowed to open an
HTTP connection to us* (or us to them).
