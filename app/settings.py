import os
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

import yaml
from pydantic import BaseModel, Field, field_validator

from app.crypto.policy import CIPHER_ALGO_IDS, DIGEST_ALGO_IDS
from app.duns import normalize_duns


class MissingEnvVarError(RuntimeError):
    def __init__(self, var_name: str):
        super().__init__(f"required environment variable {var_name!r} is not set")
        self.var_name = var_name


def resolve_env(var_name: str) -> str:
    value = os.environ.get(var_name)
    if value is None:
        raise MissingEnvVarError(var_name)
    return value


def check_known_algo_names(names: list[str], known_ids: dict[str, int], field_name: str) -> None:
    """Fail fast at config-load time rather than raising a bare KeyError the
    first time a real inbound message hits app/crypto/policy.py::enforce_policy()."""
    unknown = [name for name in names if name not in known_ids]
    if unknown:
        raise ValueError(
            f"{field_name} contains unknown algorithm name(s) {unknown!r}; "
            f"known names are {sorted(known_ids)}"
        )


class IdentityConfig(BaseModel):
    name: str
    duns: str

    @field_validator("duns")
    @classmethod
    def _normalize_duns(cls, value: str) -> str:
        return normalize_duns(value)


class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    # WGQ Cybersecurity Related Standards v4.0, Appendix C restricts Internet
    # ET to a specific list of allowed TCP ports (HTTPS 443, 5713, 6112,
    # 6304, 6874, 7403; or a mutually agreed alternate). This is a reverse
    # proxy / network-layer concern this app doesn't enforce itself -- ensure
    # whatever port the app is actually reached on (after TLS termination)
    # is one of the allowed ports or has been mutually agreed with the
    # partner via the TPW.
    port: int = 8000
    inbound_path: str = "/inbound"
    max_body_size_bytes: int = 26_214_400
    outbound_source_address: str | None = None


class CryptoConfig(BaseModel):
    private_key_path: str
    passphrase_env: str
    gnupg_home: str
    min_rsa_key_bits: int = 2048
    recommended_rsa_key_bits: int = 4096
    cipher_algo: str = "AES256"
    digest_algo: str = "SHA256"
    compress_algo: str = "ZIP"
    tls_min_version: str = "1.2"
    # Accept-list for algorithms found in *inbound* decrypted messages
    # (app/crypto/policy.py::enforce_policy(), called from
    # app/inbound/routes.py) and in partner receipt signatures
    # (app/outbound/client.py). Distinct from cipher_algo/digest_algo above,
    # which are what *this gateway* uses when it encrypts/signs -- NAESB
    # itself doesn't mandate a specific cipher/digest (standard 12.3.26), so
    # this is deliberately broader than our own outbound default to tolerate
    # real trading partners' older PGP libraries (e.g. still-common SHA1
    # signatures). A partner needing something outside this default (e.g.
    # 3DES) can opt in via that partner's `crypto_overrides` in
    # partners.yaml rather than weakening this global floor.
    allowed_ciphers: list[str] = Field(default_factory=lambda: ["AES256", "AES192", "AES128"])
    allowed_digests: list[str] = Field(
        default_factory=lambda: ["SHA256", "SHA384", "SHA512", "SHA1"]
    )

    @field_validator("allowed_ciphers")
    @classmethod
    def _validate_allowed_ciphers(cls, value: list[str]) -> list[str]:
        check_known_algo_names(value, CIPHER_ALGO_IDS, "allowed_ciphers")
        return value

    @field_validator("allowed_digests")
    @classmethod
    def _validate_allowed_digests(cls, value: list[str]) -> list[str]:
        check_known_algo_names(value, DIGEST_ALGO_IDS, "allowed_digests")
        return value

    @property
    def passphrase(self) -> str:
        return resolve_env(self.passphrase_env)


class EnvelopeConfig(BaseModel):
    # This gateway's own `server-id` receipt field: a domainname or
    # hostname.domainname, no embedded spaces (Envelope Data Dictionary).
    server_id: str
    # The NAESB Internet ET *protocol* version (data dictionary `version`
    # field, historically a small decimal like "1.9" -- NOT this manual's
    # "4.0" revision number). No safe default exists without a real Trading
    # Partner Agreement, so this is required; set per-partner via
    # `PartnerConfig.envelope_overrides.version` if a partner disagrees.
    default_version: str
    # What we request of partners in `receipt-security-selection` on
    # outbound sends. The spec's own illustrated example literally requests
    # `signed-receipt-micalg=required,md5` -- that's legacy RFC 1767/EDIINT
    # wording inherited by the data dictionary, not a live NAESB mandate to
    # actually use MD5. Kept configurable rather than hardcoded to that
    # example; default here matches this gateway's own digest policy
    # (crypto.digest_algo).
    receipt_security_selection: str = (
        "signed-receipt-protocol=required,pgp-signature;signed-receipt-micalg=required,sha256"
    )


class FilesystemSinkConfig(BaseModel):
    enabled: bool = False
    durable: bool = True
    base_dir: str = "/data/inbound"


class S3SinkConfig(BaseModel):
    enabled: bool = False
    durable: bool = True
    endpoint_url: str | None = None
    bucket: str
    prefix: str = ""
    region: str = "us-east-1"
    access_key_env: str
    secret_key_env: str

    @property
    def access_key(self) -> str:
        return resolve_env(self.access_key_env)

    @property
    def secret_key(self) -> str:
        return resolve_env(self.secret_key_env)


class WebhookSinkConfig(BaseModel):
    enabled: bool = False
    durable: bool = False
    url: str | None = None
    timeout_seconds: float = 10.0


class SinksConfig(BaseModel):
    require_at_least_one_durable_success: bool = True
    filesystem: FilesystemSinkConfig = Field(default_factory=FilesystemSinkConfig)
    s3: S3SinkConfig | None = None
    webhook: WebhookSinkConfig = Field(default_factory=WebhookSinkConfig)


class DatabaseConfig(BaseModel):
    url_env: str = "NAESB_DATABASE_URL"
    # Optional: some deployments keep the username/password out of the base
    # URL (e.g. a secrets manager rotates them independently of the
    # host/port/dbname). If set, these override whatever credentials (if any)
    # are embedded in the url_env value.
    username_env: str | None = None
    password_env: str | None = None

    @property
    def url(self) -> str:
        base_url = resolve_env(self.url_env)
        if self.username_env is None and self.password_env is None:
            return base_url
        username = resolve_env(self.username_env) if self.username_env else None
        password = resolve_env(self.password_env) if self.password_env else None
        return _with_credentials(base_url, username, password)


def _with_credentials(url: str, username: str | None, password: str | None) -> str:
    parts = urlsplit(url)
    user = username if username is not None else parts.username
    pwd = password if password is not None else parts.password

    if user and pwd:
        userinfo = f"{user}:{pwd}@"
    elif user:
        userinfo = f"{user}@"
    else:
        userinfo = ""

    host = parts.hostname or ""
    port = f":{parts.port}" if parts.port else ""
    netloc = f"{userinfo}{host}{port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


class InternalApiConfig(BaseModel):
    """Basic auth credentials protecting internal-only endpoints (e.g.
    GET /api/partners) -- distinct from any partner's inbound_auth/
    outbound_auth in partners.yaml."""

    username_env: str
    password_env: str

    @property
    def username(self) -> str:
        return resolve_env(self.username_env)

    @property
    def password(self) -> str:
        return resolve_env(self.password_env)


class OutboundConfig(BaseModel):
    timeout_seconds: float = 30.0
    # Delay, in seconds from job creation, of each delivery attempt. Length
    # of this list is the max attempt count. Standards 12.3.10/12.3.11 and
    # definition 12.2.24 require 3 attempts, with an "Exchange Failure"
    # declared to the partner if the gap between the first and last attempt
    # exceeds 30-120 minutes (FAQ Q1). Default: T+0 / +15min / +45min (45
    # minutes total, comfortably inside that band).
    retry_schedule_seconds: list[int] = Field(default_factory=lambda: [0, 900, 2700])
    # How often the worker process (app/worker.py) polls outbound_jobs for
    # due attempts.
    worker_poll_interval_seconds: float = 15.0


class PollerConfig(BaseModel):
    """Config for app/poller.py -- the file-drop outbound entry point.
    Watches `base_dir/<duns>/` for raw, unencrypted EDI files, moving each
    into that partner's `processed/` (once handed to the delivery queue) or
    `error/` (pickup failed after `max_pickup_attempts` tries) subfolder."""

    enabled: bool = False
    base_dir: str = "/data/outbound"
    # How often the poller scans base_dir for new files.
    poll_interval_seconds: float = 15.0
    # A file is only picked up once it hasn't been modified for at least
    # this long, so a writer still streaming the file to disk isn't read
    # mid-write.
    quiet_period_seconds: int = 60
    # Bounded retries for a failure *before* the file reaches outbound_jobs
    # (unreadable file, encryption failure, DB unavailable) -- mirrors the
    # "3 attempts" language already used for delivery retries
    # (outbound.retry_schedule_seconds). Exhausting these moves the file to
    # error/; this is unrelated to (and doesn't wait on) the separate
    # delivery-retry/Exchange-Failure outcome tracked in outbound_jobs.
    max_pickup_attempts: int = 3


class LoggingConfig(BaseModel):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    format: Literal["json", "console"] = "json"
    # Logs the full raw inbound HTTP request (method, path, headers with
    # Authorization redacted, and the complete body) for every call to
    # {server.inbound_path}, before any auth/parsing/decryption -- so a
    # partner's request can be inspected even if it fails before we can make
    # sense of it. Logged at INFO, so it's still subject to `level` above
    # (e.g. level: WARNING suppresses it regardless of this flag).
    capture_raw_requests: bool = True
    # Opt-in: when set, logs are additionally written to <directory>/app.log
    # (rotating) on top of stdout. Unset by default -- stdout-only is the
    # existing behavior.
    directory: str | None = None


class Settings(BaseModel):
    identity: IdentityConfig
    server: ServerConfig = Field(default_factory=ServerConfig)
    crypto: CryptoConfig
    envelope: EnvelopeConfig
    sinks: SinksConfig = Field(default_factory=SinksConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    internal_api: InternalApiConfig
    outbound: OutboundConfig = Field(default_factory=OutboundConfig)
    poller: PollerConfig = Field(default_factory=PollerConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    partners_file: str


def load_settings(path: str | Path) -> Settings:
    raw = yaml.safe_load(Path(path).read_text())
    return Settings.model_validate(raw)
