import os
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import yaml
from pydantic import BaseModel, Field

from app.envelope.mapping import HeaderMapping


class MissingEnvVarError(RuntimeError):
    def __init__(self, var_name: str):
        super().__init__(f"required environment variable {var_name!r} is not set")
        self.var_name = var_name


def resolve_env(var_name: str) -> str:
    value = os.environ.get(var_name)
    if value is None:
        raise MissingEnvVarError(var_name)
    return value


class IdentityConfig(BaseModel):
    name: str
    duns: str


class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
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

    @property
    def passphrase(self) -> str:
        return resolve_env(self.passphrase_env)


class EnvelopeConfig(BaseModel):
    header_mapping: HeaderMapping
    default_version: str = "4.0"


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
    retry_max_attempts: int = 3
    retry_backoff_seconds: float = 5.0


class LoggingConfig(BaseModel):
    level: str = "INFO"
    format: str = "json"


class Settings(BaseModel):
    identity: IdentityConfig
    server: ServerConfig = Field(default_factory=ServerConfig)
    crypto: CryptoConfig
    envelope: EnvelopeConfig
    sinks: SinksConfig = Field(default_factory=SinksConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    internal_api: InternalApiConfig
    outbound: OutboundConfig = Field(default_factory=OutboundConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    partners_file: str


def load_settings(path: str | Path) -> Settings:
    raw = yaml.safe_load(Path(path).read_text())
    return Settings.model_validate(raw)
