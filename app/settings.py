import os
from pathlib import Path

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

    @property
    def url(self) -> str:
        return resolve_env(self.url_env)


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
    outbound: OutboundConfig = Field(default_factory=OutboundConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    partners_file: str


def load_settings(path: str | Path) -> Settings:
    raw = yaml.safe_load(Path(path).read_text())
    return Settings.model_validate(raw)
