import os
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from fastapi import FastAPI

from app.api import health, send
from app.crypto.gpg_wrapper import GpgService
from app.crypto.keyring import bootstrap_keyring
from app.errors import register_exception_handlers
from app.inbound import routes as inbound_routes
from app.logging_config import configure_logging
from app.partners import load_partners
from app.settings import Settings, load_settings
from app.sinks.base import Sink
from app.sinks.filesystem_sink import FilesystemSink
from app.sinks.s3_sink import S3Sink
from app.sinks.webhook_sink import WebhookSink
from app.tracking.db import create_pool, run_migrations
from app.tracking.repository import MessageTracker

logger = structlog.get_logger()

_CONFIG_PATH = os.environ.get("NAESB_CONFIG_PATH", "config/config.yaml")
settings: Settings = load_settings(_CONFIG_PATH)


def _build_sinks(settings: Settings) -> list[Sink]:
    sinks: list[Sink] = []

    fs_cfg = settings.sinks.filesystem
    if fs_cfg.enabled:
        sinks.append(FilesystemSink(base_dir=fs_cfg.base_dir, durable=fs_cfg.durable))

    s3_cfg = settings.sinks.s3
    if s3_cfg is not None and s3_cfg.enabled:
        sinks.append(
            S3Sink(
                bucket=s3_cfg.bucket,
                prefix=s3_cfg.prefix,
                region=s3_cfg.region,
                endpoint_url=s3_cfg.endpoint_url,
                access_key=s3_cfg.access_key,
                secret_key=s3_cfg.secret_key,
                durable=s3_cfg.durable,
            )
        )

    webhook_cfg = settings.sinks.webhook
    if webhook_cfg.enabled:
        assert webhook_cfg.url is not None
        sinks.append(WebhookSink(url=webhook_cfg.url, timeout_seconds=webhook_cfg.timeout_seconds))

    return sinks


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging(settings.logging.level, settings.logging.format)

    partners = load_partners(settings.partners_file)

    Path(settings.crypto.gnupg_home).mkdir(parents=True, exist_ok=True, mode=0o700)
    gpg_service = GpgService(
        gnupg_home=settings.crypto.gnupg_home,
        cipher_algo=settings.crypto.cipher_algo,
        digest_algo=settings.crypto.digest_algo,
        compress_algo=settings.crypto.compress_algo,
    )
    fingerprints = bootstrap_keyring(
        gpg_service.gpg,
        settings.crypto.private_key_path,
        partners,
        settings.crypto.min_rsa_key_bits,
        settings.crypto.recommended_rsa_key_bits,
        logger,
    )

    pool = await create_pool(settings.database.url)
    await run_migrations(pool)
    tracker = MessageTracker(pool)

    sinks = _build_sinks(settings)

    app.state.settings = settings
    app.state.partners = partners
    app.state.gpg = gpg_service
    app.state.fingerprints = fingerprints
    app.state.tracker = tracker
    app.state.sinks = sinks
    app.state.db_pool = pool

    logger.info("startup_complete", partners=len(partners), sinks=[s.name for s in sinks])
    yield

    await pool.close()


def create_app() -> FastAPI:
    app = FastAPI(title="naesb-edi", lifespan=lifespan)
    register_exception_handlers(app)
    app.include_router(health.router)
    app.include_router(send.router)
    app.include_router(inbound_routes.router, prefix=settings.server.inbound_path)
    return app


app = create_app()
