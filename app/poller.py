"""Background poller: watches `settings.poller.base_dir` for raw,
unencrypted EDI files dropped into partner-DUNS-named subfolders, encrypts +
enqueues them through the same path `POST /outbound/send` uses
(`app/outbound/enqueue.py`), and moves each file into that partner's
`processed/` (once handed to the delivery queue) or `error/` (pickup failed
`max_pickup_attempts` times) subfolder.

Runs as its own process, sharing the same Postgres database and GPG keyring
as the main app (`python -m app.poller`; see docker-compose.yml's `poller`
service) -- same reasoning as `app/worker.py`: filesystem scanning across
many partner folders shouldn't block the request path or the delivery-retry
worker's own loop.

IMPORTANT: a file moving to `processed/` means "handed to `outbound_jobs`",
not "delivered". The actual delivery outcome -- including the existing
3-attempt Exchange-Failure window (`app/worker.py`) -- is tracked only in
`outbound_jobs`/`messages` and logs, never reflected back onto the
filesystem. See `docs/outbound-flow.md`.
"""

import asyncio
import os
import time
from pathlib import Path

import structlog

from app.crypto.gpg_wrapper import GpgService
from app.crypto.keyring import bootstrap_keyring
from app.envelope.fields import InputFormat
from app.logging_config import configure_logging
from app.outbound.enqueue import enqueue_outbound
from app.outbound.filewatch import (
    list_duns_dirs,
    list_stable_files,
    move_to_error,
    move_to_processed,
)
from app.partners import PartnerConfig, PartnerRegistry, load_partners
from app.settings import Settings, load_settings
from app.tracking.db import create_pool, run_migrations
from app.tracking.repository import MessageTracker, OutboundJobRepository, PartnerRefnumRepository

logger = structlog.get_logger()


class _AttemptTracker:
    """Bounded in-memory retry count for pickup-phase failures (unreadable
    file, encryption error, DB unavailable), keyed by absolute file path.
    Deliberately not persisted -- these failures are either transient infra
    hiccups (resolve within the process's lifetime) or deterministic config
    problems (fail identically after a restart too), so losing counts across
    a poller restart just delays, not hides, the eventual move to error/."""

    def __init__(self, max_attempts: int):
        self.max_attempts = max_attempts
        self._counts: dict[str, int] = {}

    def record_failure(self, path: Path) -> int:
        key = str(path)
        count = self._counts.get(key, 0) + 1
        self._counts[key] = count
        return count

    def exhausted(self, path: Path) -> bool:
        return self._counts.get(str(path), 0) >= self.max_attempts

    def clear(self, path: Path) -> None:
        self._counts.pop(str(path), None)


async def _process_file(
    file_path: Path,
    duns_dir: Path,
    partner: PartnerConfig,
    settings: Settings,
    gpg: GpgService,
    fingerprints: dict[str, str],
    tracker: MessageTracker,
    jobs: OutboundJobRepository,
    refnums: PartnerRefnumRepository,
    attempts: _AttemptTracker,
) -> None:
    try:
        payload = file_path.read_bytes()
        refnum = await refnums.next_refnum(partner.name) if partner.use_refnum else None
        job_id = await enqueue_outbound(
            payload,
            partner=partner,
            input_format=InputFormat.X12,
            transaction_set=None,
            refnum=refnum,
            refnum_orig=None,
            settings=settings,
            gpg=gpg,
            fingerprints=fingerprints,
            tracker=tracker,
            jobs=jobs,
        )
    except Exception as exc:  # noqa: BLE001 - pickup failures must never crash the poll loop
        attempt = attempts.record_failure(file_path)
        if attempts.exhausted(file_path):
            dest = move_to_error(file_path, duns_dir)
            attempts.clear(file_path)
            logger.error(
                "poller_file_errored",
                path=str(dest),
                partner=partner.name,
                attempts=attempt,
                error=str(exc),
            )
        else:
            logger.warning(
                "poller_file_pickup_failed",
                path=str(file_path),
                partner=partner.name,
                attempt=attempt,
                max_attempts=attempts.max_attempts,
                error=str(exc),
            )
        return

    attempts.clear(file_path)
    dest = move_to_processed(file_path, duns_dir)
    logger.info("poller_file_enqueued", job_id=str(job_id), partner=partner.name, path=str(dest))


async def _poll_once(
    settings: Settings,
    partners: PartnerRegistry,
    gpg: GpgService,
    fingerprints: dict[str, str],
    tracker: MessageTracker,
    jobs: OutboundJobRepository,
    refnums: PartnerRefnumRepository,
    attempts: _AttemptTracker,
    unknown_duns_warned: set[str],
) -> None:
    base_dir = Path(settings.poller.base_dir)
    now = time.time()
    for duns_dir in list_duns_dirs(base_dir):
        partner = partners.get_by_duns(duns_dir.duns)
        if partner is None:
            # Left in place, not moved anywhere -- self-heals once the
            # partner is added to partners.yaml. Rate-limited to one warning
            # per DUNS per "unknown" streak, not once per poll cycle.
            if duns_dir.duns not in unknown_duns_warned:
                logger.warning("poller_unknown_duns", duns=duns_dir.duns, path=str(duns_dir.path))
                unknown_duns_warned.add(duns_dir.duns)
            continue
        unknown_duns_warned.discard(duns_dir.duns)

        for file_path in list_stable_files(duns_dir.path, settings.poller.quiet_period_seconds, now):
            await _process_file(
                file_path,
                duns_dir.path,
                partner,
                settings,
                gpg,
                fingerprints,
                tracker,
                jobs,
                refnums,
                attempts,
            )


async def run_poller(settings: Settings, *, iterations: int | None = None) -> None:
    """`iterations=None` runs forever (production); a finite value lets
    tests run a bounded number of poll cycles."""
    configure_logging(settings.logging.level, settings.logging.format, settings.logging.directory)

    if not settings.poller.enabled:
        logger.info("poller_disabled")
        return

    partners = load_partners(settings.partners_file)

    Path(settings.crypto.gnupg_home).mkdir(parents=True, exist_ok=True, mode=0o700)
    gpg = GpgService(
        gnupg_home=settings.crypto.gnupg_home,
        cipher_algo=settings.crypto.cipher_algo,
        digest_algo=settings.crypto.digest_algo,
        compress_algo=settings.crypto.compress_algo,
    )
    fingerprints = bootstrap_keyring(
        gpg.gpg,
        settings.crypto.private_key_path,
        partners,
        settings.crypto.min_rsa_key_bits,
        settings.crypto.recommended_rsa_key_bits,
        logger,
    )

    pool = await create_pool(settings.database.url)
    await run_migrations(pool)
    tracker = MessageTracker(pool)
    jobs = OutboundJobRepository(pool)
    refnums = PartnerRefnumRepository(pool)

    attempts = _AttemptTracker(settings.poller.max_pickup_attempts)
    unknown_duns_warned: set[str] = set()

    Path(settings.poller.base_dir).mkdir(parents=True, exist_ok=True)

    logger.info("poller_started", partners=len(partners), base_dir=settings.poller.base_dir)
    try:
        count = 0
        while iterations is None or count < iterations:
            await _poll_once(
                settings,
                partners,
                gpg,
                fingerprints,
                tracker,
                jobs,
                refnums,
                attempts,
                unknown_duns_warned,
            )
            count += 1
            if iterations is None or count < iterations:
                await asyncio.sleep(settings.poller.poll_interval_seconds)
    finally:
        await pool.close()


def main() -> None:
    config_path = os.environ.get("NAESB_CONFIG_PATH", "config/config.yaml")
    settings = load_settings(config_path)
    asyncio.run(run_poller(settings))


if __name__ == "__main__":
    main()
