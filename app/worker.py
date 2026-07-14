"""Background worker: polls `outbound_jobs` for due delivery attempts and
executes them, rescheduling per `outbound.retry_schedule_seconds` or
declaring an Exchange Failure once that schedule is exhausted (WGQ
Cybersecurity Related Standards v4.0, standards 12.3.10/12.3.11 -- 3 attempts
before notifying the Trading Partner of an Exchange Failure).

Runs as its own process, sharing the same Postgres database and GPG keyring
as the main app (`python -m app.worker`; see docker-compose.yml's `worker`
service). Kept separate from the FastAPI app so a retry window spanning up
to ~2 hours never blocks an HTTP request, and so retry state survives an
app/worker restart mid-window (it's persisted in `outbound_jobs`, not held
in memory).
"""

import asyncio
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import structlog

from app.crypto.gpg_wrapper import GpgService
from app.crypto.keyring import bootstrap_keyring
from app.logging_config import configure_logging
from app.outbound.client import DeliveryAttemptError, send_once
from app.partners import PartnerRegistry, load_partners
from app.settings import Settings, load_settings
from app.tracking.db import create_pool, run_migrations
from app.tracking.models import OutboundJob
from app.tracking.repository import MessageTracker, OutboundJobRepository

logger = structlog.get_logger()


async def _process_job(
    job: OutboundJob,
    settings: Settings,
    gpg: GpgService,
    fingerprints: dict[str, str],
    partners: PartnerRegistry,
    jobs: OutboundJobRepository,
    tracker: MessageTracker,
) -> None:
    partner = partners.get_by_name(job.partner_name)
    if partner is None:
        logger.error("outbound_job_unknown_partner", job_id=str(job.id), partner=job.partner_name)
        await jobs.mark_exchange_failure(job.id, f"unknown partner {job.partner_name!r}")
        return

    try:
        receipt = await send_once(job, partner, settings, gpg, fingerprints[partner.name])
    except DeliveryAttemptError as exc:
        await _handle_failure(job, settings, jobs, tracker, str(exc))
        return

    if receipt.is_ok:
        await jobs.mark_delivered(job.id, receipt.trans_id, receipt.server_id, receipt.time_c)
        if job.message_id is not None:
            await tracker.update_status(job.message_id, status="delivered", receipt_verified=True)
        logger.info("outbound_delivered", job_id=str(job.id), partner=job.partner_name)
        return

    code, _, description = receipt.request_status.partition(":")
    await jobs.mark_failed_nack(job.id, code.strip(), description.strip() or receipt.request_status)
    if job.message_id is not None:
        await tracker.update_status(
            job.message_id, status="failed_nack", error_code=code.strip(), receipt_verified=True
        )
    logger.warning(
        "outbound_rejected_by_partner",
        job_id=str(job.id),
        partner=job.partner_name,
        request_status=receipt.request_status,
    )


async def _handle_failure(
    job: OutboundJob,
    settings: Settings,
    jobs: OutboundJobRepository,
    tracker: MessageTracker,
    error: str,
) -> None:
    schedule = settings.outbound.retry_schedule_seconds
    if job.attempt_count >= len(schedule):
        await jobs.mark_exchange_failure(job.id, error)
        if job.message_id is not None:
            await tracker.update_status(job.message_id, status="exchange_failure")
        # Distinct structured event from an ordinary retry -- this is the
        # spec's "Exchange Failure" notification trigger, not just a log line.
        logger.error(
            "outbound_exchange_failure",
            job_id=str(job.id),
            partner=job.partner_name,
            attempts=job.attempt_count,
            error=error,
        )
        return

    delay = schedule[job.attempt_count]
    next_attempt_at = datetime.now(UTC) + timedelta(seconds=delay)
    await jobs.reschedule(job.id, next_attempt_at, error)
    logger.warning(
        "outbound_attempt_failed",
        job_id=str(job.id),
        partner=job.partner_name,
        attempt=job.attempt_count,
        next_attempt_at=next_attempt_at.isoformat(),
        error=error,
    )


async def run_worker(settings: Settings, *, iterations: int | None = None) -> None:
    """`iterations=None` runs forever (production); a finite value lets
    tests run a bounded number of poll cycles."""
    configure_logging(settings.logging.level, settings.logging.format)
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
    jobs = OutboundJobRepository(pool)
    tracker = MessageTracker(pool)

    logger.info("worker_started", partners=len(partners))
    try:
        count = 0
        while iterations is None or count < iterations:
            due = await jobs.claim_due_jobs(limit=10)
            for job in due:
                await _process_job(job, settings, gpg, fingerprints, partners, jobs, tracker)
            count += 1
            if iterations is None or count < iterations:
                await asyncio.sleep(settings.outbound.worker_poll_interval_seconds)
    finally:
        await pool.close()


def main() -> None:
    config_path = os.environ.get("NAESB_CONFIG_PATH", "config/config.yaml")
    settings = load_settings(config_path)
    asyncio.run(run_worker(settings))


if __name__ == "__main__":
    main()
