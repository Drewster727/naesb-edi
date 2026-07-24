import uuid
from datetime import datetime
from typing import Any

from psycopg.types.json import Json
from psycopg_pool import AsyncConnectionPool

from app.tracking.models import MessageRecord, OutboundJob


class MessageTracker:
    """Cross-cutting audit trail over the whole message lifecycle -- not a
    Sink. Updated at every pipeline checkpoint, including failures that never
    reach the sink-delivery stage (auth, crypto, dedupe)."""

    def __init__(self, pool: AsyncConnectionPool):
        self.pool = pool

    async def find_duplicate(self, partner_name: str, content_digest: str, direction: str) -> bool:
        async with self.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                "SELECT 1 FROM messages WHERE partner_name=%s AND content_digest=%s AND direction=%s",
                (partner_name, content_digest, direction),
            )
            return await cur.fetchone() is not None

    async def find_refnum_reuse(self, partner_name: str, refnum: str, direction: str) -> bool:
        """Per the spec's own tracking mechanism: a refnum should not be
        duplicated by the same partner ("First send"/"resend" semantics --
        only refnum-orig may repeat)."""
        async with self.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                "SELECT 1 FROM messages WHERE partner_name=%s AND refnum=%s AND direction=%s",
                (partner_name, refnum, direction),
            )
            return await cur.fetchone() is not None

    async def next_trans_id(self) -> int:
        """Sequential integer assigned by the server upon processing, per the
        Envelope Data Dictionary's `trans-id` field."""
        async with self.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute("SELECT nextval('trans_id_seq')")
            row = await cur.fetchone()
            assert row is not None
            return int(row[0])

    async def create(self, record: MessageRecord) -> uuid.UUID:
        async with self.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO messages (
                    direction, partner_name, content_digest, transaction_set, input_format,
                    status, error_code, receipt_verified, trans_id, refnum, refnum_orig,
                    sinks_status, raw_headers, received_at, sent_at,
                    receipt_sent_at, receipt_received_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    record.direction,
                    record.partner_name,
                    record.content_digest,
                    record.transaction_set,
                    record.input_format,
                    record.status,
                    record.error_code,
                    record.receipt_verified,
                    record.trans_id,
                    record.refnum,
                    record.refnum_orig,
                    Json(record.sinks_status),
                    Json(record.raw_headers) if record.raw_headers is not None else None,
                    record.received_at,
                    record.sent_at,
                    record.receipt_sent_at,
                    record.receipt_received_at,
                ),
            )
            row = await cur.fetchone()
            assert row is not None
            return row[0]

    async def update_status(
        self,
        message_id: uuid.UUID,
        *,
        status: str,
        error_code: str | None = None,
        receipt_verified: bool | None = None,
        trans_id: int | None = None,
        receipt_sent_at: datetime | None = None,
        receipt_received_at: datetime | None = None,
    ) -> None:
        async with self.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                "UPDATE messages SET status=%s, error_code=%s, receipt_verified=%s, "
                "trans_id=COALESCE(%s, trans_id), "
                "receipt_sent_at=COALESCE(%s, receipt_sent_at), "
                "receipt_received_at=COALESCE(%s, receipt_received_at), "
                "updated_at=now() WHERE id=%s",
                (
                    status,
                    error_code,
                    receipt_verified,
                    trans_id,
                    receipt_sent_at,
                    receipt_received_at,
                    message_id,
                ),
            )

    async def update_sinks_status(self, message_id: uuid.UUID, sinks_status: dict[str, Any]) -> None:
        async with self.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                "UPDATE messages SET sinks_status=%s, updated_at=now() WHERE id=%s",
                (Json(sinks_status), message_id),
            )


_JOB_COLUMNS = (
    "id, partner_name, from_id, to_id, version, input_format, transaction_set, "
    "refnum, refnum_orig, payload_ciphertext, content_digest, status, attempt_count, "
    "last_error_code, last_error_description, receipt_trans_id, receipt_server_id, "
    "receipt_time_c, message_id"
)


def _row_to_job(row: tuple) -> OutboundJob:
    return OutboundJob(
        id=row[0],
        partner_name=row[1],
        from_id=row[2],
        to_id=row[3],
        version=row[4],
        input_format=row[5],
        transaction_set=row[6],
        refnum=row[7],
        refnum_orig=row[8],
        payload_ciphertext=bytes(row[9]),
        content_digest=row[10],
        status=row[11],
        attempt_count=row[12],
        last_error_code=row[13],
        last_error_description=row[14],
        receipt_trans_id=row[15],
        receipt_server_id=row[16],
        receipt_time_c=row[17],
        message_id=row[18],
    )


class OutboundJobRepository:
    """DB-backed job queue for outbound deliveries. `app/api/send.py` enqueues
    jobs; `app/worker.py` claims and executes them on a schedule that can
    span the NAESB Exchange Failure window (30-120 minutes) without blocking
    the HTTP request that enqueued the job."""

    def __init__(self, pool: AsyncConnectionPool):
        self.pool = pool

    async def create(self, job: OutboundJob) -> uuid.UUID:
        async with self.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO outbound_jobs (
                    partner_name, from_id, to_id, version, input_format, transaction_set,
                    refnum, refnum_orig, payload_ciphertext, content_digest, message_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    job.partner_name,
                    job.from_id,
                    job.to_id,
                    job.version,
                    job.input_format,
                    job.transaction_set,
                    job.refnum,
                    job.refnum_orig,
                    job.payload_ciphertext,
                    job.content_digest,
                    job.message_id,
                ),
            )
            row = await cur.fetchone()
            assert row is not None
            return row[0]

    async def get(self, job_id: uuid.UUID) -> OutboundJob | None:
        async with self.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(f"SELECT {_JOB_COLUMNS} FROM outbound_jobs WHERE id=%s", (job_id,))
            row = await cur.fetchone()
            return _row_to_job(row) if row else None

    async def claim_due_jobs(self, limit: int) -> list[OutboundJob]:
        """Atomically claim up to `limit` due jobs (queued -- either fresh or
        rescheduled after a failed attempt), marking them in_progress and
        incrementing attempt_count. Uses SELECT ... FOR UPDATE SKIP LOCKED so
        multiple worker instances can run safely.

        Only 'queued' jobs are claimable -- 'in_progress' is deliberately
        excluded so a job doesn't get reclaimed by every poll cycle while a
        delivery attempt is still in flight. reschedule()/mark_delivered()/
        mark_failed_nack()/mark_exchange_failure() all move a job out of
        'in_progress' once its attempt concludes."""
        async with self.pool.connection() as conn:
            async with conn.transaction(), conn.cursor() as cur:
                await cur.execute(
                    f"""
                    SELECT {_JOB_COLUMNS} FROM outbound_jobs
                    WHERE status = 'queued' AND next_attempt_at <= now()
                    ORDER BY next_attempt_at
                    LIMIT %s
                    FOR UPDATE SKIP LOCKED
                    """,
                    (limit,),
                )
                rows = await cur.fetchall()
                if not rows:
                    return []
                ids = [row[0] for row in rows]
                await cur.execute(
                    "UPDATE outbound_jobs SET status='in_progress', attempt_count=attempt_count+1, "
                    "updated_at=now() WHERE id = ANY(%s)",
                    (ids,),
                )
            jobs = [_row_to_job(row) for row in rows]
            for job in jobs:
                job.attempt_count += 1
            return jobs

    async def mark_delivered(
        self, job_id: uuid.UUID, receipt_trans_id: str, receipt_server_id: str, receipt_time_c: str
    ) -> None:
        async with self.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                "UPDATE outbound_jobs SET status='delivered', receipt_trans_id=%s, "
                "receipt_server_id=%s, receipt_time_c=%s, updated_at=now() WHERE id=%s",
                (receipt_trans_id, receipt_server_id, receipt_time_c, job_id),
            )

    async def mark_failed_nack(self, job_id: uuid.UUID, error_code: str, error_description: str) -> None:
        async with self.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                "UPDATE outbound_jobs SET status='failed_nack', last_error_code=%s, "
                "last_error_description=%s, updated_at=now() WHERE id=%s",
                (error_code, error_description, job_id),
            )

    async def reschedule(
        self, job_id: uuid.UUID, next_attempt_at: datetime, error_description: str
    ) -> None:
        async with self.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                "UPDATE outbound_jobs SET status='queued', next_attempt_at=%s, "
                "last_error_description=%s, updated_at=now() WHERE id=%s",
                (next_attempt_at, error_description, job_id),
            )

    async def mark_exchange_failure(self, job_id: uuid.UUID, error_description: str) -> None:
        """Attempts exhausted per standards 12.3.10/12.3.11 -- a distinct
        outcome from an ordinary failed_nack, meant to be distinguishable
        for partner notification purposes."""
        async with self.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                "UPDATE outbound_jobs SET status='exchange_failure', last_error_description=%s, "
                "updated_at=now() WHERE id=%s",
                (error_description, job_id),
            )


class PartnerRefnumRepository:
    """Assigns refnum values for outbound messages that have no API caller to
    supply one -- currently just the file-drop poller (app/poller.py), for
    partners configured with envelope_overrides.use_refnum: true. Backed by
    `partner_refnum_counters` (db/migrations/0005_partner_refnum_counters.sql),
    a simple per-partner monotonic counter."""

    def __init__(self, pool: AsyncConnectionPool):
        self.pool = pool

    async def next_refnum(self, partner_name: str) -> str:
        async with self.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO partner_refnum_counters (partner_name, next_refnum)
                VALUES (%s, 2)
                ON CONFLICT (partner_name) DO UPDATE
                    SET next_refnum = partner_refnum_counters.next_refnum + 1
                RETURNING next_refnum - 1
                """,
                (partner_name,),
            )
            row = await cur.fetchone()
            assert row is not None
            return str(row[0])
