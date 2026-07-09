import uuid
from typing import Any

from psycopg.types.json import Json
from psycopg_pool import AsyncConnectionPool

from app.tracking.models import MessageRecord


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

    async def create(self, record: MessageRecord) -> uuid.UUID:
        async with self.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO messages (
                    direction, partner_name, content_digest, transaction_set, input_format,
                    status, error_code, receipt_verified, sinks_status, raw_headers, received_at, sent_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                    Json(record.sinks_status),
                    Json(record.raw_headers) if record.raw_headers is not None else None,
                    record.received_at,
                    record.sent_at,
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
        error_code: int | None = None,
        receipt_verified: bool | None = None,
    ) -> None:
        async with self.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                "UPDATE messages SET status=%s, error_code=%s, receipt_verified=%s, "
                "updated_at=now() WHERE id=%s",
                (status, error_code, receipt_verified, message_id),
            )

    async def update_sinks_status(self, message_id: uuid.UUID, sinks_status: dict[str, Any]) -> None:
        async with self.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                "UPDATE messages SET sinks_status=%s, updated_at=now() WHERE id=%s",
                (Json(sinks_status), message_id),
            )
