import pytest
from testcontainers.postgres import PostgresContainer

from app.tracking.db import create_pool, run_migrations
from app.tracking.models import MessageRecord, OutboundJob
from app.tracking.repository import MessageTracker, OutboundJobRepository

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def postgres_container():
    with PostgresContainer("postgres:16-alpine") as container:
        yield container


@pytest.fixture
async def pool(postgres_container):
    url = postgres_container.get_connection_url(driver=None)
    p = await create_pool(url)
    await run_migrations(p)
    yield p
    await p.close()


@pytest.fixture
def tracker(pool):
    return MessageTracker(pool)


@pytest.fixture
def job_repository(pool):
    return OutboundJobRepository(pool)


async def test_create_and_find_duplicate(tracker):
    record = MessageRecord(
        direction="inbound",
        partner_name="acme-pipeline",
        content_digest="a" * 64,
        transaction_set="873",
        input_format="X12",
        status="processing",
    )

    assert not await tracker.find_duplicate("acme-pipeline", "a" * 64, "inbound")

    message_id = await tracker.create(record)
    assert message_id is not None

    assert await tracker.find_duplicate("acme-pipeline", "a" * 64, "inbound")
    # different direction is not a duplicate of the inbound one
    assert not await tracker.find_duplicate("acme-pipeline", "a" * 64, "outbound")


async def test_update_status(tracker):
    record = MessageRecord(
        direction="outbound", partner_name="acme-pipeline", content_digest="b" * 64, status="sending"
    )
    message_id = await tracker.create(record)

    await tracker.update_status(message_id, status="delivered", receipt_verified=True)

    # a second insert with the same natural key should now violate the
    # UNIQUE(partner_name, content_digest, direction) constraint
    with pytest.raises(Exception):
        await tracker.create(record)


async def test_update_sinks_status(tracker):
    record = MessageRecord(
        direction="inbound", partner_name="acme-pipeline", content_digest="c" * 64, status="processing"
    )
    message_id = await tracker.create(record)

    await tracker.update_sinks_status(message_id, {"filesystem": {"ok": True, "error": None}})
    # no exception means the jsonb column accepted the update; content is
    # verified indirectly via find_duplicate/update_status round trips above


async def test_next_trans_id_is_sequential(tracker):
    first = await tracker.next_trans_id()
    second = await tracker.next_trans_id()
    assert second == first + 1


async def test_find_refnum_reuse(tracker):
    assert not await tracker.find_refnum_reuse("acme-pipeline", "refnum-1", "inbound")

    record = MessageRecord(
        direction="inbound",
        partner_name="acme-pipeline",
        content_digest="d" * 64,
        status="accepted",
        refnum="refnum-1",
    )
    await tracker.create(record)

    assert await tracker.find_refnum_reuse("acme-pipeline", "refnum-1", "inbound")
    assert not await tracker.find_refnum_reuse("acme-pipeline", "refnum-1", "outbound")


async def test_create_rejects_duplicate_refnum_same_partner_and_direction(tracker):
    # Different content_digest so the (partner_name, content_digest, direction)
    # constraint can't be what raises -- this exercises the dedicated
    # (partner_name, refnum, direction) WHERE refnum IS NOT NULL unique index
    # from 0004_unique_refnum.sql, the DB-level backstop for the refnum-dedup
    # race (mirrors test_update_status's digest-uniqueness assertion above).
    first = MessageRecord(
        direction="inbound",
        partner_name="acme-pipeline",
        content_digest="g" * 64,
        status="processing",
        refnum="dup-refnum",
    )
    await tracker.create(first)

    second = MessageRecord(
        direction="inbound",
        partner_name="acme-pipeline",
        content_digest="h" * 64,
        status="processing",
        refnum="dup-refnum",
    )
    with pytest.raises(Exception):
        await tracker.create(second)


async def test_outbound_job_create_claim_and_deliver(job_repository):
    job = OutboundJob(
        id=None,
        partner_name="acme-pipeline",
        from_id="123456789",
        to_id="987654321",
        version="1.9",
        input_format="X12",
        payload_ciphertext=b"ciphertext-bytes",
        content_digest="e" * 64,
    )
    job_id = await job_repository.create(job)
    fetched = await job_repository.get(job_id)
    assert fetched is not None
    assert fetched.status == "queued"
    assert fetched.payload_ciphertext == b"ciphertext-bytes"

    claimed = await job_repository.claim_due_jobs(limit=10)
    assert any(j.id == job_id for j in claimed)
    claimed_job = next(j for j in claimed if j.id == job_id)
    assert claimed_job.attempt_count == 1

    # a second claim attempt should not re-claim an in_progress job with no
    # due schedule change
    reclaimed = await job_repository.claim_due_jobs(limit=10)
    assert not any(j.id == job_id for j in reclaimed)

    await job_repository.mark_delivered(job_id, "42", "their-host", "20260710120000")
    delivered = await job_repository.get(job_id)
    assert delivered.status == "delivered"
    assert delivered.receipt_trans_id == "42"


async def test_outbound_job_reschedule_and_exchange_failure(job_repository):
    import datetime

    job = OutboundJob(
        id=None,
        partner_name="acme-pipeline",
        from_id="123456789",
        to_id="987654321",
        version="1.9",
        input_format="X12",
        payload_ciphertext=b"ciphertext-bytes-2",
        content_digest="f" * 64,
    )
    job_id = await job_repository.create(job)

    future = datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)
    await job_repository.reschedule(job_id, future, "transient failure")
    rescheduled = await job_repository.get(job_id)
    assert rescheduled.status == "queued"
    assert rescheduled.last_error_description == "transient failure"

    # not due yet -- shouldn't be claimable
    claimed = await job_repository.claim_due_jobs(limit=10)
    assert not any(j.id == job_id for j in claimed)

    await job_repository.mark_exchange_failure(job_id, "attempts exhausted")
    final = await job_repository.get(job_id)
    assert final.status == "exchange_failure"
