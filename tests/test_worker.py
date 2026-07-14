import pytest

import app.worker as worker_module
from app.envelope.error_codes import NaesbErrorCode
from app.envelope.receipt import NaesbReceipt
from app.outbound.client import DeliveryAttemptError
from app.partners import ApiKeyAuthConfig, BasicAuthConfig, PartnerConfig, PartnerRegistry
from app.settings import OutboundConfig
from app.tracking.models import OutboundJob


class FakeJobRepository:
    def __init__(self):
        self.delivered: list[tuple] = []
        self.failed_nack: list[tuple] = []
        self.rescheduled: list[tuple] = []
        self.exchange_failures: list[tuple] = []

    async def mark_delivered(self, job_id, receipt_trans_id, receipt_server_id, receipt_time_c):
        self.delivered.append((job_id, receipt_trans_id, receipt_server_id, receipt_time_c))

    async def mark_failed_nack(self, job_id, error_code, error_description):
        self.failed_nack.append((job_id, error_code, error_description))

    async def reschedule(self, job_id, next_attempt_at, error_description):
        self.rescheduled.append((job_id, next_attempt_at, error_description))

    async def mark_exchange_failure(self, job_id, error_description):
        self.exchange_failures.append((job_id, error_description))


class FakeTracker:
    def __init__(self):
        self.updates: list[tuple] = []

    async def update_status(self, message_id, *, status, error_code=None, receipt_verified=None, **_kwargs):
        self.updates.append((message_id, status, error_code, receipt_verified))


@pytest.fixture
def partner():
    return PartnerConfig(
        name="acme-pipeline",
        duns="987654321",
        endpoint_url="https://partner.example.com/edi/receiver-endpoint",
        pgp_public_key_path="unused",
        outbound_auth=BasicAuthConfig(username="u", password_env="TEST_UNUSED"),
        inbound_auth=ApiKeyAuthConfig(key_env="TEST_UNUSED"),
    )


@pytest.fixture
def partners(partner):
    return PartnerRegistry([partner])


def _job(**overrides) -> OutboundJob:
    defaults = dict(
        id="job-1",
        partner_name="acme-pipeline",
        from_id="123456789",
        to_id="987654321",
        version="1.9",
        input_format="X12",
        payload_ciphertext=b"cipher",
        content_digest="digest",
        attempt_count=0,
        message_id="msg-1",
    )
    defaults.update(overrides)
    return OutboundJob(**defaults)


async def test_process_job_success(monkeypatch, partners):
    async def fake_send_once(job, partner, settings, gpg, fingerprint):
        return NaesbReceipt.ok("their-host", 7)

    monkeypatch.setattr(worker_module, "send_once", fake_send_once)

    jobs = FakeJobRepository()
    tracker = FakeTracker()
    await worker_module._process_job(_job(), None, None, {"acme-pipeline": "fp"}, partners, jobs, tracker)

    assert jobs.delivered == [("job-1", "7", "their-host", jobs.delivered[0][3])]
    assert tracker.updates == [("msg-1", "delivered", None, True)]


async def test_process_job_partner_rejection(monkeypatch, partners):
    async def fake_send_once(job, partner, settings, gpg, fingerprint):
        return NaesbReceipt.rejected("their-host", 1, NaesbErrorCode.INVALID_TRANSACTION_SET)

    monkeypatch.setattr(worker_module, "send_once", fake_send_once)

    jobs = FakeJobRepository()
    tracker = FakeTracker()
    await worker_module._process_job(_job(), None, None, {"acme-pipeline": "fp"}, partners, jobs, tracker)

    assert len(jobs.failed_nack) == 1
    job_id, code, description = jobs.failed_nack[0]
    assert code == "EEDM108"
    assert tracker.updates[0][1] == "failed_nack"


async def test_process_job_unknown_partner_is_exchange_failure(monkeypatch):
    jobs = FakeJobRepository()
    tracker = FakeTracker()
    await worker_module._process_job(
        _job(partner_name="ghost-pipeline"), None, None, {}, PartnerRegistry([]), jobs, tracker
    )
    assert len(jobs.exchange_failures) == 1


async def test_handle_failure_reschedules_when_attempts_remain():
    settings = _fake_settings()
    jobs = FakeJobRepository()
    tracker = FakeTracker()
    job = _job(attempt_count=1)

    await worker_module._handle_failure(job, settings, jobs, tracker, "boom")

    assert len(jobs.rescheduled) == 1
    assert not jobs.exchange_failures


async def test_handle_failure_declares_exchange_failure_when_schedule_exhausted():
    settings = _fake_settings()
    jobs = FakeJobRepository()
    tracker = FakeTracker()
    job = _job(attempt_count=3)  # == len(schedule) -- no attempts left

    await worker_module._handle_failure(job, settings, jobs, tracker, "boom")

    assert len(jobs.exchange_failures) == 1
    assert not jobs.rescheduled
    assert tracker.updates[0][1] == "exchange_failure"


async def test_process_job_delivery_failure_reschedules(monkeypatch, partners):
    async def fake_send_once(job, partner, settings, gpg, fingerprint):
        raise DeliveryAttemptError("network blip")

    monkeypatch.setattr(worker_module, "send_once", fake_send_once)

    settings = _fake_settings()
    jobs = FakeJobRepository()
    tracker = FakeTracker()
    await worker_module._process_job(_job(attempt_count=0), settings, None, {"acme-pipeline": "fp"}, partners, jobs, tracker)

    assert len(jobs.rescheduled) == 1


def _fake_settings():
    class _Settings:
        outbound = OutboundConfig(retry_schedule_seconds=[0, 900, 2700])

    return _Settings()
