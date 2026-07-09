import uuid

import httpx
import pytest
import respx

from app.crypto.gpg_wrapper import GpgService
from app.envelope.fields import CanonicalField, InputFormat
from app.envelope.mapping import HeaderMapping
from app.envelope.receipt import ReasonCode, Receipt
from app.outbound.client import OutboundDeliveryError, send_message
from app.partners import ApiKeyAuthConfig, BasicAuthConfig, PartnerConfig
from app.settings import (
    CryptoConfig,
    EnvelopeConfig,
    IdentityConfig,
    InternalApiConfig,
    OutboundConfig,
    ServerConfig,
    Settings,
    SinksConfig,
)
from app.tracking.models import MessageRecord

PARTNER_ENDPOINT = "https://partner.example.com/edi/receiver-endpoint"


def _header_mapping() -> HeaderMapping:
    return HeaderMapping(
        {
            CanonicalField.VERSION: "version",
            CanonicalField.FROM_ID: "from-id",
            CanonicalField.TO_ID: "to-id",
            CanonicalField.INPUT_FORMAT: "input-format",
            CanonicalField.TRANSACTION_SET: "transaction-set",
        }
    )


@pytest.fixture
def settings(gnupg_home, monkeypatch):
    monkeypatch.setenv("TEST_US_PASSPHRASE", "us-passphrase")
    return Settings(
        identity=IdentityConfig(name="MyCompany", duns="123456789"),
        server=ServerConfig(),
        crypto=CryptoConfig(
            private_key_path="unused",
            passphrase_env="TEST_US_PASSPHRASE",
            gnupg_home=gnupg_home,
            cipher_algo="AES256",
            digest_algo="SHA256",
            compress_algo="ZIP",
        ),
        envelope=EnvelopeConfig(header_mapping=_header_mapping()),
        sinks=SinksConfig(),
        internal_api=InternalApiConfig(
            username_env="TEST_INTERNAL_API_USERNAME", password_env="TEST_INTERNAL_API_PASSWORD"
        ),
        outbound=OutboundConfig(timeout_seconds=5, retry_max_attempts=2, retry_backoff_seconds=0),
        partners_file="unused",
    )


@pytest.fixture
def partner(monkeypatch):
    monkeypatch.setenv("TEST_PARTNER_PASSWORD", "partner-out-password")
    return PartnerConfig(
        name="acme-pipeline",
        duns="987654321",
        endpoint_url=PARTNER_ENDPOINT,
        pgp_public_key_path="unused",
        outbound_auth=BasicAuthConfig(username="myuid", password_env="TEST_PARTNER_PASSWORD"),
        inbound_auth=ApiKeyAuthConfig(key_env="TEST_PARTNER_PASSWORD"),
    )


@pytest.fixture
def fingerprints(us_key, partner_key):
    return {"_self": us_key, "acme-pipeline": partner_key}


class FakeMessageTracker:
    def __init__(self):
        self.records: dict[uuid.UUID, MessageRecord] = {}

    async def find_duplicate(self, partner_name, content_digest, direction) -> bool:
        return False

    async def create(self, record: MessageRecord) -> uuid.UUID:
        message_id = uuid.uuid4()
        self.records[message_id] = record
        return message_id

    async def update_status(self, message_id, *, status, error_code=None, receipt_verified=None):
        record = self.records[message_id]
        record.status = status
        record.error_code = error_code
        record.receipt_verified = receipt_verified

    async def update_sinks_status(self, message_id, sinks_status):
        pass


@pytest.fixture
def tracker():
    return FakeMessageTracker()


def _signed_receipt_body(gpg_service: GpgService, signer_key: str, passphrase: str, receipt: Receipt) -> bytes:
    return gpg_service.sign_message(receipt.encode(), signer_fingerprint=signer_key, passphrase=passphrase)


@respx.mock
async def test_send_message_success(settings, partner, gpg_service, fingerprints, tracker, us_key, partner_key):
    receipt_body = _signed_receipt_body(gpg_service, partner_key, "partner-passphrase", Receipt.accepted())
    route = respx.post(PARTNER_ENDPOINT).mock(return_value=httpx.Response(200, content=receipt_body))

    result = await send_message(
        partner, b"ISA*00*...", InputFormat.X12, "873", settings, gpg_service, fingerprints, tracker
    )

    assert result.receipt.status.value == "success"
    assert route.called
    sent_request = route.calls.last.request
    assert sent_request.headers["version"] == "4.0"
    assert sent_request.headers["from-id"] == "123456789"
    assert sent_request.headers["to-id"] == "987654321"
    assert sent_request.headers["input-format"] == "X12"
    assert sent_request.headers["transaction-set"] == "873"
    assert sent_request.headers["content-type"] == "application/octet-stream"
    assert sent_request.headers["authorization"].startswith("Basic ")
    # the wire body must be the encrypted ciphertext, never the plaintext payload
    assert b"ISA*00*..." not in sent_request.content

    record = next(iter(tracker.records.values()))
    assert record.status == "delivered"


@respx.mock
async def test_send_message_records_partner_rejection(settings, partner, gpg_service, fingerprints, tracker, partner_key):
    receipt = Receipt.rejected(ReasonCode.INVALID_TRANSACTION_SET)
    receipt_body = _signed_receipt_body(gpg_service, partner_key, "partner-passphrase", receipt)
    respx.post(PARTNER_ENDPOINT).mock(return_value=httpx.Response(200, content=receipt_body))

    result = await send_message(
        partner, b"payload", InputFormat.X12, "873", settings, gpg_service, fingerprints, tracker
    )

    assert result.receipt.status.value == "validation-failed"
    record = next(iter(tracker.records.values()))
    assert record.status == "failed_nack"


@respx.mock
async def test_send_message_retries_on_unverifiable_receipt_then_raises(settings, partner, gpg_service, fingerprints, tracker):
    # Response isn't signed by anyone we trust -- every retry attempt sees the same thing.
    route = respx.post(PARTNER_ENDPOINT).mock(return_value=httpx.Response(200, content=b"not a signed message"))

    with pytest.raises(OutboundDeliveryError):
        await send_message(
            partner, b"payload", InputFormat.X12, "873", settings, gpg_service, fingerprints, tracker
        )

    assert route.call_count == settings.outbound.retry_max_attempts
    record = next(iter(tracker.records.values()))
    assert record.status == "unacknowledged"
    assert record.receipt_verified is False


@respx.mock
async def test_send_message_retries_on_http_error_then_raises(settings, partner, gpg_service, fingerprints, tracker):
    route = respx.post(PARTNER_ENDPOINT).mock(return_value=httpx.Response(503))

    with pytest.raises(OutboundDeliveryError):
        await send_message(
            partner, b"payload", InputFormat.X12, "873", settings, gpg_service, fingerprints, tracker
        )

    assert route.call_count == settings.outbound.retry_max_attempts


@respx.mock
async def test_send_message_encrypts_same_ciphertext_across_retries(settings, partner, gpg_service, fingerprints, tracker):
    bodies_seen = []

    def _capture(request):
        bodies_seen.append(request.content)
        return httpx.Response(503)

    respx.post(PARTNER_ENDPOINT).mock(side_effect=_capture)

    with pytest.raises(OutboundDeliveryError):
        await send_message(
            partner, b"payload", InputFormat.X12, "873", settings, gpg_service, fingerprints, tracker
        )

    assert len(bodies_seen) == settings.outbound.retry_max_attempts
    assert len(set(bodies_seen)) == 1  # identical ciphertext reused, not re-encrypted per attempt
