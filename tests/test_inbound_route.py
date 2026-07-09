import uuid
from dataclasses import dataclass, field

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.crypto.gpg_wrapper import GpgService
from app.dependencies import (
    get_fingerprints,
    get_gpg,
    get_partners,
    get_settings,
    get_sinks,
    get_tracker,
)
from app.envelope.fields import CanonicalField
from app.envelope.mapping import HeaderMapping
from app.envelope.receipt import Receipt
from app.inbound import routes as inbound_routes
from app.partners import ApiKeyAuthConfig, BasicAuthConfig, PartnerConfig, PartnerRegistry
from app.settings import (
    CryptoConfig,
    EnvelopeConfig,
    IdentityConfig,
    ServerConfig,
    Settings,
    SinksConfig,
)
from app.sinks.base import SinkResult
from app.tracking.models import MessageRecord

PARTNER_DUNS = "987654321"
PARTNER_NAME = "acme-pipeline"


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
        server=ServerConfig(inbound_path="/inbound", max_body_size_bytes=26_214_400),
        crypto=CryptoConfig(
            private_key_path="unused",
            passphrase_env="TEST_US_PASSPHRASE",
            gnupg_home=gnupg_home,
            cipher_algo="AES256",
            digest_algo="SHA256",
            compress_algo="ZIP",
        ),
        envelope=EnvelopeConfig(header_mapping=_header_mapping()),
        sinks=SinksConfig(require_at_least_one_durable_success=True),
        partners_file="unused",
    )


@pytest.fixture
def partner(monkeypatch):
    monkeypatch.setenv("TEST_PARTNER_IN_KEY", "partner-inbound-key")
    return PartnerConfig(
        name=PARTNER_NAME,
        duns=PARTNER_DUNS,
        endpoint_url="https://partner.example.com/edi/receiver-endpoint",
        pgp_public_key_path="unused",
        outbound_auth=BasicAuthConfig(username="u", password_env="TEST_PARTNER_OUT_PASSWORD_UNUSED"),
        inbound_auth=ApiKeyAuthConfig(key_env="TEST_PARTNER_IN_KEY"),
    )


@pytest.fixture
def partners(partner):
    return PartnerRegistry([partner])


@pytest.fixture
def fingerprints(us_key, partner_key):
    return {"_self": us_key, PARTNER_NAME: partner_key}


@dataclass
class RecordingSink:
    name: str = "recording"
    durable: bool = True
    ok: bool = True
    received: list = field(default_factory=list)

    async def deliver(self, message):
        self.received.append(message)
        return SinkResult(sink_name=self.name, ok=self.ok, error=None if self.ok else "sink boom")


class FakeMessageTracker:
    def __init__(self):
        self.records: dict[uuid.UUID, MessageRecord] = {}
        self._seen: set[tuple[str, str, str]] = set()

    async def find_duplicate(self, partner_name, content_digest, direction) -> bool:
        return (partner_name, content_digest, direction) in self._seen

    async def create(self, record: MessageRecord) -> uuid.UUID:
        message_id = uuid.uuid4()
        self.records[message_id] = record
        self._seen.add((record.partner_name, record.content_digest, record.direction))
        return message_id

    async def update_status(self, message_id, *, status, error_code=None, receipt_verified=None):
        record = self.records[message_id]
        record.status = status
        record.error_code = error_code
        record.receipt_verified = receipt_verified

    async def update_sinks_status(self, message_id, sinks_status):
        self.records[message_id].sinks_status = sinks_status


@pytest.fixture
def tracker():
    return FakeMessageTracker()


@pytest.fixture
def recording_sink():
    return RecordingSink()


def build_client(settings, partners, gpg_service, fingerprints, tracker, sinks) -> TestClient:
    app = FastAPI()
    app.include_router(inbound_routes.router, prefix=settings.server.inbound_path)
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_partners] = lambda: partners
    app.dependency_overrides[get_gpg] = lambda: gpg_service
    app.dependency_overrides[get_fingerprints] = lambda: fingerprints
    app.dependency_overrides[get_tracker] = lambda: tracker
    app.dependency_overrides[get_sinks] = lambda: sinks
    return TestClient(app)


def _valid_headers(**overrides) -> dict[str, str]:
    headers = {
        "version": "4.0",
        "from-id": PARTNER_DUNS,
        "to-id": "123456789",
        "input-format": "X12",
        "transaction-set": "873",
        "authorization": "Bearer partner-inbound-key",
    }
    headers.update(overrides)
    return headers


def _encrypt(gpg_service: GpgService, us_key: str, signer_key: str, passphrase: str, payload: bytes = b"ISA*00*...") -> bytes:
    return gpg_service.encrypt_and_sign(
        payload, recipient_fingerprint=us_key, signer_fingerprint=signer_key, passphrase=passphrase
    )


def _decode_receipt(gpg_service: GpgService, us_key: str, response_body: bytes) -> Receipt:
    result = gpg_service.verify_message(response_body, expected_fingerprint=us_key)
    assert result.valid, "response was not validly signed by our own key"
    return Receipt.decode(result.plaintext.decode("utf-8"))


def test_happy_path_accepted(settings, partners, gpg_service, fingerprints, tracker, recording_sink, us_key, partner_key):
    client = build_client(settings, partners, gpg_service, fingerprints, tracker, [recording_sink])
    body = _encrypt(gpg_service, us_key, partner_key, "partner-passphrase")

    response = client.post("/inbound", headers=_valid_headers(), content=body)

    assert response.status_code == 200
    receipt = _decode_receipt(gpg_service, us_key, response.content)
    assert receipt.status.value == "success"
    assert len(recording_sink.received) == 1
    assert recording_sink.received[0].plaintext == b"ISA*00*..."
    assert any(r.status == "accepted" for r in tracker.records.values())


def test_missing_authorization_returns_plain_401(settings, partners, gpg_service, fingerprints, tracker, recording_sink, us_key, partner_key):
    client = build_client(settings, partners, gpg_service, fingerprints, tracker, [recording_sink])
    body = _encrypt(gpg_service, us_key, partner_key, "partner-passphrase")

    headers = _valid_headers()
    del headers["authorization"]
    response = client.post("/inbound", headers=headers, content=body)

    assert response.status_code == 401
    # not a signed receipt -- shouldn't even parse as one
    result = gpg_service.verify_message(response.content, expected_fingerprint=us_key)
    assert not result.valid


def test_wrong_authorization_key_returns_401(settings, partners, gpg_service, fingerprints, tracker, recording_sink, us_key, partner_key):
    client = build_client(settings, partners, gpg_service, fingerprints, tracker, [recording_sink])
    body = _encrypt(gpg_service, us_key, partner_key, "partner-passphrase")

    response = client.post("/inbound", headers=_valid_headers(authorization="Bearer wrong-key"), content=body)
    assert response.status_code == 401


def test_from_id_mismatch_rejected_as_unknown_partner(settings, partners, gpg_service, fingerprints, tracker, recording_sink, us_key, partner_key):
    client = build_client(settings, partners, gpg_service, fingerprints, tracker, [recording_sink])
    body = _encrypt(gpg_service, us_key, partner_key, "partner-passphrase")

    response = client.post("/inbound", headers=_valid_headers(**{"from-id": "000000000"}), content=body)

    assert response.status_code == 200
    receipt = _decode_receipt(gpg_service, us_key, response.content)
    assert receipt.status.value == "validation-failed"
    assert receipt.error_code.value == 104


def test_decryption_failure_rejected(settings, partners, gpg_service, fingerprints, tracker, recording_sink, us_key):
    client = build_client(settings, partners, gpg_service, fingerprints, tracker, [recording_sink])

    response = client.post("/inbound", headers=_valid_headers(), content=b"not a valid PGP message at all")

    assert response.status_code == 200
    receipt = _decode_receipt(gpg_service, us_key, response.content)
    assert receipt.status.value == "validation-failed"
    assert receipt.error_code.value == 101


def test_wrong_signer_rejected_as_signature_failure(settings, partners, gpg_service, fingerprints, tracker, recording_sink, us_key):
    client = build_client(settings, partners, gpg_service, fingerprints, tracker, [recording_sink])
    # Encrypted correctly to us, but signed by a key that isn't the partner's.
    body = _encrypt(gpg_service, us_key, us_key, "us-passphrase")

    response = client.post("/inbound", headers=_valid_headers(), content=body)

    assert response.status_code == 200
    receipt = _decode_receipt(gpg_service, us_key, response.content)
    assert receipt.status.value == "validation-failed"
    assert receipt.error_code.value == 102


def test_weak_cipher_rejected(settings, partners, gpg_service, fingerprints, tracker, recording_sink, gnupg_home, us_key, partner_key):
    # Modern GnuPG refuses to even produce a 3DES-encrypted message without
    # this override -- it's only here to construct a deliberately
    # noncompliant test payload, never used in production code.
    weak_gpg = GpgService(gnupg_home=gnupg_home, cipher_algo="3DES", digest_algo="SHA256", compress_algo="ZIP")
    result = weak_gpg.gpg.encrypt(
        b"ISA*00*...",
        recipients=[us_key],
        sign=partner_key,
        passphrase="partner-passphrase",
        always_trust=True,
        armor=False,
        extra_args=[*weak_gpg._encrypt_extra_args(), "--allow-old-cipher-algos"],
    )
    assert result.ok, f"test setup failed to build a weak-cipher payload: {result.stderr}"
    body = result.data

    client = build_client(settings, partners, gpg_service, fingerprints, tracker, [recording_sink])
    response = client.post("/inbound", headers=_valid_headers(), content=body)

    assert response.status_code == 200
    receipt = _decode_receipt(gpg_service, us_key, response.content)
    assert receipt.status.value == "validation-failed"
    assert receipt.error_code.value == 106


def test_duplicate_message_rejected_on_second_delivery(settings, partners, gpg_service, fingerprints, tracker, recording_sink, us_key, partner_key):
    client = build_client(settings, partners, gpg_service, fingerprints, tracker, [recording_sink])
    body = _encrypt(gpg_service, us_key, partner_key, "partner-passphrase")

    first = client.post("/inbound", headers=_valid_headers(), content=body)
    second = client.post("/inbound", headers=_valid_headers(), content=body)

    assert _decode_receipt(gpg_service, us_key, first.content).status.value == "success"
    second_receipt = _decode_receipt(gpg_service, us_key, second.content)
    assert second_receipt.status.value == "validation-failed"
    assert second_receipt.error_code.value == 105
    assert len(recording_sink.received) == 1  # not delivered twice


def test_sink_failure_rejected_when_no_durable_sink_succeeds(settings, partners, gpg_service, fingerprints, tracker, us_key, partner_key):
    failing_sink = RecordingSink(name="fs", durable=True, ok=False)
    client = build_client(settings, partners, gpg_service, fingerprints, tracker, [failing_sink])
    body = _encrypt(gpg_service, us_key, partner_key, "partner-passphrase")

    response = client.post("/inbound", headers=_valid_headers(), content=body)

    assert response.status_code == 200
    receipt = _decode_receipt(gpg_service, us_key, response.content)
    assert receipt.status.value == "validation-failed"
    assert receipt.error_code.value == 107


def test_missing_header_rejected_as_invalid_header_parameters(settings, partners, gpg_service, fingerprints, tracker, recording_sink, us_key, partner_key):
    client = build_client(settings, partners, gpg_service, fingerprints, tracker, [recording_sink])
    body = _encrypt(gpg_service, us_key, partner_key, "partner-passphrase")

    headers = _valid_headers()
    del headers["transaction-set"]
    response = client.post("/inbound", headers=headers, content=body)

    assert response.status_code == 200
    receipt = _decode_receipt(gpg_service, us_key, response.content)
    assert receipt.status.value == "validation-failed"
    assert receipt.error_code.value == 103
