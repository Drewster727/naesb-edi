import base64
import uuid
from dataclasses import dataclass, field

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from structlog.testing import capture_logs

from app.crypto.gpg_wrapper import GpgService
from app.dependencies import (
    get_fingerprints,
    get_gpg,
    get_partners,
    get_settings,
    get_sinks,
    get_tracker,
)
from app.envelope.fields import EnvelopeFields, InputFormat
from app.envelope.multipart_codec import build_multipart_body
from app.envelope.receipt import NaesbReceipt, parse_signed_mime
from app.inbound import routes as inbound_routes
from app.partners import ApiKeyAuthConfig, BasicAuthConfig, EnvelopeOverrides, PartnerConfig, PartnerRegistry
from app.settings import (
    CryptoConfig,
    EnvelopeConfig,
    IdentityConfig,
    InternalApiConfig,
    ServerConfig,
    Settings,
    SinksConfig,
)
from app.sinks.base import SinkResult
from app.tracking.models import MessageRecord

PARTNER_DUNS = "987654321"
PARTNER_NAME = "acme-pipeline"
OUR_DUNS = "123456789"
SERVER_ID = "coolhost.example.com"


@pytest.fixture
def settings(gnupg_home, monkeypatch):
    monkeypatch.setenv("TEST_US_PASSPHRASE", "us-passphrase")
    return Settings(
        identity=IdentityConfig(name="MyCompany", duns=OUR_DUNS),
        server=ServerConfig(inbound_path="/inbound", max_body_size_bytes=26_214_400),
        crypto=CryptoConfig(
            private_key_path="unused",
            passphrase_env="TEST_US_PASSPHRASE",
            gnupg_home=gnupg_home,
            cipher_algo="AES256",
            digest_algo="SHA256",
            compress_algo="ZIP",
        ),
        envelope=EnvelopeConfig(server_id=SERVER_ID, default_version="1.9"),
        sinks=SinksConfig(require_at_least_one_durable_success=True),
        internal_api=InternalApiConfig(
            username_env="TEST_INTERNAL_API_USERNAME", password_env="TEST_INTERNAL_API_PASSWORD"
        ),
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
def refnum_partner(monkeypatch):
    monkeypatch.setenv("TEST_REFNUM_PARTNER_IN_KEY", "refnum-partner-inbound-key")
    return PartnerConfig(
        name="refnum-pipeline",
        duns="111222333",
        endpoint_url="https://refnum-partner.example.com/edi/receiver-endpoint",
        pgp_public_key_path="unused",
        outbound_auth=BasicAuthConfig(username="u", password_env="TEST_REFNUM_PARTNER_OUT_PW_UNUSED"),
        inbound_auth=ApiKeyAuthConfig(key_env="TEST_REFNUM_PARTNER_IN_KEY"),
        envelope_overrides=EnvelopeOverrides(use_refnum=True),
    )


@pytest.fixture
def unsigned_ok_partner(monkeypatch):
    """A partner with a documented, accepted gap: their real system doesn't
    PGP-sign outbound messages at all (mirrors OpenAS2's
    reject_unsigned_messages="false", see partners.yaml's require_signature)."""
    monkeypatch.setenv("TEST_UNSIGNED_PARTNER_IN_KEY", "unsigned-partner-inbound-key")
    return PartnerConfig(
        name="unsigned-ok-pipeline",
        duns="444555666",
        endpoint_url="https://unsigned-partner.example.com/edi/receiver-endpoint",
        pgp_public_key_path="unused",
        outbound_auth=BasicAuthConfig(username="u", password_env="TEST_UNSIGNED_PARTNER_OUT_PW_UNUSED"),
        inbound_auth=ApiKeyAuthConfig(key_env="TEST_UNSIGNED_PARTNER_IN_KEY"),
        require_signature=False,
    )


@pytest.fixture
def partners(partner):
    return PartnerRegistry([partner])


@pytest.fixture
def fingerprints(us_key, partner_key):
    return {
        "_self": us_key,
        PARTNER_NAME: partner_key,
        "refnum-pipeline": partner_key,
        "unsigned-ok-pipeline": partner_key,
    }


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
        self._seen_digest: set[tuple[str, str, str]] = set()
        self._seen_refnum: set[tuple[str, str, str]] = set()
        self._next_trans_id = 0

    async def next_trans_id(self) -> int:
        self._next_trans_id += 1
        return self._next_trans_id

    async def find_duplicate(self, partner_name, content_digest, direction) -> bool:
        return (partner_name, content_digest, direction) in self._seen_digest

    async def find_refnum_reuse(self, partner_name, refnum, direction) -> bool:
        return (partner_name, refnum, direction) in self._seen_refnum

    async def create(self, record: MessageRecord) -> uuid.UUID:
        message_id = uuid.uuid4()
        self.records[message_id] = record
        self._seen_digest.add((record.partner_name, record.content_digest, record.direction))
        if record.refnum:
            self._seen_refnum.add((record.partner_name, record.refnum, record.direction))
        return message_id

    async def update_status(self, message_id, *, status, error_code=None, receipt_verified=None, **_kwargs):
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


def _envelope_fields(**overrides) -> EnvelopeFields:
    defaults = dict(
        from_id=PARTNER_DUNS,
        to_id=OUR_DUNS,
        version="1.9",
        receipt_disposition_to=PARTNER_DUNS,
        input_format=InputFormat.X12,
        receipt_security_selection="signed-receipt-protocol=required,pgp-signature;signed-receipt-micalg=required,sha256",
        transaction_set="NOM00001",
    )
    defaults.update(overrides)
    return EnvelopeFields(**defaults)


def _build_body(
    gpg_service: GpgService,
    us_key: str,
    signer_key: str,
    passphrase: str,
    payload: bytes = b"ISA*00*...",
    fields: EnvelopeFields | None = None,
) -> tuple[bytes, str]:
    ciphertext = gpg_service.encrypt_and_sign(
        payload, recipient_fingerprint=us_key, signer_fingerprint=signer_key, passphrase=passphrase
    )
    return build_multipart_body(fields or _envelope_fields(), ciphertext)


def _auth_headers(**overrides) -> dict[str, str]:
    headers = {"authorization": "Bearer partner-inbound-key"}
    headers.update(overrides)
    return headers


def _decode_receipt(gpg_service: GpgService, us_key: str, response) -> NaesbReceipt:
    content_type = response.headers["content-type"]
    report_body, report_content_type, signature = parse_signed_mime(response.content, content_type)
    result = gpg_service.verify_detached(report_body, signature, expected_fingerprint=us_key)
    assert result.valid, "response was not validly signed by our own key"
    return NaesbReceipt.decode_report_part(report_body, report_content_type)


def test_happy_path_accepted(settings, partners, gpg_service, fingerprints, tracker, recording_sink, us_key, partner_key):
    client = build_client(settings, partners, gpg_service, fingerprints, tracker, [recording_sink])
    body, content_type = _build_body(gpg_service, us_key, partner_key, "partner-passphrase")

    response = client.post("/inbound", headers={**_auth_headers(), "content-type": content_type}, content=body)

    assert response.status_code == 200
    receipt = _decode_receipt(gpg_service, us_key, response)
    assert receipt.is_ok
    assert receipt.server_id == SERVER_ID
    assert len(recording_sink.received) == 1
    assert recording_sink.received[0].plaintext == b"ISA*00*..."
    assert any(r.status == "accepted" for r in tracker.records.values())


def test_missing_authorization_returns_plain_401(settings, partners, gpg_service, fingerprints, tracker, recording_sink, us_key, partner_key):
    client = build_client(settings, partners, gpg_service, fingerprints, tracker, [recording_sink])
    body, content_type = _build_body(gpg_service, us_key, partner_key, "partner-passphrase")

    response = client.post("/inbound", headers={"content-type": content_type}, content=body)

    assert response.status_code == 401
    # not a signed receipt -- shouldn't even parse as one
    with pytest.raises(Exception):
        _decode_receipt(gpg_service, us_key, response)


def test_wrong_authorization_key_returns_401(settings, partners, gpg_service, fingerprints, tracker, recording_sink, us_key, partner_key):
    client = build_client(settings, partners, gpg_service, fingerprints, tracker, [recording_sink])
    body, content_type = _build_body(gpg_service, us_key, partner_key, "partner-passphrase")

    response = client.post(
        "/inbound",
        headers={**_auth_headers(authorization="Bearer wrong-key"), "content-type": content_type},
        content=body,
    )
    assert response.status_code == 401


def test_from_mismatch_rejected_as_sender_not_associated(settings, partners, gpg_service, fingerprints, tracker, recording_sink, us_key, partner_key):
    client = build_client(settings, partners, gpg_service, fingerprints, tracker, [recording_sink])
    body, content_type = _build_body(
        gpg_service, us_key, partner_key, "partner-passphrase", fields=_envelope_fields(from_id="000000000")
    )

    response = client.post("/inbound", headers={**_auth_headers(), "content-type": content_type}, content=body)

    assert response.status_code == 200
    receipt = _decode_receipt(gpg_service, us_key, response)
    assert not receipt.is_ok
    assert receipt.request_status.startswith("EEDM701")


def test_to_mismatch_rejected_as_invalid_to(settings, partners, gpg_service, fingerprints, tracker, recording_sink, us_key, partner_key):
    client = build_client(settings, partners, gpg_service, fingerprints, tracker, [recording_sink])
    body, content_type = _build_body(
        gpg_service, us_key, partner_key, "partner-passphrase", fields=_envelope_fields(to_id="000000000")
    )

    response = client.post("/inbound", headers={**_auth_headers(), "content-type": content_type}, content=body)

    assert response.status_code == 200
    receipt = _decode_receipt(gpg_service, us_key, response)
    assert not receipt.is_ok
    assert receipt.request_status.startswith("EEDM106")


def test_to_missing_leading_zero_normalized_and_accepted(
    settings, partners, gpg_service, fingerprints, tracker, recording_sink, us_key, partner_key
):
    # Our real DUNS has a leading zero; a sender whose system dropped it
    # (e.g. treated the value as an integer) should still be recognized.
    padded_settings = settings.model_copy(
        update={"identity": IdentityConfig(name="MyCompany", duns="023456789")}
    )
    client = build_client(padded_settings, partners, gpg_service, fingerprints, tracker, [recording_sink])
    body, content_type = _build_body(
        gpg_service, us_key, partner_key, "partner-passphrase", fields=_envelope_fields(to_id="23456789")
    )

    response = client.post("/inbound", headers={**_auth_headers(), "content-type": content_type}, content=body)

    assert response.status_code == 200
    receipt = _decode_receipt(gpg_service, us_key, response)
    assert receipt.is_ok


def test_from_missing_leading_zero_normalized_and_accepted(
    settings, gpg_service, fingerprints, tracker, recording_sink, us_key, partner_key, monkeypatch
):
    # Same normalization applies to a partner's DUNS with a leading zero.
    monkeypatch.setenv("TEST_PADDED_PARTNER_IN_KEY", "padded-partner-inbound-key")
    padded_partner = PartnerConfig(
        name="padded-duns-pipeline",
        duns="087654321",
        endpoint_url="https://padded-partner.example.com/edi/receiver-endpoint",
        pgp_public_key_path="unused",
        outbound_auth=BasicAuthConfig(username="u", password_env="TEST_PADDED_PARTNER_OUT_PW_UNUSED"),
        inbound_auth=ApiKeyAuthConfig(key_env="TEST_PADDED_PARTNER_IN_KEY"),
    )
    padded_partners = PartnerRegistry([padded_partner])
    padded_fingerprints = {**fingerprints, "padded-duns-pipeline": partner_key}
    client = build_client(settings, padded_partners, gpg_service, padded_fingerprints, tracker, [recording_sink])
    body, content_type = _build_body(
        gpg_service, us_key, partner_key, "partner-passphrase", fields=_envelope_fields(from_id="87654321")
    )

    response = client.post(
        "/inbound",
        headers={
            **_auth_headers(authorization="Bearer padded-partner-inbound-key"),
            "content-type": content_type,
        },
        content=body,
    )

    assert response.status_code == 200
    receipt = _decode_receipt(gpg_service, us_key, response)
    assert receipt.is_ok


def test_decryption_failure_rejected(settings, partners, gpg_service, fingerprints, tracker, recording_sink, us_key):
    client = build_client(settings, partners, gpg_service, fingerprints, tracker, [recording_sink])
    body, content_type = build_multipart_body(_envelope_fields(), b"not a valid PGP message at all")

    response = client.post("/inbound", headers={**_auth_headers(), "content-type": content_type}, content=body)

    assert response.status_code == 200
    receipt = _decode_receipt(gpg_service, us_key, response)
    assert not receipt.is_ok
    assert receipt.request_status.startswith("EEDM699")


def test_wrong_signer_rejected_as_signature_failure(settings, partners, gpg_service, fingerprints, tracker, recording_sink, us_key):
    client = build_client(settings, partners, gpg_service, fingerprints, tracker, [recording_sink])
    # Encrypted correctly to us, but signed by a key that isn't the partner's.
    body, content_type = _build_body(gpg_service, us_key, us_key, "us-passphrase")

    response = client.post("/inbound", headers={**_auth_headers(), "content-type": content_type}, content=body)

    assert response.status_code == 200
    receipt = _decode_receipt(gpg_service, us_key, response)
    assert not receipt.is_ok
    assert receipt.request_status.startswith("EEDM604")


def test_unsigned_message_accepted_when_signature_not_required(
    settings, gpg_service, fingerprints, tracker, recording_sink, us_key, unsigned_ok_partner
):
    partners = PartnerRegistry([unsigned_ok_partner])
    client = build_client(settings, partners, gpg_service, fingerprints, tracker, [recording_sink])
    fields = _envelope_fields(from_id=unsigned_ok_partner.duns)
    encrypt_result = gpg_service.gpg.encrypt(
        b"ISA*00*...", recipients=[us_key], sign=None, always_trust=True, armor=False
    )
    assert encrypt_result.ok, f"encrypt-only failed: {encrypt_result.status}"
    body, content_type = build_multipart_body(fields, encrypt_result.data)
    headers = {"authorization": "Bearer unsigned-partner-inbound-key", "content-type": content_type}

    response = client.post("/inbound", headers=headers, content=body)

    assert response.status_code == 200
    receipt = _decode_receipt(gpg_service, us_key, response)
    assert receipt.is_ok, receipt.request_status
    assert len(recording_sink.received) == 1
    (record,) = tracker.records.values()
    assert record.status == "accepted"
    assert record.receipt_verified is False  # accepted despite no verifiable signature


def test_weak_cipher_rejected(settings, partners, gpg_service, fingerprints, tracker, recording_sink, gnupg_home, us_key, partner_key):
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
    body, content_type = build_multipart_body(_envelope_fields(), result.data)

    client = build_client(settings, partners, gpg_service, fingerprints, tracker, [recording_sink])
    response = client.post("/inbound", headers={**_auth_headers(), "content-type": content_type}, content=body)

    assert response.status_code == 200
    receipt = _decode_receipt(gpg_service, us_key, response)
    assert not receipt.is_ok
    assert "GWX-WEAK-ALGO" in receipt.request_status


def test_duplicate_message_rejected_on_second_delivery(settings, partners, gpg_service, fingerprints, tracker, recording_sink, us_key, partner_key):
    client = build_client(settings, partners, gpg_service, fingerprints, tracker, [recording_sink])
    body, content_type = _build_body(gpg_service, us_key, partner_key, "partner-passphrase")

    first = client.post("/inbound", headers={**_auth_headers(), "content-type": content_type}, content=body)
    second = client.post("/inbound", headers={**_auth_headers(), "content-type": content_type}, content=body)

    assert _decode_receipt(gpg_service, us_key, first).is_ok
    second_receipt = _decode_receipt(gpg_service, us_key, second)
    assert not second_receipt.is_ok
    assert "GWX-DUPLICATE-DIGEST" in second_receipt.request_status
    assert len(recording_sink.received) == 1  # not delivered twice


def test_duplicate_refnum_rejected_for_refnum_partner(settings, gpg_service, fingerprints, tracker, recording_sink, us_key, partner_key, refnum_partner):
    partners = PartnerRegistry([refnum_partner])
    client = build_client(settings, partners, gpg_service, fingerprints, tracker, [recording_sink])
    fields = _envelope_fields(from_id=refnum_partner.duns, refnum="1", refnum_orig="1")
    body, content_type = _build_body(gpg_service, us_key, partner_key, "partner-passphrase", fields=fields)
    headers = {"authorization": "Bearer refnum-partner-inbound-key", "content-type": content_type}

    first = client.post("/inbound", headers=headers, content=body)
    second = client.post("/inbound", headers=headers, content=body)

    assert _decode_receipt(gpg_service, us_key, first).is_ok
    second_receipt = _decode_receipt(gpg_service, us_key, second)
    assert "EEDM121" in second_receipt.request_status


def test_refnum_required_when_partner_uses_refnum(settings, gpg_service, fingerprints, tracker, recording_sink, us_key, partner_key, refnum_partner):
    partners = PartnerRegistry([refnum_partner])
    client = build_client(settings, partners, gpg_service, fingerprints, tracker, [recording_sink])
    fields = _envelope_fields(from_id=refnum_partner.duns)  # no refnum
    body, content_type = _build_body(gpg_service, us_key, partner_key, "partner-passphrase", fields=fields)
    headers = {"authorization": "Bearer refnum-partner-inbound-key", "content-type": content_type}

    response = client.post("/inbound", headers=headers, content=body)
    receipt = _decode_receipt(gpg_service, us_key, response)
    assert "EEDM119" in receipt.request_status


def test_sink_failure_rejected_when_no_durable_sink_succeeds(settings, partners, gpg_service, fingerprints, tracker, us_key, partner_key):
    failing_sink = RecordingSink(name="fs", durable=True, ok=False)
    client = build_client(settings, partners, gpg_service, fingerprints, tracker, [failing_sink])
    body, content_type = _build_body(gpg_service, us_key, partner_key, "partner-passphrase")

    response = client.post("/inbound", headers={**_auth_headers(), "content-type": content_type}, content=body)

    assert response.status_code == 200
    receipt = _decode_receipt(gpg_service, us_key, response)
    assert not receipt.is_ok
    assert "GWX-SINK-FAILURE" in receipt.request_status


def test_realistic_partner_shape_sha1_armored_dash_boundary_accepted(
    settings, partners, gpg_service, fingerprints, tracker, recording_sink, gnupg_home, us_key, partner_key
):
    """Reproduces the structural quirks consistently seen in real
    trading-partner captures (samples/request-ssc-*.txt), none of which our
    own build_multipart_body()/wrap_pgp_encrypted() ever exercise: a SHA1
    signature digest, ASCII-armored (not armor-less) ciphertext, an inner
    multipart/encrypted boundary containing an embedded "--", no
    content-transfer-encoding header on the octet-stream part, and
    input-data placed last in the outer field order. We can't decrypt the
    real captures (no real private key for that DUNS), so this proves the
    pipeline accepts a message shaped exactly like theirs using test keys,
    relying on the crypto.allowed_digests default (which now includes SHA1)
    rather than a partner-specific override."""
    sha1_gpg = GpgService(gnupg_home=gnupg_home, cipher_algo="AES256", digest_algo="SHA1", compress_algo="ZIP")
    result = sha1_gpg.gpg.encrypt(
        b"ISA*00*...",
        recipients=[us_key],
        sign=partner_key,
        passphrase="partner-passphrase",
        always_trust=True,
        armor=True,
        extra_args=[*sha1_gpg._encrypt_extra_args(), "--allow-weak-digest-algos"],
    )
    assert result.ok, f"test setup failed to build a SHA1/armored payload: {result.stderr}"
    armored_ciphertext = bytes(result.data)
    assert armored_ciphertext.startswith(b"-----BEGIN PGP MESSAGE-----")

    inner_boundary = "--boundary2--test-dash-boundary"
    inner_body = (
        f"--{inner_boundary}\r\n"
        "content-type: application/pgp-encrypted\r\n\r\n"
        "Version: 1.46\r\n"
        f"--{inner_boundary}\r\n"
        "content-type: application/octet-stream\r\n\r\n"
    ).encode() + armored_ciphertext + f"\r\n--{inner_boundary}--\r\n".encode()
    inner_content_type = f'multipart/encrypted; boundary={inner_boundary}; protocol="application/pgp-encrypted"'

    fields = _envelope_fields(
        receipt_security_selection=(
            "signed-receipt-protocol=required,pgp-signature; signed-receipt-micalg=required,sha1"
        )
    )
    outer_boundary = "outerBoundary--test5"

    def field_part(name: str, value: str) -> bytes:
        return f'--{outer_boundary}\r\ncontent-disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode()

    input_data_part = (
        f'--{outer_boundary}\r\ncontent-disposition: form-data; name="input-data"; filename="test.dat"\r\n'
        f"content-type: {inner_content_type}\r\n\r\n"
    ).encode() + inner_body

    body = (
        field_part("from", fields.from_id)
        + field_part("to", fields.to_id)
        + field_part("version", fields.version)
        + field_part("receipt-disposition-to", fields.receipt_disposition_to)
        + field_part("receipt-report-type", fields.receipt_report_type)
        + field_part("input-format", fields.input_format.value)
        + field_part("receipt-security-selection", fields.receipt_security_selection)
        + field_part("transaction-set", fields.transaction_set)
        + input_data_part
        + f"--{outer_boundary}--\r\n".encode()
    )
    content_type = f"multipart/form-data; boundary={outer_boundary}"

    client = build_client(settings, partners, gpg_service, fingerprints, tracker, [recording_sink])
    response = client.post("/inbound", headers={**_auth_headers(), "content-type": content_type}, content=body)

    assert response.status_code == 200
    receipt = _decode_receipt(gpg_service, us_key, response)
    assert receipt.is_ok, receipt.request_status
    assert len(recording_sink.received) == 1
    assert recording_sink.received[0].plaintext == b"ISA*00*..."


def test_missing_field_rejected_with_exact_eedm_code(settings, partners, gpg_service, fingerprints, tracker, recording_sink, us_key, partner_key):
    client = build_client(settings, partners, gpg_service, fingerprints, tracker, [recording_sink])
    body, content_type = _build_body(gpg_service, us_key, partner_key, "partner-passphrase")
    corrupted = body.replace(b'name="receipt-disposition-to"', b'name="receipt-disposition-to-x"')

    response = client.post("/inbound", headers={**_auth_headers(), "content-type": content_type}, content=corrupted)

    assert response.status_code == 200
    receipt = _decode_receipt(gpg_service, us_key, response)
    assert not receipt.is_ok
    assert receipt.request_status.startswith("EEDM114")  # missing 'receipt-disposition-to'


def test_trans_id_is_sequential(settings, partners, gpg_service, fingerprints, tracker, recording_sink, us_key, partner_key):
    client = build_client(settings, partners, gpg_service, fingerprints, tracker, [recording_sink])
    body1, ct1 = _build_body(gpg_service, us_key, partner_key, "partner-passphrase", payload=b"first")
    body2, ct2 = _build_body(gpg_service, us_key, partner_key, "partner-passphrase", payload=b"second")

    r1 = client.post("/inbound", headers={**_auth_headers(), "content-type": ct1}, content=body1)
    r2 = client.post("/inbound", headers={**_auth_headers(), "content-type": ct2}, content=body2)

    receipt1 = _decode_receipt(gpg_service, us_key, r1)
    receipt2 = _decode_receipt(gpg_service, us_key, r2)
    assert int(receipt2.trans_id) == int(receipt1.trans_id) + 1


def test_raw_request_logged_with_authorization_redacted(settings, partners, gpg_service, fingerprints, tracker, recording_sink, us_key, partner_key):
    client = build_client(settings, partners, gpg_service, fingerprints, tracker, [recording_sink])
    body, content_type = _build_body(gpg_service, us_key, partner_key, "partner-passphrase")

    with capture_logs() as logs:
        client.post("/inbound", headers={**_auth_headers(), "content-type": content_type}, content=body)

    raw_events = [e for e in logs if e["event"] == "inbound_raw_request"]
    assert len(raw_events) == 1
    event = raw_events[0]
    assert event["method"] == "POST"
    assert event["headers"]["authorization"] == "[REDACTED]"
    assert base64.b64decode(event["body_base64"]) == body
    assert event["body_length"] == len(body)


def test_raw_request_logged_even_when_auth_fails(settings, partners, gpg_service, fingerprints, tracker, recording_sink, us_key, partner_key):
    client = build_client(settings, partners, gpg_service, fingerprints, tracker, [recording_sink])
    body, content_type = _build_body(gpg_service, us_key, partner_key, "partner-passphrase")

    with capture_logs() as logs:
        response = client.post("/inbound", headers={"content-type": content_type}, content=body)

    assert response.status_code == 401
    assert any(e["event"] == "inbound_raw_request" for e in logs)


def test_raw_request_capture_disabled_via_config(settings, partners, gpg_service, fingerprints, tracker, recording_sink, us_key, partner_key):
    settings_disabled = settings.model_copy(
        update={"logging": settings.logging.model_copy(update={"capture_raw_requests": False})}
    )
    client = build_client(settings_disabled, partners, gpg_service, fingerprints, tracker, [recording_sink])
    body, content_type = _build_body(gpg_service, us_key, partner_key, "partner-passphrase")

    with capture_logs() as logs:
        client.post("/inbound", headers={**_auth_headers(), "content-type": content_type}, content=body)

    assert not any(e["event"] == "inbound_raw_request" for e in logs)
