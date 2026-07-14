import httpx
import pytest
import respx

from app.crypto.gpg_wrapper import GpgService
from app.envelope.error_codes import NaesbErrorCode
from app.envelope.receipt import NaesbReceipt, build_signed_mime
from app.outbound.client import DeliveryAttemptError, send_once
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
from app.tracking.models import OutboundJob

PARTNER_ENDPOINT = "https://partner.example.com/edi/receiver-endpoint"


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
        envelope=EnvelopeConfig(server_id="us.example.com", default_version="1.9"),
        sinks=SinksConfig(),
        internal_api=InternalApiConfig(
            username_env="TEST_INTERNAL_API_USERNAME", password_env="TEST_INTERNAL_API_PASSWORD"
        ),
        outbound=OutboundConfig(timeout_seconds=5),
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


@pytest.fixture
def job(gpg_service, us_key):
    ciphertext = gpg_service.encrypt_and_sign(
        b"ISA*00*...", recipient_fingerprint=us_key, signer_fingerprint=us_key, passphrase="us-passphrase"
    )
    return OutboundJob(
        id="job-1",
        partner_name="acme-pipeline",
        from_id="123456789",
        to_id="987654321",
        version="1.9",
        input_format="X12",
        transaction_set="NOM00001",
        payload_ciphertext=ciphertext,
        content_digest="unused",
    )


def _signed_receipt_response(
    gpg_service: GpgService, signer_key: str, passphrase: str, receipt: NaesbReceipt
) -> tuple[bytes, str]:
    report_body, report_content_type = receipt.encode_report_part()
    signature = gpg_service.detached_sign(report_body, signer_fingerprint=signer_key, passphrase=passphrase)
    return build_signed_mime(report_body, report_content_type, signature, "pgp-sha256")


@respx.mock
async def test_send_once_success(settings, partner, gpg_service, fingerprints, job, us_key, partner_key):
    receipt_body, receipt_content_type = _signed_receipt_response(
        gpg_service, partner_key, "partner-passphrase", NaesbReceipt.ok("their-host", 42)
    )
    route = respx.post(PARTNER_ENDPOINT).mock(
        return_value=httpx.Response(200, content=receipt_body, headers={"content-type": receipt_content_type})
    )

    receipt = await send_once(job, partner, settings, gpg_service, fingerprints["acme-pipeline"])

    assert receipt.is_ok
    assert receipt.trans_id == "42"
    assert route.called
    sent_request = route.calls.last.request
    assert sent_request.headers["content-type"].startswith("multipart/form-data")
    assert sent_request.headers["authorization"].startswith("Basic ")
    assert b'name="from"' in sent_request.content
    assert b"ISA*00*..." not in sent_request.content  # wire body is ciphertext, never plaintext


@respx.mock
async def test_send_once_records_partner_rejection(settings, partner, gpg_service, fingerprints, job, partner_key):
    receipt = NaesbReceipt.rejected("their-host", 1, NaesbErrorCode.INVALID_TRANSACTION_SET)
    receipt_body, receipt_content_type = _signed_receipt_response(gpg_service, partner_key, "partner-passphrase", receipt)
    respx.post(PARTNER_ENDPOINT).mock(
        return_value=httpx.Response(200, content=receipt_body, headers={"content-type": receipt_content_type})
    )

    result = await send_once(job, partner, settings, gpg_service, fingerprints["acme-pipeline"])
    assert not result.is_ok
    assert "EEDM108" in result.request_status


@respx.mock
async def test_send_once_raises_on_http_error(settings, partner, gpg_service, fingerprints, job):
    respx.post(PARTNER_ENDPOINT).mock(return_value=httpx.Response(503))

    with pytest.raises(DeliveryAttemptError):
        await send_once(job, partner, settings, gpg_service, fingerprints["acme-pipeline"])


@respx.mock
async def test_send_once_raises_on_unverifiable_receipt(settings, partner, gpg_service, fingerprints, job):
    respx.post(PARTNER_ENDPOINT).mock(return_value=httpx.Response(200, content=b"not a signed message"))

    with pytest.raises(DeliveryAttemptError):
        await send_once(job, partner, settings, gpg_service, fingerprints["acme-pipeline"])


@respx.mock
async def test_send_once_raises_when_signed_by_wrong_key(settings, partner, gpg_service, fingerprints, job, us_key):
    # Signed validly, but by *our* key, not the partner's -- the partner's
    # receipt must be signed by the partner.
    receipt_body, receipt_content_type = _signed_receipt_response(
        gpg_service, us_key, "us-passphrase", NaesbReceipt.ok("their-host", 1)
    )
    respx.post(PARTNER_ENDPOINT).mock(
        return_value=httpx.Response(200, content=receipt_body, headers={"content-type": receipt_content_type})
    )

    with pytest.raises(DeliveryAttemptError):
        await send_once(job, partner, settings, gpg_service, fingerprints["acme-pipeline"])
