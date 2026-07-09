import base64
import hashlib
import ssl
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx
import structlog
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_fixed

from app.crypto.gpg_wrapper import GpgService
from app.crypto.policy import WeakAlgorithmError, enforce_digest_policy
from app.envelope.codec import build_headers
from app.envelope.fields import EnvelopeFields, InputFormat
from app.envelope.mapping import merge
from app.envelope.receipt import Receipt as ReceiptModel
from app.envelope.receipt import ReceiptDecodeError, ReceiptStatus
from app.partners import ApiKeyAuthConfig, BasicAuthConfig, PartnerConfig
from app.settings import Settings
from app.tracking.models import MessageRecord
from app.tracking.repository import MessageTracker

logger = structlog.get_logger()


class OutboundDeliveryError(Exception):
    """Raised when a transmission could not be delivered and confirmed after
    all retry attempts. The message may or may not have reached the partner --
    the receipt was never verified, so it must be treated as unacknowledged."""


class ReceiptUnverifiedError(Exception):
    """Internal signal to trigger a retry: got an HTTP response, but its
    signature didn't verify (or verified but wasn't decodable), so we can't
    trust whatever `receipt-status` it claims."""


@dataclass
class SendResult:
    receipt: ReceiptModel
    message_id: uuid.UUID


def _build_transport(settings: Settings) -> httpx.AsyncHTTPTransport:
    ctx = ssl.create_default_context()
    ctx.minimum_version = (
        ssl.TLSVersion.TLSv1_3 if settings.crypto.tls_min_version == "1.3" else ssl.TLSVersion.TLSv1_2
    )
    kwargs: dict[str, object] = {"verify": ctx}
    if settings.server.outbound_source_address:
        kwargs["local_address"] = settings.server.outbound_source_address
    return httpx.AsyncHTTPTransport(**kwargs)


def _auth_header(auth: BasicAuthConfig | ApiKeyAuthConfig) -> dict[str, str]:
    if isinstance(auth, BasicAuthConfig):
        token = base64.b64encode(f"{auth.username}:{auth.password}".encode()).decode("ascii")
        return {"authorization": f"Basic {token}"}
    return {"authorization": f"Bearer {auth.key}"}


async def send_message(
    partner: PartnerConfig,
    payload: bytes,
    input_format: InputFormat,
    transaction_set: str,
    settings: Settings,
    gpg: GpgService,
    fingerprints: dict[str, str],
    tracker: MessageTracker,
) -> SendResult:
    fields = EnvelopeFields(
        version=settings.envelope.default_version,
        from_id=settings.identity.duns,
        to_id=partner.duns,
        input_format=input_format,
        transaction_set=transaction_set,
    )
    mapping = merge(
        settings.envelope.header_mapping,
        partner.envelope_overrides.header_mapping if partner.envelope_overrides else None,
    )
    headers = build_headers(fields, mapping)
    headers["content-type"] = "application/octet-stream"
    headers.update(_auth_header(partner.outbound_auth))

    # Encrypt once; the same ciphertext (and thus the same content digest) is
    # reused across every retry attempt so partner-side dedup still works.
    encrypted = gpg.encrypt_and_sign(
        payload,
        recipient_fingerprint=fingerprints[partner.name],
        signer_fingerprint=fingerprints["_self"],
        passphrase=settings.crypto.passphrase,
    )
    content_digest = hashlib.sha256(encrypted).hexdigest()

    record = MessageRecord(
        direction="outbound",
        partner_name=partner.name,
        content_digest=content_digest,
        transaction_set=transaction_set,
        input_format=input_format.value,
        status="sending",
        sent_at=datetime.now(UTC),
    )
    message_id = await tracker.create(record)

    sender = _retrying_sender(settings)
    try:
        receipt = await sender(partner, headers, encrypted, settings, gpg, fingerprints[partner.name])
    except (httpx.HTTPError, ReceiptUnverifiedError) as exc:
        logger.error("outbound_unacknowledged", partner=partner.name, digest=content_digest, error=str(exc))
        await tracker.update_status(message_id, status="unacknowledged", receipt_verified=False)
        raise OutboundDeliveryError(str(exc)) from exc

    if receipt.status == ReceiptStatus.SUCCESS:
        await tracker.update_status(message_id, status="delivered", receipt_verified=True)
    else:
        logger.warning(
            "outbound_rejected_by_partner",
            partner=partner.name,
            digest=content_digest,
            error_code=receipt.error_code,
        )
        await tracker.update_status(
            message_id,
            status="failed_nack",
            error_code=receipt.error_code.value if receipt.error_code else None,
            receipt_verified=True,
        )

    return SendResult(receipt=receipt, message_id=message_id)


def _retrying_sender(settings: Settings):
    @retry(
        stop=stop_after_attempt(settings.outbound.retry_max_attempts),
        wait=wait_fixed(settings.outbound.retry_backoff_seconds),
        retry=retry_if_exception_type((httpx.HTTPError, ReceiptUnverifiedError)),
        reraise=True,
    )
    async def _send(
        partner: PartnerConfig,
        headers: dict[str, str],
        encrypted: bytes,
        settings: Settings,
        gpg: GpgService,
        partner_fingerprint: str,
    ) -> ReceiptModel:
        transport = _build_transport(settings)
        async with httpx.AsyncClient(timeout=settings.outbound.timeout_seconds, transport=transport) as client:
            response = await client.post(partner.endpoint_url, headers=headers, content=encrypted)
            response.raise_for_status()
        raw_response = response.content

        verify_result = gpg.verify_message(raw_response, partner_fingerprint)
        if not verify_result.valid:
            raise ReceiptUnverifiedError("partner receipt signature missing or invalid")

        try:
            enforce_digest_policy(verify_result.algo_info.hash_algo, {settings.crypto.digest_algo})
        except WeakAlgorithmError as exc:
            raise ReceiptUnverifiedError(f"partner receipt used a weak digest algorithm: {exc}") from exc

        try:
            return ReceiptModel.decode(verify_result.plaintext.decode("utf-8"))
        except (ReceiptDecodeError, UnicodeDecodeError) as exc:
            raise ReceiptUnverifiedError(f"partner receipt body was not decodable: {exc}") from exc

    return _send
