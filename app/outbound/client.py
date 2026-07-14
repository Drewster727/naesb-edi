import base64
import ssl

import httpx
import structlog

from app.crypto.gpg_wrapper import GpgService
from app.crypto.policy import WeakAlgorithmError, enforce_digest_policy
from app.envelope.fields import RECEIPT_REPORT_TYPE_LITERAL, EnvelopeFields, InputFormat
from app.envelope.multipart_codec import build_multipart_body
from app.envelope.receipt import NaesbReceipt, ReceiptDecodeError, parse_signed_mime
from app.partners import ApiKeyAuthConfig, BasicAuthConfig, PartnerConfig
from app.settings import Settings
from app.tracking.models import OutboundJob

logger = structlog.get_logger()


class DeliveryAttemptError(Exception):
    """A single delivery attempt failed (network/HTTP error, or the
    partner's receipt couldn't be verified/decoded). The caller (the
    worker) decides whether to retry or declare an Exchange Failure based
    on the job's remaining retry schedule."""


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


def envelope_fields_from_job(job: OutboundJob, settings: Settings) -> EnvelopeFields:
    return EnvelopeFields(
        from_id=job.from_id,
        to_id=job.to_id,
        version=job.version,
        receipt_disposition_to=job.from_id,
        receipt_report_type=RECEIPT_REPORT_TYPE_LITERAL,
        input_format=InputFormat(job.input_format),
        receipt_security_selection=settings.envelope.receipt_security_selection,
        transaction_set=job.transaction_set,
        refnum=job.refnum,
        refnum_orig=job.refnum_orig,
    )


async def send_once(
    job: OutboundJob,
    partner: PartnerConfig,
    settings: Settings,
    gpg: GpgService,
    partner_fingerprint: str,
) -> NaesbReceipt:
    """Perform exactly one delivery attempt: build the ordered
    `multipart/form-data` request, POST it, and verify + decode the
    partner's `multipart/signed` `gisb-acknowledgement-receipt` response.
    Raises DeliveryAttemptError on any failure -- retry/Exchange-Failure
    decisions live in the caller (app/worker.py)."""
    fields = envelope_fields_from_job(job, settings)
    body, content_type = build_multipart_body(fields, job.payload_ciphertext)

    headers = {"content-type": content_type}
    headers.update(_auth_header(partner.outbound_auth))

    transport = _build_transport(settings)
    try:
        async with httpx.AsyncClient(
            timeout=settings.outbound.timeout_seconds, transport=transport
        ) as client:
            response = await client.post(partner.endpoint_url, headers=headers, content=body)
            response.raise_for_status()
    except httpx.HTTPError as exc:
        raise DeliveryAttemptError(f"HTTP request failed: {exc}") from exc

    response_content_type = response.headers.get("content-type", "")
    try:
        report_body, report_content_type, signature = parse_signed_mime(
            response.content, response_content_type
        )
    except ReceiptDecodeError as exc:
        raise DeliveryAttemptError(
            f"partner response was not a valid multipart/signed receipt: {exc}"
        ) from exc

    verify_result = gpg.verify_detached(report_body, signature, partner_fingerprint)
    if not verify_result.valid:
        raise DeliveryAttemptError("partner receipt signature missing or invalid")

    try:
        enforce_digest_policy(verify_result.algo_info.hash_algo, {settings.crypto.digest_algo})
    except WeakAlgorithmError as exc:
        raise DeliveryAttemptError(f"partner receipt used a weak digest algorithm: {exc}") from exc

    try:
        return NaesbReceipt.decode_report_part(report_body, report_content_type)
    except ReceiptDecodeError as exc:
        raise DeliveryAttemptError(f"partner receipt body was not decodable: {exc}") from exc
