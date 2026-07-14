import base64
import hashlib
from collections.abc import Mapping
from datetime import UTC, datetime

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from psycopg.errors import UniqueViolation

from app.crypto.gpg_wrapper import GpgService
from app.crypto.policy import WeakAlgorithmError, enforce_policy
from app.dependencies import (
    get_fingerprints,
    get_gpg,
    get_partners,
    get_settings,
    get_sinks,
    get_tracker,
)
from app.envelope.error_codes import ErrorCode, GatewayExtensionCode, NaesbErrorCode, error_code_for_field
from app.envelope.multipart_codec import EnvelopeError, parse_multipart_form
from app.envelope.receipt import NaesbReceipt, build_signed_mime
from app.inbound.auth import authenticate_inbound
from app.message import InboundMessage
from app.partners import PartnerRegistry
from app.settings import Settings
from app.sinks.base import Sink
from app.sinks.dispatcher import fan_out, has_durable_success
from app.tracking.models import MessageRecord
from app.tracking.repository import MessageTracker

logger = structlog.get_logger()

router = APIRouter()


@router.post("")
async def receive(
    request: Request,
    settings: Settings = Depends(get_settings),
    partners: PartnerRegistry = Depends(get_partners),
    gpg: GpgService = Depends(get_gpg),
    fingerprints: dict[str, str] = Depends(get_fingerprints),
    tracker: MessageTracker = Depends(get_tracker),
    sinks: list[Sink] = Depends(get_sinks),
) -> Response:
    content_length = request.headers.get("content-length")
    if content_length is not None and int(content_length) > settings.server.max_body_size_bytes:
        raise HTTPException(status_code=413, detail="payload too large")

    body = await request.body()
    # Standard 12.3.5: the Receiver generates the receipt timestamp
    # immediately upon successful receipt of a complete file, prior to any
    # further processing (auth, parsing, decryption).
    received_at = datetime.now(UTC)

    if len(body) > settings.server.max_body_size_bytes:
        raise HTTPException(status_code=413, detail="payload too large")

    if settings.logging.capture_raw_requests:
        logger.info(
            "inbound_raw_request",
            method=request.method,
            path=request.url.path,
            query_params=dict(request.query_params),
            headers=_redact_headers(request.headers),
            body_base64=base64.b64encode(body).decode("ascii"),
            body_length=len(body),
        )

    # Step 1: transport-level auth, before any GPG work. Fails closed with a
    # plain (unsigned) HTTP error -- this is not a protocol-level NACK. HTTP
    # Basic Authentication over TLS *is* a real NAESB requirement (standards
    # 12.3.14/12.3.28/12.3.29); see app/inbound/auth.py for the (gateway-only)
    # Bearer/API-key alternative.
    partner = authenticate_inbound(request.headers.get("authorization"), partners)
    if partner is None:
        raise HTTPException(status_code=401, detail="unauthorized")

    # trans-id is "assigned by the Server upon processing before being
    # passed to the decryption process" -- assign it once we know who's
    # authenticated, and reuse it across every receipt path below.
    trans_id = await tracker.next_trans_id()

    def reject(code: ErrorCode, message: str | None = None) -> Response:
        logger.info(
            "inbound_rejected", partner=partner.name, trans_id=trans_id, error_code=code.value
        )
        receipt = NaesbReceipt.rejected(
            settings.envelope.server_id, trans_id, code, message, time_c=received_at
        )
        return _signed_receipt(gpg, fingerprints, settings, receipt)

    # Step 2: parse the multipart/form-data envelope + unwrap input-data.
    try:
        form = await request.form()
        fields, ciphertext = await parse_multipart_form(form)
    except EnvelopeError as exc:
        code = error_code_for_field(exc.field, exc.problem)
        return reject(code, str(exc))
    except Exception as exc:  # noqa: BLE001 - malformed multipart body entirely
        return reject(NaesbErrorCode.NO_PARAMETERS_SUPPLIED, f"malformed multipart body: {exc}")

    # Step 3: the authenticated partner's DUNS must match the claimed 'from'.
    if fields.from_id != partner.duns:
        return reject(
            NaesbErrorCode.SENDER_NOT_ASSOCIATED, "'from' does not match the authenticated partner"
        )

    if partner.use_refnum and not fields.refnum:
        return reject(NaesbErrorCode.REFNUM_NOT_PRESENT)

    content_digest = hashlib.sha256(ciphertext).hexdigest()

    # Step 4: dedupe. Primarily by (partner, refnum) when this partner uses
    # refnum tracking (the spec's own mechanism); otherwise by a digest of
    # the extracted ciphertext -- the spec defines no message-id header.
    if partner.use_refnum and fields.refnum:
        if await tracker.find_refnum_reuse(partner.name, fields.refnum, "inbound"):
            return reject(NaesbErrorCode.DUPLICATE_REFNUM)
    elif await tracker.find_duplicate(partner.name, content_digest, "inbound"):
        return reject(GatewayExtensionCode.DUPLICATE_DIGEST)

    record = MessageRecord(
        direction="inbound",
        partner_name=partner.name,
        content_digest=content_digest,
        transaction_set=fields.transaction_set,
        input_format=fields.input_format.value,
        trans_id=trans_id,
        refnum=fields.refnum,
        refnum_orig=fields.refnum_orig,
        raw_headers=dict(request.headers),
        received_at=received_at,
        status="processing",
    )
    try:
        message_id = await tracker.create(record)
    except UniqueViolation:
        # find_duplicate()/find_refnum_reuse() above and this insert aren't
        # atomic -- a concurrent identical request can race between them.
        # The UNIQUE constraint on (partner_name, content_digest, direction)
        # is the real backstop.
        return reject(GatewayExtensionCode.DUPLICATE_DIGEST)

    # Step 5: decrypt + verify signature. GnuPG doesn't always discriminate
    # between "public key invalid", "not encrypted", and "truncated" --
    # per the spec's own "Pre-validation before Decryption" guidance, a
    # generic decryption error (EEDM699) is used when finer classification
    # isn't reliably available.
    decrypt_result = gpg.decrypt_and_verify(ciphertext, settings.crypto.passphrase)
    if not decrypt_result.ok:
        await tracker.update_status(
            message_id, status="rejected", error_code=NaesbErrorCode.DECRYPTION_ERROR.value
        )
        return reject(NaesbErrorCode.DECRYPTION_ERROR)

    partner_fingerprint = fingerprints.get(partner.name)
    if not decrypt_result.signature_valid or decrypt_result.signer_fingerprint != partner_fingerprint:
        await tracker.update_status(
            message_id,
            status="rejected",
            error_code=NaesbErrorCode.SIGNATURE_NOT_MATCHED.value,
            receipt_verified=False,
        )
        return reject(NaesbErrorCode.SIGNATURE_NOT_MATCHED)

    # Step 6: enforce this gateway's local cryptographic policy (NAESB
    # itself only mandates a minimum RSA key length -- see policy.py).
    try:
        enforce_policy(
            decrypt_result.algo_info,
            allowed_ciphers={settings.crypto.cipher_algo},
            allowed_digests={settings.crypto.digest_algo},
        )
    except WeakAlgorithmError as exc:
        await tracker.update_status(
            message_id, status="rejected", error_code=GatewayExtensionCode.WEAK_ALGORITHM.value
        )
        return reject(GatewayExtensionCode.WEAK_ALGORITHM, str(exc))

    # Step 7: fan out to configured sinks.
    inbound_message = InboundMessage(
        partner_name=partner.name,
        content_digest=content_digest,
        envelope=fields,
        plaintext=decrypt_result.plaintext,
        received_at=received_at,
    )
    sink_results = await fan_out(sinks, inbound_message)
    await tracker.update_sinks_status(
        message_id, {name: {"ok": r.ok, "error": r.error} for name, r in sink_results.items()}
    )

    if settings.sinks.require_at_least_one_durable_success and not has_durable_success(
        sinks, sink_results
    ):
        await tracker.update_status(
            message_id, status="rejected", error_code=GatewayExtensionCode.SINK_FAILURE.value
        )
        return reject(GatewayExtensionCode.SINK_FAILURE)

    # Step 8: accepted.
    await tracker.update_status(message_id, status="accepted", receipt_verified=True)
    logger.info("inbound_accepted", partner=partner.name, digest=content_digest, trans_id=trans_id)
    receipt = NaesbReceipt.ok(settings.envelope.server_id, trans_id, time_c=received_at)
    return _signed_receipt(gpg, fingerprints, settings, receipt)


def _redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {
        name: ("[REDACTED]" if name.lower() == "authorization" else value)
        for name, value in headers.items()
    }


def _signed_receipt(
    gpg: GpgService, fingerprints: dict[str, str], settings: Settings, receipt: NaesbReceipt
) -> Response:
    report_body, report_content_type = receipt.encode_report_part()
    signature = gpg.detached_sign(report_body, fingerprints["_self"], settings.crypto.passphrase)
    micalg = f"pgp-{settings.crypto.digest_algo.lower()}"
    signed_body, content_type = build_signed_mime(report_body, report_content_type, signature, micalg)
    return Response(content=signed_body, media_type=content_type, status_code=200)
