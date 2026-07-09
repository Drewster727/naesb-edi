import hashlib
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
from app.envelope.codec import EnvelopeError, parse_headers
from app.envelope.mapping import merge
from app.envelope.receipt import ReasonCode, Receipt
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
    if len(body) > settings.server.max_body_size_bytes:
        raise HTTPException(status_code=413, detail="payload too large")

    # Step 1: transport-level auth, before any GPG work. Fails closed with a
    # plain (unsigned) HTTP error -- this is not a protocol-level NACK.
    partner = authenticate_inbound(request.headers.get("authorization"), partners)
    if partner is None:
        raise HTTPException(status_code=401, detail="unauthorized")

    mapping = merge(
        settings.envelope.header_mapping,
        partner.envelope_overrides.header_mapping if partner.envelope_overrides else None,
    )

    received_at = datetime.now(UTC)
    content_digest = hashlib.sha256(body).hexdigest()

    def reject(code: ReasonCode, message: str | None = None) -> Response:
        logger.info("inbound_rejected", partner=partner.name, digest=content_digest, error_code=code.value)
        return _signed_receipt(gpg, fingerprints, settings, Receipt.rejected(code, message))

    # Step 2: parse the NAESB transport headers.
    try:
        fields = parse_headers(request.headers, mapping)
    except EnvelopeError as exc:
        return reject(ReasonCode.INVALID_HEADER_PARAMETERS, str(exc))

    # Step 3: the authenticated partner's DUNS must match the claimed from-id.
    if fields.from_id != partner.duns:
        return reject(ReasonCode.UNKNOWN_PARTNER, "from-id does not match the authenticated partner")

    # Step 4: dedupe on content digest -- naesb4.md defines no message-id header.
    if await tracker.find_duplicate(partner.name, content_digest, "inbound"):
        return reject(ReasonCode.DUPLICATE_MESSAGE)

    record = MessageRecord(
        direction="inbound",
        partner_name=partner.name,
        content_digest=content_digest,
        transaction_set=fields.transaction_set,
        input_format=fields.input_format.value,
        raw_headers=dict(request.headers),
        received_at=received_at,
        status="processing",
    )
    try:
        message_id = await tracker.create(record)
    except UniqueViolation:
        # find_duplicate() above and this insert aren't atomic -- a concurrent
        # identical request can race between them. The UNIQUE constraint on
        # (partner_name, content_digest, direction) is the real backstop.
        return reject(ReasonCode.DUPLICATE_MESSAGE)

    # Step 5: decrypt + verify signature.
    decrypt_result = gpg.decrypt_and_verify(body, settings.crypto.passphrase)
    if not decrypt_result.ok:
        await tracker.update_status(
            message_id, status="rejected", error_code=ReasonCode.DECRYPTION_FAILED.value
        )
        return reject(ReasonCode.DECRYPTION_FAILED)

    partner_fingerprint = fingerprints.get(partner.name)
    if not decrypt_result.signature_valid or decrypt_result.signer_fingerprint != partner_fingerprint:
        await tracker.update_status(
            message_id,
            status="rejected",
            error_code=ReasonCode.SIGNATURE_VERIFICATION_FAILED.value,
            receipt_verified=False,
        )
        return reject(ReasonCode.SIGNATURE_VERIFICATION_FAILED)

    # Step 6: enforce modern-OpenPGP-only policy.
    try:
        enforce_policy(
            decrypt_result.algo_info,
            allowed_ciphers={settings.crypto.cipher_algo},
            allowed_digests={settings.crypto.digest_algo},
        )
    except WeakAlgorithmError as exc:
        await tracker.update_status(
            message_id, status="rejected", error_code=ReasonCode.WEAK_ALGORITHM.value
        )
        return reject(ReasonCode.WEAK_ALGORITHM, str(exc))

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
            message_id, status="rejected", error_code=ReasonCode.SINK_FAILURE.value
        )
        return reject(ReasonCode.SINK_FAILURE)

    # Step 9: accepted.
    await tracker.update_status(message_id, status="accepted", receipt_verified=True)
    logger.info("inbound_accepted", partner=partner.name, digest=content_digest)
    return _signed_receipt(gpg, fingerprints, settings, Receipt.accepted())


def _signed_receipt(
    gpg: GpgService, fingerprints: dict[str, str], settings: Settings, receipt: Receipt
) -> Response:
    signed = gpg.sign_message(receipt.encode(), fingerprints["_self"], settings.crypto.passphrase)
    return Response(content=signed, media_type="application/octet-stream", status_code=200)
