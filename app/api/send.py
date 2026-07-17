import base64
import binascii
import hashlib
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.partners import require_internal_auth
from app.crypto.gpg_wrapper import GpgService
from app.dependencies import (
    get_fingerprints,
    get_gpg,
    get_job_repository,
    get_partners,
    get_settings,
    get_tracker,
)
from app.envelope.fields import InputFormat
from app.partners import PartnerRegistry
from app.settings import Settings
from app.tracking.models import MessageRecord, OutboundJob
from app.tracking.repository import MessageTracker, OutboundJobRepository

router = APIRouter()


class SendRequest(BaseModel):
    partner_name: str
    input_format: InputFormat
    transaction_set: str | None = None
    refnum: str | None = None
    refnum_orig: str | None = None
    payload_base64: str


class SendAcceptedResponse(BaseModel):
    job_id: uuid.UUID
    status: str


class JobStatusResponse(BaseModel):
    job_id: uuid.UUID
    status: str
    attempt_count: int
    last_error_code: str | None = None
    last_error_description: str | None = None
    receipt_trans_id: str | None = None
    receipt_server_id: str | None = None
    receipt_time_c: str | None = None


@router.post("/outbound/send", response_model=SendAcceptedResponse, status_code=202)
async def trigger_send(
    body: SendRequest,
    _: None = Depends(require_internal_auth),
    settings: Settings = Depends(get_settings),
    partners: PartnerRegistry = Depends(get_partners),
    gpg: GpgService = Depends(get_gpg),
    fingerprints: dict[str, str] = Depends(get_fingerprints),
    tracker: MessageTracker = Depends(get_tracker),
    jobs: OutboundJobRepository = Depends(get_job_repository),
) -> SendAcceptedResponse:
    """Enqueues an outbound transmission and returns immediately -- delivery
    (including retries spanning the NAESB Exchange Failure window) is
    handled asynchronously by the worker process. Poll
    GET /outbound/jobs/{job_id} for the outcome."""
    partner = partners.get_by_name(body.partner_name)
    if partner is None:
        raise HTTPException(status_code=404, detail=f"unknown partner {body.partner_name!r}")

    try:
        payload = base64.b64decode(body.payload_base64, validate=True)
    except binascii.Error as exc:
        raise HTTPException(status_code=400, detail=f"invalid payload_base64: {exc}") from exc

    version = (
        partner.envelope_overrides.version if partner.envelope_overrides else None
    ) or settings.envelope.default_version

    # Encrypt once; the same ciphertext (and content digest) is reused by
    # the worker across every retry attempt, so partner-side dedup still
    # works.
    encrypted = gpg.encrypt_and_sign(
        payload,
        recipient_fingerprint=fingerprints[partner.name],
        signer_fingerprint=fingerprints["_self"],
        passphrase=settings.crypto.passphrase,
    )
    content_digest = hashlib.sha256(encrypted).hexdigest()

    message_id = await tracker.create(
        MessageRecord(
            direction="outbound",
            partner_name=partner.name,
            content_digest=content_digest,
            transaction_set=body.transaction_set,
            input_format=body.input_format.value,
            refnum=body.refnum,
            refnum_orig=body.refnum_orig,
            status="queued",
        )
    )

    job = OutboundJob(
        id=None,
        partner_name=partner.name,
        from_id=settings.identity.duns,
        to_id=partner.duns,
        version=version,
        input_format=body.input_format.value,
        transaction_set=body.transaction_set,
        refnum=body.refnum,
        refnum_orig=body.refnum_orig,
        payload_ciphertext=encrypted,
        content_digest=content_digest,
        message_id=message_id,
    )
    job_id = await jobs.create(job)

    return SendAcceptedResponse(job_id=job_id, status="queued")


@router.get("/outbound/jobs/{job_id}", response_model=JobStatusResponse)
async def get_job_status(
    job_id: uuid.UUID,
    _: None = Depends(require_internal_auth),
    jobs: OutboundJobRepository = Depends(get_job_repository),
) -> JobStatusResponse:
    job = await jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="unknown job")
    return JobStatusResponse(
        job_id=job.id,
        status=job.status,
        attempt_count=job.attempt_count,
        last_error_code=job.last_error_code,
        last_error_description=job.last_error_description,
        receipt_trans_id=job.receipt_trans_id,
        receipt_server_id=job.receipt_server_id,
        receipt_time_c=job.receipt_time_c,
    )
