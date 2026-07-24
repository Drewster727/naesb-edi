import hashlib
import uuid

from app.crypto.gpg_wrapper import GpgService
from app.envelope.fields import InputFormat
from app.partners import PartnerConfig
from app.settings import Settings
from app.tracking.models import MessageRecord, OutboundJob
from app.tracking.repository import MessageTracker, OutboundJobRepository


async def enqueue_outbound(
    payload: bytes,
    *,
    partner: PartnerConfig,
    input_format: InputFormat,
    transaction_set: str | None,
    refnum: str | None,
    refnum_orig: str | None,
    settings: Settings,
    gpg: GpgService,
    fingerprints: dict[str, str],
    tracker: MessageTracker,
    jobs: OutboundJobRepository,
) -> uuid.UUID:
    """Encrypts+signs `payload` for `partner`, records it in the audit trail,
    and enqueues an `OutboundJob` for `app/worker.py` to deliver. Shared by
    `app/api/send.py`'s `POST /outbound/send` and `app/poller.py`'s file-drop
    path so the two entry points can never drift out of sync."""
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
            transaction_set=transaction_set,
            input_format=input_format.value,
            refnum=refnum,
            refnum_orig=refnum_orig,
            status="queued",
        )
    )

    job = OutboundJob(
        id=None,
        partner_name=partner.name,
        from_id=settings.identity.duns,
        to_id=partner.duns,
        version=version,
        input_format=input_format.value,
        transaction_set=transaction_set,
        refnum=refnum,
        refnum_orig=refnum_orig,
        payload_ciphertext=encrypted,
        content_digest=content_digest,
        message_id=message_id,
    )
    return await jobs.create(job)
