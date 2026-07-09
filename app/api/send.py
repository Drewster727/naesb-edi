import base64
import binascii

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.crypto.gpg_wrapper import GpgService
from app.dependencies import get_fingerprints, get_gpg, get_partners, get_settings, get_tracker
from app.envelope.fields import InputFormat
from app.outbound.client import OutboundDeliveryError, send_message
from app.partners import PartnerRegistry
from app.settings import Settings
from app.tracking.repository import MessageTracker

router = APIRouter()


class SendRequest(BaseModel):
    partner_name: str
    input_format: InputFormat
    transaction_set: str
    payload_base64: str


class SendResponse(BaseModel):
    status: str
    error_code: int | None = None
    error_description: str | None = None


@router.post("/outbound/send", response_model=SendResponse)
async def trigger_send(
    body: SendRequest,
    settings: Settings = Depends(get_settings),
    partners: PartnerRegistry = Depends(get_partners),
    gpg: GpgService = Depends(get_gpg),
    fingerprints: dict[str, str] = Depends(get_fingerprints),
    tracker: MessageTracker = Depends(get_tracker),
) -> SendResponse:
    partner = partners.get_by_name(body.partner_name)
    if partner is None:
        raise HTTPException(status_code=404, detail=f"unknown partner {body.partner_name!r}")

    try:
        payload = base64.b64decode(body.payload_base64, validate=True)
    except binascii.Error as exc:
        raise HTTPException(status_code=400, detail=f"invalid payload_base64: {exc}") from exc

    try:
        result = await send_message(
            partner,
            payload,
            body.input_format,
            body.transaction_set,
            settings,
            gpg,
            fingerprints,
            tracker,
        )
    except OutboundDeliveryError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return SendResponse(
        status=result.receipt.status.value,
        error_code=result.receipt.error_code.value if result.receipt.error_code else None,
        error_description=result.receipt.error_description,
    )
