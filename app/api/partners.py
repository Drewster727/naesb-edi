import secrets

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel

from app.dependencies import get_partners, get_settings
from app.partners import PartnerRegistry
from app.settings import Settings

router = APIRouter(prefix="/api")
security = HTTPBasic()


class PartnerSummary(BaseModel):
    name: str
    duns: str
    endpoint_url: str
    has_envelope_overrides: bool


def require_internal_auth(
    credentials: HTTPBasicCredentials = Depends(security),
    settings: Settings = Depends(get_settings),
) -> None:
    valid_username = secrets.compare_digest(credentials.username, settings.internal_api.username)
    valid_password = secrets.compare_digest(credentials.password, settings.internal_api.password)
    if not (valid_username and valid_password):
        raise HTTPException(
            status_code=401, detail="unauthorized", headers={"WWW-Authenticate": "Basic"}
        )


@router.get("/partners", response_model=list[PartnerSummary])
async def list_partners(
    _: None = Depends(require_internal_auth),
    partners: PartnerRegistry = Depends(get_partners),
) -> list[PartnerSummary]:
    return [
        PartnerSummary(
            name=partner.name,
            duns=partner.duns,
            endpoint_url=partner.endpoint_url,
            has_envelope_overrides=partner.envelope_overrides is not None,
        )
        for partner in partners
    ]
