import base64
import binascii
import secrets

from app.partners import ApiKeyAuthConfig, BasicAuthConfig, PartnerConfig, PartnerRegistry


def authenticate_inbound(authorization_header: str | None, partners: PartnerRegistry) -> PartnerConfig | None:
    """Match the incoming Authorization header against each partner's
    configured inbound_auth (Basic -> Authorization: Basic ..., api_key ->
    Authorization: Bearer <key>). Checked before any GPG work.

    naesb4.md doesn't define an inbound authentication scheme at all -- this
    is a gateway-layer addition on top of the documented transport, since
    something has to reject unauthenticated traffic before we spend CPU on
    decryption.
    """
    if not authorization_header:
        return None

    scheme, _, value = authorization_header.partition(" ")
    scheme = scheme.strip().lower()
    value = value.strip()

    for partner in partners:
        auth = partner.inbound_auth
        if scheme == "basic" and isinstance(auth, BasicAuthConfig):
            if _check_basic(value, auth):
                return partner
        elif scheme == "bearer" and isinstance(auth, ApiKeyAuthConfig):
            if secrets.compare_digest(value, auth.key):
                return partner
    return None


def _check_basic(encoded: str, auth: BasicAuthConfig) -> bool:
    try:
        decoded = base64.b64decode(encoded).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return False
    username, _, password = decoded.partition(":")
    return secrets.compare_digest(username, auth.username) and secrets.compare_digest(
        password, auth.password
    )
