"""RFC 1847/3156-style `multipart/encrypted` MIME wrapping for the NAESB
Internet ET `input-data` field's content, per WGQ Cybersecurity Related
Standards v4.0, "Anatomy of an Internet ET Package" / "Payload".
"""

import secrets

from app.envelope.mime_split import MimeSplitError, content_type_param, split_mime_parts

CRLF = b"\r\n"


class PgpMimeError(Exception):
    pass


def _boundary() -> str:
    return f"----naesb-pgp-{secrets.token_hex(16)}"


def wrap_pgp_encrypted(ciphertext: bytes) -> tuple[bytes, str]:
    """Build the `multipart/encrypted` structure NAESB requires inside
    `input-data`: a control part (`application/pgp-encrypted`, literally
    "Version: 1") plus the OpenPGP message itself (`application/octet-stream`,
    raw/armor-less binary). Returns (body_bytes, content_type_header_value)."""
    boundary = _boundary()
    body = (
        b"--" + boundary.encode() + CRLF
        + b"content-type: application/pgp-encrypted" + CRLF + CRLF
        + b"Version: 1" + CRLF
        + b"--" + boundary.encode() + CRLF
        + b"content-type: application/octet-stream" + CRLF
        + b"content-transfer-encoding: binary" + CRLF + CRLF
        + ciphertext + CRLF
        + b"--" + boundary.encode() + b"--" + CRLF
    )
    content_type = f'multipart/encrypted; boundary="{boundary}"; protocol="application/pgp-encrypted"'
    return body, content_type


def unwrap_pgp_encrypted(data: bytes, content_type: str) -> bytes:
    """Inverse of wrap_pgp_encrypted(): given the input-data field's raw
    bytes and its declared Content-Type, extract the OpenPGP message bytes."""
    boundary = content_type_param(content_type, "boundary")
    if boundary is None:
        raise PgpMimeError("input-data content-type is missing a boundary parameter")
    try:
        parts = split_mime_parts(data, boundary)
    except MimeSplitError as exc:
        raise PgpMimeError(str(exc)) from exc
    if len(parts) != 2:
        raise PgpMimeError(f"expected 2 parts in multipart/encrypted, got {len(parts)}")
    (control_headers, _control_body), (_payload_headers, payload_body) = parts
    # Media types are case-insensitive per RFC 2045; header values (unlike
    # names) aren't normalized by _parse_headers(), so lower-case here.
    if not control_headers.get("content-type", "").lower().startswith("application/pgp-encrypted"):
        raise PgpMimeError("first multipart/encrypted part must be application/pgp-encrypted")
    if not payload_body:
        raise PgpMimeError("multipart/encrypted payload part is empty")
    return payload_body
