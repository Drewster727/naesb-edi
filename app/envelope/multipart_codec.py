"""Build/parse the outer NAESB Internet ET `multipart/form-data` envelope.

Building (outbound requests, our own): hand-rolled byte construction so the
spec-mandated field order is exact and predictable.

Parsing (inbound requests, untrusted network input): delegates to Starlette's
`request.form()` (backed by `python-multipart`, a mature, security-reviewed
parser) rather than hand-rolling a parser for attacker-controlled bytes.
"""

import secrets

from starlette.datastructures import FormData, UploadFile

from app.envelope.fields import EnvelopeField, EnvelopeFields, InputFormat
from app.envelope.pgp_mime import PgpMimeError, unwrap_pgp_encrypted, wrap_pgp_encrypted

CRLF = b"\r\n"


class EnvelopeError(Exception):
    """Raised when a required NAESB envelope field is missing or malformed.
    `field` is the literal spec field name (e.g. "to", "input-format");
    `problem` is "missing" or "invalid" -- callers map (field, problem) to
    the exact EEDM1xx error code via app.envelope.error_codes."""

    def __init__(self, field: str, problem: str, detail: str | None = None):
        self.field = field
        self.problem = problem
        self.detail = detail
        message = f"{field}: {problem}"
        if detail:
            message += f" ({detail})"
        super().__init__(message)


def _boundary() -> str:
    return f"----naesb-form-{secrets.token_hex(16)}"


def build_multipart_body(
    fields: EnvelopeFields, payload_ciphertext: bytes, filename: str = "payload.pgp"
) -> tuple[bytes, str]:
    """Assemble the ordered `multipart/form-data` body for an outbound
    transmission. Returns (body_bytes, content_type_header_value)."""
    boundary = _boundary()
    encrypted_body, encrypted_content_type = wrap_pgp_encrypted(payload_ciphertext)

    def field_part(name: str, value: str) -> bytes:
        return (
            b"--" + boundary.encode() + CRLF
            + f'content-disposition: form-data; name="{name}"'.encode() + CRLF + CRLF
            + value.encode() + CRLF
        )

    input_data_part = (
        b"--" + boundary.encode() + CRLF
        + (
            f'content-disposition: form-data; name="{EnvelopeField.INPUT_DATA.value}"; '
            f'filename="{filename}"'
        ).encode()
        + CRLF
        + f"content-type: {encrypted_content_type}".encode() + CRLF + CRLF
        + encrypted_body + CRLF
    )

    parts = [
        field_part(EnvelopeField.FROM.value, fields.from_id),
        field_part(EnvelopeField.TO.value, fields.to_id),
        field_part(EnvelopeField.VERSION.value, fields.version),
        field_part(EnvelopeField.RECEIPT_DISPOSITION_TO.value, fields.receipt_disposition_to),
        field_part(EnvelopeField.RECEIPT_REPORT_TYPE.value, fields.receipt_report_type),
        field_part(EnvelopeField.INPUT_FORMAT.value, fields.input_format.value),
        input_data_part,
        field_part(EnvelopeField.RECEIPT_SECURITY_SELECTION.value, fields.receipt_security_selection),
    ]
    if fields.transaction_set is not None:
        parts.append(field_part(EnvelopeField.TRANSACTION_SET.value, fields.transaction_set))
    if fields.refnum is not None:
        parts.append(field_part(EnvelopeField.REFNUM.value, fields.refnum))
    if fields.refnum_orig is not None:
        parts.append(field_part(EnvelopeField.REFNUM_ORIG.value, fields.refnum_orig))

    body = b"".join(parts) + b"--" + boundary.encode() + b"--" + CRLF
    content_type = f'multipart/form-data; boundary="{boundary}"'
    return body, content_type


async def parse_multipart_form(form: FormData) -> tuple[EnvelopeFields, bytes]:
    """Given a Starlette `FormData` (from `await request.form()`), extract
    and validate the NAESB envelope fields plus the `input-data` payload
    (unwrapped from its inner `multipart/encrypted` MIME structure).
    Returns (fields, plaintext_ciphertext_bytes)."""

    def get_str(field: EnvelopeField) -> str | None:
        value = form.get(field.value)
        if not isinstance(value, str):
            return None
        value = value.strip()
        return value or None

    def require(field: EnvelopeField) -> str:
        value = get_str(field)
        if value is None:
            raise EnvelopeError(field.value, "missing")
        return value

    from_id = require(EnvelopeField.FROM)
    to_id = require(EnvelopeField.TO)
    version = require(EnvelopeField.VERSION)
    receipt_disposition_to = require(EnvelopeField.RECEIPT_DISPOSITION_TO)
    receipt_report_type = require(EnvelopeField.RECEIPT_REPORT_TYPE)
    input_format_raw = require(EnvelopeField.INPUT_FORMAT)
    receipt_security_selection = require(EnvelopeField.RECEIPT_SECURITY_SELECTION)

    try:
        input_format = InputFormat(input_format_raw)
    except ValueError:
        raise EnvelopeError(EnvelopeField.INPUT_FORMAT.value, "invalid", input_format_raw) from None

    upload = form.get(EnvelopeField.INPUT_DATA.value)
    if upload is None or not isinstance(upload, UploadFile):
        raise EnvelopeError(EnvelopeField.INPUT_DATA.value, "missing")
    raw = await upload.read()
    content_type = upload.content_type or ""
    try:
        ciphertext = unwrap_pgp_encrypted(raw, content_type)
    except PgpMimeError as exc:
        raise EnvelopeError(EnvelopeField.INPUT_DATA.value, "invalid", str(exc)) from exc

    transaction_set = get_str(EnvelopeField.TRANSACTION_SET)
    refnum = get_str(EnvelopeField.REFNUM)
    refnum_orig = get_str(EnvelopeField.REFNUM_ORIG)

    try:
        fields = EnvelopeFields(
            from_id=from_id,
            to_id=to_id,
            version=version,
            receipt_disposition_to=receipt_disposition_to,
            receipt_report_type=receipt_report_type,
            input_format=input_format,
            receipt_security_selection=receipt_security_selection,
            transaction_set=transaction_set,
            refnum=refnum,
            refnum_orig=refnum_orig,
        )
    except ValueError as exc:
        raise EnvelopeError(EnvelopeField.TRANSACTION_SET.value, "invalid", str(exc)) from exc

    return fields, ciphertext
