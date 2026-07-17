"""'gisb-acknowledgement-receipt': `multipart/signed` (detached PGP
signature) wrapping `multipart/report` (report-type=
"gisb-acknowledgement-receipt"), per WGQ Cybersecurity Related Standards
v4.0, "Receiving Internet ET Packages" / "Acknowledgement Receipt".
"""

import re
import secrets
from datetime import UTC, datetime

from pydantic import BaseModel

from app.envelope.error_codes import ErrorCode, describe
from app.envelope.mime_split import MimeSplitError, content_type_param, split_mime_parts

CRLF = b"\r\n"
TIME_C_FORMAT = "%Y%m%d%H%M%S"

# `*` is the field delimiter in _fields_text()'s `key=value*` encoding, and
# CR/LF would break out of a single logical line -- descriptions can carry
# attacker-influenced text (e.g. a raw envelope field value or a pydantic
# ValidationError message echoing it back), so any of these characters must
# be neutralized before being embedded in a signed receipt.
_UNSAFE_RECEIPT_TEXT = re.compile(r"[*\r\n]")


def _sanitize_receipt_text(value: str) -> str:
    return _UNSAFE_RECEIPT_TEXT.sub(" ", value)


class ReceiptDecodeError(Exception):
    pass


def _boundary(prefix: str) -> str:
    return f"----naesb-{prefix}-{secrets.token_hex(16)}"


class NaesbReceipt(BaseModel):
    """The four required HTTP Response data elements, in the spec-mandated
    order: time-c, request-status, server-id, trans-id."""

    time_c: str
    request_status: str
    server_id: str
    trans_id: str

    @classmethod
    def ok(cls, server_id: str, trans_id: int, *, time_c: datetime | None = None) -> "NaesbReceipt":
        return cls(
            time_c=(time_c or datetime.now(UTC)).strftime(TIME_C_FORMAT),
            request_status="ok",
            server_id=server_id,
            trans_id=str(trans_id),
        )

    @classmethod
    def rejected(
        cls,
        server_id: str,
        trans_id: int,
        code: ErrorCode,
        description: str | None = None,
        *,
        time_c: datetime | None = None,
    ) -> "NaesbReceipt":
        safe_description = _sanitize_receipt_text(description) if description else None
        return cls(
            time_c=(time_c or datetime.now(UTC)).strftime(TIME_C_FORMAT),
            request_status=f"{code.value}: {safe_description or describe(code)}",
            server_id=server_id,
            trans_id=str(trans_id),
        )

    @property
    def is_ok(self) -> bool:
        return self.request_status == "ok"

    def _fields_text(self) -> bytes:
        lines = [
            f"time-c={self.time_c}*",
            f"request-status={self.request_status}*",
            f"server-id={self.server_id}*",
            f"trans-id={self.trans_id}*",
        ]
        return CRLF.join(line.encode() for line in lines) + CRLF

    def encode_report_part(self) -> tuple[bytes, str]:
        """`multipart/report; report-type="gisb-acknowledgement-receipt"`,
        with a text/html and a text/plain sub-part, matching the spec's own
        illustrated examples. Returns (body_bytes, content_type)."""
        boundary = _boundary("report")
        fields_text = self._fields_text()
        html_body = (
            b"<HTML><HEAD><TITLE>Acknowledgement Receipt</TITLE></HEAD><BODY><P>" + CRLF
            + fields_text
            + b"</P></BODY></HTML>" + CRLF
        )
        body = (
            b"--" + boundary.encode() + CRLF
            + b"content-type: text/html" + CRLF + CRLF
            + html_body
            + b"--" + boundary.encode() + CRLF
            + b"content-type: text/plain" + CRLF + CRLF
            + fields_text
            + b"--" + boundary.encode() + b"--" + CRLF
        )
        content_type = (
            f'multipart/report; report-type="gisb-acknowledgement-receipt"; boundary="{boundary}"'
        )
        return body, content_type

    @classmethod
    def decode_report_part(cls, data: bytes, content_type: str) -> "NaesbReceipt":
        boundary = content_type_param(content_type, "boundary")
        if boundary is None:
            raise ReceiptDecodeError("multipart/report content-type is missing a boundary parameter")
        try:
            parts = split_mime_parts(data, boundary)
        except MimeSplitError as exc:
            raise ReceiptDecodeError(str(exc)) from exc

        text_body: bytes | None = None
        for headers, body in parts:
            # Media types are case-insensitive per RFC 2045.
            if headers.get("content-type", "").lower().startswith("text/plain"):
                text_body = body
                break
        if text_body is None:
            raise ReceiptDecodeError("no text/plain sub-part found in multipart/report")
        return cls._parse_fields(text_body.decode("utf-8", errors="replace"))

    @classmethod
    def _parse_fields(cls, text: str) -> "NaesbReceipt":
        values: dict[str, str] = {}
        for chunk in text.replace("\r\n", "\n").split("*"):
            chunk = chunk.strip()
            if not chunk or "=" not in chunk:
                continue
            key, _, value = chunk.partition("=")
            values[key.strip()] = value.strip()
        try:
            return cls(
                time_c=values["time-c"],
                request_status=values["request-status"],
                server_id=values["server-id"],
                trans_id=values["trans-id"],
            )
        except KeyError as exc:
            raise ReceiptDecodeError(f"missing required receipt field: {exc}") from exc


def build_signed_mime(
    report_body: bytes, report_content_type: str, signature: bytes, micalg: str
) -> tuple[bytes, str]:
    """Wrap a `multipart/report` part and its detached PGP signature in the
    `multipart/signed` envelope (RFC 1847)."""
    boundary = _boundary("signed")
    body = (
        b"--" + boundary.encode() + CRLF
        + b"content-type: " + report_content_type.encode() + CRLF + CRLF
        + report_body + CRLF
        + b"--" + boundary.encode() + CRLF
        + b"content-type: application/pgp-signature" + CRLF + CRLF
        + signature.rstrip(b"\r\n") + CRLF
        + b"--" + boundary.encode() + b"--" + CRLF
    )
    content_type = (
        f'multipart/signed; micalg="{micalg}"; protocol="application/pgp-signature"; '
        f'boundary="{boundary}"'
    )
    return body, content_type


def parse_signed_mime(data: bytes, content_type: str) -> tuple[bytes, str, bytes]:
    """Inverse of build_signed_mime(): returns
    (report_body_bytes, report_content_type, signature_bytes)."""
    boundary = content_type_param(content_type, "boundary")
    if boundary is None:
        raise ReceiptDecodeError("multipart/signed content-type is missing a boundary parameter")
    try:
        parts = split_mime_parts(data, boundary)
    except MimeSplitError as exc:
        raise ReceiptDecodeError(str(exc)) from exc
    if len(parts) != 2:
        raise ReceiptDecodeError(f"expected 2 parts in multipart/signed, got {len(parts)}")

    (report_headers, report_body), (sig_headers, sig_body) = parts
    report_content_type = report_headers.get("content-type")
    if not report_content_type:
        raise ReceiptDecodeError("multipart/report part is missing a content-type header")
    if not sig_headers.get("content-type", "").lower().startswith("application/pgp-signature"):
        raise ReceiptDecodeError("second multipart/signed part must be application/pgp-signature")
    return report_body, report_content_type, sig_body
