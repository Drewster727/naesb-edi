from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel


class ReasonCode(int, Enum):
    """error-code values for the synchronous receipt (naesb4.md section 4).

    101-103 are the codes documented in naesb4.md itself (given as examples,
    not an exhaustive list). 104+ are gateway-specific extensions for
    guarantees this service adds on top of the documented transport (dedup,
    sink durability, key/algorithm policy) -- they are NOT NAESB-assigned
    codes, and should be renumbered/reconciled if the licensed spec text
    turns out to define its own codes in that range.
    """

    DECRYPTION_FAILED = 101
    SIGNATURE_VERIFICATION_FAILED = 102
    INVALID_HEADER_PARAMETERS = 103
    UNKNOWN_PARTNER = 104
    DUPLICATE_MESSAGE = 105
    WEAK_ALGORITHM = 106
    SINK_FAILURE = 107
    INVALID_TRANSACTION_SET = 108


REASON_DESCRIPTIONS: dict[ReasonCode, str] = {
    ReasonCode.DECRYPTION_FAILED: "Decryption Failed",
    ReasonCode.SIGNATURE_VERIFICATION_FAILED: "Signature Verification Failed",
    ReasonCode.INVALID_HEADER_PARAMETERS: "Invalid Header Parameters",
    ReasonCode.UNKNOWN_PARTNER: "Unknown Partner",
    ReasonCode.DUPLICATE_MESSAGE: "Duplicate Message",
    ReasonCode.WEAK_ALGORITHM: "Weak Cryptographic Algorithm Or Key Length",
    ReasonCode.SINK_FAILURE: "Delivery Sink Failure",
    ReasonCode.INVALID_TRANSACTION_SET: "Invalid Transaction Set",
}


class ReceiptStatus(str, Enum):
    SUCCESS = "success"
    VALIDATION_FAILED = "validation-failed"


class ReceiptDecodeError(Exception):
    pass


class Receipt(BaseModel):
    status: ReceiptStatus
    timestamp: datetime
    error_code: ReasonCode | None = None
    error_description: str | None = None

    @classmethod
    def accepted(cls) -> "Receipt":
        return cls(status=ReceiptStatus.SUCCESS, timestamp=datetime.now(UTC))

    @classmethod
    def rejected(cls, code: ReasonCode, description: str | None = None) -> "Receipt":
        return cls(
            status=ReceiptStatus.VALIDATION_FAILED,
            timestamp=datetime.now(UTC),
            error_code=code,
            error_description=description or REASON_DESCRIPTIONS[code],
        )

    def encode(self) -> str:
        """Line-delimited key: value text, per naesb4.md section 4. This exact
        string is what gets OpenPGP-signed -- never re-serialize after signing."""
        lines = [
            f"receipt-status: {self.status.value}",
            f"receipt-timestamp: {self.timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')}",
            f"error-code: {self.error_code.value if self.error_code is not None else ''}",
            f"error-description: {self.error_description or ''}",
        ]
        return "\n".join(lines) + "\n"

    @classmethod
    def decode(cls, text: str) -> "Receipt":
        values: dict[str, str] = {}
        for line in text.strip("\n").splitlines():
            if not line.strip():
                continue
            if ":" not in line:
                raise ReceiptDecodeError(f"malformed receipt line: {line!r}")
            key, _, value = line.partition(":")
            values[key.strip()] = value.strip()

        try:
            status = ReceiptStatus(values["receipt-status"])
            timestamp = datetime.strptime(values["receipt-timestamp"], "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=UTC
            )
        except (KeyError, ValueError) as exc:
            raise ReceiptDecodeError(f"malformed receipt body: {exc}") from exc

        error_code_raw = values.get("error-code", "").strip()
        error_code = ReasonCode(int(error_code_raw)) if error_code_raw else None
        error_description = values.get("error-description", "").strip() or None

        return cls(
            status=status, timestamp=timestamp, error_code=error_code, error_description=error_description
        )
