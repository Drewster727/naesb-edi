from enum import Enum

from pydantic import BaseModel, field_validator

from app.duns import normalize_duns


class EnvelopeField(str, Enum):
    """Literal NAESB Internet ET envelope/multipart field names, per the
    "Data Dictionary for Internet ET" (WGQ Cybersecurity Related Standards
    v4.0). These are fixed protocol literals -- not something a Trading
    Partner Agreement renames -- carried as `multipart/form-data` field
    names, not HTTP headers."""

    FROM = "from"
    TO = "to"
    VERSION = "version"
    RECEIPT_DISPOSITION_TO = "receipt-disposition-to"
    RECEIPT_REPORT_TYPE = "receipt-report-type"
    INPUT_FORMAT = "input-format"
    INPUT_DATA = "input-data"
    RECEIPT_SECURITY_SELECTION = "receipt-security-selection"
    TRANSACTION_SET = "transaction-set"
    REFNUM = "refnum"
    REFNUM_ORIG = "refnum-orig"


class InputFormat(str, Enum):
    """The data dictionary allows X12/FF/error. This gateway scopes to X12
    only: it's a pure automated HTTP/API service (the spec's "Batch Browser"
    model). `FF` belongs to the separate "Internet Flat File EDM" mechanism
    built around an Interactive Browser/HTML upload form for humans
    (Appendix B/C), which is out of scope here. `error` is only meaningful
    for the Error Notification flow, which this gateway also doesn't
    implement (it decrypts synchronously before sending the receipt, so
    decryption errors are always reported in that same receipt)."""

    X12 = "X12"


RECEIPT_REPORT_TYPE_LITERAL = "gisb-acknowledgement-receipt"


class EnvelopeFields(BaseModel):
    """Required + mutually-agreed-optional Internet ET envelope fields, in
    the spec-mandated order (see "Sender HTTP Request Data Elements")."""

    from_id: str
    to_id: str
    version: str
    receipt_disposition_to: str
    receipt_report_type: str = RECEIPT_REPORT_TYPE_LITERAL
    input_format: InputFormat
    receipt_security_selection: str
    # Mutually agreed (optional). transaction-set is an "8 character code"
    # per the data dictionary -- the real WGQ code table isn't available to
    # us, so it's treated as an opaque, length-validated string rather than
    # derived from e.g. a 3-digit ANSI X12 transaction set number.
    transaction_set: str | None = None
    refnum: str | None = None
    refnum_orig: str | None = None

    @field_validator("from_id", "to_id")
    @classmethod
    def _normalize_duns(cls, value: str) -> str:
        return normalize_duns(value)

    @field_validator("transaction_set")
    @classmethod
    def _validate_transaction_set(cls, value: str | None) -> str | None:
        if value is not None and len(value) != 8:
            raise ValueError("transaction-set must be an 8-character code per the data dictionary")
        return value

    @field_validator("refnum", "refnum_orig")
    @classmethod
    def _validate_refnum(cls, value: str | None) -> str | None:
        if value is not None and (len(value) > 40 or not value.isdigit()):
            raise ValueError("refnum/refnum-orig must be a maximum 40-character integer value")
        return value
