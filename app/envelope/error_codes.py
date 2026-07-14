"""Real NAESB WGQ Cybersecurity Related Standards v4.0 error/warning codes
(Appendices, "Table 1 - Internet ET Standard Error Codes and Messages").

EEDM### = standard error format; further processing does not take place.
WEDM### = standard warning format; further processing does take place.

This is a subset of the documented table (the fields this gateway can
actually detect at the transport layer -- missing/invalid envelope fields,
crypto failures, unknown partner). Codes in the 700s that depend on
downstream business-process knowledge this gateway doesn't have (e.g.
EEDM702/EEDM703, which require QEDM-level format/agreement knowledge) are
included for completeness but only used where we genuinely can tell.
"""

from enum import Enum


class NaesbErrorCode(str, Enum):
    MISSING_FROM = "EEDM100"
    MISSING_TO = "EEDM101"
    MISSING_INPUT_FORMAT = "EEDM102"
    MISSING_INPUT_DATA = "EEDM103"
    MISSING_TRANSACTION_SET = "EEDM104"
    INVALID_FROM = "EEDM105"
    INVALID_TO = "EEDM106"
    INVALID_INPUT_FORMAT = "EEDM107"
    INVALID_TRANSACTION_SET = "EEDM108"
    NO_PARAMETERS_SUPPLIED = "EEDM109"
    INVALID_VERSION = "EEDM110"
    MISSING_VERSION = "EEDM111"
    INVALID_RECEIPT_SECURITY_SELECTION = "EEDM113"
    MISSING_RECEIPT_DISPOSITION_TO = "EEDM114"
    INVALID_RECEIPT_DISPOSITION_TO = "EEDM115"
    MISSING_RECEIPT_REPORT_TYPE = "EEDM116"
    INVALID_RECEIPT_REPORT_TYPE = "EEDM117"
    MISSING_RECEIPT_SECURITY_SELECTION = "EEDM118"
    REFNUM_NOT_PRESENT = "EEDM119"
    REFNUM_ORIG_NOT_PRESENT = "EEDM120"
    DUPLICATE_REFNUM = "EEDM121"

    PUBLIC_KEY_INVALID = "EEDM601"
    FILE_NOT_ENCRYPTED = "EEDM602"
    ENCRYPTED_FILE_TRUNCATED = "EEDM603"
    SIGNATURE_NOT_MATCHED = "EEDM604"
    DECRYPTION_ERROR = "EEDM699"

    SENDER_NOT_ASSOCIATED = "EEDM701"
    PACKAGE_FORMAT_NOT_RECOGNIZED = "EEDM702"
    DATA_SET_EXCHANGE_NOT_ESTABLISHED = "EEDM703"
    SYSTEM_ERROR = "EEDM999"

    TRANSACTION_SET_NOT_MUTUALLY_AGREED = "WEDM100"
    MISSING_RECEIPT_SECURITY_SELECTION_WARNING = "WEDM103"
    REFNUM_RECEIVED_NOT_MUTUALLY_AGREED = "WEDM104"
    REFNUM_ORIG_RECEIVED_NOT_MUTUALLY_AGREED = "WEDM105"


NAESB_ERROR_DESCRIPTIONS: dict[NaesbErrorCode, str] = {
    NaesbErrorCode.MISSING_FROM: "Missing 'from' Common Code Identifier code",
    NaesbErrorCode.MISSING_TO: "Missing 'to' Common Code Identifier",
    NaesbErrorCode.MISSING_INPUT_FORMAT: "Missing input format",
    NaesbErrorCode.MISSING_INPUT_DATA: "Missing data file",
    NaesbErrorCode.MISSING_TRANSACTION_SET: "Missing transaction set",
    NaesbErrorCode.INVALID_FROM: "Invalid 'from' Common Code Identifier",
    NaesbErrorCode.INVALID_TO: "Invalid 'to' Common Code Identifier",
    NaesbErrorCode.INVALID_INPUT_FORMAT: "Invalid input format",
    NaesbErrorCode.INVALID_TRANSACTION_SET: "Invalid transaction set",
    NaesbErrorCode.NO_PARAMETERS_SUPPLIED: "No parameters supplied",
    NaesbErrorCode.INVALID_VERSION: "Invalid 'version'",
    NaesbErrorCode.MISSING_VERSION: "Missing 'version'",
    NaesbErrorCode.INVALID_RECEIPT_SECURITY_SELECTION: "Invalid 'receipt-security-selection'",
    NaesbErrorCode.MISSING_RECEIPT_DISPOSITION_TO: "Missing 'receipt-disposition-to'",
    NaesbErrorCode.INVALID_RECEIPT_DISPOSITION_TO: "Invalid 'receipt-disposition-to'",
    NaesbErrorCode.MISSING_RECEIPT_REPORT_TYPE: "Missing 'receipt-report-type'",
    NaesbErrorCode.INVALID_RECEIPT_REPORT_TYPE: "Invalid 'receipt-report-type'",
    NaesbErrorCode.MISSING_RECEIPT_SECURITY_SELECTION: "Missing 'receipt-security-selection'",
    NaesbErrorCode.REFNUM_NOT_PRESENT: "Mutually agreed element, refnum, not present",
    NaesbErrorCode.REFNUM_ORIG_NOT_PRESENT: "Mutually agreed element refnum-orig not present",
    NaesbErrorCode.DUPLICATE_REFNUM: "Duplicate refnum received",
    NaesbErrorCode.PUBLIC_KEY_INVALID: "Public key invalid",
    NaesbErrorCode.FILE_NOT_ENCRYPTED: "File not encrypted",
    NaesbErrorCode.ENCRYPTED_FILE_TRUNCATED: "Encrypted file truncated",
    NaesbErrorCode.SIGNATURE_NOT_MATCHED: "Encrypted file not signed or signature not matched",
    NaesbErrorCode.DECRYPTION_ERROR: "Decryption Error",
    NaesbErrorCode.SENDER_NOT_ASSOCIATED: "Sending party not associated with Receiving party",
    NaesbErrorCode.PACKAGE_FORMAT_NOT_RECOGNIZED: "Package file format not recognized by Receiving party",
    NaesbErrorCode.DATA_SET_EXCHANGE_NOT_ESTABLISHED: "Data set exchange not established for Trading Partner",
    NaesbErrorCode.SYSTEM_ERROR: "System error",
    NaesbErrorCode.TRANSACTION_SET_NOT_MUTUALLY_AGREED: "Transaction set sent not mutually agreed",
    NaesbErrorCode.MISSING_RECEIPT_SECURITY_SELECTION_WARNING: "Missing 'receipt-security-selection'",
    NaesbErrorCode.REFNUM_RECEIVED_NOT_MUTUALLY_AGREED: "Element refnum received, not mutually agreed; ignored",
    NaesbErrorCode.REFNUM_ORIG_RECEIVED_NOT_MUTUALLY_AGREED: (
        "Refnum-orig received but not mutually agreed; ignored"
    ),
}


class GatewayExtensionCode(str, Enum):
    """Local extensions this gateway needs (dedup, sink durability, weak-key
    policy, transport auth) that have no real NAESB-assigned code. Prefixed
    `GWX-` so the shape can never collide with the fixed `EEDM###`/`WEDM###`
    codes above -- these are NOT NAESB-assigned."""

    DUPLICATE_DIGEST = "GWX-DUPLICATE-DIGEST"
    WEAK_ALGORITHM = "GWX-WEAK-ALGO"
    SINK_FAILURE = "GWX-SINK-FAILURE"
    UNAUTHENTICATED = "GWX-UNAUTHENTICATED"


GATEWAY_EXTENSION_DESCRIPTIONS: dict[GatewayExtensionCode, str] = {
    GatewayExtensionCode.DUPLICATE_DIGEST: "Duplicate transmission (content digest already processed)",
    GatewayExtensionCode.WEAK_ALGORITHM: "Weak cryptographic algorithm or key length",
    GatewayExtensionCode.SINK_FAILURE: "No durable delivery sink accepted the payload",
    GatewayExtensionCode.UNAUTHENTICATED: "Transport-level authentication failed",
}

ErrorCode = NaesbErrorCode | GatewayExtensionCode


def describe(code: ErrorCode) -> str:
    if isinstance(code, NaesbErrorCode):
        return NAESB_ERROR_DESCRIPTIONS[code]
    return GATEWAY_EXTENSION_DESCRIPTIONS[code]


# Maps (envelope field name, "missing"|"invalid") -> the exact EEDM1xx code,
# per the data dictionary field list in "Sending Internet ET Packages".
FIELD_ERROR_CODES: dict[tuple[str, str], NaesbErrorCode] = {
    ("from", "missing"): NaesbErrorCode.MISSING_FROM,
    ("from", "invalid"): NaesbErrorCode.INVALID_FROM,
    ("to", "missing"): NaesbErrorCode.MISSING_TO,
    ("to", "invalid"): NaesbErrorCode.INVALID_TO,
    ("input-format", "missing"): NaesbErrorCode.MISSING_INPUT_FORMAT,
    ("input-format", "invalid"): NaesbErrorCode.INVALID_INPUT_FORMAT,
    ("input-data", "missing"): NaesbErrorCode.MISSING_INPUT_DATA,
    ("input-data", "invalid"): NaesbErrorCode.FILE_NOT_ENCRYPTED,
    ("transaction-set", "missing"): NaesbErrorCode.MISSING_TRANSACTION_SET,
    ("transaction-set", "invalid"): NaesbErrorCode.INVALID_TRANSACTION_SET,
    ("version", "missing"): NaesbErrorCode.MISSING_VERSION,
    ("version", "invalid"): NaesbErrorCode.INVALID_VERSION,
    ("receipt-disposition-to", "missing"): NaesbErrorCode.MISSING_RECEIPT_DISPOSITION_TO,
    ("receipt-disposition-to", "invalid"): NaesbErrorCode.INVALID_RECEIPT_DISPOSITION_TO,
    ("receipt-report-type", "missing"): NaesbErrorCode.MISSING_RECEIPT_REPORT_TYPE,
    ("receipt-report-type", "invalid"): NaesbErrorCode.INVALID_RECEIPT_REPORT_TYPE,
    ("receipt-security-selection", "missing"): NaesbErrorCode.MISSING_RECEIPT_SECURITY_SELECTION,
    ("receipt-security-selection", "invalid"): NaesbErrorCode.INVALID_RECEIPT_SECURITY_SELECTION,
}


def error_code_for_field(field: str, problem: str) -> NaesbErrorCode:
    """Looks up the exact EEDM1xx code for a given envelope field/problem;
    falls back to the generic "no parameters supplied" code for anything not
    in the table above (e.g. a field name we don't recognize at all)."""
    return FIELD_ERROR_CODES.get((field, problem), NaesbErrorCode.NO_PARAMETERS_SUPPLIED)
