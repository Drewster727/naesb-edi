from enum import Enum

from pydantic import BaseModel


class CanonicalField(str, Enum):
    """Canonical transport metadata fields, per naesb4.md section 3.

    Each maps to a literal, strictly-lowercase HTTP header on the wire. The
    actual header *name* used for each field lives in config (HeaderMapping),
    not here -- this enum is the stable internal vocabulary.
    """

    VERSION = "version"
    FROM_ID = "from_id"
    TO_ID = "to_id"
    INPUT_FORMAT = "input_format"
    TRANSACTION_SET = "transaction_set"


class InputFormat(str, Enum):
    X12 = "X12"
    XML = "XML"
    FLATFILE = "FLATFILE"


# Known WGQ-relevant ANSI ASC X12 transaction sets (naesb4.md section 5).
# Informational only -- the gateway treats transaction_set as opaque metadata
# and does not require it to be one of these.
KNOWN_TRANSACTION_SETS = {
    "873": "Nomination",
    "861": "Scheduled Quantity",
    "811": "Consolidated Invoice",
    "824": "Application Advice",
}


class EnvelopeFields(BaseModel):
    version: str
    from_id: str
    to_id: str
    input_format: InputFormat
    transaction_set: str
