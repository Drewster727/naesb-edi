from collections.abc import Mapping

from app.envelope.fields import CanonicalField, EnvelopeFields, InputFormat
from app.envelope.mapping import HeaderMapping


class EnvelopeError(Exception):
    """Raised when required NAESB transport headers are missing or malformed.
    Maps to error-code 103 (Invalid Header Parameters) per naesb4.md section 4."""


def build_headers(fields: EnvelopeFields, mapping: HeaderMapping) -> dict[str, str]:
    return {
        mapping.name_for(CanonicalField.VERSION): fields.version,
        mapping.name_for(CanonicalField.FROM_ID): fields.from_id,
        mapping.name_for(CanonicalField.TO_ID): fields.to_id,
        mapping.name_for(CanonicalField.INPUT_FORMAT): fields.input_format.value,
        mapping.name_for(CanonicalField.TRANSACTION_SET): fields.transaction_set,
    }


def parse_headers(raw_headers: Mapping[str, str], mapping: HeaderMapping) -> EnvelopeFields:
    # HTTP headers are case-insensitive on the wire; normalize the incoming
    # mapping's keys to lowercase for lookup regardless of how the caller's
    # framework presents them (naesb4.md itself mandates lowercase headers,
    # but we should still parse whatever case shows up).
    lowered = {k.lower(): v for k, v in raw_headers.items()}

    def get(field: CanonicalField) -> str:
        header_name = mapping.name_for(field)
        value = lowered.get(header_name)
        if value is None or not value.strip():
            raise EnvelopeError(f"missing required header {header_name!r} ({field.value})")
        return value.strip()

    try:
        input_format = InputFormat(get(CanonicalField.INPUT_FORMAT))
    except ValueError as exc:
        raise EnvelopeError(f"invalid input-format: {exc}") from exc

    return EnvelopeFields(
        version=get(CanonicalField.VERSION),
        from_id=get(CanonicalField.FROM_ID),
        to_id=get(CanonicalField.TO_ID),
        input_format=input_format,
        transaction_set=get(CanonicalField.TRANSACTION_SET),
    )
