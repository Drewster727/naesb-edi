import pytest

from app.envelope.codec import EnvelopeError, build_headers, parse_headers
from app.envelope.fields import CanonicalField, EnvelopeFields, InputFormat
from app.envelope.mapping import HeaderMapping, HeaderOverrides, merge

DEFAULT_MAPPING = HeaderMapping(
    {
        CanonicalField.VERSION: "version",
        CanonicalField.FROM_ID: "from-id",
        CanonicalField.TO_ID: "to-id",
        CanonicalField.INPUT_FORMAT: "input-format",
        CanonicalField.TRANSACTION_SET: "transaction-set",
    }
)


def test_build_headers_uses_literal_lowercase_names():
    fields = EnvelopeFields(
        version="4.0", from_id="123456789", to_id="987654321",
        input_format=InputFormat.X12, transaction_set="873",
    )
    headers = build_headers(fields, DEFAULT_MAPPING)
    assert headers == {
        "version": "4.0",
        "from-id": "123456789",
        "to-id": "987654321",
        "input-format": "X12",
        "transaction-set": "873",
    }


def test_parse_headers_round_trips_build_headers():
    fields = EnvelopeFields(
        version="4.0", from_id="123456789", to_id="987654321",
        input_format=InputFormat.XML, transaction_set="861",
    )
    headers = build_headers(fields, DEFAULT_MAPPING)
    parsed = parse_headers(headers, DEFAULT_MAPPING)
    assert parsed == fields


def test_parse_headers_is_case_insensitive_on_incoming_names():
    headers = {
        "Version": "4.0",
        "From-Id": "123456789",
        "To-Id": "987654321",
        "Input-Format": "X12",
        "Transaction-Set": "873",
    }
    parsed = parse_headers(headers, DEFAULT_MAPPING)
    assert parsed.from_id == "123456789"


def test_parse_headers_missing_field_raises():
    headers = {"version": "4.0", "from-id": "123456789"}
    with pytest.raises(EnvelopeError):
        parse_headers(headers, DEFAULT_MAPPING)


def test_parse_headers_invalid_input_format_raises():
    headers = {
        "version": "4.0", "from-id": "1", "to-id": "2",
        "input-format": "NOT_A_FORMAT", "transaction-set": "873",
    }
    with pytest.raises(EnvelopeError):
        parse_headers(headers, DEFAULT_MAPPING)


def test_header_mapping_rejects_uppercase_names():
    with pytest.raises(ValueError):
        HeaderMapping(
            {
                CanonicalField.VERSION: "Version",
                CanonicalField.FROM_ID: "from-id",
                CanonicalField.TO_ID: "to-id",
                CanonicalField.INPUT_FORMAT: "input-format",
                CanonicalField.TRANSACTION_SET: "transaction-set",
            }
        )


def test_header_mapping_requires_all_fields():
    with pytest.raises(ValueError):
        HeaderMapping({CanonicalField.VERSION: "version"})


def test_partner_override_replaces_only_named_fields():
    override = HeaderOverrides({CanonicalField.TRANSACTION_SET: "x-transaction-set"})
    merged = merge(DEFAULT_MAPPING, override)

    assert merged.name_for(CanonicalField.TRANSACTION_SET) == "x-transaction-set"
    assert merged.name_for(CanonicalField.FROM_ID) == "from-id"  # untouched


def test_merge_with_no_override_returns_default():
    assert merge(DEFAULT_MAPPING, None) is DEFAULT_MAPPING
