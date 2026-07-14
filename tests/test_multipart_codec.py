from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.envelope.fields import EnvelopeFields, InputFormat
from app.envelope.multipart_codec import build_multipart_body, parse_multipart_form


def _fields(**overrides) -> EnvelopeFields:
    defaults = dict(
        from_id="123456789",
        to_id="987654321",
        version="1.9",
        receipt_disposition_to="123456789",
        input_format=InputFormat.X12,
        receipt_security_selection="signed-receipt-protocol=required,pgp-signature;signed-receipt-micalg=required,sha256",
        transaction_set="NOM00001",
    )
    defaults.update(overrides)
    return EnvelopeFields(**defaults)


def _build_parse_app() -> FastAPI:
    app = FastAPI()

    @app.post("/parse")
    async def parse(request: Request):
        form = await request.form()
        fields, ciphertext = await parse_multipart_form(form)
        return {
            "from_id": fields.from_id,
            "to_id": fields.to_id,
            "version": fields.version,
            "input_format": fields.input_format.value,
            "transaction_set": fields.transaction_set,
            "refnum": fields.refnum,
            "refnum_orig": fields.refnum_orig,
            "receipt_report_type": fields.receipt_report_type,
            "ciphertext_b64": ciphertext.hex(),
        }

    return app


def test_build_then_parse_round_trips_all_fields():
    fields = _fields(refnum="123467890123456", refnum_orig="123467890123456")
    body, content_type = build_multipart_body(fields, b"totally-not-real-pgp-bytes")

    client = TestClient(_build_parse_app())
    response = client.post("/parse", content=body, headers={"content-type": content_type})

    assert response.status_code == 200
    data = response.json()
    assert data["from_id"] == "123456789"
    assert data["to_id"] == "987654321"
    assert data["version"] == "1.9"
    assert data["input_format"] == "X12"
    assert data["transaction_set"] == "NOM00001"
    assert data["refnum"] == "123467890123456"
    assert data["refnum_orig"] == "123467890123456"
    assert data["receipt_report_type"] == "gisb-acknowledgement-receipt"
    assert bytes.fromhex(data["ciphertext_b64"]) == b"totally-not-real-pgp-bytes"


def test_build_omits_mutually_agreed_fields_when_absent():
    fields = _fields(transaction_set=None)
    body, content_type = build_multipart_body(fields, b"x")
    assert b'name="transaction-set"' not in body
    assert b'name="refnum"' not in body


def test_field_order_matches_spec_required_order():
    fields = _fields()
    body, _ = build_multipart_body(fields, b"x")
    expected_order = [b'name="from"', b'name="to"', b'name="version"',
                       b'name="receipt-disposition-to"', b'name="receipt-report-type"',
                       b'name="input-format"', b'name="input-data"',
                       b'name="receipt-security-selection"', b'name="transaction-set"']
    positions = [body.index(marker) for marker in expected_order]
    assert positions == sorted(positions)


def test_parse_missing_required_field_raises_envelope_error():
    fields = _fields()
    body, content_type = build_multipart_body(fields, b"x")
    # Corrupt the 'to' field name so it's no longer recognized.
    corrupted = body.replace(b'name="to"', b'name="to-corrupted"')

    client = TestClient(_build_parse_app(), raise_server_exceptions=False)
    response = client.post("/parse", content=corrupted, headers={"content-type": content_type})
    assert response.status_code == 500  # unhandled EnvelopeError surfaces as 500 in this bare test app


def test_parse_invalid_input_format_raises():
    fields = _fields()
    body, content_type = build_multipart_body(fields, b"x")
    corrupted = body.replace(b"X12", b"EBCDIC")

    client = TestClient(_build_parse_app(), raise_server_exceptions=False)
    response = client.post("/parse", content=corrupted, headers={"content-type": content_type})
    assert response.status_code == 500
