import pytest

from app.envelope.error_codes import GatewayExtensionCode, NaesbErrorCode
from app.envelope.receipt import (
    NaesbReceipt,
    ReceiptDecodeError,
    build_signed_mime,
    parse_signed_mime,
)


def test_ok_receipt_report_part_round_trips():
    receipt = NaesbReceipt.ok(server_id="coolhost", trans_id=234423897)
    report_body, content_type = receipt.encode_report_part()

    assert content_type.startswith("multipart/report;")
    assert 'report-type="gisb-acknowledgement-receipt"' in content_type
    assert b"request-status=ok*" in report_body
    assert b"server-id=coolhost*" in report_body
    assert b"trans-id=234423897*" in report_body

    decoded = NaesbReceipt.decode_report_part(report_body, content_type)
    assert decoded == receipt


def test_rejected_receipt_uses_real_eedm_code():
    receipt = NaesbReceipt.rejected("coolhost", 1, NaesbErrorCode.SIGNATURE_NOT_MATCHED)
    report_body, content_type = receipt.encode_report_part()

    assert b"request-status=EEDM604: Encrypted file not signed or signature not matched*" in report_body

    decoded = NaesbReceipt.decode_report_part(report_body, content_type)
    assert decoded.request_status.startswith("EEDM604")
    assert not decoded.is_ok


def test_rejected_receipt_uses_gateway_extension_code():
    receipt = NaesbReceipt.rejected("coolhost", 2, GatewayExtensionCode.DUPLICATE_DIGEST)
    report_body, _ = receipt.encode_report_part()
    assert b"GWX-DUPLICATE-DIGEST" in report_body


def test_time_c_format_is_yyyymmddhhmmss():
    import datetime

    receipt = NaesbReceipt.ok(
        "coolhost", 1, time_c=datetime.datetime(1996, 6, 19, 8, 28, 55, tzinfo=datetime.UTC)
    )
    assert receipt.time_c == "19960619082855"


def test_decode_report_part_rejects_missing_field():
    with pytest.raises(ReceiptDecodeError):
        NaesbReceipt.decode_report_part(
            b'--B\r\ncontent-type: text/plain\r\n\r\nrequest-status=ok*\r\n--B--\r\n',
            'multipart/report; report-type="gisb-acknowledgement-receipt"; boundary="B"',
        )


def test_signed_mime_wrap_and_parse_round_trip_bytes():
    receipt = NaesbReceipt.ok("coolhost", 42)
    report_body, report_content_type = receipt.encode_report_part()
    fake_signature = b"-----BEGIN PGP SIGNATURE-----\nfake\n-----END PGP SIGNATURE-----\n"

    signed_body, content_type = build_signed_mime(report_body, report_content_type, fake_signature, "pgp-sha256")

    assert content_type.startswith("multipart/signed;")
    assert 'protocol="application/pgp-signature"' in content_type
    assert 'micalg="pgp-sha256"' in content_type

    parsed_report_body, parsed_report_content_type, parsed_signature = parse_signed_mime(
        signed_body, content_type
    )
    assert parsed_report_body == report_body
    assert parsed_report_content_type == report_content_type
    assert parsed_signature.rstrip(b"\r\n") == fake_signature.rstrip(b"\r\n")


def test_full_signed_receipt_round_trip_with_real_gpg(gpg_service, us_key):
    """The exact scenario used in production: encode a report, detached-sign
    it with real GnuPG, wrap in multipart/signed, then parse it back out and
    verify the signature against the *exact* bytes extracted by the
    manual MIME splitter -- this is what proves split_mime_parts() never
    mutates the bytes that were actually signed."""
    receipt = NaesbReceipt.ok("coolhost", 999)
    report_body, report_content_type = receipt.encode_report_part()

    signature = gpg_service.detached_sign(report_body, signer_fingerprint=us_key, passphrase="us-passphrase")
    micalg = "pgp-sha256"
    signed_body, content_type = build_signed_mime(report_body, report_content_type, signature, micalg)

    parsed_report_body, parsed_report_content_type, parsed_signature = parse_signed_mime(
        signed_body, content_type
    )
    verify_result = gpg_service.verify_detached(parsed_report_body, parsed_signature, expected_fingerprint=us_key)
    assert verify_result.valid

    decoded = NaesbReceipt.decode_report_part(parsed_report_body, parsed_report_content_type)
    assert decoded == receipt


def test_parse_signed_mime_rejects_wrong_part_count():
    with pytest.raises(ReceiptDecodeError):
        parse_signed_mime(
            b"--B\r\ncontent-type: text/plain\r\n\r\nx\r\n--B--\r\n",
            'multipart/signed; protocol="application/pgp-signature"; boundary="B"',
        )
