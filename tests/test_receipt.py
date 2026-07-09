import pytest

from app.envelope.receipt import ReasonCode, Receipt, ReceiptDecodeError, ReceiptStatus


def test_accepted_receipt_encodes_and_decodes():
    receipt = Receipt.accepted()
    text = receipt.encode()

    assert "receipt-status: success" in text
    assert "receipt-timestamp:" in text
    assert "error-code: \n" in text

    decoded = Receipt.decode(text)
    assert decoded.status == ReceiptStatus.SUCCESS
    assert decoded.error_code is None
    assert decoded.error_description is None
    # timestamps round-trip at second precision (the wire format has no sub-second component)
    assert decoded.timestamp.replace(microsecond=0) == receipt.timestamp.replace(microsecond=0)


def test_rejected_receipt_encodes_documented_error_code():
    receipt = Receipt.rejected(ReasonCode.SIGNATURE_VERIFICATION_FAILED)
    text = receipt.encode()

    assert "receipt-status: validation-failed" in text
    assert "error-code: 102" in text
    assert "error-description: Signature Verification Failed" in text

    decoded = Receipt.decode(text)
    assert decoded.status == ReceiptStatus.VALIDATION_FAILED
    assert decoded.error_code == ReasonCode.SIGNATURE_VERIFICATION_FAILED


def test_rejected_receipt_custom_description():
    receipt = Receipt.rejected(ReasonCode.INVALID_HEADER_PARAMETERS, "missing to-id header")
    decoded = Receipt.decode(receipt.encode())
    assert decoded.error_description == "missing to-id header"


def test_decode_rejects_malformed_body():
    with pytest.raises(ReceiptDecodeError):
        Receipt.decode("not a valid receipt body at all")


def test_decode_rejects_missing_required_fields():
    with pytest.raises(ReceiptDecodeError):
        Receipt.decode("receipt-status: success\n")  # missing receipt-timestamp


@pytest.mark.parametrize("code", list(ReasonCode))
def test_every_reason_code_round_trips(code):
    receipt = Receipt.rejected(code)
    decoded = Receipt.decode(receipt.encode())
    assert decoded.error_code == code
