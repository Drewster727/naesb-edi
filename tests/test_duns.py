from app.duns import normalize_duns


def test_pads_short_numeric_value_to_nine_digits():
    assert normalize_duns("123456789") == "123456789"
    assert normalize_duns("23456789") == "023456789"
    assert normalize_duns("1") == "000000001"


def test_leaves_already_nine_digit_value_unchanged():
    assert normalize_duns("023456789") == "023456789"


def test_leaves_non_numeric_value_unchanged():
    assert normalize_duns("ABC123") == "ABC123"
    assert normalize_duns("") == ""


def test_leaves_overlong_numeric_value_unchanged():
    assert normalize_duns("1234567890") == "1234567890"
