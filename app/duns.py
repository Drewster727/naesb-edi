def normalize_duns(value: str) -> str:
    """Canonicalizes a DUNS-like identifier by left-padding pure-numeric
    values shorter than 9 digits with leading zeros. DUNS numbers are
    9-digit codes that may start with 0, and commonly lose that leading
    zero when passed through systems (spreadsheets, ERPs, config files)
    that treat the value as an integer rather than a fixed-width string.

    Values that aren't purely numeric, or are already >= 9 digits, are left
    untouched -- identity comparisons elsewhere should reject those as
    genuine mismatches rather than have this silently coerce them."""
    return value.zfill(9) if value.isdigit() and len(value) < 9 else value
