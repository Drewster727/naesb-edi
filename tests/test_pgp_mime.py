import pytest

from app.envelope.pgp_mime import PgpMimeError, unwrap_pgp_encrypted, wrap_pgp_encrypted


def test_wrap_unwrap_roundtrip():
    ciphertext = b"\x00\x01\x02not really PGP but binary-safe\xff\xfe\r\n--boundary-lookalike\r\n"
    body, content_type = wrap_pgp_encrypted(ciphertext)

    assert content_type.startswith("multipart/encrypted;")
    assert 'protocol="application/pgp-encrypted"' in content_type

    extracted = unwrap_pgp_encrypted(body, content_type)
    assert extracted == ciphertext


def test_wrap_produces_pgp_encrypted_control_part():
    body, content_type = wrap_pgp_encrypted(b"payload")
    assert b"application/pgp-encrypted" in body
    assert b"Version: 1" in body


def test_unwrap_missing_boundary_raises():
    with pytest.raises(PgpMimeError):
        unwrap_pgp_encrypted(b"whatever", "multipart/encrypted")


def test_unwrap_wrong_first_part_type_raises():
    body, content_type = wrap_pgp_encrypted(b"payload")
    tampered = body.replace(b"application/pgp-encrypted", b"text/plain", 1)
    with pytest.raises(PgpMimeError):
        unwrap_pgp_encrypted(tampered, content_type)


def test_wrap_unwrap_roundtrip_empty_ciphertext_rejected():
    body, content_type = wrap_pgp_encrypted(b"x")
    # Sanity: a genuinely empty payload part should still fail cleanly
    # rather than silently succeed with empty bytes.
    boundary = content_type.split("boundary=")[1].split(";")[0].strip('"')
    corrupted = body.replace(b"x\r\n--" + boundary.encode(), b"\r\n--" + boundary.encode())
    with pytest.raises(PgpMimeError):
        unwrap_pgp_encrypted(corrupted, content_type)
