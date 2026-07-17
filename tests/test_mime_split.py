from app.envelope.mime_split import content_type_param, split_mime_parts


def test_split_basic_two_parts():
    data = (
        b"--BOUND\r\ncontent-type: text/plain\r\n\r\n"
        b"hello\r\n"
        b"--BOUND\r\ncontent-type: application/octet-stream\r\n\r\n"
        b"world\r\n"
        b"--BOUND--\r\n"
    )
    parts = split_mime_parts(data, "BOUND")
    assert parts == [
        ({"content-type": "text/plain"}, b"hello"),
        ({"content-type": "application/octet-stream"}, b"world"),
    ]


def test_split_ignores_marker_bytes_not_preceded_by_line_break():
    # Binary part content that happens to contain the literal marker bytes
    # *mid-line* (not at the start of a line) must not be mistaken for a real
    # boundary -- a plain substring search would incorrectly split here.
    payload = b"leading junk --BOUND embedded mid-line, not a real boundary"
    data = (
        b"--BOUND\r\ncontent-type: application/octet-stream\r\n\r\n"
        + payload
        + b"\r\n--BOUND--\r\n"
    )
    parts = split_mime_parts(data, "BOUND")
    assert len(parts) == 1
    assert parts[0][1] == payload


def test_split_tolerates_bare_lf_before_boundary():
    # Some real-world MIME producers emit bare LF rather than CRLF -- the
    # splitter should still find the boundary rather than raising.
    data = (
        b"--BOUND\ncontent-type: text/plain\n\n"
        b"hello\n"
        b"--BOUND--\n"
    )
    parts = split_mime_parts(data, "BOUND")
    assert parts == [({"content-type": "text/plain"}, b"hello")]


def test_content_type_param_extracts_boundary():
    assert content_type_param('multipart/mixed; boundary="ABC123"', "boundary") == "ABC123"
