"""Manual byte-level MIME multipart splitter.

We deliberately don't use `email.generator` to re-serialize parts when
extracting bytes for PGP signature verification: re-serialization through
Python's `email` package is not guaranteed to reproduce byte-identical
output to what was actually transmitted (header folding, charset handling,
etc.), and PGP signatures are byte-exact. This hand-rolled splitter never
reconstructs bytes -- it only slices the original buffer.
"""

import re

CRLF = b"\r\n"


class MimeSplitError(Exception):
    pass


def content_type_param(content_type: str, name: str) -> str | None:
    for piece in content_type.split(";")[1:]:
        piece = piece.strip()
        if piece.lower().startswith(f"{name.lower()}="):
            value = piece[len(name) + 1 :].strip()
            return value.strip('"')
    return None


def split_mime_parts(data: bytes, boundary: str) -> list[tuple[dict[str, str], bytes]]:
    """Split a MIME multipart body into (headers, body) pairs for each part,
    given the boundary token (without the leading `--`)."""
    marker = b"--" + boundary.encode()
    # Per RFC 2046, a boundary delimiter line must be preceded by a line break
    # (or be at the very start of the body) -- a plain substring search would
    # also match the marker bytes appearing anywhere inside binary part
    # content (e.g. PGP ciphertext) not actually at a line start. Only
    # relevant for partner-chosen boundaries (our own are 128 bits of random
    # hex, so a spurious mid-content collision is negligible either way).
    # Tolerates a bare LF as well as CRLF before the marker, matching this
    # module's existing tolerance for LF-only producers (see the `\n\n`
    # fallback below) -- real trading partners' MIME stacks aren't uniform.
    boundary_pattern = re.compile(b"(?:^|" + re.escape(CRLF) + b"|\n)" + re.escape(marker))
    raw_parts = boundary_pattern.split(data)
    if len(raw_parts) < 3:
        raise MimeSplitError(f"boundary {boundary!r} not found (or found only once) in MIME body")

    # The line break immediately preceding each boundary occurrence (matched
    # above) is part of the *next* part's leading delimiter, not trailing
    # content -- re.split() already consumes it, so unlike a bare substring
    # split, no further trailing-newline stripping is needed here.
    parts: list[tuple[dict[str, str], bytes]] = []
    for raw in raw_parts[1:]:
        if raw.startswith(b"--"):
            break  # final boundary terminator ("--boundary--")
        raw = raw[2:] if raw[:2] == CRLF else raw.lstrip(b"\r\n")
        if CRLF + CRLF in raw:
            header_bytes, body = raw.split(CRLF + CRLF, 1)
        elif b"\n\n" in raw:
            header_bytes, body = raw.split(b"\n\n", 1)
        else:
            header_bytes, body = b"", raw
        parts.append((_parse_headers(header_bytes), body))

    if not parts:
        raise MimeSplitError(f"no MIME parts found for boundary {boundary!r}")
    return parts


def _parse_headers(header_bytes: bytes) -> dict[str, str]:
    headers: dict[str, str] = {}
    text = header_bytes.decode("utf-8", errors="replace")
    for line in text.replace("\r\n", "\n").split("\n"):
        if not line.strip() or ":" not in line:
            continue
        key, _, value = line.partition(":")
        headers[key.strip().lower()] = value.strip()
    return headers
