import asyncio
from datetime import UTC, datetime

from app.envelope.fields import EnvelopeFields, InputFormat
from app.message import InboundMessage
from app.sinks.filesystem_sink import FilesystemSink


def _message(**overrides) -> InboundMessage:
    defaults = dict(
        partner_name="acme-pipeline",
        content_digest="abc123def456" + "0" * 52,
        envelope=EnvelopeFields(
            version="4.0", from_id="987654321", to_id="123456789", input_format=InputFormat.X12, transaction_set="873"
        ),
        plaintext=b"ISA*00*...",
        received_at=datetime(2026, 7, 8, 19, 30, 0, tzinfo=UTC),
    )
    defaults.update(overrides)
    return InboundMessage(**defaults)


def test_filesystem_sink_writes_file(tmp_path):
    sink = FilesystemSink(base_dir=str(tmp_path))
    message = _message()

    result = asyncio.run(sink.deliver(message))

    assert result.ok
    assert result.sink_name == "filesystem"
    written = list((tmp_path / "987654321").iterdir())
    assert len(written) == 1
    assert written[0].read_bytes() == b"ISA*00*..."
    assert "873" in written[0].name


def test_filesystem_sink_creates_duns_subdirectory(tmp_path):
    sink = FilesystemSink(base_dir=str(tmp_path))
    envelope = EnvelopeFields(
        version="4.0", from_id="111222333", to_id="123456789", input_format=InputFormat.X12, transaction_set="873"
    )
    asyncio.run(sink.deliver(_message(partner_name="other-partner", envelope=envelope)))
    assert (tmp_path / "111222333").is_dir()


def test_filesystem_sink_reports_failure_on_unwritable_dir(tmp_path):
    unwritable = tmp_path / "locked"
    unwritable.mkdir(mode=0o400)
    sink = FilesystemSink(base_dir=str(unwritable / "partner_dir"))

    result = asyncio.run(sink.deliver(_message()))

    assert not result.ok
    assert result.error is not None
