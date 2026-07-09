import asyncio
from datetime import UTC, datetime

import httpx
import respx

from app.envelope.fields import EnvelopeFields, InputFormat
from app.message import InboundMessage
from app.sinks.webhook_sink import WebhookSink


def _message() -> InboundMessage:
    return InboundMessage(
        partner_name="acme-pipeline",
        content_digest="abc123",
        envelope=EnvelopeFields(
            version="4.0", from_id="1", to_id="2", input_format=InputFormat.X12, transaction_set="873"
        ),
        plaintext=b"ISA*00*...",
        received_at=datetime(2026, 7, 8, 19, 30, 0, tzinfo=UTC),
    )


@respx.mock
def test_webhook_sink_posts_payload():
    route = respx.post("https://internal.example.com/hook").mock(return_value=httpx.Response(200))
    sink = WebhookSink(url="https://internal.example.com/hook")

    result = asyncio.run(sink.deliver(_message()))

    assert result.ok
    assert route.called
    sent_body = route.calls.last.request.content
    assert b"acme-pipeline" in sent_body


@respx.mock
def test_webhook_sink_reports_failure_on_http_error():
    respx.post("https://internal.example.com/hook").mock(return_value=httpx.Response(500))
    sink = WebhookSink(url="https://internal.example.com/hook")

    result = asyncio.run(sink.deliver(_message()))

    assert not result.ok
    assert result.error is not None
