import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime

from app.envelope.fields import EnvelopeFields, InputFormat
from app.message import InboundMessage
from app.sinks.dispatcher import fan_out, has_durable_success


def _message() -> InboundMessage:
    return InboundMessage(
        partner_name="acme-pipeline",
        content_digest="abc123",
        envelope=EnvelopeFields(
            version="4.0", from_id="1", to_id="2", input_format=InputFormat.X12, transaction_set="873"
        ),
        plaintext=b"data",
        received_at=datetime(2026, 7, 8, 19, 30, 0, tzinfo=UTC),
    )


@dataclass
class _FakeSink:
    name: str
    durable: bool
    succeed: bool = True
    raises: bool = False

    async def deliver(self, message):
        from app.sinks.base import SinkResult

        if self.raises:
            raise RuntimeError(f"{self.name} blew up")
        return SinkResult(sink_name=self.name, ok=self.succeed, error=None if self.succeed else "boom")


def test_fan_out_runs_all_sinks():
    sinks = [_FakeSink("a", durable=True), _FakeSink("b", durable=False)]
    results = asyncio.run(fan_out(sinks, _message()))
    assert set(results) == {"a", "b"}
    assert all(r.ok for r in results.values())


def test_fan_out_isolates_a_raising_sink():
    sinks = [_FakeSink("good", durable=True), _FakeSink("bad", durable=True, raises=True)]
    results = asyncio.run(fan_out(sinks, _message()))
    assert results["good"].ok
    assert not results["bad"].ok
    assert "blew up" in results["bad"].error


def test_fan_out_empty_sink_list():
    assert asyncio.run(fan_out([], _message())) == {}


def test_has_durable_success_true_when_a_durable_sink_ok():
    sinks = [_FakeSink("fs", durable=True), _FakeSink("webhook", durable=False, succeed=False)]
    results = asyncio.run(fan_out(sinks, _message()))
    assert has_durable_success(sinks, results)


def test_has_durable_success_false_when_all_durable_sinks_fail():
    sinks = [_FakeSink("fs", durable=True, succeed=False), _FakeSink("webhook", durable=False)]
    results = asyncio.run(fan_out(sinks, _message()))
    assert not has_durable_success(sinks, results)


def test_has_durable_success_true_when_no_durable_sinks_configured():
    sinks = [_FakeSink("webhook", durable=False, succeed=False)]
    results = asyncio.run(fan_out(sinks, _message()))
    assert has_durable_success(sinks, results)
