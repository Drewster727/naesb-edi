import asyncio
from collections.abc import Sequence

from app.message import InboundMessage
from app.sinks.base import Sink, SinkResult


async def fan_out(sinks: Sequence[Sink], message: InboundMessage) -> dict[str, SinkResult]:
    """Deliver to all enabled sinks concurrently; one sink raising never
    prevents the others from running."""
    if not sinks:
        return {}
    results = await asyncio.gather(*(_deliver_safely(sink, message) for sink in sinks))
    return {result.sink_name: result for result in results}


async def _deliver_safely(sink: Sink, message: InboundMessage) -> SinkResult:
    try:
        return await sink.deliver(message)
    except Exception as exc:  # noqa: BLE001 - isolate arbitrary sink failures
        return SinkResult(sink_name=sink.name, ok=False, error=str(exc))


def has_durable_success(sinks: Sequence[Sink], results: dict[str, SinkResult]) -> bool:
    durable_names = {sink.name for sink in sinks if sink.durable}
    if not durable_names:
        return True  # no durable sinks configured -- nothing to require
    return any(name in results and results[name].ok for name in durable_names)
