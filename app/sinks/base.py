from dataclasses import dataclass
from typing import Protocol

from app.message import InboundMessage


@dataclass
class SinkResult:
    sink_name: str
    ok: bool
    error: str | None = None


class Sink(Protocol):
    name: str
    durable: bool

    async def deliver(self, message: InboundMessage) -> SinkResult: ...
