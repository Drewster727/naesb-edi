import asyncio
from pathlib import Path

from app.message import InboundMessage
from app.sinks.base import SinkResult


class FilesystemSink:
    name = "filesystem"

    def __init__(self, base_dir: str, durable: bool = True):
        self.base_dir = Path(base_dir)
        self.durable = durable

    async def deliver(self, message: InboundMessage) -> SinkResult:
        try:
            await asyncio.to_thread(self._write, message)
            return SinkResult(sink_name=self.name, ok=True)
        except OSError as exc:
            return SinkResult(sink_name=self.name, ok=False, error=str(exc))

    def _write(self, message: InboundMessage) -> None:
        partner_dir = self.base_dir / message.partner_name
        partner_dir.mkdir(parents=True, exist_ok=True)
        filename = (
            f"{message.received_at.strftime('%Y%m%dT%H%M%SZ')}"
            f"_{message.content_digest[:16]}"
            f"_{message.envelope.transaction_set}.edi"
        )
        (partner_dir / filename).write_bytes(message.plaintext)
