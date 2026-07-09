import base64

import httpx

from app.message import InboundMessage
from app.sinks.base import SinkResult


class WebhookSink:
    name = "webhook"
    durable = False

    def __init__(self, url: str, timeout_seconds: float = 10.0):
        self.url = url
        self.timeout_seconds = timeout_seconds

    async def deliver(self, message: InboundMessage) -> SinkResult:
        payload = {
            "partner": message.partner_name,
            "content_digest": message.content_digest,
            "transaction_set": message.envelope.transaction_set,
            "input_format": message.envelope.input_format.value,
            "received_at": message.received_at.isoformat(),
            "payload_base64": base64.b64encode(message.plaintext).decode("ascii"),
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(self.url, json=payload)
                response.raise_for_status()
            return SinkResult(sink_name=self.name, ok=True)
        except httpx.HTTPError as exc:
            return SinkResult(sink_name=self.name, ok=False, error=str(exc))
