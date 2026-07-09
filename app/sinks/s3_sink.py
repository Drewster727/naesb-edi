import asyncio

import boto3

from app.message import InboundMessage
from app.sinks.base import SinkResult


class S3Sink:
    name = "s3"

    def __init__(
        self,
        bucket: str,
        prefix: str,
        region: str,
        endpoint_url: str | None,
        access_key: str,
        secret_key: str,
        durable: bool = True,
    ):
        self.bucket = bucket
        self.prefix = prefix
        self.durable = durable
        self.client = boto3.client(
            "s3",
            region_name=region,
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )

    async def deliver(self, message: InboundMessage) -> SinkResult:
        try:
            await asyncio.to_thread(self._put, message)
            return SinkResult(sink_name=self.name, ok=True)
        except Exception as exc:  # noqa: BLE001 - boto3 raises various botocore exceptions
            return SinkResult(sink_name=self.name, ok=False, error=str(exc))

    def _put(self, message: InboundMessage) -> None:
        # Keyed by DUNS (the canonical wire identifier, message.envelope.from_id)
        # rather than the partner's config-file name label.
        key = (
            f"{self.prefix}{message.envelope.from_id}/"
            f"{message.received_at.strftime('%Y%m%dT%H%M%SZ')}"
            f"_{message.content_digest[:16]}"
            f"_{message.envelope.transaction_set}.edi"
        )
        self.client.put_object(Bucket=self.bucket, Key=key, Body=message.plaintext)
