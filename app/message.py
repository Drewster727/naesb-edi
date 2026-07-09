from dataclasses import dataclass
from datetime import datetime

from app.envelope.fields import EnvelopeFields


@dataclass
class InboundMessage:
    """A successfully decrypted, verified inbound transmission, ready for
    delivery to sinks and tracking."""

    partner_name: str
    content_digest: str
    envelope: EnvelopeFields
    plaintext: bytes
    received_at: datetime
