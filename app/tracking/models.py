from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class MessageRecord:
    direction: str  # "inbound" | "outbound"
    partner_name: str
    content_digest: str
    transaction_set: str | None = None
    input_format: str | None = None
    status: str = "pending"
    error_code: int | None = None
    receipt_verified: bool | None = None
    sinks_status: dict[str, Any] = field(default_factory=dict)
    raw_headers: dict[str, Any] | None = None
    received_at: datetime | None = None
    sent_at: datetime | None = None
