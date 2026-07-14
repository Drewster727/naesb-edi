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
    error_code: str | None = None
    receipt_verified: bool | None = None
    trans_id: int | None = None
    refnum: str | None = None
    refnum_orig: str | None = None
    sinks_status: dict[str, Any] = field(default_factory=dict)
    raw_headers: dict[str, Any] | None = None
    received_at: datetime | None = None
    sent_at: datetime | None = None
    receipt_sent_at: datetime | None = None
    receipt_received_at: datetime | None = None


@dataclass
class OutboundJob:
    id: Any
    partner_name: str
    from_id: str
    to_id: str
    version: str
    input_format: str
    payload_ciphertext: bytes
    content_digest: str
    status: str = "queued"
    transaction_set: str | None = None
    refnum: str | None = None
    refnum_orig: str | None = None
    attempt_count: int = 0
    last_error_code: str | None = None
    last_error_description: str | None = None
    receipt_trans_id: str | None = None
    receipt_server_id: str | None = None
    receipt_time_c: str | None = None
    message_id: Any = None
