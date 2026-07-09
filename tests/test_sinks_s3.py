import asyncio
from datetime import UTC, datetime

import boto3
import pytest
from moto import mock_aws

from app.envelope.fields import EnvelopeFields, InputFormat
from app.message import InboundMessage
from app.sinks.s3_sink import S3Sink


def _message(**overrides) -> InboundMessage:
    defaults = dict(
        partner_name="acme-pipeline",
        content_digest="abc123def456" + "0" * 52,
        envelope=EnvelopeFields(
            version="4.0", from_id="1", to_id="2", input_format=InputFormat.X12, transaction_set="873"
        ),
        plaintext=b"ISA*00*...",
        received_at=datetime(2026, 7, 8, 19, 30, 0, tzinfo=UTC),
    )
    defaults.update(overrides)
    return InboundMessage(**defaults)


@pytest.fixture
def s3_bucket():
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="naesb-inbound-test")
        yield "naesb-inbound-test"


def test_s3_sink_puts_object(s3_bucket):
    sink = S3Sink(
        bucket=s3_bucket,
        prefix="inbound/",
        region="us-east-1",
        endpoint_url=None,
        access_key="test",
        secret_key="test",
    )
    result = asyncio.run(sink.deliver(_message()))

    assert result.ok
    assert result.sink_name == "s3"

    client = boto3.client("s3", region_name="us-east-1")
    listing = client.list_objects_v2(Bucket=s3_bucket, Prefix="inbound/acme-pipeline/")
    assert listing["KeyCount"] == 1
    body = client.get_object(Bucket=s3_bucket, Key=listing["Contents"][0]["Key"])["Body"].read()
    assert body == b"ISA*00*..."


def test_s3_sink_reports_failure_for_missing_bucket():
    with mock_aws():
        sink = S3Sink(
            bucket="does-not-exist",
            prefix="",
            region="us-east-1",
            endpoint_url=None,
            access_key="test",
            secret_key="test",
        )
        result = asyncio.run(sink.deliver(_message()))
        assert not result.ok
        assert result.error is not None
