import uuid

import app.poller as poller_module
from app.outbound.filewatch import ERROR_DIRNAME, PROCESSED_DIRNAME
from app.partners import (
    ApiKeyAuthConfig,
    BasicAuthConfig,
    EnvelopeOverrides,
    PartnerConfig,
    PartnerRegistry,
)
from app.settings import PollerConfig


class FakeRefnumRepository:
    def __init__(self, value: str = "1"):
        self.value = value
        self.calls: list[str] = []

    async def next_refnum(self, partner_name: str) -> str:
        self.calls.append(partner_name)
        return self.value


class _FakeSettings:
    def __init__(self, base_dir, quiet_period_seconds: int = 60):
        self.poller = PollerConfig(
            base_dir=str(base_dir), quiet_period_seconds=quiet_period_seconds
        )


def _partner(**overrides) -> PartnerConfig:
    defaults = dict(
        name="acme-pipeline",
        duns="987654321",
        endpoint_url="https://partner.example.com/edi/receiver-endpoint",
        pgp_public_key_path="unused",
        outbound_auth=BasicAuthConfig(username="u", password_env="TEST_UNUSED"),
        inbound_auth=ApiKeyAuthConfig(key_env="TEST_UNUSED"),
    )
    defaults.update(overrides)
    return PartnerConfig(**defaults)


async def test_process_file_success_moves_to_processed(tmp_path, monkeypatch):
    partner = _partner()
    duns_dir = tmp_path / partner.duns
    duns_dir.mkdir()
    src = duns_dir / "message.edi"
    src.write_bytes(b"segment data")

    async def fake_enqueue(payload, **kwargs):
        return uuid.uuid4()

    monkeypatch.setattr(poller_module, "enqueue_outbound", fake_enqueue)
    refnums = FakeRefnumRepository()
    attempts = poller_module._AttemptTracker(max_attempts=3)

    await poller_module._process_file(
        src, duns_dir, partner, None, None, {}, None, None, refnums, attempts
    )

    assert not src.exists()
    assert (duns_dir / PROCESSED_DIRNAME / "message.edi").read_bytes() == b"segment data"
    assert refnums.calls == []  # use_refnum defaults to False


async def test_process_file_use_refnum_partner_calls_refnum_repository(tmp_path, monkeypatch):
    partner = _partner(envelope_overrides=EnvelopeOverrides(use_refnum=True))
    duns_dir = tmp_path / partner.duns
    duns_dir.mkdir()
    src = duns_dir / "message.edi"
    src.write_bytes(b"segment data")

    async def fake_enqueue(payload, **kwargs):
        assert kwargs["refnum"] == "1"
        return uuid.uuid4()

    monkeypatch.setattr(poller_module, "enqueue_outbound", fake_enqueue)
    refnums = FakeRefnumRepository()
    attempts = poller_module._AttemptTracker(max_attempts=3)

    await poller_module._process_file(
        src, duns_dir, partner, None, None, {}, None, None, refnums, attempts
    )

    assert refnums.calls == ["acme-pipeline"]


async def test_process_file_failure_retries_then_errors(tmp_path, monkeypatch):
    partner = _partner()
    duns_dir = tmp_path / partner.duns
    duns_dir.mkdir()
    src = duns_dir / "message.edi"
    src.write_bytes(b"segment data")

    async def fake_enqueue(payload, **kwargs):
        raise RuntimeError("gpg key not found")

    monkeypatch.setattr(poller_module, "enqueue_outbound", fake_enqueue)
    refnums = FakeRefnumRepository()
    attempts = poller_module._AttemptTracker(max_attempts=3)

    for _ in range(2):
        await poller_module._process_file(
            src, duns_dir, partner, None, None, {}, None, None, refnums, attempts
        )
        assert src.exists()
        assert not (duns_dir / ERROR_DIRNAME).exists()

    await poller_module._process_file(
        src, duns_dir, partner, None, None, {}, None, None, refnums, attempts
    )

    assert not src.exists()
    assert (duns_dir / ERROR_DIRNAME / "message.edi").read_bytes() == b"segment data"
    assert attempts.exhausted(src) is False  # cleared once moved to error/


async def test_poll_once_skips_unknown_duns_and_warns_once(tmp_path):
    partners = PartnerRegistry([])
    (tmp_path / "000000000").mkdir()
    (tmp_path / "000000000" / "message.edi").write_bytes(b"segment data")

    settings = _FakeSettings(tmp_path)
    unknown_duns_warned: set[str] = set()

    for _ in range(2):
        await poller_module._poll_once(
            settings,
            partners,
            None,
            {},
            None,
            None,
            FakeRefnumRepository(),
            poller_module._AttemptTracker(3),
            unknown_duns_warned,
        )

    assert (tmp_path / "000000000" / "message.edi").exists()
    assert unknown_duns_warned == {"000000000"}


async def test_poll_once_respects_quiet_period(tmp_path, monkeypatch):
    partner = _partner()
    partners = PartnerRegistry([partner])
    duns_dir = tmp_path / partner.duns
    duns_dir.mkdir()
    (duns_dir / "message.edi").write_bytes(b"segment data")

    called = False

    async def fake_enqueue(payload, **kwargs):
        nonlocal called
        called = True
        return uuid.uuid4()

    monkeypatch.setattr(poller_module, "enqueue_outbound", fake_enqueue)
    settings = _FakeSettings(tmp_path)

    await poller_module._poll_once(
        settings,
        partners,
        None,
        {},
        None,
        None,
        FakeRefnumRepository(),
        poller_module._AttemptTracker(3),
        set(),
    )

    assert called is False
    assert (duns_dir / "message.edi").exists()
