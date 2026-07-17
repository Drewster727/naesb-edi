import base64
import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import send as send_api
from app.dependencies import (
    get_fingerprints,
    get_gpg,
    get_job_repository,
    get_partners,
    get_settings,
    get_tracker,
)
from app.partners import ApiKeyAuthConfig, BasicAuthConfig, PartnerConfig, PartnerRegistry
from app.settings import CryptoConfig, EnvelopeConfig, IdentityConfig, InternalApiConfig, Settings


def _unexpectedly_called():
    raise AssertionError("dependency should not be resolved before auth succeeds")


@pytest.fixture
def settings(monkeypatch):
    monkeypatch.setenv("TEST_SEND_INTERNAL_API_USERNAME", "admin")
    monkeypatch.setenv("TEST_SEND_INTERNAL_API_PASSWORD", "s3cr3t")
    monkeypatch.setenv("TEST_SEND_UNUSED_PASSPHRASE", "unused")
    return Settings(
        identity=IdentityConfig(name="MyCompany", duns="123456789"),
        crypto=CryptoConfig(
            private_key_path="unused",
            passphrase_env="TEST_SEND_UNUSED_PASSPHRASE",
            gnupg_home="/tmp/unused",
        ),
        envelope=EnvelopeConfig(server_id="gateway.example.com", default_version="1.9"),
        internal_api=InternalApiConfig(
            username_env="TEST_SEND_INTERNAL_API_USERNAME",
            password_env="TEST_SEND_INTERNAL_API_PASSWORD",
        ),
        partners_file="unused",
    )


@pytest.fixture
def partners(monkeypatch):
    monkeypatch.setenv("TEST_SEND_PARTNER_OUT_PW", "unused")
    monkeypatch.setenv("TEST_SEND_PARTNER_IN_KEY", "unused")
    partner = PartnerConfig(
        name="acme-pipeline",
        duns="987654321",
        endpoint_url="https://acme.example.com/edi/receiver-endpoint",
        pgp_public_key_path="unused",
        outbound_auth=BasicAuthConfig(username="u", password_env="TEST_SEND_PARTNER_OUT_PW"),
        inbound_auth=ApiKeyAuthConfig(key_env="TEST_SEND_PARTNER_IN_KEY"),
    )
    return PartnerRegistry([partner])


def build_client(settings, partners) -> TestClient:
    app = FastAPI()
    app.include_router(send_api.router)
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_partners] = lambda: partners
    # These must never be reached if auth is enforced correctly.
    app.dependency_overrides[get_gpg] = _unexpectedly_called
    app.dependency_overrides[get_fingerprints] = _unexpectedly_called
    app.dependency_overrides[get_tracker] = _unexpectedly_called
    app.dependency_overrides[get_job_repository] = _unexpectedly_called
    return TestClient(app)


def _basic_auth_header(username: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
    return {"authorization": f"Basic {token}"}


def test_trigger_send_requires_auth(settings, partners):
    client = build_client(settings, partners)
    response = client.post(
        "/outbound/send",
        json={
            "partner_name": "acme-pipeline",
            "input_format": "X12",
            "payload_base64": base64.b64encode(b"hello").decode("ascii"),
        },
    )
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Basic"


def test_trigger_send_rejects_wrong_credentials(settings, partners):
    client = build_client(settings, partners)
    response = client.post(
        "/outbound/send",
        json={
            "partner_name": "acme-pipeline",
            "input_format": "X12",
            "payload_base64": base64.b64encode(b"hello").decode("ascii"),
        },
        headers=_basic_auth_header("admin", "wrong"),
    )
    assert response.status_code == 401


def test_get_job_status_requires_auth(settings, partners):
    client = build_client(settings, partners)
    response = client.get(f"/outbound/jobs/{uuid.uuid4()}")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Basic"


def test_get_job_status_rejects_wrong_credentials(settings, partners):
    client = build_client(settings, partners)
    response = client.get(
        f"/outbound/jobs/{uuid.uuid4()}", headers=_basic_auth_header("admin", "wrong")
    )
    assert response.status_code == 401
