import base64

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import partners as partners_api
from app.dependencies import get_partners, get_settings
from app.partners import (
    ApiKeyAuthConfig,
    BasicAuthConfig,
    EnvelopeOverrides,
    PartnerConfig,
    PartnerRegistry,
)
from app.settings import (
    CryptoConfig,
    EnvelopeConfig,
    IdentityConfig,
    InternalApiConfig,
    Settings,
)


@pytest.fixture
def settings(monkeypatch):
    monkeypatch.setenv("TEST_INTERNAL_API_USERNAME", "admin")
    monkeypatch.setenv("TEST_INTERNAL_API_PASSWORD", "s3cr3t")
    monkeypatch.setenv("TEST_UNUSED_PASSPHRASE", "unused")
    return Settings(
        identity=IdentityConfig(name="MyCompany", duns="123456789"),
        crypto=CryptoConfig(
            private_key_path="unused",
            passphrase_env="TEST_UNUSED_PASSPHRASE",
            gnupg_home="/tmp/unused",
        ),
        envelope=EnvelopeConfig(server_id="gateway.example.com", default_version="1.9"),
        internal_api=InternalApiConfig(
            username_env="TEST_INTERNAL_API_USERNAME", password_env="TEST_INTERNAL_API_PASSWORD"
        ),
        partners_file="unused",
    )


@pytest.fixture
def partners(monkeypatch):
    monkeypatch.setenv("TEST_PARTNER_A_OUT_PW", "unused")
    monkeypatch.setenv("TEST_PARTNER_A_IN_KEY", "unused")
    monkeypatch.setenv("TEST_PARTNER_B_OUT_PW", "unused")
    monkeypatch.setenv("TEST_PARTNER_B_IN_KEY", "unused")
    plain_partner = PartnerConfig(
        name="acme-pipeline",
        duns="987654321",
        endpoint_url="https://acme.example.com/edi/receiver-endpoint",
        pgp_public_key_path="unused",
        outbound_auth=BasicAuthConfig(username="u", password_env="TEST_PARTNER_A_OUT_PW"),
        inbound_auth=ApiKeyAuthConfig(key_env="TEST_PARTNER_A_IN_KEY"),
    )
    overridden_partner = PartnerConfig(
        name="beta-pipeline",
        duns="111222333",
        endpoint_url="https://beta.example.com/edi/receiver-endpoint",
        pgp_public_key_path="unused",
        outbound_auth=BasicAuthConfig(username="u", password_env="TEST_PARTNER_B_OUT_PW"),
        inbound_auth=ApiKeyAuthConfig(key_env="TEST_PARTNER_B_IN_KEY"),
        envelope_overrides=EnvelopeOverrides(use_refnum=True),
    )
    return PartnerRegistry([plain_partner, overridden_partner])


def build_client(settings, partners) -> TestClient:
    app = FastAPI()
    app.include_router(partners_api.router)
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_partners] = lambda: partners
    return TestClient(app)


def _basic_auth_header(username: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
    return {"authorization": f"Basic {token}"}


def test_list_partners_requires_auth(settings, partners):
    client = build_client(settings, partners)
    response = client.get("/api/partners")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Basic"


def test_list_partners_rejects_wrong_credentials(settings, partners):
    client = build_client(settings, partners)
    response = client.get("/api/partners", headers=_basic_auth_header("admin", "wrong"))
    assert response.status_code == 401


def test_list_partners_returns_basic_details_only(settings, partners):
    client = build_client(settings, partners)
    response = client.get("/api/partners", headers=_basic_auth_header("admin", "s3cr3t"))

    assert response.status_code == 200
    body = response.json()
    assert body == [
        {
            "name": "acme-pipeline",
            "duns": "987654321",
            "endpoint_url": "https://acme.example.com/edi/receiver-endpoint",
            "has_envelope_overrides": False,
        },
        {
            "name": "beta-pipeline",
            "duns": "111222333",
            "endpoint_url": "https://beta.example.com/edi/receiver-endpoint",
            "has_envelope_overrides": True,
        },
    ]

    raw_text = response.text
    assert "TEST_PARTNER" not in raw_text
    assert "pgp_public_key_path" not in raw_text
    assert "unused" not in raw_text
