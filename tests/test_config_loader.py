import os

import pytest
import yaml

from app.partners import load_partners
from app.settings import MissingEnvVarError, load_settings

VALID_CONFIG = {
    "identity": {"name": "MyCompany", "duns": "123456789"},
    "server": {"inbound_path": "/inbound"},
    "crypto": {
        "private_key_path": "/data/gnupg/private_key.asc",
        "passphrase_env": "TEST_GPG_PASSPHRASE",
        "gnupg_home": "/data/gnupg",
    },
    "envelope": {
        "header_mapping": {
            "version": "version",
            "from_id": "from-id",
            "to_id": "to-id",
            "input_format": "input-format",
            "transaction_set": "transaction-set",
        }
    },
    "database": {"url_env": "TEST_DATABASE_URL"},
    "partners_file": "/app/config/partners.yaml",
}

VALID_PARTNERS = {
    "partners": [
        {
            "name": "acme-pipeline",
            "duns": "987654321",
            "endpoint_url": "https://example.com/edi/receiver-endpoint",
            "pgp_public_key_path": "/data/gnupg/partners/acme.pub.asc",
            "outbound_auth": {"type": "basic", "username": "myuid", "password_env": "TEST_ACME_PASSWORD"},
            "inbound_auth": {"type": "api_key", "key_env": "TEST_ACME_INBOUND_KEY"},
        }
    ]
}


def _write_yaml(path, data):
    path.write_text(yaml.safe_dump(data))
    return path


def test_load_settings_valid_config(tmp_path):
    path = _write_yaml(tmp_path / "config.yaml", VALID_CONFIG)
    settings = load_settings(path)
    assert settings.identity.duns == "123456789"
    assert settings.server.inbound_path == "/inbound"


def test_load_settings_missing_required_field(tmp_path):
    bad = {k: v for k, v in VALID_CONFIG.items() if k != "crypto"}
    path = _write_yaml(tmp_path / "config.yaml", bad)
    with pytest.raises(Exception):
        load_settings(path)


def test_load_settings_header_mapping_missing_entry(tmp_path):
    bad = {**VALID_CONFIG, "envelope": {"header_mapping": {"version": "version"}}}
    path = _write_yaml(tmp_path / "config.yaml", bad)
    with pytest.raises(Exception):
        load_settings(path)


def test_load_settings_header_mapping_uppercase_rejected(tmp_path):
    bad_mapping = dict(VALID_CONFIG["envelope"]["header_mapping"])
    bad_mapping["from_id"] = "From-Id"
    bad = {**VALID_CONFIG, "envelope": {"header_mapping": bad_mapping}}
    path = _write_yaml(tmp_path / "config.yaml", bad)
    with pytest.raises(Exception):
        load_settings(path)


def test_resolve_env_missing_raises(tmp_path, monkeypatch):
    monkeypatch.delenv("TEST_GPG_PASSPHRASE", raising=False)
    path = _write_yaml(tmp_path / "config.yaml", VALID_CONFIG)
    settings = load_settings(path)
    with pytest.raises(MissingEnvVarError):
        _ = settings.crypto.passphrase


def test_resolve_env_present_returns_value(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_GPG_PASSPHRASE", "secret123")
    path = _write_yaml(tmp_path / "config.yaml", VALID_CONFIG)
    settings = load_settings(path)
    assert settings.crypto.passphrase == "secret123"


def test_load_partners_valid(tmp_path):
    path = _write_yaml(tmp_path / "partners.yaml", VALID_PARTNERS)
    registry = load_partners(path)
    assert len(registry) == 1
    partner = registry.get_by_name("acme-pipeline")
    assert partner is not None
    assert registry.get_by_duns("987654321") is partner
    assert registry.get_by_name("nonexistent") is None


def test_load_partners_rejects_duplicate_duns(tmp_path):
    duplicated = {
        "partners": [
            VALID_PARTNERS["partners"][0],
            {**VALID_PARTNERS["partners"][0], "name": "acme-pipeline-2"},
        ]
    }
    path = _write_yaml(tmp_path / "partners.yaml", duplicated)
    with pytest.raises(ValueError):
        load_partners(path)


def test_partner_envelope_override_merges(tmp_path):
    with_override = {
        "partners": [
            {
                **VALID_PARTNERS["partners"][0],
                "envelope_overrides": {"header_mapping": {"transaction_set": "x-transaction-set"}},
            }
        ]
    }
    path = _write_yaml(tmp_path / "partners.yaml", with_override)
    registry = load_partners(path)
    partner = registry.get_by_name("acme-pipeline")
    assert partner.envelope_overrides is not None
    from app.envelope.fields import CanonicalField

    assert partner.envelope_overrides.header_mapping.root[CanonicalField.TRANSACTION_SET] == "x-transaction-set"
