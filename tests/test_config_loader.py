
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
        "server_id": "gateway.example.com",
        "default_version": "1.9",
    },
    "database": {"url_env": "TEST_DATABASE_URL"},
    "internal_api": {
        "username_env": "TEST_INTERNAL_API_USERNAME",
        "password_env": "TEST_INTERNAL_API_PASSWORD",
    },
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


def test_load_settings_envelope_requires_default_version(tmp_path):
    bad = {**VALID_CONFIG, "envelope": {"server_id": "gateway.example.com"}}  # missing default_version
    path = _write_yaml(tmp_path / "config.yaml", bad)
    with pytest.raises(Exception):
        load_settings(path)


def test_load_settings_envelope_requires_server_id(tmp_path):
    bad = {**VALID_CONFIG, "envelope": {"default_version": "1.9"}}  # missing server_id
    path = _write_yaml(tmp_path / "config.yaml", bad)
    with pytest.raises(Exception):
        load_settings(path)


def test_load_settings_rejects_unknown_allowed_cipher(tmp_path):
    bad = {
        **VALID_CONFIG,
        "crypto": {**VALID_CONFIG["crypto"], "allowed_ciphers": ["AES256", "AES-NOT-REAL"]},
    }
    path = _write_yaml(tmp_path / "config.yaml", bad)
    with pytest.raises(Exception):
        load_settings(path)


def test_load_settings_rejects_unknown_allowed_digest(tmp_path):
    bad = {
        **VALID_CONFIG,
        "crypto": {**VALID_CONFIG["crypto"], "allowed_digests": ["SHA256", "SHA-NOT-REAL"]},
    }
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


def test_database_url_unchanged_when_no_separate_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_DATABASE_URL", "postgresql://embeddeduser:embeddedpass@dbhost:5432/naesb")
    path = _write_yaml(tmp_path / "config.yaml", VALID_CONFIG)
    settings = load_settings(path)
    assert settings.database.url == "postgresql://embeddeduser:embeddedpass@dbhost:5432/naesb"


def test_database_url_injects_separate_username_and_password(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_DATABASE_URL", "postgresql://dbhost:5432/naesb")
    monkeypatch.setenv("TEST_DB_USERNAME", "naesb")
    monkeypatch.setenv("TEST_DB_PASSWORD", "s3cr3t")
    config = {
        **VALID_CONFIG,
        "database": {
            "url_env": "TEST_DATABASE_URL",
            "username_env": "TEST_DB_USERNAME",
            "password_env": "TEST_DB_PASSWORD",
        },
    }
    path = _write_yaml(tmp_path / "config.yaml", config)
    settings = load_settings(path)
    assert settings.database.url == "postgresql://naesb:s3cr3t@dbhost:5432/naesb"


def test_database_url_separate_credentials_override_embedded_ones(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_DATABASE_URL", "postgresql://olduser:oldpass@dbhost:5432/naesb")
    monkeypatch.setenv("TEST_DB_USERNAME", "newuser")
    monkeypatch.setenv("TEST_DB_PASSWORD", "newpass")
    config = {
        **VALID_CONFIG,
        "database": {
            "url_env": "TEST_DATABASE_URL",
            "username_env": "TEST_DB_USERNAME",
            "password_env": "TEST_DB_PASSWORD",
        },
    }
    path = _write_yaml(tmp_path / "config.yaml", config)
    settings = load_settings(path)
    assert settings.database.url == "postgresql://newuser:newpass@dbhost:5432/naesb"


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
                "envelope_overrides": {"version": "1.6", "use_refnum": True},
            }
        ]
    }
    path = _write_yaml(tmp_path / "partners.yaml", with_override)
    registry = load_partners(path)
    partner = registry.get_by_name("acme-pipeline")
    assert partner.envelope_overrides is not None
    assert partner.envelope_overrides.version == "1.6"
    assert partner.use_refnum is True


def test_partner_use_refnum_defaults_false(tmp_path):
    path = _write_yaml(tmp_path / "partners.yaml", VALID_PARTNERS)
    registry = load_partners(path)
    partner = registry.get_by_name("acme-pipeline")
    assert partner.use_refnum is False


def test_partner_crypto_override_rejects_unknown_cipher(tmp_path):
    with_bad_override = {
        "partners": [
            {
                **VALID_PARTNERS["partners"][0],
                "crypto_overrides": {"allowed_ciphers": ["NOT-A-REAL-CIPHER"]},
            }
        ]
    }
    path = _write_yaml(tmp_path / "partners.yaml", with_bad_override)
    with pytest.raises(Exception):
        load_partners(path)


def test_get_by_duns_normalizes_leading_zeros(tmp_path):
    padded = {
        "partners": [{**VALID_PARTNERS["partners"][0], "duns": "023456789"}],
    }
    path = _write_yaml(tmp_path / "partners.yaml", padded)
    registry = load_partners(path)
    partner = registry.get_by_name("acme-pipeline")
    assert registry.get_by_duns("23456789") is partner  # non-padded lookup still resolves
