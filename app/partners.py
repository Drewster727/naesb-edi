from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, Field, field_validator

from app.duns import normalize_duns
from app.settings import resolve_env


class BasicAuthConfig(BaseModel):
    type: Literal["basic"] = "basic"
    username: str
    password_env: str

    @property
    def password(self) -> str:
        return resolve_env(self.password_env)


class ApiKeyAuthConfig(BaseModel):
    type: Literal["api_key"] = "api_key"
    key_env: str

    @property
    def key(self) -> str:
        return resolve_env(self.key_env)


AuthConfig = Annotated[BasicAuthConfig | ApiKeyAuthConfig, Field(discriminator="type")]


class EnvelopeOverrides(BaseModel):
    """Per-partner deviations from the global envelope defaults -- real,
    spec-anticipated variability (protocol version, mutually-agreed
    transaction sets, whether this partner uses refnum tracking), not a
    header-name remapping (the envelope field names themselves are fixed
    protocol literals, not TPA-negotiable)."""

    version: str | None = None
    agreed_transaction_sets: list[str] | None = None
    use_refnum: bool = False


class CryptoOverrides(BaseModel):
    """Per-partner deviations from the global crypto.allowed_ciphers/
    allowed_digests accept-list (app/settings.py::CryptoConfig). Only set
    these for a partner whose real-world payloads/receipts genuinely need an
    algorithm outside the global default (e.g. a partner still on 3DES) --
    this widens acceptance for that one partner rather than weakening the
    floor for everyone."""

    allowed_ciphers: list[str] | None = None
    allowed_digests: list[str] | None = None
    # Accepts this partner's on-file PGP key below crypto.min_rsa_key_bits
    # (NAESB Appendix A's real minimum). Only for a documented, accepted
    # compliance gap with a specific partner's legacy key (e.g. issued before
    # the 2048-bit floor) -- it does not touch the global floor enforced for
    # every other key in the keyring, and should be paired with a plan to get
    # that partner to rotate to a compliant key.
    min_rsa_key_bits: int | None = None

    allowed_ciphers: list[str] | None = None
    allowed_digests: list[str] | None = None


class PartnerConfig(BaseModel):
    name: str
    duns: str
    endpoint_url: str
    pgp_public_key_path: str
    outbound_auth: AuthConfig
    inbound_auth: AuthConfig
    envelope_overrides: EnvelopeOverrides | None = None
    crypto_overrides: CryptoOverrides | None = None
    # Mirrors OpenAS2's reject_unsigned_messages="false": some real trading
    # partners' systems don't actually PGP-sign their outbound messages
    # despite a TPA nominally calling for it. Set false only for a partner
    # with a documented, accepted gap -- transport-level auth (inbound_auth
    # above) still authenticates the sender; this only stops enforcing the
    # PGP-level signature/digest check on the payload itself.
    require_signature: bool = True

    @field_validator("duns")
    @classmethod
    def _normalize_duns(cls, value: str) -> str:
        return normalize_duns(value)

    @property
    def use_refnum(self) -> bool:
        return bool(self.envelope_overrides and self.envelope_overrides.use_refnum)


class PartnersFile(BaseModel):
    partners: list[PartnerConfig]


class PartnerRegistry:
    def __init__(self, partners: list[PartnerConfig]):
        self._by_name = {p.name: p for p in partners}
        self._by_duns = {p.duns: p for p in partners}

    def get_by_name(self, name: str) -> PartnerConfig | None:
        return self._by_name.get(name)

    def get_by_duns(self, duns: str) -> PartnerConfig | None:
        return self._by_duns.get(duns)

    def __iter__(self):
        return iter(self._by_name.values())

    def __len__(self) -> int:
        return len(self._by_name)


def load_partners(path: str | Path) -> PartnerRegistry:
    raw = yaml.safe_load(Path(path).read_text())
    parsed = PartnersFile.model_validate(raw)
    duns_seen: dict[str, str] = {}
    for partner in parsed.partners:
        if partner.duns in duns_seen:
            raise ValueError(
                f"duplicate DUNS {partner.duns!r} used by both "
                f"{duns_seen[partner.duns]!r} and {partner.name!r}"
            )
        duns_seen[partner.duns] = partner.name
    return PartnerRegistry(parsed.partners)
