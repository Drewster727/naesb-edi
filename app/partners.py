from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, Field

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


class PartnerConfig(BaseModel):
    name: str
    duns: str
    endpoint_url: str
    pgp_public_key_path: str
    outbound_auth: AuthConfig
    inbound_auth: AuthConfig
    envelope_overrides: EnvelopeOverrides | None = None

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
