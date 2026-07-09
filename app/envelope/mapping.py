from pydantic import RootModel, field_validator

from app.envelope.fields import CanonicalField


def _check_lowercase(value: dict[CanonicalField, str]) -> dict[CanonicalField, str]:
    for field, header_name in value.items():
        if header_name != header_name.lower():
            raise ValueError(
                f"header name for {field.value!r} must be lowercase per naesb4.md section 3: "
                f"{header_name!r}"
            )
    return value


class HeaderMapping(RootModel[dict[CanonicalField, str]]):
    """Canonical field -> literal HTTP header name, complete for every field.

    This is the one piece of the protocol we don't hardcode: if a partner's
    Trading Partner Agreement uses different header names, override just the
    fields that differ via that partner's `envelope_overrides` (HeaderOverrides
    below) -- no code change required.
    """

    @field_validator("root")
    @classmethod
    def _validate(cls, value: dict[CanonicalField, str]) -> dict[CanonicalField, str]:
        missing = set(CanonicalField) - set(value)
        if missing:
            raise ValueError(f"header_mapping missing entries for: {sorted(m.value for m in missing)}")
        return _check_lowercase(value)

    def name_for(self, field: CanonicalField) -> str:
        return self.root[field]

    def field_for(self, header_name: str) -> CanonicalField | None:
        lowered = header_name.lower()
        for field, name in self.root.items():
            if name == lowered:
                return field
        return None


class HeaderOverrides(RootModel[dict[CanonicalField, str]]):
    """A partial header_mapping -- only the fields a specific partner's TPA
    deviates on. Never used standalone; always merged onto a HeaderMapping."""

    @field_validator("root")
    @classmethod
    def _validate(cls, value: dict[CanonicalField, str]) -> dict[CanonicalField, str]:
        return _check_lowercase(value)


def merge(default: HeaderMapping, override: HeaderOverrides | None) -> HeaderMapping:
    """Partner-specific header names win, field-by-field; everything else falls
    back to the global default mapping."""
    if override is None:
        return default
    merged = dict(default.root)
    merged.update(override.root)
    return HeaderMapping(merged)
