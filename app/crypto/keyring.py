from pathlib import Path
from typing import Any

import gnupg

from app.crypto.policy import WeakAlgorithmError, check_key_length
from app.partners import PartnerRegistry


class KeyringError(Exception):
    pass


def bootstrap_keyring(
    gpg: gnupg.GPG,
    our_private_key_path: str,
    partners: PartnerRegistry,
    min_bits: int,
    recommended_bits: int,
    logger: Any = None,
) -> dict[str, str]:
    """Import our private key and every partner's public key into the managed
    keyring, then reject startup if any key is non-RSA or below min_bits.
    Returns {"_self": our_fingerprint, "<partner-name>": partner_fingerprint}."""
    fingerprints: dict[str, str] = {}

    our_key_data = Path(our_private_key_path).read_text()
    import_result = gpg.import_keys(our_key_data)
    if not import_result.fingerprints:
        raise KeyringError(f"failed to import our private key from {our_private_key_path}")
    fingerprints["_self"] = import_result.fingerprints[0]

    for partner in partners:
        key_data = Path(partner.pgp_public_key_path).read_text()
        result = gpg.import_keys(key_data)
        if not result.fingerprints:
            raise KeyringError(
                f"failed to import public key for partner {partner.name!r} "
                f"from {partner.pgp_public_key_path}"
            )
        fingerprints[partner.name] = result.fingerprints[0]

    _validate_key_lengths(gpg, min_bits, recommended_bits, logger)
    return fingerprints


def _validate_key_lengths(gpg: gnupg.GPG, min_bits: int, recommended_bits: int, logger: Any) -> None:
    all_keys = gpg.list_keys(secret=True) + gpg.list_keys(secret=False)
    for key in all_keys:
        fingerprint = key.get("fingerprint")
        algo = key.get("algo", "")
        length = int(key.get("length") or 0)
        try:
            check_key_length(algo, length, min_bits)
        except WeakAlgorithmError as exc:
            raise KeyringError(f"key {fingerprint} rejected: {exc}") from exc
        if logger is not None and length < recommended_bits:
            logger.warning(
                "key_below_recommended_length",
                fingerprint=fingerprint,
                length=length,
                recommended=recommended_bits,
            )
