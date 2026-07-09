from dataclasses import dataclass

# RFC 4880 9.2 (symmetric-key algorithms) and 9.4 (hash algorithms) numeric IDs,
# as reported by GnuPG's status-fd protocol (see gnupg doc/DETAILS).
CIPHER_ALGO_IDS: dict[str, int] = {
    "IDEA": 1,
    "3DES": 2,
    "CAST5": 3,
    "BLOWFISH": 4,
    "AES128": 7,
    "AES192": 8,
    "AES256": 9,
    "TWOFISH": 10,
}

DIGEST_ALGO_IDS: dict[str, int] = {
    "MD5": 1,
    "SHA1": 2,
    "RIPEMD160": 3,
    "SHA256": 8,
    "SHA384": 9,
    "SHA512": 10,
    "SHA224": 11,
}

# GnuPG public-key algorithm IDs that count as "RSA" for our purposes
# (RSA Encrypt-or-Sign / Encrypt-Only / Sign-Only). naesb4.md section 2
# mandates RSA as the asymmetric algorithm.
RSA_PUBKEY_ALGO_IDS = {"1", "2", "3"}


class WeakAlgorithmError(Exception):
    """Raised when a decrypted message used a cipher/digest outside the
    configured allow-list, or a key is below the configured minimum length."""


@dataclass
class AlgorithmInfo:
    cipher_algo: int | None
    hash_algo: int | None


def parse_status(stderr: str) -> AlgorithmInfo:
    """Parse GnuPG's status-fd lines (captured in python-gnupg's result.stderr)
    to determine which cipher and hash algorithm were *actually* used --
    python-gnupg doesn't expose these as named attributes.

    DECRYPTION_INFO <mdc_method> <sym_algo> <aead_algo>
    VALIDSIG <fpr> <sig_creation_date> <sig-timestamp> <expire-timestamp>
             <sig-version> <reserved> <pubkey-algo> <hash-algo> <sig-class> ...

    Field order per gnupg doc/DETAILS; has been stable for years but is not
    part of any formal API contract, so test_gpg_policy.py asserts this
    against a real roundtrip rather than trusting this parser blindly.
    """
    cipher_algo: int | None = None
    hash_algo: int | None = None

    for line in stderr.splitlines():
        tokens = line.split()
        if "DECRYPTION_INFO" in tokens:
            idx = tokens.index("DECRYPTION_INFO")
            if len(tokens) > idx + 2:
                cipher_algo = _safe_int(tokens[idx + 2])
        if "VALIDSIG" in tokens:
            idx = tokens.index("VALIDSIG")
            if len(tokens) > idx + 8:
                hash_algo = _safe_int(tokens[idx + 8])

    return AlgorithmInfo(cipher_algo=cipher_algo, hash_algo=hash_algo)


def _safe_int(value: str) -> int | None:
    try:
        return int(value)
    except ValueError:
        return None


def enforce_policy(
    info: AlgorithmInfo,
    allowed_ciphers: set[str],
    allowed_digests: set[str],
) -> None:
    """For encrypted+signed payloads (an inbound transmission): both the
    symmetric cipher and the signature digest must be in the allowed sets."""
    allowed_cipher_ids = {CIPHER_ALGO_IDS[name] for name in allowed_ciphers}

    if info.cipher_algo not in allowed_cipher_ids:
        raise WeakAlgorithmError(
            f"symmetric cipher algo {info.cipher_algo!r} not in allowed set {allowed_ciphers}"
        )
    enforce_digest_policy(info.hash_algo, allowed_digests)


def enforce_digest_policy(hash_algo: int | None, allowed_digests: set[str]) -> None:
    """For sign-only messages (the synchronous receipt): there is no symmetric
    cipher to check, only the signature digest."""
    allowed_digest_ids = {DIGEST_ALGO_IDS[name] for name in allowed_digests}
    if hash_algo not in allowed_digest_ids:
        raise WeakAlgorithmError(
            f"signature digest algo {hash_algo!r} not in allowed set {allowed_digests}"
        )


def check_key_length(pubkey_algo: str, length_bits: int, min_bits: int) -> None:
    if pubkey_algo not in RSA_PUBKEY_ALGO_IDS:
        raise WeakAlgorithmError(f"key algorithm id {pubkey_algo!r} is not RSA")
    if length_bits < min_bits:
        raise WeakAlgorithmError(f"RSA key length {length_bits} bits is below minimum {min_bits}")
