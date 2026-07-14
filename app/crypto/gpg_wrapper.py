import tempfile
from dataclasses import dataclass

import gnupg

from app.crypto.policy import AlgorithmInfo, parse_status


class GpgError(Exception):
    pass


@dataclass
class DecryptResult:
    ok: bool
    plaintext: bytes
    signature_valid: bool
    signer_fingerprint: str | None
    algo_info: AlgorithmInfo
    status_text: str


@dataclass
class VerifyResult:
    valid: bool
    plaintext: bytes
    signer_fingerprint: str | None
    algo_info: AlgorithmInfo


class GpgService:
    """Thin wrapper around python-gnupg implementing the NAESB Internet ET
    payload pipeline: compress -> sign -> encrypt outbound / decrypt +
    verify inbound (WGQ Cybersecurity Related Standards v4.0, "Security" /
    "Encryption / Digital Signature"), plus a detached-signature flow used
    for the synchronous `gisb-acknowledgement-receipt`.

    Note: the specific cipher/digest/compress algorithms configured here
    (`cipher_algo`, `digest_algo`, `compress_algo`) are this gateway's own
    local security policy default, not a NAESB mandate -- the standard only
    requires OpenPGP or PGP with a minimum 2048-bit RSA key (Appendix A);
    standard 12.3.26 explicitly disclaims setting site-level crypto-algorithm
    standards beyond that.
    """

    def __init__(self, gnupg_home: str, cipher_algo: str, digest_algo: str, compress_algo: str):
        self.gpg = gnupg.GPG(gnupghome=gnupg_home)
        self.gpg.encoding = "utf-8"
        self.cipher_algo = cipher_algo
        self.digest_algo = digest_algo
        self.compress_algo = compress_algo

    def _encrypt_extra_args(self) -> list[str]:
        return [
            "--compress-algo", self.compress_algo,
            "--cipher-algo", self.cipher_algo,
            "--digest-algo", self.digest_algo,
            "--s2k-digest-algo", self.digest_algo,
            "--personal-cipher-preferences", self.cipher_algo,
            "--personal-digest-preferences", self.digest_algo,
        ]

    def encrypt_and_sign(
        self,
        data: bytes,
        recipient_fingerprint: str,
        signer_fingerprint: str,
        passphrase: str,
    ) -> bytes:
        """Compress, sign (our key), encrypt (recipient's key) in one pass.
        Returns armor-less raw binary -- this is the OpenPGP message that
        goes inside the `input-data` field's `multipart/encrypted` wrapper."""
        result = self.gpg.encrypt(
            data,
            recipients=[recipient_fingerprint],
            sign=signer_fingerprint,
            passphrase=passphrase,
            always_trust=True,
            armor=False,
            extra_args=self._encrypt_extra_args(),
        )
        if not result.ok:
            raise GpgError(f"encrypt_and_sign failed: {result.status} / {result.stderr}")
        return result.data

    def decrypt_and_verify(self, data: bytes, passphrase: str) -> DecryptResult:
        result = self.gpg.decrypt(data, passphrase=passphrase, always_trust=True)
        info = parse_status(result.stderr)
        return DecryptResult(
            ok=bool(result.ok),
            plaintext=result.data,
            signature_valid=bool(result.valid),
            signer_fingerprint=result.fingerprint,
            algo_info=info,
            status_text=result.status or "",
        )

    def detached_sign(self, data: bytes, signer_fingerprint: str, passphrase: str) -> bytes:
        """Produce a standalone, ASCII-armored detached OpenPGP signature
        (`application/pgp-signature`) over `data`, for the receipt's
        `multipart/signed` structure (RFC 1847 / RFC 3156)."""
        result = self.gpg.sign(
            data,
            keyid=signer_fingerprint,
            passphrase=passphrase,
            detach=True,
            clearsign=False,
            binary=False,
            extra_args=["--digest-algo", self.digest_algo],
        )
        if not result.data:
            raise GpgError(f"detached_sign failed: {result.status} / {getattr(result, 'stderr', '')}")
        return bytes(result.data)

    def verify_detached(self, data: bytes, signature: bytes, expected_fingerprint: str) -> VerifyResult:
        """Verify a detached signature (as produced by detached_sign(), or
        received from a partner's `application/pgp-signature` body part)
        against `data`. python-gnupg's `verify_data()` requires the
        signature on disk, hence the temp file."""
        with tempfile.NamedTemporaryFile(suffix=".sig") as sig_file:
            sig_file.write(signature)
            sig_file.flush()
            result = self.gpg.verify_data(sig_file.name, data)
        info = parse_status(result.stderr)
        valid = bool(result.valid) and result.fingerprint == expected_fingerprint
        return VerifyResult(
            valid=valid, plaintext=data, signer_fingerprint=result.fingerprint, algo_info=info
        )
