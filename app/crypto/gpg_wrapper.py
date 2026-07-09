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
    """Thin wrapper around python-gnupg implementing the compress->sign->encrypt
    outbound pipeline and decrypt+verify inbound pipeline from naesb4.md section 2,
    plus the sign-only flow used for the synchronous receipt (section 4)."""

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
        Returns armor-less raw binary, per naesb4.md section 2/3."""
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

    def sign_message(self, plaintext: str, signer_fingerprint: str, passphrase: str, armor: bool = True) -> bytes:
        """Combined one-pass-signature + literal-data OpenPGP message (`gpg --sign`),
        not a detached signature and not ASCII clearsign -- avoids clearsign's
        dash-escaping/line-ending re-serialization pitfalls while still producing
        a single self-contained "OpenPGP-signed" blob, per naesb4.md section 4."""
        result = self.gpg.sign(
            plaintext,
            keyid=signer_fingerprint,
            passphrase=passphrase,
            detach=False,
            clearsign=False,
            binary=not armor,
            extra_args=["--digest-algo", self.digest_algo],
        )
        if not result.data:
            raise GpgError(f"sign_message failed: {result.status} / {getattr(result, 'stderr', '')}")
        return bytes(result.data)

    def verify_message(self, signed_data: bytes, expected_fingerprint: str) -> VerifyResult:
        """Verify + extract plaintext from a combined signed (non-encrypted)
        OpenPGP message produced by sign_message(). GnuPG's --decrypt handles
        signed-only input just like decrypt_and_verify() handles encrypted
        input, so this reuses the same underlying call."""
        result = self.gpg.decrypt(signed_data, always_trust=True)
        info = parse_status(result.stderr)
        valid = bool(result.valid) and result.fingerprint == expected_fingerprint
        return VerifyResult(
            valid=valid,
            plaintext=result.data,
            signer_fingerprint=result.fingerprint,
            algo_info=info,
        )
