import shutil
import subprocess
import tempfile

import gnupg
import pytest

from app.crypto.gpg_wrapper import GpgService


@pytest.fixture(scope="module")
def gnupg_home():
    # Deliberately NOT pytest's tmp_path: it nests under a long path
    # (.../pytest-of-<user>/pytest-N/<test-name>/...) that overflows the
    # ~100-byte limit on AF_UNIX socket paths, which breaks gpg-agent with
    # "File name too long". A short directory directly under /tmp avoids that.
    #
    # Note: don't set default-cache-ttl/max-cache-ttl to 0 here to avoid
    # agent passphrase caching across tests -- with a 0 TTL, gpg-agent can't
    # complete the self-signature step during --batch key generation at all
    # ("Inappropriate ioctl for device", since it tries to re-prompt via
    # pinentry mid-operation). Use the fresh_agent_cache fixture instead.
    home = tempfile.mkdtemp(prefix="naesb-gnupg-", dir="/tmp")
    yield home
    shutil.rmtree(home, ignore_errors=True)


@pytest.fixture(scope="module")
def raw_gpg(gnupg_home):
    gpg = gnupg.GPG(gnupghome=gnupg_home)
    gpg.encoding = "utf-8"
    return gpg


@pytest.fixture(scope="module")
def keypair(raw_gpg):
    """Generates an ephemeral RSA-2048 keypair. Module-scoped: RSA keygen is
    expensive enough that regenerating per-test would make the suite slow for
    no correctness benefit -- these tests don't need distinct keys per test."""

    def _generate(name: str, passphrase: str):
        key_input = raw_gpg.gen_key_input(
            key_type="RSA",
            key_length=2048,
            name_real=name,
            name_email=f"{name}@example.com",
            passphrase=passphrase,
        )
        key = raw_gpg.gen_key(key_input)
        assert key.fingerprint, f"key generation failed: {key.status} / {key.stderr}"
        return key.fingerprint

    return _generate


@pytest.fixture(scope="module")
def us_key(keypair):
    return keypair("us", "us-passphrase")


@pytest.fixture(scope="module")
def partner_key(keypair):
    return keypair("partner", "partner-passphrase")


@pytest.fixture(scope="module")
def gpg_service(gnupg_home):
    return GpgService(gnupg_home=gnupg_home, cipher_algo="AES256", digest_algo="SHA256", compress_algo="ZIP")


@pytest.fixture
def fresh_agent_cache(gnupg_home):
    """Clears gpg-agent's passphrase cache. Needed because keys are
    module-scoped: without this, a test verifying wrong-passphrase behavior
    can spuriously pass if an earlier test in the same module already
    unlocked the same key and the agent cached it."""
    subprocess.run(["gpgconf", "--homedir", gnupg_home, "--reload", "gpg-agent"], check=True)
