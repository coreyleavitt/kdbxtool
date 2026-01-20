"""Test utilities for kdbxtool.

WARNING: The mock providers in this module are for TESTING ONLY.
They are NOT secure for production use.

Software-based "soft keys" cannot provide the security guarantees of
hardware tokens:

| Property              | Hardware Key        | Soft Key (Mock)     |
|-----------------------|---------------------|---------------------|
| Secret extraction     | Impossible (HSM)    | Trivial (read file) |
| Malware resistance    | High (physical)     | None (memory access)|
| Copyability           | Cannot clone        | Can be duplicated   |
| Physical theft needed | Yes                 | No                  |

A soft key is NOT meaningfully more secure than a keyfile - if an attacker
can read the secret, they compute the same HMAC. These mocks are useful for:
- Unit testing without hardware
- CI/CD pipelines
- Development in containers without USB passthrough
- Testing multi-key enrollment workflows

DO NOT use these mocks to "secure" production databases.
"""

from __future__ import annotations

import hashlib
import hmac

from kdbxtool.security.memory import SecureBytes


class MockProvider:
    """Base mock for any challenge-response provider.

    Computes HMAC-SHA1 of the challenge using the configured secret.
    This mimics YubiKey behavior but runs entirely in software.

    WARNING: This is for TESTING ONLY. See module docstring for details.

    Example:
        >>> provider = MockProvider(secret=b"my-test-secret")
        >>> response = provider.challenge_response(b"challenge")
        >>> len(response.data)
        20
    """

    def __init__(self, secret: bytes) -> None:
        """Initialize with a secret.

        Args:
            secret: The HMAC secret (typically 20 bytes for HMAC-SHA1)
        """
        if not secret:
            raise ValueError("Secret must not be empty")
        self._secret = secret

    def challenge_response(self, challenge: bytes) -> SecureBytes:
        """Compute HMAC-SHA1 response for the given challenge.

        Args:
            challenge: Challenge bytes

        Returns:
            20-byte HMAC-SHA1 response wrapped in SecureBytes
        """
        if not challenge:
            raise ValueError("Challenge must not be empty")

        response = hmac.new(self._secret, challenge, hashlib.sha1).digest()
        return SecureBytes(response)

    def __repr__(self) -> str:
        """Return string representation (hides secret)."""
        return f"MockProvider(<{len(self._secret)} byte secret>)"


class MockYubiKey(MockProvider):
    """Mock YubiKey for testing HMAC-SHA1 challenge-response.

    This class mimics a YubiKey's HMAC-SHA1 challenge-response behavior
    using software. It implements the ChallengeResponseProvider protocol.

    WARNING: This is for TESTING ONLY. See module docstring for details.

    Class attributes provide standard test secrets:
        ZERO_SECRET: 20 zero bytes (easy to compute expected values)
        TEST_SECRET: "12345678901234567890" (human-readable test secret)

    Example:
        >>> # Use zero secret for predictable test values
        >>> provider = MockYubiKey.with_zero_secret()
        >>> response = provider.challenge_response(b"x" * 32)

        >>> # Use custom secret
        >>> provider = MockYubiKey.with_secret(b"my-secret-key-20b")

        >>> # Use with Database
        >>> from kdbxtool import Database
        >>> db = Database.open("test.kdbx", password="pass", provider=provider)
    """

    # Standard test secrets (20 bytes = HMAC-SHA1 key size)
    ZERO_SECRET = b"\x00" * 20
    TEST_SECRET = b"12345678901234567890"

    @classmethod
    def with_zero_secret(cls) -> MockYubiKey:
        """Create a MockYubiKey with all-zero secret.

        Useful for tests where you want predictable, easy-to-compute
        expected values.
        """
        return cls(cls.ZERO_SECRET)

    @classmethod
    def with_secret(cls, secret: bytes) -> MockYubiKey:
        """Create a MockYubiKey with a custom secret.

        Args:
            secret: The HMAC secret (typically 20 bytes)
        """
        return cls(secret)

    @classmethod
    def with_test_secret(cls) -> MockYubiKey:
        """Create a MockYubiKey with the standard test secret."""
        return cls(cls.TEST_SECRET)

    def __repr__(self) -> str:
        """Return string representation."""
        if self._secret == self.ZERO_SECRET:
            return "MockYubiKey(ZERO_SECRET)"
        elif self._secret == self.TEST_SECRET:
            return "MockYubiKey(TEST_SECRET)"
        return f"MockYubiKey(<{len(self._secret)} byte secret>)"


class MockFido2(MockProvider):
    """Mock FIDO2 for testing hmac-secret extension.

    This class mimics a FIDO2 device's hmac-secret behavior using software.
    Unlike real FIDO2 which uses 32-byte salt and returns 32 bytes, this
    mock uses HMAC-SHA256 to produce 32-byte output.

    WARNING: This is for TESTING ONLY. See module docstring for details.

    Example:
        >>> provider = MockFido2.with_zero_secret()
        >>> response = provider.challenge_response(b"x" * 32)
        >>> len(response.data)
        32
    """

    # Standard test secrets (32 bytes for FIDO2)
    ZERO_SECRET = b"\x00" * 32
    TEST_SECRET = b"12345678901234567890123456789012"

    def challenge_response(self, challenge: bytes) -> SecureBytes:
        """Compute HMAC-SHA256 response for the given challenge.

        Args:
            challenge: Challenge bytes (should be 32 bytes for FIDO2 compat)

        Returns:
            32-byte HMAC-SHA256 response wrapped in SecureBytes
        """
        if not challenge:
            raise ValueError("Challenge must not be empty")

        # FIDO2 hmac-secret uses SHA-256
        response = hmac.new(self._secret, challenge, hashlib.sha256).digest()
        return SecureBytes(response)

    @classmethod
    def with_zero_secret(cls) -> MockFido2:
        """Create a MockFido2 with all-zero secret."""
        return cls(cls.ZERO_SECRET)

    @classmethod
    def with_secret(cls, secret: bytes) -> MockFido2:
        """Create a MockFido2 with a custom secret.

        Args:
            secret: The HMAC secret (typically 32 bytes)
        """
        return cls(secret)

    @classmethod
    def with_test_secret(cls) -> MockFido2:
        """Create a MockFido2 with the standard test secret."""
        return cls(cls.TEST_SECRET)

    def __repr__(self) -> str:
        """Return string representation."""
        if self._secret == self.ZERO_SECRET:
            return "MockFido2(ZERO_SECRET)"
        elif self._secret == self.TEST_SECRET:
            return "MockFido2(TEST_SECRET)"
        return f"MockFido2(<{len(self._secret)} byte secret>)"


__all__ = [
    "MockProvider",
    "MockYubiKey",
    "MockFido2",
]
