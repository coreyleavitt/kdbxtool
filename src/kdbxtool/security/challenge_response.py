"""Challenge-response authentication protocol.

This module defines the ChallengeResponseProvider protocol for hardware-backed
key derivation. Implementations include:

- YubiKeyHmacSha1: YubiKey HMAC-SHA1 (KeePassXC-compatible)
- Fido2HmacSecret: FIDO2 hmac-secret extension (broader device support)
- MockYubiKey/MockFido2: Software implementations for testing (in testing module)

Third parties can implement this protocol without importing kdbxtool.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from .memory import SecureBytes


@runtime_checkable
class ChallengeResponseProvider(Protocol):
    """Protocol for challenge-response authentication providers.

    This protocol defines the interface for hardware security keys that
    perform challenge-response authentication. The challenge is typically
    the database's KDF salt (32 bytes), and the response is incorporated
    into key derivation.

    Implementations:
        - YubiKeyHmacSha1: YubiKey HMAC-SHA1 (KeePassXC-compatible)
        - Fido2HmacSecret: FIDO2 hmac-secret extension
        - MockYubiKey: Software implementation for testing (in kdbxtool.testing)

    Third parties can implement this protocol without importing kdbxtool,
    enabling custom providers for other hardware tokens.

    Example:
        >>> from kdbxtool import Database, YubiKeyHmacSha1
        >>> provider = YubiKeyHmacSha1(slot=2)
        >>> db = Database.open("vault.kdbx", password="secret", provider=provider)

    Security Note:
        Hardware implementations store secrets in tamper-resistant HSMs.
        Software implementations (mocks) are for TESTING ONLY - they cannot
        provide the same security guarantees as hardware tokens.
    """

    def challenge_response(self, challenge: bytes) -> SecureBytes:
        """Compute response for the given challenge.

        Args:
            challenge: Challenge bytes (typically 32-byte KDF salt from KDBX header)

        Returns:
            Response bytes wrapped in SecureBytes for automatic zeroization.
            - YubiKey HMAC-SHA1: 20 bytes
            - FIDO2 hmac-secret: 32 bytes

        Raises:
            ChallengeResponseError: If the operation fails (device not found,
                timeout, slot not configured, credential not found, etc.)
        """
        ...
