"""Abstract challenge-response authentication interface.

This module provides the abstract base class for challenge-response
authentication providers. Implementations include:
- HardwareYubiKey: Physical YubiKey hardware via yubikey-manager
- MockYubiKey: Software implementation for testing

The ChallengeResponseProvider ABC allows different hardware tokens
to be used interchangeably for database authentication.

Example:
    >>> from kdbxtool.security.yubikey import HardwareYubiKey
    >>> provider = HardwareYubiKey(slot=2)
    >>> db = Database.open("vault.kdbx", password="secret",
    ...                    challenge_response_provider=provider)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .memory import SecureBytes


class ChallengeResponseProvider(ABC):
    """Abstract base class for HMAC-SHA1 challenge-response providers.

    This interface allows different implementations of challenge-response
    authentication to be used interchangeably:
    - HardwareYubiKey: Uses physical YubiKey hardware
    - MockYubiKey: Software implementation for testing

    Implementations must provide challenge_response() which computes an
    HMAC-SHA1 response for a given challenge.

    Example:
        >>> # Using hardware YubiKey
        >>> from kdbxtool.security.yubikey import HardwareYubiKey
        >>> provider = HardwareYubiKey(slot=2)
        >>> db = Database.open("vault.kdbx", password="secret",
        ...                    challenge_response_provider=provider)
        >>>
        >>> # Using mock for testing
        >>> from kdbxtool.security.yubikey import MockYubiKey
        >>> provider = MockYubiKey.with_zero_secret(slot=1)
        >>> db = Database.open_bytes(data, password="test",
        ...                          challenge_response_provider=provider)
    """

    @abstractmethod
    def challenge_response(
        self,
        challenge: bytes,
    ) -> SecureBytes:
        """Compute HMAC-SHA1 response for the given challenge.

        Args:
            challenge: Challenge bytes (e.g., 32-byte KDF salt from database)

        Returns:
            20-byte HMAC-SHA1 response wrapped in SecureBytes

        Raises:
            ChallengeResponseError: If the operation fails. Implementations
                may raise subclasses with device-specific details.
        """
        ...
