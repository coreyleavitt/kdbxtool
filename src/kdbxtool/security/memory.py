"""Secure memory handling for sensitive data.

This module provides SecureBytes, a mutable byte container that:
- Stores data in a bytearray (mutable, can be zeroized)
- Automatically zeroizes memory on destruction
- Supports context manager protocol for guaranteed cleanup
- Prevents accidental exposure through repr/str
"""

from __future__ import annotations

from typing import Self


class SecureBytes:
    """A secure container for sensitive byte data that zeroizes on destruction.

    Unlike Python's immutable `bytes`, SecureBytes uses a mutable `bytearray`
    that can be explicitly zeroed when no longer needed. This prevents sensitive
    data like passwords and cryptographic keys from lingering in memory.

    Usage:
        # Basic usage
        key = SecureBytes(derived_key_bytes)
        # ... use key.data for crypto operations ...
        key.zeroize()  # Explicit cleanup

        # Context manager (recommended)
        with SecureBytes(password.encode()) as pwd:
            hash = sha256(pwd.data)
        # Automatically zeroized here

    Note:
        While this provides defense-in-depth against memory disclosure attacks,
        Python's memory management means copies may still exist. For maximum
        security, consider using specialized libraries like PyNaCl's SecretBox.
    """

    __slots__ = ("_buffer", "_zeroized")

    def __init__(self, data: bytes | bytearray) -> None:
        """Initialize with sensitive data.

        Args:
            data: The sensitive bytes to protect. Will be copied into internal buffer.
        """
        self._buffer = bytearray(data)
        self._zeroized = False

    @property
    def data(self) -> bytes:
        """Access the underlying data as immutable bytes.

        Returns:
            The protected data as bytes.

        Raises:
            ValueError: If the buffer has already been zeroized.
        """
        if self._zeroized:
            raise ValueError("SecureBytes has been zeroized")
        return bytes(self._buffer)

    def __len__(self) -> int:
        """Return the length of the protected data."""
        return len(self._buffer)

    def __bool__(self) -> bool:
        """Return True if buffer contains data and hasn't been zeroized."""
        return not self._zeroized and len(self._buffer) > 0

    def zeroize(self) -> None:
        """Overwrite the buffer with zeros.

        This method overwrites every byte in the buffer with 0x00,
        making the original data unrecoverable from this object.
        Safe to call multiple times.
        """
        if not self._zeroized:
            for i in range(len(self._buffer)):
                self._buffer[i] = 0
            self._zeroized = True

    def __del__(self) -> None:
        """Ensure buffer is zeroized when object is garbage collected."""
        self.zeroize()

    def __enter__(self) -> Self:
        """Context manager entry."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Context manager exit - always zeroize."""
        self.zeroize()

    def __repr__(self) -> str:
        """Safe repr that doesn't expose data."""
        if self._zeroized:
            return "SecureBytes(<zeroized>)"
        return f"SecureBytes(<{len(self._buffer)} bytes>)"

    def __str__(self) -> str:
        """Safe str that doesn't expose data."""
        return self.__repr__()

    def __eq__(self, other: object) -> bool:
        """Constant-time comparison to prevent timing attacks.

        Uses hmac.compare_digest for constant-time comparison.
        """
        if not isinstance(other, SecureBytes):
            return NotImplemented
        if self._zeroized or other._zeroized:
            return False

        import hmac

        return hmac.compare_digest(self._buffer, other._buffer)

    def __hash__(self) -> int:
        """Raise TypeError - SecureBytes should not be hashable."""
        raise TypeError("SecureBytes is not hashable")

    @classmethod
    def from_str(cls, s: str, encoding: str = "utf-8") -> Self:
        """Create SecureBytes from a string.

        Args:
            s: String to encode
            encoding: Character encoding (default: utf-8)

        Returns:
            SecureBytes containing the encoded string
        """
        return cls(s.encode(encoding))
