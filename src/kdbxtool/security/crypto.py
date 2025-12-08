"""Cryptographic primitives and utilities for kdbxtool.

This module provides:
- Constant-time comparison functions for authentication
- Cipher abstractions for KDBX encryption
- HMAC utilities for integrity verification

All cryptographic operations use well-audited libraries (PyCryptodome).
"""

from __future__ import annotations

import hmac
import os
from enum import Enum
from typing import TYPE_CHECKING

from Cryptodome.Cipher import AES, ChaCha20

from kdbxtool.exceptions import TwofishNotAvailableError, UnknownCipherError

# Optional Twofish support via oxifish
try:
    from oxifish import TwofishCBC

    TWOFISH_AVAILABLE = True
except ImportError:
    TwofishCBC = None  # type: ignore[misc,assignment]
    TWOFISH_AVAILABLE = False

if TYPE_CHECKING:
    pass


class Cipher(Enum):
    """Supported ciphers for KDBX encryption.

    KDBX supports three ciphers:
    - AES-256-CBC: Traditional cipher, widely supported
    - ChaCha20: Modern stream cipher, faster in software
    - Twofish-256-CBC: Legacy cipher, requires oxifish package

    Note: KDBX uses plain ChaCha20, not ChaCha20-Poly1305.
    Authentication is provided by the HMAC block stream.

    The UUID values are defined in the KDBX specification.
    """

    AES256_CBC = bytes.fromhex("31c1f2e6bf714350be5805216afc5aff")
    CHACHA20 = bytes.fromhex("d6038a2b8b6f4cb5a524339a31dbb59a")
    TWOFISH256_CBC = bytes.fromhex("ad68f29f576f4bb9a36ad47af965346c")

    @property
    def key_size(self) -> int:
        """Return the key size in bytes for this cipher."""
        return 32  # Both use 256-bit keys

    @property
    def iv_size(self) -> int:
        """Return the IV/nonce size in bytes for this cipher."""
        if self == Cipher.AES256_CBC:
            return 16  # AES block size
        if self == Cipher.TWOFISH256_CBC:
            return 16  # Twofish block size
        return 12  # ChaCha20 nonce

    @property
    def display_name(self) -> str:
        """Human-readable cipher name."""
        if self == Cipher.AES256_CBC:
            return "AES-256-CBC"
        if self == Cipher.TWOFISH256_CBC:
            return "Twofish-256-CBC"
        return "ChaCha20"

    @classmethod
    def from_uuid(cls, uuid_bytes: bytes) -> Cipher:
        """Look up cipher by its KDBX UUID.

        Args:
            uuid_bytes: 16-byte cipher identifier from KDBX header

        Returns:
            The corresponding Cipher enum value

        Raises:
            ValueError: If the UUID doesn't match any known cipher
        """
        for cipher in cls:
            if cipher.value == uuid_bytes:
                return cipher
        raise UnknownCipherError(uuid_bytes)


def constant_time_compare(a: bytes | bytearray, b: bytes | bytearray) -> bool:
    """Compare two byte sequences in constant time.

    This prevents timing attacks where an attacker could measure
    response time differences to deduce secret values.

    Args:
        a: First byte sequence
        b: Second byte sequence

    Returns:
        True if sequences are equal, False otherwise
    """
    return hmac.compare_digest(a, b)


def secure_random_bytes(n: int) -> bytes:
    """Generate cryptographically secure random bytes.

    Uses os.urandom which is suitable for cryptographic use.

    Args:
        n: Number of random bytes to generate

    Returns:
        n cryptographically random bytes
    """
    return os.urandom(n)


def compute_hmac_sha256(key: bytes, data: bytes) -> bytes:
    """Compute HMAC-SHA256 of data using the given key.

    Args:
        key: HMAC key
        data: Data to authenticate

    Returns:
        32-byte HMAC-SHA256 digest
    """
    return hmac.new(key, data, "sha256").digest()


def verify_hmac_sha256(key: bytes, data: bytes, expected_mac: bytes) -> bool:
    """Verify HMAC-SHA256 in constant time.

    Args:
        key: HMAC key
        data: Data that was authenticated
        expected_mac: Expected MAC value to verify against

    Returns:
        True if MAC is valid, False otherwise
    """
    computed = compute_hmac_sha256(key, data)
    return constant_time_compare(computed, expected_mac)


class CipherContext:
    """Context for encrypting or decrypting data with a KDBX cipher.

    This class wraps PyCryptodome cipher implementations with a
    consistent interface for KDBX operations.
    """

    def __init__(self, cipher: Cipher, key: bytes, iv: bytes) -> None:
        """Initialize cipher context.

        Args:
            cipher: Which cipher algorithm to use
            key: Encryption key (32 bytes)
            iv: Initialization vector/nonce

        Raises:
            ValueError: If key or IV size is incorrect
            TwofishNotAvailableError: If Twofish requested but oxifish not installed
        """
        if cipher == Cipher.TWOFISH256_CBC and not TWOFISH_AVAILABLE:
            raise TwofishNotAvailableError()

        if len(key) != cipher.key_size:
            raise ValueError(
                f"{cipher.display_name} requires {cipher.key_size}-byte key, got {len(key)}"
            )
        if len(iv) != cipher.iv_size:
            raise ValueError(
                f"{cipher.display_name} requires {cipher.iv_size}-byte IV, got {len(iv)}"
            )

        self._cipher = cipher
        self._key = key
        self._iv = iv

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext data.

        For AES-CBC and Twofish-CBC, data must be padded to block size.
        For ChaCha20, returns stream-encrypted ciphertext (same length as input).

        Args:
            plaintext: Data to encrypt

        Returns:
            Encrypted data (same length as input for ChaCha20)
        """
        if self._cipher == Cipher.AES256_CBC:
            aes_cipher = AES.new(self._key, AES.MODE_CBC, iv=self._iv)
            return aes_cipher.encrypt(plaintext)
        elif self._cipher == Cipher.TWOFISH256_CBC:
            twofish_cipher = TwofishCBC(self._key)
            return twofish_cipher.encrypt(plaintext, self._iv)
        else:
            chacha_cipher = ChaCha20.new(key=self._key, nonce=self._iv)
            return chacha_cipher.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext data.

        For AES-CBC and Twofish-CBC, returns decrypted data (caller must remove padding).
        For ChaCha20, returns stream-decrypted plaintext.

        Args:
            ciphertext: Data to decrypt

        Returns:
            Decrypted plaintext
        """
        if self._cipher == Cipher.AES256_CBC:
            aes_cipher = AES.new(self._key, AES.MODE_CBC, iv=self._iv)
            return aes_cipher.decrypt(ciphertext)
        elif self._cipher == Cipher.TWOFISH256_CBC:
            twofish_cipher = TwofishCBC(self._key)
            return twofish_cipher.decrypt(ciphertext, self._iv)
        else:
            chacha_cipher = ChaCha20.new(key=self._key, nonce=self._iv)
            return chacha_cipher.decrypt(ciphertext)
