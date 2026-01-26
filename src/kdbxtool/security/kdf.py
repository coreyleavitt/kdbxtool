"""Key Derivation Functions for KDBX databases.

This module provides secure KDF implementations for:
- Argon2d: Default KDF for KDBX4 (KeePassXC compatible, better GPU resistance)
- Argon2id: Alternative Argon2 variant with timing attack resistance
- AES-KDF: Legacy KDF for KDBX3 read support (not for new databases)

Security considerations:
- Argon2 enforces minimum parameters to prevent weak configurations
- All derived keys are returned as SecureBytes for automatic zeroization
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from argon2.low_level import Type as Argon2Type
from argon2.low_level import hash_secret_raw

from kdbxtool.exceptions import KdfError, MissingCredentialsError

from .keyfile import parse_keyfile
from .memory import SecureBytes

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class KdfType(Enum):
    """Supported Key Derivation Functions in KDBX.

    The UUID values are defined in the KDBX specification.
    """

    ARGON2D = bytes.fromhex("ef636ddf8c29444b91f7a9a403e30a0c")
    ARGON2ID = bytes.fromhex("9e298b1956db4773b23dfc3ec6f0a1e6")
    AES_KDF = bytes.fromhex("c9d9f39a628a4460bf740d08c18a4fea")

    @property
    def display_name(self) -> str:
        """Human-readable KDF name."""
        names = {
            KdfType.ARGON2D: "Argon2d",
            KdfType.ARGON2ID: "Argon2id",
            KdfType.AES_KDF: "AES-KDF",
        }
        return names[self]

    @classmethod
    def from_uuid(cls, uuid_bytes: bytes) -> KdfType:
        """Look up KDF by its KDBX UUID.

        Args:
            uuid_bytes: 16-byte KDF identifier from KDBX header

        Returns:
            The corresponding KdfType enum value

        Raises:
            ValueError: If the UUID doesn't match any known KDF
        """
        for kdf in cls:
            if kdf.value == uuid_bytes:
                return kdf
        raise KdfError(f"Unknown KDF UUID: {uuid_bytes.hex()}")


# Minimum Argon2 parameters for security
# Based on OWASP recommendations (as of 2024)
ARGON2_MIN_MEMORY_KIB = 16 * 1024  # 16 MiB minimum
ARGON2_MIN_ITERATIONS = 3
ARGON2_MIN_PARALLELISM = 1


@dataclass(frozen=True, slots=True)
class Argon2Config:
    """Configuration for Argon2 key derivation.

    Attributes:
        memory_kib: Memory usage in KiB
        iterations: Number of iterations (time cost)
        parallelism: Degree of parallelism
        salt: Random salt (must be at least 16 bytes)
        variant: Argon2 variant (Argon2d or Argon2id)
    """

    memory_kib: int
    iterations: int
    parallelism: int
    salt: bytes
    variant: KdfType = KdfType.ARGON2D

    def __post_init__(self) -> None:
        """Validate configuration parameters."""
        if self.variant not in (KdfType.ARGON2D, KdfType.ARGON2ID):
            raise KdfError(f"Invalid Argon2 variant: {self.variant}")
        if len(self.salt) < 16:
            raise KdfError("Argon2 salt must be at least 16 bytes")

    def validate_security(self) -> None:
        """Check that parameters meet minimum security requirements.

        Raises:
            ValueError: If parameters are below security minimums
        """
        issues = []
        if self.memory_kib < ARGON2_MIN_MEMORY_KIB:
            issues.append(
                f"Memory {self.memory_kib} KiB is below minimum {ARGON2_MIN_MEMORY_KIB} KiB"
            )
        if self.iterations < ARGON2_MIN_ITERATIONS:
            issues.append(f"Iterations {self.iterations} is below minimum {ARGON2_MIN_ITERATIONS}")
        if self.parallelism < ARGON2_MIN_PARALLELISM:
            issues.append(
                f"Parallelism {self.parallelism} is below minimum {ARGON2_MIN_PARALLELISM}"
            )
        if issues:
            raise KdfError("Weak Argon2 parameters: " + "; ".join(issues))

    @classmethod
    def default(
        cls,
        salt: bytes | None = None,
        variant: KdfType = KdfType.ARGON2D,
    ) -> Argon2Config:
        """Create configuration with secure defaults.

        Alias for standard(). Provides balanced security and performance.

        Args:
            salt: Optional salt (32 random bytes generated if not provided)
            variant: Argon2 variant (ARGON2D or ARGON2ID). Default is ARGON2D
                which provides better GPU resistance for local password databases.

        Returns:
            Argon2Config with recommended security parameters
        """
        return cls.standard(salt=salt, variant=variant)

    @classmethod
    def standard(
        cls,
        salt: bytes | None = None,
        variant: KdfType = KdfType.ARGON2D,
    ) -> Argon2Config:
        """Create configuration with balanced security/performance.

        Suitable for most use cases. Provides good security with
        reasonable unlock times on modern hardware.

        Parameters: 64 MiB memory, 3 iterations, 4 parallelism

        Args:
            salt: Optional salt (32 random bytes generated if not provided)
            variant: Argon2 variant (ARGON2D or ARGON2ID). Default is ARGON2D
                which provides better GPU resistance for local password databases.
                Use ARGON2ID if timing attack resistance is needed.

        Returns:
            Argon2Config with standard security parameters
        """
        import os

        if salt is None:
            salt = os.urandom(32)
        return cls(
            memory_kib=64 * 1024,  # 64 MiB
            iterations=3,
            parallelism=4,
            salt=salt,
            variant=variant,
        )

    @classmethod
    def high_security(
        cls,
        salt: bytes | None = None,
        variant: KdfType = KdfType.ARGON2D,
    ) -> Argon2Config:
        """Create configuration for high-security applications.

        Use for sensitive data where longer unlock times are acceptable.
        Provides stronger protection against brute-force attacks.

        Parameters: 256 MiB memory, 10 iterations, 4 parallelism

        Args:
            salt: Optional salt (32 random bytes generated if not provided)
            variant: Argon2 variant (ARGON2D or ARGON2ID). Default is ARGON2D
                which provides better GPU resistance for local password databases.

        Returns:
            Argon2Config with high security parameters
        """
        import os

        if salt is None:
            salt = os.urandom(32)
        return cls(
            memory_kib=256 * 1024,  # 256 MiB
            iterations=10,
            parallelism=4,
            salt=salt,
            variant=variant,
        )

    @classmethod
    def fast(
        cls,
        salt: bytes | None = None,
        variant: KdfType = KdfType.ARGON2D,
    ) -> Argon2Config:
        """Create configuration for fast operations (testing only).

        WARNING: This provides minimal security and should only be used
        for testing or development. Not suitable for production databases.

        Parameters: 16 MiB memory, 3 iterations, 2 parallelism

        Args:
            salt: Optional salt (32 random bytes generated if not provided)
            variant: Argon2 variant (ARGON2D or ARGON2ID). Default is ARGON2D.

        Returns:
            Argon2Config with minimal parameters
        """
        import os

        if salt is None:
            salt = os.urandom(32)
        return cls(
            memory_kib=16 * 1024,  # 16 MiB (minimum secure)
            iterations=3,
            parallelism=2,
            salt=salt,
            variant=variant,
        )


@dataclass(frozen=True, slots=True)
class AesKdfConfig:
    """Configuration for AES-KDF key derivation.

    AES-KDF is supported in both KDBX3 and KDBX4. While Argon2 is generally
    recommended for new databases, AES-KDF may be preferred for compatibility
    with older KeePass clients or on systems where Argon2 is slow.

    Attributes:
        rounds: Number of AES encryption rounds (higher = slower but more secure)
        salt: 32-byte salt
    """

    rounds: int
    salt: bytes

    def __post_init__(self) -> None:
        """Validate configuration."""
        if len(self.salt) != 32:
            raise KdfError("AES-KDF salt must be exactly 32 bytes")
        if self.rounds < 1:
            raise KdfError("AES-KDF rounds must be at least 1")

    @classmethod
    def standard(cls, salt: bytes | None = None) -> AesKdfConfig:
        """Create configuration with balanced security/performance.

        Uses 600,000 rounds which provides reasonable security while
        keeping unlock times acceptable on most hardware.

        Args:
            salt: Optional salt (32 random bytes generated if not provided)

        Returns:
            AesKdfConfig with standard parameters
        """
        import os

        if salt is None:
            salt = os.urandom(32)
        return cls(rounds=600_000, salt=salt)

    @classmethod
    def high_security(cls, salt: bytes | None = None) -> AesKdfConfig:
        """Create configuration for high-security applications.

        Uses 6,000,000 rounds for stronger protection at the cost of
        longer unlock times.

        Args:
            salt: Optional salt (32 random bytes generated if not provided)

        Returns:
            AesKdfConfig with high security parameters
        """
        import os

        if salt is None:
            salt = os.urandom(32)
        return cls(rounds=6_000_000, salt=salt)

    @classmethod
    def fast(cls, salt: bytes | None = None) -> AesKdfConfig:
        """Create configuration for fast operations (testing only).

        WARNING: Uses only 60,000 rounds which provides minimal security.
        Only use for testing or development.

        Args:
            salt: Optional salt (32 random bytes generated if not provided)

        Returns:
            AesKdfConfig with minimal parameters
        """
        import os

        if salt is None:
            salt = os.urandom(32)
        return cls(rounds=60_000, salt=salt)


def derive_key_argon2(
    password: bytes,
    config: Argon2Config,
    *,
    enforce_minimums: bool = True,
) -> SecureBytes:
    """Derive a 32-byte key using Argon2.

    Args:
        password: Password bytes (usually composite key hash)
        config: Argon2 configuration parameters
        enforce_minimums: If True, reject weak parameters

    Returns:
        32-byte derived key wrapped in SecureBytes

    Raises:
        ValueError: If parameters are invalid or below minimums
    """
    if enforce_minimums:
        config.validate_security()

    argon2_type = Argon2Type.ID if config.variant == KdfType.ARGON2ID else Argon2Type.D
    logger.debug("Starting Argon2 derivation (%s)", config.variant.display_name)

    derived = hash_secret_raw(
        secret=password,
        salt=config.salt,
        time_cost=config.iterations,
        memory_cost=config.memory_kib,
        parallelism=config.parallelism,
        hash_len=32,
        type=argon2_type,
    )
    logger.debug("Argon2 derivation complete")
    return SecureBytes(derived)


def derive_key_aes_kdf(
    password: bytes,
    config: AesKdfConfig,
) -> SecureBytes:
    """Derive a 32-byte key using legacy AES-KDF.

    This performs repeated AES-ECB encryption of the password
    using the salt as key. Only use for KDBX3 compatibility.

    Args:
        password: 32-byte password hash
        config: AES-KDF configuration

    Returns:
        32-byte derived key wrapped in SecureBytes

    Raises:
        ValueError: If password is not 32 bytes
    """
    if len(password) != 32:
        raise KdfError("AES-KDF requires 32-byte input")

    logger.debug("Starting AES-KDF with %d rounds", config.rounds)

    from Cryptodome.Cipher import AES

    cipher = AES.new(config.salt, AES.MODE_ECB)

    # Split into two 16-byte blocks and encrypt repeatedly
    block1 = bytearray(password[:16])
    block2 = bytearray(password[16:])

    for _ in range(config.rounds):
        block1 = bytearray(cipher.encrypt(bytes(block1)))
        block2 = bytearray(cipher.encrypt(bytes(block2)))

    # Combine and hash
    combined = bytearray(bytes(block1) + bytes(block2))
    derived = hashlib.sha256(combined).digest()

    # Zeroize all intermediate values
    for i in range(16):
        block1[i] = 0
        block2[i] = 0
    for i in range(32):
        combined[i] = 0

    logger.debug("AES-KDF complete")
    return SecureBytes(derived)


def derive_composite_key(
    password: str | None = None,
    keyfile_data: bytes | None = None,
    yubikey_hmac_response: bytes | None = None,
) -> SecureBytes:
    """Create composite key from password and/or keyfile.

    The composite key is SHA-256(password_hash || keyfile_key [|| challenge_result]).

    **KEK Mode (default):**
    Pass yubikey_hmac_response=None. The device challenge-response output is used
    separately to unwrap the KEK, which is then combined with the base master
    key via derive_final_key() AFTER KDF. This is the recommended mode for all
    new databases and supports multiple enrolled devices.

    **KeePassXC-Compatible Mode:**
    Pass a 20-byte YubiKey HMAC-SHA1 response to mix it directly into the
    composite key. This provides KeePassXC/KeePassDX compatibility but only
    supports a single device. NOTE: Only YubiKey HMAC-SHA1 (20 bytes) is
    supported in this mode. FIDO2, Trezor, and other providers MUST use KEK mode.

    The keyfile_key is processed according to KeePass keyfile format rules.

    Args:
        password: Optional password string
        keyfile_data: Optional keyfile contents
        yubikey_hmac_response: Optional YubiKey HMAC-SHA1 response (20 bytes)
            for KeePassXC-compatible mode ONLY. For KEK mode, pass None.
            NOTE: FIDO2 responses (32 bytes) are NOT accepted here - FIDO2
            must use KEK mode.

    Returns:
        32-byte composite key wrapped in SecureBytes

    Raises:
        MissingCredentialsError: If no credentials are provided
        ValueError: If yubikey_hmac_response is provided but not 20 bytes
    """
    if password is None and keyfile_data is None and yubikey_hmac_response is None:
        raise MissingCredentialsError()

    # KeePassXC-compatible mode: only accept 20-byte YubiKey HMAC-SHA1 responses
    # FIDO2 and other providers must use KEK mode
    if yubikey_hmac_response is not None and len(yubikey_hmac_response) != 20:
        raise ValueError(
            "KeePassXC-compatible mode only supports YubiKey HMAC-SHA1 (20 bytes). "
            f"Got {len(yubikey_hmac_response)} bytes. "
            "FIDO2 and other providers must use KEK mode."
        )

    logger.debug(
        "Deriving composite key (password=%s, keyfile=%s, compat_cr=%s)",
        password is not None,
        keyfile_data is not None,
        yubikey_hmac_response is not None,
    )

    # Use bytearrays for all intermediates so they can be zeroized
    parts: list[bytearray] = []
    composite = bytearray(32)

    try:
        if password is not None:
            pwd_hash = bytearray(hashlib.sha256(password.encode("utf-8")).digest())
            parts.append(pwd_hash)

        if keyfile_data is not None:
            key_bytes = bytearray(parse_keyfile(keyfile_data))
            parts.append(key_bytes)

        if yubikey_hmac_response is not None:
            # KeePassXC-compatible mode: mix YubiKey HMAC-SHA1 response directly
            # KeePassXC: challenge() returns SHA256 of CR key's rawKey
            challenge_result = bytearray(hashlib.sha256(yubikey_hmac_response).digest())
            parts.append(challenge_result)

        composite[:] = hashlib.sha256(b"".join(parts)).digest()
        return SecureBytes(bytes(composite))
    finally:
        # Zeroize all intermediate values
        for part in parts:
            for i in range(len(part)):
                part[i] = 0
        for i in range(len(composite)):
            composite[i] = 0
