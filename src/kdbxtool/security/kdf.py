"""Key Derivation Functions for KDBX databases.

This module provides secure KDF implementations for:
- Argon2id: Modern KDF for KDBX4 (recommended)
- Argon2d: Legacy Argon2 variant for KDBX4 compatibility
- AES-KDF: Legacy KDF for KDBX3 read support (not for new databases)

Security considerations:
- Argon2id enforces minimum parameters to prevent weak configurations
- All derived keys are returned as SecureBytes for automatic zeroization
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

import argon2
from argon2.low_level import Type as Argon2Type
from argon2.low_level import hash_secret_raw

from .crypto import constant_time_compare
from .memory import SecureBytes

if TYPE_CHECKING:
    pass


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
        raise ValueError(f"Unknown KDF UUID: {uuid_bytes.hex()}")


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
    variant: KdfType = KdfType.ARGON2ID

    def __post_init__(self) -> None:
        """Validate configuration parameters."""
        if self.variant not in (KdfType.ARGON2D, KdfType.ARGON2ID):
            raise ValueError(f"Invalid Argon2 variant: {self.variant}")
        if len(self.salt) < 16:
            raise ValueError("Argon2 salt must be at least 16 bytes")

    def validate_security(self) -> None:
        """Check that parameters meet minimum security requirements.

        Raises:
            ValueError: If parameters are below security minimums
        """
        issues = []
        if self.memory_kib < ARGON2_MIN_MEMORY_KIB:
            issues.append(
                f"Memory {self.memory_kib} KiB is below minimum "
                f"{ARGON2_MIN_MEMORY_KIB} KiB"
            )
        if self.iterations < ARGON2_MIN_ITERATIONS:
            issues.append(
                f"Iterations {self.iterations} is below minimum "
                f"{ARGON2_MIN_ITERATIONS}"
            )
        if self.parallelism < ARGON2_MIN_PARALLELISM:
            issues.append(
                f"Parallelism {self.parallelism} is below minimum "
                f"{ARGON2_MIN_PARALLELISM}"
            )
        if issues:
            raise ValueError("Weak Argon2 parameters: " + "; ".join(issues))

    @classmethod
    def default(cls, salt: bytes | None = None) -> Argon2Config:
        """Create configuration with secure defaults.

        Args:
            salt: Optional salt (32 random bytes generated if not provided)

        Returns:
            Argon2Config with recommended security parameters
        """
        import os

        if salt is None:
            salt = os.urandom(32)
        return cls(
            memory_kib=64 * 1024,  # 64 MiB
            iterations=3,
            parallelism=4,
            salt=salt,
            variant=KdfType.ARGON2ID,
        )


@dataclass(frozen=True, slots=True)
class AesKdfConfig:
    """Configuration for legacy AES-KDF (KDBX3).

    Note: AES-KDF is only supported for reading KDBX3 databases.
    New databases should use Argon2id.

    Attributes:
        rounds: Number of AES encryption rounds
        salt: 32-byte salt
    """

    rounds: int
    salt: bytes

    def __post_init__(self) -> None:
        """Validate configuration."""
        if len(self.salt) != 32:
            raise ValueError("AES-KDF salt must be exactly 32 bytes")
        if self.rounds < 1:
            raise ValueError("AES-KDF rounds must be at least 1")


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

    argon2_type = (
        Argon2Type.ID if config.variant == KdfType.ARGON2ID else Argon2Type.D
    )

    derived = hash_secret_raw(
        secret=password,
        salt=config.salt,
        time_cost=config.iterations,
        memory_cost=config.memory_kib,
        parallelism=config.parallelism,
        hash_len=32,
        type=argon2_type,
    )
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
        raise ValueError("AES-KDF requires 32-byte input")

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

    return SecureBytes(derived)


def _process_keyfile(keyfile_data: bytes) -> bytes:
    """Process keyfile data according to KeePass keyfile format.

    KeePass supports several keyfile formats:
    1. XML keyfile (v1.0 or v2.0) - key is base64/hex encoded in XML
    2. 32-byte raw binary - used directly
    3. 64-byte hex string - decoded from hex
    4. Any other size - SHA-256 hashed

    Args:
        keyfile_data: Raw keyfile contents

    Returns:
        32-byte key derived from keyfile
    """
    # Try parsing as XML keyfile
    try:
        import base64
        import defusedxml.ElementTree as ET

        tree = ET.fromstring(keyfile_data)
        version_elem = tree.find("Meta/Version")
        data_elem = tree.find("Key/Data")

        if version_elem is not None and data_elem is not None:
            version = version_elem.text or ""
            if version.startswith("1.0"):
                # Version 1.0: base64 encoded
                return base64.b64decode(data_elem.text or "")
            elif version.startswith("2.0"):
                # Version 2.0: hex encoded with hash verification
                key_hex = (data_elem.text or "").strip()
                key_bytes = bytes.fromhex(key_hex)
                # Verify hash if present (constant-time comparison)
                if "Hash" in data_elem.attrib:
                    expected_hash = bytes.fromhex(data_elem.attrib["Hash"])
                    computed_hash = hashlib.sha256(key_bytes).digest()[:4]
                    if not constant_time_compare(expected_hash, computed_hash):
                        raise ValueError("Keyfile hash verification failed")
                return key_bytes
    except (ET.ParseError, ValueError, AttributeError):
        pass  # Not an XML keyfile

    # Check for raw 32-byte key
    if len(keyfile_data) == 32:
        return keyfile_data

    # Check for 64-byte hex-encoded key
    if len(keyfile_data) == 64:
        try:
            # Verify it's valid hex
            int(keyfile_data, 16)
            return bytes.fromhex(keyfile_data.decode("ascii"))
        except (ValueError, UnicodeDecodeError):
            pass  # Not hex

    # Hash anything else
    return hashlib.sha256(keyfile_data).digest()


def derive_composite_key(
    password: str | None = None,
    keyfile_data: bytes | None = None,
) -> SecureBytes:
    """Create composite key from password and/or keyfile.

    The composite key is SHA-256(SHA-256(password) || keyfile_key).
    The keyfile_key is processed according to KeePass keyfile format rules.

    Args:
        password: Optional password string
        keyfile_data: Optional keyfile contents

    Returns:
        32-byte composite key wrapped in SecureBytes

    Raises:
        ValueError: If neither password nor keyfile is provided
    """
    if password is None and keyfile_data is None:
        raise ValueError("At least one credential required")

    parts: list[bytes] = []
    secure_parts: list[SecureBytes] = []

    try:
        if password is not None:
            # Wrap password hash in SecureBytes for proper zeroization
            pwd_hash = SecureBytes(
                hashlib.sha256(password.encode("utf-8")).digest()
            )
            secure_parts.append(pwd_hash)
            parts.append(pwd_hash.data)

        if keyfile_data is not None:
            key_bytes = _process_keyfile(keyfile_data)
            parts.append(key_bytes)

        composite = hashlib.sha256(b"".join(parts)).digest()
        return SecureBytes(composite)
    finally:
        # Zeroize intermediate values
        for sp in secure_parts:
            sp.zeroize()
