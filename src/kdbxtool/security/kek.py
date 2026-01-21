"""Key Encryption Key (KEK) wrapping for multi-device support.

This module provides KEK-based challenge-response device enrollment, enabling
multiple hardware devices (YubiKeys, FIDO2 keys, TPMs) to unlock the same
database. Each enrolled device wraps the same KEK with its unique CR output.

Security model:
- KEK is a random 32-byte key, generated once per database
- Each device's CR response is used to derive an AES-256 key via SHA-256
- The KEK is encrypted with AES-256-GCM for each enrolled device
- Password/keyfile derive the "base master key" independently
- Final master key = base_master_key XOR KEK

This allows:
- Multiple devices to unlock the same database
- Password/keyfile changes without re-enrolling devices
- Adding backup devices without all devices present
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

from Cryptodome.Cipher import AES

from .memory import SecureBytes

logger = logging.getLogger(__name__)

# CustomData keys for KEK mode storage (strings to match header.public_custom_data)
CR_VERSION_KEY = "KDBXTOOL_CR_VERSION"
CR_SALT_KEY = "KDBXTOOL_CR_SALT"
CR_DEVICE_PREFIX = "KDBXTOOL_CR_DEVICE_"

# Version constants
VERSION_LEGACY = b"\x01"  # Direct CR mixing (KeePassXC compatible, YubiKey HMAC-SHA1 only)
VERSION_KEK = b"\x02"  # KEK wrapping (multi-key support)

# Wrapped KEK size: nonce (16, PyCryptodome default) + tag (16) + ciphertext (32) = 64 bytes
WRAPPED_KEK_SIZE = 64


@dataclass
class EnrolledDevice:
    """Metadata for an enrolled challenge-response device.

    Attributes:
        device_type: Type identifier ("yubikey_hmac", "fido2", "tpm")
        label: User-friendly name (e.g., "Primary YubiKey")
        device_id: Unique identifier (slot+serial, credential_id, etc.)
        metadata: Additional device-specific data
        wrapped_kek: AES-GCM encrypted KEK (64 bytes)
    """

    device_type: str
    label: str
    device_id: str
    metadata: dict[str, Any] = field(default_factory=dict)
    wrapped_kek: bytes = b""

    def __post_init__(self) -> None:
        """Validate device entry."""
        if not self.device_type:
            raise ValueError("device_type is required")
        if not self.label:
            raise ValueError("label is required")
        if not self.device_id:
            raise ValueError("device_id is required")


def generate_kek() -> SecureBytes:
    """Generate a random 32-byte KEK.

    Returns:
        SecureBytes containing the random KEK
    """
    return SecureBytes(os.urandom(32))


def generate_salt() -> bytes:
    """Generate a random 32-byte salt for challenge-response.

    Returns:
        32-byte random salt
    """
    return os.urandom(32)


def wrap_kek(kek: bytes, cr_response: bytes) -> bytes:
    """Encrypt KEK with device's CR response using AES-256-GCM.

    The CR response is hashed with SHA-256 to derive the AES key.
    AES-GCM provides authenticated encryption to detect tampering.

    Args:
        kek: 32-byte Key Encryption Key
        cr_response: Challenge-response output (20 or 32 bytes)

    Returns:
        64-byte encrypted KEK: nonce (16) + tag (16) + ciphertext (32)

    Raises:
        ValueError: If kek is not 32 bytes
    """
    if len(kek) != 32:
        raise ValueError(f"KEK must be 32 bytes, got {len(kek)}")

    # Derive AES key from CR response
    device_key = hashlib.sha256(cr_response).digest()

    # Encrypt with AES-256-GCM
    cipher = AES.new(device_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(kek)

    logger.debug("Wrapped KEK for device (ciphertext length: %d)", len(ciphertext))
    return bytes(cipher.nonce) + tag + ciphertext


def unwrap_kek(wrapped: bytes, cr_response: bytes) -> SecureBytes:
    """Decrypt KEK using device's CR response.

    Args:
        wrapped: 64-byte encrypted KEK from wrap_kek()
        cr_response: Challenge-response output (20 or 32 bytes)

    Returns:
        32-byte KEK wrapped in SecureBytes

    Raises:
        ValueError: If wrapped is wrong size or decryption fails
    """
    if len(wrapped) != WRAPPED_KEK_SIZE:
        raise ValueError(f"Invalid wrapped KEK length: {len(wrapped)}, expected {WRAPPED_KEK_SIZE}")

    # Derive AES key from CR response
    device_key = hashlib.sha256(cr_response).digest()

    # Parse components (16-byte nonce is PyCryptodome default)
    nonce = wrapped[:16]
    tag = wrapped[16:32]
    ciphertext = wrapped[32:]

    # Decrypt and verify
    cipher = AES.new(device_key, AES.MODE_GCM, nonce=nonce)
    try:
        kek = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as e:
        raise ValueError("KEK decryption failed - wrong device or corrupted data") from e

    logger.debug("Successfully unwrapped KEK")
    return SecureBytes(kek)


def derive_final_key(base_master_key: bytes, kek: bytes) -> SecureBytes:
    """Combine base master key with KEK to get final encryption key.

    Uses XOR which is secure when both inputs are cryptographically
    random or derived from strong key derivation.

    Args:
        base_master_key: 32-byte key from password/keyfile KDF
        kek: 32-byte Key Encryption Key

    Returns:
        32-byte final master key wrapped in SecureBytes

    Raises:
        ValueError: If inputs are not 32 bytes
    """
    if len(base_master_key) != 32:
        raise ValueError(f"base_master_key must be 32 bytes, got {len(base_master_key)}")
    if len(kek) != 32:
        raise ValueError(f"kek must be 32 bytes, got {len(kek)}")

    final = bytes(a ^ b for a, b in zip(base_master_key, kek, strict=True))
    return SecureBytes(final)


def serialize_device_entry(device: EnrolledDevice) -> bytes:
    """Serialize device metadata + wrapped KEK for CustomData storage.

    Format: JSON metadata (UTF-8) + null byte + wrapped KEK

    Args:
        device: EnrolledDevice to serialize

    Returns:
        Serialized bytes for storage in CustomData
    """
    metadata = {
        "type": device.device_type,
        "label": device.label,
        "id": device.device_id,
        **device.metadata,
    }
    json_bytes = json.dumps(metadata, separators=(",", ":")).encode("utf-8")
    return json_bytes + b"\x00" + device.wrapped_kek


def deserialize_device_entry(data: bytes) -> EnrolledDevice:
    """Deserialize device entry from CustomData.

    Args:
        data: Serialized device entry from serialize_device_entry()

    Returns:
        EnrolledDevice with metadata and wrapped KEK

    Raises:
        ValueError: If data is malformed
    """
    try:
        null_idx = data.index(b"\x00")
    except ValueError:
        raise ValueError("Invalid device entry: missing null separator") from None

    json_bytes = data[:null_idx]
    wrapped_kek = data[null_idx + 1 :]

    if len(wrapped_kek) != WRAPPED_KEK_SIZE:
        raise ValueError(
            f"Invalid wrapped_kek size: {len(wrapped_kek)}, expected {WRAPPED_KEK_SIZE}"
        )

    try:
        metadata = json.loads(json_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError(f"Invalid device entry: bad JSON - {e}") from e

    return EnrolledDevice(
        device_type=metadata.pop("type"),
        label=metadata.pop("label"),
        device_id=metadata.pop("id"),
        metadata=metadata,
        wrapped_kek=wrapped_kek,
    )


def get_device_key_name(index: int) -> str:
    """Get CustomData key name for a device by index.

    Args:
        index: Device index (0, 1, 2, ...)

    Returns:
        Key name like "KDBXTOOL_CR_DEVICE_0"
    """
    return CR_DEVICE_PREFIX + str(index)


def parse_device_key_name(key: str) -> int | None:
    """Parse device index from CustomData key name.

    Args:
        key: CustomData key like "KDBXTOOL_CR_DEVICE_0"

    Returns:
        Device index, or None if not a device key
    """
    if not key.startswith(CR_DEVICE_PREFIX):
        return None
    try:
        return int(key[len(CR_DEVICE_PREFIX) :])
    except ValueError:
        return None
