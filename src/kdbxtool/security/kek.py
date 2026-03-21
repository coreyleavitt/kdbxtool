"""Key Encryption Key (KEK) wrapping for multi-device support.

.. warning:: **Experimental** -- KEK mode is not yet considered stable. The
   on-disk format and API may change in future releases.  Databases created
   in KEK mode are **not** compatible with KeePassXC, KeePassDX, or other
   KeePass applications.

This module provides KEK-based challenge-response device enrollment, enabling
multiple hardware devices (YubiKeys, FIDO2 keys, TPMs) to unlock the same
database. Each enrolled device wraps the same KEK with its unique CR output.

Security model:
- KEK is a random 32-byte key, generated once per database
- Each device's CR response is processed through HKDF-SHA256 with domain
  separation to derive an AES-256 key (prevents key confusion attacks)
- The KEK is encrypted with AES-256-GCM for each enrolled device
- Password/keyfile derive the "base master key" independently
- Final master key = HKDF-SHA256(salt=base_master_key, ikm=kek, info="kdbxtool-final-key-v1")

This allows:
- Multiple devices to unlock the same database
- Password/keyfile changes without re-enrolling devices
- Adding backup devices without all devices present

Known limitation - Device metadata visibility:
    Device type and identifiers (e.g., FIDO2 credential_id, YubiKey slot) are
    stored in the unencrypted header. This is required for protocol negotiation
    - we must know HOW to challenge a device before we can decrypt anything.
    An attacker with file access can see what types of devices are enrolled,
    but cannot decrypt the database without possessing an enrolled device.
    Device labels could potentially be moved to encrypted storage in a future
    version (see GitHub issue for details).
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, cast

from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.Protocol.KDF import HKDF

from .memory import SecureBytes

logger = logging.getLogger(__name__)

# Domain separation info for HKDF key derivation
# This ensures keys derived for KEK wrapping cannot be confused with keys
# derived for other purposes, even if the same CR response is used elsewhere
HKDF_INFO_KEK_WRAP = b"kdbxtool-kek-wrap-v1"

# Domain separation info for final key derivation (base_master_key + KEK)
HKDF_INFO_FINAL_KEY = b"kdbxtool-final-key-v1"


def _hkdf_sha256(ikm: bytes, info: bytes, length: int = 32, salt: bytes = b"") -> bytes:
    """Derive a key using HKDF-SHA256 (RFC 5869).

    This provides domain separation to ensure keys derived for different
    purposes are cryptographically independent, even from the same input.

    Uses PyCryptodome's HKDF implementation which properly supports
    multi-block expansion per RFC 5869.

    Args:
        ikm: Input keying material (e.g., CR response)
        info: Context/application-specific info for domain separation
        length: Desired output length in bytes (max 255 * 32 = 8160 for SHA-256)
        salt: Optional salt (defaults to empty, which uses zero-filled salt)

    Returns:
        Derived key of specified length
    """
    # PyCryptodome's HKDF with num_keys=1 (default) returns bytes, but the
    # stub types it as bytes | tuple[bytes, ...]. Cast to narrow the type.
    return cast(
        bytes,
        HKDF(
            master=ikm,
            key_len=length,
            salt=salt or b"\x00" * 32,  # RFC 5869: zero-filled salt of hash length
            hashmod=SHA256,
            context=info,
        ),
    )


# CustomData keys for KEK mode storage (strings to match header.public_custom_data)
CR_VERSION_KEY = "KDBXTOOL_CR_VERSION"
CR_SALT_KEY = "KDBXTOOL_CR_SALT"
CR_DEVICE_PREFIX = "KDBXTOOL_CR_DEVICE_"

# Version constants
VERSION_COMPAT = b"\x01"  # Direct CR mixing (KeePassXC-compatible, YubiKey HMAC-SHA1 only)
VERSION_KEK = b"\x02"  # KEK wrapping (multi-key support)

# Wrapped KEK size: nonce (16, PyCryptodome default) + tag (16) + ciphertext (32) = 64 bytes
WRAPPED_KEK_SIZE = 64

# Maximum label length for enrolled devices
MAX_LABEL_LENGTH = 256

# Minimum CR response length for security (128 bits)
# YubiKey HMAC-SHA1 = 20 bytes, FIDO2 hmac-secret = 32 bytes
# Anything shorter than 16 bytes provides insufficient entropy
MIN_CR_RESPONSE_LENGTH = 16

# Reserved keys in device metadata JSON (used for required fields)
_RESERVED_DEVICE_KEYS = frozenset({"type", "label", "id"})


@dataclass(frozen=True)
class KekState:
    """Immutable KEK mode state. Enforces invariants structurally.

    When present, the database is in KEK mode. ``None`` means inactive.
    This replaces separate ``_kek``, ``_cr_salt``, and ``_kek_mode`` fields.

    Attributes:
        kek: Unwrapped Key Encryption Key (32 bytes)
        cr_salt: Challenge-response salt used by enrolled devices
    """

    kek: SecureBytes
    cr_salt: bytes

    def zeroize(self) -> None:
        """Zeroize the KEK from memory."""
        self.kek.zeroize()


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
        # Defense-in-depth: reject reserved keys in metadata
        collision = _RESERVED_DEVICE_KEYS & self.metadata.keys()
        if collision:
            raise ValueError(f"Device metadata contains reserved keys: {collision}")


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

    The CR response is processed through HKDF-SHA256 with domain separation
    to derive the AES key. This ensures the derived key is unique to KEK
    wrapping and cannot be confused with keys derived for other purposes.
    AES-GCM provides authenticated encryption to detect tampering.

    Args:
        kek: 32-byte Key Encryption Key
        cr_response: Challenge-response output (minimum 16 bytes, typically 20 or 32)

    Returns:
        64-byte encrypted KEK: nonce (16) + tag (16) + ciphertext (32)

    Raises:
        ValueError: If kek is not 32 bytes or cr_response is too short
    """
    if len(kek) != 32:
        raise ValueError(f"KEK must be 32 bytes, got {len(kek)}")

    if len(cr_response) < MIN_CR_RESPONSE_LENGTH:
        raise ValueError(
            f"CR response too short: {len(cr_response)} bytes, "
            f"minimum {MIN_CR_RESPONSE_LENGTH} bytes required for security"
        )

    # Derive AES key from CR response using HKDF with domain separation
    # This prevents key reuse if the same CR response is used elsewhere
    device_key = bytearray(_hkdf_sha256(cr_response, HKDF_INFO_KEK_WRAP))

    try:
        # Encrypt with AES-256-GCM
        cipher = AES.new(bytes(device_key), AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(kek)

        logger.debug("Wrapped KEK for device (ciphertext length: %d)", len(ciphertext))
        return bytes(cipher.nonce) + tag + ciphertext
    finally:
        # Zeroize device key from memory
        for i in range(len(device_key)):
            device_key[i] = 0


def unwrap_kek(wrapped: bytes, cr_response: bytes) -> SecureBytes:
    """Decrypt KEK using device's CR response.

    The CR response is processed through HKDF-SHA256 with the same domain
    separation used in wrap_kek() to derive the AES decryption key.

    Args:
        wrapped: 64-byte encrypted KEK from wrap_kek()
        cr_response: Challenge-response output (minimum 16 bytes, typically 20 or 32)

    Returns:
        32-byte KEK wrapped in SecureBytes

    Raises:
        ValueError: If wrapped is wrong size, cr_response too short, or decryption fails
    """
    if len(wrapped) != WRAPPED_KEK_SIZE:
        raise ValueError(f"Invalid wrapped KEK length: {len(wrapped)}, expected {WRAPPED_KEK_SIZE}")

    if len(cr_response) < MIN_CR_RESPONSE_LENGTH:
        raise ValueError(
            f"CR response too short: {len(cr_response)} bytes, "
            f"minimum {MIN_CR_RESPONSE_LENGTH} bytes required for security"
        )

    # Derive AES key from CR response using HKDF with domain separation
    device_key = bytearray(_hkdf_sha256(cr_response, HKDF_INFO_KEK_WRAP))

    try:
        # Parse components (16-byte nonce is PyCryptodome default)
        nonce = wrapped[:16]
        tag = wrapped[16:32]
        ciphertext = wrapped[32:]

        # Decrypt and verify
        cipher = AES.new(bytes(device_key), AES.MODE_GCM, nonce=nonce)
        try:
            kek = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError as e:
            raise ValueError("KEK decryption failed - wrong device or corrupted data") from e

        logger.debug("Successfully unwrapped KEK")
        return SecureBytes(kek)
    finally:
        # Zeroize device key from memory
        for i in range(len(device_key)):
            device_key[i] = 0


def derive_final_key(base_master_key: bytes, kek: bytes) -> SecureBytes:
    """Combine base master key with KEK to get final encryption key.

    Uses HKDF-SHA256 (RFC 5869) for proper key combination:
    - Extract: HKDF-Extract(salt=base_master_key, ikm=kek) produces a PRK
    - Expand: HKDF-Expand(prk, info="kdbxtool-final-key-v1", length=32)

    This is cryptographically stronger than XOR because HKDF provides:
    - Domain separation via the info parameter
    - Proper key mixing even if one input has structure
    - Forward-compatible with longer key material

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

    final = _hkdf_sha256(ikm=kek, info=HKDF_INFO_FINAL_KEY, salt=base_master_key)
    return SecureBytes(final)


def serialize_device_entry(device: EnrolledDevice) -> bytes:
    """Serialize device metadata + wrapped KEK for CustomData storage.

    Format: JSON metadata (UTF-8) + null byte + wrapped KEK

    Args:
        device: EnrolledDevice to serialize

    Returns:
        Serialized bytes for storage in CustomData

    Raises:
        ValueError: If device metadata contains reserved keys
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

    try:
        device_type = metadata.pop("type")
        label = metadata.pop("label")
        device_id = metadata.pop("id")
    except KeyError as e:
        raise ValueError(f"Invalid device entry: missing required field {e}") from e

    if (
        not isinstance(device_type, str)
        or not isinstance(label, str)
        or not isinstance(device_id, str)
    ):
        raise ValueError("Invalid device entry: 'type', 'label', and 'id' must be strings")

    if len(label) > MAX_LABEL_LENGTH:
        raise ValueError(
            f"Invalid device entry: label too long ({len(label)} > {MAX_LABEL_LENGTH})"
        )

    return EnrolledDevice(
        device_type=device_type,
        label=label,
        device_id=device_id,
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


def detect_device_type(provider: object) -> str:
    """Detect device type from a challenge-response provider.

    Checks for an explicit ``device_type`` attribute first, then falls back
    to a class-name heuristic for backward compatibility with third-party
    providers that don't declare the attribute.

    Args:
        provider: Any object implementing ChallengeResponseProvider

    Returns:
        Device type string (e.g., "yubikey_hmac", "fido2")
    """
    explicit = getattr(provider, "device_type", None)
    if isinstance(explicit, str) and explicit:
        return explicit
    name = type(provider).__name__.lower()
    if "yubikey" in name and "fido" not in name:
        return "yubikey_hmac"
    if "fido" in name:
        return "fido2"
    return name


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
