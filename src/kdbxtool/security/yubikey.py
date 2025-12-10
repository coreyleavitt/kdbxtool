"""YubiKey HMAC-SHA1 challenge-response support.

This module provides hardware-backed key derivation using YubiKey devices
configured with HMAC-SHA1 challenge-response in slot 1 or 2.

The implementation follows the KeePassXC approach:
1. Database's KDF salt (32 bytes) is used as the challenge
2. YubiKey computes HMAC-SHA1(challenge, hardware_secret)
3. 20-byte response is SHA-256 hashed and incorporated into composite key

This provides hardware-backed security: the database cannot be decrypted
without physical access to the configured YubiKey, even if the password
is known.

Requirements:
    - yubikey-manager package (install with: pip install kdbxtool[yubikey])
    - YubiKey 2.2+ with HMAC-SHA1 configured in slot 1 or 2
    - Linux: udev rules for YubiKey access (usually automatic)
    - Windows: May require administrator privileges
    - macOS: Works out of box

Security Notes:
    - The YubiKey's HMAC secret is never extracted or stored
    - Response is wrapped in SecureBytes for automatic zeroization
    - YubiKey loss = data loss (unless backup credentials exist)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from kdbxtool.exceptions import (
    YubiKeyError,
    YubiKeyNotAvailableError,
    YubiKeyNotFoundError,
    YubiKeySlotError,
    YubiKeyTimeoutError,
)

from .memory import SecureBytes

# Optional yubikey-manager support
try:
    from ykman.device import list_all_devices  # type: ignore[import-not-found]
    from yubikit.core.otp import OtpConnection  # type: ignore[import-not-found]
    from yubikit.yubiotp import (  # type: ignore[import-not-found]
        SLOT,
        YubiOtpSession,
    )

    YUBIKEY_AVAILABLE = True
except ImportError:
    YUBIKEY_AVAILABLE = False

if TYPE_CHECKING:
    pass


# HMAC-SHA1 response is always 20 bytes
HMAC_SHA1_RESPONSE_SIZE = 20


@dataclass(frozen=True, slots=True)
class YubiKeyConfig:
    """Configuration for YubiKey challenge-response.

    Attributes:
        slot: YubiKey slot to use (1 or 2). Slot 2 is typically used for
            challenge-response as slot 1 is often used for OTP.
        serial: Optional serial number to select a specific YubiKey when
            multiple devices are connected. If None, uses the first device.
            Use list_yubikeys() to discover available devices and serials.
        timeout_seconds: Timeout for challenge-response operation in seconds.
            If touch is required, this is the time to wait for the button press.
    """

    slot: int = 2
    serial: int | None = None
    timeout_seconds: float = 15.0

    def __post_init__(self) -> None:
        """Validate configuration."""
        if self.slot not in (1, 2):
            raise ValueError("YubiKey slot must be 1 or 2")
        if self.timeout_seconds <= 0:
            raise ValueError("Timeout must be positive")


def list_yubikeys() -> list[dict[str, str | int]]:
    """List connected YubiKey devices.

    Returns:
        List of dictionaries containing device info:
        - serial: Device serial number (if available)
        - name: Device name/model

    Raises:
        YubiKeyNotAvailableError: If yubikey-manager is not installed.
    """
    if not YUBIKEY_AVAILABLE:
        raise YubiKeyNotAvailableError()

    devices = []
    for _device, info in list_all_devices():
        # Build a descriptive name from version and form factor
        version_str = f"{info.version.major}.{info.version.minor}.{info.version.patch}"
        form_factor = str(info.form_factor) if info.form_factor else "Unknown"
        name = f"YubiKey {version_str} {form_factor}"

        device_info: dict[str, str | int] = {"name": name}
        if info.serial:
            device_info["serial"] = info.serial
        devices.append(device_info)

    return devices


def compute_challenge_response(
    challenge: bytes,
    config: YubiKeyConfig | None = None,
) -> SecureBytes:
    """Send challenge to YubiKey and return HMAC-SHA1 response.

    This function sends the challenge (the database's KDF salt) to the
    YubiKey and returns the HMAC-SHA1 response. The response is computed
    by the YubiKey hardware using a secret that never leaves the device.

    Args:
        challenge: Challenge bytes (32-byte KDF salt from KDBX header).
            Must be at least 1 byte.
        config: Optional YubiKey configuration. If not provided, uses
            slot 2 with 15 second timeout.

    Returns:
        20-byte HMAC-SHA1 response wrapped in SecureBytes for automatic
        zeroization when no longer needed.

    Raises:
        YubiKeyNotAvailableError: If yubikey-manager is not installed.
        YubiKeyNotFoundError: If no YubiKey is connected.
        YubiKeySlotError: If the specified slot is not configured for
            HMAC-SHA1 challenge-response.
        YubiKeyTimeoutError: If the operation times out (e.g., touch
            was required but not received).
        YubiKeyError: For other YubiKey communication errors.
    """
    if not YUBIKEY_AVAILABLE:
        raise YubiKeyNotAvailableError()

    if not challenge:
        raise ValueError("Challenge must not be empty")

    if config is None:
        config = YubiKeyConfig()

    # Find connected YubiKey
    devices = list_all_devices()
    if not devices:
        raise YubiKeyNotFoundError()

    # Select device by serial number if specified, otherwise use first device
    device = None
    info = None
    if config.serial is not None:
        for dev, dev_info in devices:
            if dev_info.serial == config.serial:
                device = dev
                info = dev_info
                break
        if device is None:
            raise YubiKeyNotFoundError(
                f"No YubiKey with serial {config.serial} found. "
                f"Available serials: {[d[1].serial for d in devices if d[1].serial]}"
            )
    else:
        device, info = devices[0]

    # Convert slot number to SLOT enum
    slot = SLOT.ONE if config.slot == 1 else SLOT.TWO

    try:
        # Connect via smartcard interface for challenge-response
        connection = device.open_connection(OtpConnection)
        try:
            session = YubiOtpSession(connection)

            # Calculate challenge response
            # Note: yubikey-manager handles the timeout internally
            response = session.calculate_hmac_sha1(slot, challenge)

            return SecureBytes(bytes(response))

        finally:
            connection.close()

    except Exception as e:
        error_msg = str(e).lower()

        # Translate common errors to specific exceptions
        if "timeout" in error_msg or "timed out" in error_msg:
            raise YubiKeyTimeoutError(config.timeout_seconds) from e
        if "not configured" in error_msg or "not programmed" in error_msg:
            raise YubiKeySlotError(config.slot) from e
        if "no device" in error_msg or "not found" in error_msg:
            raise YubiKeyNotFoundError() from e

        # Generic YubiKey error for anything else
        raise YubiKeyError(f"YubiKey challenge-response failed: {e}") from e


def check_slot_configured(slot: int = 2, serial: int | None = None) -> bool:
    """Check if a YubiKey slot is configured for HMAC-SHA1.

    This is a convenience function to verify that a slot is properly
    configured before attempting to use it.

    Args:
        slot: YubiKey slot to check (1 or 2).
        serial: Optional serial number to select a specific YubiKey when
            multiple devices are connected.

    Returns:
        True if the slot is configured for HMAC-SHA1, False otherwise.

    Raises:
        YubiKeyNotAvailableError: If yubikey-manager is not installed.
        YubiKeyNotFoundError: If no YubiKey is connected (or specified serial not found).
    """
    if not YUBIKEY_AVAILABLE:
        raise YubiKeyNotAvailableError()

    devices = list_all_devices()
    if not devices:
        raise YubiKeyNotFoundError()

    # Select device by serial or use first
    device = None
    if serial is not None:
        for dev, dev_info in devices:
            if dev_info.serial == serial:
                device = dev
                break
        if device is None:
            raise YubiKeyNotFoundError(f"No YubiKey with serial {serial} found")
    else:
        device, _info = devices[0]

    try:
        connection = device.open_connection(OtpConnection)
        try:
            session = YubiOtpSession(connection)
            config = session.get_config_state()

            # Check if the slot is configured (not empty)
            slot_enum = SLOT.ONE if slot == 1 else SLOT.TWO
            return bool(config.is_configured(slot_enum))

        finally:
            connection.close()

    except Exception:
        return False
