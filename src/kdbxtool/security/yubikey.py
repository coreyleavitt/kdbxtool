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

import logging
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

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
    from ykman.device import list_all_devices
    from yubikit.core.otp import OtpConnection
    from yubikit.yubiotp import (
        SLOT,
        YubiOtpSession,
    )

    YUBIKEY_HARDWARE_AVAILABLE = True
except ImportError:
    YUBIKEY_HARDWARE_AVAILABLE = False

# Backwards compatibility alias
YUBIKEY_AVAILABLE = YUBIKEY_HARDWARE_AVAILABLE

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# HMAC-SHA1 response is always 20 bytes
HMAC_SHA1_RESPONSE_SIZE = 20


def DEFAULT_TOUCH_CALLBACK() -> None:
    """Default callback that prints touch prompt to stderr."""
    print("Touch your YubiKey...", file=sys.stderr, flush=True)


@dataclass(frozen=True, slots=True)
class YubiKeyConfig:
    """Configuration for YubiKey challenge-response.

    Note: This class is deprecated for new code. Use YubiKeyHmacSha1 instead.

    Attributes:
        slot: YubiKey slot to use (1 or 2). Slot 2 is typically used for
            challenge-response as slot 1 is often used for OTP.
        serial: Optional serial number to select a specific YubiKey when
            multiple devices are connected. If None, uses the first device.
            Use list_yubikeys() to discover available devices and serials.
    """

    slot: int = 2
    serial: int | None = None

    def __post_init__(self) -> None:
        """Validate configuration."""
        if self.slot not in (1, 2):
            raise ValueError("YubiKey slot must be 1 or 2")


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

    logger.debug("Found %d YubiKey devices", len(devices))
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
    logger.debug("Starting YubiKey challenge-response on slot %d", config.slot)

    try:
        # Connect via smartcard interface for challenge-response
        connection = device.open_connection(OtpConnection)
        try:
            session = YubiOtpSession(connection)

            # Calculate challenge response
            # Note: yubikey-manager handles the timeout internally
            response = session.calculate_hmac_sha1(slot, challenge)

            logger.debug("YubiKey challenge-response complete")
            return SecureBytes(bytes(response))

        finally:
            connection.close()

    except Exception as e:
        error_msg = str(e).lower()

        # Translate common errors to specific exceptions
        if "timeout" in error_msg or "timed out" in error_msg:
            raise YubiKeyTimeoutError() from e
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


class YubiKeyHmacSha1:
    """YubiKey HMAC-SHA1 challenge-response provider.

    This class implements the ChallengeResponseProvider protocol for YubiKey
    devices configured with HMAC-SHA1 challenge-response. It provides hardware-
    backed key derivation that is compatible with KeePassXC.

    The device and touch requirement are verified at initialization time
    (fail fast), and touch prompts are shown proactively when needed.

    Example:
        >>> provider = YubiKeyHmacSha1(slot=2)
        >>> db = Database.open("vault.kdbx", password="secret", provider=provider)

        # With specific serial and custom touch callback
        >>> provider = YubiKeyHmacSha1(
        ...     slot=2,
        ...     serial=12345678,
        ...     on_touch_required=lambda: print("Please touch..."),
        ... )

        # Disable touch prompts
        >>> provider = YubiKeyHmacSha1(slot=2, on_touch_required=None)

    Attributes:
        slot: YubiKey slot (1 or 2)
        serial: Device serial number (if specified)
        requires_touch: Whether the slot requires touch for challenge-response

    Raises:
        YubiKeyNotAvailableError: If yubikey-manager is not installed
        YubiKeyNotFoundError: If no YubiKey is connected (or specified serial not found)
        YubiKeySlotError: If the slot is not configured for HMAC-SHA1
    """

    # Sentinel value for default callback (allows distinguishing None from unset)
    _DEFAULT_CALLBACK: Callable[[], None] | None = DEFAULT_TOUCH_CALLBACK

    def __init__(
        self,
        slot: int = 2,
        serial: int | None = None,
        on_touch_required: Callable[[], None] | None = _DEFAULT_CALLBACK,
    ) -> None:
        """Initialize YubiKey provider.

        Validates device exists and queries touch requirement at init time.

        Args:
            slot: YubiKey slot to use (1 or 2). Slot 2 is typically used for
                challenge-response as slot 1 is often used for OTP.
            serial: Optional serial number to select a specific YubiKey when
                multiple devices are connected. If None, uses the first device.
            on_touch_required: Callback invoked before operations that require
                touch. Set to None to disable touch prompts. Default prints
                "Touch your YubiKey..." to stderr.

        Raises:
            ValueError: If slot is not 1 or 2
            YubiKeyNotAvailableError: If yubikey-manager is not installed
            YubiKeyNotFoundError: If no YubiKey is connected
            YubiKeySlotError: If the slot is not configured for HMAC-SHA1
        """
        if slot not in (1, 2):
            raise ValueError("YubiKey slot must be 1 or 2")

        if not YUBIKEY_HARDWARE_AVAILABLE:
            raise YubiKeyNotAvailableError()

        self._slot = slot
        self._serial = serial
        self._on_touch_required = on_touch_required

        # Validate device exists and query touch requirement at init
        self._device, self._device_info = self._find_device()
        self._requires_touch = self._check_touch_required()

    def _find_device(self) -> tuple[Any, Any]:
        """Find and return the YubiKey device.

        Returns:
            Tuple of (device, device_info)

        Raises:
            YubiKeyNotFoundError: If no matching device found
        """
        devices = list_all_devices()
        if not devices:
            raise YubiKeyNotFoundError()

        if self._serial is not None:
            for dev, dev_info in devices:
                if dev_info.serial == self._serial:
                    return dev, dev_info
            raise YubiKeyNotFoundError(
                f"No YubiKey with serial {self._serial} found. "
                f"Available serials: {[d[1].serial for d in devices if d[1].serial]}"
            )

        return devices[0]

    def _check_touch_required(self) -> bool:
        """Query if slot is configured to require touch.

        Returns:
            True if touch is required, False otherwise
        """
        try:
            connection = self._device.open_connection(OtpConnection)
            try:
                session = YubiOtpSession(connection)
                config_state = session.get_config_state()
                slot_enum = SLOT.ONE if self._slot == 1 else SLOT.TWO

                # Check if slot is configured
                if not config_state.is_configured(slot_enum):
                    raise YubiKeySlotError(self._slot)

                # Check if touch is triggered for this slot
                return bool(config_state.is_touch_triggered(slot_enum))
            finally:
                connection.close()
        except YubiKeySlotError:
            raise
        except Exception as e:
            # If we can't check, assume it might need touch
            logger.debug("Could not check touch requirement: %s", e)
            return True

    @property
    def slot(self) -> int:
        """YubiKey slot number (1 or 2)."""
        return self._slot

    @property
    def serial(self) -> int | None:
        """Device serial number, if specified."""
        return self._serial

    @property
    def requires_touch(self) -> bool:
        """Whether this YubiKey slot requires touch for challenge-response."""
        return self._requires_touch

    def challenge_response(self, challenge: bytes) -> SecureBytes:
        """Compute HMAC-SHA1 response for the given challenge.

        Args:
            challenge: Challenge bytes (typically 32-byte KDF salt)

        Returns:
            20-byte HMAC-SHA1 response wrapped in SecureBytes

        Raises:
            YubiKeyTimeoutError: If touch was required but not received
            YubiKeyError: For other YubiKey communication errors
        """
        if not challenge:
            raise ValueError("Challenge must not be empty")

        # Prompt proactively if touch is required
        if self._requires_touch and self._on_touch_required is not None:
            self._on_touch_required()

        slot_enum = SLOT.ONE if self._slot == 1 else SLOT.TWO
        logger.debug("Starting YubiKey challenge-response on slot %d", self._slot)

        try:
            connection = self._device.open_connection(OtpConnection)
            try:
                session = YubiOtpSession(connection)
                response = session.calculate_hmac_sha1(slot_enum, challenge)
                logger.debug("YubiKey challenge-response complete")
                return SecureBytes(bytes(response))
            finally:
                connection.close()

        except Exception as e:
            error_msg = str(e).lower()

            if "timeout" in error_msg or "timed out" in error_msg:
                raise YubiKeyTimeoutError() from e
            if "not configured" in error_msg or "not programmed" in error_msg:
                raise YubiKeySlotError(self._slot) from e
            if "no device" in error_msg or "not found" in error_msg:
                raise YubiKeyNotFoundError() from e

            raise YubiKeyError(f"YubiKey challenge-response failed: {e}") from e

    def __repr__(self) -> str:
        """Return string representation."""
        serial_str = f", serial={self._serial}" if self._serial else ""
        touch_str = ", touch=required" if self._requires_touch else ""
        return f"YubiKeyHmacSha1(slot={self._slot}{serial_str}{touch_str})"
