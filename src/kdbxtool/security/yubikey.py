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

Provider Architecture:
    ChallengeResponseProvider is an abstract base class that defines the
    interface for challenge-response operations. Two implementations are provided:
    - HardwareYubiKey: Uses physical YubiKey hardware via yubikey-manager
    - MockYubiKey: Software implementation for testing without hardware

    Pass a provider to Database.open(), Database.save(), etc. via the
    `challenge_response_provider` parameter.

Requirements (for HardwareYubiKey):
    - yubikey-manager package (install with: pip install kdbxtool[yubikey])
    - YubiKey 2.2+ with HMAC-SHA1 configured in slot 1 or 2
    - Linux: udev rules for YubiKey access (usually automatic)
    - Windows: May require administrator privileges
    - macOS: Works out of box

Security Notes:
    - The YubiKey's HMAC secret is never extracted or stored
    - Response is wrapped in SecureBytes for automatic zeroization
    - YubiKey loss = data loss (unless backup credentials exist)

Testing Notes:
    - Use MockYubiKey for testing without hardware
    - Common test secrets:
        - ZERO_SECRET: 20 zero bytes (0x00 * 20) - typically slot 1
        - NUMERIC_SECRET: "12345678901234567890" - typically slot 2
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from kdbxtool.exceptions import (
    YubiKeyError,
    YubiKeyNotAvailableError,
    YubiKeyNotFoundError,
    YubiKeySlotError,
    YubiKeyTimeoutError,
)

from .challenge_response import ChallengeResponseProvider
from .memory import SecureBytes

# Optional yubikey-manager support for hardware YubiKey
try:
    from ykman.device import list_all_devices  # type: ignore[import-not-found]
    from yubikit.core.otp import OtpConnection  # type: ignore[import-not-found]
    from yubikit.yubiotp import (
        SLOT,  # type: ignore[import-not-found]
        YubiOtpSession,
    )

    YUBIKEY_HARDWARE_AVAILABLE = True
except ImportError:
    YUBIKEY_HARDWARE_AVAILABLE = False

if TYPE_CHECKING:
    pass


# HMAC-SHA1 response is always 20 bytes
HMAC_SHA1_RESPONSE_SIZE = 20


def DEFAULT_TOUCH_CALLBACK() -> None:
    """Default callback to notify user when YubiKey touch is required.

    Prints a message to stderr (critical user feedback, always visible).
    """
    import sys

    print("Touch your YubiKey...", file=sys.stderr)  # noqa: T201


@dataclass(frozen=True, slots=True)
class YubiKeyConfig:
    """Configuration for YubiKey challenge-response.

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
    if not YUBIKEY_HARDWARE_AVAILABLE:
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
    on_touch_required: Callable[[], None] | None = None,
) -> SecureBytes:
    """Send challenge to YubiKey and return HMAC-SHA1 response.

    This function sends the challenge (the database's KDF salt) to the
    YubiKey and returns the HMAC-SHA1 response. The response is computed
    by the YubiKey hardware using a secret that never leaves the device.

    Note: For new code, prefer using HardwareYubiKey provider directly:
        provider = HardwareYubiKey(slot=2)
        response = provider.challenge_response(challenge)

    Args:
        challenge: Challenge bytes (32-byte KDF salt from KDBX header).
            Must be at least 1 byte.
        config: Optional YubiKey configuration. If not provided, uses
            default settings (slot 2, first device).
        on_touch_required: Optional callback invoked when the YubiKey is
            waiting for touch. This is called at most once per operation.
            Use this to prompt the user to touch their YubiKey. If not
            provided, no notification is given when touch is needed.

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
    if not YUBIKEY_HARDWARE_AVAILABLE:
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

            # Set up keepalive handler to detect when touch is required
            # The keepalive callback is invoked while waiting for the response,
            # which happens when the YubiKey slot requires touch confirmation
            touch_notified = False

            def on_keepalive(_status: int) -> None:
                nonlocal touch_notified
                if not touch_notified and on_touch_required is not None:
                    touch_notified = True
                    on_touch_required()

            # Calculate challenge response with touch detection
            response = session.calculate_hmac_sha1(slot, challenge, on_keepalive=on_keepalive)

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
    if not YUBIKEY_HARDWARE_AVAILABLE:
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


# ============================================================================
# Hardware YubiKey Provider
# ============================================================================


class HardwareYubiKey(ChallengeResponseProvider):
    """Challenge-response provider using physical YubiKey hardware.

    Uses the yubikey-manager library to communicate with a physical YubiKey
    device for HMAC-SHA1 challenge-response authentication.

    Requires:
        - yubikey-manager package: pip install kdbxtool[yubikey]
        - Physical YubiKey with HMAC-SHA1 configured in the specified slot

    Example:
        >>> from kdbxtool.security.yubikey import HardwareYubiKey
        >>> provider = HardwareYubiKey(slot=2)
        >>> db = Database.open("vault.kdbx", password="secret",
        ...                    challenge_response_provider=provider)
    """

    def __init__(
        self,
        slot: int = 2,
        serial: int | None = None,
        on_touch_required: Callable[[], None] | None = None,
    ) -> None:
        """Initialize hardware YubiKey provider.

        Args:
            slot: YubiKey slot to use (1 or 2). Slot 2 is typically used for
                challenge-response as slot 1 is often used for OTP.
            serial: Optional serial number to select a specific YubiKey when
                multiple devices are connected. If None, uses the first device.
            on_touch_required: Optional callback invoked when YubiKey touch is
                required. If None, uses the default touch callback which prints
                to stderr.

        Raises:
            YubiKeyNotAvailableError: If yubikey-manager is not installed.
            YubiKeyNotFoundError: If no YubiKey is connected (or specified serial not found).
            ValueError: If slot is not 1 or 2.
        """
        if not YUBIKEY_HARDWARE_AVAILABLE:
            raise YubiKeyNotAvailableError()
        if slot not in (1, 2):
            raise ValueError("YubiKey slot must be 1 or 2")

        # Find and store the actual device
        devices = list_all_devices()
        if not devices:
            raise YubiKeyNotFoundError()

        # Select device by serial number if specified, otherwise use first device
        device = None
        info = None
        if serial is not None:
            for dev, dev_info in devices:
                if dev_info.serial == serial:
                    device = dev
                    info = dev_info
                    break
            if device is None:
                raise YubiKeyNotFoundError(
                    f"No YubiKey with serial {serial} found. "
                    f"Available serials: {[d[1].serial for d in devices if d[1].serial]}"
                )
        else:
            device, info = devices[0]

        self._slot = slot
        self._device = device
        self._device_info = info
        self._on_touch_required = on_touch_required

    @property
    def slot(self) -> int:
        """Return the slot number used by this provider."""
        return self._slot

    @property
    def serial(self) -> int | None:
        """Return the actual device serial number, or None if not available."""
        return self._device_info.serial

    def __repr__(self) -> str:
        """Return string representation of the provider."""
        serial_str = f"serial={self.serial}" if self.serial else "serial=None"
        version = self._device_info.version
        version_str = f"{version.major}.{version.minor}.{version.patch}"
        return f"HardwareYubiKey(slot={self._slot}, {serial_str}, version={version_str})"

    def _get_slot_enum(self) -> SLOT:
        """Convert slot number to SLOT enum."""
        return SLOT.ONE if self._slot == 1 else SLOT.TWO

    def _open_session(self):
        """Open a YubiOtpSession context manager."""
        from contextlib import contextmanager

        @contextmanager
        def session_context():
            connection = self._device.open_connection(OtpConnection)
            try:
                yield YubiOtpSession(connection)
            finally:
                connection.close()

        return session_context()

    def challenge_response(
        self,
        challenge: bytes,
    ) -> SecureBytes:
        """Compute HMAC-SHA1 response using the physical YubiKey.

        Args:
            challenge: Challenge bytes (e.g., 32-byte KDF salt)

        Returns:
            20-byte HMAC-SHA1 response wrapped in SecureBytes

        Raises:
            YubiKeySlotError: If slot is not configured for HMAC-SHA1
            YubiKeyTimeoutError: If touch times out
            YubiKeyError: For other communication errors
        """
        if not challenge:
            raise ValueError("Challenge must not be empty")

        slot_enum = self._get_slot_enum()

        # Call the touch callback before attempting if one is set
        if self._on_touch_required is not None:
            self._on_touch_required()

        try:
            with self._open_session() as session:
                response = session.calculate_hmac_sha1(slot_enum, challenge)
                return SecureBytes(bytes(response))

        except Exception as e:
            error_msg = str(e).lower()

            # Check if it's a timeout error
            if isinstance(e, TimeoutError) or "timed out waiting for touch" in error_msg:
                # Got a timeout - call callback and retry once
                if self._on_touch_required is not None:
                    self._on_touch_required()
                else:
                    DEFAULT_TOUCH_CALLBACK()

                try:
                    with self._open_session() as session:
                        response = session.calculate_hmac_sha1(slot_enum, challenge)
                        return SecureBytes(bytes(response))
                except Exception as retry_e:
                    retry_msg = str(retry_e).lower()
                    if (
                        isinstance(retry_e, TimeoutError)
                        or "timed out waiting for touch" in retry_msg
                    ):
                        raise YubiKeyTimeoutError() from retry_e
                    if "not configured" in retry_msg or "not programmed" in retry_msg:
                        raise YubiKeySlotError(self._slot) from retry_e
                    raise YubiKeyError(f"YubiKey challenge-response failed: {retry_e}") from retry_e

            # Check for configuration errors
            if "not configured" in error_msg or "not programmed" in error_msg:
                raise YubiKeySlotError(self._slot) from e

            # Generic error
            raise YubiKeyError(f"YubiKey challenge-response failed: {e}") from e


# ============================================================================
# Mock YubiKey for Testing
# ============================================================================


class MockYubiKey(ChallengeResponseProvider):
    """Mock challenge-response provider for testing without hardware.

    Simulates YubiKey HMAC-SHA1 challenge-response using configurable secrets.
    Useful for unit tests and CI environments where no YubiKey is available.

    As a ChallengeResponseProvider, MockYubiKey can be passed directly to
    Database.open(), Database.save(), etc. When used as a provider, it uses
    the slot specified at construction time.

    Default secrets match common test configurations:
    - Slot 1: 20 zero bytes (0x00 * 20)
    - Slot 2: "12345678901234567890" (20 bytes)

    Example:
        >>> from kdbxtool.security.yubikey import MockYubiKey
        >>> # As a provider for Database operations
        >>> provider = MockYubiKey.with_zero_secret(slot=1)
        >>> db = Database.open("test.kdbx", password="test",
        ...                    challenge_response_provider=provider)
        >>>
        >>> # Direct challenge-response (for testing)
        >>> response = provider.challenge_response(b"test challenge")
        >>> len(response.data)
        20
    """

    # Common test secrets
    ZERO_SECRET = b"\x00" * 20
    TEST_NUMERIC_SECRET = b"12345678901234567890"

    def __init__(
        self,
        slot: int = 2,
        secret: bytes | None = None,
        serial: int = 12345678,
        simulate_touch: bool = False,
    ) -> None:
        """Initialize mock YubiKey provider.

        Args:
            slot: Slot number this provider represents (1 or 2).
            secret: 20-byte HMAC secret. If None, uses ZERO_SECRET for slot 1
                or NUMERIC_SECRET for slot 2.
            serial: Simulated serial number for identification.
            simulate_touch: Whether to call the touch callback during operations.

        Raises:
            ValueError: If slot is not 1 or 2, or secret is wrong length.
        """
        if slot not in (1, 2):
            raise ValueError("Slot must be 1 or 2")

        if secret is None:
            secret = self.ZERO_SECRET if slot == 1 else self.TEST_NUMERIC_SECRET
        elif len(secret) != 20:
            raise ValueError("HMAC secret must be exactly 20 bytes")

        self._slot = slot
        self._secret = secret
        self._serial = serial
        self._simulate_touch = simulate_touch

    @property
    def slot(self) -> int:
        """Return the slot number this provider represents."""
        return self._slot

    @property
    def serial(self) -> int:
        """Return the simulated serial number."""
        return self._serial

    @property
    def secret(self) -> bytes:
        """Return the HMAC secret (for testing inspection)."""
        return self._secret

    def __repr__(self) -> str:
        """Return string representation of the mock provider."""
        secret_desc = (
            "ZERO_SECRET"
            if self._secret == self.ZERO_SECRET
            else "NUMERIC_SECRET"
            if self._secret == self.TEST_NUMERIC_SECRET
            else "custom"
        )
        touch_str = ", touch=True" if self._simulate_touch else ""
        return (
            f"MockYubiKey(slot={self._slot}, serial={self._serial}, "
            f"secret={secret_desc}{touch_str})"
        )

    def challenge_response(
        self,
        challenge: bytes,
    ) -> SecureBytes:
        """Compute HMAC-SHA1 response using the configured secret.

        Args:
            challenge: Challenge bytes (e.g., 32-byte KDF salt)

        Returns:
            20-byte HMAC-SHA1 response wrapped in SecureBytes
        """
        import hashlib
        import hmac

        if self._simulate_touch:
            DEFAULT_TOUCH_CALLBACK()

        response = hmac.new(self._secret, challenge, hashlib.sha1).digest()
        return SecureBytes(response)

    @classmethod
    def with_zero_secret(cls, slot: int = 1, simulate_touch: bool = False) -> MockYubiKey:
        """Create a mock YubiKey with all-zeros secret on specified slot.

        Args:
            slot: Slot to configure with zero secret (default: 1)
            simulate_touch: Whether to simulate touch requirement

        Returns:
            MockYubiKey instance
        """
        return cls(slot=slot, secret=cls.ZERO_SECRET, simulate_touch=simulate_touch)

    @classmethod
    def with_numeric_secret(
        cls, secret: bytes, slot: int = 2, simulate_touch: bool = False
    ) -> MockYubiKey:
        """Create a mock YubiKey with a numeric/predictable secret on specified slot.

        Unlike with_zero_secret(), this method requires you to explicitly pass
        the secret bytes to make it clear that a specific predictable value
        is being used.

        Common test secret: MockYubiKey.TEST_NUMERIC_SECRET (b"12345678901234567890")

        Args:
            secret: 20-byte HMAC secret (e.g., MockYubiKey.TEST_NUMERIC_SECRET)
            slot: Slot to configure (default: 2)
            simulate_touch: Whether to simulate touch requirement

        Returns:
            MockYubiKey instance

        Example:
            >>> mock = MockYubiKey.with_numeric_secret(MockYubiKey.TEST_NUMERIC_SECRET, slot=2)
        """
        return cls(slot=slot, secret=secret, simulate_touch=simulate_touch)

    @classmethod
    def with_secret(cls, slot: int, secret: bytes, simulate_touch: bool = False) -> MockYubiKey:
        """Create a mock YubiKey with a custom secret.

        Args:
            slot: Slot number (1 or 2)
            secret: 20-byte HMAC secret
            simulate_touch: Whether to simulate touch requirement

        Returns:
            MockYubiKey instance
        """
        return cls(slot=slot, secret=secret, simulate_touch=simulate_touch)
