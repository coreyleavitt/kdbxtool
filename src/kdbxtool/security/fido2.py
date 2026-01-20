"""FIDO2 hmac-secret extension support.

This module provides hardware-backed key derivation using FIDO2 devices
with the hmac-secret extension. This works with a broader range of
security keys than YubiKey HMAC-SHA1.

The FIDO2 hmac-secret extension:
1. Requires a credential to be created on the device first
2. The credential_id must be stored (in KDBX header CustomData)
3. On each challenge, the device returns HMAC(device_secret, challenge)

Unlike YubiKey HMAC-SHA1:
- FIDO2 works with many more devices (any FIDO2 key with hmac-secret)
- FIDO2 may require PIN
- FIDO2 requires storing credential_id (not just slot number)
- YubiKey HMAC-SHA1 is KeePassXC-compatible

Device-specific subclasses:
- YubiKeyFido2: For YubiKey devices (host-side PIN entry, touch prompt)
- Future: TrezorFido2, SoloKeyFido2, etc.

Requirements:
    - python-fido2 package (install with: pip install kdbxtool[fido2])
    - FIDO2 device with hmac-secret extension support
    - User verification (PIN/biometric) may be required

Security Notes:
    - The device secret is never extracted or stored
    - Response is wrapped in SecureBytes for automatic zeroization
    - Device loss = data loss (unless backup credentials exist)
"""

from __future__ import annotations

import logging
import sys
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from kdbxtool.exceptions import (
    Fido2CredentialNotFoundError,
    Fido2DeviceNotFoundError,
    Fido2Error,
    Fido2NotAvailableError,
    Fido2PinRequiredError,
)

from .memory import SecureBytes

# Optional python-fido2 support
try:
    from fido2.client import Fido2Client, UserInteraction  # type: ignore[import-not-found]
    from fido2.hid import CtapHidDevice  # type: ignore[import-not-found]
    from fido2.webauthn import (  # type: ignore[import-not-found]
        PublicKeyCredentialCreationOptions,
        PublicKeyCredentialDescriptor,
        PublicKeyCredentialRequestOptions,
        PublicKeyCredentialRpEntity,
        PublicKeyCredentialType,
        PublicKeyCredentialUserEntity,
    )

    FIDO2_AVAILABLE = True
except ImportError:
    FIDO2_AVAILABLE = False
    # Define a placeholder for type checking
    UserInteraction = object  # type: ignore[misc,assignment]

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Default relying party ID for kdbxtool credentials
DEFAULT_RP_ID = "kdbxtool"


def list_fido2_devices() -> list[dict[str, str | int]]:
    """List connected FIDO2 devices with hmac-secret support.

    Returns:
        List of dictionaries containing device info:
        - product_name: Device product name
        - vendor_id: USB vendor ID
        - product_id: USB product ID

    Raises:
        Fido2NotAvailableError: If python-fido2 is not installed.
    """
    if not FIDO2_AVAILABLE:
        raise Fido2NotAvailableError()

    devices = []
    for dev in CtapHidDevice.list_devices():
        device_info: dict[str, str | int] = {
            "product_name": dev.product_name or "Unknown FIDO2 Device",
            "vendor_id": dev.descriptor.vid,
            "product_id": dev.descriptor.pid,
        }
        devices.append(device_info)

    logger.debug("Found %d FIDO2 devices", len(devices))
    return devices


def create_fido2_credential(
    rp_id: str = DEFAULT_RP_ID,
    user_name: str = "kdbxtool-user",
    pin: str | None = None,
    on_touch: Callable[[str], None] | None = None,
) -> bytes:
    """Create a new FIDO2 credential with hmac-secret support.

    This registers a new credential on the FIDO2 device. The returned
    credential_id must be stored (in the KDBX header CustomData) to use
    the credential later.

    This is a one-time setup operation. After creating the credential,
    construct a device-specific provider (e.g., YubiKeyFido2) with the
    credential_id.

    Args:
        rp_id: Relying party ID (default: "kdbxtool")
        user_name: User name for the credential
        pin: Device PIN if required (for host-side PIN devices)
        on_touch: Callback for messages like "Touch your device..."

    Returns:
        The credential_id bytes to store

    Raises:
        Fido2NotAvailableError: If python-fido2 is not installed
        Fido2DeviceNotFoundError: If no FIDO2 device is connected
        Fido2PinRequiredError: If device requires PIN but none provided
        Fido2Error: For other FIDO2 errors

    Example:
        >>> credential_id = create_fido2_credential(pin="1234")
        >>> # Store credential_id in database header...
        >>> provider = YubiKeyFido2(credential_id, pin_callback=lambda: "1234")
    """
    if not FIDO2_AVAILABLE:
        raise Fido2NotAvailableError()

    devices = list(CtapHidDevice.list_devices())
    if not devices:
        raise Fido2DeviceNotFoundError()

    device = devices[0]

    # Simple interaction handler for credential creation
    class CreationInteraction(UserInteraction):  # type: ignore[misc]
        def prompt_up(self) -> None:
            if on_touch is not None:
                on_touch("Touch your security key to create credential...")

        def request_pin(self, permissions: Any, rd_id: str | None = None) -> str | None:
            if pin is None:
                raise Fido2PinRequiredError()
            return pin

        def request_uv(self, permissions: Any, rd_id: str | None = None) -> bool:
            return True

    try:
        client = Fido2Client(
            device,
            f"https://{rp_id}",
            user_interaction=CreationInteraction(),
        )

        # Check for hmac-secret support
        if not client.info.extensions or "hmac-secret" not in client.info.extensions:
            raise Fido2Error(
                "FIDO2 device does not support hmac-secret extension. "
                "Use a compatible security key."
            )

        # Create credential with hmac-secret extension
        rp = PublicKeyCredentialRpEntity(id=rp_id, name="kdbxtool")
        user = PublicKeyCredentialUserEntity(
            id=user_name.encode(),
            name=user_name,
            display_name=user_name,
        )

        if on_touch is not None:
            on_touch("Touch your security key...")

        result = client.make_credential(
            PublicKeyCredentialCreationOptions(
                rp=rp,
                user=user,
                challenge=b"kdbxtool-credential-creation",
                pub_key_cred_params=[
                    {"type": "public-key", "alg": -7},  # ES256
                    {"type": "public-key", "alg": -257},  # RS256
                ],
                extensions={"hmacCreateSecret": True},
            )
        )

        credential_id = result.attestation_object.auth_data.credential_data.credential_id
        logger.info("Created FIDO2 credential: %s", credential_id.hex()[:16] + "...")

        return bytes(credential_id)

    except Fido2PinRequiredError:
        raise
    except Exception as e:
        error_msg = str(e).lower()
        if "pin" in error_msg:
            raise Fido2PinRequiredError() from e
        raise Fido2Error(f"FIDO2 credential creation failed: {e}") from e


class Fido2HmacSecret(ABC):
    """Abstract base class for FIDO2 hmac-secret providers.

    This ABC provides the common FIDO2 hmac-secret implementation. Subclasses
    must implement _get_user_interaction() to provide device-specific
    interaction handling.

    Subclasses:
        - YubiKeyFido2: For YubiKey devices (host-side PIN, touch callback)
        - Future: TrezorFido2, SoloKeyFido2, etc.

    All subclasses implement the ChallengeResponseProvider protocol.

    Attributes:
        credential_id: The FIDO2 credential ID
        rp_id: Relying party ID
    """

    def __init__(
        self,
        credential_id: bytes,
        rp_id: str = DEFAULT_RP_ID,
    ) -> None:
        """Initialize FIDO2 hmac-secret provider.

        Args:
            credential_id: The credential ID from create_fido2_credential()
            rp_id: Relying party ID (must match credential creation)

        Raises:
            Fido2NotAvailableError: If python-fido2 is not installed
            Fido2DeviceNotFoundError: If no FIDO2 device is connected
        """
        if not FIDO2_AVAILABLE:
            raise Fido2NotAvailableError()

        self._credential_id = credential_id
        self._rp_id = rp_id
        self._device = self._find_device()

    def _find_device(self) -> Any:
        """Find a FIDO2 device.

        Returns:
            CtapHidDevice

        Raises:
            Fido2DeviceNotFoundError: If no device found
        """
        devices = list(CtapHidDevice.list_devices())
        if not devices:
            raise Fido2DeviceNotFoundError()

        # Return first device (subclasses could override for device selection)
        return devices[0]

    @property
    def credential_id(self) -> bytes:
        """The FIDO2 credential ID."""
        return self._credential_id

    @property
    def rp_id(self) -> str:
        """The relying party ID."""
        return self._rp_id

    @abstractmethod
    def _get_user_interaction(self) -> UserInteraction:
        """Get the device-specific user interaction handler.

        Subclasses must implement this to provide appropriate interaction
        handling for their device type.

        Returns:
            A UserInteraction instance for the fido2 library
        """
        ...

    def challenge_response(self, challenge: bytes) -> SecureBytes:
        """Get hmac-secret output using challenge as salt.

        Args:
            challenge: Challenge bytes (typically 32-byte KDF salt).
                Must be exactly 32 bytes for FIDO2 hmac-secret.

        Returns:
            32-byte hmac-secret output wrapped in SecureBytes

        Raises:
            ValueError: If challenge is not 32 bytes
            Fido2CredentialNotFoundError: If credential not found on device
            Fido2PinRequiredError: If device requires PIN but none provided
            Fido2Error: For other FIDO2 errors
        """
        if len(challenge) != 32:
            raise ValueError("FIDO2 hmac-secret requires exactly 32 bytes challenge")

        user_interaction = self._get_user_interaction()

        try:
            client = Fido2Client(
                self._device,
                f"https://{self._rp_id}",
                user_interaction=user_interaction,
            )

            # Get assertion with hmac-secret extension
            allow_credentials = [
                PublicKeyCredentialDescriptor(
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                    id=self._credential_id,
                )
            ]

            logger.debug("Starting FIDO2 hmac-secret challenge-response")

            result = client.get_assertion(
                PublicKeyCredentialRequestOptions(
                    rp_id=self._rp_id,
                    challenge=challenge,
                    allow_credentials=allow_credentials,
                    extensions={"hmacGetSecret": {"salt1": challenge}},
                )
            )

            # Extract hmac-secret output from extension results
            response = result.get_response(0)
            extension_results = response.extension_results

            if not extension_results or "hmacGetSecret" not in extension_results:
                raise Fido2Error("Device did not return hmac-secret output")

            output = extension_results["hmacGetSecret"]["output1"]
            logger.debug("FIDO2 hmac-secret challenge-response complete")

            return SecureBytes(bytes(output))

        except Fido2PinRequiredError:
            raise
        except Fido2CredentialNotFoundError:
            raise
        except Exception as e:
            error_msg = str(e).lower()

            if "credential" in error_msg and "not" in error_msg:
                raise Fido2CredentialNotFoundError() from e
            if "pin" in error_msg:
                raise Fido2PinRequiredError() from e
            if "no device" in error_msg or "not found" in error_msg:
                raise Fido2DeviceNotFoundError() from e

            raise Fido2Error(f"FIDO2 hmac-secret failed: {e}") from e

    def __repr__(self) -> str:
        """Return string representation."""
        cred_str = self._credential_id.hex()[:16] + "..."
        return f"{self.__class__.__name__}(credential_id={cred_str}, rp_id={self._rp_id})"


class YubiKeyFido2(Fido2HmacSecret):
    """FIDO2 hmac-secret provider for YubiKey devices.

    YubiKey FIDO2 uses host-side PIN entry (PIN is entered on the computer,
    not the device) and requires touch for user presence.

    Example:
        >>> # With PIN callback for interactive PIN entry
        >>> provider = YubiKeyFido2(
        ...     credential_id=stored_id,
        ...     pin_callback=lambda: getpass.getpass("YubiKey PIN: "),
        ...     on_touch=lambda msg: print(msg),
        ... )
        >>>
        >>> # With known PIN
        >>> provider = YubiKeyFido2(
        ...     credential_id=stored_id,
        ...     pin_callback=lambda: "123456",
        ... )
        >>>
        >>> # No PIN required (device configured without PIN)
        >>> provider = YubiKeyFido2(credential_id=stored_id)
    """

    def __init__(
        self,
        credential_id: bytes,
        rp_id: str = DEFAULT_RP_ID,
        pin_callback: Callable[[], str] | None = None,
        on_touch: Callable[[str], None] | None = None,
    ) -> None:
        """Initialize YubiKey FIDO2 provider.

        Args:
            credential_id: The credential ID from create_fido2_credential()
            rp_id: Relying party ID (must match credential creation)
            pin_callback: Called when PIN is needed. Should return the PIN.
                If None and PIN is required, Fido2PinRequiredError is raised.
            on_touch: Called with a message when touch is required.
                Example: lambda msg: print(msg)

        Raises:
            Fido2NotAvailableError: If python-fido2 is not installed
            Fido2DeviceNotFoundError: If no FIDO2 device is connected
        """
        self._pin_callback = pin_callback
        self._on_touch = on_touch
        super().__init__(credential_id, rp_id)

    def _get_user_interaction(self) -> UserInteraction:
        """Get YubiKey-specific user interaction handler."""
        return _YubiKeyInteraction(self._pin_callback, self._on_touch)


# YubiKey-specific UserInteraction implementation
if FIDO2_AVAILABLE:

    class _YubiKeyInteraction(UserInteraction):  # type: ignore[misc]
        """UserInteraction for YubiKey FIDO2 devices.

        Handles host-side PIN entry and touch prompts.
        """

        def __init__(
            self,
            pin_callback: Callable[[], str] | None,
            on_touch: Callable[[str], None] | None,
        ) -> None:
            self._pin_callback = pin_callback
            self._on_touch = on_touch
            self._touch_prompted = False

        def prompt_up(self) -> None:
            """Called when user presence (touch) is required."""
            if not self._touch_prompted and self._on_touch is not None:
                self._on_touch("Touch your YubiKey...")
                self._touch_prompted = True

        def request_pin(self, permissions: Any, rd_id: str | None = None) -> str | None:
            """Called when PIN is required - get from callback."""
            if self._pin_callback is None:
                raise Fido2PinRequiredError()
            return self._pin_callback()

        def request_uv(self, permissions: Any, rd_id: str | None = None) -> bool:
            """Called when user verification is required."""
            return True
