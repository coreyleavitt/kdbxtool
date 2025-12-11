"""Custom exception hierarchy for kdbxtool.

This module provides a rich exception hierarchy for better error handling
and user feedback. All exceptions inherit from KdbxError.

Exception Hierarchy:
    KdbxError (base)
    ├── FormatError
    │   ├── InvalidSignatureError
    │   ├── UnsupportedVersionError
    │   └── CorruptedDataError
    ├── CryptoError
    │   ├── DecryptionError
    │   ├── AuthenticationError
    │   ├── KdfError
    │   ├── UnknownCipherError
    │   └── TwofishNotAvailableError
    ├── CredentialError
    │   ├── InvalidPasswordError
    │   ├── InvalidKeyFileError
    │   ├── MissingCredentialsError
    │   └── YubiKeyError
    │       ├── YubiKeyNotFoundError
    │       ├── YubiKeySlotError
    │       ├── YubiKeyTimeoutError
    │       └── YubiKeyNotAvailableError
    └── DatabaseError
        ├── EntryNotFoundError
        └── GroupNotFoundError

Security Note:
    Exception messages are designed to avoid leaking sensitive information.
    They provide enough context for debugging without exposing secrets.
"""

from __future__ import annotations


class KdbxError(Exception):
    """Base exception for all kdbxtool errors.

    All exceptions raised by kdbxtool inherit from this class,
    making it easy to catch all library-specific errors.
    """


# --- Format Errors ---


class FormatError(KdbxError):
    """Error in KDBX file format or structure.

    Raised when the file doesn't conform to the KDBX specification.
    """


class InvalidSignatureError(FormatError):
    """Invalid KDBX file signature (magic bytes).

    The file doesn't start with the expected KDBX magic bytes,
    indicating it's not a valid KeePass database file.
    """


class UnsupportedVersionError(FormatError):
    """Unsupported KDBX version.

    The file uses a KDBX version that this library doesn't support.
    """

    def __init__(self, version_major: int, version_minor: int) -> None:
        self.version_major = version_major
        self.version_minor = version_minor
        super().__init__(f"Unsupported KDBX version: {version_major}.{version_minor}")


class CorruptedDataError(FormatError):
    """Database file is corrupted or truncated.

    The file structure is invalid, possibly due to incomplete download,
    disk corruption, or other data integrity issues.
    """


# --- Crypto Errors ---


class CryptoError(KdbxError):
    """Error in cryptographic operations.

    Base class for all cryptographic errors including encryption,
    decryption, and key derivation.
    """


class DecryptionError(CryptoError):
    """Failed to decrypt database content.

    This typically indicates wrong credentials (password/keyfile),
    but the message is kept generic to avoid confirming which
    credential component is incorrect.
    """

    def __init__(self, message: str = "Decryption failed") -> None:
        super().__init__(message)


class AuthenticationError(CryptoError):
    """HMAC or integrity verification failed.

    The database's authentication code doesn't match, indicating
    either wrong credentials or data tampering.
    """

    def __init__(
        self, message: str = "Authentication failed - wrong credentials or corrupted data"
    ) -> None:
        super().__init__(message)


class KdfError(CryptoError):
    """Error in key derivation function.

    Problems with KDF parameters, unsupported KDF types,
    or KDF computation failures.
    """


class UnknownCipherError(CryptoError):
    """Unknown or unsupported cipher algorithm.

    The database uses a cipher that this library doesn't recognize.
    """

    def __init__(self, cipher_uuid: bytes) -> None:
        self.cipher_uuid = cipher_uuid
        super().__init__(f"Unknown cipher: {cipher_uuid.hex()}")


class TwofishNotAvailableError(CryptoError):
    """Twofish cipher requested but oxifish package not installed.

    The database uses Twofish encryption, which requires the optional
    oxifish package. Install it with: pip install kdbxtool[twofish]
    """

    def __init__(self) -> None:
        super().__init__(
            "Twofish cipher requires the oxifish package. "
            "Install with: pip install kdbxtool[twofish]"
        )


# --- Credential Errors ---


class CredentialError(KdbxError):
    """Error with database credentials.

    Base class for credential-related errors. Messages are kept
    generic to avoid information disclosure about which credential
    component is incorrect.
    """


class InvalidPasswordError(CredentialError):
    """Invalid or missing password.

    Note: This is only raised when we can definitively determine
    the password is wrong without revealing information about
    other credential components.
    """

    def __init__(self, message: str = "Invalid password") -> None:
        super().__init__(message)


class InvalidKeyFileError(CredentialError):
    """Invalid or missing keyfile.

    The keyfile is malformed, has wrong format, or failed
    hash verification.
    """

    def __init__(self, message: str = "Invalid keyfile") -> None:
        super().__init__(message)


class MissingCredentialsError(CredentialError):
    """No credentials provided.

    At least one credential (password or keyfile) is required
    to open or create a database.
    """

    def __init__(self) -> None:
        super().__init__("At least one credential (password or keyfile) is required")


# --- YubiKey Errors ---


class YubiKeyError(CredentialError):
    """Error communicating with YubiKey.

    Base class for YubiKey-related errors. These occur during
    challenge-response authentication with a hardware YubiKey.
    """


class YubiKeyNotFoundError(YubiKeyError):
    """No YubiKey detected.

    No YubiKey device was found connected to the system.
    Ensure the YubiKey is properly inserted.
    """

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or "No YubiKey device found. Ensure it is connected.")


class YubiKeySlotError(YubiKeyError):
    """YubiKey slot not configured for HMAC-SHA1.

    The specified slot on the YubiKey is not configured for
    HMAC-SHA1 challenge-response authentication.
    """

    def __init__(self, slot: int) -> None:
        self.slot = slot
        super().__init__(f"YubiKey slot {slot} is not configured for HMAC-SHA1 challenge-response")


class YubiKeyTimeoutError(YubiKeyError):
    """YubiKey operation timed out.

    The YubiKey operation timed out, typically because touch
    was required but not received within the timeout period.
    """

    def __init__(self, timeout_seconds: float = 15.0) -> None:
        self.timeout_seconds = timeout_seconds
        super().__init__(
            f"YubiKey operation timed out after {timeout_seconds}s. "
            "Touch may be required - try again and press the YubiKey button."
        )


class YubiKeyNotAvailableError(YubiKeyError):
    """YubiKey support requested but yubikey-manager not installed.

    The yubikey-manager package is required for YubiKey challenge-response
    authentication. Install it with: pip install kdbxtool[yubikey]
    """

    def __init__(self) -> None:
        super().__init__(
            "YubiKey support requires the yubikey-manager package. "
            "Install with: pip install kdbxtool[yubikey]"
        )


# --- Database Errors ---


class DatabaseError(KdbxError):
    """Error in database operations.

    Base class for errors that occur during database manipulation
    after successful decryption.
    """


class EntryNotFoundError(DatabaseError):
    """Entry not found in database.

    The requested entry doesn't exist or was not found
    in the specified location.
    """

    def __init__(self, message: str = "Entry not found") -> None:
        super().__init__(message)


class GroupNotFoundError(DatabaseError):
    """Group not found in database.

    The requested group doesn't exist or was not found
    in the database hierarchy.
    """

    def __init__(self, message: str = "Group not found") -> None:
        super().__init__(message)


class InvalidXmlError(DatabaseError):
    """Invalid or malformed XML payload.

    The decrypted XML content doesn't conform to the expected
    KDBX XML schema.
    """

    def __init__(self, message: str = "Invalid KDBX XML structure") -> None:
        super().__init__(message)


class Kdbx3UpgradeRequired(DatabaseError):
    """KDBX3 database requires explicit upgrade confirmation.

    When saving a KDBX3 database to its original file, explicit
    confirmation is required since the save will upgrade it to KDBX4.
    Use save(allow_upgrade=True) to confirm the upgrade.
    """

    def __init__(self) -> None:
        super().__init__(
            "Saving a KDBX3 database will upgrade it to KDBX4 format. "
            "Use save(allow_upgrade=True) to confirm, or save to a different file."
        )


class MergeError(DatabaseError):
    """Error during database merge operation.

    Raised when a merge operation fails due to incompatible databases,
    invalid state, or other merge-specific issues.
    """

    def __init__(self, message: str = "Merge operation failed") -> None:
        super().__init__(message)
