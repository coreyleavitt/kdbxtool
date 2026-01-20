"""Security-critical components for kdbxtool.

This module contains all security-sensitive code including:
- Secure memory handling (SecureBytes)
- Cryptographic operations
- Key derivation functions
- Challenge-response providers (YubiKey, FIDO2)

All code in this module should be audited carefully.
"""

from .challenge_response import ChallengeResponseProvider
from .crypto import (
    Cipher,
    CipherContext,
    compute_hmac_sha256,
    constant_time_compare,
    secure_random_bytes,
    verify_hmac_sha256,
)
from .fido2 import (
    DEFAULT_RP_ID,
    FIDO2_AVAILABLE,
    Fido2HmacSecret,
    YubiKeyFido2,
    create_fido2_credential,
    list_fido2_devices,
)
from .kdf import (
    ARGON2_MIN_ITERATIONS,
    ARGON2_MIN_MEMORY_KIB,
    ARGON2_MIN_PARALLELISM,
    AesKdfConfig,
    Argon2Config,
    KdfType,
    derive_composite_key,
    derive_key_aes_kdf,
    derive_key_argon2,
)
from .keyfile import (
    KeyFileVersion,
    create_keyfile,
    create_keyfile_bytes,
    parse_keyfile,
)
from .memory import SecureBytes
from .yubikey import (
    HMAC_SHA1_RESPONSE_SIZE,
    YUBIKEY_AVAILABLE,
    YUBIKEY_HARDWARE_AVAILABLE,
    YubiKeyHmacSha1,
    YubiKeyConfig,
    check_slot_configured,
    compute_challenge_response,
    list_yubikeys,
)

__all__ = [
    # Memory
    "SecureBytes",
    # Crypto
    "Cipher",
    "CipherContext",
    "compute_hmac_sha256",
    "constant_time_compare",
    "secure_random_bytes",
    "verify_hmac_sha256",
    # KDF
    "ARGON2_MIN_ITERATIONS",
    "ARGON2_MIN_MEMORY_KIB",
    "ARGON2_MIN_PARALLELISM",
    "AesKdfConfig",
    "Argon2Config",
    "KdfType",
    "derive_composite_key",
    "derive_key_aes_kdf",
    "derive_key_argon2",
    # Keyfile
    "KeyFileVersion",
    "create_keyfile",
    "create_keyfile_bytes",
    "parse_keyfile",
    # Challenge-Response Protocol
    "ChallengeResponseProvider",
    # YubiKey
    "HMAC_SHA1_RESPONSE_SIZE",
    "YUBIKEY_AVAILABLE",
    "YUBIKEY_HARDWARE_AVAILABLE",
    "YubiKeyHmacSha1",
    "YubiKeyConfig",
    "check_slot_configured",
    "compute_challenge_response",
    "list_yubikeys",
    # FIDO2
    "DEFAULT_RP_ID",
    "FIDO2_AVAILABLE",
    "Fido2HmacSecret",
    "YubiKeyFido2",
    "create_fido2_credential",
    "list_fido2_devices",
]
