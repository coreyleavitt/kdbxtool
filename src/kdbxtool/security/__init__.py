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
from .kek import (
    CR_DEVICE_PREFIX,
    CR_SALT_KEY,
    CR_VERSION_KEY,
    VERSION_KEK,
    VERSION_COMPAT,
    WRAPPED_KEK_SIZE,
    EnrolledDevice,
    derive_final_key,
    deserialize_device_entry,
    generate_kek,
    generate_salt,
    get_device_key_name,
    parse_device_key_name,
    serialize_device_entry,
    unwrap_kek,
    wrap_kek,
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
    YubiKeyConfig,
    YubiKeyHmacSha1,
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
    # KEK (Key Encryption Key) for multi-device support
    "CR_DEVICE_PREFIX",
    "CR_SALT_KEY",
    "CR_VERSION_KEY",
    "VERSION_KEK",
    "VERSION_COMPAT",
    "WRAPPED_KEK_SIZE",
    "EnrolledDevice",
    "derive_final_key",
    "deserialize_device_entry",
    "generate_kek",
    "generate_salt",
    "get_device_key_name",
    "parse_device_key_name",
    "serialize_device_entry",
    "unwrap_kek",
    "wrap_kek",
]
