"""kdbxtool - A modern, secure Python library for KeePass KDBX databases.

This library provides a clean, type-safe API for reading and writing KeePass
database files (KDBX format). It prioritizes security with:
- Secure memory handling (zeroization of sensitive data)
- Constant-time comparisons for authentication
- Modern cryptographic defaults (Argon2d, ChaCha20)

Example:
    from kdbxtool import Database

    db = Database.open("vault.kdbx", password="secret")
    entry = db.find_entries(title="Gmail")[0]
    print(entry.username)

    # Create new entry
    db.root_group.create_entry(
        title="New Site",
        username="user",
        password="pass123",
    )
    db.save()
"""

from importlib.metadata import version

__version__ = version("kdbxtool")

from .database import Database, DatabaseSettings
from .exceptions import (
    AuthenticationError,
    CorruptedDataError,
    CredentialError,
    CryptoError,
    DatabaseError,
    DecryptionError,
    EntryNotFoundError,
    FormatError,
    GroupNotFoundError,
    InvalidKeyFileError,
    InvalidPasswordError,
    InvalidSignatureError,
    InvalidXmlError,
    Kdbx3UpgradeRequired,
    KdbxError,
    KdfError,
    MergeError,
    MissingCredentialsError,
    TwofishNotAvailableError,
    UnknownCipherError,
    UnsupportedVersionError,
    YubiKeyError,
    YubiKeyNotAvailableError,
    YubiKeyNotFoundError,
    YubiKeySlotError,
    YubiKeyTimeoutError,
)
from .merge import DeletedObject, MergeMode, MergeResult
from .models import Attachment, Entry, Group, HistoryEntry, Times
from .security import AesKdfConfig, Argon2Config, Cipher, KdfType
from .security.keyfile import (
    KeyFileVersion,
    create_keyfile,
    create_keyfile_bytes,
    parse_keyfile,
)
from .security.yubikey import (
    YubiKeyConfig,
    check_slot_configured,
    list_yubikeys,
)
from .templates import EntryTemplate, IconId, Templates

__all__ = [
    # Core classes
    "AesKdfConfig",
    "Argon2Config",
    "Attachment",
    "Database",
    "DatabaseSettings",
    "Entry",
    "Group",
    "HistoryEntry",
    "Times",
    "Cipher",
    "KdfType",
    # Merge support
    "MergeMode",
    "MergeResult",
    "DeletedObject",
    # Entry templates
    "EntryTemplate",
    "IconId",
    "Templates",
    # Keyfile support
    "KeyFileVersion",
    "create_keyfile",
    "create_keyfile_bytes",
    "parse_keyfile",
    # YubiKey support
    "YubiKeyConfig",
    "check_slot_configured",
    "list_yubikeys",
    # Exceptions
    "KdbxError",
    "FormatError",
    "InvalidSignatureError",
    "UnsupportedVersionError",
    "CorruptedDataError",
    "CryptoError",
    "DecryptionError",
    "AuthenticationError",
    "KdfError",
    "TwofishNotAvailableError",
    "UnknownCipherError",
    "CredentialError",
    "InvalidPasswordError",
    "InvalidKeyFileError",
    "MergeError",
    "MissingCredentialsError",
    "DatabaseError",
    "EntryNotFoundError",
    "GroupNotFoundError",
    "InvalidXmlError",
    "Kdbx3UpgradeRequired",
    "YubiKeyError",
    "YubiKeyNotAvailableError",
    "YubiKeyNotFoundError",
    "YubiKeySlotError",
    "YubiKeyTimeoutError",
]
