"""High-level Database API for KDBX files.

This module provides the main interface for working with KeePass databases:
- Opening and decrypting KDBX files
- Creating new databases
- Searching for entries and groups
- Saving databases
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import getpass
import hashlib
import os
import uuid as uuid_module
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Protocol, cast
from xml.etree.ElementTree import Element, SubElement, tostring

if TYPE_CHECKING:
    from .merge import DeletedObject, MergeMode, MergeResult

from Cryptodome.Cipher import ChaCha20, Salsa20
from defusedxml import ElementTree as DefusedET

from .exceptions import (
    AuthenticationError,
    DatabaseError,
    InvalidXmlError,
    Kdbx3UpgradeRequired,
    MissingCredentialsError,
    UnknownCipherError,
)
from .models import Attachment, Entry, Group, HistoryEntry, Times
from .models.entry import AutoType, BinaryRef, StringField
from .parsing import CompressionType, KdbxHeader, KdbxVersion
from .parsing.kdbx3 import read_kdbx3
from .parsing.kdbx4 import InnerHeader, read_kdbx4, write_kdbx4
from .security import AesKdfConfig, Argon2Config, Cipher, KdfType
from .security import yubikey as yubikey_module
from .security.yubikey import YubiKeyConfig, compute_challenge_response

# Union type for KDF configurations
KdfConfig = Argon2Config | AesKdfConfig


class _StreamCipher(Protocol):
    """Protocol for stream ciphers used for protected value encryption."""

    def encrypt(self, plaintext: bytes) -> bytes: ...
    def decrypt(self, ciphertext: bytes) -> bytes: ...


# KDBX4 time format (ISO 8601, compatible with KeePassXC)
KDBX4_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# Protected stream cipher IDs
PROTECTED_STREAM_SALSA20 = 2
PROTECTED_STREAM_CHACHA20 = 3


class ProtectedStreamCipher:
    """Stream cipher for encrypting/decrypting protected values in XML.

    KDBX uses a stream cipher (ChaCha20 or Salsa20) to protect sensitive
    values like passwords in the XML payload. Each protected value is
    XOR'd with the cipher output in document order.
    """

    def __init__(self, stream_id: int, stream_key: bytes) -> None:
        """Initialize the stream cipher.

        Args:
            stream_id: Cipher type (2=Salsa20, 3=ChaCha20)
            stream_key: Key material from inner header (typically 64 bytes)
        """
        self._stream_id = stream_id
        self._stream_key = stream_key
        self._cipher = self._create_cipher()

    def _create_cipher(self) -> _StreamCipher:
        """Create the appropriate cipher based on stream_id."""
        if self._stream_id == PROTECTED_STREAM_CHACHA20:
            # ChaCha20: SHA-512 of key, first 32 bytes = key, bytes 32-44 = nonce
            key_hash = hashlib.sha512(self._stream_key).digest()
            key = key_hash[:32]
            nonce = key_hash[32:44]
            return ChaCha20.new(key=key, nonce=nonce)
        elif self._stream_id == PROTECTED_STREAM_SALSA20:
            # Salsa20: SHA-256 of key, fixed nonce
            key = hashlib.sha256(self._stream_key).digest()
            nonce = b"\xe8\x30\x09\x4b\x97\x20\x5d\x2a"
            return Salsa20.new(key=key, nonce=nonce)
        else:
            raise UnknownCipherError(self._stream_id.to_bytes(4, "little"))

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt protected value (XOR with stream)."""
        return self._cipher.decrypt(ciphertext)

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt protected value (XOR with stream)."""
        return self._cipher.encrypt(plaintext)


@dataclass
class CustomIcon:
    """A custom icon in a KDBX database.

    Custom icons are PNG images that can be assigned to entries and groups
    for visual customization beyond the standard icon set.

    Attributes:
        uuid: Unique identifier for the icon
        data: PNG image data
        name: Optional display name for the icon
        last_modification_time: When the icon was last modified
    """

    uuid: uuid_module.UUID
    data: bytes
    name: str | None = None
    last_modification_time: datetime | None = None


@dataclass
class DatabaseSettings:
    """Settings for a KDBX database.

    Attributes:
        generator: Generator application name
        database_name: Name of the database
        database_description: Description of the database
        default_username: Default username for new entries
        maintenance_history_days: Days to keep deleted items
        color: Database color (hex)
        master_key_change_rec: Days until master key change recommended
        master_key_change_force: Days until master key change forced
        memory_protection: Which fields to protect in memory
        recycle_bin_enabled: Whether recycle bin is enabled
        recycle_bin_uuid: UUID of recycle bin group
        history_max_items: Max history entries per entry
        history_max_size: Max history size in bytes
        custom_icons: Dictionary of custom icons (UUID -> CustomIcon)
    """

    generator: str = "kdbxtool"
    database_name: str = "Database"
    database_description: str = ""
    default_username: str = ""
    maintenance_history_days: int = 365
    color: str | None = None
    master_key_change_rec: int = -1
    master_key_change_force: int = -1
    memory_protection: dict[str, bool] = field(
        default_factory=lambda: {
            "Title": False,
            "UserName": False,
            "Password": True,
            "URL": False,
            "Notes": False,
        }
    )
    recycle_bin_enabled: bool = True
    recycle_bin_uuid: uuid_module.UUID | None = None
    history_max_items: int = 10
    history_max_size: int = 6 * 1024 * 1024  # 6 MiB
    custom_icons: dict[uuid_module.UUID, CustomIcon] = field(default_factory=dict)
    deleted_objects: list[DeletedObject] = field(default_factory=list)


class Database:
    """High-level interface for KDBX databases.

    This class provides the main API for working with KeePass databases.
    It handles encryption/decryption, XML parsing, and model management.

    Example usage:
        # Open existing database
        db = Database.open("passwords.kdbx", password="secret")

        # Find entries
        entries = db.find_entries(title="GitHub")

        # Create entry
        entry = db.root_group.create_entry(
            title="New Site",
            username="user",
            password="pass123",
        )

        # Save changes
        db.save()
    """

    def __init__(
        self,
        root_group: Group,
        settings: DatabaseSettings | None = None,
        header: KdbxHeader | None = None,
        inner_header: InnerHeader | None = None,
        binaries: dict[int, bytes] | None = None,
    ) -> None:
        """Initialize database.

        Usually you should use Database.open() or Database.create() instead.

        Args:
            root_group: Root group containing all entries/groups
            settings: Database settings
            header: KDBX header (for existing databases)
            inner_header: Inner header (for existing databases)
            binaries: Binary attachments
        """
        self._root_group = root_group
        self._settings = settings or DatabaseSettings()
        self._header = header
        self._inner_header = inner_header
        self._binaries = binaries or {}
        self._password: str | None = None
        self._keyfile_data: bytes | None = None
        self._transformed_key: bytes | None = None
        self._filepath: Path | None = None
        self._yubikey_slot: int | None = None
        self._yubikey_serial: int | None = None
        # Set database reference on all entries and groups
        self._set_database_references(root_group)

    def _set_database_references(self, group: Group) -> None:
        """Recursively set _database reference on a group and all its contents."""
        group._database = self
        for entry in group.entries:
            entry._database = self
        for subgroup in group.subgroups:
            self._set_database_references(subgroup)

    def __enter__(self) -> Database:
        """Enter context manager."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Exit context manager, zeroizing credentials."""
        self.zeroize_credentials()

    def zeroize_credentials(self) -> None:
        """Explicitly zeroize stored credentials from memory.

        Call this when done with the database to minimize the time
        credentials remain in memory. Note that Python's string
        interning may retain copies; for maximum security, use
        SecureBytes for credential input.
        """
        # Clear password (Python GC will eventually free memory)
        self._password = None
        # Clear keyfile data (convert to bytearray and zeroize if possible)
        if self._keyfile_data is not None:
            try:
                # Attempt to overwrite the memory
                data = bytearray(self._keyfile_data)
                for i in range(len(data)):
                    data[i] = 0
            except TypeError:
                pass  # bytes is immutable, just dereference
            self._keyfile_data = None
        # Clear transformed key
        if self._transformed_key is not None:
            try:
                data = bytearray(self._transformed_key)
                for i in range(len(data)):
                    data[i] = 0
            except TypeError:
                pass
            self._transformed_key = None

    def dump(self) -> str:
        """Return a human-readable summary of the database for debugging.

        Returns:
            Multi-line string with database metadata and statistics.
        """
        lines = [f'Database: "{self._settings.database_name or "(unnamed)"}"']
        if self._header is not None:
            lines.append(f"  Format: KDBX{self._header.version.value}")
            lines.append(f"  Cipher: {self._header.cipher.name}")
            lines.append(f"  KDF: {self._header.kdf_type.name}")

        # Count entries and groups
        entry_count = sum(1 for _ in self._root_group.iter_entries(recursive=True))
        group_count = sum(1 for _ in self._root_group.iter_groups(recursive=True))
        lines.append(f"  Total entries: {entry_count}")
        lines.append(f"  Total groups: {group_count}")

        # Custom icons
        if self.custom_icons:
            lines.append(f"  Custom icons: {len(self.custom_icons)}")

        # Recycle bin
        if self._settings.recycle_bin_enabled:
            lines.append("  Recycle bin: enabled")

        return "\n".join(lines)

    def merge(
        self,
        source: Database,
        *,
        mode: MergeMode | None = None,
    ) -> MergeResult:
        """Merge another database into this one.

        Combines entries, groups, history, attachments, and custom icons
        from the source database into this database using UUID-based
        matching and timestamp-based conflict resolution.

        Args:
            source: Database to merge from (read-only)
            mode: Merge mode (STANDARD or SYNCHRONIZE). Defaults to STANDARD.
                - STANDARD: Add and update only, never deletes
                - SYNCHRONIZE: Full sync including deletions

        Returns:
            MergeResult with counts and statistics about the merge

        Raises:
            MergeError: If merge cannot be completed

        Example:
            >>> target_db = Database.open("main.kdbx", password="secret")
            >>> source_db = Database.open("branch.kdbx", password="secret")
            >>> result = target_db.merge(source_db)
            >>> print(f"Added {result.entries_added} entries")
            >>> target_db.save()
        """
        from .merge import MergeMode, Merger

        if mode is None:
            mode = MergeMode.STANDARD

        merger = Merger(self, source, mode=mode)
        return merger.merge()

    @property
    def transformed_key(self) -> bytes | None:
        """Get the transformed key for caching.

        The transformed key is the result of applying the KDF (Argon2) to
        the credentials. Caching this allows fast repeated database opens
        without re-running the expensive KDF.

        Security note: The transformed key is as sensitive as the password.
        Anyone with this key can decrypt the database. Store securely and
        zeroize when done.

        Returns:
            The transformed key, or None if not available (e.g., newly created DB)
        """
        return self._transformed_key

    @property
    def kdf_salt(self) -> bytes | None:
        """Get the KDF salt used for key derivation.

        The salt is used together with credentials to derive the transformed key.
        If the salt changes (e.g., after save with regenerate_seeds=True),
        any cached transformed_key becomes invalid.

        Returns:
            The KDF salt, or None if no header is set
        """
        if self._header is None:
            return None
        return self._header.kdf_salt

    @property
    def root_group(self) -> Group:
        """Get the root group of the database."""
        return self._root_group

    @property
    def settings(self) -> DatabaseSettings:
        """Get database settings."""
        return self._settings

    @property
    def filepath(self) -> Path | None:
        """Get the file path (if opened from file)."""
        return self._filepath

    # --- Opening databases ---

    @classmethod
    def open(
        cls,
        filepath: str | Path,
        password: str | None = None,
        keyfile: str | Path | None = None,
        yubikey_slot: int | None = None,
        yubikey_serial: int | None = None,
    ) -> Database:
        """Open an existing KDBX database.

        Args:
            filepath: Path to the .kdbx file
            password: Database password
            keyfile: Path to keyfile (optional)
            yubikey_slot: YubiKey slot for challenge-response (1 or 2, optional).
                If provided, the database's KDF salt is used as challenge and
                the 20-byte HMAC-SHA1 response is incorporated into key derivation.
                Requires yubikey-manager package: pip install kdbxtool[yubikey]
            yubikey_serial: Serial number of specific YubiKey to use when multiple
                devices are connected. Use list_yubikeys() to discover serials.

        Returns:
            Database instance

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If credentials are wrong or file is corrupted
            YubiKeyError: If YubiKey operation fails
        """
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"Database file not found: {filepath}")

        data = filepath.read_bytes()

        keyfile_data = None
        if keyfile:
            keyfile_path = Path(keyfile)
            if not keyfile_path.exists():
                raise FileNotFoundError(f"Keyfile not found: {keyfile}")
            keyfile_data = keyfile_path.read_bytes()

        return cls.open_bytes(
            data,
            password=password,
            keyfile_data=keyfile_data,
            filepath=filepath,
            yubikey_slot=yubikey_slot,
            yubikey_serial=yubikey_serial,
        )

    @classmethod
    def open_interactive(
        cls,
        filepath: str | Path,
        keyfile: str | Path | None = None,
        yubikey_slot: int | None = None,
        yubikey_serial: int | None = None,
        prompt: str = "Password: ",
        max_attempts: int = 3,
    ) -> Database:
        """Open a KDBX database with interactive password prompt.

        Prompts the user for a password using secure input (no echo). If the
        password is incorrect, allows retrying up to max_attempts times.

        This is a convenience method for CLI applications that need to securely
        prompt for database credentials.

        Args:
            filepath: Path to the .kdbx file
            keyfile: Path to keyfile (optional)
            yubikey_slot: YubiKey slot for challenge-response (1 or 2, optional)
            yubikey_serial: Serial number of specific YubiKey to use
            prompt: Custom prompt string (default: "Password: ")
            max_attempts: Maximum password attempts before raising (default: 3)

        Returns:
            Database instance

        Raises:
            FileNotFoundError: If file or keyfile doesn't exist
            AuthenticationError: If max_attempts exceeded with wrong password
            YubiKeyError: If YubiKey operation fails

        Example:
            >>> db = Database.open_interactive("vault.kdbx")
            Password:
            >>> db = Database.open_interactive("vault.kdbx", keyfile="vault.key")
            Password:
        """
        import sys

        for attempt in range(max_attempts):
            password = getpass.getpass(prompt)
            try:
                return cls.open(
                    filepath,
                    password=password,
                    keyfile=keyfile,
                    yubikey_slot=yubikey_slot,
                    yubikey_serial=yubikey_serial,
                )
            except AuthenticationError:
                if attempt < max_attempts - 1:
                    print("Invalid password, try again.", file=sys.stderr)
                else:
                    raise AuthenticationError(
                        f"Authentication failed after {max_attempts} attempts"
                    ) from None
        # This should never be reached due to the raise in the loop
        raise AuthenticationError(f"Authentication failed after {max_attempts} attempts")

    @classmethod
    def open_bytes(
        cls,
        data: bytes,
        password: str | None = None,
        keyfile_data: bytes | None = None,
        filepath: Path | None = None,
        transformed_key: bytes | None = None,
        yubikey_slot: int | None = None,
        yubikey_serial: int | None = None,
    ) -> Database:
        """Open a KDBX database from bytes.

        Supports both KDBX3 and KDBX4 formats. KDBX3 databases are opened
        read-only and will be automatically upgraded to KDBX4 on save.

        Args:
            data: KDBX file contents
            password: Database password
            keyfile_data: Keyfile contents (optional)
            filepath: Original file path (for save)
            transformed_key: Precomputed transformed key (skips KDF, faster opens)
            yubikey_slot: YubiKey slot for challenge-response (1 or 2, optional).
                If provided, the database's KDF salt is used as challenge and
                the 20-byte HMAC-SHA1 response is incorporated into key derivation.
                Requires yubikey-manager package: pip install kdbxtool[yubikey]
            yubikey_serial: Serial number of specific YubiKey to use when multiple
                devices are connected. Use list_yubikeys() to discover serials.

        Returns:
            Database instance

        Raises:
            YubiKeyError: If YubiKey operation fails
        """
        # Detect version from header (parse just enough to get version)
        header, _ = KdbxHeader.parse(data)

        # Get YubiKey response if slot specified
        # KeePassXC uses the KDF salt as the challenge, not master_seed
        yubikey_response: bytes | None = None
        if yubikey_slot is not None:
            if not yubikey_module.YUBIKEY_AVAILABLE:
                from .exceptions import YubiKeyNotAvailableError

                raise YubiKeyNotAvailableError()
            config = YubiKeyConfig(slot=yubikey_slot, serial=yubikey_serial)
            response = compute_challenge_response(header.kdf_salt, config)
            yubikey_response = response.data

        # Decrypt the file using appropriate reader
        is_kdbx3 = header.version == KdbxVersion.KDBX3
        if is_kdbx3:
            import warnings

            warnings.warn(
                "Opening KDBX3 database. Saving will automatically upgrade to KDBX4 "
                "with modern security settings (Argon2d, ChaCha20). "
                "Use save(allow_upgrade=True) to confirm.",
                UserWarning,
                stacklevel=3,
            )
            # KDBX3 doesn't support YubiKey CR in the same way
            # (KeeChallenge used a sidecar XML file, not integrated)
            if yubikey_slot is not None:
                raise DatabaseError(
                    "YubiKey challenge-response is not supported for KDBX3 databases. "
                    "Upgrade to KDBX4 first."
                )
            payload = read_kdbx3(
                data,
                password=password,
                keyfile_data=keyfile_data,
                transformed_key=transformed_key,
            )
        else:
            payload = read_kdbx4(
                data,
                password=password,
                keyfile_data=keyfile_data,
                transformed_key=transformed_key,
                yubikey_response=yubikey_response,
            )

        # Parse XML into models (with protected value decryption)
        root_group, settings, binaries = cls._parse_xml(payload.xml_data, payload.inner_header)

        db = cls(
            root_group=root_group,
            settings=settings,
            header=payload.header,
            inner_header=payload.inner_header,
            binaries=binaries,
        )
        db._password = password
        db._keyfile_data = keyfile_data
        db._transformed_key = payload.transformed_key
        db._filepath = filepath
        db._opened_as_kdbx3 = is_kdbx3
        db._yubikey_slot = yubikey_slot
        db._yubikey_serial = yubikey_serial

        return db

    # --- Creating databases ---

    @classmethod
    def create(
        cls,
        filepath: str | Path | None = None,
        password: str | None = None,
        keyfile: str | Path | None = None,
        database_name: str = "Database",
        cipher: Cipher = Cipher.AES256_CBC,
        kdf_config: KdfConfig | None = None,
    ) -> Database:
        """Create a new KDBX database.

        Args:
            filepath: Path to save the database (optional)
            password: Database password
            keyfile: Path to keyfile (optional)
            database_name: Name for the database
            cipher: Encryption cipher to use
            kdf_config: KDF configuration (Argon2Config or AesKdfConfig).
                Defaults to Argon2Config.standard() with Argon2d variant.

        Returns:
            New Database instance
        """
        if password is None and keyfile is None:
            raise MissingCredentialsError()

        keyfile_data = None
        if keyfile:
            keyfile_path = Path(keyfile)
            if not keyfile_path.exists():
                raise FileNotFoundError(f"Keyfile not found: {keyfile}")
            keyfile_data = keyfile_path.read_bytes()

        # Use provided config or standard Argon2d defaults
        if kdf_config is None:
            kdf_config = Argon2Config.standard()

        # Create root group
        root_group = Group.create_root(database_name)

        # Create recycle bin group
        recycle_bin = Group(name="Recycle Bin", icon_id="43")
        root_group.add_subgroup(recycle_bin)

        # Create header based on KDF config type
        if isinstance(kdf_config, Argon2Config):
            header = KdbxHeader(
                version=KdbxVersion.KDBX4,
                cipher=cipher,
                compression=CompressionType.GZIP,
                master_seed=os.urandom(32),
                encryption_iv=os.urandom(cipher.iv_size),
                kdf_type=kdf_config.variant,
                kdf_salt=kdf_config.salt,
                argon2_memory_kib=kdf_config.memory_kib,
                argon2_iterations=kdf_config.iterations,
                argon2_parallelism=kdf_config.parallelism,
            )
        elif isinstance(kdf_config, AesKdfConfig):
            header = KdbxHeader(
                version=KdbxVersion.KDBX4,
                cipher=cipher,
                compression=CompressionType.GZIP,
                master_seed=os.urandom(32),
                encryption_iv=os.urandom(cipher.iv_size),
                kdf_type=KdfType.AES_KDF,
                kdf_salt=kdf_config.salt,
                aes_kdf_rounds=kdf_config.rounds,
            )
        else:
            raise DatabaseError(f"Unsupported KDF config type: {type(kdf_config)}")

        # Create inner header
        inner_header = InnerHeader(
            random_stream_id=3,  # ChaCha20
            random_stream_key=os.urandom(64),
            binaries={},
        )

        settings = DatabaseSettings(
            database_name=database_name,
            recycle_bin_enabled=True,
            recycle_bin_uuid=recycle_bin.uuid,
        )

        db = cls(
            root_group=root_group,
            settings=settings,
            header=header,
            inner_header=inner_header,
        )
        db._password = password
        db._keyfile_data = keyfile_data
        if filepath:
            db._filepath = Path(filepath)

        return db

    # --- Saving databases ---

    def _apply_encryption_config(
        self,
        kdf_config: KdfConfig | None = None,
        cipher: Cipher | None = None,
    ) -> None:
        """Apply encryption configuration to the database header.

        Updates KDF and/or cipher settings. Used for both KDBX3 upgrades
        and modifying existing KDBX4 databases. Always results in KDBX4.

        Args:
            kdf_config: KDF configuration (Argon2Config or AesKdfConfig).
                If None, preserves existing KDF settings.
            cipher: Encryption cipher. If None, preserves existing cipher.
        """
        if self._header is None:
            raise DatabaseError("No header - database not properly initialized")

        target_cipher = cipher if cipher is not None else self._header.cipher

        if kdf_config is not None:
            if isinstance(kdf_config, Argon2Config):
                self._header = KdbxHeader(
                    version=KdbxVersion.KDBX4,
                    cipher=target_cipher,
                    compression=self._header.compression,
                    master_seed=self._header.master_seed,
                    encryption_iv=self._header.encryption_iv,
                    kdf_type=kdf_config.variant,
                    kdf_salt=kdf_config.salt,
                    argon2_memory_kib=kdf_config.memory_kib,
                    argon2_iterations=kdf_config.iterations,
                    argon2_parallelism=kdf_config.parallelism,
                )
            elif isinstance(kdf_config, AesKdfConfig):
                self._header = KdbxHeader(
                    version=KdbxVersion.KDBX4,
                    cipher=target_cipher,
                    compression=self._header.compression,
                    master_seed=self._header.master_seed,
                    encryption_iv=self._header.encryption_iv,
                    kdf_type=KdfType.AES_KDF,
                    kdf_salt=kdf_config.salt,
                    aes_kdf_rounds=kdf_config.rounds,
                )
            # KDF change invalidates cached transformed key
            self._transformed_key = None
        elif cipher is not None and cipher != self._header.cipher:
            # Cipher-only change
            self._header.cipher = target_cipher
            self._header.encryption_iv = os.urandom(target_cipher.iv_size)
            self._transformed_key = None

    def save(
        self,
        filepath: str | Path | None = None,
        *,
        allow_upgrade: bool = False,
        regenerate_seeds: bool = True,
        kdf_config: KdfConfig | None = None,
        cipher: Cipher | None = None,
        yubikey_slot: int | None = None,
        yubikey_serial: int | None = None,
    ) -> None:
        """Save the database to a file.

        KDBX3 databases are automatically upgraded to KDBX4 on save. When saving
        a KDBX3 database to its original file, explicit confirmation is required
        via the allow_upgrade parameter.

        Args:
            filepath: Path to save to (uses original path if not specified)
            allow_upgrade: Must be True to confirm KDBX3 to KDBX4 upgrade when
                saving to the original file. Not required when saving to a new file.
            regenerate_seeds: If True (default), regenerate all cryptographic seeds
                (master_seed, encryption_iv, kdf_salt, random_stream_key) on save.
                Set to False only for testing or when using pre-computed transformed keys.
            kdf_config: Optional KDF configuration. Use presets like:
                - Argon2Config.standard() / high_security() / fast()
                - AesKdfConfig.standard() / high_security() / fast()
                For KDBX3 databases, defaults to Argon2Config.standard() for upgrade.
                For KDBX4 databases, allows changing KDF settings.
            cipher: Optional encryption cipher. Use one of:
                - Cipher.AES256_CBC (default, widely compatible)
                - Cipher.CHACHA20 (modern, faster in software)
                - Cipher.TWOFISH256_CBC (requires oxifish package)
                If not specified, preserves existing cipher.
            yubikey_slot: YubiKey slot for challenge-response (1 or 2, optional).
                If provided (or if database was opened with yubikey_slot), the new
                KDF salt is used as challenge and the response is incorporated
                into key derivation. Requires yubikey-manager package.
            yubikey_serial: Serial number of specific YubiKey to use when multiple
                devices are connected. Use list_yubikeys() to discover serials.

        Raises:
            DatabaseError: If no filepath specified and database wasn't opened from file
            Kdbx3UpgradeRequired: If saving KDBX3 to original file without allow_upgrade=True
            YubiKeyError: If YubiKey operation fails
        """
        save_to_new_file = filepath is not None
        if filepath:
            self._filepath = Path(filepath)
        elif self._filepath is None:
            raise DatabaseError("No filepath specified and database wasn't opened from file")

        # Require explicit confirmation when saving KDBX3 to original file
        was_kdbx3 = getattr(self, "_opened_as_kdbx3", False)
        if was_kdbx3 and not save_to_new_file and not allow_upgrade:
            raise Kdbx3UpgradeRequired()

        # Use provided yubikey params, or fall back to stored ones
        effective_yubikey_slot = yubikey_slot if yubikey_slot is not None else self._yubikey_slot
        effective_yubikey_serial = (
            yubikey_serial if yubikey_serial is not None else self._yubikey_serial
        )

        data = self.to_bytes(
            regenerate_seeds=regenerate_seeds,
            kdf_config=kdf_config,
            cipher=cipher,
            yubikey_slot=effective_yubikey_slot,
            yubikey_serial=effective_yubikey_serial,
        )
        self._filepath.write_bytes(data)

        # Update stored yubikey params if changed
        if yubikey_slot is not None:
            self._yubikey_slot = yubikey_slot
        if yubikey_serial is not None:
            self._yubikey_serial = yubikey_serial

        # After KDBX3 upgrade, reload to get proper KDBX4 state (including transformed_key)
        if was_kdbx3:
            self.reload()
            self._opened_as_kdbx3 = False

    def reload(self) -> None:
        """Reload the database from disk using stored credentials.

        Re-reads the database file and replaces all in-memory state with
        the current file contents. Useful for discarding unsaved changes
        or syncing with external modifications.

        Raises:
            DatabaseError: If database wasn't opened from a file
            MissingCredentialsError: If no credentials are stored
        """
        if self._filepath is None:
            raise DatabaseError("Cannot reload: database wasn't opened from a file")

        if self._password is None and self._keyfile_data is None:
            raise MissingCredentialsError()

        # Re-read and parse the file
        data = self._filepath.read_bytes()
        reloaded = self.open_bytes(
            data,
            password=self._password,
            keyfile_data=self._keyfile_data,
            filepath=self._filepath,
        )

        # Copy all state from reloaded database
        self._root_group = reloaded._root_group
        self._settings = reloaded._settings
        self._header = reloaded._header
        self._inner_header = reloaded._inner_header
        self._binaries = reloaded._binaries
        self._transformed_key = reloaded._transformed_key
        self._opened_as_kdbx3 = reloaded._opened_as_kdbx3

    def xml(self, *, pretty_print: bool = False) -> bytes:
        """Export database XML payload.

        Returns the decrypted, decompressed XML payload of the database.
        Protected values (passwords, etc.) are shown in plaintext.
        Useful for debugging and migration.

        Args:
            pretty_print: If True, format XML with indentation for readability

        Returns:
            XML payload as bytes (UTF-8 encoded)
        """
        root = Element("KeePassFile")

        # Meta section
        meta = SubElement(root, "Meta")
        self._build_meta(meta)

        # Root section
        root_elem = SubElement(root, "Root")
        self._build_group(root_elem, self._root_group)

        # Note: We do NOT encrypt protected values here - the point is to
        # export the decrypted XML for debugging/inspection

        if pretty_print:
            self._indent_xml(root)

        return cast(bytes, tostring(root, encoding="utf-8", xml_declaration=True))

    def dump_xml(self, filepath: str | Path, *, pretty_print: bool = True) -> None:
        """Write database XML payload to a file.

        Writes the decrypted, decompressed XML payload to a file.
        Protected values (passwords, etc.) are shown in plaintext.
        Useful for debugging and migration.

        Args:
            filepath: Path to write the XML file
            pretty_print: If True (default), format XML with indentation
        """
        xml_data = self.xml(pretty_print=pretty_print)
        Path(filepath).write_bytes(xml_data)

    @staticmethod
    def _indent_xml(elem: Element, level: int = 0) -> None:
        """Add indentation to XML element tree for pretty printing."""
        indent = "\n" + "  " * level
        if len(elem):
            if not elem.text or not elem.text.strip():
                elem.text = indent + "  "
            if not elem.tail or not elem.tail.strip():
                elem.tail = indent
            for child in elem:
                Database._indent_xml(child, level + 1)
            if not child.tail or not child.tail.strip():
                child.tail = indent
        else:
            if level and (not elem.tail or not elem.tail.strip()):
                elem.tail = indent

    def to_bytes(
        self,
        *,
        regenerate_seeds: bool = True,
        kdf_config: KdfConfig | None = None,
        cipher: Cipher | None = None,
        yubikey_slot: int | None = None,
        yubikey_serial: int | None = None,
    ) -> bytes:
        """Serialize the database to KDBX4 format.

        KDBX3 databases are automatically upgraded to KDBX4 on save.
        This includes converting to the specified KDF and ChaCha20 protected stream.

        Args:
            regenerate_seeds: If True (default), regenerate all cryptographic seeds
                (master_seed, encryption_iv, kdf_salt, random_stream_key) on save.
                This prevents precomputation attacks where an attacker can derive
                the encryption key in advance. Set to False only for testing or
                when using pre-computed transformed keys.
            kdf_config: Optional KDF configuration. Use presets like:
                - Argon2Config.standard() / high_security() / fast()
                - AesKdfConfig.standard() / high_security() / fast()
                For KDBX3 databases, defaults to Argon2Config.standard() for upgrade.
                For KDBX4 databases, allows changing KDF settings.
            cipher: Optional encryption cipher. Use one of:
                - Cipher.AES256_CBC (default, widely compatible)
                - Cipher.CHACHA20 (modern, faster in software)
                - Cipher.TWOFISH256_CBC (requires oxifish package)
                If not specified, preserves existing cipher.
            yubikey_slot: YubiKey slot for challenge-response (1 or 2, optional).
                If provided, the (new) KDF salt is used as challenge and the
                20-byte HMAC-SHA1 response is incorporated into key derivation.
                Requires yubikey-manager package: pip install kdbxtool[yubikey]
            yubikey_serial: Serial number of specific YubiKey to use when multiple
                devices are connected. Use list_yubikeys() to discover serials.

        Returns:
            KDBX4 file contents as bytes

        Raises:
            MissingCredentialsError: If no credentials are set
            YubiKeyError: If YubiKey operation fails
        """
        # Need either credentials, a transformed key, or YubiKey
        has_credentials = self._password is not None or self._keyfile_data is not None
        has_transformed_key = self._transformed_key is not None
        has_yubikey = yubikey_slot is not None
        if not has_credentials and not has_transformed_key and not has_yubikey:
            raise MissingCredentialsError()

        if self._header is None:
            raise DatabaseError("No header - database not properly initialized")

        if self._inner_header is None:
            raise DatabaseError("No inner header - database not properly initialized")

        # Handle KDBX3 upgrade or KDBX4 config changes
        if self._header.version == KdbxVersion.KDBX3:
            self._apply_encryption_config(kdf_config or Argon2Config.standard(), cipher=cipher)
            # Upgrade inner header to ChaCha20 (KDBX3 uses Salsa20)
            self._inner_header.random_stream_id = PROTECTED_STREAM_CHACHA20
            self._inner_header.random_stream_key = os.urandom(64)
        elif kdf_config is not None or cipher is not None:
            self._apply_encryption_config(kdf_config, cipher=cipher)

        # Regenerate all cryptographic seeds to prevent precomputation attacks.
        # This ensures each save produces a file encrypted with fresh randomness.
        # See: https://github.com/libkeepass/pykeepass/issues/219
        if regenerate_seeds:
            self._header.master_seed = os.urandom(32)
            self._header.encryption_iv = os.urandom(self._header.cipher.iv_size)
            self._header.kdf_salt = os.urandom(32)
            self._inner_header.random_stream_key = os.urandom(64)
            # Cached transformed_key is now invalid (salt changed)
            self._transformed_key = None

        # Get YubiKey response if slot specified
        # KeePassXC uses the KDF salt as the challenge, not master_seed
        yubikey_response: bytes | None = None
        if yubikey_slot is not None:
            if not yubikey_module.YUBIKEY_AVAILABLE:
                from .exceptions import YubiKeyNotAvailableError

                raise YubiKeyNotAvailableError()
            config = YubiKeyConfig(slot=yubikey_slot, serial=yubikey_serial)
            response = compute_challenge_response(self._header.kdf_salt, config)
            yubikey_response = response.data

        # Sync binaries to inner header (preserve protection flags where possible)
        existing_binaries = self._inner_header.binaries
        new_binaries: dict[int, tuple[bool, bytes]] = {}
        for ref, data in self._binaries.items():
            if ref in existing_binaries:
                # Preserve existing protection flag
                protected, _ = existing_binaries[ref]
                new_binaries[ref] = (protected, data)
            else:
                # New binary, default to protected
                new_binaries[ref] = (True, data)
        self._inner_header.binaries = new_binaries

        # Build XML
        xml_data = self._build_xml()

        # Encrypt and return
        # Use cached transformed_key if available (faster), otherwise use credentials
        return write_kdbx4(
            header=self._header,
            inner_header=self._inner_header,
            xml_data=xml_data,
            password=self._password,
            keyfile_data=self._keyfile_data,
            transformed_key=self._transformed_key,
            yubikey_response=yubikey_response,
        )

    def set_credentials(
        self,
        password: str | None = None,
        keyfile_data: bytes | None = None,
    ) -> None:
        """Set or update database credentials.

        Args:
            password: New password (None to remove)
            keyfile_data: New keyfile data (None to remove)

        Raises:
            ValueError: If both password and keyfile are None
        """
        if password is None and keyfile_data is None:
            raise MissingCredentialsError()
        self._password = password
        self._keyfile_data = keyfile_data

    # --- Search operations ---

    def find_entries(
        self,
        title: str | None = None,
        username: str | None = None,
        password: str | None = None,
        url: str | None = None,
        notes: str | None = None,
        otp: str | None = None,
        tags: list[str] | None = None,
        string: dict[str, str] | None = None,
        autotype_enabled: bool | None = None,
        autotype_sequence: str | None = None,
        autotype_window: str | None = None,
        uuid: uuid_module.UUID | None = None,
        path: list[str] | str | None = None,
        recursive: bool = True,
        history: bool = False,
        first: bool = False,
    ) -> list[Entry] | Entry | None:
        """Find entries matching criteria.

        Args:
            title: Match entries with this title
            username: Match entries with this username
            password: Match entries with this password
            url: Match entries with this URL
            notes: Match entries with these notes
            otp: Match entries with this OTP
            tags: Match entries with all these tags
            string: Match entries with custom properties (dict of key:value)
            autotype_enabled: Filter by AutoType enabled state
            autotype_sequence: Match entries with this AutoType sequence
            autotype_window: Match entries with this AutoType window
            uuid: Match entry with this UUID
            path: Path to entry as list of group names ending with entry title,
                or as a '/'-separated string. When specified, other criteria
                are ignored.
            recursive: Search in subgroups
            history: Include history entries in search
            first: If True, return first match or None. If False, return list.

        Returns:
            If first=True: Entry or None
            If first=False: List of matching entries
        """
        # Path-based search
        if path is not None:
            results = self._find_entry_by_path(path)
            if first:
                return results[0] if results else None
            return results

        if uuid is not None:
            entry = self._root_group.find_entry_by_uuid(uuid, recursive=recursive)
            if first:
                return entry
            return [entry] if entry else []

        results = self._root_group.find_entries(
            title=title,
            username=username,
            password=password,
            url=url,
            notes=notes,
            otp=otp,
            tags=tags,
            string=string,
            autotype_enabled=autotype_enabled,
            autotype_sequence=autotype_sequence,
            autotype_window=autotype_window,
            recursive=recursive,
            history=history,
        )

        if first:
            return results[0] if results else None
        return results

    def _find_entry_by_path(self, path: list[str] | str) -> list[Entry]:
        """Find entry by path.

        Args:
            path: Path as list ['group1', 'group2', 'entry_title'] or
                string 'group1/group2/entry_title'

        Returns:
            List containing matching entry, or empty list if not found
        """
        if isinstance(path, str):
            path = [p for p in path.split("/") if p]

        if not path:
            return []

        # Last element is entry title, rest are group names
        entry_title = path[-1]
        group_path = path[:-1]

        # Navigate to target group
        current = self._root_group
        for group_name in group_path:
            found = None
            for subgroup in current.subgroups:
                if subgroup.name == group_name:
                    found = subgroup
                    break
            if found is None:
                return []
            current = found

        # Find entry in target group (non-recursive)
        for entry in current.entries:
            if entry.title == entry_title:
                return [entry]

        return []

    def find_groups(
        self,
        name: str | None = None,
        uuid: uuid_module.UUID | None = None,
        path: list[str] | str | None = None,
        recursive: bool = True,
        first: bool = False,
    ) -> list[Group] | Group | None:
        """Find groups matching criteria.

        Args:
            name: Match groups with this name
            uuid: Match group with this UUID
            path: Path to group as list of group names or as a '/'-separated
                string. When specified, other criteria are ignored.
            recursive: Search in nested subgroups
            first: If True, return first matching group or None instead of list

        Returns:
            List of matching groups, or single Group/None if first=True
        """
        # Path-based search
        if path is not None:
            results = self._find_group_by_path(path)
            if first:
                return results[0] if results else None
            return results

        if uuid is not None:
            group = self._root_group.find_group_by_uuid(uuid, recursive=recursive)
            if first:
                return group
            return [group] if group else []

        # find_groups with first=False always returns list
        group_results = cast(
            list[Group],
            self._root_group.find_groups(name=name, recursive=recursive),
        )
        if first:
            return group_results[0] if group_results else None
        return group_results

    def _find_group_by_path(self, path: list[str] | str) -> list[Group]:
        """Find group by path.

        Args:
            path: Path as list ['group1', 'group2'] or string 'group1/group2'

        Returns:
            List containing matching group, or empty list if not found
        """
        if isinstance(path, str):
            path = [p for p in path.split("/") if p]

        if not path:
            return [self._root_group]

        # Navigate through path
        current = self._root_group
        for group_name in path:
            found = None
            for subgroup in current.subgroups:
                if subgroup.name == group_name:
                    found = subgroup
                    break
            if found is None:
                return []
            current = found

        return [current]

    def find_entries_contains(
        self,
        title: str | None = None,
        username: str | None = None,
        password: str | None = None,
        url: str | None = None,
        notes: str | None = None,
        otp: str | None = None,
        recursive: bool = True,
        case_sensitive: bool = False,
        history: bool = False,
    ) -> list[Entry]:
        """Find entries where fields contain the given substrings.

        All criteria are combined with AND logic. None means "any value".

        Args:
            title: Match entries whose title contains this substring
            username: Match entries whose username contains this substring
            password: Match entries whose password contains this substring
            url: Match entries whose URL contains this substring
            notes: Match entries whose notes contain this substring
            otp: Match entries whose OTP contains this substring
            recursive: Search in subgroups
            case_sensitive: If False (default), matching is case-insensitive
            history: Include history entries in search

        Returns:
            List of matching entries
        """
        return self._root_group.find_entries_contains(
            title=title,
            username=username,
            password=password,
            url=url,
            notes=notes,
            otp=otp,
            recursive=recursive,
            case_sensitive=case_sensitive,
            history=history,
        )

    def find_entries_regex(
        self,
        title: str | None = None,
        username: str | None = None,
        password: str | None = None,
        url: str | None = None,
        notes: str | None = None,
        otp: str | None = None,
        recursive: bool = True,
        case_sensitive: bool = False,
        history: bool = False,
    ) -> list[Entry]:
        """Find entries where fields match the given regex patterns.

        All criteria are combined with AND logic. None means "any value".

        Args:
            title: Regex pattern to match against title
            username: Regex pattern to match against username
            password: Regex pattern to match against password
            url: Regex pattern to match against URL
            notes: Regex pattern to match against notes
            otp: Regex pattern to match against OTP
            recursive: Search in subgroups
            case_sensitive: If False (default), matching is case-insensitive
            history: Include history entries in search

        Returns:
            List of matching entries

        Raises:
            re.error: If any pattern is not a valid regex
        """
        return self._root_group.find_entries_regex(
            title=title,
            username=username,
            password=password,
            url=url,
            notes=notes,
            otp=otp,
            recursive=recursive,
            case_sensitive=case_sensitive,
            history=history,
        )

    def find_attachments(
        self,
        id: int | None = None,
        filename: str | None = None,
        regex: bool = False,
        recursive: bool = True,
        history: bool = False,
        first: bool = False,
    ) -> list[Attachment] | Attachment | None:
        """Find attachments in the database.

        Args:
            id: Match attachments with this binary reference ID
            filename: Match attachments with this filename (exact or regex)
            regex: If True, treat filename as a regex pattern
            recursive: Search in subgroups
            history: Include history entries in search
            first: If True, return first match or None. If False, return list.

        Returns:
            If first=True: Attachment or None
            If first=False: List of matching attachments
        """
        import re as re_module

        results: list[Attachment] = []
        pattern: re_module.Pattern[str] | None = None

        if regex and filename is not None:
            pattern = re_module.compile(filename)

        for entry in self._root_group.iter_entries(recursive=recursive, history=history):
            for binary_ref in entry.binaries:
                # Check ID filter
                if id is not None and binary_ref.ref != id:
                    continue

                # Check filename filter
                if filename is not None:
                    if regex and pattern is not None:
                        if not pattern.search(binary_ref.key):
                            continue
                    elif binary_ref.key != filename:
                        continue

                attachment = Attachment(
                    filename=binary_ref.key,
                    id=binary_ref.ref,
                    entry=entry,
                )
                results.append(attachment)

                if first:
                    return attachment

        if first:
            return None
        return results

    @property
    def attachments(self) -> list[Attachment]:
        """Get all attachments in the database."""
        result = self.find_attachments(filename=".*", regex=True)
        # find_attachments returns list when first=False (default)
        return result if isinstance(result, list) else []

    def iter_entries(self, recursive: bool = True) -> Iterator[Entry]:
        """Iterate over all entries in the database.

        Args:
            recursive: Include entries from all subgroups

        Yields:
            Entry objects
        """
        yield from self._root_group.iter_entries(recursive=recursive)

    def iter_groups(self, recursive: bool = True) -> Iterator[Group]:
        """Iterate over all groups in the database.

        Args:
            recursive: Include nested subgroups

        Yields:
            Group objects
        """
        yield from self._root_group.iter_groups(recursive=recursive)

    # --- Field References ---

    def deref(self, value: str | None) -> str | uuid_module.UUID | None:
        """Resolve KeePass field references in a value.

        Parses field references in the format {REF:X@Y:Z} and replaces them
        with the actual values from the referenced entries:
        - X = Field to retrieve (T=Title, U=Username, P=Password, A=URL, N=Notes, I=UUID)
        - Y = Field to search by (T, U, P, A, N, I)
        - Z = Search value

        References are resolved recursively, so a reference that resolves to
        another reference will continue resolving until a final value is found.

        Args:
            value: String potentially containing field references

        Returns:
            - The resolved string with all references replaced
            - A UUID if the final result is a UUID reference
            - None if any referenced entry cannot be found
            - The original value if it contains no references or is None

        Example:
            >>> # Entry with password = '{REF:P@I:ABCD1234...}'
            >>> db.deref(entry.password)  # Returns the referenced password
            >>>
            >>> # With prefix/suffix: 'prefix{REF:U@I:...}suffix'
            >>> db.deref(value)  # Returns 'prefix<username>suffix'
        """
        import re

        if not value:
            return value

        # Pattern matches {REF:X@Y:Z} where X and Y are field codes, Z is search value
        pattern = r"(\{REF:([TUPANI])@([TUPANI]):([^}]+)\})"
        references = set(re.findall(pattern, value))

        if not references:
            return value

        field_to_attr = {
            "T": "title",
            "U": "username",
            "P": "password",
            "A": "url",
            "N": "notes",
            "I": "uuid",
        }

        for ref_str, wanted_field, search_field, search_value in references:
            wanted_attr = field_to_attr[wanted_field]
            search_attr = field_to_attr[search_field]

            # Convert UUID search value to proper UUID object
            if search_attr == "uuid":
                try:
                    search_value = uuid_module.UUID(search_value)
                except ValueError:
                    return None

            # Find the referenced entry
            ref_entry = self.find_entries(first=True, **{search_attr: search_value})
            if ref_entry is None:
                return None

            # Get the wanted field value
            resolved_value = getattr(ref_entry, wanted_attr)
            if resolved_value is None:
                resolved_value = ""

            # UUID needs special handling - convert to string for replacement
            if isinstance(resolved_value, uuid_module.UUID):
                resolved_value = str(resolved_value)

            value = value.replace(ref_str, resolved_value)

        # Recursively resolve any nested references
        return self.deref(value)

    # --- Move operations ---

    def move_entry(self, entry: Entry, destination: Group) -> None:
        """Move an entry to a different group.

        This is a convenience method that calls entry.move_to(). It validates
        that both the entry and destination belong to this database.

        Args:
            entry: Entry to move
            destination: Target group to move the entry to

        Raises:
            ValueError: If entry or destination is not in this database
            ValueError: If entry has no parent
            ValueError: If destination is the current parent
        """
        # Validate entry is in this database
        if entry.parent is None:
            raise ValueError("Entry has no parent group")
        found = self._root_group.find_entry_by_uuid(entry.uuid)
        if found is None:
            raise ValueError("Entry is not in this database")

        # Validate destination is in this database
        if destination is not self._root_group:
            found_group = self._root_group.find_group_by_uuid(destination.uuid)
            if found_group is None:
                raise ValueError("Destination group is not in this database")

        entry.move_to(destination)

    def move_group(self, group: Group, destination: Group) -> None:
        """Move a group to a different parent group.

        This is a convenience method that calls group.move_to(). It validates
        that both the group and destination belong to this database.

        Args:
            group: Group to move
            destination: Target parent group to move the group to

        Raises:
            ValueError: If group or destination is not in this database
            ValueError: If group is the root group
            ValueError: If group has no parent
            ValueError: If destination is the current parent
            ValueError: If destination is the group itself or a descendant
        """
        # Validate group is in this database (and not root)
        if group.is_root_group:
            raise ValueError("Cannot move the root group")
        if group.parent is None:
            raise ValueError("Group has no parent")
        found = self._root_group.find_group_by_uuid(group.uuid)
        if found is None:
            raise ValueError("Group is not in this database")

        # Validate destination is in this database
        if destination is not self._root_group:
            found_dest = self._root_group.find_group_by_uuid(destination.uuid)
            if found_dest is None:
                raise ValueError("Destination group is not in this database")

        group.move_to(destination)

    # --- Recycle bin operations ---

    @property
    def recyclebin_group(self) -> Group | None:
        """Get the recycle bin group, or None if disabled.

        If recycle_bin_enabled is True but no recycle bin exists yet,
        this creates one automatically.

        Returns:
            Recycle bin Group, or None if recycle bin is disabled
        """
        if not self._settings.recycle_bin_enabled:
            return None

        # Try to find existing recycle bin
        if self._settings.recycle_bin_uuid is not None:
            group = self._root_group.find_group_by_uuid(self._settings.recycle_bin_uuid)
            if group is not None:
                return group

        # Create new recycle bin
        recycle_bin = Group(name="Recycle Bin", icon_id="43")
        self._root_group.add_subgroup(recycle_bin)
        self._settings.recycle_bin_uuid = recycle_bin.uuid
        return recycle_bin

    def trash_entry(self, entry: Entry) -> None:
        """Move an entry to the recycle bin.

        If the entry is already in the recycle bin, it is permanently deleted.

        Args:
            entry: Entry to trash

        Raises:
            ValueError: If entry is not in this database
            ValueError: If recycle bin is disabled
        """
        # Validate entry is in this database
        if entry.parent is None:
            raise ValueError("Entry has no parent group")
        found = self._root_group.find_entry_by_uuid(entry.uuid)
        if found is None:
            raise ValueError("Entry is not in this database")

        recycle_bin = self.recyclebin_group
        if recycle_bin is None:
            raise ValueError("Recycle bin is disabled")

        # If already in recycle bin, delete permanently
        if entry.parent is recycle_bin:
            recycle_bin.remove_entry(entry)
            return

        # Move to recycle bin
        entry.move_to(recycle_bin)

    def trash_group(self, group: Group) -> None:
        """Move a group to the recycle bin.

        If the group is already in the recycle bin, it is permanently deleted.
        Cannot trash the root group or the recycle bin itself.

        Args:
            group: Group to trash

        Raises:
            ValueError: If group is not in this database
            ValueError: If group is the root group
            ValueError: If group is the recycle bin
            ValueError: If recycle bin is disabled
        """
        # Validate group
        if group.is_root_group:
            raise ValueError("Cannot trash the root group")
        if group.parent is None:
            raise ValueError("Group has no parent")
        found = self._root_group.find_group_by_uuid(group.uuid)
        if found is None:
            raise ValueError("Group is not in this database")

        recycle_bin = self.recyclebin_group
        if recycle_bin is None:
            raise ValueError("Recycle bin is disabled")

        # Cannot trash the recycle bin itself
        if group is recycle_bin:
            raise ValueError("Cannot trash the recycle bin")

        # If already in recycle bin, delete permanently
        if group.parent is recycle_bin:
            recycle_bin.remove_subgroup(group)
            return

        # Move to recycle bin
        group.move_to(recycle_bin)

    def empty_group(self, group: Group) -> None:
        """Delete all entries and subgroups from a group.

        This permanently deletes all contents (does not use recycle bin).
        The group itself is not deleted.

        Args:
            group: Group to empty

        Raises:
            ValueError: If group is not in this database
        """
        # Validate group is in this database
        if group is not self._root_group:
            found = self._root_group.find_group_by_uuid(group.uuid)
            if found is None:
                raise ValueError("Group is not in this database")

        # Delete all subgroups (iterate over copy since we're modifying)
        for subgroup in list(group.subgroups):
            group.remove_subgroup(subgroup)

        # Delete all entries
        for entry in list(group.entries):
            group.remove_entry(entry)

    # --- Memory protection ---

    def apply_protection_policy(self, entry: Entry) -> None:
        """Apply the database's memory protection policy to an entry.

        Updates the `protected` flag on the entry's string fields
        according to the database's memory_protection settings.

        This is automatically applied when saving the database, but
        can be called manually if you need protection applied immediately
        for in-memory operations.

        Args:
            entry: Entry to apply policy to
        """
        for key, string_field in entry.strings.items():
            if key in self._settings.memory_protection:
                string_field.protected = self._settings.memory_protection[key]

    def apply_protection_policy_all(self) -> None:
        """Apply memory protection policy to all entries in the database.

        Updates all entries' string field protection flags according
        to the database's memory_protection settings.
        """
        for entry in self.iter_entries():
            self.apply_protection_policy(entry)

    # --- Binary attachments ---

    def get_binary(self, ref: int) -> bytes | None:
        """Get binary attachment data by reference ID.

        Args:
            ref: Binary reference ID

        Returns:
            Binary data or None if not found
        """
        return self._binaries.get(ref)

    def add_binary(self, data: bytes, protected: bool = True) -> int:
        """Add a new binary attachment to the database.

        Args:
            data: Binary data
            protected: Whether the binary should be memory-protected

        Returns:
            Reference ID for the new binary
        """
        # Find next available index
        ref = max(self._binaries.keys(), default=-1) + 1
        self._binaries[ref] = data
        # Update inner header
        if self._inner_header is not None:
            self._inner_header.binaries[ref] = (protected, data)
        return ref

    def remove_binary(self, ref: int) -> bool:
        """Remove a binary attachment from the database.

        Args:
            ref: Binary reference ID

        Returns:
            True if removed, False if not found
        """
        if ref in self._binaries:
            del self._binaries[ref]
            if self._inner_header is not None and ref in self._inner_header.binaries:
                del self._inner_header.binaries[ref]
            return True
        return False

    def get_attachment(self, entry: Entry, name: str) -> bytes | None:
        """Get an attachment from an entry by filename.

        Args:
            entry: Entry to get attachment from
            name: Filename of the attachment

        Returns:
            Attachment data or None if not found
        """
        for binary_ref in entry.binaries:
            if binary_ref.key == name:
                return self._binaries.get(binary_ref.ref)
        return None

    def add_attachment(self, entry: Entry, name: str, data: bytes, protected: bool = True) -> None:
        """Add an attachment to an entry.

        Args:
            entry: Entry to add attachment to
            name: Filename for the attachment
            data: Attachment data
            protected: Whether the attachment should be memory-protected
        """
        ref = self.add_binary(data, protected=protected)
        entry.binaries.append(BinaryRef(key=name, ref=ref))

    def remove_attachment(self, entry: Entry, name: str) -> bool:
        """Remove an attachment from an entry by filename.

        Args:
            entry: Entry to remove attachment from
            name: Filename of the attachment

        Returns:
            True if removed, False if not found
        """
        for i, binary_ref in enumerate(entry.binaries):
            if binary_ref.key == name:
                # Remove from entry's list
                entry.binaries.pop(i)
                # Note: We don't remove from _binaries as other entries may reference it
                return True
        return False

    def list_attachments(self, entry: Entry) -> list[str]:
        """List all attachment filenames for an entry.

        Args:
            entry: Entry to list attachments for

        Returns:
            List of attachment filenames
        """
        return [binary_ref.key for binary_ref in entry.binaries]

    # --- Custom icons ---

    @property
    def custom_icons(self) -> dict[uuid_module.UUID, CustomIcon]:
        """Get dictionary of custom icons (UUID -> CustomIcon)."""
        return self._settings.custom_icons

    def get_custom_icon(self, uuid: uuid_module.UUID) -> bytes | None:
        """Get custom icon data by UUID.

        Args:
            uuid: UUID of the custom icon

        Returns:
            PNG image data, or None if not found
        """
        icon = self._settings.custom_icons.get(uuid)
        return icon.data if icon else None

    def add_custom_icon(self, data: bytes, name: str | None = None) -> uuid_module.UUID:
        """Add a custom icon to the database.

        Args:
            data: PNG image data
            name: Optional display name for the icon

        Returns:
            UUID of the new custom icon
        """
        icon_uuid = uuid_module.uuid4()
        icon = CustomIcon(
            uuid=icon_uuid,
            data=data,
            name=name,
            last_modification_time=datetime.now(UTC),
        )
        self._settings.custom_icons[icon_uuid] = icon
        return icon_uuid

    def remove_custom_icon(self, uuid: uuid_module.UUID) -> bool:
        """Remove a custom icon from the database.

        Note: This does not update entries/groups that reference this icon.
        They will continue to reference the now-missing UUID.

        Args:
            uuid: UUID of the custom icon to remove

        Returns:
            True if removed, False if not found
        """
        if uuid in self._settings.custom_icons:
            del self._settings.custom_icons[uuid]
            return True
        return False

    def find_custom_icon_by_name(self, name: str) -> uuid_module.UUID | None:
        """Find a custom icon by name.

        Args:
            name: Name of the icon to find (must match exactly one icon)

        Returns:
            UUID of the matching icon, or None if not found

        Raises:
            ValueError: If multiple icons have the same name
        """
        matches = [icon.uuid for icon in self._settings.custom_icons.values() if icon.name == name]
        if len(matches) == 0:
            return None
        if len(matches) > 1:
            raise ValueError(f"Multiple custom icons found with name: {name}")
        return matches[0]

    # --- XML parsing ---

    @classmethod
    def _parse_xml(
        cls, xml_data: bytes, inner_header: InnerHeader | None = None
    ) -> tuple[Group, DatabaseSettings, dict[int, bytes]]:
        """Parse KDBX XML into models.

        Args:
            xml_data: XML payload bytes
            inner_header: Inner header with stream cipher info (for decrypting protected values)

        Returns:
            Tuple of (root_group, settings, binaries)
        """
        root = DefusedET.fromstring(xml_data)

        # Decrypt protected values in-place before parsing
        if inner_header is not None:
            cls._decrypt_protected_values(root, inner_header)

        # Parse Meta section for settings
        settings = cls._parse_meta(root.find("Meta"))

        # Parse Root/Group for entries
        root_elem = root.find("Root")
        if root_elem is None:
            raise InvalidXmlError("Missing Root element")

        group_elem = root_elem.find("Group")
        if group_elem is None:
            raise InvalidXmlError("Missing root Group element")

        root_group = cls._parse_group(group_elem)
        root_group._is_root = True

        # Extract binaries from inner header (KDBX4 style)
        # The protection flag indicates memory protection policy, not encryption
        binaries: dict[int, bytes] = {}
        if inner_header is not None:
            for idx, (_protected, data) in inner_header.binaries.items():
                binaries[idx] = data

        return root_group, settings, binaries

    @classmethod
    def _decrypt_protected_values(cls, root: Element, inner_header: InnerHeader) -> None:
        """Decrypt all protected values in the XML tree in document order.

        Protected values are XOR'd with a stream cipher and base64 encoded.
        This method decrypts them in-place.
        """
        cipher = ProtectedStreamCipher(
            inner_header.random_stream_id,
            inner_header.random_stream_key,
        )

        # Find all Value elements with Protected="True" in document order
        for elem in root.iter("Value"):
            if elem.get("Protected") == "True" and elem.text:
                try:
                    ciphertext = base64.b64decode(elem.text)
                    plaintext = cipher.decrypt(ciphertext)
                    elem.text = plaintext.decode("utf-8")
                except (binascii.Error, ValueError, UnicodeDecodeError):
                    # If decryption fails, leave as-is
                    pass

    @classmethod
    def _parse_meta(cls, meta_elem: Element | None) -> DatabaseSettings:
        """Parse Meta element into DatabaseSettings."""
        settings = DatabaseSettings()

        if meta_elem is None:
            return settings

        def get_text(tag: str) -> str | None:
            elem = meta_elem.find(tag)
            return elem.text if elem is not None else None

        if name := get_text("DatabaseName"):
            settings.database_name = name
        if desc := get_text("DatabaseDescription"):
            settings.database_description = desc
        if username := get_text("DefaultUserName"):
            settings.default_username = username
        if gen := get_text("Generator"):
            settings.generator = gen

        # Parse memory protection
        mp_elem = meta_elem.find("MemoryProtection")
        if mp_elem is not None:
            for field in ["Title", "UserName", "Password", "URL", "Notes"]:
                elem = mp_elem.find(f"Protect{field}")
                if elem is not None:
                    settings.memory_protection[field] = elem.text == "True"

        # Parse recycle bin
        if rb := get_text("RecycleBinEnabled"):
            settings.recycle_bin_enabled = rb == "True"
        if rb_uuid := get_text("RecycleBinUUID"):
            import contextlib

            with contextlib.suppress(binascii.Error, ValueError):
                settings.recycle_bin_uuid = uuid_module.UUID(bytes=base64.b64decode(rb_uuid))

        # Parse custom icons
        custom_icons_elem = meta_elem.find("CustomIcons")
        if custom_icons_elem is not None:
            for icon_elem in custom_icons_elem.findall("Icon"):
                icon_uuid_elem = icon_elem.find("UUID")
                icon_data_elem = icon_elem.find("Data")
                if (
                    icon_uuid_elem is not None
                    and icon_uuid_elem.text
                    and icon_data_elem is not None
                    and icon_data_elem.text
                ):
                    try:
                        icon_uuid = uuid_module.UUID(bytes=base64.b64decode(icon_uuid_elem.text))
                        icon_data = base64.b64decode(icon_data_elem.text)
                        icon_name = None
                        name_elem = icon_elem.find("Name")
                        if name_elem is not None:
                            icon_name = name_elem.text
                        icon_mtime = None
                        mtime_elem = icon_elem.find("LastModificationTime")
                        if mtime_elem is not None and mtime_elem.text:
                            icon_mtime = cls._decode_time(mtime_elem.text)
                        settings.custom_icons[icon_uuid] = CustomIcon(
                            uuid=icon_uuid,
                            data=icon_data,
                            name=icon_name,
                            last_modification_time=icon_mtime,
                        )
                    except (binascii.Error, ValueError):
                        pass  # Skip invalid icon

        return settings

    @classmethod
    def _parse_group(cls, elem: Element) -> Group:
        """Parse a Group element into a Group model."""
        group = Group()

        # UUID
        uuid_elem = elem.find("UUID")
        if uuid_elem is not None and uuid_elem.text:
            group.uuid = uuid_module.UUID(bytes=base64.b64decode(uuid_elem.text))

        # Name
        name_elem = elem.find("Name")
        if name_elem is not None:
            group.name = name_elem.text

        # Notes
        notes_elem = elem.find("Notes")
        if notes_elem is not None:
            group.notes = notes_elem.text

        # Icon
        icon_elem = elem.find("IconID")
        if icon_elem is not None and icon_elem.text:
            group.icon_id = icon_elem.text

        # Custom icon UUID
        custom_icon_elem = elem.find("CustomIconUUID")
        if custom_icon_elem is not None and custom_icon_elem.text:
            with contextlib.suppress(binascii.Error, ValueError):
                group.custom_icon_uuid = uuid_module.UUID(
                    bytes=base64.b64decode(custom_icon_elem.text)
                )

        # Times
        group.times = cls._parse_times(elem.find("Times"))

        # Entries
        for entry_elem in elem.findall("Entry"):
            entry = cls._parse_entry(entry_elem)
            group.add_entry(entry)

        # Subgroups (recursive)
        for subgroup_elem in elem.findall("Group"):
            subgroup = cls._parse_group(subgroup_elem)
            group.add_subgroup(subgroup)

        return group

    @classmethod
    def _parse_entry(cls, elem: Element) -> Entry:
        """Parse an Entry element into an Entry model."""
        entry = Entry()

        # UUID
        uuid_elem = elem.find("UUID")
        if uuid_elem is not None and uuid_elem.text:
            entry.uuid = uuid_module.UUID(bytes=base64.b64decode(uuid_elem.text))

        # Icon
        icon_elem = elem.find("IconID")
        if icon_elem is not None and icon_elem.text:
            entry.icon_id = icon_elem.text

        # Custom icon UUID
        custom_icon_elem = elem.find("CustomIconUUID")
        if custom_icon_elem is not None and custom_icon_elem.text:
            with contextlib.suppress(binascii.Error, ValueError):
                entry.custom_icon_uuid = uuid_module.UUID(
                    bytes=base64.b64decode(custom_icon_elem.text)
                )

        # Tags
        tags_elem = elem.find("Tags")
        if tags_elem is not None and tags_elem.text:
            tag_text = tags_elem.text.replace(",", ";")
            entry.tags = [t.strip() for t in tag_text.split(";") if t.strip()]

        # Times
        entry.times = cls._parse_times(elem.find("Times"))

        # String fields
        for string_elem in elem.findall("String"):
            key_elem = string_elem.find("Key")
            value_elem = string_elem.find("Value")
            if key_elem is not None and key_elem.text:
                key = key_elem.text
                value = value_elem.text if value_elem is not None else None
                protected = value_elem is not None and value_elem.get("Protected") == "True"
                entry.strings[key] = StringField(key=key, value=value, protected=protected)

        # Binary references
        for binary_elem in elem.findall("Binary"):
            key_elem = binary_elem.find("Key")
            value_elem = binary_elem.find("Value")
            if key_elem is not None and key_elem.text and value_elem is not None:
                ref = value_elem.get("Ref")
                if ref is not None:
                    entry.binaries.append(BinaryRef(key=key_elem.text, ref=int(ref)))

        # AutoType
        at_elem = elem.find("AutoType")
        if at_elem is not None:
            enabled_elem = at_elem.find("Enabled")
            seq_elem = at_elem.find("DefaultSequence")
            obf_elem = at_elem.find("DataTransferObfuscation")

            entry.autotype = AutoType(
                enabled=enabled_elem is not None and enabled_elem.text == "True",
                sequence=seq_elem.text if seq_elem is not None else None,
                obfuscation=int(obf_elem.text) if obf_elem is not None and obf_elem.text else 0,
            )

            # Window from Association
            assoc_elem = at_elem.find("Association")
            if assoc_elem is not None:
                window_elem = assoc_elem.find("Window")
                if window_elem is not None:
                    entry.autotype.window = window_elem.text

        # History
        history_elem = elem.find("History")
        if history_elem is not None:
            for hist_entry_elem in history_elem.findall("Entry"):
                hist_entry = cls._parse_entry(hist_entry_elem)
                history_entry = HistoryEntry.from_entry(hist_entry)
                entry.history.append(history_entry)

        return entry

    @classmethod
    def _parse_times(cls, times_elem: Element | None) -> Times:
        """Parse Times element into Times model."""
        times = Times.create_new()

        if times_elem is None:
            return times

        def parse_time(tag: str) -> datetime | None:
            elem = times_elem.find(tag)
            if elem is not None and elem.text:
                return cls._decode_time(elem.text)
            return None

        if ct := parse_time("CreationTime"):
            times.creation_time = ct
        if mt := parse_time("LastModificationTime"):
            times.last_modification_time = mt
        if at := parse_time("LastAccessTime"):
            times.last_access_time = at
        if et := parse_time("ExpiryTime"):
            times.expiry_time = et
        if lc := parse_time("LocationChanged"):
            times.location_changed = lc

        expires_elem = times_elem.find("Expires")
        if expires_elem is not None:
            times.expires = expires_elem.text == "True"

        usage_elem = times_elem.find("UsageCount")
        if usage_elem is not None and usage_elem.text:
            times.usage_count = int(usage_elem.text)

        return times

    @classmethod
    def _decode_time(cls, time_str: str) -> datetime:
        """Decode KDBX time string to datetime.

        KDBX4 uses base64-encoded binary timestamps or ISO format.
        """
        # Try base64 binary format first (KDBX4)
        # Base64 strings don't contain - or : which are present in ISO dates
        if "-" not in time_str and ":" not in time_str:
            try:
                binary = base64.b64decode(time_str)
                if len(binary) == 8:  # int64 = 8 bytes
                    # KDBX4 stores seconds since 0001-01-01 as int64
                    import struct

                    seconds = struct.unpack("<q", binary)[0]
                    # Convert to datetime (epoch is 0001-01-01)
                    base = datetime(1, 1, 1, tzinfo=UTC)
                    return base + timedelta(seconds=seconds)
            except (ValueError, struct.error):
                pass  # Not valid base64 or wrong size

        # Try ISO format
        try:
            return datetime.strptime(time_str, KDBX4_TIME_FORMAT).replace(tzinfo=UTC)
        except ValueError:
            pass

        # Fallback: try without timezone
        try:
            return datetime.fromisoformat(time_str.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(UTC)

    @classmethod
    def _encode_time(cls, dt: datetime) -> str:
        """Encode datetime to ISO 8601 format for KDBX4.

        Uses ISO 8601 format (e.g., 2025-01-15T10:30:45Z) which is
        human-readable and compatible with KeePassXC.
        """
        # Ensure UTC timezone
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.strftime(KDBX4_TIME_FORMAT)

    # --- XML building ---

    def _build_xml(self) -> bytes:
        """Build KDBX XML from models."""
        root = Element("KeePassFile")

        # Meta section
        meta = SubElement(root, "Meta")
        self._build_meta(meta)

        # Root section
        root_elem = SubElement(root, "Root")
        self._build_group(root_elem, self._root_group)

        # Encrypt protected values before serializing
        if self._inner_header is not None:
            self._encrypt_protected_values(root, self._inner_header)

        # Serialize to bytes (tostring returns bytes when encoding is specified)
        return cast(bytes, tostring(root, encoding="utf-8", xml_declaration=True))

    def _encrypt_protected_values(self, root: Element, inner_header: InnerHeader) -> None:
        """Encrypt all protected values in the XML tree in document order.

        Protected values are XOR'd with a stream cipher and base64 encoded.
        This method encrypts them in-place.
        """
        cipher = ProtectedStreamCipher(
            inner_header.random_stream_id,
            inner_header.random_stream_key,
        )

        # Find all Value elements with Protected="True" in document order
        for elem in root.iter("Value"):
            if elem.get("Protected") == "True":
                plaintext = (elem.text or "").encode("utf-8")
                ciphertext = cipher.encrypt(plaintext)
                elem.text = base64.b64encode(ciphertext).decode("ascii")

    def _build_meta(self, meta: Element) -> None:
        """Build Meta element from settings."""
        s = self._settings

        SubElement(meta, "Generator").text = s.generator
        SubElement(meta, "DatabaseName").text = s.database_name
        if s.database_description:
            SubElement(meta, "DatabaseDescription").text = s.database_description
        if s.default_username:
            SubElement(meta, "DefaultUserName").text = s.default_username

        SubElement(meta, "MaintenanceHistoryDays").text = str(s.maintenance_history_days)
        SubElement(meta, "MasterKeyChangeRec").text = str(s.master_key_change_rec)
        SubElement(meta, "MasterKeyChangeForce").text = str(s.master_key_change_force)

        # Memory protection
        mp = SubElement(meta, "MemoryProtection")
        for field_name, is_protected in s.memory_protection.items():
            SubElement(mp, f"Protect{field_name}").text = str(is_protected)

        SubElement(meta, "RecycleBinEnabled").text = str(s.recycle_bin_enabled)
        if s.recycle_bin_uuid:
            SubElement(meta, "RecycleBinUUID").text = base64.b64encode(
                s.recycle_bin_uuid.bytes
            ).decode("ascii")
        else:
            # Empty UUID
            SubElement(meta, "RecycleBinUUID").text = base64.b64encode(b"\x00" * 16).decode("ascii")

        SubElement(meta, "HistoryMaxItems").text = str(s.history_max_items)
        SubElement(meta, "HistoryMaxSize").text = str(s.history_max_size)

        # Custom icons
        if s.custom_icons:
            custom_icons_elem = SubElement(meta, "CustomIcons")
            for icon in s.custom_icons.values():
                icon_elem = SubElement(custom_icons_elem, "Icon")
                SubElement(icon_elem, "UUID").text = base64.b64encode(icon.uuid.bytes).decode(
                    "ascii"
                )
                SubElement(icon_elem, "Data").text = base64.b64encode(icon.data).decode("ascii")
                if icon.name:
                    SubElement(icon_elem, "Name").text = icon.name
                if icon.last_modification_time:
                    SubElement(icon_elem, "LastModificationTime").text = self._encode_time(
                        icon.last_modification_time
                    )

    def _build_group(self, parent: Element, group: Group) -> None:
        """Build Group element from Group model."""
        elem = SubElement(parent, "Group")

        SubElement(elem, "UUID").text = base64.b64encode(group.uuid.bytes).decode("ascii")
        SubElement(elem, "Name").text = group.name or ""
        if group.notes:
            SubElement(elem, "Notes").text = group.notes
        SubElement(elem, "IconID").text = group.icon_id
        if group.custom_icon_uuid:
            SubElement(elem, "CustomIconUUID").text = base64.b64encode(
                group.custom_icon_uuid.bytes
            ).decode("ascii")

        self._build_times(elem, group.times)

        SubElement(elem, "IsExpanded").text = str(group.is_expanded)

        if group.default_autotype_sequence:
            SubElement(elem, "DefaultAutoTypeSequence").text = group.default_autotype_sequence
        if group.enable_autotype is not None:
            SubElement(elem, "EnableAutoType").text = str(group.enable_autotype)
        if group.enable_searching is not None:
            SubElement(elem, "EnableSearching").text = str(group.enable_searching)

        SubElement(elem, "LastTopVisibleEntry").text = base64.b64encode(
            (group.last_top_visible_entry or uuid_module.UUID(int=0)).bytes
        ).decode("ascii")

        # Entries
        for entry in group.entries:
            self._build_entry(elem, entry)

        # Subgroups (recursive)
        for subgroup in group.subgroups:
            self._build_group(elem, subgroup)

    def _build_entry(self, parent: Element, entry: Entry) -> None:
        """Build Entry element from Entry model."""
        elem = SubElement(parent, "Entry")

        SubElement(elem, "UUID").text = base64.b64encode(entry.uuid.bytes).decode("ascii")
        SubElement(elem, "IconID").text = entry.icon_id
        if entry.custom_icon_uuid:
            SubElement(elem, "CustomIconUUID").text = base64.b64encode(
                entry.custom_icon_uuid.bytes
            ).decode("ascii")

        if entry.foreground_color:
            SubElement(elem, "ForegroundColor").text = entry.foreground_color
        if entry.background_color:
            SubElement(elem, "BackgroundColor").text = entry.background_color
        if entry.override_url:
            SubElement(elem, "OverrideURL").text = entry.override_url

        if entry.tags:
            SubElement(elem, "Tags").text = ";".join(entry.tags)

        self._build_times(elem, entry.times)

        # String fields - apply memory protection policy from database settings
        for key, string_field in entry.strings.items():
            string_elem = SubElement(elem, "String")
            SubElement(string_elem, "Key").text = key
            value_elem = SubElement(string_elem, "Value")
            value_elem.text = string_field.value or ""
            # Use database memory_protection policy for standard fields,
            # fall back to string_field.protected for custom fields
            if key in self._settings.memory_protection:
                should_protect = self._settings.memory_protection[key]
            else:
                should_protect = string_field.protected
            if should_protect:
                value_elem.set("Protected", "True")

        # Binary references
        for binary_ref in entry.binaries:
            binary_elem = SubElement(elem, "Binary")
            SubElement(binary_elem, "Key").text = binary_ref.key
            value_elem = SubElement(binary_elem, "Value")
            value_elem.set("Ref", str(binary_ref.ref))

        # AutoType
        at = entry.autotype
        at_elem = SubElement(elem, "AutoType")
        SubElement(at_elem, "Enabled").text = str(at.enabled)
        SubElement(at_elem, "DataTransferObfuscation").text = str(at.obfuscation)
        SubElement(at_elem, "DefaultSequence").text = at.sequence or ""

        if at.window:
            assoc = SubElement(at_elem, "Association")
            SubElement(assoc, "Window").text = at.window
            SubElement(assoc, "KeystrokeSequence").text = ""

        # History
        if entry.history:
            history_elem = SubElement(elem, "History")
            for hist_entry in entry.history:
                self._build_entry(history_elem, hist_entry)

    def _build_times(self, parent: Element, times: Times) -> None:
        """Build Times element from Times model."""
        elem = SubElement(parent, "Times")

        SubElement(elem, "CreationTime").text = self._encode_time(times.creation_time)
        SubElement(elem, "LastModificationTime").text = self._encode_time(
            times.last_modification_time
        )
        SubElement(elem, "LastAccessTime").text = self._encode_time(times.last_access_time)
        if times.expiry_time:
            SubElement(elem, "ExpiryTime").text = self._encode_time(times.expiry_time)
        else:
            SubElement(elem, "ExpiryTime").text = self._encode_time(times.creation_time)
        SubElement(elem, "Expires").text = str(times.expires)
        SubElement(elem, "UsageCount").text = str(times.usage_count)
        if times.location_changed:
            SubElement(elem, "LocationChanged").text = self._encode_time(times.location_changed)

    def __str__(self) -> str:
        entry_count = sum(1 for _ in self.iter_entries())
        group_count = sum(1 for _ in self.iter_groups())
        name = self._settings.database_name
        return f'Database: "{name}" ({entry_count} entries, {group_count} groups)'
