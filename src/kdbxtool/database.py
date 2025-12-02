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
import hashlib
import os
import uuid as uuid_module
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import Protocol, cast
from xml.etree.ElementTree import Element, SubElement, tostring

from Cryptodome.Cipher import ChaCha20, Salsa20
from defusedxml import ElementTree as DefusedET

from .models import Entry, Group, HistoryEntry, Times
from .models.entry import AutoType, BinaryRef, StringField
from .parsing import CompressionType, KdbxHeader, KdbxVersion
from .parsing.kdbx4 import InnerHeader, read_kdbx4, write_kdbx4
from .security import Cipher, KdfType


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
            nonce = b'\xE8\x30\x09\x4B\x97\x20\x5D\x2A'
            return Salsa20.new(key=key, nonce=nonce)
        else:
            raise ValueError(f"Unknown protected stream cipher ID: {self._stream_id}")

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt protected value (XOR with stream)."""
        return self._cipher.decrypt(ciphertext)

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt protected value (XOR with stream)."""
        return self._cipher.encrypt(plaintext)


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
        self._filepath: Path | None = None

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
    ) -> Database:
        """Open an existing KDBX database.

        Args:
            filepath: Path to the .kdbx file
            password: Database password
            keyfile: Path to keyfile (optional)

        Returns:
            Database instance

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If credentials are wrong or file is corrupted
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
        )

    @classmethod
    def open_bytes(
        cls,
        data: bytes,
        password: str | None = None,
        keyfile_data: bytes | None = None,
        filepath: Path | None = None,
    ) -> Database:
        """Open a KDBX database from bytes.

        Args:
            data: KDBX file contents
            password: Database password
            keyfile_data: Keyfile contents (optional)
            filepath: Original file path (for save)

        Returns:
            Database instance
        """
        # Decrypt the file
        payload = read_kdbx4(data, password=password, keyfile_data=keyfile_data)

        # Parse XML into models (with protected value decryption)
        root_group, settings, binaries = cls._parse_xml(
            payload.xml_data, payload.inner_header
        )

        db = cls(
            root_group=root_group,
            settings=settings,
            header=payload.header,
            inner_header=payload.inner_header,
            binaries=binaries,
        )
        db._password = password
        db._keyfile_data = keyfile_data
        db._filepath = filepath

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
        kdf_type: KdfType = KdfType.ARGON2ID,
    ) -> Database:
        """Create a new KDBX database.

        Args:
            filepath: Path to save the database (optional)
            password: Database password
            keyfile: Path to keyfile (optional)
            database_name: Name for the database
            cipher: Encryption cipher to use
            kdf_type: KDF type to use

        Returns:
            New Database instance
        """
        if password is None and keyfile is None:
            raise ValueError("At least one of password or keyfile is required")

        keyfile_data = None
        if keyfile:
            keyfile_path = Path(keyfile)
            if not keyfile_path.exists():
                raise FileNotFoundError(f"Keyfile not found: {keyfile}")
            keyfile_data = keyfile_path.read_bytes()

        # Create root group
        root_group = Group.create_root(database_name)

        # Create recycle bin group
        recycle_bin = Group(name="Recycle Bin", icon_id="43")
        root_group.add_subgroup(recycle_bin)

        # Create default header
        header = KdbxHeader(
            version=KdbxVersion.KDBX4,
            cipher=cipher,
            compression=CompressionType.GZIP,
            master_seed=os.urandom(32),
            encryption_iv=os.urandom(cipher.iv_size),
            kdf_type=kdf_type,
            kdf_salt=os.urandom(32),
            argon2_memory_kib=64 * 1024,  # 64 MiB
            argon2_iterations=3,
            argon2_parallelism=4,
        )

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

    def save(self, filepath: str | Path | None = None) -> None:
        """Save the database to a file.

        Args:
            filepath: Path to save to (uses original path if not specified)

        Raises:
            ValueError: If no filepath specified and database wasn't opened from file
        """
        if filepath:
            self._filepath = Path(filepath)
        elif self._filepath is None:
            raise ValueError("No filepath specified and database wasn't opened from file")

        data = self.to_bytes()
        self._filepath.write_bytes(data)

    def to_bytes(self) -> bytes:
        """Serialize the database to KDBX format.

        Returns:
            KDBX file contents as bytes

        Raises:
            ValueError: If no credentials are set
        """
        if self._password is None and self._keyfile_data is None:
            raise ValueError("No credentials set - use set_credentials() first")

        if self._header is None:
            raise ValueError("No header - database not properly initialized")

        if self._inner_header is None:
            raise ValueError("No inner header - database not properly initialized")

        # Regenerate protected stream key to avoid keystream reuse across saves.
        # This prevents theoretical attacks where an attacker compares multiple
        # versions of the encrypted file to XOR plaintexts.
        self._inner_header.random_stream_key = os.urandom(64)

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
        return write_kdbx4(
            header=self._header,
            inner_header=self._inner_header,
            xml_data=xml_data,
            password=self._password,
            keyfile_data=self._keyfile_data,
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
            raise ValueError("At least one of password or keyfile_data is required")
        self._password = password
        self._keyfile_data = keyfile_data

    # --- Search operations ---

    def find_entries(
        self,
        title: str | None = None,
        username: str | None = None,
        url: str | None = None,
        tags: list[str] | None = None,
        uuid: uuid_module.UUID | None = None,
        recursive: bool = True,
    ) -> list[Entry]:
        """Find entries matching criteria.

        Args:
            title: Match entries with this title
            username: Match entries with this username
            url: Match entries with this URL
            tags: Match entries with all these tags
            uuid: Match entry with this UUID
            recursive: Search in subgroups

        Returns:
            List of matching entries
        """
        if uuid is not None:
            entry = self._root_group.find_entry_by_uuid(uuid, recursive=recursive)
            return [entry] if entry else []

        return self._root_group.find_entries(
            title=title,
            username=username,
            url=url,
            tags=tags,
            recursive=recursive,
        )

    def find_groups(
        self,
        name: str | None = None,
        uuid: uuid_module.UUID | None = None,
        recursive: bool = True,
    ) -> list[Group]:
        """Find groups matching criteria.

        Args:
            name: Match groups with this name
            uuid: Match group with this UUID
            recursive: Search in nested subgroups

        Returns:
            List of matching groups
        """
        if uuid is not None:
            group = self._root_group.find_group_by_uuid(uuid, recursive=recursive)
            return [group] if group else []

        return self._root_group.find_groups(name=name, recursive=recursive)

    def find_entries_contains(
        self,
        title: str | None = None,
        username: str | None = None,
        url: str | None = None,
        notes: str | None = None,
        recursive: bool = True,
        case_sensitive: bool = False,
    ) -> list[Entry]:
        """Find entries where fields contain the given substrings.

        All criteria are combined with AND logic. None means "any value".

        Args:
            title: Match entries whose title contains this substring
            username: Match entries whose username contains this substring
            url: Match entries whose URL contains this substring
            notes: Match entries whose notes contain this substring
            recursive: Search in subgroups
            case_sensitive: If False (default), matching is case-insensitive

        Returns:
            List of matching entries
        """
        return self._root_group.find_entries_contains(
            title=title,
            username=username,
            url=url,
            notes=notes,
            recursive=recursive,
            case_sensitive=case_sensitive,
        )

    def find_entries_regex(
        self,
        title: str | None = None,
        username: str | None = None,
        url: str | None = None,
        notes: str | None = None,
        recursive: bool = True,
        case_sensitive: bool = False,
    ) -> list[Entry]:
        """Find entries where fields match the given regex patterns.

        All criteria are combined with AND logic. None means "any value".

        Args:
            title: Regex pattern to match against title
            username: Regex pattern to match against username
            url: Regex pattern to match against URL
            notes: Regex pattern to match against notes
            recursive: Search in subgroups
            case_sensitive: If False (default), matching is case-insensitive

        Returns:
            List of matching entries

        Raises:
            re.error: If any pattern is not a valid regex
        """
        return self._root_group.find_entries_regex(
            title=title,
            username=username,
            url=url,
            notes=notes,
            recursive=recursive,
            case_sensitive=case_sensitive,
        )

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

    def add_attachment(
        self, entry: Entry, name: str, data: bytes, protected: bool = True
    ) -> None:
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
            raise ValueError("Invalid KDBX XML: missing Root element")

        group_elem = root_elem.find("Group")
        if group_elem is None:
            raise ValueError("Invalid KDBX XML: missing root Group element")

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
                settings.recycle_bin_uuid = uuid_module.UUID(
                    bytes=base64.b64decode(rb_uuid)
                )

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
            SubElement(meta, "RecycleBinUUID").text = base64.b64encode(
                b"\x00" * 16
            ).decode("ascii")

        SubElement(meta, "HistoryMaxItems").text = str(s.history_max_items)
        SubElement(meta, "HistoryMaxSize").text = str(s.history_max_size)

    def _build_group(self, parent: Element, group: Group) -> None:
        """Build Group element from Group model."""
        elem = SubElement(parent, "Group")

        SubElement(elem, "UUID").text = base64.b64encode(group.uuid.bytes).decode("ascii")
        SubElement(elem, "Name").text = group.name or ""
        if group.notes:
            SubElement(elem, "Notes").text = group.notes
        SubElement(elem, "IconID").text = group.icon_id

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
