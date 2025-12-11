"""Entry model for KDBX password entries."""

from __future__ import annotations

import uuid as uuid_module
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

from .times import Times

if TYPE_CHECKING:
    from ..database import Database
    from ..security.totp import TotpCode
    from .group import Group


# Fields that have special handling and shouldn't be treated as custom properties
RESERVED_KEYS = frozenset(
    {
        "Title",
        "UserName",
        "Password",
        "URL",
        "Notes",
        "otp",
    }
)


@dataclass
class StringField:
    """A string field in an entry.

    Attributes:
        key: Field name (e.g., "Title", "UserName", "Password")
        value: Field value
        protected: Whether the field should be protected in memory
    """

    key: str
    value: str | None = None
    protected: bool = False


@dataclass
class AutoType:
    """AutoType settings for an entry.

    Attributes:
        enabled: Whether AutoType is enabled for this entry
        sequence: Default keystroke sequence
        window: Window filter for AutoType
        obfuscation: Data transfer obfuscation level (0 = none)
    """

    enabled: bool = True
    sequence: str | None = None
    window: str | None = None
    obfuscation: int = 0


@dataclass
class BinaryRef:
    """Reference to a binary attachment.

    Attributes:
        key: Filename of the attachment
        ref: Reference ID to the binary in the database
    """

    key: str
    ref: int


@dataclass
class Entry:
    """A password entry in a KDBX database.

    Entries store credentials and associated metadata. Each entry has
    standard fields (title, username, password, url, notes) plus support
    for custom string fields and binary attachments.

    Attributes:
        uuid: Unique identifier for the entry
        times: Timestamps (creation, modification, access, expiry)
        icon_id: Icon ID for display (standard icon)
        custom_icon_uuid: UUID of custom icon (overrides icon_id if set)
        tags: List of tags for categorization
        strings: Dictionary of string fields (key -> StringField)
        binaries: List of binary attachment references
        autotype: AutoType settings
        history: List of previous versions of this entry
        foreground_color: Custom foreground color (hex)
        background_color: Custom background color (hex)
        override_url: URL override for AutoType
        quality_check: Whether to check password quality
    """

    uuid: uuid_module.UUID = field(default_factory=uuid_module.uuid4)
    times: Times = field(default_factory=Times.create_new)
    icon_id: str = "0"
    custom_icon_uuid: uuid_module.UUID | None = None
    tags: list[str] = field(default_factory=list)
    strings: dict[str, StringField] = field(default_factory=dict)
    binaries: list[BinaryRef] = field(default_factory=list)
    autotype: AutoType = field(default_factory=AutoType)
    history: list[HistoryEntry] = field(default_factory=list)
    foreground_color: str | None = None
    background_color: str | None = None
    override_url: str | None = None
    quality_check: bool = True

    # Runtime reference to parent group (not serialized)
    _parent: Group | None = field(default=None, repr=False, compare=False)
    # Runtime reference to database (not serialized) - used for icon name resolution
    _database: Database | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Initialize default string fields if not present."""
        for key in ("Title", "UserName", "Password", "URL", "Notes"):
            if key not in self.strings:
                protected = key == "Password"
                self.strings[key] = StringField(key=key, protected=protected)

    # --- Standard field properties ---

    @property
    def title(self) -> str | None:
        """Get or set entry title."""
        return self.strings.get("Title", StringField("Title")).value

    @title.setter
    def title(self, value: str | None) -> None:
        if "Title" not in self.strings:
            self.strings["Title"] = StringField("Title")
        self.strings["Title"].value = value

    @property
    def username(self) -> str | None:
        """Get or set entry username."""
        return self.strings.get("UserName", StringField("UserName")).value

    @username.setter
    def username(self, value: str | None) -> None:
        if "UserName" not in self.strings:
            self.strings["UserName"] = StringField("UserName")
        self.strings["UserName"].value = value

    @property
    def password(self) -> str | None:
        """Get or set entry password."""
        return self.strings.get("Password", StringField("Password")).value

    @password.setter
    def password(self, value: str | None) -> None:
        if "Password" not in self.strings:
            self.strings["Password"] = StringField("Password", protected=True)
        self.strings["Password"].value = value

    @property
    def url(self) -> str | None:
        """Get or set entry URL."""
        return self.strings.get("URL", StringField("URL")).value

    @url.setter
    def url(self, value: str | None) -> None:
        if "URL" not in self.strings:
            self.strings["URL"] = StringField("URL")
        self.strings["URL"].value = value

    @property
    def notes(self) -> str | None:
        """Get or set entry notes."""
        return self.strings.get("Notes", StringField("Notes")).value

    @notes.setter
    def notes(self, value: str | None) -> None:
        if "Notes" not in self.strings:
            self.strings["Notes"] = StringField("Notes")
        self.strings["Notes"].value = value

    @property
    def otp(self) -> str | None:
        """Get or set OTP secret (TOTP/HOTP)."""
        return self.strings.get("otp", StringField("otp")).value

    @otp.setter
    def otp(self, value: str | None) -> None:
        if "otp" not in self.strings:
            self.strings["otp"] = StringField("otp", protected=True)
        self.strings["otp"].value = value

    def totp(self, *, at: datetime | float | None = None) -> TotpCode | None:
        """Generate current TOTP code from the entry's otp field.

        Supports both standard otpauth:// URIs and KeePassXC legacy format
        (TOTP Seed / TOTP Settings custom fields).

        Args:
            at: Optional timestamp for code generation. Can be a datetime
                or Unix timestamp float. Defaults to current time.

        Returns:
            TotpCode object with code and expiration info, or None if no OTP configured.

        Raises:
            ValueError: If OTP configuration is invalid

        Example:
            >>> result = entry.totp()
            >>> print(f"Code: {result.code}")
            Code: 123456

            >>> print(f"Expires in {result.remaining}s")
            Expires in 15s

            >>> # TotpCode also works as a string
            >>> print(result)
            123456
        """
        from ..security.totp import (
            generate_totp,
            parse_keepassxc_legacy,
            parse_otpauth_uri,
        )

        # Try standard otp field first (otpauth:// URI)
        otp_value = self.otp
        if otp_value and otp_value.startswith("otpauth://"):
            config = parse_otpauth_uri(otp_value)
        # Try KeePassXC legacy fields
        elif self.strings.get("TOTP Seed"):
            seed = self.strings["TOTP Seed"].value
            if not seed:
                return None
            settings = None
            if self.strings.get("TOTP Settings"):
                settings = self.strings["TOTP Settings"].value
            config = parse_keepassxc_legacy(seed, settings)
        else:
            # No OTP configured
            return None

        # Convert datetime to timestamp if needed
        timestamp: float | None = None
        if at is not None:
            timestamp = at.timestamp() if isinstance(at, datetime) else at

        return generate_totp(config, timestamp)

    @property
    def custom_icon(self) -> uuid_module.UUID | None:
        """Get or set custom icon by UUID or name.

        When setting, accepts either a UUID or an icon name (string).
        If a string is provided, it must match exactly one icon name in the
        database. Requires the entry to be associated with a database for
        name-based lookup.

        Returns:
            UUID of the custom icon, or None if not set
        """
        return self.custom_icon_uuid

    @custom_icon.setter
    def custom_icon(self, value: uuid_module.UUID | str | None) -> None:
        if value is None:
            self.custom_icon_uuid = None
        elif isinstance(value, uuid_module.UUID):
            self.custom_icon_uuid = value
        elif isinstance(value, str):
            # Look up icon by name
            if self._database is None:
                raise ValueError(
                    "Cannot set custom icon by name: entry is not associated with a database"
                )
            icon_uuid = self._database.find_custom_icon_by_name(value)
            if icon_uuid is None:
                raise ValueError(f"No custom icon found with name: {value}")
            self.custom_icon_uuid = icon_uuid
        else:
            raise TypeError(f"custom_icon must be UUID, str, or None, not {type(value).__name__}")

    # --- Custom properties ---

    def get_custom_property(self, key: str) -> str | None:
        """Get a custom property value.

        Args:
            key: Property name (must not be a reserved key)

        Returns:
            Property value, or None if not set

        Raises:
            ValueError: If key is a reserved key
        """
        if key in RESERVED_KEYS:
            raise ValueError(f"{key} is a reserved key, use the property instead")
        field = self.strings.get(key)
        return field.value if field else None

    def set_custom_property(self, key: str, value: str, protected: bool = False) -> None:
        """Set a custom property.

        Args:
            key: Property name (must not be a reserved key)
            value: Property value
            protected: Whether to mark as protected in memory

        Raises:
            ValueError: If key is a reserved key
        """
        if key in RESERVED_KEYS:
            raise ValueError(f"{key} is a reserved key, use the property instead")
        self.strings[key] = StringField(key=key, value=value, protected=protected)

    def delete_custom_property(self, key: str) -> None:
        """Delete a custom property.

        Args:
            key: Property name to delete

        Raises:
            ValueError: If key is a reserved key
            KeyError: If property doesn't exist
        """
        if key in RESERVED_KEYS:
            raise ValueError(f"{key} is a reserved key")
        if key not in self.strings:
            raise KeyError(f"No such property: {key}")
        del self.strings[key]

    @property
    def custom_properties(self) -> dict[str, str | None]:
        """Get all custom properties as a dictionary."""
        return {k: v.value for k, v in self.strings.items() if k not in RESERVED_KEYS}

    # --- Convenience methods ---

    @property
    def parent(self) -> Group | None:
        """Get parent group."""
        return self._parent

    @property
    def database(self) -> Database | None:
        """Get the database this entry belongs to."""
        return self._database

    @property
    def index(self) -> int:
        """Get the index of this entry within its parent group.

        Returns:
            Zero-based index of this entry in the parent's entries list.

        Raises:
            ValueError: If entry has no parent group.
        """
        if self._parent is None:
            raise ValueError("Entry has no parent group")
        return self._parent.entries.index(self)

    @property
    def expired(self) -> bool:
        """Check if entry has expired."""
        return self.times.expired

    def touch(self, modify: bool = False) -> None:
        """Update access time, optionally modification time."""
        self.times.touch(modify=modify)

    def reindex(self, new_index: int) -> None:
        """Move this entry to a new position within its parent group.

        Args:
            new_index: Target position (zero-based). Negative indices are
                supported (e.g., -1 for last position).

        Raises:
            ValueError: If entry has no parent group.
            IndexError: If new_index is out of range.
        """
        if self._parent is None:
            raise ValueError("Entry has no parent group")

        entries = self._parent.entries
        current_index = entries.index(self)

        # Handle negative indices
        if new_index < 0:
            new_index = len(entries) + new_index

        # Validate bounds
        if new_index < 0 or new_index >= len(entries):
            raise IndexError(f"Index {new_index} out of range for {len(entries)} entries")

        # No-op if already at target position
        if current_index == new_index:
            return

        # Remove from current position and insert at new position
        entries.pop(current_index)
        entries.insert(new_index, self)

    def save_history(self) -> None:
        """Save current state to history before making changes."""
        # Create a history entry from current state
        history_entry = HistoryEntry.from_entry(self)
        self.history.append(history_entry)

    def delete_history(
        self, history_entry: HistoryEntry | None = None, *, all: bool = False
    ) -> None:
        """Delete history entries.

        Either deletes a specific history entry or all history entries.
        At least one of history_entry or all=True must be specified.

        Args:
            history_entry: Specific history entry to delete
            all: If True, delete all history entries

        Raises:
            ValueError: If neither history_entry nor all=True is specified
            ValueError: If history_entry is not in this entry's history
        """
        if history_entry is None and not all:
            raise ValueError("Must specify history_entry or all=True")

        if all:
            self.history.clear()
            return

        if history_entry not in self.history:
            raise ValueError("History entry not found in this entry's history")

        self.history.remove(history_entry)

    def clear_history(self) -> None:
        """Clear all history entries.

        This is a convenience method equivalent to delete_history(all=True).
        """
        self.history.clear()

    def move_to(self, destination: Group) -> None:
        """Move this entry to a different group.

        Removes the entry from its current parent and adds it to the
        destination group. Updates the location_changed timestamp.

        Args:
            destination: Target group to move the entry to

        Raises:
            ValueError: If entry has no parent (not yet added to a group)
            ValueError: If destination is the current parent (no-op would be confusing)
        """
        if self._parent is None:
            raise ValueError("Cannot move entry that has no parent group")
        if self._parent is destination:
            raise ValueError("Entry is already in the destination group")

        # Remove from current parent
        self._parent.entries.remove(self)
        old_parent = self._parent
        self._parent = None

        # Add to new parent
        destination.entries.append(self)
        self._parent = destination

        # Update timestamps
        self.times.update_location()
        old_parent.touch(modify=True)
        destination.touch(modify=True)

    # --- Field References ---

    def ref(self, field: str) -> str:
        """Create a reference string pointing to a field of this entry.

        Creates a KeePass field reference string that can be used in other
        entries to reference values from this entry. References use the
        entry's UUID for lookup.

        Args:
            field: One of 'title', 'username', 'password', 'url', 'notes', or 'uuid'

        Returns:
            Field reference string in format {REF:X@I:UUID}

        Raises:
            ValueError: If field is not a valid field name

        Example:
            >>> main_entry = db.find_entries(title='Main Account', first=True)
            >>> ref_string = main_entry.ref('password')
            >>> # Returns '{REF:P@I:...UUID...}'
            >>> other_entry.password = ref_string
        """
        field_codes = {
            "title": "T",
            "username": "U",
            "password": "P",
            "url": "A",
            "notes": "N",
            "uuid": "I",
        }
        field_lower = field.lower()
        if field_lower not in field_codes:
            valid = ", ".join(sorted(field_codes.keys()))
            raise ValueError(f"Invalid field '{field}'. Must be one of: {valid}")

        field_code = field_codes[field_lower]
        uuid_hex = self.uuid.hex.upper()
        return f"{{REF:{field_code}@I:{uuid_hex}}}"

    def deref(self, field: str) -> str | uuid_module.UUID | None:
        """Resolve any field references in the given field's value.

        If the field's value contains KeePass field references ({REF:X@Y:Z}),
        resolves them to the actual values from the referenced entries.

        Args:
            field: One of 'title', 'username', 'password', 'url', 'notes'

        Returns:
            The resolved value with all references replaced, a UUID if the
            referenced field is 'uuid', or None if a referenced entry is not found

        Raises:
            ValueError: If no database reference is available

        Example:
            >>> # If entry.password contains '{REF:P@I:...UUID...}'
            >>> actual_password = entry.deref('password')
        """
        if self._database is None:
            raise ValueError("Cannot dereference field: entry is not connected to a database")

        value = getattr(self, field.lower())
        return self._database.deref(value)

    def dump(self) -> str:
        """Return a human-readable summary of the entry for debugging.

        Returns:
            Multi-line string with entry details (passwords are masked).
        """
        lines = [f'Entry: "{self.title}" ({self.username})']
        lines.append(f"  UUID: {self.uuid}")
        if self.url:
            lines.append(f"  URL: {self.url}")
        if self.tags:
            lines.append(f"  Tags: {self.tags}")
        lines.append(f"  Created: {self.times.creation_time}")
        lines.append(f"  Modified: {self.times.last_modification_time}")
        if self.times.expires:
            lines.append(f"  Expires: {self.times.expiry_time}")
        custom_count = len(self.custom_properties)
        if custom_count > 0:
            lines.append(f"  Custom fields: {custom_count}")
        if self.binaries:
            lines.append(f"  Attachments: {len(self.binaries)}")
        if self.history:
            lines.append(f"  History: {len(self.history)} versions")
        return "\n".join(lines)

    def __str__(self) -> str:
        return f'Entry: "{self.title}" ({self.username})'

    def __hash__(self) -> int:
        return hash(self.uuid)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Entry):
            return self.uuid == other.uuid
        return NotImplemented

    @classmethod
    def create(
        cls,
        title: str | None = None,
        username: str | None = None,
        password: str | None = None,
        url: str | None = None,
        notes: str | None = None,
        tags: list[str] | None = None,
        icon_id: str = "0",
        expires: bool = False,
        expiry_time: datetime | None = None,
    ) -> Entry:
        """Create a new entry with common fields.

        Args:
            title: Entry title
            username: Username
            password: Password
            url: URL
            notes: Notes
            tags: List of tags
            icon_id: Icon ID
            expires: Whether entry expires
            expiry_time: Expiration time

        Returns:
            New Entry instance
        """
        entry = cls(
            times=Times.create_new(expires=expires, expiry_time=expiry_time),
            icon_id=icon_id,
            tags=tags or [],
        )
        entry.title = title
        entry.username = username
        entry.password = password
        entry.url = url
        entry.notes = notes
        return entry


@dataclass
class HistoryEntry(Entry):
    """A historical version of an entry.

    History entries are snapshots of an entry at a previous point in time.
    They share the same UUID as their parent entry.
    """

    def __str__(self) -> str:
        return f'HistoryEntry: "{self.title}" ({self.times.last_modification_time})'

    def __hash__(self) -> int:
        # Include mtime since history entries share UUID with parent
        return hash((self.uuid, self.times.last_modification_time))

    @classmethod
    def from_entry(cls, entry: Entry) -> HistoryEntry:
        """Create a history entry from an existing entry.

        Args:
            entry: Entry to create history from

        Returns:
            New HistoryEntry with copied data
        """
        import copy

        # Deep copy all fields except history and parent
        return cls(
            uuid=entry.uuid,
            times=copy.deepcopy(entry.times),
            icon_id=entry.icon_id,
            custom_icon_uuid=entry.custom_icon_uuid,
            tags=list(entry.tags),
            strings=copy.deepcopy(entry.strings),
            binaries=list(entry.binaries),
            autotype=copy.deepcopy(entry.autotype),
            history=[],  # History entries don't have history
            foreground_color=entry.foreground_color,
            background_color=entry.background_color,
            override_url=entry.override_url,
            quality_check=entry.quality_check,
            _parent=None,
        )
