"""Entry model for KDBX password entries."""

from __future__ import annotations

import uuid as uuid_module
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

from .times import Times

if TYPE_CHECKING:
    from .group import Group


# Fields that have special handling and shouldn't be treated as custom properties
RESERVED_KEYS = frozenset({
    "Title",
    "UserName",
    "Password",
    "URL",
    "Notes",
    "otp",
})


@dataclass
class StringField:
    """A string field in an entry.

    Attributes:
        key: Field name (e.g., "Title", "UserName", "Password")
        value: Field value
        protected: Whether the field should be protected in memory
    """

    key: str
    value: Optional[str] = None
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
    sequence: Optional[str] = None
    window: Optional[str] = None
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
        icon_id: Icon ID for display
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
    tags: list[str] = field(default_factory=list)
    strings: dict[str, StringField] = field(default_factory=dict)
    binaries: list[BinaryRef] = field(default_factory=list)
    autotype: AutoType = field(default_factory=AutoType)
    history: list[HistoryEntry] = field(default_factory=list)
    foreground_color: Optional[str] = None
    background_color: Optional[str] = None
    override_url: Optional[str] = None
    quality_check: bool = True

    # Runtime reference to parent group (not serialized)
    _parent: Optional[Group] = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Initialize default string fields if not present."""
        for key in ("Title", "UserName", "Password", "URL", "Notes"):
            if key not in self.strings:
                protected = key == "Password"
                self.strings[key] = StringField(key=key, protected=protected)

    # --- Standard field properties ---

    @property
    def title(self) -> Optional[str]:
        """Get or set entry title."""
        return self.strings.get("Title", StringField("Title")).value

    @title.setter
    def title(self, value: Optional[str]) -> None:
        if "Title" not in self.strings:
            self.strings["Title"] = StringField("Title")
        self.strings["Title"].value = value

    @property
    def username(self) -> Optional[str]:
        """Get or set entry username."""
        return self.strings.get("UserName", StringField("UserName")).value

    @username.setter
    def username(self, value: Optional[str]) -> None:
        if "UserName" not in self.strings:
            self.strings["UserName"] = StringField("UserName")
        self.strings["UserName"].value = value

    @property
    def password(self) -> Optional[str]:
        """Get or set entry password."""
        return self.strings.get("Password", StringField("Password")).value

    @password.setter
    def password(self, value: Optional[str]) -> None:
        if "Password" not in self.strings:
            self.strings["Password"] = StringField("Password", protected=True)
        self.strings["Password"].value = value

    @property
    def url(self) -> Optional[str]:
        """Get or set entry URL."""
        return self.strings.get("URL", StringField("URL")).value

    @url.setter
    def url(self, value: Optional[str]) -> None:
        if "URL" not in self.strings:
            self.strings["URL"] = StringField("URL")
        self.strings["URL"].value = value

    @property
    def notes(self) -> Optional[str]:
        """Get or set entry notes."""
        return self.strings.get("Notes", StringField("Notes")).value

    @notes.setter
    def notes(self, value: Optional[str]) -> None:
        if "Notes" not in self.strings:
            self.strings["Notes"] = StringField("Notes")
        self.strings["Notes"].value = value

    @property
    def otp(self) -> Optional[str]:
        """Get or set OTP secret (TOTP/HOTP)."""
        return self.strings.get("otp", StringField("otp")).value

    @otp.setter
    def otp(self, value: Optional[str]) -> None:
        if "otp" not in self.strings:
            self.strings["otp"] = StringField("otp", protected=True)
        self.strings["otp"].value = value

    # --- Custom properties ---

    def get_custom_property(self, key: str) -> Optional[str]:
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

    def set_custom_property(
        self, key: str, value: str, protected: bool = False
    ) -> None:
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
    def custom_properties(self) -> dict[str, Optional[str]]:
        """Get all custom properties as a dictionary."""
        return {
            k: v.value
            for k, v in self.strings.items()
            if k not in RESERVED_KEYS
        }

    # --- Convenience methods ---

    @property
    def parent(self) -> Optional[Group]:
        """Get parent group."""
        return self._parent

    @property
    def expired(self) -> bool:
        """Check if entry has expired."""
        return self.times.expired

    def touch(self, modify: bool = False) -> None:
        """Update access time, optionally modification time."""
        self.times.touch(modify=modify)

    def save_history(self) -> None:
        """Save current state to history before making changes."""
        # Create a history entry from current state
        history_entry = HistoryEntry.from_entry(self)
        self.history.append(history_entry)

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
        title: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        url: Optional[str] = None,
        notes: Optional[str] = None,
        tags: Optional[list[str]] = None,
        icon_id: str = "0",
        expires: bool = False,
        expiry_time: Optional[object] = None,  # datetime
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
