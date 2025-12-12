"""Group model for KDBX database folders."""

from __future__ import annotations

import re
import uuid as uuid_module
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .entry import Entry
from .times import Times

if TYPE_CHECKING:
    from ..database import Database
    from ..templates import EntryTemplate


@dataclass
class Group:
    """A group (folder) in a KDBX database.

    Groups organize entries into a hierarchical structure. Each group can
    contain entries and subgroups.

    Attributes:
        uuid: Unique identifier for the group
        name: Display name of the group
        notes: Optional notes/description
        times: Timestamps (creation, modification, access, expiry)
        icon_id: Icon ID for display (standard icon)
        custom_icon_uuid: UUID of custom icon (overrides icon_id if set)
        is_expanded: Whether group is expanded in UI
        default_autotype_sequence: Default AutoType sequence for entries
        enable_autotype: Whether AutoType is enabled for this group
        enable_searching: Whether entries in this group are searchable
        last_top_visible_entry: UUID of last visible entry (UI state)
        entries: List of entries in this group
        subgroups: List of subgroups
    """

    uuid: uuid_module.UUID = field(default_factory=uuid_module.uuid4)
    name: str | None = None
    notes: str | None = None
    times: Times = field(default_factory=Times.create_new)
    icon_id: str = "48"  # Default folder icon
    custom_icon_uuid: uuid_module.UUID | None = None
    is_expanded: bool = True
    default_autotype_sequence: str | None = None
    enable_autotype: bool | None = None  # None = inherit from parent
    enable_searching: bool | None = None  # None = inherit from parent
    last_top_visible_entry: uuid_module.UUID | None = None
    entries: list[Entry] = field(default_factory=list)
    subgroups: list[Group] = field(default_factory=list)

    # Runtime reference to parent group (not serialized)
    _parent: Group | None = field(default=None, repr=False, compare=False)
    # Flag for root group
    _is_root: bool = field(default=False, repr=False)
    # Runtime reference to database (not serialized) - used for icon name resolution
    _database: Database | None = field(default=None, repr=False, compare=False)

    @property
    def parent(self) -> Group | None:
        """Get parent group, or None if this is the root."""
        return self._parent

    @property
    def database(self) -> Database | None:
        """Get the database this group belongs to."""
        return self._database

    @property
    def is_root_group(self) -> bool:
        """Check if this is the database root group."""
        return self._is_root

    @property
    def index(self) -> int:
        """Get the index of this group within its parent group.

        Returns:
            Zero-based index of this group in the parent's subgroups list.

        Raises:
            ValueError: If group has no parent (is root group).
        """
        if self._parent is None:
            raise ValueError("Group has no parent (is root group)")
        return self._parent.subgroups.index(self)

    @property
    def path(self) -> list[str]:
        """Get path from root to this group.

        Returns:
            List of group names from root (exclusive) to this group (inclusive).
            Empty list for the root group.
        """
        if self.is_root_group or self._parent is None:
            return []
        parts: list[str] = []
        current: Group | None = self
        while current is not None and not current.is_root_group:
            if current.name is not None:
                parts.insert(0, current.name)
            current = current._parent
        return parts

    @property
    def expired(self) -> bool:
        """Check if group has expired."""
        return self.times.expired

    @property
    def custom_icon(self) -> uuid_module.UUID | None:
        """Get or set custom icon by UUID or name.

        When setting, accepts either a UUID or an icon name (string).
        If a string is provided, it must match exactly one icon name in the
        database. Requires the group to be associated with a database for
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
                    "Cannot set custom icon by name: group is not associated with a database"
                )
            icon_uuid = self._database.find_custom_icon_by_name(value)
            if icon_uuid is None:
                raise ValueError(f"No custom icon found with name: {value}")
            self.custom_icon_uuid = icon_uuid
        else:
            raise TypeError(f"custom_icon must be UUID, str, or None, not {type(value).__name__}")

    def touch(self, modify: bool = False) -> None:
        """Update access time, optionally modification time."""
        self.times.touch(modify=modify)

    def reindex(self, new_index: int) -> None:
        """Move this group to a new position within its parent group.

        Args:
            new_index: Target position (zero-based). Negative indices are
                supported (e.g., -1 for last position).

        Raises:
            ValueError: If group has no parent (is root group).
            IndexError: If new_index is out of range.
        """
        if self._parent is None:
            raise ValueError("Group has no parent (is root group)")

        subgroups = self._parent.subgroups
        current_index = subgroups.index(self)

        # Handle negative indices
        if new_index < 0:
            new_index = len(subgroups) + new_index

        # Validate bounds
        if new_index < 0 or new_index >= len(subgroups):
            raise IndexError(f"Index {new_index} out of range for {len(subgroups)} groups")

        # No-op if already at target position
        if current_index == new_index:
            return

        # Remove from current position and insert at new position
        subgroups.pop(current_index)
        subgroups.insert(new_index, self)

    # --- Entry management ---

    def add_entry(self, entry: Entry) -> Entry:
        """Add an entry to this group.

        Args:
            entry: Entry to add

        Returns:
            The added entry
        """
        entry._parent = self
        entry._database = self._database
        self.entries.append(entry)
        self.touch(modify=True)
        return entry

    def remove_entry(self, entry: Entry) -> None:
        """Remove an entry from this group.

        Args:
            entry: Entry to remove

        Raises:
            ValueError: If entry is not in this group
        """
        if entry not in self.entries:
            raise ValueError("Entry not in this group")
        self.entries.remove(entry)
        entry._parent = None
        self.touch(modify=True)

    def create_entry(
        self,
        title: str | None = None,
        username: str | None = None,
        password: str | None = None,
        url: str | None = None,
        notes: str | None = None,
        tags: list[str] | None = None,
        *,
        template: EntryTemplate | None = None,
    ) -> Entry:
        """Create and add a new entry to this group.

        Args:
            title: Entry title
            username: Username
            password: Password
            url: URL
            notes: Notes
            tags: Tags
            template: Optional entry template instance with field values

        Returns:
            Newly created entry

        Example:
            >>> # Standard entry (no template)
            >>> entry = group.create_entry(title="Site", username="user", password="pass")

            >>> # Using a template with typed fields
            >>> from kdbxtool import Templates
            >>> entry = group.create_entry(
            ...     title="My Visa",
            ...     template=Templates.CreditCard(
            ...         card_number="4111111111111111",
            ...         expiry_date="12/25",
            ...         cvv="123",
            ...     ),
            ... )

            >>> # Server template with standard fields
            >>> entry = group.create_entry(
            ...     title="prod-server",
            ...     username="admin",
            ...     password="secret",
            ...     template=Templates.Server(
            ...         hostname="192.168.1.1",
            ...         port="22",
            ...     ),
            ... )
        """
        from .entry import StringField

        # Determine icon and whether to include standard fields
        icon_id = "0"
        include_standard = True
        if template is not None:
            icon_id = str(template._icon_id)
            include_standard = template._include_standard

        # Create base entry
        entry = Entry.create(
            title=title,
            username=username if include_standard else None,
            password=password if include_standard else None,
            url=url if include_standard else None,
            notes=notes,
            tags=tags,
            icon_id=icon_id,
        )

        # Add template fields from the template instance
        if template is not None:
            for display_name, (value, is_protected) in template._get_fields().items():
                if value is not None:
                    entry.strings[display_name] = StringField(
                        key=display_name,
                        value=value,
                        protected=is_protected,
                    )

        return self.add_entry(entry)

    # --- Subgroup management ---

    def add_subgroup(self, group: Group) -> Group:
        """Add a subgroup to this group.

        Args:
            group: Group to add

        Returns:
            The added group
        """
        group._parent = self
        # Propagate database reference to the subgroup and all its contents
        self._propagate_database(group)
        self.subgroups.append(group)
        self.touch(modify=True)
        return group

    def _propagate_database(self, group: Group) -> None:
        """Recursively propagate database reference to a group and its contents."""
        group._database = self._database
        for entry in group.entries:
            entry._database = self._database
        for subgroup in group.subgroups:
            self._propagate_database(subgroup)

    def remove_subgroup(self, group: Group) -> None:
        """Remove a subgroup from this group.

        Args:
            group: Group to remove

        Raises:
            ValueError: If group is not a subgroup of this group
        """
        if group not in self.subgroups:
            raise ValueError("Group is not a subgroup")
        self.subgroups.remove(group)
        group._parent = None
        self.touch(modify=True)

    def create_subgroup(
        self,
        name: str,
        notes: str | None = None,
        icon_id: str = "48",
    ) -> Group:
        """Create and add a new subgroup.

        Args:
            name: Group name
            notes: Optional notes
            icon_id: Icon ID

        Returns:
            Newly created group
        """
        group = Group(name=name, notes=notes, icon_id=icon_id)
        return self.add_subgroup(group)

    def move_to(self, destination: Group) -> None:
        """Move this group to a different parent group.

        Removes the group from its current parent and adds it to the
        destination group. Updates the location_changed timestamp.

        Args:
            destination: Target parent group to move this group to

        Raises:
            ValueError: If this is the root group (cannot be moved)
            ValueError: If group has no parent (not yet added to a database)
            ValueError: If destination is the current parent
            ValueError: If destination is this group (cannot move into self)
            ValueError: If destination is a descendant of this group (would create cycle)
        """
        if self._is_root:
            raise ValueError("Cannot move the root group")
        if self._parent is None:
            raise ValueError("Cannot move group that has no parent")
        if self._parent is destination:
            raise ValueError("Group is already in the destination group")
        if destination is self:
            raise ValueError("Cannot move group into itself")

        # Check for cycle: destination cannot be a descendant of this group
        if self._is_descendant(destination):
            raise ValueError("Cannot move group into its own descendant (would create cycle)")

        # Remove from current parent
        self._parent.subgroups.remove(self)
        old_parent = self._parent
        self._parent = None

        # Add to new parent
        destination.subgroups.append(self)
        self._parent = destination

        # Update timestamps
        self.times.update_location()
        old_parent.touch(modify=True)
        destination.touch(modify=True)

    def _is_descendant(self, group: Group) -> bool:
        """Check if the given group is a descendant of this group.

        Args:
            group: Group to check

        Returns:
            True if group is a descendant of this group
        """
        for subgroup in self.subgroups:
            if subgroup is group:
                return True
            if subgroup._is_descendant(group):
                return True
        return False

    # --- Iteration and search ---

    def iter_entries(self, recursive: bool = True, history: bool = False) -> Iterator[Entry]:
        """Iterate over entries in this group.

        Args:
            recursive: If True, include entries from all subgroups
            history: If True, include history entries

        Yields:
            Entry objects
        """
        for entry in self.entries:
            yield entry
            if history:
                yield from entry.history
        if recursive:
            for subgroup in self.subgroups:
                yield from subgroup.iter_entries(recursive=True, history=history)

    def iter_groups(self, recursive: bool = True) -> Iterator[Group]:
        """Iterate over subgroups.

        Args:
            recursive: If True, include nested subgroups

        Yields:
            Group objects
        """
        for subgroup in self.subgroups:
            yield subgroup
            if recursive:
                yield from subgroup.iter_groups(recursive=True)

    def find_entry_by_uuid(self, uuid: uuid_module.UUID, recursive: bool = True) -> Entry | None:
        """Find an entry by UUID.

        Args:
            uuid: Entry UUID to find
            recursive: Search in subgroups

        Returns:
            Entry if found, None otherwise
        """
        for entry in self.iter_entries(recursive=recursive):
            if entry.uuid == uuid:
                return entry
        return None

    def find_group_by_uuid(self, uuid: uuid_module.UUID, recursive: bool = True) -> Group | None:
        """Find a group by UUID.

        Args:
            uuid: Group UUID to find
            recursive: Search in nested subgroups

        Returns:
            Group if found, None otherwise
        """
        if self.uuid == uuid:
            return self
        for group in self.iter_groups(recursive=recursive):
            if group.uuid == uuid:
                return group
        return None

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
        recursive: bool = True,
        history: bool = False,
    ) -> list[Entry]:
        """Find entries matching criteria.

        All criteria are combined with AND logic. None means "any value".

        Args:
            title: Match entries with this title (exact)
            username: Match entries with this username (exact)
            password: Match entries with this password (exact)
            url: Match entries with this URL (exact)
            notes: Match entries with these notes (exact)
            otp: Match entries with this OTP (exact)
            tags: Match entries containing all these tags
            string: Match entries with custom properties (dict of key:value)
            autotype_enabled: Filter by AutoType enabled state
            autotype_sequence: Match entries with this AutoType sequence (exact)
            autotype_window: Match entries with this AutoType window (exact)
            recursive: Search in subgroups
            history: Include history entries in search

        Returns:
            List of matching entries
        """
        results: list[Entry] = []
        for entry in self.iter_entries(recursive=recursive, history=history):
            if title is not None and entry.title != title:
                continue
            if username is not None and entry.username != username:
                continue
            if password is not None and entry.password != password:
                continue
            if url is not None and entry.url != url:
                continue
            if notes is not None and entry.notes != notes:
                continue
            if otp is not None and entry.otp != otp:
                continue
            if tags is not None and not all(t in entry.tags for t in tags):
                continue
            if string is not None and not all(
                entry.get_custom_property(k) == v for k, v in string.items()
            ):
                continue
            if autotype_enabled is not None and entry.autotype.enabled != autotype_enabled:
                continue
            if autotype_sequence is not None and entry.autotype.sequence != autotype_sequence:
                continue
            if autotype_window is not None and entry.autotype.window != autotype_window:
                continue
            results.append(entry)
        return results

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

        def contains(field_value: str | None, search: str) -> bool:
            if field_value is None:
                return False
            if case_sensitive:
                return search in field_value
            return search.lower() in field_value.lower()

        results: list[Entry] = []
        for entry in self.iter_entries(recursive=recursive, history=history):
            if title is not None and not contains(entry.title, title):
                continue
            if username is not None and not contains(entry.username, username):
                continue
            if password is not None and not contains(entry.password, password):
                continue
            if url is not None and not contains(entry.url, url):
                continue
            if notes is not None and not contains(entry.notes, notes):
                continue
            if otp is not None and not contains(entry.otp, otp):
                continue
            results.append(entry)
        return results

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
        # Pre-compile patterns for efficiency
        flags = 0 if case_sensitive else re.IGNORECASE
        patterns: dict[str, re.Pattern[str]] = {}
        if title is not None:
            patterns["title"] = re.compile(title, flags)
        if username is not None:
            patterns["username"] = re.compile(username, flags)
        if password is not None:
            patterns["password"] = re.compile(password, flags)
        if url is not None:
            patterns["url"] = re.compile(url, flags)
        if notes is not None:
            patterns["notes"] = re.compile(notes, flags)
        if otp is not None:
            patterns["otp"] = re.compile(otp, flags)

        def matches(field_value: str | None, pattern: re.Pattern[str]) -> bool:
            if field_value is None:
                return False
            return pattern.search(field_value) is not None

        results: list[Entry] = []
        for entry in self.iter_entries(recursive=recursive, history=history):
            if "title" in patterns and not matches(entry.title, patterns["title"]):
                continue
            if "username" in patterns and not matches(entry.username, patterns["username"]):
                continue
            if "password" in patterns and not matches(entry.password, patterns["password"]):
                continue
            if "url" in patterns and not matches(entry.url, patterns["url"]):
                continue
            if "notes" in patterns and not matches(entry.notes, patterns["notes"]):
                continue
            if "otp" in patterns and not matches(entry.otp, patterns["otp"]):
                continue
            results.append(entry)
        return results

    def find_groups(
        self,
        name: str | None = None,
        recursive: bool = True,
        first: bool = False,
    ) -> list[Group] | Group | None:
        """Find groups matching criteria.

        Args:
            name: Match groups with this name (exact)
            recursive: Search in nested subgroups
            first: If True, return first matching group or None instead of list

        Returns:
            List of matching groups, or single Group/None if first=True
        """
        results: list[Group] = []
        for group in self.iter_groups(recursive=recursive):
            if name is not None and group.name != name:
                continue
            if first:
                return group
            results.append(group)
        if first:
            return None
        return results

    def dump(self, recursive: bool = False) -> str:
        """Return a human-readable summary of the group for debugging.

        Args:
            recursive: If True, include subgroups and entries recursively

        Returns:
            Multi-line string with group details.
        """
        path_str = "/".join(self.path) if self.path else "(root)"
        lines = [f'Group: "{path_str}"']
        lines.append(f"  UUID: {self.uuid}")
        if self.notes:
            notes_display = f"{self.notes[:50]}..." if len(self.notes) > 50 else self.notes
            lines.append(f"  Notes: {notes_display}")
        lines.append(f"  Entries: {len(self.entries)}")
        lines.append(f"  Subgroups: {len(self.subgroups)}")
        lines.append(f"  Created: {self.times.creation_time}")
        lines.append(f"  Modified: {self.times.last_modification_time}")

        if recursive:
            for entry in self.entries:
                for line in entry.dump().split("\n"):
                    lines.append("  " + line)
            for subgroup in self.subgroups:
                for line in subgroup.dump(recursive=True).split("\n"):
                    lines.append("  " + line)

        return "\n".join(lines)

    def __str__(self) -> str:
        path_str = "/".join(self.path) if self.path else "(root)"
        return f'Group: "{path_str}"'

    def __hash__(self) -> int:
        return hash(self.uuid)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Group):
            return self.uuid == other.uuid
        return NotImplemented

    @classmethod
    def create_root(cls, name: str = "Root") -> Group:
        """Create a root group for a new database.

        Args:
            name: Name for the root group

        Returns:
            New root Group instance
        """
        group = cls(name=name)
        group._is_root = True
        return group
