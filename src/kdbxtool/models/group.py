"""Group model for KDBX database folders."""

from __future__ import annotations

import re
import uuid as uuid_module
from collections.abc import Iterator
from dataclasses import dataclass, field

from .entry import Entry
from .times import Times


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
        icon_id: Icon ID for display
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

    @property
    def parent(self) -> Group | None:
        """Get parent group, or None if this is the root."""
        return self._parent

    @property
    def is_root_group(self) -> bool:
        """Check if this is the database root group."""
        return self._is_root

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

    def touch(self, modify: bool = False) -> None:
        """Update access time, optionally modification time."""
        self.times.touch(modify=modify)

    # --- Entry management ---

    def add_entry(self, entry: Entry) -> Entry:
        """Add an entry to this group.

        Args:
            entry: Entry to add

        Returns:
            The added entry
        """
        entry._parent = self
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
    ) -> Entry:
        """Create and add a new entry to this group.

        Args:
            title: Entry title
            username: Username
            password: Password
            url: URL
            notes: Notes
            tags: Tags

        Returns:
            Newly created entry
        """
        entry = Entry.create(
            title=title,
            username=username,
            password=password,
            url=url,
            notes=notes,
            tags=tags,
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
        self.subgroups.append(group)
        self.touch(modify=True)
        return group

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

    def iter_entries(self, recursive: bool = True) -> Iterator[Entry]:
        """Iterate over entries in this group.

        Args:
            recursive: If True, include entries from all subgroups

        Yields:
            Entry objects
        """
        yield from self.entries
        if recursive:
            for subgroup in self.subgroups:
                yield from subgroup.iter_entries(recursive=True)

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

    def find_entry_by_uuid(
        self, uuid: uuid_module.UUID, recursive: bool = True
    ) -> Entry | None:
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

    def find_group_by_uuid(
        self, uuid: uuid_module.UUID, recursive: bool = True
    ) -> Group | None:
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
        url: str | None = None,
        tags: list[str] | None = None,
        recursive: bool = True,
    ) -> list[Entry]:
        """Find entries matching criteria.

        All criteria are combined with AND logic. None means "any value".

        Args:
            title: Match entries with this title (exact)
            username: Match entries with this username (exact)
            url: Match entries with this URL (exact)
            tags: Match entries containing all these tags
            recursive: Search in subgroups

        Returns:
            List of matching entries
        """
        results = []
        for entry in self.iter_entries(recursive=recursive):
            if title is not None and entry.title != title:
                continue
            if username is not None and entry.username != username:
                continue
            if url is not None and entry.url != url:
                continue
            if tags is not None and not all(t in entry.tags for t in tags):
                continue
            results.append(entry)
        return results

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

        def contains(field_value: str | None, search: str) -> bool:
            if field_value is None:
                return False
            if case_sensitive:
                return search in field_value
            return search.lower() in field_value.lower()

        results = []
        for entry in self.iter_entries(recursive=recursive):
            if title is not None and not contains(entry.title, title):
                continue
            if username is not None and not contains(entry.username, username):
                continue
            if url is not None and not contains(entry.url, url):
                continue
            if notes is not None and not contains(entry.notes, notes):
                continue
            results.append(entry)
        return results

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
        # Pre-compile patterns for efficiency
        flags = 0 if case_sensitive else re.IGNORECASE
        patterns: dict[str, re.Pattern[str]] = {}
        if title is not None:
            patterns["title"] = re.compile(title, flags)
        if username is not None:
            patterns["username"] = re.compile(username, flags)
        if url is not None:
            patterns["url"] = re.compile(url, flags)
        if notes is not None:
            patterns["notes"] = re.compile(notes, flags)

        def matches(field_value: str | None, pattern: re.Pattern[str]) -> bool:
            if field_value is None:
                return False
            return pattern.search(field_value) is not None

        results = []
        for entry in self.iter_entries(recursive=recursive):
            if "title" in patterns and not matches(entry.title, patterns["title"]):
                continue
            if "username" in patterns and not matches(entry.username, patterns["username"]):
                continue
            if "url" in patterns and not matches(entry.url, patterns["url"]):
                continue
            if "notes" in patterns and not matches(entry.notes, patterns["notes"]):
                continue
            results.append(entry)
        return results

    def find_groups(
        self,
        name: str | None = None,
        recursive: bool = True,
    ) -> list[Group]:
        """Find groups matching criteria.

        Args:
            name: Match groups with this name (exact)
            recursive: Search in nested subgroups

        Returns:
            List of matching groups
        """
        results = []
        for group in self.iter_groups(recursive=recursive):
            if name is not None and group.name != name:
                continue
            results.append(group)
        return results

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
