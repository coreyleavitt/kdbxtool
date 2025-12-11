"""Database merge functionality for combining KDBX databases.

This module provides the Merger class for merging two KeePass databases
following a UUID-based matching and timestamp-based conflict resolution
algorithm similar to KeePassXC.

Example:
    >>> from kdbxtool import Database
    >>> target = Database.open("main.kdbx", password="secret")
    >>> source = Database.open("branch.kdbx", password="secret")
    >>> result = target.merge(source)
    >>> print(f"Added {result.entries_added} entries")
    >>> target.save()
"""

from __future__ import annotations

import copy
import hashlib
import uuid as uuid_module
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, auto
from typing import TYPE_CHECKING

from .models.entry import BinaryRef, Entry, HistoryEntry, StringField
from .models.group import Group
from .models.times import Times

if TYPE_CHECKING:
    from .database import Database


class MergeMode(Enum):
    """Merge mode determining how conflicts and deletions are handled.

    Attributes:
        STANDARD: Add and update entries/groups from source. Does not delete
            anything from target. This is the default and safest mode.
        SYNCHRONIZE: Full bidirectional sync including deletions. Items deleted
            in source (tracked in DeletedObjects) will be deleted from target
            if they haven't been modified after the deletion time.
    """

    STANDARD = auto()
    SYNCHRONIZE = auto()


@dataclass
class DeletedObject:
    """Record of a deleted entry or group.

    Used in SYNCHRONIZE mode to track deletions that should propagate
    to other databases during merge.

    Attributes:
        uuid: UUID of the deleted entry or group
        deletion_time: When the deletion occurred
    """

    uuid: uuid_module.UUID
    deletion_time: datetime


@dataclass
class MergeResult:
    """Result of a database merge operation.

    Contains detailed statistics about what was changed during the merge.

    Attributes:
        entries_added: Number of new entries added from source
        entries_updated: Number of existing entries updated (source was newer)
        entries_relocated: Number of entries moved to different groups
        entries_deleted: Number of entries deleted (SYNCHRONIZE mode only)
        groups_added: Number of new groups added from source
        groups_updated: Number of existing groups updated (source was newer)
        groups_relocated: Number of groups moved to different parents
        groups_deleted: Number of groups deleted (SYNCHRONIZE mode only)
        history_entries_merged: Number of history entries added
        binaries_added: Number of new binary attachments added
        custom_icons_added: Number of new custom icons added
    """

    entries_added: int = 0
    entries_updated: int = 0
    entries_relocated: int = 0
    entries_deleted: int = 0
    groups_added: int = 0
    groups_updated: int = 0
    groups_relocated: int = 0
    groups_deleted: int = 0
    history_entries_merged: int = 0
    binaries_added: int = 0
    custom_icons_added: int = 0

    @property
    def has_changes(self) -> bool:
        """Check if any changes were made during the merge."""
        return any(
            [
                self.entries_added,
                self.entries_updated,
                self.entries_relocated,
                self.entries_deleted,
                self.groups_added,
                self.groups_updated,
                self.groups_relocated,
                self.groups_deleted,
                self.binaries_added,
                self.custom_icons_added,
            ]
        )

    @property
    def total_changes(self) -> int:
        """Total number of changes made."""
        return (
            self.entries_added
            + self.entries_updated
            + self.entries_relocated
            + self.entries_deleted
            + self.groups_added
            + self.groups_updated
            + self.groups_relocated
            + self.groups_deleted
        )

    def summary(self) -> str:
        """Get a human-readable summary of the merge result."""
        lines = []
        if self.entries_added:
            lines.append(f"Added {self.entries_added} entries")
        if self.entries_updated:
            lines.append(f"Updated {self.entries_updated} entries")
        if self.entries_relocated:
            lines.append(f"Relocated {self.entries_relocated} entries")
        if self.entries_deleted:
            lines.append(f"Deleted {self.entries_deleted} entries")
        if self.groups_added:
            lines.append(f"Added {self.groups_added} groups")
        if self.groups_updated:
            lines.append(f"Updated {self.groups_updated} groups")
        if self.groups_relocated:
            lines.append(f"Relocated {self.groups_relocated} groups")
        if self.groups_deleted:
            lines.append(f"Deleted {self.groups_deleted} groups")
        if self.history_entries_merged:
            lines.append(f"Merged {self.history_entries_merged} history entries")
        if self.binaries_added:
            lines.append(f"Added {self.binaries_added} attachments")
        if self.custom_icons_added:
            lines.append(f"Added {self.custom_icons_added} custom icons")
        return "\n".join(lines) if lines else "No changes"


class Merger:
    """Merges two KDBX databases with configurable conflict resolution.

    The merge algorithm follows these principles:
    1. UUID-based matching: Entries and groups are matched by UUID
    2. Timestamp-based resolution: Newer last_modification_time wins
    3. History preservation: Losing versions are preserved in history
    4. Location tracking: Entry moves are tracked via location_changed

    Example:
        >>> merger = Merger(target_db, source_db)
        >>> result = merger.merge()
        >>> print(result.summary())
    """

    def __init__(
        self,
        target: Database,
        source: Database,
        *,
        mode: MergeMode = MergeMode.STANDARD,
    ) -> None:
        """Initialize the merger.

        Args:
            target: Database to merge into (will be modified)
            source: Database to merge from (read-only)
            mode: Merge mode (STANDARD or SYNCHRONIZE)
        """
        self._target = target
        self._source = source
        self._mode = mode
        self._result = MergeResult()
        self._binary_remap: dict[int, int] = {}

    def merge(self) -> MergeResult:
        """Execute the merge operation.

        Returns:
            MergeResult with statistics about the merge

        Raises:
            MergeError: If merge fails
        """
        # Phase 1: Merge custom icons
        self._merge_custom_icons()

        # Phase 2: Merge binaries (must be done before entries to get remapping)
        self._merge_binaries()

        # Phase 3: Merge groups (structure first)
        self._merge_groups_recursive(
            self._target.root_group,
            self._source.root_group,
        )

        # Phase 4: Merge entries
        self._merge_entries()

        # Phase 5: Handle location changes
        self._merge_locations()

        # Phase 6: Apply deletions (SYNCHRONIZE mode only)
        if self._mode == MergeMode.SYNCHRONIZE:
            self._apply_deletions()

        return self._result

    # --- Custom Icons ---

    def _merge_custom_icons(self) -> None:
        """Merge custom icons from source to target."""
        for source_uuid, source_icon in self._source.custom_icons.items():
            if source_uuid in self._target.custom_icons:
                # Icon exists - check if source is newer
                target_icon = self._target.custom_icons[source_uuid]
                source_mtime = source_icon.last_modification_time
                target_mtime = target_icon.last_modification_time
                if source_mtime and target_mtime and source_mtime > target_mtime:
                    # Source is newer, update target
                    self._target._settings.custom_icons[source_uuid] = copy.deepcopy(source_icon)
            else:
                # New icon, add to target
                self._target._settings.custom_icons[source_uuid] = copy.deepcopy(source_icon)
                self._result.custom_icons_added += 1

    # --- Binaries ---

    def _merge_binaries(self) -> None:
        """Merge binary attachments, deduplicating by content hash."""
        # Build hash -> ref map for target binaries
        target_hashes: dict[bytes, int] = {}
        for ref, data in self._target._binaries.items():
            content_hash = hashlib.sha256(data).digest()
            target_hashes[content_hash] = ref

        # Process source binaries
        for source_ref, source_data in self._source._binaries.items():
            content_hash = hashlib.sha256(source_data).digest()
            if content_hash in target_hashes:
                # Duplicate content, reuse existing ref
                self._binary_remap[source_ref] = target_hashes[content_hash]
            else:
                # New binary, add to target
                new_ref = self._target.add_binary(source_data)
                self._binary_remap[source_ref] = new_ref
                target_hashes[content_hash] = new_ref
                self._result.binaries_added += 1

    def _remap_binary_refs(self, entry: Entry) -> None:
        """Remap binary references in an entry after merge."""
        for binary_ref in entry.binaries:
            if binary_ref.ref in self._binary_remap:
                binary_ref.ref = self._binary_remap[binary_ref.ref]

    # --- Groups ---

    def _merge_groups_recursive(
        self,
        target_group: Group,
        source_group: Group,
    ) -> None:
        """Recursively merge source group tree into target."""
        for source_subgroup in source_group.subgroups:
            # Skip recycle bin
            if self._is_recycle_bin(source_subgroup, self._source):
                continue

            # Find matching group in target
            target_subgroup = self._find_group_in_children(target_group, source_subgroup.uuid)

            if target_subgroup is None:
                # New group - clone and add
                new_group = self._clone_group(source_subgroup, recursive=True)
                target_group.add_subgroup(new_group)
                # Count all groups and entries in new group tree
                self._result.groups_added += 1
                for _ in new_group.iter_groups(recursive=True):
                    self._result.groups_added += 1
                for _ in new_group.iter_entries(recursive=True):
                    self._result.entries_added += 1
            else:
                # Existing group - update if source is newer
                if self._is_source_newer(target_subgroup.times, source_subgroup.times):
                    self._update_group_metadata(target_subgroup, source_subgroup)
                    self._result.groups_updated += 1

                # Recurse into subgroups
                self._merge_groups_recursive(target_subgroup, source_subgroup)

    def _find_group_in_children(self, parent: Group, uuid: uuid_module.UUID) -> Group | None:
        """Find a group by UUID in parent's children (non-recursive)."""
        for subgroup in parent.subgroups:
            if subgroup.uuid == uuid:
                return subgroup
        # Also check globally in case of restructuring
        return self._target.root_group.find_group_by_uuid(uuid, recursive=True)

    def _clone_group(self, group: Group, recursive: bool = False) -> Group:
        """Create a deep copy of a group."""
        new_group = Group(
            uuid=group.uuid,
            name=group.name,
            notes=group.notes,
            times=copy.deepcopy(group.times),
            icon_id=group.icon_id,
            custom_icon_uuid=group.custom_icon_uuid,
            is_expanded=group.is_expanded,
            default_autotype_sequence=group.default_autotype_sequence,
            enable_autotype=group.enable_autotype,
            enable_searching=group.enable_searching,
            last_top_visible_entry=group.last_top_visible_entry,
        )

        if recursive:
            for entry in group.entries:
                cloned_entry = self._clone_entry(entry)
                new_group.add_entry(cloned_entry)
            for subgroup in group.subgroups:
                if not self._is_recycle_bin(subgroup, self._source):
                    cloned_subgroup = self._clone_group(subgroup, recursive=True)
                    new_group.add_subgroup(cloned_subgroup)

        return new_group

    def _update_group_metadata(self, target: Group, source: Group) -> None:
        """Update target group metadata from source."""
        target.name = source.name
        target.notes = source.notes
        target.icon_id = source.icon_id
        target.custom_icon_uuid = source.custom_icon_uuid
        target.is_expanded = source.is_expanded
        target.default_autotype_sequence = source.default_autotype_sequence
        target.enable_autotype = source.enable_autotype
        target.enable_searching = source.enable_searching
        target.times = copy.deepcopy(source.times)

    # --- Entries ---

    def _merge_entries(self) -> None:
        """Merge all entries from source to target."""
        for source_entry in self._source.root_group.iter_entries(recursive=True):
            # Skip entries in recycle bin
            if self._is_in_recycle_bin(source_entry, self._source):
                continue

            target_entry = self._target.root_group.find_entry_by_uuid(source_entry.uuid)

            if target_entry is None:
                # New entry - add to target
                self._add_new_entry(source_entry)
            else:
                # Existing entry - merge
                self._merge_entry(target_entry, source_entry)

    def _add_new_entry(self, source_entry: Entry) -> None:
        """Add a new entry from source to target."""
        # Find or create parent group
        source_parent = source_entry.parent
        target_parent: Group
        if source_parent is None:
            target_parent = self._target.root_group
        else:
            found_parent = self._target.root_group.find_group_by_uuid(source_parent.uuid)
            if found_parent is None:
                # Parent group doesn't exist, create group path
                target_parent = self._ensure_group_path(source_parent)
            else:
                target_parent = found_parent

        # Clone entry and add
        new_entry = self._clone_entry(source_entry)
        target_parent.add_entry(new_entry)
        self._result.entries_added += 1

    def _merge_entry(self, target: Entry, source: Entry) -> None:
        """Merge source entry into target entry."""
        source_mtime = source.times.last_modification_time
        target_mtime = target.times.last_modification_time

        if source_mtime > target_mtime:
            # Source is newer - update target, preserve old in history
            target.save_history()
            self._copy_entry_fields(source, target)
            self._merge_entry_history(target, source)
            self._result.entries_updated += 1
        elif source_mtime < target_mtime:
            # Target is newer - add source to target's history
            history_entry = HistoryEntry.from_entry(source)
            target.history.append(history_entry)
            self._result.history_entries_merged += 1
        else:
            # Same timestamp - merge history only
            self._merge_entry_history(target, source)

    def _clone_entry(self, entry: Entry) -> Entry:
        """Create a deep copy of an entry with UUID preserved."""
        new_entry = Entry(
            uuid=entry.uuid,
            times=copy.deepcopy(entry.times),
            icon_id=entry.icon_id,
            custom_icon_uuid=entry.custom_icon_uuid,
            tags=list(entry.tags),
            strings={k: StringField(k, v.value, v.protected) for k, v in entry.strings.items()},
            binaries=[
                BinaryRef(b.key, self._binary_remap.get(b.ref, b.ref)) for b in entry.binaries
            ],
            autotype=copy.deepcopy(entry.autotype),
            history=[HistoryEntry.from_entry(h) for h in entry.history],
            foreground_color=entry.foreground_color,
            background_color=entry.background_color,
            override_url=entry.override_url,
            quality_check=entry.quality_check,
        )
        return new_entry

    def _copy_entry_fields(self, source: Entry, target: Entry) -> None:
        """Copy all fields from source to target, preserving target's UUID."""
        target.times = copy.deepcopy(source.times)
        target.icon_id = source.icon_id
        target.custom_icon_uuid = source.custom_icon_uuid
        target.tags = list(source.tags)
        target.strings = {
            k: StringField(k, v.value, v.protected) for k, v in source.strings.items()
        }
        target.binaries = [
            BinaryRef(b.key, self._binary_remap.get(b.ref, b.ref)) for b in source.binaries
        ]
        target.autotype = copy.deepcopy(source.autotype)
        target.foreground_color = source.foreground_color
        target.background_color = source.background_color
        target.override_url = source.override_url
        target.quality_check = source.quality_check

    # --- History ---

    def _merge_entry_history(self, target: Entry, source: Entry) -> None:
        """Merge history entries, deduplicating by modification time."""
        # Build map of existing history timestamps
        existing_times: set[datetime] = {h.times.last_modification_time for h in target.history}

        # Add source history entries not already present
        for hist in source.history:
            if hist.times.last_modification_time not in existing_times:
                cloned_hist = HistoryEntry.from_entry(hist)
                # Remap binary refs in history
                for binary_ref in cloned_hist.binaries:
                    if binary_ref.ref in self._binary_remap:
                        binary_ref.ref = self._binary_remap[binary_ref.ref]
                target.history.append(cloned_hist)
                existing_times.add(hist.times.last_modification_time)
                self._result.history_entries_merged += 1

        # Sort history by modification time
        target.history.sort(key=lambda h: h.times.last_modification_time)

        # Respect history_max_items if set
        max_items = self._target._settings.history_max_items
        if max_items >= 0 and len(target.history) > max_items:
            target.history = target.history[-max_items:]

    # --- Location Changes ---

    def _merge_locations(self) -> None:
        """Handle entry location changes based on location_changed timestamps."""
        for source_entry in self._source.root_group.iter_entries(recursive=True):
            if self._is_in_recycle_bin(source_entry, self._source):
                continue

            target_entry = self._target.root_group.find_entry_by_uuid(source_entry.uuid)
            if target_entry is None:
                continue

            source_loc_time = source_entry.times.location_changed
            target_loc_time = target_entry.times.location_changed

            if source_loc_time and target_loc_time and source_loc_time > target_loc_time:
                # Source location is newer - move entry
                source_parent = source_entry.parent
                if source_parent is not None:
                    target_parent = self._target.root_group.find_group_by_uuid(source_parent.uuid)
                    if target_parent is not None and target_entry.parent is not target_parent:
                        try:
                            target_entry.move_to(target_parent)
                            # Restore source location_changed time
                            target_entry.times.location_changed = source_loc_time
                            self._result.entries_relocated += 1
                        except ValueError:
                            # Move failed (e.g., already in destination)
                            pass

        # Also handle group location changes
        for source_group in self._source.root_group.iter_groups(recursive=True):
            if self._is_recycle_bin(source_group, self._source):
                continue

            target_group = self._target.root_group.find_group_by_uuid(source_group.uuid)
            if target_group is None or target_group.is_root_group:
                continue

            source_loc_time = source_group.times.location_changed
            target_loc_time = target_group.times.location_changed

            if source_loc_time and target_loc_time and source_loc_time > target_loc_time:
                source_parent = source_group.parent
                if source_parent is not None:
                    target_parent = self._target.root_group.find_group_by_uuid(source_parent.uuid)
                    if target_parent is not None and target_group.parent is not target_parent:
                        try:
                            target_group.move_to(target_parent)
                            target_group.times.location_changed = source_loc_time
                            self._result.groups_relocated += 1
                        except ValueError:
                            pass

    # --- Deletions (SYNCHRONIZE mode) ---

    def _apply_deletions(self) -> None:
        """Apply deletions from source in SYNCHRONIZE mode."""
        for deleted in self._source._settings.deleted_objects:
            # Try as entry first
            target_entry = self._target.root_group.find_entry_by_uuid(deleted.uuid)
            if (
                target_entry is not None
                and target_entry.times.last_modification_time <= deleted.deletion_time
                and target_entry.parent is not None
            ):
                target_entry.parent.remove_entry(target_entry)
                self._result.entries_deleted += 1
                continue

            # Try as group
            target_group = self._target.root_group.find_group_by_uuid(deleted.uuid)
            if (
                target_group is not None
                and not target_group.is_root_group
                and target_group.times.last_modification_time <= deleted.deletion_time
                and target_group.parent is not None
            ):
                target_group.parent.remove_subgroup(target_group)
                self._result.groups_deleted += 1

        # Merge deleted objects lists
        target_deleted_uuids = {d.uuid for d in self._target._settings.deleted_objects}
        for deleted in self._source._settings.deleted_objects:
            if deleted.uuid not in target_deleted_uuids:
                self._target._settings.deleted_objects.append(
                    DeletedObject(uuid=deleted.uuid, deletion_time=deleted.deletion_time)
                )

    # --- Helpers ---

    def _is_recycle_bin(self, group: Group, db: Database) -> bool:
        """Check if group is the recycle bin."""
        recycle_bin = db.recyclebin_group
        return recycle_bin is not None and group.uuid == recycle_bin.uuid

    def _is_in_recycle_bin(self, entry: Entry, db: Database) -> bool:
        """Check if entry is in the recycle bin."""
        recycle_bin = db.recyclebin_group
        if recycle_bin is None:
            return False
        current = entry.parent
        while current is not None:
            if current.uuid == recycle_bin.uuid:
                return True
            current = current.parent
        return False

    def _is_source_newer(self, target_times: Times, source_times: Times) -> bool:
        """Check if source has a newer modification time."""
        return source_times.last_modification_time > target_times.last_modification_time

    def _ensure_group_path(self, source_group: Group) -> Group:
        """Ensure the group path exists in target, creating groups as needed."""
        path = source_group.path
        current = self._target.root_group

        for name in path:
            found = None
            for subgroup in current.subgroups:
                if subgroup.name == name:
                    found = subgroup
                    break
            if found is None:
                found = current.create_subgroup(name)
                self._result.groups_added += 1
            current = found

        return current
