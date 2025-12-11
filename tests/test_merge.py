"""Tests for database merge functionality."""

from datetime import UTC, datetime, timedelta

import pytest

from kdbxtool import Database, MergeMode, MergeResult
from kdbxtool.merge import DeletedObject, Merger


class TestMergeBasic:
    """Basic merge operation tests."""

    def test_merge_new_entry(self) -> None:
        """Test that new entries from source are added to target."""
        target = Database.create(password="test")
        source = Database.create(password="test")

        # Add entry to source only
        source.root_group.create_entry(title="Source Entry", username="user1")

        result = target.merge(source)

        assert result.entries_added == 1
        found = target.find_entries(title="Source Entry", first=True)
        assert found is not None
        assert found.username == "user1"

    def test_merge_new_group(self) -> None:
        """Test that new groups from source are added to target."""
        target = Database.create(password="test")
        source = Database.create(password="test")

        # Add group to source only
        source.root_group.create_subgroup("New Group")

        result = target.merge(source)

        assert result.groups_added == 1
        found = target.find_groups(name="New Group", first=True)
        assert found is not None

    def test_merge_identical_databases(self) -> None:
        """Test that merging identical databases produces no changes."""
        target = Database.create(password="test")
        entry = target.root_group.create_entry(title="Test", username="user")

        # Create source with same UUID and timestamps
        source = Database.create(password="test")
        source_entry = source.root_group.create_entry(title="Test", username="user")
        # Set same UUID
        source_entry.uuid = entry.uuid
        source_entry.times = entry.times

        result = target.merge(source)

        # No changes expected (same timestamps)
        assert result.entries_added == 0
        assert result.entries_updated == 0

    def test_merge_empty_source(self) -> None:
        """Test merging from empty source database."""
        target = Database.create(password="test")
        target.root_group.create_entry(title="Target Entry")
        source = Database.create(password="test")

        result = target.merge(source)

        assert not result.has_changes
        assert result.total_changes == 0

    def test_merge_into_empty_target(self) -> None:
        """Test merging into empty target database."""
        target = Database.create(password="test")
        source = Database.create(password="test")
        source.root_group.create_entry(title="Entry 1")
        source.root_group.create_entry(title="Entry 2")
        source.root_group.create_subgroup("Group 1")

        result = target.merge(source)

        assert result.entries_added == 2
        assert result.groups_added == 1


class TestMergeConflicts:
    """Conflict resolution tests."""

    def test_merge_source_newer_wins(self) -> None:
        """Test that source entry wins when it has newer modification time."""
        target = Database.create(password="test")
        source = Database.create(password="test")

        # Create entry in target
        target_entry = target.root_group.create_entry(
            title="Entry", username="old_user", password="old_pass"
        )
        entry_uuid = target_entry.uuid

        # Create same entry in source with newer timestamp
        source_entry = source.root_group.create_entry(
            title="Entry", username="new_user", password="new_pass"
        )
        source_entry.uuid = entry_uuid
        source_entry.times.last_modification_time = (
            target_entry.times.last_modification_time + timedelta(hours=1)
        )

        result = target.merge(source)

        assert result.entries_updated == 1
        found = target.find_entries(uuid=entry_uuid, first=True)
        assert found is not None
        assert found.username == "new_user"
        assert found.password == "new_pass"

    def test_merge_target_newer_preserves(self) -> None:
        """Test that target entry is preserved when it has newer modification time."""
        target = Database.create(password="test")
        source = Database.create(password="test")

        # Create entry in target with newer timestamp
        target_entry = target.root_group.create_entry(title="Entry", username="target_user")
        entry_uuid = target_entry.uuid
        target_entry.times.last_modification_time = datetime.now(UTC) + timedelta(hours=1)

        # Create same entry in source with older timestamp
        source_entry = source.root_group.create_entry(title="Entry", username="source_user")
        source_entry.uuid = entry_uuid
        source_entry.times.last_modification_time = datetime.now(UTC) - timedelta(hours=1)

        result = target.merge(source)

        found = target.find_entries(uuid=entry_uuid, first=True)
        assert found is not None
        assert found.username == "target_user"
        # Source should be added to history
        assert result.history_entries_merged >= 1

    def test_merge_same_timestamp_no_change(self) -> None:
        """Test that equal timestamps result in no update."""
        target = Database.create(password="test")
        source = Database.create(password="test")

        timestamp = datetime.now(UTC)

        target_entry = target.root_group.create_entry(title="Entry", username="user")
        entry_uuid = target_entry.uuid
        target_entry.times.last_modification_time = timestamp

        source_entry = source.root_group.create_entry(title="Entry", username="same_user")
        source_entry.uuid = entry_uuid
        source_entry.times.last_modification_time = timestamp

        result = target.merge(source)

        assert result.entries_updated == 0


class TestMergeGroups:
    """Group merging tests."""

    def test_merge_creates_missing_groups(self) -> None:
        """Test that missing groups are created during merge."""
        target = Database.create(password="test")
        source = Database.create(password="test")

        # Create nested groups in source
        work = source.root_group.create_subgroup("Work")
        projects = work.create_subgroup("Projects")
        projects.create_entry(title="Project Entry")

        result = target.merge(source)

        assert result.groups_added >= 2
        found = target.find_groups(name="Projects", first=True)
        assert found is not None
        assert found.parent.name == "Work"

    def test_merge_nested_groups(self) -> None:
        """Test deep group hierarchy merging."""
        target = Database.create(password="test")
        source = Database.create(password="test")

        # Create deep hierarchy
        level1 = source.root_group.create_subgroup("Level1")
        level2 = level1.create_subgroup("Level2")
        level3 = level2.create_subgroup("Level3")
        level3.create_entry(title="Deep Entry")

        result = target.merge(source)

        assert result.groups_added == 3
        assert result.entries_added == 1
        deep_entry = target.find_entries(title="Deep Entry", first=True)
        assert deep_entry is not None
        assert deep_entry.parent.name == "Level3"

    def test_merge_updates_group_metadata(self) -> None:
        """Test that group metadata is updated when source is newer."""
        target = Database.create(password="test")
        source = Database.create(password="test")

        # Create same group in both
        target_group = target.root_group.create_subgroup("Group")
        target_group.notes = "old notes"
        group_uuid = target_group.uuid

        source_group = source.root_group.create_subgroup("Group")
        source_group.uuid = group_uuid
        source_group.notes = "new notes"
        source_group.times.last_modification_time = (
            target_group.times.last_modification_time + timedelta(hours=1)
        )

        result = target.merge(source)

        found = target.find_groups(name="Group", first=True)
        assert found is not None
        assert found.notes == "new notes"
        assert result.groups_updated == 1

    def test_merge_skips_recycle_bin(self) -> None:
        """Test that recycle bin contents are not merged."""
        target = Database.create(password="test")
        source = Database.create(password="test")

        # Create entry in source's recycle bin
        source_entry = source.root_group.create_entry(title="Trashed Entry")
        source.trash_entry(source_entry)

        result = target.merge(source)

        # Trashed entry should not be merged
        found = target.find_entries(title="Trashed Entry", first=True)
        assert found is None


class TestMergeHistory:
    """History merging tests."""

    def test_losing_version_goes_to_history(self) -> None:
        """Test that the losing version is preserved in history."""
        target = Database.create(password="test")
        source = Database.create(password="test")

        # Create entry in target
        target_entry = target.root_group.create_entry(title="Entry", username="old")
        entry_uuid = target_entry.uuid

        # Create same entry in source with newer timestamp
        source_entry = source.root_group.create_entry(title="Entry", username="new")
        source_entry.uuid = entry_uuid
        source_entry.times.last_modification_time = (
            target_entry.times.last_modification_time + timedelta(hours=1)
        )

        target.merge(source)

        found = target.find_entries(uuid=entry_uuid, first=True)
        assert found is not None
        assert found.username == "new"
        # Old version should be in history
        assert len(found.history) >= 1
        old_version = found.history[-1]
        assert old_version.username == "old"

    def test_history_deduplication(self) -> None:
        """Test that duplicate history entries are not created."""
        target = Database.create(password="test")
        source = Database.create(password="test")

        timestamp = datetime.now(UTC)

        # Create entry with history in target
        target_entry = target.root_group.create_entry(title="Entry")
        target_entry.save_history()
        target_entry.username = "v2"
        entry_uuid = target_entry.uuid

        # Create same entry with same history in source
        source_entry = source.root_group.create_entry(title="Entry")
        source_entry.uuid = entry_uuid
        source_entry.times = target_entry.times
        # Add same history entry
        for hist in target_entry.history:
            from kdbxtool.models.entry import HistoryEntry

            source_entry.history.append(HistoryEntry.from_entry(hist))

        initial_history_count = len(target_entry.history)
        target.merge(source)

        found = target.find_entries(uuid=entry_uuid, first=True)
        assert found is not None
        # History count should not increase (duplicates filtered)
        assert len(found.history) == initial_history_count

    def test_history_combined_from_both(self) -> None:
        """Test that unique history from both databases is combined."""
        target = Database.create(password="test")
        source = Database.create(password="test")

        base_time = datetime.now(UTC)

        # Create entry in target with one history entry
        target_entry = target.root_group.create_entry(title="Entry", username="v1")
        target_entry.times.last_modification_time = base_time
        target_entry.save_history()
        target_entry.username = "v2"
        target_entry.times.last_modification_time = base_time + timedelta(hours=1)
        entry_uuid = target_entry.uuid

        # Create same entry in source with different history
        source_entry = source.root_group.create_entry(title="Entry", username="v0")
        source_entry.uuid = entry_uuid
        source_entry.times.last_modification_time = base_time - timedelta(hours=1)
        source_entry.save_history()
        source_entry.username = "v3"
        source_entry.times.last_modification_time = base_time + timedelta(hours=2)

        target.merge(source)

        found = target.find_entries(uuid=entry_uuid, first=True)
        assert found is not None
        # Should have history from both
        assert len(found.history) >= 2


class TestMergeBinaries:
    """Binary attachment merging tests."""

    def test_merge_new_binary(self) -> None:
        """Test that new binaries are added."""
        target = Database.create(password="test")
        source = Database.create(password="test")

        # Add entry with attachment in source
        source_entry = source.root_group.create_entry(title="Entry")
        source.add_attachment(source_entry, "test.txt", b"Hello World")

        result = target.merge(source)

        assert result.binaries_added == 1
        found = target.find_entries(title="Entry", first=True)
        assert found is not None
        assert len(found.binaries) == 1
        data = target.get_attachment(found, "test.txt")
        assert data == b"Hello World"

    def test_merge_duplicate_binary_deduplicated(self) -> None:
        """Test that duplicate binary content is deduplicated."""
        target = Database.create(password="test")
        source = Database.create(password="test")

        same_content = b"Same content in both"

        # Add same binary to target
        target_entry = target.root_group.create_entry(title="Target Entry")
        target.add_attachment(target_entry, "target.txt", same_content)

        # Add same binary to source (different name)
        source_entry = source.root_group.create_entry(title="Source Entry")
        source.add_attachment(source_entry, "source.txt", same_content)

        result = target.merge(source)

        # Binary should be deduplicated (same content hash)
        assert result.binaries_added == 0

        # Both entries should reference the same binary
        target_found = target.find_entries(title="Target Entry", first=True)
        source_found = target.find_entries(title="Source Entry", first=True)
        assert target_found is not None and source_found is not None

        target_data = target.get_attachment(target_found, "target.txt")
        source_data = target.get_attachment(source_found, "source.txt")
        assert target_data == source_data == same_content


class TestMergeCustomIcons:
    """Custom icon merging tests."""

    def test_merge_new_icon(self) -> None:
        """Test that new custom icons are added."""
        target = Database.create(password="test")
        source = Database.create(password="test")

        # Add custom icon to source
        icon_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100  # Fake PNG
        icon_uuid = source.add_custom_icon(icon_data, "test_icon")

        # Use icon on an entry
        source_entry = source.root_group.create_entry(title="Entry")
        source_entry.custom_icon_uuid = icon_uuid

        result = target.merge(source)

        assert result.custom_icons_added == 1
        assert icon_uuid in target.custom_icons
        assert target.get_custom_icon(icon_uuid) == icon_data


class TestMergeLocation:
    """Location tracking tests."""

    def test_merge_entry_moved_in_source(self) -> None:
        """Test that entry location change is detected."""
        target = Database.create(password="test")
        source = Database.create(password="test")

        base_time = datetime.now(UTC)

        # Create group and entry in target (entry at root level)
        group = target.root_group.create_subgroup("Group")
        entry = target.root_group.create_entry(title="Entry")
        entry.times.last_modification_time = base_time
        entry.times.location_changed = base_time
        entry_uuid = entry.uuid
        group_uuid = group.uuid

        # In source, create matching group and entry, but entry is IN the group
        # with a newer location_changed timestamp
        source_group = source.root_group.create_subgroup("Group")
        source_group.uuid = group_uuid
        source_group.times = group.times  # Same timestamps

        # Create entry directly in source_group
        source_entry = source_group.create_entry(title="Entry")
        source_entry.uuid = entry_uuid
        # Set timestamps AFTER creation to control them precisely
        source_entry.times.last_modification_time = base_time  # Same mod time as target
        source_entry.times.location_changed = base_time + timedelta(hours=1)  # Newer location

        result = target.merge(source)

        assert result.entries_relocated == 1
        found = target.find_entries(uuid=entry_uuid, first=True)
        assert found is not None
        assert found.parent.uuid == group_uuid


class TestMergeSynchronize:
    """SYNCHRONIZE mode tests."""

    def test_synchronize_deletes_entry(self) -> None:
        """Test that deleted entries are removed in SYNCHRONIZE mode."""
        target = Database.create(password="test")
        source = Database.create(password="test")

        # Create entry in target
        entry = target.root_group.create_entry(title="To Delete")
        entry_uuid = entry.uuid

        # In source, entry is marked as deleted
        deletion_time = datetime.now(UTC) + timedelta(hours=1)
        source._settings.deleted_objects.append(
            DeletedObject(uuid=entry_uuid, deletion_time=deletion_time)
        )

        result = target.merge(source, mode=MergeMode.SYNCHRONIZE)

        assert result.entries_deleted == 1
        found = target.find_entries(uuid=entry_uuid, first=True)
        assert found is None

    def test_synchronize_keeps_modified_entry(self) -> None:
        """Test that modified entries are not deleted even if in DeletedObjects."""
        target = Database.create(password="test")
        source = Database.create(password="test")

        # Create entry in target with recent modification
        entry = target.root_group.create_entry(title="Modified")
        entry_uuid = entry.uuid
        entry.times.last_modification_time = datetime.now(UTC) + timedelta(hours=2)

        # In source, entry was deleted earlier
        deletion_time = datetime.now(UTC)
        source._settings.deleted_objects.append(
            DeletedObject(uuid=entry_uuid, deletion_time=deletion_time)
        )

        result = target.merge(source, mode=MergeMode.SYNCHRONIZE)

        # Entry should NOT be deleted because it was modified after deletion
        assert result.entries_deleted == 0
        found = target.find_entries(uuid=entry_uuid, first=True)
        assert found is not None

    def test_standard_mode_no_deletions(self) -> None:
        """Test that STANDARD mode never deletes entries."""
        target = Database.create(password="test")
        source = Database.create(password="test")

        # Create entry in target
        entry = target.root_group.create_entry(title="To Delete")
        entry_uuid = entry.uuid

        # In source, entry is marked as deleted
        deletion_time = datetime.now(UTC) + timedelta(hours=1)
        source._settings.deleted_objects.append(
            DeletedObject(uuid=entry_uuid, deletion_time=deletion_time)
        )

        result = target.merge(source, mode=MergeMode.STANDARD)

        # STANDARD mode should never delete
        assert result.entries_deleted == 0
        found = target.find_entries(uuid=entry_uuid, first=True)
        assert found is not None


class TestMergeResult:
    """MergeResult dataclass tests."""

    def test_has_changes_true(self) -> None:
        """Test has_changes returns True when changes exist."""
        result = MergeResult(entries_added=1)
        assert result.has_changes

    def test_has_changes_false(self) -> None:
        """Test has_changes returns False when no changes."""
        result = MergeResult()
        assert not result.has_changes

    def test_total_changes(self) -> None:
        """Test total_changes calculation."""
        result = MergeResult(
            entries_added=2,
            entries_updated=3,
            groups_added=1,
        )
        assert result.total_changes == 6

    def test_summary_format(self) -> None:
        """Test summary produces readable output."""
        result = MergeResult(entries_added=5, groups_added=2)
        summary = result.summary()
        assert "5 entries" in summary
        assert "2 groups" in summary


class TestMergeEdgeCases:
    """Edge case tests."""

    def test_merge_different_root_uuids(self) -> None:
        """Test merging databases with different root UUIDs."""
        target = Database.create(password="test")
        source = Database.create(password="test")

        # Root UUIDs will be different by default
        assert target.root_group.uuid != source.root_group.uuid

        # Add content to source
        source.root_group.create_entry(title="Entry")
        source.root_group.create_subgroup("Group")

        # Should still merge successfully
        result = target.merge(source)
        assert result.entries_added == 1
        assert result.groups_added == 1

    def test_merge_preserves_references(self) -> None:
        """Test that field references still work after merge."""
        target = Database.create(password="test")
        source = Database.create(password="test")

        # Create referenced entry in source
        main = source.root_group.create_entry(title="Main", password="secret123")
        main_uuid = main.uuid

        # Create referencing entry
        ref_entry = source.root_group.create_entry(title="Reference")
        ref_entry.password = main.ref("password")

        target.merge(source)

        # Find entries in target
        target_ref = target.find_entries(title="Reference", first=True)
        assert target_ref is not None

        # Reference should resolve
        resolved = target_ref.deref("password")
        assert resolved == "secret123"

    def test_merge_returns_result(self) -> None:
        """Test that merge returns MergeResult instance."""
        target = Database.create(password="test")
        source = Database.create(password="test")

        result = target.merge(source)

        assert isinstance(result, MergeResult)


class TestMerger:
    """Direct Merger class tests."""

    def test_merger_init(self) -> None:
        """Test Merger initialization."""
        target = Database.create(password="test")
        source = Database.create(password="test")

        merger = Merger(target, source)
        assert merger._target is target
        assert merger._source is source
        assert merger._mode == MergeMode.STANDARD

    def test_merger_custom_mode(self) -> None:
        """Test Merger with custom mode."""
        target = Database.create(password="test")
        source = Database.create(password="test")

        merger = Merger(target, source, mode=MergeMode.SYNCHRONIZE)
        assert merger._mode == MergeMode.SYNCHRONIZE
