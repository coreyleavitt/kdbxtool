"""Tests for empty group operation."""

import time

import pytest

from kdbxtool import Database, Group


class TestEmptyGroup:
    """Tests for Database.empty_group() method."""

    @pytest.fixture
    def db(self) -> Database:
        """Create a test database with nested structure."""
        db = Database.create(password="test")
        # Create hierarchy:
        # root -> Test Group -> Subgroup1 -> Deep Subgroup
        #                    -> Subgroup2
        #      -> Entry in Group
        group = db.root_group.create_subgroup("Test Group")
        sub1 = group.create_subgroup("Subgroup1")
        sub1.create_subgroup("Deep Subgroup")
        group.create_subgroup("Subgroup2")
        group.create_entry(title="Entry 1", username="user1")
        group.create_entry(title="Entry 2", username="user2")
        return db

    def test_empty_group_removes_entries(self, db: Database) -> None:
        """Test that empty_group removes all entries."""
        group = db.find_groups(name="Test Group")[0]
        assert len(list(group.entries)) == 2

        db.empty_group(group)

        assert len(list(group.entries)) == 0

    def test_empty_group_removes_subgroups(self, db: Database) -> None:
        """Test that empty_group removes all subgroups."""
        group = db.find_groups(name="Test Group")[0]
        assert len(list(group.subgroups)) == 2

        db.empty_group(group)

        assert len(list(group.subgroups)) == 0

    def test_empty_group_preserves_group(self, db: Database) -> None:
        """Test that empty_group does not delete the group itself."""
        group = db.find_groups(name="Test Group")[0]

        db.empty_group(group)

        # Group should still exist
        found = db.find_groups(name="Test Group")
        assert len(found) == 1
        assert found[0] is group

    def test_empty_group_on_root(self, db: Database) -> None:
        """Test that empty_group works on root group."""
        # Root has Test Group and Recycle Bin
        initial_count = len(list(db.root_group.subgroups))
        assert initial_count >= 1

        db.empty_group(db.root_group)

        assert len(list(db.root_group.subgroups)) == 0
        assert len(list(db.root_group.entries)) == 0

    def test_empty_group_already_empty(self, db: Database) -> None:
        """Test that empty_group on empty group is a no-op."""
        group = db.root_group.create_subgroup("Empty Group")
        assert len(list(group.entries)) == 0
        assert len(list(group.subgroups)) == 0

        # Should not raise
        db.empty_group(group)

        assert len(list(group.entries)) == 0
        assert len(list(group.subgroups)) == 0

    def test_empty_group_foreign_group_raises(self, db: Database) -> None:
        """Test that empty_group raises for foreign group."""
        foreign_group = Group(name="Foreign")

        with pytest.raises(ValueError, match="not in this database"):
            db.empty_group(foreign_group)

    def test_empty_group_updates_parent_timestamp(self, db: Database) -> None:
        """Test that empty_group updates group modification time."""
        group = db.find_groups(name="Test Group")[0]

        # Sleep to ensure clock ticks between timestamp capture and operation
        # (Windows datetime.now() has ~15ms resolution and can return same value)
        time.sleep(0.002)
        old_mtime = group.times.last_modification_time

        time.sleep(0.002)
        db.empty_group(group)

        assert group.times.last_modification_time > old_mtime


class TestEmptyGroupRoundtrip:
    """Tests for empty_group persistence through save/load."""

    def test_empty_group_roundtrip(self) -> None:
        """Test that emptied group stays empty after save/load."""
        db = Database.create(password="test")
        group = db.root_group.create_subgroup("Test Group")
        group.create_entry(title="Entry 1")
        group.create_subgroup("Subgroup 1")

        # Verify initial state
        assert len(list(group.entries)) == 1
        assert len(list(group.subgroups)) == 1

        # Empty the group
        db.empty_group(group)

        # Save and reload
        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        # Group should still exist but be empty
        groups = db2.find_groups(name="Test Group")
        assert len(groups) == 1
        reloaded_group = groups[0]
        assert len(list(reloaded_group.entries)) == 0
        assert len(list(reloaded_group.subgroups)) == 0
