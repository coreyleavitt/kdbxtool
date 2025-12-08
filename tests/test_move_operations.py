"""Tests for move entry/group operations."""

import time

import pytest

from kdbxtool import Database, Entry, Group


class TestEntryMoveTo:
    """Tests for Entry.move_to() method."""

    @pytest.fixture
    def db(self) -> Database:
        """Create a test database with groups and entries."""
        db = Database.create(password="test")
        # Create groups
        group_a = db.root_group.create_subgroup("Group A")
        group_b = db.root_group.create_subgroup("Group B")
        # Create entries
        group_a.create_entry(title="Entry 1", username="user1")
        group_a.create_entry(title="Entry 2", username="user2")
        return db

    def test_move_entry_to_different_group(self, db: Database) -> None:
        """Test moving an entry to a different group."""
        group_a = db.find_groups(name="Group A")[0]
        group_b = db.find_groups(name="Group B")[0]
        entry = db.find_entries(title="Entry 1")[0]

        # Sleep to ensure clock ticks between timestamp capture and operation
        # (Windows datetime.now() has ~15ms resolution and can return same value)
        time.sleep(0.002)
        original_location_changed = entry.times.location_changed

        time.sleep(0.002)
        entry.move_to(group_b)

        assert entry.parent is group_b
        assert entry in group_b.entries
        assert entry not in group_a.entries
        assert entry.times.location_changed > original_location_changed

    def test_move_entry_updates_timestamps(self, db: Database) -> None:
        """Test that moving entry updates timestamps correctly."""
        group_a = db.find_groups(name="Group A")[0]
        group_b = db.find_groups(name="Group B")[0]
        entry = db.find_entries(title="Entry 1")[0]

        # Sleep to ensure clock ticks between timestamp capture and operation
        # (Windows datetime.now() has ~15ms resolution and can return same value)
        time.sleep(0.002)
        old_group_a_mtime = group_a.times.last_modification_time
        old_group_b_mtime = group_b.times.last_modification_time

        time.sleep(0.002)
        entry.move_to(group_b)

        # Both groups should have updated modification times
        assert group_a.times.last_modification_time > old_group_a_mtime
        assert group_b.times.last_modification_time > old_group_b_mtime

    def test_move_entry_no_parent_raises(self) -> None:
        """Test that moving entry without parent raises error."""
        entry = Entry.create(title="Orphan")

        group = Group(name="Target")

        with pytest.raises(ValueError, match="no parent"):
            entry.move_to(group)

    def test_move_entry_to_same_group_raises(self, db: Database) -> None:
        """Test that moving entry to same group raises error."""
        group_a = db.find_groups(name="Group A")[0]
        entry = db.find_entries(title="Entry 1")[0]

        with pytest.raises(ValueError, match="already in"):
            entry.move_to(group_a)

    def test_move_entry_to_root_group(self, db: Database) -> None:
        """Test moving entry to root group."""
        entry = db.find_entries(title="Entry 1")[0]

        entry.move_to(db.root_group)

        assert entry.parent is db.root_group
        assert entry in db.root_group.entries


class TestGroupMoveTo:
    """Tests for Group.move_to() method."""

    @pytest.fixture
    def db(self) -> Database:
        """Create a test database with nested groups."""
        db = Database.create(password="test")
        # Create hierarchy: root -> A -> A1, A2
        #                   root -> B
        group_a = db.root_group.create_subgroup("Group A")
        group_a.create_subgroup("Group A1")
        group_a.create_subgroup("Group A2")
        db.root_group.create_subgroup("Group B")
        return db

    def test_move_group_to_different_parent(self, db: Database) -> None:
        """Test moving a group to a different parent."""
        group_a1 = db.find_groups(name="Group A1")[0]
        group_b = db.find_groups(name="Group B")[0]

        # Sleep to ensure clock ticks between timestamp capture and operation
        # (Windows datetime.now() has ~15ms resolution and can return same value)
        time.sleep(0.002)
        original_location_changed = group_a1.times.location_changed

        time.sleep(0.002)
        group_a1.move_to(group_b)

        assert group_a1.parent is group_b
        assert group_a1 in group_b.subgroups
        assert group_a1.times.location_changed > original_location_changed

    def test_move_group_to_root(self, db: Database) -> None:
        """Test moving a group to root."""
        group_a1 = db.find_groups(name="Group A1")[0]

        group_a1.move_to(db.root_group)

        assert group_a1.parent is db.root_group
        assert group_a1 in db.root_group.subgroups

    def test_move_root_group_raises(self, db: Database) -> None:
        """Test that moving root group raises error."""
        group_b = db.find_groups(name="Group B")[0]

        with pytest.raises(ValueError, match="root group"):
            db.root_group.move_to(group_b)

    def test_move_group_to_same_parent_raises(self, db: Database) -> None:
        """Test that moving group to same parent raises error."""
        group_a = db.find_groups(name="Group A")[0]

        with pytest.raises(ValueError, match="already in"):
            group_a.move_to(db.root_group)

    def test_move_group_into_itself_raises(self, db: Database) -> None:
        """Test that moving group into itself raises error."""
        group_a = db.find_groups(name="Group A")[0]

        with pytest.raises(ValueError, match="into itself"):
            group_a.move_to(group_a)

    def test_move_group_into_descendant_raises(self, db: Database) -> None:
        """Test that moving group into its descendant raises error."""
        group_a = db.find_groups(name="Group A")[0]
        group_a1 = db.find_groups(name="Group A1")[0]

        with pytest.raises(ValueError, match="cycle"):
            group_a.move_to(group_a1)

    def test_move_group_no_parent_raises(self) -> None:
        """Test that moving group without parent raises error."""
        group = Group(name="Orphan")
        target = Group(name="Target")

        with pytest.raises(ValueError, match="no parent"):
            group.move_to(target)


class TestDatabaseMoveEntry:
    """Tests for Database.move_entry() method."""

    @pytest.fixture
    def db(self) -> Database:
        """Create a test database."""
        db = Database.create(password="test")
        group_a = db.root_group.create_subgroup("Group A")
        db.root_group.create_subgroup("Group B")
        group_a.create_entry(title="Entry 1")
        return db

    def test_move_entry_via_database(self, db: Database) -> None:
        """Test moving entry using Database.move_entry()."""
        entry = db.find_entries(title="Entry 1")[0]
        group_b = db.find_groups(name="Group B")[0]

        db.move_entry(entry, group_b)

        assert entry.parent is group_b

    def test_move_entry_not_in_database_raises(self, db: Database) -> None:
        """Test that moving entry not in database raises error."""
        foreign_entry = Entry.create(title="Foreign")
        foreign_entry._parent = Group(name="Foreign Parent")
        group_b = db.find_groups(name="Group B")[0]

        with pytest.raises(ValueError, match="not in this database"):
            db.move_entry(foreign_entry, group_b)

    def test_move_entry_to_foreign_group_raises(self, db: Database) -> None:
        """Test that moving entry to foreign group raises error."""
        entry = db.find_entries(title="Entry 1")[0]
        foreign_group = Group(name="Foreign")

        with pytest.raises(ValueError, match="not in this database"):
            db.move_entry(entry, foreign_group)


class TestDatabaseMoveGroup:
    """Tests for Database.move_group() method."""

    @pytest.fixture
    def db(self) -> Database:
        """Create a test database."""
        db = Database.create(password="test")
        group_a = db.root_group.create_subgroup("Group A")
        group_a.create_subgroup("Group A1")
        db.root_group.create_subgroup("Group B")
        return db

    def test_move_group_via_database(self, db: Database) -> None:
        """Test moving group using Database.move_group()."""
        group_a1 = db.find_groups(name="Group A1")[0]
        group_b = db.find_groups(name="Group B")[0]

        db.move_group(group_a1, group_b)

        assert group_a1.parent is group_b

    def test_move_group_not_in_database_raises(self, db: Database) -> None:
        """Test that moving group not in database raises error."""
        foreign_group = Group(name="Foreign")
        foreign_group._parent = Group(name="Foreign Parent")
        group_b = db.find_groups(name="Group B")[0]

        with pytest.raises(ValueError, match="not in this database"):
            db.move_group(foreign_group, group_b)

    def test_move_group_to_foreign_parent_raises(self, db: Database) -> None:
        """Test that moving group to foreign parent raises error."""
        group_a1 = db.find_groups(name="Group A1")[0]
        foreign_group = Group(name="Foreign")

        with pytest.raises(ValueError, match="not in this database"):
            db.move_group(group_a1, foreign_group)

    def test_move_root_group_via_database_raises(self, db: Database) -> None:
        """Test that moving root group via database raises error."""
        group_b = db.find_groups(name="Group B")[0]

        with pytest.raises(ValueError, match="root group"):
            db.move_group(db.root_group, group_b)


class TestMoveRoundtrip:
    """Tests for moving entries/groups and saving the database."""

    def test_move_entry_roundtrip(self) -> None:
        """Test that moved entry is preserved after save/load."""
        db = Database.create(password="test")
        group_a = db.root_group.create_subgroup("Group A")
        group_b = db.root_group.create_subgroup("Group B")
        entry = group_a.create_entry(title="Test Entry", username="user")

        # Move entry
        entry.move_to(group_b)

        # Save and reload
        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        # Verify entry is in correct group
        group_b2 = db2.find_groups(name="Group B")[0]
        entries_in_b = list(group_b2.entries)
        assert len(entries_in_b) == 1
        assert entries_in_b[0].title == "Test Entry"

        group_a2 = db2.find_groups(name="Group A")[0]
        assert len(list(group_a2.entries)) == 0

    def test_move_group_roundtrip(self) -> None:
        """Test that moved group is preserved after save/load."""
        db = Database.create(password="test")
        group_a = db.root_group.create_subgroup("Group A")
        group_a1 = group_a.create_subgroup("Group A1")
        group_b = db.root_group.create_subgroup("Group B")

        # Move group A1 to B
        group_a1.move_to(group_b)

        # Save and reload
        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        # Verify group hierarchy
        group_b2 = db2.find_groups(name="Group B")[0]
        subgroups = list(group_b2.subgroups)
        assert len(subgroups) == 1
        assert subgroups[0].name == "Group A1"

        group_a2 = db2.find_groups(name="Group A")[0]
        assert len(list(group_a2.subgroups)) == 0
