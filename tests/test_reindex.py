"""Tests for reindex operations (Entry and Group)."""

import pytest

from kdbxtool import Database, Entry, Group


class TestEntryIndex:
    """Tests for Entry.index property."""

    def test_index_returns_correct_position(self) -> None:
        """Test that index returns correct position."""
        db = Database.create(password="test")
        group = db.root_group.create_subgroup("Test")
        e0 = group.create_entry(title="Entry 0")
        e1 = group.create_entry(title="Entry 1")
        e2 = group.create_entry(title="Entry 2")

        assert e0.index == 0
        assert e1.index == 1
        assert e2.index == 2

    def test_index_no_parent_raises(self) -> None:
        """Test that index raises for orphan entry."""
        entry = Entry.create(title="Orphan")

        with pytest.raises(ValueError, match="no parent"):
            _ = entry.index


class TestEntryReindex:
    """Tests for Entry.reindex() method."""

    @pytest.fixture
    def group_with_entries(self) -> Group:
        """Create a group with 5 entries."""
        db = Database.create(password="test")
        group = db.root_group.create_subgroup("Test")
        for i in range(5):
            group.create_entry(title=f"Entry {i}")
        return group

    def test_reindex_move_forward(self, group_with_entries: Group) -> None:
        """Test moving an entry forward."""
        entries = group_with_entries.entries
        e0 = entries[0]

        e0.reindex(2)

        assert entries[0].title == "Entry 1"
        assert entries[1].title == "Entry 2"
        assert entries[2].title == "Entry 0"
        assert e0.index == 2

    def test_reindex_move_backward(self, group_with_entries: Group) -> None:
        """Test moving an entry backward."""
        entries = group_with_entries.entries
        e3 = entries[3]

        e3.reindex(1)

        assert entries[0].title == "Entry 0"
        assert entries[1].title == "Entry 3"
        assert entries[2].title == "Entry 1"
        assert e3.index == 1

    def test_reindex_to_first(self, group_with_entries: Group) -> None:
        """Test moving an entry to first position."""
        entries = group_with_entries.entries
        e4 = entries[4]

        e4.reindex(0)

        assert entries[0].title == "Entry 4"
        assert e4.index == 0

    def test_reindex_to_last(self, group_with_entries: Group) -> None:
        """Test moving an entry to last position."""
        entries = group_with_entries.entries
        e0 = entries[0]

        e0.reindex(4)

        assert entries[4].title == "Entry 0"
        assert e0.index == 4

    def test_reindex_same_position(self, group_with_entries: Group) -> None:
        """Test reindex to same position is no-op."""
        entries = group_with_entries.entries
        e2 = entries[2]
        original_order = [e.title for e in entries]

        e2.reindex(2)

        new_order = [e.title for e in entries]
        assert new_order == original_order

    def test_reindex_negative_index(self, group_with_entries: Group) -> None:
        """Test reindex with negative index."""
        entries = group_with_entries.entries
        e0 = entries[0]

        e0.reindex(-1)  # Move to last position

        assert entries[4].title == "Entry 0"
        assert e0.index == 4

    def test_reindex_out_of_bounds_raises(self, group_with_entries: Group) -> None:
        """Test that out-of-bounds index raises error."""
        e0 = group_with_entries.entries[0]

        with pytest.raises(IndexError):
            e0.reindex(10)

    def test_reindex_negative_out_of_bounds_raises(self, group_with_entries: Group) -> None:
        """Test that negative out-of-bounds index raises error."""
        e0 = group_with_entries.entries[0]

        with pytest.raises(IndexError):
            e0.reindex(-10)

    def test_reindex_no_parent_raises(self) -> None:
        """Test that reindex on orphan entry raises error."""
        entry = Entry.create(title="Orphan")

        with pytest.raises(ValueError, match="no parent"):
            entry.reindex(0)


class TestGroupIndex:
    """Tests for Group.index property."""

    def test_index_returns_correct_position(self) -> None:
        """Test that index returns correct position."""
        db = Database.create(password="test")
        g0 = db.root_group.create_subgroup("Group 0")
        g1 = db.root_group.create_subgroup("Group 1")
        g2 = db.root_group.create_subgroup("Group 2")

        # Note: Recycle Bin is at index 0
        assert g0.index == 1
        assert g1.index == 2
        assert g2.index == 3

    def test_index_root_group_raises(self) -> None:
        """Test that index raises for root group."""
        db = Database.create(password="test")

        with pytest.raises(ValueError, match="no parent"):
            _ = db.root_group.index


class TestGroupReindex:
    """Tests for Group.reindex() method."""

    @pytest.fixture
    def db_with_groups(self) -> Database:
        """Create a database with multiple groups."""
        db = Database.create(password="test")
        # Note: Recycle Bin already exists at index 0
        for i in range(5):
            db.root_group.create_subgroup(f"Group {i}")
        return db

    def test_reindex_move_forward(self, db_with_groups: Database) -> None:
        """Test moving a group forward."""
        subgroups = db_with_groups.root_group.subgroups
        # Groups: Recycle Bin, Group 0, Group 1, Group 2, Group 3, Group 4
        g1 = subgroups[2]  # Group 1

        g1.reindex(4)

        assert subgroups[2].name == "Group 2"
        assert subgroups[4].name == "Group 1"

    def test_reindex_move_backward(self, db_with_groups: Database) -> None:
        """Test moving a group backward."""
        subgroups = db_with_groups.root_group.subgroups
        g3 = subgroups[4]  # Group 3

        g3.reindex(1)

        assert subgroups[1].name == "Group 3"

    def test_reindex_same_position(self, db_with_groups: Database) -> None:
        """Test reindex to same position is no-op."""
        subgroups = db_with_groups.root_group.subgroups
        g2 = subgroups[3]  # Group 2
        original_order = [g.name for g in subgroups]

        g2.reindex(3)

        new_order = [g.name for g in subgroups]
        assert new_order == original_order

    def test_reindex_negative_index(self, db_with_groups: Database) -> None:
        """Test reindex with negative index."""
        subgroups = db_with_groups.root_group.subgroups
        g0 = subgroups[1]  # Group 0

        g0.reindex(-1)  # Move to last position

        assert subgroups[5].name == "Group 0"

    def test_reindex_out_of_bounds_raises(self, db_with_groups: Database) -> None:
        """Test that out-of-bounds index raises error."""
        g0 = db_with_groups.root_group.subgroups[1]

        with pytest.raises(IndexError):
            g0.reindex(10)

    def test_reindex_root_group_raises(self, db_with_groups: Database) -> None:
        """Test that reindex on root group raises error."""
        with pytest.raises(ValueError, match="no parent"):
            db_with_groups.root_group.reindex(0)


class TestReindexRoundtrip:
    """Tests for reindex persistence through save/load."""

    def test_entry_reindex_roundtrip(self) -> None:
        """Test that reindexed entries persist after save/load."""
        db = Database.create(password="test")
        group = db.root_group.create_subgroup("Test")
        group.create_entry(title="Entry 0")
        group.create_entry(title="Entry 1")
        group.create_entry(title="Entry 2")

        # Reorder: move Entry 2 to position 0
        group.entries[2].reindex(0)

        # Verify before save
        assert [e.title for e in group.entries] == ["Entry 2", "Entry 0", "Entry 1"]

        # Save and reload
        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        # Verify order persisted
        group2 = db2.find_groups(name="Test")[0]
        assert [e.title for e in group2.entries] == ["Entry 2", "Entry 0", "Entry 1"]

    def test_group_reindex_roundtrip(self) -> None:
        """Test that reindexed groups persist after save/load."""
        db = Database.create(password="test")
        db.root_group.create_subgroup("Group A")
        db.root_group.create_subgroup("Group B")
        db.root_group.create_subgroup("Group C")

        # Reorder: move Group C to position 1 (after Recycle Bin)
        subgroups = db.root_group.subgroups
        group_c = next(g for g in subgroups if g.name == "Group C")
        group_c.reindex(1)

        # Save and reload
        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        # Verify order persisted
        names = [g.name for g in db2.root_group.subgroups]
        assert names.index("Group C") < names.index("Group A")
        assert names.index("Group C") < names.index("Group B")
