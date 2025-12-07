"""Tests for recycle bin (trash) operations."""

import pytest

from kdbxtool import Database, Entry, Group


class TestRecyclebinGroup:
    """Tests for Database.recyclebin_group property."""

    def test_recyclebin_group_creates_if_missing(self) -> None:
        """Test that recyclebin_group creates recycle bin if missing."""
        db = Database.create(password="test")
        # Remove the default recycle bin
        for group in list(db.root_group.subgroups):
            if group.name == "Recycle Bin":
                db.root_group.remove_subgroup(group)
        db.settings.recycle_bin_uuid = None

        recycle_bin = db.recyclebin_group

        assert recycle_bin is not None
        assert recycle_bin.name == "Recycle Bin"
        assert recycle_bin in db.root_group.subgroups
        assert db.settings.recycle_bin_uuid == recycle_bin.uuid

    def test_recyclebin_group_returns_existing(self) -> None:
        """Test that recyclebin_group returns existing recycle bin."""
        db = Database.create(password="test")
        recycle_bin1 = db.recyclebin_group
        recycle_bin2 = db.recyclebin_group

        assert recycle_bin1 is recycle_bin2

    def test_recyclebin_group_returns_none_when_disabled(self) -> None:
        """Test that recyclebin_group returns None when disabled."""
        db = Database.create(password="test")
        db.settings.recycle_bin_enabled = False

        assert db.recyclebin_group is None

    def test_recyclebin_group_icon(self) -> None:
        """Test that recycle bin has correct icon."""
        db = Database.create(password="test")
        # Remove existing and reset
        for group in list(db.root_group.subgroups):
            if group.name == "Recycle Bin":
                db.root_group.remove_subgroup(group)
        db.settings.recycle_bin_uuid = None

        recycle_bin = db.recyclebin_group

        assert recycle_bin.icon_id == "43"  # Trash icon


class TestTrashEntry:
    """Tests for Database.trash_entry() method."""

    @pytest.fixture
    def db(self) -> Database:
        """Create a test database with entries."""
        db = Database.create(password="test")
        group = db.root_group.create_subgroup("Test Group")
        group.create_entry(title="Entry 1")
        group.create_entry(title="Entry 2")
        return db

    def test_trash_entry_moves_to_recycle_bin(self, db: Database) -> None:
        """Test that trash_entry moves entry to recycle bin."""
        entry = db.find_entries(title="Entry 1")[0]
        original_group = entry.parent

        db.trash_entry(entry)

        recycle_bin = db.recyclebin_group
        assert entry.parent is recycle_bin
        assert entry in recycle_bin.entries
        assert entry not in original_group.entries

    def test_trash_entry_deletes_if_already_in_bin(self, db: Database) -> None:
        """Test that trashing entry in recycle bin deletes it permanently."""
        entry = db.find_entries(title="Entry 1")[0]

        # First trash moves to recycle bin
        db.trash_entry(entry)
        recycle_bin = db.recyclebin_group
        assert entry in recycle_bin.entries

        # Second trash permanently deletes
        db.trash_entry(entry)
        assert entry not in recycle_bin.entries
        assert db.find_entries(title="Entry 1") == []

    def test_trash_entry_raises_if_not_in_database(self, db: Database) -> None:
        """Test that trash_entry raises if entry not in database."""
        foreign_entry = Entry.create(title="Foreign")
        foreign_entry._parent = Group(name="Foreign")

        with pytest.raises(ValueError, match="not in this database"):
            db.trash_entry(foreign_entry)

    def test_trash_entry_raises_if_disabled(self, db: Database) -> None:
        """Test that trash_entry raises if recycle bin disabled."""
        db.settings.recycle_bin_enabled = False
        entry = db.find_entries(title="Entry 1")[0]

        with pytest.raises(ValueError, match="disabled"):
            db.trash_entry(entry)


class TestTrashGroup:
    """Tests for Database.trash_group() method."""

    @pytest.fixture
    def db(self) -> Database:
        """Create a test database with groups."""
        db = Database.create(password="test")
        group = db.root_group.create_subgroup("Test Group")
        group.create_subgroup("Subgroup")
        group.create_entry(title="Entry in Group")
        return db

    def test_trash_group_moves_to_recycle_bin(self, db: Database) -> None:
        """Test that trash_group moves group to recycle bin."""
        group = db.find_groups(name="Test Group")[0]

        db.trash_group(group)

        recycle_bin = db.recyclebin_group
        assert group.parent is recycle_bin
        assert group in recycle_bin.subgroups

    def test_trash_group_preserves_contents(self, db: Database) -> None:
        """Test that trashing group preserves its contents."""
        group = db.find_groups(name="Test Group")[0]
        subgroup = db.find_groups(name="Subgroup")[0]
        entry = db.find_entries(title="Entry in Group")[0]

        db.trash_group(group)

        # Contents should still be there
        assert subgroup in group.subgroups
        assert entry in group.entries

    def test_trash_group_deletes_if_already_in_bin(self, db: Database) -> None:
        """Test that trashing group in recycle bin deletes it permanently."""
        group = db.find_groups(name="Test Group")[0]

        # First trash moves to recycle bin
        db.trash_group(group)
        recycle_bin = db.recyclebin_group
        assert group in recycle_bin.subgroups

        # Second trash permanently deletes
        db.trash_group(group)
        assert group not in recycle_bin.subgroups
        assert db.find_groups(name="Test Group") == []

    def test_trash_root_group_raises(self, db: Database) -> None:
        """Test that trash_group raises for root group."""
        with pytest.raises(ValueError, match="root group"):
            db.trash_group(db.root_group)

    def test_trash_recycle_bin_raises(self, db: Database) -> None:
        """Test that trash_group raises for recycle bin itself."""
        recycle_bin = db.recyclebin_group

        with pytest.raises(ValueError, match="Cannot trash the recycle bin"):
            db.trash_group(recycle_bin)

    def test_trash_group_raises_if_not_in_database(self, db: Database) -> None:
        """Test that trash_group raises if group not in database."""
        foreign_group = Group(name="Foreign")
        foreign_group._parent = Group(name="Foreign Parent")

        with pytest.raises(ValueError, match="not in this database"):
            db.trash_group(foreign_group)

    def test_trash_group_raises_if_disabled(self, db: Database) -> None:
        """Test that trash_group raises if recycle bin disabled."""
        db.settings.recycle_bin_enabled = False
        group = db.find_groups(name="Test Group")[0]

        with pytest.raises(ValueError, match="disabled"):
            db.trash_group(group)


class TestRecycleBinRoundtrip:
    """Tests for recycle bin persistence through save/load."""

    def test_trash_entry_roundtrip(self) -> None:
        """Test that trashed entry is in recycle bin after save/load."""
        db = Database.create(password="test")
        group = db.root_group.create_subgroup("Test Group")
        entry = group.create_entry(title="Test Entry")

        db.trash_entry(entry)

        # Save and reload
        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        # Entry should be in recycle bin
        recycle_bin = db2.recyclebin_group
        entries_in_bin = list(recycle_bin.entries)
        assert len(entries_in_bin) == 1
        assert entries_in_bin[0].title == "Test Entry"

        # Original group should be empty
        test_group = db2.find_groups(name="Test Group")[0]
        assert len(list(test_group.entries)) == 0

    def test_trash_group_roundtrip(self) -> None:
        """Test that trashed group is in recycle bin after save/load."""
        db = Database.create(password="test")
        group = db.root_group.create_subgroup("Test Group")
        group.create_entry(title="Entry in Group")

        db.trash_group(group)

        # Save and reload
        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        # Group should be in recycle bin
        recycle_bin = db2.recyclebin_group
        groups_in_bin = [g for g in recycle_bin.subgroups if g.name == "Test Group"]
        assert len(groups_in_bin) == 1

        # Entry should still be in the group
        trashed_group = groups_in_bin[0]
        assert len(list(trashed_group.entries)) == 1
        assert list(trashed_group.entries)[0].title == "Entry in Group"

    def test_recyclebin_uuid_persists(self) -> None:
        """Test that recycle bin UUID persists through save/load."""
        db = Database.create(password="test")
        recycle_bin = db.recyclebin_group
        original_uuid = recycle_bin.uuid

        # Save and reload
        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        # UUID should be preserved
        assert db2.settings.recycle_bin_uuid == original_uuid
        assert db2.recyclebin_group.uuid == original_uuid
