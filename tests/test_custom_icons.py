"""Tests for custom icon support."""

import uuid

import pytest

from kdbxtool import Database
from kdbxtool.database import CustomIcon


# Minimal valid PNG (1x1 transparent pixel)
MINIMAL_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
    b"\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
    b"\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01"
    b"\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
)


class TestCustomIconDataclass:
    """Tests for CustomIcon dataclass."""

    def test_create_custom_icon(self) -> None:
        """Test creating a CustomIcon instance."""
        icon_uuid = uuid.uuid4()
        icon = CustomIcon(
            uuid=icon_uuid,
            data=MINIMAL_PNG,
            name="Test Icon",
        )

        assert icon.uuid == icon_uuid
        assert icon.data == MINIMAL_PNG
        assert icon.name == "Test Icon"
        assert icon.last_modification_time is None

    def test_custom_icon_defaults(self) -> None:
        """Test CustomIcon default values."""
        icon_uuid = uuid.uuid4()
        icon = CustomIcon(uuid=icon_uuid, data=MINIMAL_PNG)

        assert icon.name is None
        assert icon.last_modification_time is None


class TestAddCustomIcon:
    """Tests for Database.add_custom_icon()."""

    def test_add_custom_icon(self) -> None:
        """Test adding a custom icon."""
        db = Database.create(password="test")

        icon_uuid = db.add_custom_icon(MINIMAL_PNG)

        assert icon_uuid in db.custom_icons
        assert db.custom_icons[icon_uuid].data == MINIMAL_PNG
        assert db.custom_icons[icon_uuid].last_modification_time is not None

    def test_add_custom_icon_with_name(self) -> None:
        """Test adding a custom icon with name."""
        db = Database.create(password="test")

        icon_uuid = db.add_custom_icon(MINIMAL_PNG, name="My Icon")

        assert db.custom_icons[icon_uuid].name == "My Icon"

    def test_add_multiple_icons(self) -> None:
        """Test adding multiple custom icons."""
        db = Database.create(password="test")

        uuid1 = db.add_custom_icon(MINIMAL_PNG, name="Icon 1")
        uuid2 = db.add_custom_icon(MINIMAL_PNG, name="Icon 2")
        uuid3 = db.add_custom_icon(MINIMAL_PNG, name="Icon 3")

        assert len(db.custom_icons) == 3
        assert db.custom_icons[uuid1].name == "Icon 1"
        assert db.custom_icons[uuid2].name == "Icon 2"
        assert db.custom_icons[uuid3].name == "Icon 3"


class TestGetCustomIcon:
    """Tests for Database.get_custom_icon()."""

    def test_get_custom_icon(self) -> None:
        """Test getting custom icon data."""
        db = Database.create(password="test")
        icon_uuid = db.add_custom_icon(MINIMAL_PNG)

        data = db.get_custom_icon(icon_uuid)

        assert data == MINIMAL_PNG

    def test_get_custom_icon_not_found(self) -> None:
        """Test getting non-existent custom icon."""
        db = Database.create(password="test")

        data = db.get_custom_icon(uuid.uuid4())

        assert data is None


class TestRemoveCustomIcon:
    """Tests for Database.remove_custom_icon()."""

    def test_remove_custom_icon(self) -> None:
        """Test removing a custom icon."""
        db = Database.create(password="test")
        icon_uuid = db.add_custom_icon(MINIMAL_PNG)

        result = db.remove_custom_icon(icon_uuid)

        assert result is True
        assert icon_uuid not in db.custom_icons

    def test_remove_custom_icon_not_found(self) -> None:
        """Test removing non-existent custom icon."""
        db = Database.create(password="test")

        result = db.remove_custom_icon(uuid.uuid4())

        assert result is False


class TestEntryCustomIcon:
    """Tests for Entry.custom_icon_uuid."""

    def test_set_custom_icon_on_entry(self) -> None:
        """Test setting custom icon on entry."""
        db = Database.create(password="test")
        icon_uuid = db.add_custom_icon(MINIMAL_PNG)
        entry = db.root_group.create_entry(title="Test")

        entry.custom_icon_uuid = icon_uuid

        assert entry.custom_icon_uuid == icon_uuid

    def test_entry_custom_icon_default_none(self) -> None:
        """Test that entry custom icon defaults to None."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Test")

        assert entry.custom_icon_uuid is None


class TestGroupCustomIcon:
    """Tests for Group.custom_icon_uuid."""

    def test_set_custom_icon_on_group(self) -> None:
        """Test setting custom icon on group."""
        db = Database.create(password="test")
        icon_uuid = db.add_custom_icon(MINIMAL_PNG)
        group = db.root_group.create_subgroup("Test Group")

        group.custom_icon_uuid = icon_uuid

        assert group.custom_icon_uuid == icon_uuid

    def test_group_custom_icon_default_none(self) -> None:
        """Test that group custom icon defaults to None."""
        db = Database.create(password="test")
        group = db.root_group.create_subgroup("Test Group")

        assert group.custom_icon_uuid is None


class TestCustomIconRoundtrip:
    """Tests for custom icon persistence through save/load."""

    def test_custom_icon_roundtrip(self) -> None:
        """Test that custom icons persist through save/load."""
        db = Database.create(password="test")
        icon_uuid = db.add_custom_icon(MINIMAL_PNG, name="Test Icon")

        # Save and reload
        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        assert icon_uuid in db2.custom_icons
        assert db2.custom_icons[icon_uuid].data == MINIMAL_PNG
        assert db2.custom_icons[icon_uuid].name == "Test Icon"
        assert db2.custom_icons[icon_uuid].last_modification_time is not None

    def test_entry_custom_icon_roundtrip(self) -> None:
        """Test that entry custom icons persist through save/load."""
        db = Database.create(password="test")
        icon_uuid = db.add_custom_icon(MINIMAL_PNG)
        entry = db.root_group.create_entry(title="Test Entry")
        entry.custom_icon_uuid = icon_uuid

        # Save and reload
        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        entry2 = db2.find_entries(title="Test Entry")[0]
        assert entry2.custom_icon_uuid == icon_uuid

    def test_group_custom_icon_roundtrip(self) -> None:
        """Test that group custom icons persist through save/load."""
        db = Database.create(password="test")
        icon_uuid = db.add_custom_icon(MINIMAL_PNG)
        group = db.root_group.create_subgroup("Test Group")
        group.custom_icon_uuid = icon_uuid

        # Save and reload
        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        group2 = db2.find_groups(name="Test Group")[0]
        assert group2.custom_icon_uuid == icon_uuid

    def test_multiple_icons_roundtrip(self) -> None:
        """Test that multiple custom icons persist through save/load."""
        db = Database.create(password="test")
        uuid1 = db.add_custom_icon(MINIMAL_PNG, name="Icon 1")
        uuid2 = db.add_custom_icon(MINIMAL_PNG, name="Icon 2")

        entry = db.root_group.create_entry(title="Entry")
        entry.custom_icon_uuid = uuid1

        group = db.root_group.create_subgroup("Group")
        group.custom_icon_uuid = uuid2

        # Save and reload
        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        assert len(db2.custom_icons) == 2
        assert db2.custom_icons[uuid1].name == "Icon 1"
        assert db2.custom_icons[uuid2].name == "Icon 2"

        entry2 = db2.find_entries(title="Entry")[0]
        assert entry2.custom_icon_uuid == uuid1

        group2 = db2.find_groups(name="Group")[0]
        assert group2.custom_icon_uuid == uuid2


class TestCustomIconHistory:
    """Tests for custom icon in entry history."""

    def test_custom_icon_in_history(self) -> None:
        """Test that custom icon is preserved in history."""
        db = Database.create(password="test")
        icon_uuid = db.add_custom_icon(MINIMAL_PNG)
        entry = db.root_group.create_entry(title="Test")
        entry.custom_icon_uuid = icon_uuid

        # Save history
        entry.save_history()

        # Change icon
        new_uuid = db.add_custom_icon(MINIMAL_PNG, name="New Icon")
        entry.custom_icon_uuid = new_uuid

        # Check history preserved old icon
        assert len(entry.history) == 1
        assert entry.history[0].custom_icon_uuid == icon_uuid
        assert entry.custom_icon_uuid == new_uuid


class TestCustomIconProperty:
    """Tests for the custom_icon property on Entry and Group."""

    def test_entry_custom_icon_set_by_uuid(self) -> None:
        """Test setting entry custom icon by UUID."""
        db = Database.create(password="test")
        icon_uuid = db.add_custom_icon(MINIMAL_PNG)
        entry = db.root_group.create_entry(title="Test")

        entry.custom_icon = icon_uuid

        assert entry.custom_icon == icon_uuid
        assert entry.custom_icon_uuid == icon_uuid

    def test_entry_custom_icon_set_by_name(self) -> None:
        """Test setting entry custom icon by name."""
        db = Database.create(password="test")
        icon_uuid = db.add_custom_icon(MINIMAL_PNG, name="My Icon")
        entry = db.root_group.create_entry(title="Test")

        entry.custom_icon = "My Icon"

        assert entry.custom_icon == icon_uuid

    def test_entry_custom_icon_set_none(self) -> None:
        """Test clearing entry custom icon."""
        db = Database.create(password="test")
        icon_uuid = db.add_custom_icon(MINIMAL_PNG)
        entry = db.root_group.create_entry(title="Test")
        entry.custom_icon = icon_uuid

        entry.custom_icon = None

        assert entry.custom_icon is None

    def test_entry_custom_icon_name_not_found(self) -> None:
        """Test error when icon name not found."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Test")

        with pytest.raises(ValueError, match="No custom icon found"):
            entry.custom_icon = "Nonexistent"

    def test_group_custom_icon_set_by_name(self) -> None:
        """Test setting group custom icon by name."""
        db = Database.create(password="test")
        icon_uuid = db.add_custom_icon(MINIMAL_PNG, name="Folder Icon")
        group = db.root_group.create_subgroup("Test Group")

        group.custom_icon = "Folder Icon"

        assert group.custom_icon == icon_uuid


class TestDatabaseReference:
    """Tests for database reference on entries and groups."""

    def test_entry_has_database_reference(self) -> None:
        """Test that entry has database reference after creation."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Test")

        assert entry.database is db

    def test_group_has_database_reference(self) -> None:
        """Test that group has database reference after creation."""
        db = Database.create(password="test")
        group = db.root_group.create_subgroup("Test")

        assert group.database is db

    def test_root_group_has_database_reference(self) -> None:
        """Test that root group has database reference."""
        db = Database.create(password="test")

        assert db.root_group.database is db

    def test_database_reference_persists_roundtrip(self) -> None:
        """Test that database reference is set after load."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="Test Entry")
        db.root_group.create_subgroup("Test Group")

        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        entry = db2.find_entries(title="Test Entry")[0]
        group = db2.find_groups(name="Test Group")[0]

        assert entry.database is db2
        assert group.database is db2

    def test_nested_entries_have_database_reference(self) -> None:
        """Test that nested entries have database reference."""
        db = Database.create(password="test")
        group = db.root_group.create_subgroup("Level1")
        subgroup = group.create_subgroup("Level2")
        entry = subgroup.create_entry(title="Deep Entry")

        assert entry.database is db
        assert subgroup.database is db


class TestFindCustomIconByName:
    """Tests for Database.find_custom_icon_by_name()."""

    def test_find_icon_by_name(self) -> None:
        """Test finding icon by name."""
        db = Database.create(password="test")
        icon_uuid = db.add_custom_icon(MINIMAL_PNG, name="Test Icon")

        found = db.find_custom_icon_by_name("Test Icon")

        assert found == icon_uuid

    def test_find_icon_not_found(self) -> None:
        """Test finding non-existent icon."""
        db = Database.create(password="test")

        found = db.find_custom_icon_by_name("Nonexistent")

        assert found is None

    def test_find_icon_duplicate_name_raises(self) -> None:
        """Test error when multiple icons have same name."""
        db = Database.create(password="test")
        db.add_custom_icon(MINIMAL_PNG, name="Duplicate")
        db.add_custom_icon(MINIMAL_PNG, name="Duplicate")

        with pytest.raises(ValueError, match="Multiple custom icons"):
            db.find_custom_icon_by_name("Duplicate")
