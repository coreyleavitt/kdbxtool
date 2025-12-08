"""Tests for KDBX data models."""

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from kdbxtool.models import Entry, Group, HistoryEntry, Times
from kdbxtool.models.entry import RESERVED_KEYS, AutoType, BinaryRef, StringField


class TestTimes:
    """Tests for Times dataclass."""

    def test_create_new(self) -> None:
        """Test creating new timestamps."""
        times = Times.create_new()
        assert times.creation_time is not None
        assert times.last_modification_time is not None
        assert times.last_access_time is not None
        assert times.expires is False
        assert times.usage_count == 0

    def test_create_with_expiry(self) -> None:
        """Test creating timestamps with expiry."""
        expiry = datetime.now(timezone.utc) + timedelta(days=30)
        times = Times.create_new(expires=True, expiry_time=expiry)
        assert times.expires is True
        assert times.expiry_time == expiry
        assert times.expired is False

    def test_expired(self) -> None:
        """Test expired check."""
        past = datetime.now(timezone.utc) - timedelta(days=1)
        times = Times.create_new(expires=True, expiry_time=past)
        assert times.expired is True

    def test_not_expired_when_disabled(self) -> None:
        """Test that expired is False when expires is False."""
        past = datetime.now(timezone.utc) - timedelta(days=1)
        times = Times.create_new(expires=False, expiry_time=past)
        assert times.expired is False

    def test_touch(self) -> None:
        """Test touch updates access time."""
        times = Times.create_new()
        original_atime = times.last_access_time
        original_mtime = times.last_modification_time

        # Small delay to ensure time difference
        import time

        time.sleep(0.01)

        times.touch()
        assert times.last_access_time > original_atime
        assert times.last_modification_time == original_mtime

    def test_touch_with_modify(self) -> None:
        """Test touch with modify=True updates both times."""
        times = Times.create_new()
        original_atime = times.last_access_time
        original_mtime = times.last_modification_time

        import time

        time.sleep(0.01)

        times.touch(modify=True)
        assert times.last_access_time > original_atime
        assert times.last_modification_time > original_mtime

    def test_increment_usage(self) -> None:
        """Test usage count increment."""
        times = Times.create_new()
        assert times.usage_count == 0
        times.increment_usage()
        assert times.usage_count == 1
        times.increment_usage()
        assert times.usage_count == 2


class TestStringField:
    """Tests for StringField dataclass."""

    def test_create_basic(self) -> None:
        """Test basic string field creation."""
        field = StringField(key="Title", value="My Entry")
        assert field.key == "Title"
        assert field.value == "My Entry"
        assert field.protected is False

    def test_create_protected(self) -> None:
        """Test protected string field."""
        field = StringField(key="Password", value="secret", protected=True)
        assert field.protected is True


class TestEntry:
    """Tests for Entry dataclass."""

    def test_create_basic(self) -> None:
        """Test basic entry creation."""
        entry = Entry.create(
            title="Test Entry",
            username="testuser",
            password="secret123",
        )
        assert entry.title == "Test Entry"
        assert entry.username == "testuser"
        assert entry.password == "secret123"
        assert entry.uuid is not None

    def test_create_with_all_fields(self) -> None:
        """Test entry creation with all fields."""
        entry = Entry.create(
            title="Full Entry",
            username="user",
            password="pass",
            url="https://example.com",
            notes="Some notes",
            tags=["tag1", "tag2"],
            icon_id="1",
        )
        assert entry.title == "Full Entry"
        assert entry.url == "https://example.com"
        assert entry.notes == "Some notes"
        assert entry.tags == ["tag1", "tag2"]
        assert entry.icon_id == "1"

    def test_default_string_fields(self) -> None:
        """Test that default string fields are created."""
        entry = Entry()
        assert "Title" in entry.strings
        assert "UserName" in entry.strings
        assert "Password" in entry.strings
        assert "URL" in entry.strings
        assert "Notes" in entry.strings

    def test_password_is_protected(self) -> None:
        """Test that password field is protected by default."""
        entry = Entry.create(password="secret")
        assert entry.strings["Password"].protected is True

    def test_set_properties(self) -> None:
        """Test setting entry properties."""
        entry = Entry()
        entry.title = "New Title"
        entry.username = "newuser"
        entry.password = "newpass"
        entry.url = "https://new.com"
        entry.notes = "New notes"

        assert entry.title == "New Title"
        assert entry.username == "newuser"
        assert entry.password == "newpass"
        assert entry.url == "https://new.com"
        assert entry.notes == "New notes"

    def test_otp_property(self) -> None:
        """Test OTP property."""
        entry = Entry()
        entry.otp = "otpauth://totp/Example"
        assert entry.otp == "otpauth://totp/Example"
        assert entry.strings["otp"].protected is True

    def test_custom_properties(self) -> None:
        """Test custom property operations."""
        entry = Entry()

        # Set custom property
        entry.set_custom_property("CustomField", "CustomValue", protected=False)
        assert entry.get_custom_property("CustomField") == "CustomValue"

        # Get all custom properties
        props = entry.custom_properties
        assert "CustomField" in props
        assert props["CustomField"] == "CustomValue"

        # Delete custom property
        entry.delete_custom_property("CustomField")
        assert entry.get_custom_property("CustomField") is None

    def test_custom_property_reserved_key_error(self) -> None:
        """Test that reserved keys raise errors."""
        entry = Entry()

        with pytest.raises(ValueError, match="reserved key"):
            entry.set_custom_property("Title", "value")

        with pytest.raises(ValueError, match="reserved key"):
            entry.get_custom_property("Password")

        with pytest.raises(ValueError, match="reserved key"):
            entry.delete_custom_property("UserName")

    def test_delete_nonexistent_property_error(self) -> None:
        """Test deleting nonexistent property raises KeyError."""
        entry = Entry()
        with pytest.raises(KeyError):
            entry.delete_custom_property("DoesNotExist")

    def test_entry_equality(self) -> None:
        """Test entry equality is based on UUID."""
        entry1 = Entry()
        entry2 = Entry()
        entry3 = Entry(uuid=entry1.uuid)

        assert entry1 != entry2  # Different UUIDs
        assert entry1 == entry3  # Same UUID

    def test_entry_hash(self) -> None:
        """Test entry hashing."""
        entry1 = Entry()
        entry2 = Entry(uuid=entry1.uuid)

        # Same UUID should have same hash
        assert hash(entry1) == hash(entry2)

        # Can be used in sets
        entries = {entry1, entry2}
        assert len(entries) == 1

    def test_entry_str(self) -> None:
        """Test entry string representation."""
        entry = Entry.create(title="My Entry", username="myuser")
        assert "My Entry" in str(entry)
        assert "myuser" in str(entry)

    def test_save_history(self) -> None:
        """Test saving entry history."""
        entry = Entry.create(title="Original", username="user")
        assert len(entry.history) == 0

        entry.save_history()
        entry.title = "Modified"

        assert len(entry.history) == 1
        assert entry.history[0].title == "Original"
        assert entry.title == "Modified"


class TestHistoryEntry:
    """Tests for HistoryEntry."""

    def test_from_entry(self) -> None:
        """Test creating history entry from entry."""
        entry = Entry.create(
            title="Test",
            username="user",
            password="pass",
            tags=["tag1"],
        )
        entry.set_custom_property("Custom", "Value")

        history = HistoryEntry.from_entry(entry)

        assert history.uuid == entry.uuid
        assert history.title == entry.title
        assert history.username == entry.username
        assert history.password == entry.password
        assert history.tags == entry.tags
        assert history.get_custom_property("Custom") == "Value"
        assert len(history.history) == 0  # History entries don't have history

    def test_history_entry_hash(self) -> None:
        """Test history entry hashing includes mtime."""
        entry = Entry.create(title="Test")

        history1 = HistoryEntry.from_entry(entry)

        import time

        time.sleep(0.01)
        entry.times.last_modification_time = datetime.now(timezone.utc)
        history2 = HistoryEntry.from_entry(entry)

        # Same UUID but different mtime -> different hash
        assert history1.uuid == history2.uuid
        assert hash(history1) != hash(history2)


class TestAutoType:
    """Tests for AutoType dataclass."""

    def test_defaults(self) -> None:
        """Test AutoType defaults."""
        at = AutoType()
        assert at.enabled is True
        assert at.sequence is None
        assert at.window is None
        assert at.obfuscation == 0


class TestBinaryRef:
    """Tests for BinaryRef dataclass."""

    def test_create(self) -> None:
        """Test creating binary reference."""
        ref = BinaryRef(key="document.pdf", ref=0)
        assert ref.key == "document.pdf"
        assert ref.ref == 0


class TestGroup:
    """Tests for Group dataclass."""

    def test_create_basic(self) -> None:
        """Test basic group creation."""
        group = Group(name="My Group")
        assert group.name == "My Group"
        assert group.uuid is not None
        assert len(group.entries) == 0
        assert len(group.subgroups) == 0

    def test_create_root(self) -> None:
        """Test creating root group."""
        root = Group.create_root("Database")
        assert root.name == "Database"
        assert root.is_root_group is True
        assert root.path == []

    def test_add_entry(self) -> None:
        """Test adding entry to group."""
        group = Group(name="Group")
        entry = Entry.create(title="Entry")

        group.add_entry(entry)

        assert entry in group.entries
        assert entry.parent is group

    def test_remove_entry(self) -> None:
        """Test removing entry from group."""
        group = Group(name="Group")
        entry = Entry.create(title="Entry")
        group.add_entry(entry)

        group.remove_entry(entry)

        assert entry not in group.entries
        assert entry.parent is None

    def test_remove_entry_not_in_group(self) -> None:
        """Test removing entry not in group raises error."""
        group = Group(name="Group")
        entry = Entry.create(title="Entry")

        with pytest.raises(ValueError, match="not in this group"):
            group.remove_entry(entry)

    def test_create_entry(self) -> None:
        """Test creating entry in group."""
        group = Group(name="Group")
        entry = group.create_entry(title="New Entry", username="user")

        assert entry.title == "New Entry"
        assert entry.username == "user"
        assert entry in group.entries
        assert entry.parent is group

    def test_add_subgroup(self) -> None:
        """Test adding subgroup."""
        parent = Group(name="Parent")
        child = Group(name="Child")

        parent.add_subgroup(child)

        assert child in parent.subgroups
        assert child.parent is parent

    def test_remove_subgroup(self) -> None:
        """Test removing subgroup."""
        parent = Group(name="Parent")
        child = Group(name="Child")
        parent.add_subgroup(child)

        parent.remove_subgroup(child)

        assert child not in parent.subgroups
        assert child.parent is None

    def test_create_subgroup(self) -> None:
        """Test creating subgroup."""
        parent = Group(name="Parent")
        child = parent.create_subgroup("Child", notes="Child notes")

        assert child.name == "Child"
        assert child.notes == "Child notes"
        assert child in parent.subgroups
        assert child.parent is parent

    def test_path(self) -> None:
        """Test group path."""
        root = Group.create_root("Root")
        level1 = Group(name="Level1")
        level2 = Group(name="Level2")

        root.add_subgroup(level1)
        level1.add_subgroup(level2)

        assert root.path == []
        assert level1.path == ["Level1"]
        assert level2.path == ["Level1", "Level2"]

    def test_iter_entries_recursive(self) -> None:
        """Test iterating entries recursively."""
        root = Group.create_root("Root")
        entry1 = root.create_entry(title="Entry1")

        sub = root.create_subgroup("Sub")
        entry2 = sub.create_entry(title="Entry2")

        subsub = sub.create_subgroup("SubSub")
        entry3 = subsub.create_entry(title="Entry3")

        entries = list(root.iter_entries(recursive=True))
        assert len(entries) == 3
        assert entry1 in entries
        assert entry2 in entries
        assert entry3 in entries

    def test_iter_entries_non_recursive(self) -> None:
        """Test iterating entries non-recursively."""
        root = Group.create_root("Root")
        entry1 = root.create_entry(title="Entry1")

        sub = root.create_subgroup("Sub")
        entry2 = sub.create_entry(title="Entry2")

        entries = list(root.iter_entries(recursive=False))
        assert len(entries) == 1
        assert entry1 in entries
        assert entry2 not in entries

    def test_iter_groups(self) -> None:
        """Test iterating groups."""
        root = Group.create_root("Root")
        sub1 = root.create_subgroup("Sub1")
        sub2 = root.create_subgroup("Sub2")
        subsub = sub1.create_subgroup("SubSub")

        groups = list(root.iter_groups(recursive=True))
        assert len(groups) == 3
        assert sub1 in groups
        assert sub2 in groups
        assert subsub in groups

    def test_find_entry_by_uuid(self) -> None:
        """Test finding entry by UUID."""
        root = Group.create_root("Root")
        entry = root.create_entry(title="Target")
        sub = root.create_subgroup("Sub")
        sub.create_entry(title="Other")

        found = root.find_entry_by_uuid(entry.uuid)
        assert found is entry

        not_found = root.find_entry_by_uuid(uuid.uuid4())
        assert not_found is None

    def test_find_group_by_uuid(self) -> None:
        """Test finding group by UUID."""
        root = Group.create_root("Root")
        sub = root.create_subgroup("Sub")
        subsub = sub.create_subgroup("SubSub")

        found = root.find_group_by_uuid(subsub.uuid)
        assert found is subsub

        # Should also find self
        found_root = root.find_group_by_uuid(root.uuid)
        assert found_root is root

    def test_find_entries(self) -> None:
        """Test finding entries by criteria."""
        root = Group.create_root("Root")
        entry1 = root.create_entry(title="Login", username="user1", tags=["work"])
        entry2 = root.create_entry(title="Login", username="user2", tags=["personal"])
        entry3 = root.create_entry(title="API Key", username="user1")

        # Find by title
        found = root.find_entries(title="Login")
        assert len(found) == 2
        assert entry1 in found
        assert entry2 in found

        # Find by username
        found = root.find_entries(username="user1")
        assert len(found) == 2
        assert entry1 in found
        assert entry3 in found

        # Find by multiple criteria
        found = root.find_entries(title="Login", username="user1")
        assert len(found) == 1
        assert entry1 in found

        # Find by tags
        found = root.find_entries(tags=["work"])
        assert len(found) == 1
        assert entry1 in found

    def test_find_groups(self) -> None:
        """Test finding groups by name."""
        root = Group.create_root("Root")
        sub1 = root.create_subgroup("Work")
        sub2 = root.create_subgroup("Personal")
        subsub = sub1.create_subgroup("Projects")

        found = root.find_groups(name="Work")
        assert len(found) == 1
        assert sub1 in found

        # Without name filter, find all
        all_groups = root.find_groups()
        assert len(all_groups) == 3

    def test_group_equality(self) -> None:
        """Test group equality based on UUID."""
        group1 = Group(name="Group")
        group2 = Group(name="Group")  # Same name, different UUID
        group3 = Group(uuid=group1.uuid, name="Other")

        assert group1 != group2
        assert group1 == group3

    def test_group_str(self) -> None:
        """Test group string representation."""
        root = Group.create_root("Root")
        sub = root.create_subgroup("Child")

        assert "root" in str(root).lower()
        assert "Child" in str(sub)
