"""Tests for extended search capabilities."""

import pytest

from kdbxtool import Attachment, Database
from kdbxtool.models.entry import BinaryRef


class TestFindEntriesByPassword:
    """Tests for find_entries with password parameter."""

    def test_find_by_password(self) -> None:
        """Test finding entries by password."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="Entry1", password="secret123")
        db.root_group.create_entry(title="Entry2", password="secret456")
        db.root_group.create_entry(title="Entry3", password="secret123")

        entries = db.find_entries(password="secret123")

        assert len(entries) == 2
        titles = {e.title for e in entries}
        assert titles == {"Entry1", "Entry3"}

    def test_find_by_password_no_match(self) -> None:
        """Test finding entries by password with no match."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="Entry1", password="secret123")

        entries = db.find_entries(password="wrongpassword")

        assert entries == []


class TestFindEntriesByOtp:
    """Tests for find_entries with otp parameter."""

    def test_find_by_otp(self) -> None:
        """Test finding entries by OTP."""
        db = Database.create(password="test")
        entry1 = db.root_group.create_entry(title="Entry1")
        entry1.otp = "otpauth://totp/example"
        entry2 = db.root_group.create_entry(title="Entry2")
        entry2.otp = "otpauth://totp/other"
        db.root_group.create_entry(title="Entry3")  # No OTP

        entries = db.find_entries(otp="otpauth://totp/example")

        assert len(entries) == 1
        assert entries[0].title == "Entry1"


class TestFindEntriesByNotes:
    """Tests for find_entries with notes parameter."""

    def test_find_by_notes(self) -> None:
        """Test finding entries by notes."""
        db = Database.create(password="test")
        entry1 = db.root_group.create_entry(title="Entry1", notes="Important note")
        entry2 = db.root_group.create_entry(title="Entry2", notes="Other note")

        entries = db.find_entries(notes="Important note")

        assert len(entries) == 1
        assert entries[0].title == "Entry1"


class TestFindEntriesByCustomProperties:
    """Tests for find_entries with string parameter."""

    def test_find_by_custom_property(self) -> None:
        """Test finding entries by custom property."""
        db = Database.create(password="test")
        entry1 = db.root_group.create_entry(title="Entry1")
        entry1.set_custom_property("API_KEY", "abc123")
        entry2 = db.root_group.create_entry(title="Entry2")
        entry2.set_custom_property("API_KEY", "xyz789")
        db.root_group.create_entry(title="Entry3")  # No custom property

        entries = db.find_entries(string={"API_KEY": "abc123"})

        assert len(entries) == 1
        assert entries[0].title == "Entry1"

    def test_find_by_multiple_custom_properties(self) -> None:
        """Test finding entries by multiple custom properties."""
        db = Database.create(password="test")
        entry1 = db.root_group.create_entry(title="Entry1")
        entry1.set_custom_property("KEY1", "value1")
        entry1.set_custom_property("KEY2", "value2")
        entry2 = db.root_group.create_entry(title="Entry2")
        entry2.set_custom_property("KEY1", "value1")
        entry2.set_custom_property("KEY2", "other")

        entries = db.find_entries(string={"KEY1": "value1", "KEY2": "value2"})

        assert len(entries) == 1
        assert entries[0].title == "Entry1"


class TestFindEntriesByAutotype:
    """Tests for find_entries with autotype parameters."""

    def test_find_by_autotype_enabled(self) -> None:
        """Test finding entries by autotype enabled state."""
        db = Database.create(password="test")
        entry1 = db.root_group.create_entry(title="Entry1")
        entry1.autotype.enabled = True
        entry2 = db.root_group.create_entry(title="Entry2")
        entry2.autotype.enabled = False
        entry3 = db.root_group.create_entry(title="Entry3")
        entry3.autotype.enabled = True

        entries = db.find_entries(autotype_enabled=False)

        assert len(entries) == 1
        assert entries[0].title == "Entry2"

    def test_find_by_autotype_sequence(self) -> None:
        """Test finding entries by autotype sequence."""
        db = Database.create(password="test")
        entry1 = db.root_group.create_entry(title="Entry1")
        entry1.autotype.sequence = "{USERNAME}{TAB}{PASSWORD}{ENTER}"
        entry2 = db.root_group.create_entry(title="Entry2")
        entry2.autotype.sequence = "{PASSWORD}{ENTER}"

        entries = db.find_entries(autotype_sequence="{USERNAME}{TAB}{PASSWORD}{ENTER}")

        assert len(entries) == 1
        assert entries[0].title == "Entry1"

    def test_find_by_autotype_window(self) -> None:
        """Test finding entries by autotype window."""
        db = Database.create(password="test")
        entry1 = db.root_group.create_entry(title="Entry1")
        entry1.autotype.window = "*Firefox*"
        entry2 = db.root_group.create_entry(title="Entry2")
        entry2.autotype.window = "*Chrome*"

        entries = db.find_entries(autotype_window="*Firefox*")

        assert len(entries) == 1
        assert entries[0].title == "Entry1"


class TestFindEntriesWithHistory:
    """Tests for find_entries with history parameter."""

    def test_find_includes_history(self) -> None:
        """Test that history parameter includes history entries."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Current", password="new")

        # Save history with old password
        entry.save_history()
        entry.password = "updated"

        # Search for old password without history
        entries_no_history = db.find_entries(password="new", history=False)
        assert len(entries_no_history) == 0

        # Search for old password with history
        entries_with_history = db.find_entries(password="new", history=True)
        assert len(entries_with_history) == 1

    def test_find_history_by_title(self) -> None:
        """Test finding history entries by title."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="OldTitle")

        # Save history and change title
        entry.save_history()
        entry.title = "NewTitle"

        entries = db.find_entries(title="OldTitle", history=True)
        assert len(entries) == 1


class TestFindEntriesFirst:
    """Tests for find_entries with first parameter."""

    def test_first_returns_single_entry(self) -> None:
        """Test that first=True returns a single entry."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="Match", username="user1")
        db.root_group.create_entry(title="Match", username="user2")

        entry = db.find_entries(title="Match", first=True)

        assert entry is not None
        assert entry.title == "Match"

    def test_first_returns_none_when_not_found(self) -> None:
        """Test that first=True returns None when no match."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="Other")

        entry = db.find_entries(title="NotExist", first=True)

        assert entry is None

    def test_first_false_returns_list(self) -> None:
        """Test that first=False returns a list."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="Match")

        result = db.find_entries(title="Match", first=False)

        assert isinstance(result, list)
        assert len(result) == 1


class TestFindEntriesContainsExtended:
    """Tests for find_entries_contains with new parameters."""

    def test_find_contains_password(self) -> None:
        """Test finding entries by password substring."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="Entry1", password="my_secret_password")
        db.root_group.create_entry(title="Entry2", password="other_pass")

        entries = db.find_entries_contains(password="secret")

        assert len(entries) == 1
        assert entries[0].title == "Entry1"

    def test_find_contains_otp(self) -> None:
        """Test finding entries by OTP substring."""
        db = Database.create(password="test")
        entry1 = db.root_group.create_entry(title="Entry1")
        entry1.otp = "otpauth://totp/example.com"

        entries = db.find_entries_contains(otp="example.com")

        assert len(entries) == 1
        assert entries[0].title == "Entry1"

    def test_find_contains_with_history(self) -> None:
        """Test finding entries with history."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Entry", password="oldpassword")
        entry.save_history()
        entry.password = "newpassword"

        entries = db.find_entries_contains(password="oldpass", history=True)
        assert len(entries) == 1


class TestFindEntriesRegexExtended:
    """Tests for find_entries_regex with new parameters."""

    def test_find_regex_password(self) -> None:
        """Test finding entries by password regex."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="Entry1", password="Pass123!")
        db.root_group.create_entry(title="Entry2", password="simple")

        entries = db.find_entries_regex(password=r"Pass\d+!")

        assert len(entries) == 1
        assert entries[0].title == "Entry1"

    def test_find_regex_otp(self) -> None:
        """Test finding entries by OTP regex."""
        db = Database.create(password="test")
        entry1 = db.root_group.create_entry(title="Entry1")
        entry1.otp = "otpauth://totp/user@example.com?secret=ABC"

        entries = db.find_entries_regex(otp=r"user@.*\.com")

        assert len(entries) == 1
        assert entries[0].title == "Entry1"

    def test_find_regex_with_history(self) -> None:
        """Test finding entries with regex in history."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Entry", password="OldPass123")
        entry.save_history()
        entry.password = "NewPass"

        entries = db.find_entries_regex(password=r"Old.*\d+", history=True)
        assert len(entries) == 1


class TestFindAttachments:
    """Tests for find_attachments method."""

    def test_find_attachment_by_filename(self) -> None:
        """Test finding attachments by filename."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Entry")

        # Add binary and attachment
        ref = db.add_binary(b"file content")
        entry.binaries.append(BinaryRef(key="document.pdf", ref=ref))

        attachments = db.find_attachments(filename="document.pdf")

        assert len(attachments) == 1
        assert attachments[0].filename == "document.pdf"
        assert attachments[0].entry.title == "Entry"

    def test_find_attachment_by_id(self) -> None:
        """Test finding attachments by binary ID."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Entry")

        ref = db.add_binary(b"file content")
        entry.binaries.append(BinaryRef(key="file.txt", ref=ref))

        attachments = db.find_attachments(id=ref)

        assert len(attachments) == 1
        assert attachments[0].id == ref

    def test_find_attachment_by_regex(self) -> None:
        """Test finding attachments by filename regex."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Entry")

        ref1 = db.add_binary(b"content1")
        ref2 = db.add_binary(b"content2")
        entry.binaries.append(BinaryRef(key="photo_001.jpg", ref=ref1))
        entry.binaries.append(BinaryRef(key="document.pdf", ref=ref2))

        attachments = db.find_attachments(filename=r"photo_\d+\.jpg", regex=True)

        assert len(attachments) == 1
        assert attachments[0].filename == "photo_001.jpg"

    def test_find_attachment_first(self) -> None:
        """Test finding first attachment."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Entry")

        ref = db.add_binary(b"content")
        entry.binaries.append(BinaryRef(key="file.txt", ref=ref))

        attachment = db.find_attachments(filename="file.txt", first=True)

        assert attachment is not None
        assert attachment.filename == "file.txt"

    def test_find_attachment_first_not_found(self) -> None:
        """Test finding first attachment when not found."""
        db = Database.create(password="test")

        attachment = db.find_attachments(filename="nonexistent.txt", first=True)

        assert attachment is None

    def test_find_attachment_with_history(self) -> None:
        """Test finding attachments in history entries."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Entry")

        ref = db.add_binary(b"old content")
        entry.binaries.append(BinaryRef(key="old_file.txt", ref=ref))

        # Save history and remove attachment
        entry.save_history()
        entry.binaries.clear()

        # Without history
        attachments_no_history = db.find_attachments(filename="old_file.txt", history=False)
        assert len(attachments_no_history) == 0

        # With history
        attachments_with_history = db.find_attachments(filename="old_file.txt", history=True)
        assert len(attachments_with_history) == 1

    def test_attachments_property(self) -> None:
        """Test the attachments property returns all attachments."""
        db = Database.create(password="test")
        entry1 = db.root_group.create_entry(title="Entry1")
        entry2 = db.root_group.create_entry(title="Entry2")

        ref1 = db.add_binary(b"content1")
        ref2 = db.add_binary(b"content2")
        entry1.binaries.append(BinaryRef(key="file1.txt", ref=ref1))
        entry2.binaries.append(BinaryRef(key="file2.txt", ref=ref2))

        attachments = db.attachments

        assert len(attachments) == 2
        filenames = {a.filename for a in attachments}
        assert filenames == {"file1.txt", "file2.txt"}


class TestAttachmentDataProperty:
    """Tests for Attachment.data property."""

    def test_attachment_data(self) -> None:
        """Test getting attachment data."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Entry")

        content = b"Hello, World!"
        ref = db.add_binary(content)
        entry.binaries.append(BinaryRef(key="hello.txt", ref=ref))

        attachment = db.find_attachments(filename="hello.txt", first=True)

        assert attachment is not None
        assert attachment.data == content


class TestCombinedSearchParameters:
    """Tests for combining multiple search parameters."""

    def test_combine_multiple_parameters(self) -> None:
        """Test combining multiple search parameters."""
        db = Database.create(password="test")
        entry1 = db.root_group.create_entry(
            title="Gmail", username="user@gmail.com", password="pass123"
        )
        entry1.autotype.enabled = True

        entry2 = db.root_group.create_entry(
            title="Gmail", username="other@gmail.com", password="pass123"
        )
        entry2.autotype.enabled = False

        entries = db.find_entries(title="Gmail", password="pass123", autotype_enabled=True)

        assert len(entries) == 1
        assert entries[0].username == "user@gmail.com"

    def test_path_ignores_other_params(self) -> None:
        """Test that path parameter ignores other parameters."""
        db = Database.create(password="test")
        group = db.root_group.create_subgroup("Folder")
        group.create_entry(title="MyEntry", username="user")

        # Path should find entry even if username doesn't match
        entries = db.find_entries(path="Folder/MyEntry", username="wrong")

        # Path search ignores other filter parameters
        assert len(entries) == 1
        assert entries[0].title == "MyEntry"


class TestSearchRoundtrip:
    """Tests for search after save/load."""

    def test_extended_search_after_roundtrip(self) -> None:
        """Test that extended search works after save/load."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Test", username="user", password="secret")
        entry.autotype.sequence = "{TAB}{ENTER}"
        entry.set_custom_property("API_KEY", "key123")

        # Save and reload
        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        # Test various searches
        assert len(db2.find_entries(password="secret")) == 1
        assert len(db2.find_entries(autotype_sequence="{TAB}{ENTER}")) == 1
        assert len(db2.find_entries(string={"API_KEY": "key123"})) == 1
        assert db2.find_entries(title="Test", first=True) is not None
