"""Tests for high-level Database API."""

import base64
import os
import tempfile
from pathlib import Path

import pytest

from kdbxtool import (
    AuthenticationError,
    Database,
    DatabaseError,
    DatabaseSettings,
    Entry,
    Group,
    MissingCredentialsError,
    UnknownCipherError,
)
from kdbxtool.database import (
    PROTECTED_STREAM_CHACHA20,
    PROTECTED_STREAM_SALSA20,
    ProtectedStreamCipher,
)
from kdbxtool.security import Argon2Config, Cipher, KdfType


FIXTURES_DIR = Path(__file__).parent / "fixtures"
TEST4_KDBX = FIXTURES_DIR / "test4.kdbx"
TEST4_KEY = FIXTURES_DIR / "test4.key"
TEST_PASSWORD = "password"


class TestDatabaseOpen:
    """Tests for opening existing databases."""

    @pytest.fixture
    def test4_db(self) -> Database:
        """Open test4.kdbx database."""
        if not TEST4_KDBX.exists():
            pytest.skip("Test fixture test4.kdbx not found")
        return Database.open(
            TEST4_KDBX,
            password=TEST_PASSWORD,
            keyfile=TEST4_KEY,
        )

    def test_open_with_password_and_keyfile(self, test4_db: Database) -> None:
        """Test opening database with password and keyfile."""
        assert test4_db is not None
        assert test4_db.root_group is not None
        assert test4_db.root_group.is_root_group

    def test_open_returns_entries(self, test4_db: Database) -> None:
        """Test that opened database has entries."""
        entries = list(test4_db.iter_entries())
        # test4.kdbx has at least one entry
        assert len(entries) >= 1

    def test_open_file_not_found(self) -> None:
        """Test that opening non-existent file raises error."""
        with pytest.raises(FileNotFoundError):
            Database.open("/nonexistent/path.kdbx", password="test")

    def test_open_wrong_password(self) -> None:
        """Test that wrong password raises error."""
        if not TEST4_KDBX.exists():
            pytest.skip("Test fixture test4.kdbx not found")
        with pytest.raises(AuthenticationError):
            Database.open(TEST4_KDBX, password="wrongpassword", keyfile=TEST4_KEY)

    def test_open_bytes(self) -> None:
        """Test opening database from bytes."""
        if not TEST4_KDBX.exists():
            pytest.skip("Test fixture test4.kdbx not found")

        data = TEST4_KDBX.read_bytes()
        keyfile_data = TEST4_KEY.read_bytes()

        db = Database.open_bytes(data, password=TEST_PASSWORD, keyfile_data=keyfile_data)
        assert db.root_group is not None


class TestDatabaseCreate:
    """Tests for creating new databases."""

    def test_create_basic(self) -> None:
        """Test creating a new database."""
        db = Database.create(password="testpassword", database_name="Test DB")

        assert db.root_group is not None
        assert db.root_group.name == "Test DB"
        assert db.settings.database_name == "Test DB"

    def test_create_no_credentials_raises(self) -> None:
        """Test that creating without credentials raises error."""
        with pytest.raises(MissingCredentialsError):
            Database.create()

    def test_create_with_options(self) -> None:
        """Test creating database with custom options."""
        kdf = Argon2Config.fast(variant=KdfType.ARGON2D)
        db = Database.create(
            password="test",
            database_name="Custom DB",
            cipher=Cipher.CHACHA20,
            kdf_config=kdf,
        )

        assert db.settings.database_name == "Custom DB"
        assert db._header.cipher == Cipher.CHACHA20
        assert db._header.kdf_type == KdfType.ARGON2D


class TestDatabaseSave:
    """Tests for saving databases."""

    def test_save_and_reopen(self) -> None:
        """Test that saved database can be reopened."""
        with tempfile.NamedTemporaryFile(suffix=".kdbx", delete=False) as f:
            filepath = Path(f.name)

        try:
            # Create and save
            db = Database.create(password="testpass", database_name="Save Test")
            db.root_group.create_entry(
                title="Test Entry",
                username="testuser",
                password="testpassword",
            )
            db.save(filepath)

            # Reopen
            db2 = Database.open(filepath, password="testpass")

            assert db2.settings.database_name == "Save Test"
            entries = db2.find_entries(title="Test Entry")
            assert len(entries) == 1
            assert entries[0].username == "testuser"
            assert entries[0].password == "testpassword"
        finally:
            filepath.unlink(missing_ok=True)

    def test_to_bytes_roundtrip(self) -> None:
        """Test serializing to bytes and back."""
        db = Database.create(password="test", database_name="Bytes Test")
        db.root_group.create_entry(title="Entry1", username="user1")

        data = db.to_bytes()

        db2 = Database.open_bytes(data, password="test")
        entries = db2.find_entries(title="Entry1")
        assert len(entries) == 1
        assert entries[0].username == "user1"

    def test_save_no_filepath_raises(self) -> None:
        """Test that save without filepath raises error."""
        db = Database.create(password="test")
        with pytest.raises(DatabaseError):
            db.save()

    def test_to_bytes_no_credentials_raises(self) -> None:
        """Test that to_bytes without credentials raises error."""
        db = Database.create(password="test")
        db._password = None
        db._keyfile_data = None
        with pytest.raises(MissingCredentialsError):
            db.to_bytes()


class TestDatabaseSearch:
    """Tests for search operations."""

    @pytest.fixture
    def populated_db(self) -> Database:
        """Create a database with test data."""
        db = Database.create(password="test")

        # Create groups
        work = db.root_group.create_subgroup("Work")
        personal = db.root_group.create_subgroup("Personal")

        # Create entries
        db.root_group.create_entry(
            title="GitHub", username="dev@example.com", url="https://github.com"
        )
        work.create_entry(title="Jira", username="dev@work.com", tags=["work", "tracking"])
        work.create_entry(title="Slack", username="dev@work.com", tags=["work", "chat"])
        personal.create_entry(title="Gmail", username="me@gmail.com", tags=["personal", "email"])

        return db

    def test_find_entries_by_title(self, populated_db: Database) -> None:
        """Test finding entries by title."""
        entries = populated_db.find_entries(title="GitHub")
        assert len(entries) == 1
        assert entries[0].title == "GitHub"

    def test_find_entries_by_username(self, populated_db: Database) -> None:
        """Test finding entries by username."""
        entries = populated_db.find_entries(username="dev@work.com")
        assert len(entries) == 2

    def test_find_entries_by_tags(self, populated_db: Database) -> None:
        """Test finding entries by tags."""
        entries = populated_db.find_entries(tags=["work"])
        assert len(entries) == 2

        entries = populated_db.find_entries(tags=["work", "chat"])
        assert len(entries) == 1
        assert entries[0].title == "Slack"

    def test_find_entries_by_uuid(self, populated_db: Database) -> None:
        """Test finding entry by UUID."""
        all_entries = list(populated_db.iter_entries())
        target = all_entries[0]

        found = populated_db.find_entries(uuid=target.uuid)
        assert len(found) == 1
        assert found[0] == target

    def test_find_entries_non_recursive(self, populated_db: Database) -> None:
        """Test finding entries non-recursively."""
        # Only root group entry
        entries = populated_db.find_entries(recursive=False)
        assert len(entries) == 1
        assert entries[0].title == "GitHub"

    def test_find_groups_by_name(self, populated_db: Database) -> None:
        """Test finding groups by name."""
        groups = populated_db.find_groups(name="Work")
        assert len(groups) == 1
        assert groups[0].name == "Work"

    def test_find_groups_by_uuid(self, populated_db: Database) -> None:
        """Test finding group by UUID."""
        work = populated_db.find_groups(name="Work")[0]
        found = populated_db.find_groups(uuid=work.uuid)
        assert len(found) == 1
        assert found[0] == work

    def test_iter_entries(self, populated_db: Database) -> None:
        """Test iterating all entries."""
        entries = list(populated_db.iter_entries())
        assert len(entries) == 4

    def test_iter_groups(self, populated_db: Database) -> None:
        """Test iterating all groups."""
        groups = list(populated_db.iter_groups())
        assert len(groups) == 3  # Recycle Bin, Work, Personal (not root)

    def test_find_entries_contains_title(self, populated_db: Database) -> None:
        """Test finding entries by partial title match."""
        # Should find GitHub (case-insensitive by default)
        entries = populated_db.find_entries_contains(title="git")
        assert len(entries) == 1
        assert entries[0].title == "GitHub"

    def test_find_entries_contains_username(self, populated_db: Database) -> None:
        """Test finding entries by partial username match."""
        # Should find all @work.com entries
        entries = populated_db.find_entries_contains(username="@work.com")
        assert len(entries) == 2

    def test_find_entries_contains_case_sensitive(self, populated_db: Database) -> None:
        """Test case-sensitive substring matching."""
        # Case-insensitive (default) should find GitHub
        entries = populated_db.find_entries_contains(title="GITHUB")
        assert len(entries) == 1

        # Case-sensitive should not find it
        entries = populated_db.find_entries_contains(title="GITHUB", case_sensitive=True)
        assert len(entries) == 0

    def test_find_entries_contains_multiple_criteria(self, populated_db: Database) -> None:
        """Test substring search with multiple criteria (AND logic)."""
        entries = populated_db.find_entries_contains(title="a", username="@work.com")
        # "Jira" and "Slack" both have 'a' in title and @work.com in username
        assert len(entries) == 2

    def test_find_entries_regex_title(self, populated_db: Database) -> None:
        """Test finding entries by regex pattern on title."""
        # Match titles starting with 'G' or 'S'
        entries = populated_db.find_entries_regex(title="^[GS]")
        assert len(entries) == 3  # GitHub, Gmail, Slack

    def test_find_entries_regex_url(self, populated_db: Database) -> None:
        """Test finding entries by regex on URL."""
        entries = populated_db.find_entries_regex(url=r"https://.*\.com")
        assert len(entries) == 1
        assert entries[0].title == "GitHub"

    def test_find_entries_regex_case_sensitivity(self) -> None:
        """Test regex case sensitivity options."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="TestEntry", username="user")

        # Case-insensitive by default
        entries = db.find_entries_regex(title="testentry")
        assert len(entries) == 1

        entries = db.find_entries_regex(title="TESTENTRY")
        assert len(entries) == 1

        # Can opt into case-sensitive
        entries = db.find_entries_regex(title="testentry", case_sensitive=True)
        assert len(entries) == 0

        entries = db.find_entries_regex(title="TestEntry", case_sensitive=True)
        assert len(entries) == 1

    def test_find_entries_regex_invalid_pattern(self) -> None:
        """Test that invalid regex raises error."""
        import re

        db = Database.create(password="test")
        db.root_group.create_entry(title="Test")

        with pytest.raises(re.error):
            db.find_entries_regex(title="[invalid")


class TestDatabaseCredentials:
    """Tests for credential management."""

    def test_set_credentials(self) -> None:
        """Test setting credentials."""
        db = Database.create(password="original")
        db.set_credentials(password="newpassword")

        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="newpassword")
        assert db2.root_group is not None

    def test_set_credentials_none_raises(self) -> None:
        """Test that setting no credentials raises error."""
        db = Database.create(password="test")
        with pytest.raises(MissingCredentialsError):
            db.set_credentials()


class TestDatabaseSettings:
    """Tests for DatabaseSettings."""

    def test_default_settings(self) -> None:
        """Test default settings values."""
        settings = DatabaseSettings()

        assert settings.generator == "kdbxtool"
        assert settings.database_name == "Database"
        assert settings.recycle_bin_enabled is True
        assert settings.memory_protection["Password"] is True
        assert settings.memory_protection["Title"] is False

    def test_settings_roundtrip(self) -> None:
        """Test that settings survive save/load."""
        db = Database.create(password="test")
        db._settings.database_name = "Custom Name"
        db._settings.database_description = "My Description"
        db._settings.default_username = "defaultuser"
        db._settings.recycle_bin_enabled = False

        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        assert db2.settings.database_name == "Custom Name"
        assert db2.settings.database_description == "My Description"
        assert db2.settings.default_username == "defaultuser"
        assert db2.settings.recycle_bin_enabled is False


class TestDatabaseXmlParsing:
    """Tests for XML parsing/building."""

    def test_entry_fields_preserved(self) -> None:
        """Test that entry fields survive roundtrip."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(
            title="Test",
            username="user",
            password="pass",
            url="https://example.com",
            notes="Some notes",
            tags=["tag1", "tag2"],
        )
        entry.set_custom_property("CustomField", "CustomValue")

        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        e = db2.find_entries(title="Test")[0]
        assert e.title == "Test"
        assert e.username == "user"
        assert e.password == "pass"
        assert e.url == "https://example.com"
        assert e.notes == "Some notes"
        assert e.tags == ["tag1", "tag2"]
        assert e.get_custom_property("CustomField") == "CustomValue"

    def test_group_hierarchy_preserved(self) -> None:
        """Test that group hierarchy survives roundtrip."""
        db = Database.create(password="test")
        level1 = db.root_group.create_subgroup("Level1")
        level2 = level1.create_subgroup("Level2")
        level2.create_entry(title="Deep Entry")

        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        level1_found = db2.find_groups(name="Level1")
        assert len(level1_found) == 1

        level2_found = db2.find_groups(name="Level2")
        assert len(level2_found) == 1

        entries = db2.find_entries(title="Deep Entry")
        assert len(entries) == 1

    def test_entry_history_preserved(self) -> None:
        """Test that entry history survives roundtrip."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Original")
        entry.save_history()
        entry.title = "Modified"

        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        e = db2.find_entries(title="Modified")[0]
        assert len(e.history) == 1
        assert e.history[0].title == "Original"


class TestDatabaseStr:
    """Tests for Database string representation."""

    def test_str_representation(self) -> None:
        """Test database string output."""
        db = Database.create(password="test", database_name="My Database")
        db.root_group.create_entry(title="Entry1")
        db.root_group.create_subgroup("Group1")

        s = str(db)
        assert "My Database" in s
        assert "1 entries" in s
        assert "2 groups" in s  # Group1 + Recycle Bin


class TestBinaryAttachments:
    """Tests for binary attachment support."""

    def test_add_and_get_attachment(self) -> None:
        """Test adding and retrieving an attachment."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Test")

        # Add attachment
        data = b"Hello, World!"
        db.add_attachment(entry, "hello.txt", data)

        # Retrieve attachment
        retrieved = db.get_attachment(entry, "hello.txt")
        assert retrieved == data

    def test_list_attachments(self) -> None:
        """Test listing attachments."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Test")

        db.add_attachment(entry, "file1.txt", b"data1")
        db.add_attachment(entry, "file2.pdf", b"data2")

        names = db.list_attachments(entry)
        assert "file1.txt" in names
        assert "file2.pdf" in names
        assert len(names) == 2

    def test_remove_attachment(self) -> None:
        """Test removing an attachment."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Test")

        db.add_attachment(entry, "removeme.txt", b"data")
        assert db.get_attachment(entry, "removeme.txt") is not None

        result = db.remove_attachment(entry, "removeme.txt")
        assert result is True
        assert db.get_attachment(entry, "removeme.txt") is None

    def test_remove_nonexistent_attachment(self) -> None:
        """Test removing a nonexistent attachment."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Test")

        result = db.remove_attachment(entry, "nonexistent.txt")
        assert result is False

    def test_attachment_roundtrip(self) -> None:
        """Test that attachments survive save/open cycle."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Test")

        data = b"\x00\x01\x02\x03\xff\xfe\xfd"  # Binary data
        db.add_attachment(entry, "binary.bin", data)

        # Save and reopen
        saved = db.to_bytes()
        db2 = Database.open_bytes(saved, password="test")

        # Find the entry and check attachment
        entries = db2.find_entries(title="Test")
        assert len(entries) == 1
        retrieved = db2.get_attachment(entries[0], "binary.bin")
        assert retrieved == data


class TestProtectedStreamCipher:
    """Tests for protected value stream cipher."""

    def test_chacha20_encrypt_decrypt_roundtrip(self) -> None:
        """Test ChaCha20 stream cipher encryption/decryption."""
        key = os.urandom(64)
        plaintext = b"secret password"

        cipher1 = ProtectedStreamCipher(PROTECTED_STREAM_CHACHA20, key)
        ciphertext = cipher1.encrypt(plaintext)

        # Ciphertext should differ from plaintext
        assert ciphertext != plaintext
        assert len(ciphertext) == len(plaintext)

        # New cipher instance should decrypt correctly
        cipher2 = ProtectedStreamCipher(PROTECTED_STREAM_CHACHA20, key)
        decrypted = cipher2.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_salsa20_encrypt_decrypt_roundtrip(self) -> None:
        """Test Salsa20 stream cipher encryption/decryption."""
        key = os.urandom(64)
        plaintext = b"another secret"

        cipher1 = ProtectedStreamCipher(PROTECTED_STREAM_SALSA20, key)
        ciphertext = cipher1.encrypt(plaintext)

        assert ciphertext != plaintext

        cipher2 = ProtectedStreamCipher(PROTECTED_STREAM_SALSA20, key)
        decrypted = cipher2.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_different_keys_produce_different_ciphertext(self) -> None:
        """Test that different keys produce different ciphertext."""
        key1 = os.urandom(64)
        key2 = os.urandom(64)
        plaintext = b"test data"

        cipher1 = ProtectedStreamCipher(PROTECTED_STREAM_CHACHA20, key1)
        cipher2 = ProtectedStreamCipher(PROTECTED_STREAM_CHACHA20, key2)

        assert cipher1.encrypt(plaintext) != cipher2.encrypt(plaintext)

    def test_unknown_stream_id_raises(self) -> None:
        """Test that unknown stream ID raises error."""
        with pytest.raises(UnknownCipherError):
            ProtectedStreamCipher(99, os.urandom(64))

    def test_sequential_encryption(self) -> None:
        """Test that sequential encryptions produce different ciphertext."""
        key = os.urandom(64)
        plaintext = b"same"

        cipher = ProtectedStreamCipher(PROTECTED_STREAM_CHACHA20, key)

        # Same plaintext encrypted sequentially should produce different ciphertext
        # because the stream cipher advances
        ct1 = cipher.encrypt(plaintext)
        ct2 = cipher.encrypt(plaintext)
        ct3 = cipher.encrypt(plaintext)

        assert ct1 != ct2
        assert ct2 != ct3
        assert ct1 != ct3


class TestProtectedValueRoundtrip:
    """Tests for protected value encryption in databases."""

    def test_password_protected_roundtrip(self) -> None:
        """Test that password field survives roundtrip with protection."""
        db = Database.create(password="dbpass")
        db.root_group.create_entry(
            title="Test",
            username="user",
            password="supersecretpassword123",
        )

        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="dbpass")

        entry = db2.find_entries(title="Test")[0]
        assert entry.password == "supersecretpassword123"

    def test_multiple_protected_values_roundtrip(self) -> None:
        """Test multiple entries with protected values."""
        db = Database.create(password="test")

        for i in range(5):
            db.root_group.create_entry(
                title=f"Entry{i}",
                username=f"user{i}",
                password=f"password{i}",
            )

        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        for i in range(5):
            entries = db2.find_entries(title=f"Entry{i}")
            assert len(entries) == 1
            assert entries[0].password == f"password{i}"

    def test_otp_protected_roundtrip(self) -> None:
        """Test that OTP field (also protected) survives roundtrip."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="OTP Test")
        entry.otp = "otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP"

        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        e = db2.find_entries(title="OTP Test")[0]
        assert e.otp == "otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP"

    def test_protected_custom_property_roundtrip(self) -> None:
        """Test that protected custom properties survive roundtrip."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Custom Test")
        entry.set_custom_property("SecretKey", "my-api-key-12345", protected=True)

        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        e = db2.find_entries(title="Custom Test")[0]
        assert e.get_custom_property("SecretKey") == "my-api-key-12345"

    def test_empty_password_roundtrip(self) -> None:
        """Test that empty/None password survives roundtrip."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Empty Pass")
        entry.password = ""

        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        e = db2.find_entries(title="Empty Pass")[0]
        # Empty string becomes None in XML parsing (both represent "no password")
        assert e.password is None or e.password == ""

    def test_unicode_password_roundtrip(self) -> None:
        """Test that unicode password survives roundtrip."""
        db = Database.create(password="test")
        db.root_group.create_entry(
            title="Unicode",
            password="pässwörd123!@#日本語",
        )

        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        e = db2.find_entries(title="Unicode")[0]
        assert e.password == "pässwörd123!@#日本語"


class TestFindGroupsFirst:
    """Tests for find_groups() with first parameter."""

    def test_find_groups_first_returns_single(self) -> None:
        """Test find_groups(first=True) returns single group."""
        db = Database.create(password="test")
        db.root_group.create_subgroup(name="Group1")
        db.root_group.create_subgroup(name="Group2")

        # first=True should return single group or None
        result = db.find_groups(name="Group1", first=True)
        assert isinstance(result, Group)
        assert result.name == "Group1"

    def test_find_groups_first_no_match_returns_none(self) -> None:
        """Test find_groups(first=True) returns None when no match."""
        db = Database.create(password="test")
        result = db.find_groups(name="NonExistent", first=True)
        assert result is None

    def test_find_groups_first_false_returns_list(self) -> None:
        """Test find_groups(first=False) returns list."""
        db = Database.create(password="test")
        db.root_group.create_subgroup(name="Group1")
        db.root_group.create_subgroup(name="Group2")

        result = db.find_groups(first=False)
        assert isinstance(result, list)
        # Root group plus two subgroups
        assert len(result) >= 2

    def test_group_find_groups_first(self) -> None:
        """Test Group.find_groups() with first parameter."""
        db = Database.create(password="test")
        parent = db.root_group.create_subgroup(name="Parent")
        parent.create_subgroup(name="Child1")
        parent.create_subgroup(name="Child2")

        result = parent.find_groups(name="Child1", first=True)
        assert isinstance(result, Group)
        assert result.name == "Child1"


class TestDumpMethods:
    """Tests for dump() debug helper methods."""

    def test_database_dump(self) -> None:
        """Test Database.dump() returns formatted string."""
        db = Database.create(password="test", database_name="TestVault")
        db.root_group.create_entry(title="Entry1", username="user1")
        db.root_group.create_entry(title="Entry2", username="user2")
        db.root_group.create_subgroup(name="Subgroup")

        dump = db.dump()
        assert isinstance(dump, str)
        assert "TestVault" in dump
        assert "KDBX" in dump
        assert "entries: 2" in dump.lower()
        assert "groups: 2" in dump.lower()

    def test_entry_dump(self) -> None:
        """Test Entry.dump() returns formatted string."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(
            title="TestEntry",
            username="testuser",
            url="https://example.com",
        )
        entry.tags = "tag1, tag2"

        dump = entry.dump()
        assert isinstance(dump, str)
        assert "TestEntry" in dump
        assert "testuser" in dump
        assert "example.com" in dump
        assert "tag1" in dump

    def test_group_dump(self) -> None:
        """Test Group.dump() returns formatted string."""
        db = Database.create(password="test")
        group = db.root_group.create_subgroup(name="TestGroup")
        group.create_entry(title="Entry1")
        group.create_entry(title="Entry2")
        group.create_subgroup(name="SubGroup")

        dump = group.dump()
        assert isinstance(dump, str)
        assert "TestGroup" in dump
        assert "Entries: 2" in dump
        assert "Subgroups: 1" in dump

    def test_group_dump_recursive(self) -> None:
        """Test Group.dump(recursive=True) includes children."""
        db = Database.create(password="test")
        group = db.root_group.create_subgroup(name="Parent")
        group.create_entry(title="EntryInParent")
        child = group.create_subgroup(name="Child")
        child.create_entry(title="EntryInChild")

        dump = group.dump(recursive=True)
        assert "Parent" in dump
        assert "Child" in dump
        assert "EntryInParent" in dump
        assert "EntryInChild" in dump


class TestOpenInteractive:
    """Tests for Database.open_interactive() method."""

    def test_open_interactive_success(self, tmp_path: Path) -> None:
        """Test open_interactive with correct password."""
        from unittest.mock import patch

        db_path = tmp_path / "test.kdbx"
        db = Database.create(password="correct")
        db.root_group.create_entry(title="Test")
        db.save(db_path)

        with patch("getpass.getpass", return_value="correct"):
            db2 = Database.open_interactive(db_path)
            assert db2 is not None
            entries = db2.find_entries(title="Test")
            assert len(entries) == 1

    def test_open_interactive_retry_then_success(self, tmp_path: Path) -> None:
        """Test open_interactive with retry on wrong password."""
        from unittest.mock import patch

        db_path = tmp_path / "test.kdbx"
        db = Database.create(password="correct")
        db.save(db_path)

        # First two calls return wrong password, third returns correct
        with patch("getpass.getpass", side_effect=["wrong1", "wrong2", "correct"]):
            with patch("builtins.print"):  # Suppress retry message
                db2 = Database.open_interactive(db_path, max_attempts=3)
                assert db2 is not None

    def test_open_interactive_max_attempts_exceeded(self, tmp_path: Path) -> None:
        """Test open_interactive raises after max_attempts."""
        from unittest.mock import patch

        db_path = tmp_path / "test.kdbx"
        db = Database.create(password="correct")
        db.save(db_path)

        with patch("getpass.getpass", return_value="wrong"):
            with patch("builtins.print"):  # Suppress retry messages
                with pytest.raises(AuthenticationError, match="3 attempts"):
                    Database.open_interactive(db_path, max_attempts=3)

    def test_open_interactive_with_keyfile(self, tmp_path: Path) -> None:
        """Test open_interactive with keyfile."""
        from unittest.mock import patch

        db_path = tmp_path / "test.kdbx"
        key_path = tmp_path / "test.key"

        # Create a simple keyfile
        key_path.write_bytes(os.urandom(32))

        db = Database.create(password="pass", keyfile=key_path)
        db.save(db_path)

        with patch("getpass.getpass", return_value="pass"):
            db2 = Database.open_interactive(db_path, keyfile=key_path)
            assert db2 is not None

    def test_open_interactive_custom_prompt(self, tmp_path: Path) -> None:
        """Test open_interactive uses custom prompt."""
        from unittest.mock import patch

        db_path = tmp_path / "test.kdbx"
        db = Database.create(password="test")
        db.save(db_path)

        mock_getpass = patch("getpass.getpass", return_value="test")
        with mock_getpass as m:
            Database.open_interactive(db_path, prompt="Enter vault password: ")
            m.assert_called_with("Enter vault password: ")
