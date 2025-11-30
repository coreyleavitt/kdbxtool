"""Tests for high-level Database API."""

import os
import tempfile
from pathlib import Path

import pytest

from kdbxtool import Database, DatabaseSettings, Entry, Group
from kdbxtool.security import Cipher, KdfType


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
        with pytest.raises(ValueError, match="HMAC|wrong|credentials"):
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
        with pytest.raises(ValueError, match="password or keyfile"):
            Database.create()

    def test_create_with_options(self) -> None:
        """Test creating database with custom options."""
        db = Database.create(
            password="test",
            database_name="Custom DB",
            cipher=Cipher.CHACHA20,
            kdf_type=KdfType.ARGON2D,
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
        with pytest.raises(ValueError, match="No filepath"):
            db.save()

    def test_to_bytes_no_credentials_raises(self) -> None:
        """Test that to_bytes without credentials raises error."""
        db = Database.create(password="test")
        db._password = None
        db._keyfile_data = None
        with pytest.raises(ValueError, match="No credentials"):
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
        db.root_group.create_entry(title="GitHub", username="dev@example.com", url="https://github.com")
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
        assert len(groups) == 2  # Work and Personal (not root)


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
        with pytest.raises(ValueError, match="password or keyfile"):
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
        assert "1 groups" in s
