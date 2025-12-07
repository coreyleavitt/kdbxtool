"""Tests for Twofish cipher integration via oxifish.

These tests verify that kdbxtool can correctly create, open, and modify
KDBX databases encrypted with Twofish-256-CBC when the oxifish package
is installed.
"""

import tempfile
from pathlib import Path

import pytest

from kdbxtool import Database, TwofishNotAvailableError
from kdbxtool.security import Cipher
from kdbxtool.security.crypto import TWOFISH_AVAILABLE

# Skip all tests in this module if oxifish is not available
pytestmark = pytest.mark.skipif(
    not TWOFISH_AVAILABLE,
    reason="oxifish package not installed",
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
TEST_TWOFISH_KDBX = FIXTURES_DIR / "test4_twofish.kdbx"
TEST_PASSWORD = "password"


class TestTwofishDatabaseOpen:
    """Tests for opening Twofish-encrypted databases."""

    @pytest.fixture
    def twofish_db(self) -> Database:
        """Open test4_twofish.kdbx database."""
        if not TEST_TWOFISH_KDBX.exists():
            pytest.skip("Test fixture test4_twofish.kdbx not found")
        return Database.open(TEST_TWOFISH_KDBX, password=TEST_PASSWORD)

    def test_open_twofish_database(self, twofish_db: Database) -> None:
        """Test opening a Twofish-encrypted database."""
        assert twofish_db is not None
        assert twofish_db.root_group is not None
        assert twofish_db.root_group.is_root_group

    def test_open_twofish_has_entries(self, twofish_db: Database) -> None:
        """Test that opened Twofish database has entries."""
        entries = list(twofish_db.iter_entries())
        assert len(entries) >= 1
        assert entries[0].title == "Test Entry"
        assert entries[0].username == "testuser"

    def test_open_twofish_bytes(self) -> None:
        """Test opening Twofish database from bytes."""
        if not TEST_TWOFISH_KDBX.exists():
            pytest.skip("Test fixture test4_twofish.kdbx not found")

        data = TEST_TWOFISH_KDBX.read_bytes()
        db = Database.open_bytes(data, password=TEST_PASSWORD)
        assert db.root_group is not None
        entries = list(db.iter_entries())
        assert len(entries) >= 1


class TestTwofishDatabaseCreate:
    """Tests for creating Twofish-encrypted databases."""

    def test_create_twofish_database(self) -> None:
        """Test creating a new Twofish-encrypted database."""
        db = Database.create(
            password="testpassword",
            database_name="Twofish Test",
            cipher=Cipher.TWOFISH256_CBC,
        )

        assert db.root_group is not None
        assert db.root_group.name == "Twofish Test"

    def test_create_twofish_with_entries(self) -> None:
        """Test creating Twofish database with entries."""
        db = Database.create(
            password="testpassword",
            cipher=Cipher.TWOFISH256_CBC,
        )

        entry = db.root_group.create_entry(
            title="My Entry",
            username="myuser",
            password="secret123",
            url="https://test.example.com",
        )

        assert entry.title == "My Entry"
        assert entry.username == "myuser"
        assert entry.password == "secret123"


class TestTwofishRoundtrip:
    """Tests for saving and reopening Twofish databases."""

    def test_create_save_reopen(self) -> None:
        """Test full roundtrip: create, save, reopen, verify."""
        with tempfile.NamedTemporaryFile(suffix=".kdbx", delete=False) as f:
            filepath = Path(f.name)

        try:
            # Create database
            db = Database.create(
                filepath=filepath,
                password="roundtriptest",
                cipher=Cipher.TWOFISH256_CBC,
            )

            # Add entry
            entry = db.root_group.create_entry(
                title="Roundtrip Entry",
                username="rounduser",
                password="roundpass",
            )
            entry_uuid = entry.uuid

            # Save
            db.save()

            # Reopen
            db2 = Database.open(filepath, password="roundtriptest")

            # Verify
            entries = list(db2.iter_entries())
            assert len(entries) == 1
            assert entries[0].title == "Roundtrip Entry"
            assert entries[0].username == "rounduser"
            assert entries[0].password == "roundpass"
            assert entries[0].uuid == entry_uuid

        finally:
            filepath.unlink(missing_ok=True)

    def test_to_bytes_roundtrip(self) -> None:
        """Test in-memory roundtrip with to_bytes."""
        # Create database
        db = Database.create(
            password="bytestest",
            cipher=Cipher.TWOFISH256_CBC,
        )

        # Add entry
        db.root_group.create_entry(
            title="Bytes Entry",
            username="bytesuser",
            password="bytespass",
        )

        # Export to bytes
        data = db.to_bytes()
        assert len(data) > 0

        # Import from bytes
        db2 = Database.open_bytes(data, password="bytestest")

        # Verify
        entries = list(db2.iter_entries())
        assert len(entries) == 1
        assert entries[0].title == "Bytes Entry"

    def test_modify_and_resave(self) -> None:
        """Test modifying and resaving a Twofish database."""
        with tempfile.NamedTemporaryFile(suffix=".kdbx", delete=False) as f:
            filepath = Path(f.name)

        try:
            # Create and save
            db = Database.create(
                filepath=filepath,
                password="modifytest",
                cipher=Cipher.TWOFISH256_CBC,
            )
            db.root_group.create_entry(title="Original", username="orig")
            db.save()

            # Reopen, modify, resave
            db2 = Database.open(filepath, password="modifytest")
            entries = list(db2.iter_entries())
            entries[0].title = "Modified"
            db2.root_group.create_entry(title="New Entry", username="new")
            db2.save()

            # Verify modifications
            db3 = Database.open(filepath, password="modifytest")
            entries = list(db3.iter_entries())
            assert len(entries) == 2
            titles = {e.title for e in entries}
            assert "Modified" in titles
            assert "New Entry" in titles

        finally:
            filepath.unlink(missing_ok=True)


class TestTwofishNotAvailable:
    """Tests for graceful handling when oxifish is not installed."""

    @pytest.mark.skipif(
        TWOFISH_AVAILABLE,
        reason="oxifish is available, cannot test unavailable behavior",
    )
    def test_twofish_not_available_error(self) -> None:
        """Test that TwofishNotAvailableError is raised without oxifish."""
        from kdbxtool.security.crypto import CipherContext

        with pytest.raises(TwofishNotAvailableError) as exc_info:
            CipherContext(
                Cipher.TWOFISH256_CBC,
                key=b"\x00" * 32,
                iv=b"\x00" * 16,
            )

        assert "oxifish" in str(exc_info.value)
        assert "kdbxtool[twofish]" in str(exc_info.value)
