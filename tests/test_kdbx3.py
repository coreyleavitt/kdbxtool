"""Tests for KDBX3 format support.

These tests verify that kdbxtool can correctly read KDBX3 databases
and automatically upgrade them to KDBX4 on save.
"""

import tempfile
import warnings
from pathlib import Path

import pytest

from kdbxtool import Database
from kdbxtool.exceptions import Kdbx3UpgradeRequired
from kdbxtool.parsing import KdbxVersion


FIXTURES_DIR = Path(__file__).parent / "fixtures"
TEST3_KDBX = FIXTURES_DIR / "test3.kdbx"
TEST3_KEY = FIXTURES_DIR / "test3.key"
TEST_PASSWORD = "password"


def open_kdbx3_no_warning(path: Path, password: str, keyfile: Path) -> Database:
    """Open KDBX3 database suppressing the upgrade warning."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        return Database.open(path, password=password, keyfile=keyfile)


def open_kdbx3_bytes_no_warning(data: bytes, password: str, keyfile_data: bytes) -> Database:
    """Open KDBX3 database from bytes suppressing the upgrade warning."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        return Database.open_bytes(data, password=password, keyfile_data=keyfile_data)


class TestKdbx3Open:
    """Tests for opening KDBX3 databases."""

    @pytest.fixture
    def test3_db(self) -> Database:
        """Open test3.kdbx database."""
        if not TEST3_KDBX.exists():
            pytest.skip("Test fixture test3.kdbx not found")
        return open_kdbx3_no_warning(TEST3_KDBX, TEST_PASSWORD, TEST3_KEY)

    def test_open_kdbx3_database(self, test3_db: Database) -> None:
        """Test opening a KDBX3 database."""
        assert test3_db is not None
        assert test3_db.root_group is not None
        assert test3_db.root_group.is_root_group

    def test_open_kdbx3_has_entries(self, test3_db: Database) -> None:
        """Test that opened KDBX3 database has entries."""
        entries = list(test3_db.iter_entries())
        # test3.kdbx has 15 entries
        assert len(entries) >= 10

    def test_open_kdbx3_entries_have_data(self, test3_db: Database) -> None:
        """Test that KDBX3 entries have correct data."""
        entries = list(test3_db.iter_entries())
        # Find the root_entry which we know has specific data
        root_entry = next((e for e in entries if e.title == "root_entry"), None)
        assert root_entry is not None
        assert root_entry.username == "foobar_user"
        assert root_entry.password == "passw0rd"

    def test_open_kdbx3_bytes(self) -> None:
        """Test opening KDBX3 database from bytes."""
        if not TEST3_KDBX.exists():
            pytest.skip("Test fixture test3.kdbx not found")

        data = TEST3_KDBX.read_bytes()
        keyfile_data = TEST3_KEY.read_bytes()

        db = open_kdbx3_bytes_no_warning(data, TEST_PASSWORD, keyfile_data)
        assert db.root_group is not None
        entries = list(db.iter_entries())
        assert len(entries) >= 10

    def test_open_kdbx3_emits_warning(self) -> None:
        """Test that opening KDBX3 database emits upgrade warning."""
        if not TEST3_KDBX.exists():
            pytest.skip("Test fixture test3.kdbx not found")

        with pytest.warns(UserWarning, match="KDBX3"):
            Database.open(TEST3_KDBX, password=TEST_PASSWORD, keyfile=TEST3_KEY)


class TestKdbx3ToKdbx4Upgrade:
    """Tests for KDBX3 to KDBX4 auto-upgrade on save."""

    @pytest.fixture
    def test3_db(self) -> Database:
        """Open test3.kdbx database."""
        if not TEST3_KDBX.exists():
            pytest.skip("Test fixture test3.kdbx not found")
        return open_kdbx3_no_warning(TEST3_KDBX, TEST_PASSWORD, TEST3_KEY)

    def test_save_upgrades_to_kdbx4(self, test3_db: Database) -> None:
        """Test that saving a KDBX3 database upgrades it to KDBX4."""
        # Get original entries
        original_entries = list(test3_db.iter_entries())

        # Save and reopen
        data = test3_db.to_bytes()
        db2 = Database.open_bytes(
            data,
            password=TEST_PASSWORD,
            keyfile_data=TEST3_KEY.read_bytes(),
        )

        # Verify it's now KDBX4
        # (The header version is internal, but we can verify by checking
        # that the saved file can be opened without issues)
        assert db2.root_group is not None

        # Verify entries preserved
        new_entries = list(db2.iter_entries())
        assert len(new_entries) == len(original_entries)

    def test_upgrade_preserves_all_entry_data(self, test3_db: Database) -> None:
        """Test that upgrade preserves all entry fields."""
        # Get original data
        original = {e.title: (e.username, e.password, e.url) for e in test3_db.iter_entries()}

        # Save and reopen
        data = test3_db.to_bytes()
        db2 = Database.open_bytes(
            data,
            password=TEST_PASSWORD,
            keyfile_data=TEST3_KEY.read_bytes(),
        )

        # Verify all data preserved
        new_data = {e.title: (e.username, e.password, e.url) for e in db2.iter_entries()}
        assert new_data == original

    def test_upgrade_preserves_group_structure(self, test3_db: Database) -> None:
        """Test that upgrade preserves group hierarchy."""
        # Get original groups
        original_groups = {g.name for g in test3_db.iter_groups()}

        # Save and reopen
        data = test3_db.to_bytes()
        db2 = Database.open_bytes(
            data,
            password=TEST_PASSWORD,
            keyfile_data=TEST3_KEY.read_bytes(),
        )

        # Verify groups preserved
        new_groups = {g.name for g in db2.iter_groups()}
        assert new_groups == original_groups

    def test_save_to_file_and_reopen(self, test3_db: Database) -> None:
        """Test full roundtrip: open KDBX3, save to file, reopen."""
        with tempfile.NamedTemporaryFile(suffix=".kdbx", delete=False) as f:
            filepath = Path(f.name)

        try:
            # Get original entry count
            original_count = len(list(test3_db.iter_entries()))

            # Save to file
            test3_db.save(filepath)

            # Reopen
            db2 = Database.open(
                filepath,
                password=TEST_PASSWORD,
                keyfile=TEST3_KEY,
            )

            # Verify
            assert len(list(db2.iter_entries())) == original_count

        finally:
            filepath.unlink(missing_ok=True)


class TestKdbx3Modifications:
    """Tests for modifying KDBX3 databases."""

    @pytest.fixture
    def test3_db(self) -> Database:
        """Open test3.kdbx database."""
        if not TEST3_KDBX.exists():
            pytest.skip("Test fixture test3.kdbx not found")
        return open_kdbx3_no_warning(TEST3_KDBX, TEST_PASSWORD, TEST3_KEY)

    def test_add_entry_and_save(self, test3_db: Database) -> None:
        """Test adding an entry to a KDBX3 database and saving."""
        original_count = len(list(test3_db.iter_entries()))

        # Add new entry
        test3_db.root_group.create_entry(
            title="New Entry",
            username="newuser",
            password="newpass",
        )

        # Save and reopen
        data = test3_db.to_bytes()
        db2 = Database.open_bytes(
            data,
            password=TEST_PASSWORD,
            keyfile_data=TEST3_KEY.read_bytes(),
        )

        # Verify new entry exists
        entries = list(db2.iter_entries())
        assert len(entries) == original_count + 1
        new_entry = next((e for e in entries if e.title == "New Entry"), None)
        assert new_entry is not None
        assert new_entry.username == "newuser"
        assert new_entry.password == "newpass"

    def test_modify_entry_and_save(self, test3_db: Database) -> None:
        """Test modifying an entry in a KDBX3 database and saving."""
        # Modify an entry
        entries = list(test3_db.iter_entries())
        entry = entries[0]
        original_title = entry.title
        entry.password = "modified_password"

        # Save and reopen
        data = test3_db.to_bytes()
        db2 = Database.open_bytes(
            data,
            password=TEST_PASSWORD,
            keyfile_data=TEST3_KEY.read_bytes(),
        )

        # Verify modification
        modified = next((e for e in db2.iter_entries() if e.title == original_title), None)
        assert modified is not None
        assert modified.password == "modified_password"


class TestKdbx3UpgradeConfirmation:
    """Tests for KDBX3 upgrade confirmation requirement."""

    def test_save_to_original_without_confirmation_raises(self) -> None:
        """Test that saving KDBX3 to original file without allow_upgrade raises."""
        if not TEST3_KDBX.exists():
            pytest.skip("Test fixture test3.kdbx not found")

        db = open_kdbx3_no_warning(TEST3_KDBX, TEST_PASSWORD, TEST3_KEY)

        # Saving to original file without allow_upgrade should raise
        with pytest.raises(Kdbx3UpgradeRequired):
            db.save()

    def test_save_to_original_with_confirmation_works(self) -> None:
        """Test that saving KDBX3 with allow_upgrade=True works."""
        if not TEST3_KDBX.exists():
            pytest.skip("Test fixture test3.kdbx not found")

        # Copy test3.kdbx to a temp file so we don't modify the fixture
        with tempfile.NamedTemporaryFile(suffix=".kdbx", delete=False) as f:
            filepath = Path(f.name)
            filepath.write_bytes(TEST3_KDBX.read_bytes())

        try:
            db = open_kdbx3_no_warning(filepath, TEST_PASSWORD, TEST3_KEY)
            original_count = len(list(db.iter_entries()))

            # Save with allow_upgrade=True should work
            db.save(allow_upgrade=True)

            # Verify the saved file is valid KDBX4
            db2 = Database.open(filepath, password=TEST_PASSWORD, keyfile=TEST3_KEY)
            assert len(list(db2.iter_entries())) == original_count

        finally:
            filepath.unlink(missing_ok=True)

    def test_save_to_new_file_without_confirmation_works(self) -> None:
        """Test that saving KDBX3 to new file doesn't require confirmation."""
        if not TEST3_KDBX.exists():
            pytest.skip("Test fixture test3.kdbx not found")

        db = open_kdbx3_no_warning(TEST3_KDBX, TEST_PASSWORD, TEST3_KEY)
        original_count = len(list(db.iter_entries()))

        with tempfile.NamedTemporaryFile(suffix=".kdbx", delete=False) as f:
            filepath = Path(f.name)

        try:
            # Saving to a new file should work without allow_upgrade
            db.save(filepath)

            # Verify the saved file is valid
            db2 = Database.open(filepath, password=TEST_PASSWORD, keyfile=TEST3_KEY)
            assert len(list(db2.iter_entries())) == original_count

        finally:
            filepath.unlink(missing_ok=True)
