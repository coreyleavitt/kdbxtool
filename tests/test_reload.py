"""Tests for database reload functionality."""

import tempfile
from pathlib import Path

import pytest

from kdbxtool import Database, DatabaseError, MissingCredentialsError


class TestReload:
    """Tests for Database.reload() method."""

    def test_reload_discards_unsaved_changes(self) -> None:
        """Test that reload discards unsaved changes."""
        with tempfile.NamedTemporaryFile(suffix=".kdbx", delete=False) as f:
            filepath = Path(f.name)

        try:
            # Create and save a database
            db = Database.create(filepath=filepath, password="test")
            db.root_group.create_entry(title="Original")
            db.save()

            # Make changes without saving
            db.root_group.create_entry(title="Unsaved")
            assert len(db.find_entries(title="Unsaved")) == 1

            # Reload should discard unsaved changes
            db.reload()

            assert len(db.find_entries(title="Original")) == 1
            assert len(db.find_entries(title="Unsaved")) == 0
        finally:
            filepath.unlink(missing_ok=True)

    def test_reload_syncs_external_changes(self) -> None:
        """Test that reload picks up external modifications."""
        with tempfile.NamedTemporaryFile(suffix=".kdbx", delete=False) as f:
            filepath = Path(f.name)

        try:
            # Create and save a database
            db1 = Database.create(filepath=filepath, password="test")
            db1.root_group.create_entry(title="Entry1")
            db1.save()

            # Open the same database in another instance and modify it
            db2 = Database.open(filepath, password="test")
            db2.root_group.create_entry(title="Entry2")
            db2.save()

            # db1 shouldn't see Entry2 yet
            assert len(db1.find_entries(title="Entry2")) == 0

            # After reload, db1 should see the external changes
            db1.reload()
            assert len(db1.find_entries(title="Entry2")) == 1
        finally:
            filepath.unlink(missing_ok=True)

    def test_reload_without_filepath_raises_error(self) -> None:
        """Test that reload raises error if opened from bytes."""
        db = Database.create(password="test")
        data = db.to_bytes()

        # Open from bytes (no filepath)
        db2 = Database.open_bytes(data, password="test")

        with pytest.raises(DatabaseError, match="wasn't opened from a file"):
            db2.reload()

    def test_reload_without_credentials_raises_error(self) -> None:
        """Test that reload raises error if credentials are cleared."""
        with tempfile.NamedTemporaryFile(suffix=".kdbx", delete=False) as f:
            filepath = Path(f.name)

        try:
            db = Database.create(filepath=filepath, password="test")
            db.save()

            # Clear credentials
            db.zeroize_credentials()

            with pytest.raises(MissingCredentialsError):
                db.reload()
        finally:
            filepath.unlink(missing_ok=True)

    def test_reload_preserves_filepath(self) -> None:
        """Test that reload preserves the filepath."""
        with tempfile.NamedTemporaryFile(suffix=".kdbx", delete=False) as f:
            filepath = Path(f.name)

        try:
            db = Database.create(filepath=filepath, password="test")
            db.save()

            original_path = db.filepath
            db.reload()

            assert db.filepath == original_path
        finally:
            filepath.unlink(missing_ok=True)

    def test_reload_with_keyfile(self) -> None:
        """Test reload with keyfile authentication."""
        with (
            tempfile.NamedTemporaryFile(suffix=".kdbx", delete=False) as db_file,
            tempfile.NamedTemporaryFile(suffix=".key", delete=False) as key_file,
        ):
            filepath = Path(db_file.name)
            keyfile = Path(key_file.name)
            keyfile.write_bytes(b"keyfile-content-12345678901234567890")

        try:
            db = Database.create(filepath=filepath, password="test", keyfile=keyfile)
            db.root_group.create_entry(title="Test")
            db.save()

            # Make unsaved changes
            db.root_group.create_entry(title="Unsaved")

            # Reload should work with keyfile
            db.reload()

            assert len(db.find_entries(title="Test")) == 1
            assert len(db.find_entries(title="Unsaved")) == 0
        finally:
            filepath.unlink(missing_ok=True)
            keyfile.unlink(missing_ok=True)

    def test_reload_updates_settings(self) -> None:
        """Test that reload updates database settings."""
        with tempfile.NamedTemporaryFile(suffix=".kdbx", delete=False) as f:
            filepath = Path(f.name)

        try:
            db1 = Database.create(filepath=filepath, password="test", database_name="Original")
            db1.save()

            # Modify settings in another instance
            db2 = Database.open(filepath, password="test")
            db2.settings.database_name = "Modified"
            db2.save()

            # Reload should pick up the new settings
            db1.reload()
            assert db1.settings.database_name == "Modified"
        finally:
            filepath.unlink(missing_ok=True)
