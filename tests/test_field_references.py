"""Tests for field reference support ({REF:X@Y:Z} syntax)."""

import uuid

import pytest

from kdbxtool import Database


class TestEntryRef:
    """Tests for Entry.ref() method."""

    def test_ref_password(self) -> None:
        """Test creating password reference."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(
            title="Main",
            username="user",
            password="secret123",
        )

        ref = entry.ref("password")

        assert ref == f"{{REF:P@I:{entry.uuid.hex.upper()}}}"

    def test_ref_username(self) -> None:
        """Test creating username reference."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Main", username="admin")

        ref = entry.ref("username")

        assert ref == f"{{REF:U@I:{entry.uuid.hex.upper()}}}"

    def test_ref_title(self) -> None:
        """Test creating title reference."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Important Entry")

        ref = entry.ref("title")

        assert ref == f"{{REF:T@I:{entry.uuid.hex.upper()}}}"

    def test_ref_url(self) -> None:
        """Test creating URL reference."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Site", url="https://example.com")

        ref = entry.ref("url")

        assert ref == f"{{REF:A@I:{entry.uuid.hex.upper()}}}"

    def test_ref_notes(self) -> None:
        """Test creating notes reference."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Entry", notes="Some notes")

        ref = entry.ref("notes")

        assert ref == f"{{REF:N@I:{entry.uuid.hex.upper()}}}"

    def test_ref_uuid(self) -> None:
        """Test creating UUID reference."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Entry")

        ref = entry.ref("uuid")

        assert ref == f"{{REF:I@I:{entry.uuid.hex.upper()}}}"

    def test_ref_case_insensitive(self) -> None:
        """Test that field name is case-insensitive."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Main", password="secret")

        assert entry.ref("Password") == entry.ref("password")
        assert entry.ref("PASSWORD") == entry.ref("password")

    def test_ref_invalid_field(self) -> None:
        """Test that invalid field raises ValueError."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Entry")

        with pytest.raises(ValueError, match="Invalid field"):
            entry.ref("invalid")


class TestDatabaseDeref:
    """Tests for Database.deref() method."""

    def test_deref_password_by_uuid(self) -> None:
        """Test dereferencing password by UUID."""
        db = Database.create(password="test")
        main_entry = db.root_group.create_entry(
            title="Main",
            username="admin",
            password="supersecret",
        )

        ref = main_entry.ref("password")
        result = db.deref(ref)

        assert result == "supersecret"

    def test_deref_username_by_uuid(self) -> None:
        """Test dereferencing username by UUID."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Entry", username="testuser")

        ref = entry.ref("username")
        result = db.deref(ref)

        assert result == "testuser"

    def test_deref_with_prefix_and_suffix(self) -> None:
        """Test dereferencing with text before and after reference."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Entry", username="admin")

        ref = entry.ref("username")
        value = f"domain\\{ref}@company"
        result = db.deref(value)

        assert result == "domain\\admin@company"

    def test_deref_multiple_references(self) -> None:
        """Test dereferencing multiple references in one value."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(
            title="Entry",
            username="user",
            password="pass",
        )

        username_ref = entry.ref("username")
        password_ref = entry.ref("password")
        value = f"{username_ref}:{password_ref}"
        result = db.deref(value)

        assert result == "user:pass"

    def test_deref_no_reference(self) -> None:
        """Test that non-reference strings are returned unchanged."""
        db = Database.create(password="test")

        result = db.deref("plain text")

        assert result == "plain text"

    def test_deref_empty_string(self) -> None:
        """Test that empty string is returned unchanged."""
        db = Database.create(password="test")

        result = db.deref("")

        assert result == ""

    def test_deref_none(self) -> None:
        """Test that None is returned unchanged."""
        db = Database.create(password="test")

        result = db.deref(None)

        assert result is None

    def test_deref_broken_reference(self) -> None:
        """Test that reference to non-existent entry returns None."""
        db = Database.create(password="test")

        # Reference to non-existent UUID
        fake_uuid = "A" * 32
        ref = f"{{REF:P@I:{fake_uuid}}}"
        result = db.deref(ref)

        assert result is None

    def test_deref_invalid_uuid(self) -> None:
        """Test that invalid UUID in reference returns None."""
        db = Database.create(password="test")

        ref = "{REF:P@I:NOTAUUID}"
        result = db.deref(ref)

        assert result is None

    def test_deref_chained_references(self) -> None:
        """Test dereferencing chained references (A -> B -> C)."""
        db = Database.create(password="test")

        # Create entry C with actual password
        entry_c = db.root_group.create_entry(title="C", password="final_password")

        # Create entry B with reference to C
        entry_b = db.root_group.create_entry(
            title="B",
            password=entry_c.ref("password"),
        )

        # Create entry A with reference to B
        entry_a = db.root_group.create_entry(
            title="A",
            password=entry_b.ref("password"),
        )

        # Deref A should resolve through B to C's actual password
        result = db.deref(entry_a.password)

        assert result == "final_password"

    def test_deref_by_title(self) -> None:
        """Test dereferencing by title search."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(
            title="UniqueTitle",
            password="mypassword",
        )

        # Reference password by title
        ref = "{REF:P@T:UniqueTitle}"
        result = db.deref(ref)

        assert result == "mypassword"

    def test_deref_by_username(self) -> None:
        """Test dereferencing by username search."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(
            title="Entry",
            username="unique_user",
            password="thepassword",
        )

        # Reference password by username
        ref = "{REF:P@U:unique_user}"
        result = db.deref(ref)

        assert result == "thepassword"


class TestEntryDeref:
    """Tests for Entry.deref() method."""

    def test_entry_deref(self) -> None:
        """Test Entry.deref() method."""
        db = Database.create(password="test")
        main_entry = db.root_group.create_entry(
            title="Main",
            password="the_password",
        )
        ref_entry = db.root_group.create_entry(
            title="Reference",
            password=main_entry.ref("password"),
        )

        result = ref_entry.deref("password")

        assert result == "the_password"

    def test_entry_deref_no_reference(self) -> None:
        """Test Entry.deref() with non-reference value."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(
            title="Entry",
            password="plainpassword",
        )

        result = entry.deref("password")

        assert result == "plainpassword"

    def test_entry_deref_no_database(self) -> None:
        """Test that Entry.deref() raises when not connected to database."""
        from kdbxtool.models import Entry

        entry = Entry.create(title="Standalone", password="{REF:P@I:00000000}")

        with pytest.raises(ValueError, match="not connected to a database"):
            entry.deref("password")


class TestFieldReferenceRoundtrip:
    """Tests for field reference roundtrip scenarios."""

    def test_reference_survives_save_reload(self) -> None:
        """Test that references survive save and reload."""
        import tempfile
        from pathlib import Path

        from kdbxtool import Argon2Config

        db = Database.create(password="test")
        main_entry = db.root_group.create_entry(
            title="Main",
            password="original_password",
        )
        ref_entry = db.root_group.create_entry(
            title="Reference",
            password=main_entry.ref("password"),
        )

        with tempfile.NamedTemporaryFile(suffix=".kdbx", delete=False) as f:
            filepath = Path(f.name)

        try:
            db.save(filepath=filepath, kdf_config=Argon2Config.fast())

            # Reload and verify
            db2 = Database.open(filepath, password="test")
            ref_entry2 = db2.find_entries(title="Reference", first=True)
            assert ref_entry2 is not None

            # Raw value should still be the reference
            assert "{REF:" in ref_entry2.password

            # Deref should still resolve
            assert ref_entry2.deref("password") == "original_password"
        finally:
            filepath.unlink(missing_ok=True)

    def test_update_original_affects_reference(self) -> None:
        """Test that updating original entry affects referenced values."""
        db = Database.create(password="test")
        main_entry = db.root_group.create_entry(
            title="Main",
            password="initial_password",
        )
        ref_entry = db.root_group.create_entry(
            title="Reference",
            password=main_entry.ref("password"),
        )

        # Verify initial deref
        assert ref_entry.deref("password") == "initial_password"

        # Update original
        main_entry.password = "updated_password"

        # Deref should return updated value
        assert ref_entry.deref("password") == "updated_password"
