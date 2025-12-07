"""Tests for XML export functionality."""

import tempfile
from pathlib import Path

from kdbxtool import Database


class TestXmlExport:
    """Tests for Database.xml() and dump_xml() methods."""

    def test_xml_returns_bytes(self) -> None:
        """Test that xml() returns bytes."""
        db = Database.create(password="test")
        xml_data = db.xml()

        assert isinstance(xml_data, bytes)

    def test_xml_contains_declaration(self) -> None:
        """Test that xml() includes XML declaration."""
        db = Database.create(password="test")
        xml_data = db.xml()

        assert xml_data.startswith(b"<?xml version=")

    def test_xml_contains_database_structure(self) -> None:
        """Test that xml() contains expected structure."""
        db = Database.create(password="test", database_name="TestDB")
        db.root_group.create_entry(title="MyEntry", username="user", password="secret")

        xml_data = db.xml()

        assert b"<KeePassFile>" in xml_data
        assert b"<Meta>" in xml_data
        assert b"<Root>" in xml_data
        assert b"<DatabaseName>TestDB</DatabaseName>" in xml_data
        # Entry fields are in String elements: <String><Key>Title</Key><Value>...</Value></String>
        assert b"<Key>Title</Key><Value>MyEntry</Value>" in xml_data

    def test_xml_shows_plaintext_password(self) -> None:
        """Test that xml() shows passwords in plaintext (not encrypted)."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="Test", password="supersecret123")

        xml_data = db.xml()

        # Password should be visible in plaintext
        assert b"supersecret123" in xml_data

    def test_xml_pretty_print(self) -> None:
        """Test that pretty_print adds indentation."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="Test")

        xml_compact = db.xml(pretty_print=False)
        xml_pretty = db.xml(pretty_print=True)

        # Pretty print should add newlines and indentation
        assert xml_pretty.count(b"\n") > xml_compact.count(b"\n")
        assert b"  " in xml_pretty  # Indentation spaces

    def test_dump_xml_creates_file(self) -> None:
        """Test that dump_xml() creates a file."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="Test")

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
            filepath = Path(f.name)

        try:
            db.dump_xml(filepath)

            assert filepath.exists()
            content = filepath.read_bytes()
            assert b"<KeePassFile>" in content
        finally:
            filepath.unlink(missing_ok=True)

    def test_dump_xml_default_pretty_print(self) -> None:
        """Test that dump_xml() uses pretty print by default."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="Test")

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
            filepath = Path(f.name)

        try:
            db.dump_xml(filepath)

            content = filepath.read_bytes()
            # Should have indentation
            assert b"  " in content
        finally:
            filepath.unlink(missing_ok=True)

    def test_dump_xml_no_pretty_print(self) -> None:
        """Test that dump_xml() can disable pretty print."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="Test")

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
            filepath = Path(f.name)

        try:
            db.dump_xml(filepath, pretty_print=False)

            content = filepath.read_bytes()
            # Should be more compact (less newlines)
            lines = content.strip().split(b"\n")
            # Without pretty print, most content is on fewer lines
            assert len(lines) < 50  # Compact format
        finally:
            filepath.unlink(missing_ok=True)

    def test_xml_includes_groups(self) -> None:
        """Test that xml() includes group hierarchy."""
        db = Database.create(password="test")
        subgroup = db.root_group.create_subgroup("SubFolder")
        subgroup.create_entry(title="NestedEntry")

        xml_data = db.xml()

        assert b"<Name>SubFolder</Name>" in xml_data
        assert b"<Key>Title</Key><Value>NestedEntry</Value>" in xml_data

    def test_xml_includes_custom_properties(self) -> None:
        """Test that xml() includes custom properties."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Test")
        entry.set_custom_property("API_KEY", "mykey123")

        xml_data = db.xml()

        assert b"API_KEY" in xml_data
        assert b"mykey123" in xml_data

    def test_xml_roundtrip_preserves_data(self) -> None:
        """Test that save/load doesn't affect xml() output structure."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="Test", password="secret")

        # Get XML before save
        xml_before = db.xml()

        # Save and reload
        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        # Get XML after reload
        xml_after = db2.xml()

        # Both should contain the same entry data
        assert b"<Key>Title</Key><Value>Test</Value>" in xml_before
        assert b"<Key>Title</Key><Value>Test</Value>" in xml_after
        assert b"secret" in xml_before
        assert b"secret" in xml_after

    def test_xml_with_history(self) -> None:
        """Test that xml() includes history entries."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Test", password="oldpass")
        entry.save_history()
        entry.password = "newpass"

        xml_data = db.xml()

        assert b"<History>" in xml_data
        # Both old and new password should be visible
        assert b"oldpass" in xml_data
        assert b"newpass" in xml_data

    def test_xml_with_attachments(self) -> None:
        """Test that xml() includes binary references."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Test")
        db.add_attachment(entry, "test.txt", b"file content")

        xml_data = db.xml()

        assert b"test.txt" in xml_data
