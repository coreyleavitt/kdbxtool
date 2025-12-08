"""Property-based tests using Hypothesis.

These tests verify roundtrip invariants and edge cases using
randomized inputs to catch issues that example-based tests might miss.
"""

from datetime import timedelta

from hypothesis import given, settings, assume, HealthCheck
from hypothesis import strategies as st

from kdbxtool import Database
from kdbxtool.models import Entry, Group

# Hypothesis settings for slow KDF operations
# Suppress health checks for slow data generation (KDF is intentionally slow)
slow_settings = settings(
    max_examples=10,
    deadline=timedelta(seconds=30),
    suppress_health_check=[HealthCheck.too_slow],
)


# --- Strategies ---

# Safe text that won't break XML
# XML 1.0 only allows: #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD]
# Exclude null bytes, surrogates, and control characters
safe_text = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cs", "Cc"),  # No surrogates or control chars
        blacklist_characters=("\x00",),  # Explicitly no null bytes
        min_codepoint=0x20,  # Start at space (0x20)
    ),
    min_size=0,
    max_size=100,
)

# Non-empty safe text (for fields where empty might become None)
nonempty_safe_text = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cs", "Cc"),
        blacklist_characters=("\x00",),
        min_codepoint=0x20,
    ),
    min_size=1,
    max_size=100,
)

# Entry field values
entry_title = safe_text
entry_username = safe_text
entry_password = safe_text
entry_url = safe_text
entry_notes = safe_text

# Tags (list of safe strings, no semicolons or commas since they're used as delimiters)
# Must contain at least one non-whitespace char to avoid being stripped
tag_text = st.text(
    alphabet=st.characters(
        whitelist_categories=("L", "N", "P", "S"),  # Letters, numbers, punctuation, symbols
        blacklist_characters=(";", ","),  # No semicolons or commas (delimiters)
    ),
    min_size=1,
    max_size=20,
)
entry_tags = st.lists(tag_text, min_size=0, max_size=5)

# Binary data for attachments
binary_data = st.binary(min_size=0, max_size=10000)


class TestEntryRoundtrip:
    """Test that entry fields survive save/open cycle."""

    @slow_settings
    @given(
        title=nonempty_safe_text,
        username=nonempty_safe_text,
        password=nonempty_safe_text,
        url=nonempty_safe_text,
        notes=nonempty_safe_text,
    )
    def test_entry_fields_roundtrip(
        self, title: str, username: str, password: str, url: str, notes: str
    ) -> None:
        """Entry string fields should survive save/open cycle."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(
            title=title,
            username=username,
            password=password,
            url=url,
            notes=notes,
        )

        # Save and reopen
        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        # Find the entry (not the recycle bin entries)
        entries = [e for e in db2.iter_entries() if e.uuid == entry.uuid]
        assert len(entries) == 1
        restored = entries[0]

        assert restored.title == title
        assert restored.username == username
        assert restored.password == password
        assert restored.url == url
        assert restored.notes == notes

    @slow_settings
    @given(tags=entry_tags)
    def test_entry_tags_roundtrip(self, tags: list[str]) -> None:
        """Entry tags should survive save/open cycle."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Test", tags=tags)

        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        entries = [e for e in db2.iter_entries() if e.uuid == entry.uuid]
        assert len(entries) == 1
        restored = entries[0]

        assert restored.tags == tags


class TestDatabaseRoundtrip:
    """Test that database structure survives save/open cycle."""

    @slow_settings
    @given(
        db_name=nonempty_safe_text,
        group_name=nonempty_safe_text,
        entry_count=st.integers(min_value=0, max_value=3),
    )
    def test_database_structure_roundtrip(
        self, db_name: str, group_name: str, entry_count: int
    ) -> None:
        """Database structure should survive save/open cycle."""

        db = Database.create(password="test", database_name=db_name)

        # Add a subgroup
        subgroup = db.root_group.create_subgroup(group_name)

        # Add entries to subgroup
        entry_uuids = []
        for i in range(entry_count):
            entry = subgroup.create_entry(title=f"Entry{i}")
            entry_uuids.append(entry.uuid)

        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        # Verify database name
        assert db2.settings.database_name == db_name

        # Verify subgroup exists (excluding recycle bin)
        groups = [g for g in db2.iter_groups() if g.name == group_name]
        assert len(groups) == 1

        # Verify entry count in subgroup
        restored_group = groups[0]
        assert len(restored_group.entries) == entry_count

        # Verify all entry UUIDs
        restored_uuids = {e.uuid for e in restored_group.entries}
        assert restored_uuids == set(entry_uuids)


class TestBinaryAttachmentRoundtrip:
    """Test that binary attachments survive save/open cycle."""

    @slow_settings
    @given(
        filename=st.text(
            alphabet=st.characters(
                whitelist_categories=("L", "N"),  # Letters and numbers only
                min_codepoint=32,
                max_codepoint=126,
            ),
            min_size=1,
            max_size=50,
        ).map(lambda s: s + ".bin"),
        data=binary_data,
    )
    def test_binary_attachment_roundtrip(self, filename: str, data: bytes) -> None:
        """Binary attachments should survive save/open cycle."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Test")

        db.add_attachment(entry, filename, data)

        saved = db.to_bytes()
        db2 = Database.open_bytes(saved, password="test")

        entries = [e for e in db2.iter_entries() if e.uuid == entry.uuid]
        assert len(entries) == 1

        restored_data = db2.get_attachment(entries[0], filename)
        assert restored_data == data

    @slow_settings
    @given(
        attachment_count=st.integers(min_value=1, max_value=3),
        data=binary_data,
    )
    def test_multiple_attachments_roundtrip(self, attachment_count: int, data: bytes) -> None:
        """Multiple attachments on one entry should survive roundtrip."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Test")

        filenames = [f"file{i}.dat" for i in range(attachment_count)]
        for filename in filenames:
            db.add_attachment(entry, filename, data)

        saved = db.to_bytes()
        db2 = Database.open_bytes(saved, password="test")

        entries = [e for e in db2.iter_entries() if e.uuid == entry.uuid]
        assert len(entries) == 1

        restored_filenames = db2.list_attachments(entries[0])
        assert set(restored_filenames) == set(filenames)


class TestCustomPropertyRoundtrip:
    """Test that custom properties survive save/open cycle."""

    @slow_settings
    @given(
        key=st.text(
            alphabet=st.characters(
                whitelist_categories=("L", "N"),
                min_codepoint=65,  # Start at 'A'
                max_codepoint=122,  # End at 'z'
            ),
            min_size=1,
            max_size=30,
        ),
        value=nonempty_safe_text,
    )
    def test_custom_property_roundtrip(self, key: str, value: str) -> None:
        """Custom properties should survive save/open cycle."""
        # Skip reserved keys
        reserved = {"Title", "UserName", "Password", "URL", "Notes", "otp"}
        assume(key not in reserved)

        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Test")
        entry.set_custom_property(key, value)

        saved = db.to_bytes()
        db2 = Database.open_bytes(saved, password="test")

        entries = [e for e in db2.iter_entries() if e.uuid == entry.uuid]
        assert len(entries) == 1

        restored_value = entries[0].get_custom_property(key)
        assert restored_value == value
