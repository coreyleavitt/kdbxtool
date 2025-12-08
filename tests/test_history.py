"""Tests for entry history operations."""

import pytest

from kdbxtool import Database, Entry, HistoryEntry


class TestDeleteHistory:
    """Tests for Entry.delete_history() method."""

    @pytest.fixture
    def entry_with_history(self) -> Entry:
        """Create an entry with multiple history entries."""
        entry = Entry.create(title="Test", username="user1", password="pass1")

        # Save first version to history
        entry.save_history()
        entry.password = "pass2"

        # Save second version to history
        entry.save_history()
        entry.password = "pass3"

        # Save third version to history
        entry.save_history()
        entry.password = "pass4"

        return entry

    def test_delete_history_specific_entry(self, entry_with_history: Entry) -> None:
        """Test deleting a specific history entry."""
        entry = entry_with_history
        assert len(entry.history) == 3

        # Delete the middle history entry
        history_to_delete = entry.history[1]
        entry.delete_history(history_to_delete)

        assert len(entry.history) == 2
        assert history_to_delete not in entry.history

    def test_delete_history_all(self, entry_with_history: Entry) -> None:
        """Test deleting all history entries."""
        entry = entry_with_history
        assert len(entry.history) == 3

        entry.delete_history(all=True)

        assert len(entry.history) == 0

    def test_delete_history_no_args_raises(self, entry_with_history: Entry) -> None:
        """Test that delete_history without args raises error."""
        entry = entry_with_history

        with pytest.raises(ValueError, match="Must specify"):
            entry.delete_history()

    def test_delete_history_entry_not_found_raises(self, entry_with_history: Entry) -> None:
        """Test that deleting non-existent history entry raises error."""
        entry = entry_with_history
        other_entry = Entry.create(title="Other")
        other_entry.save_history()
        foreign_history = other_entry.history[0]

        with pytest.raises(ValueError, match="not found"):
            entry.delete_history(foreign_history)

    def test_delete_history_first_entry(self, entry_with_history: Entry) -> None:
        """Test deleting the first history entry."""
        entry = entry_with_history
        first_history = entry.history[0]

        entry.delete_history(first_history)

        assert len(entry.history) == 2
        assert first_history not in entry.history

    def test_delete_history_last_entry(self, entry_with_history: Entry) -> None:
        """Test deleting the last history entry."""
        entry = entry_with_history
        last_history = entry.history[-1]

        entry.delete_history(last_history)

        assert len(entry.history) == 2
        assert last_history not in entry.history


class TestClearHistory:
    """Tests for Entry.clear_history() method."""

    def test_clear_history_removes_all(self) -> None:
        """Test that clear_history removes all history entries."""
        entry = Entry.create(title="Test")
        entry.save_history()
        entry.title = "Test 2"
        entry.save_history()
        entry.title = "Test 3"

        assert len(entry.history) == 2

        entry.clear_history()

        assert len(entry.history) == 0

    def test_clear_history_on_empty(self) -> None:
        """Test that clear_history on empty history is a no-op."""
        entry = Entry.create(title="Test")
        assert len(entry.history) == 0

        # Should not raise
        entry.clear_history()

        assert len(entry.history) == 0


class TestHistoryRoundtrip:
    """Tests for history deletion persistence through save/load."""

    def test_delete_specific_history_roundtrip(self) -> None:
        """Test that deleted history entry stays deleted after save/load."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Test", password="pass1")

        # Create history
        entry.save_history()
        entry.password = "pass2"
        entry.save_history()
        entry.password = "pass3"

        assert len(entry.history) == 2

        # Delete first history entry
        entry.delete_history(entry.history[0])
        assert len(entry.history) == 1

        # Save and reload
        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        # Verify history
        entry2 = db2.find_entries(title="Test")[0]
        assert len(entry2.history) == 1

    def test_clear_history_roundtrip(self) -> None:
        """Test that cleared history stays cleared after save/load."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Test", password="pass1")

        # Create history
        entry.save_history()
        entry.password = "pass2"
        entry.save_history()
        entry.password = "pass3"

        # Clear history
        entry.clear_history()
        assert len(entry.history) == 0

        # Save and reload
        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        # Verify history is still cleared
        entry2 = db2.find_entries(title="Test")[0]
        assert len(entry2.history) == 0
