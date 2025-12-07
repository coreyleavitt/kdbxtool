"""Tests for path-based search operations."""

import pytest

from kdbxtool import Database


class TestFindEntriesByPath:
    """Tests for Database.find_entries(path=...) method."""

    @pytest.fixture
    def db(self) -> Database:
        """Create a test database with nested structure."""
        db = Database.create(password="test")
        # Create hierarchy:
        # root -> Personal -> Email -> gmail_entry
        #                  -> Social -> facebook_entry
        #      -> Work -> Projects -> project_entry
        personal = db.root_group.create_subgroup("Personal")
        email = personal.create_subgroup("Email")
        email.create_entry(title="Gmail", username="user@gmail.com")
        social = personal.create_subgroup("Social")
        social.create_entry(title="Facebook", username="user")

        work = db.root_group.create_subgroup("Work")
        projects = work.create_subgroup("Projects")
        projects.create_entry(title="Project Alpha", username="admin")

        return db

    def test_find_entry_by_path_list(self, db: Database) -> None:
        """Test finding entry by path as list."""
        entries = db.find_entries(path=["Personal", "Email", "Gmail"])

        assert len(entries) == 1
        assert entries[0].title == "Gmail"
        assert entries[0].username == "user@gmail.com"

    def test_find_entry_by_path_string(self, db: Database) -> None:
        """Test finding entry by path as string."""
        entries = db.find_entries(path="Personal/Social/Facebook")

        assert len(entries) == 1
        assert entries[0].title == "Facebook"

    def test_find_entry_by_path_nested(self, db: Database) -> None:
        """Test finding deeply nested entry."""
        entries = db.find_entries(path="Work/Projects/Project Alpha")

        assert len(entries) == 1
        assert entries[0].title == "Project Alpha"

    def test_find_entry_in_root(self, db: Database) -> None:
        """Test finding entry in root group."""
        db.root_group.create_entry(title="Root Entry")

        entries = db.find_entries(path=["Root Entry"])

        assert len(entries) == 1
        assert entries[0].title == "Root Entry"

    def test_find_entry_by_path_not_found_wrong_group(self, db: Database) -> None:
        """Test that wrong group path returns empty list."""
        entries = db.find_entries(path=["NonExistent", "Gmail"])

        assert entries == []

    def test_find_entry_by_path_not_found_wrong_entry(self, db: Database) -> None:
        """Test that wrong entry name returns empty list."""
        entries = db.find_entries(path=["Personal", "Email", "Yahoo"])

        assert entries == []

    def test_find_entry_by_path_empty_list(self, db: Database) -> None:
        """Test that empty path returns empty list."""
        entries = db.find_entries(path=[])

        assert entries == []

    def test_find_entry_by_path_empty_string(self, db: Database) -> None:
        """Test that empty string path returns empty list."""
        entries = db.find_entries(path="")

        assert entries == []

    def test_find_entry_by_path_with_leading_slash(self, db: Database) -> None:
        """Test that leading slash in path is handled."""
        entries = db.find_entries(path="/Personal/Email/Gmail")

        assert len(entries) == 1
        assert entries[0].title == "Gmail"


class TestFindGroupsByPath:
    """Tests for Database.find_groups(path=...) method."""

    @pytest.fixture
    def db(self) -> Database:
        """Create a test database with nested structure."""
        db = Database.create(password="test")
        # Create hierarchy:
        # root -> Personal -> Email
        #                  -> Social
        #      -> Work -> Projects -> Active
        personal = db.root_group.create_subgroup("Personal")
        personal.create_subgroup("Email")
        personal.create_subgroup("Social")

        work = db.root_group.create_subgroup("Work")
        projects = work.create_subgroup("Projects")
        projects.create_subgroup("Active")

        return db

    def test_find_group_by_path_list(self, db: Database) -> None:
        """Test finding group by path as list."""
        groups = db.find_groups(path=["Personal", "Email"])

        assert len(groups) == 1
        assert groups[0].name == "Email"

    def test_find_group_by_path_string(self, db: Database) -> None:
        """Test finding group by path as string."""
        groups = db.find_groups(path="Work/Projects")

        assert len(groups) == 1
        assert groups[0].name == "Projects"

    def test_find_group_by_path_nested(self, db: Database) -> None:
        """Test finding deeply nested group."""
        groups = db.find_groups(path="Work/Projects/Active")

        assert len(groups) == 1
        assert groups[0].name == "Active"

    def test_find_group_by_path_single(self, db: Database) -> None:
        """Test finding top-level group."""
        groups = db.find_groups(path=["Personal"])

        assert len(groups) == 1
        assert groups[0].name == "Personal"

    def test_find_group_by_path_not_found(self, db: Database) -> None:
        """Test that wrong path returns empty list."""
        groups = db.find_groups(path=["NonExistent"])

        assert groups == []

    def test_find_group_by_path_partial_not_found(self, db: Database) -> None:
        """Test that partially wrong path returns empty list."""
        groups = db.find_groups(path=["Work", "NonExistent"])

        assert groups == []

    def test_find_group_by_empty_path_returns_root(self, db: Database) -> None:
        """Test that empty path returns root group."""
        groups = db.find_groups(path=[])

        assert len(groups) == 1
        assert groups[0].is_root_group

    def test_find_group_by_empty_string_returns_root(self, db: Database) -> None:
        """Test that empty string path returns root group."""
        groups = db.find_groups(path="")

        assert len(groups) == 1
        assert groups[0].is_root_group


class TestPathSearchRoundtrip:
    """Tests for path search persistence through save/load."""

    def test_find_entry_by_path_roundtrip(self) -> None:
        """Test that path search works after save/load."""
        db = Database.create(password="test")
        group = db.root_group.create_subgroup("Test Group")
        group.create_entry(title="Test Entry", username="user")

        # Save and reload
        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        # Find by path
        entries = db2.find_entries(path="Test Group/Test Entry")

        assert len(entries) == 1
        assert entries[0].title == "Test Entry"

    def test_find_group_by_path_roundtrip(self) -> None:
        """Test that group path search works after save/load."""
        db = Database.create(password="test")
        parent = db.root_group.create_subgroup("Parent")
        parent.create_subgroup("Child")

        # Save and reload
        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        # Find by path
        groups = db2.find_groups(path="Parent/Child")

        assert len(groups) == 1
        assert groups[0].name == "Child"
