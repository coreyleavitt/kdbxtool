"""Tests for precomputed transformed key support."""

import pytest

from kdbxtool import Database, MissingCredentialsError


class TestTransformedKey:
    """Tests for transformed key caching and reuse."""

    def test_transformed_key_available_after_open(self) -> None:
        """Test that transformed_key is available after opening a database."""
        db = Database.create(password="test")
        data = db.to_bytes()

        db2 = Database.open_bytes(data, password="test")

        assert db2.transformed_key is not None
        assert isinstance(db2.transformed_key, bytes)
        assert len(db2.transformed_key) == 32  # SHA256 output

    def test_kdf_salt_available(self) -> None:
        """Test that kdf_salt is available."""
        db = Database.create(password="test")

        assert db.kdf_salt is not None
        assert isinstance(db.kdf_salt, bytes)
        assert len(db.kdf_salt) == 32

    def test_open_with_transformed_key_skips_kdf(self) -> None:
        """Test that opening with transformed_key succeeds."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="Test", password="secret")
        data = db.to_bytes()

        # Open with credentials to get transformed_key
        db2 = Database.open_bytes(data, password="test")
        cached_key = db2.transformed_key

        # Open again with just the transformed_key (no password)
        db3 = Database.open_bytes(data, transformed_key=cached_key)

        # Data should be accessible
        entry = db3.find_entries(title="Test", first=True)
        assert entry is not None
        assert entry.password == "secret"

    def test_transformed_key_invalidated_on_regenerate_seeds(self) -> None:
        """Test that transformed_key is invalidated when seeds are regenerated."""
        db = Database.create(password="test")
        data = db.to_bytes()

        db2 = Database.open_bytes(data, password="test")
        assert db2.transformed_key is not None

        # Save with regenerate_seeds=True (default)
        db2.to_bytes(regenerate_seeds=True)

        # Transformed key should be invalidated
        assert db2.transformed_key is None

    def test_transformed_key_preserved_when_not_regenerating_seeds(self) -> None:
        """Test that transformed_key is preserved when seeds are not regenerated."""
        db = Database.create(password="test")
        data = db.to_bytes()

        db2 = Database.open_bytes(data, password="test")
        original_key = db2.transformed_key
        assert original_key is not None

        # Save with regenerate_seeds=False
        db2.to_bytes(regenerate_seeds=False)

        # Transformed key should still be valid
        assert db2.transformed_key == original_key

    def test_wrong_transformed_key_fails(self) -> None:
        """Test that wrong transformed_key fails to decrypt."""
        db = Database.create(password="test")
        data = db.to_bytes()

        # Wrong key
        wrong_key = b"\x00" * 32

        with pytest.raises(Exception):  # AuthenticationError or similar
            Database.open_bytes(data, transformed_key=wrong_key)

    def test_transformed_key_zeroized_on_cleanup(self) -> None:
        """Test that transformed_key is zeroized when credentials are cleared."""
        db = Database.create(password="test")
        data = db.to_bytes()

        db2 = Database.open_bytes(data, password="test")
        assert db2.transformed_key is not None

        db2.zeroize_credentials()

        assert db2.transformed_key is None

    def test_save_with_only_transformed_key(self) -> None:
        """Test saving with only transformed_key (no password stored)."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="Test")
        data = db.to_bytes()

        # Open and get transformed_key
        db2 = Database.open_bytes(data, password="test")
        cached_key = db2.transformed_key

        # Clear credentials but keep transformed_key
        db2._password = None
        db2._keyfile_data = None

        # Should still be able to save with regenerate_seeds=False
        data2 = db2.to_bytes(regenerate_seeds=False)

        # Verify data is valid
        db3 = Database.open_bytes(data2, transformed_key=cached_key)
        assert db3.find_entries(title="Test", first=True) is not None

    def test_save_fails_without_credentials_or_transformed_key(self) -> None:
        """Test that save fails without any credentials."""
        db = Database.create(password="test")
        data = db.to_bytes()

        db2 = Database.open_bytes(data, password="test")
        db2.zeroize_credentials()

        with pytest.raises(MissingCredentialsError):
            db2.to_bytes()

    def test_kdf_salt_changes_with_regenerate_seeds(self) -> None:
        """Test that kdf_salt changes when seeds are regenerated."""
        db = Database.create(password="test")

        original_salt = db.kdf_salt
        db.to_bytes(regenerate_seeds=True)

        assert db.kdf_salt != original_salt

    def test_kdf_salt_preserved_without_regenerate_seeds(self) -> None:
        """Test that kdf_salt is preserved when seeds are not regenerated."""
        db = Database.create(password="test")
        data = db.to_bytes(regenerate_seeds=False)

        original_salt = db.kdf_salt

        # Save again without regenerating
        db.to_bytes(regenerate_seeds=False)

        assert db.kdf_salt == original_salt

    def test_context_manager_zeroizes_transformed_key(self) -> None:
        """Test that context manager clears transformed_key."""
        db = Database.create(password="test")
        data = db.to_bytes()

        with Database.open_bytes(data, password="test") as db2:
            assert db2.transformed_key is not None

        # After context exit, key should be cleared
        assert db2.transformed_key is None


class TestKdbx3TransformedKey:
    """Tests for transformed_key behavior with KDBX3 databases."""

    def test_kdbx3_transformed_key_available(self) -> None:
        """Test that transformed_key is available for KDBX3 databases."""
        import warnings
        from pathlib import Path

        test_file = Path(__file__).parent / "fixtures" / "test3.kdbx"
        test_key = Path(__file__).parent / "fixtures" / "test3.key"

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # Ignore KDBX3 upgrade warning
            db = Database.open(test_file, password="password", keyfile=test_key)

        # KDBX3 now provides transformed_key for caching
        assert db.transformed_key is not None
        assert isinstance(db.transformed_key, bytes)
        assert len(db.transformed_key) == 32  # SHA256 output

    def test_kdbx3_open_with_transformed_key(self) -> None:
        """Test that KDBX3 can be opened with cached transformed_key."""
        import warnings
        from pathlib import Path

        test_file = Path(__file__).parent / "fixtures" / "test3.kdbx"
        test_key = Path(__file__).parent / "fixtures" / "test3.key"

        # First open to get transformed_key
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            db = Database.open(test_file, password="password", keyfile=test_key)
            cached_key = db.transformed_key

        # Open again with just the transformed_key (no password/keyfile)
        data = test_file.read_bytes()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            db2 = Database.open_bytes(data, transformed_key=cached_key)

        # Should be able to access data
        assert db2.root_group is not None

    def test_kdbx3_transformed_key_changes_after_upgrade(self) -> None:
        """Test that transformed_key changes after KDBX3 upgrade (AES-KDF to Argon2)."""
        import tempfile
        import warnings
        from pathlib import Path

        test_file = Path(__file__).parent / "fixtures" / "test3.kdbx"
        test_key = Path(__file__).parent / "fixtures" / "test3.key"

        with tempfile.NamedTemporaryFile(suffix=".kdbx", delete=False) as f:
            temp_path = Path(f.name)

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                db = Database.open(test_file, password="password", keyfile=test_key)

            # KDBX3 has transformed_key (AES-KDF derived)
            kdbx3_key = db.transformed_key
            assert kdbx3_key is not None
            assert len(kdbx3_key) == 32

            # Save triggers upgrade and auto-reload
            db.save(filepath=temp_path, allow_upgrade=True)

            # After upgrade + reload, transformed_key is different (Argon2 derived)
            kdbx4_key = db.transformed_key
            assert kdbx4_key is not None
            assert len(kdbx4_key) == 32
            # Keys should be different since KDF changed
            assert kdbx4_key != kdbx3_key
        finally:
            temp_path.unlink(missing_ok=True)
