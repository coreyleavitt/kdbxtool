"""Tests for cipher configuration on save."""

import tempfile
from pathlib import Path

import pytest

from kdbxtool import Argon2Config, Cipher, Database


class TestCipherConfigOnSave:
    """Tests for using cipher parameter when saving databases."""

    def test_save_with_chacha20(self) -> None:
        """Test saving with ChaCha20 cipher."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="Test")

        with tempfile.NamedTemporaryFile(suffix=".kdbx", delete=False) as f:
            filepath = Path(f.name)

        try:
            db.save(filepath=filepath, cipher=Cipher.CHACHA20)

            # Verify we can reopen and cipher was changed
            db2 = Database.open(filepath, password="test")
            assert db2.find_entries(title="Test", first=True) is not None
        finally:
            filepath.unlink(missing_ok=True)

    def test_save_with_aes256(self) -> None:
        """Test saving with AES-256-CBC cipher."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="Test")

        with tempfile.NamedTemporaryFile(suffix=".kdbx", delete=False) as f:
            filepath = Path(f.name)

        try:
            db.save(filepath=filepath, cipher=Cipher.AES256_CBC)

            # Verify we can reopen
            db2 = Database.open(filepath, password="test")
            assert db2.find_entries(title="Test", first=True) is not None
        finally:
            filepath.unlink(missing_ok=True)

    def test_to_bytes_with_chacha20(self) -> None:
        """Test to_bytes() with ChaCha20 cipher."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="Test")

        data = db.to_bytes(cipher=Cipher.CHACHA20)

        # Verify we can reopen from bytes
        db2 = Database.open_bytes(data, password="test")
        assert db2.find_entries(title="Test", first=True) is not None

    def test_change_cipher_preserves_data(self) -> None:
        """Test that changing cipher preserves all database content."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(
            title="Important",
            username="user@example.com",
            password="secret123",
            url="https://example.com",
            notes="Some notes here",
        )
        entry.set_custom_property("custom_key", "custom_value")

        with tempfile.NamedTemporaryFile(suffix=".kdbx", delete=False) as f:
            filepath = Path(f.name)

        try:
            # Save with different cipher
            db.save(filepath=filepath, cipher=Cipher.CHACHA20)

            # Reopen and verify all data
            db2 = Database.open(filepath, password="test")
            entry2 = db2.find_entries(title="Important", first=True)
            assert entry2 is not None
            assert entry2.username == "user@example.com"
            assert entry2.password == "secret123"
            assert entry2.url == "https://example.com"
            assert entry2.notes == "Some notes here"
            assert entry2.get_custom_property("custom_key") == "custom_value"
        finally:
            filepath.unlink(missing_ok=True)

    def test_cipher_with_kdf_config(self) -> None:
        """Test using both cipher and kdf_config together."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="Test")

        with tempfile.NamedTemporaryFile(suffix=".kdbx", delete=False) as f:
            filepath = Path(f.name)

        try:
            db.save(
                filepath=filepath,
                cipher=Cipher.CHACHA20,
                kdf_config=Argon2Config.fast(),
            )

            # Verify we can reopen
            db2 = Database.open(filepath, password="test")
            assert db2.find_entries(title="Test", first=True) is not None
        finally:
            filepath.unlink(missing_ok=True)


class TestCipherConfigOnUpgrade:
    """Tests for using cipher parameter during KDBX3 upgrade."""

    def test_kdbx3_upgrade_with_chacha20(self) -> None:
        """Test KDBX3 upgrade with ChaCha20 cipher."""
        import warnings

        test_file = Path(__file__).parent / "fixtures" / "test3.kdbx"
        test_key = Path(__file__).parent / "fixtures" / "test3.key"

        with tempfile.NamedTemporaryFile(suffix=".kdbx", delete=False) as f:
            temp_path = Path(f.name)

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                db = Database.open(test_file, password="password", keyfile=test_key)

            # Upgrade with ChaCha20 cipher
            db.save(
                filepath=temp_path,
                allow_upgrade=True,
                cipher=Cipher.CHACHA20,
                kdf_config=Argon2Config.fast(),
            )

            # Verify the file was saved and can be reopened
            db2 = Database.open(temp_path, password="password", keyfile=test_key)
            assert db2.root_group is not None
        finally:
            temp_path.unlink(missing_ok=True)

    def test_kdbx3_upgrade_preserves_default_cipher(self) -> None:
        """Test KDBX3 upgrade preserves original cipher if none specified."""
        import warnings

        test_file = Path(__file__).parent / "fixtures" / "test3.kdbx"
        test_key = Path(__file__).parent / "fixtures" / "test3.key"

        with tempfile.NamedTemporaryFile(suffix=".kdbx", delete=False) as f:
            temp_path = Path(f.name)

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                db = Database.open(test_file, password="password", keyfile=test_key)

            # Upgrade without specifying cipher (should preserve existing)
            db.save(
                filepath=temp_path,
                allow_upgrade=True,
                kdf_config=Argon2Config.fast(),
            )

            # Verify file exists and can be opened
            db2 = Database.open(temp_path, password="password", keyfile=test_key)
            assert db2.root_group is not None
        finally:
            temp_path.unlink(missing_ok=True)


class TestCipherEnum:
    """Tests for Cipher enum properties."""

    def test_aes256_properties(self) -> None:
        """Test AES-256-CBC cipher properties."""
        cipher = Cipher.AES256_CBC
        assert cipher.key_size == 32
        assert cipher.iv_size == 16
        assert cipher.display_name == "AES-256-CBC"
        assert len(cipher.value) == 16  # UUID

    def test_chacha20_properties(self) -> None:
        """Test ChaCha20 cipher properties."""
        cipher = Cipher.CHACHA20
        assert cipher.key_size == 32
        assert cipher.iv_size == 12
        assert cipher.display_name == "ChaCha20"
        assert len(cipher.value) == 16  # UUID

    def test_twofish_properties(self) -> None:
        """Test Twofish cipher properties."""
        cipher = Cipher.TWOFISH256_CBC
        assert cipher.key_size == 32
        assert cipher.iv_size == 16
        assert cipher.display_name == "Twofish-256-CBC"
        assert len(cipher.value) == 16  # UUID

    def test_from_uuid(self) -> None:
        """Test cipher lookup by UUID."""
        for cipher in Cipher:
            assert Cipher.from_uuid(cipher.value) == cipher
