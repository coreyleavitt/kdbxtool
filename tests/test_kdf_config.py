"""Tests for KDF preset configurations."""

import tempfile
import warnings
from pathlib import Path

import pytest

from kdbxtool import AesKdfConfig, Argon2Config, Database, KdfType


class TestArgon2ConfigPresets:
    """Tests for Argon2Config preset factory methods."""

    def test_standard_preset(self) -> None:
        """Test standard() preset has expected values."""
        config = Argon2Config.standard()

        assert config.memory_kib == 64 * 1024  # 64 MiB
        assert config.iterations == 3
        assert config.parallelism == 4
        assert len(config.salt) == 32
        assert config.variant == KdfType.ARGON2D  # Default is Argon2d

    def test_high_security_preset(self) -> None:
        """Test high_security() preset has stronger values."""
        config = Argon2Config.high_security()

        assert config.memory_kib == 256 * 1024  # 256 MiB
        assert config.iterations == 10
        assert config.parallelism == 4
        assert len(config.salt) == 32
        assert config.variant == KdfType.ARGON2D

    def test_fast_preset(self) -> None:
        """Test fast() preset has minimal values."""
        config = Argon2Config.fast()

        assert config.memory_kib == 16 * 1024  # 16 MiB (minimum)
        assert config.iterations == 3
        assert config.parallelism == 2
        assert len(config.salt) == 32

    def test_default_is_standard(self) -> None:
        """Test that default() returns same parameters as standard()."""
        default_config = Argon2Config.default()
        standard_config = Argon2Config.standard()

        assert default_config.memory_kib == standard_config.memory_kib
        assert default_config.iterations == standard_config.iterations
        assert default_config.parallelism == standard_config.parallelism

    def test_custom_salt(self) -> None:
        """Test that custom salt can be provided."""
        custom_salt = b"x" * 32
        config = Argon2Config.standard(salt=custom_salt)

        assert config.salt == custom_salt

    def test_presets_generate_unique_salts(self) -> None:
        """Test that each preset call generates a unique salt."""
        config1 = Argon2Config.standard()
        config2 = Argon2Config.standard()

        assert config1.salt != config2.salt

    def test_argon2id_variant(self) -> None:
        """Test that Argon2id variant can be specified."""
        config = Argon2Config.standard(variant=KdfType.ARGON2ID)

        assert config.variant == KdfType.ARGON2ID

    def test_argon2d_is_default(self) -> None:
        """Test that Argon2d is the default variant."""
        config = Argon2Config.standard()

        assert config.variant == KdfType.ARGON2D


class TestAesKdfConfigPresets:
    """Tests for AesKdfConfig preset factory methods."""

    def test_standard_preset(self) -> None:
        """Test standard() preset has expected values."""
        config = AesKdfConfig.standard()

        assert config.rounds == 600_000
        assert len(config.salt) == 32

    def test_high_security_preset(self) -> None:
        """Test high_security() preset has stronger values."""
        config = AesKdfConfig.high_security()

        assert config.rounds == 6_000_000
        assert len(config.salt) == 32

    def test_fast_preset(self) -> None:
        """Test fast() preset has minimal values."""
        config = AesKdfConfig.fast()

        assert config.rounds == 60_000
        assert len(config.salt) == 32

    def test_custom_salt(self) -> None:
        """Test that custom salt can be provided."""
        custom_salt = b"y" * 32
        config = AesKdfConfig.standard(salt=custom_salt)

        assert config.salt == custom_salt

    def test_presets_generate_unique_salts(self) -> None:
        """Test that each preset call generates a unique salt."""
        config1 = AesKdfConfig.standard()
        config2 = AesKdfConfig.standard()

        assert config1.salt != config2.salt


class TestKdfConfigOnSave:
    """Tests for using kdf_config when saving databases."""

    def test_save_with_fast_config(self) -> None:
        """Test saving with fast config for testing."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="Test")

        with tempfile.NamedTemporaryFile(suffix=".kdbx", delete=False) as f:
            filepath = Path(f.name)

        try:
            db.save(filepath=filepath, kdf_config=Argon2Config.fast())

            # Verify we can reopen
            db2 = Database.open(filepath, password="test")
            assert db2.find_entries(title="Test", first=True) is not None
        finally:
            filepath.unlink(missing_ok=True)

    def test_save_with_high_security_config(self) -> None:
        """Test saving with high security config."""
        db = Database.create(password="test")

        with tempfile.NamedTemporaryFile(suffix=".kdbx", delete=False) as f:
            filepath = Path(f.name)

        try:
            # Note: This may be slow due to high security parameters
            db.save(filepath=filepath, kdf_config=Argon2Config.high_security())

            # Verify we can reopen (slow due to KDF)
            db2 = Database.open(filepath, password="test")
            assert db2.root_group is not None
        finally:
            filepath.unlink(missing_ok=True)

    def test_to_bytes_with_config(self) -> None:
        """Test to_bytes() with kdf_config."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="Test")

        data = db.to_bytes(kdf_config=Argon2Config.fast())

        # Verify we can reopen from bytes
        db2 = Database.open_bytes(data, password="test")
        assert db2.find_entries(title="Test", first=True) is not None


class TestKdfConfigOnUpgrade:
    """Tests for using kdf_config during KDBX3 upgrade."""

    def test_kdbx3_upgrade_with_fast_config(self) -> None:
        """Test KDBX3 upgrade uses provided kdf_config."""
        test_file = Path(__file__).parent / "fixtures" / "test3.kdbx"
        test_key = Path(__file__).parent / "fixtures" / "test3.key"

        with tempfile.NamedTemporaryFile(suffix=".kdbx", delete=False) as f:
            temp_path = Path(f.name)

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                db = Database.open(test_file, password="password", keyfile=test_key)

            # Upgrade with fast config (for quick testing)
            db.save(
                filepath=temp_path,
                allow_upgrade=True,
                kdf_config=Argon2Config.fast(),
            )

            # Verify the file was saved and can be reopened
            db2 = Database.open(temp_path, password="password", keyfile=test_key)
            assert db2.root_group is not None
        finally:
            temp_path.unlink(missing_ok=True)

    def test_kdbx3_upgrade_default_uses_standard(self) -> None:
        """Test KDBX3 upgrade uses standard() by default."""
        test_file = Path(__file__).parent / "fixtures" / "test3.kdbx"
        test_key = Path(__file__).parent / "fixtures" / "test3.key"

        with tempfile.NamedTemporaryFile(suffix=".kdbx", delete=False) as f:
            temp_path = Path(f.name)

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                db = Database.open(test_file, password="password", keyfile=test_key)

            # Upgrade without specifying config (should use standard)
            db.save(filepath=temp_path, allow_upgrade=True)

            # Verify file exists and can be opened
            db2 = Database.open(temp_path, password="password", keyfile=test_key)
            assert db2.root_group is not None
        finally:
            temp_path.unlink(missing_ok=True)

    def test_kdbx3_upgrade_with_aes_kdf(self) -> None:
        """Test KDBX3 upgrade with AES-KDF config."""
        test_file = Path(__file__).parent / "fixtures" / "test3.kdbx"
        test_key = Path(__file__).parent / "fixtures" / "test3.key"

        with tempfile.NamedTemporaryFile(suffix=".kdbx", delete=False) as f:
            temp_path = Path(f.name)

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                db = Database.open(test_file, password="password", keyfile=test_key)

            # Upgrade with AES-KDF (fast for testing)
            db.save(
                filepath=temp_path,
                allow_upgrade=True,
                kdf_config=AesKdfConfig.fast(),
            )

            # Verify the file was saved and can be reopened
            db2 = Database.open(temp_path, password="password", keyfile=test_key)
            assert db2.root_group is not None
        finally:
            temp_path.unlink(missing_ok=True)

    def test_save_with_aes_kdf_config(self) -> None:
        """Test saving new database with AES-KDF config."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="Test")

        with tempfile.NamedTemporaryFile(suffix=".kdbx", delete=False) as f:
            filepath = Path(f.name)

        try:
            db.save(filepath=filepath, kdf_config=AesKdfConfig.fast())

            # Verify we can reopen
            db2 = Database.open(filepath, password="test")
            assert db2.find_entries(title="Test", first=True) is not None
        finally:
            filepath.unlink(missing_ok=True)

    def test_save_with_argon2id_variant(self) -> None:
        """Test saving with Argon2id variant."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="Test")

        with tempfile.NamedTemporaryFile(suffix=".kdbx", delete=False) as f:
            filepath = Path(f.name)

        try:
            db.save(
                filepath=filepath,
                kdf_config=Argon2Config.fast(variant=KdfType.ARGON2ID),
            )

            # Verify we can reopen
            db2 = Database.open(filepath, password="test")
            assert db2.find_entries(title="Test", first=True) is not None
        finally:
            filepath.unlink(missing_ok=True)


class TestKdfConfigOnKdbx4:
    """Tests for changing KDF settings on existing KDBX4 databases (issue #64)."""

    def test_change_kdf_config_on_kdbx4(self) -> None:
        """Test that kdf_config is applied when saving KDBX4 databases."""
        db = Database.create(password="test", kdf_config=Argon2Config.fast())
        db.root_group.create_entry(title="Test Entry")

        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")
        assert db2._header is not None
        assert db2._header.argon2_memory_kib == 16 * 1024  # fast = 16 MiB

        # Change to high_security config
        data2 = db2.to_bytes(kdf_config=Argon2Config.high_security())
        db3 = Database.open_bytes(data2, password="test")
        assert db3._header is not None
        assert db3._header.argon2_memory_kib == 256 * 1024  # high_security = 256 MiB
        assert db3._header.argon2_iterations == 10
        assert db3.find_entries(title="Test Entry", first=True) is not None

    def test_switch_argon2_to_aes_kdf(self) -> None:
        """Test switching from Argon2 to AES-KDF on KDBX4 database."""
        db = Database.create(password="test", kdf_config=Argon2Config.fast())
        db.root_group.create_entry(title="Test Entry")

        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")
        assert db2._header is not None
        assert db2._header.kdf_type == KdfType.ARGON2D

        # Switch to AES-KDF
        data2 = db2.to_bytes(kdf_config=AesKdfConfig.fast())
        db3 = Database.open_bytes(data2, password="test")
        assert db3._header is not None
        assert db3._header.kdf_type == KdfType.AES_KDF
        assert db3._header.aes_kdf_rounds == 60_000
        assert db3.find_entries(title="Test Entry", first=True) is not None

    def test_switch_aes_kdf_to_argon2(self) -> None:
        """Test switching from AES-KDF to Argon2 on KDBX4 database."""
        db = Database.create(password="test", kdf_config=AesKdfConfig.fast())
        db.root_group.create_entry(title="Test Entry")

        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")
        assert db2._header is not None
        assert db2._header.kdf_type == KdfType.AES_KDF

        # Switch to Argon2
        data2 = db2.to_bytes(kdf_config=Argon2Config.fast())
        db3 = Database.open_bytes(data2, password="test")
        assert db3._header is not None
        assert db3._header.kdf_type == KdfType.ARGON2D
        assert db3._header.argon2_memory_kib == 16 * 1024
        assert db3.find_entries(title="Test Entry", first=True) is not None

    def test_kdf_change_preserves_all_data(self) -> None:
        """Test that changing KDF preserves entries, groups, and passwords."""
        db = Database.create(password="test", kdf_config=Argon2Config.fast())
        group = db.root_group.create_subgroup(name="Test Group")
        group.create_entry(
            title="Test Entry",
            username="testuser",
            password="secretpass",
            url="https://example.com",
        )

        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        # Change KDF
        data2 = db2.to_bytes(kdf_config=AesKdfConfig.standard())
        db3 = Database.open_bytes(data2, password="test")
        assert db3._header is not None
        assert db3._header.kdf_type == KdfType.AES_KDF

        # Verify all data preserved
        found = db3.find_entries(title="Test Entry", first=True)
        assert found is not None
        assert found.username == "testuser"
        assert found.password == "secretpass"
        assert found.url == "https://example.com"
        assert len(list(db3.find_groups(name="Test Group"))) == 1
