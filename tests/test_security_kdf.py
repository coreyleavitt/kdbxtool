"""Tests for Key Derivation Functions."""

import os

import pytest

from kdbxtool import KdfError, MissingCredentialsError
from kdbxtool.security.kdf import (
    ARGON2_MIN_ITERATIONS,
    ARGON2_MIN_MEMORY_KIB,
    ARGON2_MIN_PARALLELISM,
    AesKdfConfig,
    Argon2Config,
    KdfType,
    derive_composite_key,
    derive_key_aes_kdf,
    derive_key_argon2,
)
from kdbxtool.security.memory import SecureBytes


class TestKdfType:
    """Tests for KdfType enum."""

    def test_argon2id_properties(self) -> None:
        """Test Argon2id KDF properties."""
        kdf = KdfType.ARGON2ID
        assert kdf.display_name == "Argon2id"
        assert len(kdf.value) == 16

    def test_argon2d_properties(self) -> None:
        """Test Argon2d KDF properties."""
        kdf = KdfType.ARGON2D
        assert kdf.display_name == "Argon2d"
        assert len(kdf.value) == 16

    def test_aes_kdf_properties(self) -> None:
        """Test AES-KDF properties."""
        kdf = KdfType.AES_KDF
        assert kdf.display_name == "AES-KDF"
        assert len(kdf.value) == 16

    def test_from_uuid_argon2id(self) -> None:
        """Test lookup of Argon2id by UUID."""
        uuid = bytes.fromhex("9e298b1956db4773b23dfc3ec6f0a1e6")
        kdf = KdfType.from_uuid(uuid)
        assert kdf == KdfType.ARGON2ID

    def test_from_uuid_argon2d(self) -> None:
        """Test lookup of Argon2d by UUID."""
        uuid = bytes.fromhex("ef636ddf8c29444b91f7a9a403e30a0c")
        kdf = KdfType.from_uuid(uuid)
        assert kdf == KdfType.ARGON2D

    def test_from_uuid_aes_kdf(self) -> None:
        """Test lookup of AES-KDF by UUID."""
        uuid = bytes.fromhex("c9d9f39a628a4460bf740d08c18a4fea")
        kdf = KdfType.from_uuid(uuid)
        assert kdf == KdfType.AES_KDF

    def test_from_uuid_unknown(self) -> None:
        """Test that unknown UUID raises ValueError."""
        unknown_uuid = b"\x00" * 16
        with pytest.raises(KdfError):
            KdfType.from_uuid(unknown_uuid)


class TestArgon2Config:
    """Tests for Argon2Config dataclass."""

    def test_valid_config(self) -> None:
        """Test creating valid configuration."""
        salt = os.urandom(32)
        config = Argon2Config(
            memory_kib=64 * 1024,
            iterations=3,
            parallelism=4,
            salt=salt,
            variant=KdfType.ARGON2ID,
        )
        assert config.memory_kib == 64 * 1024
        assert config.iterations == 3
        assert config.parallelism == 4
        assert config.salt == salt
        assert config.variant == KdfType.ARGON2ID

    def test_default_config(self) -> None:
        """Test default configuration has secure values."""
        config = Argon2Config.default()
        assert config.memory_kib >= ARGON2_MIN_MEMORY_KIB
        assert config.iterations >= ARGON2_MIN_ITERATIONS
        assert config.parallelism >= ARGON2_MIN_PARALLELISM
        assert len(config.salt) == 32
        # Default is Argon2d - better GPU resistance for local password databases
        assert config.variant == KdfType.ARGON2D

    def test_default_config_with_salt(self) -> None:
        """Test default configuration with provided salt."""
        salt = b"custom_salt_here_32bytes________"
        config = Argon2Config.default(salt=salt)
        assert config.salt == salt

    def test_invalid_variant(self) -> None:
        """Test that AES-KDF variant is rejected."""
        salt = os.urandom(32)
        with pytest.raises(KdfError):
            Argon2Config(
                memory_kib=64 * 1024,
                iterations=3,
                parallelism=4,
                salt=salt,
                variant=KdfType.AES_KDF,
            )

    def test_short_salt(self) -> None:
        """Test that short salt is rejected."""
        with pytest.raises(KdfError):
            Argon2Config(
                memory_kib=64 * 1024,
                iterations=3,
                parallelism=4,
                salt=b"short",
                variant=KdfType.ARGON2ID,
            )

    def test_validate_security_passes(self) -> None:
        """Test that valid config passes security validation."""
        config = Argon2Config.default()
        config.validate_security()  # Should not raise

    def test_validate_security_low_memory(self) -> None:
        """Test that low memory is rejected."""
        salt = os.urandom(32)
        config = Argon2Config(
            memory_kib=1024,  # Only 1 MiB
            iterations=3,
            parallelism=4,
            salt=salt,
        )
        with pytest.raises(KdfError):
            config.validate_security()

    def test_validate_security_low_iterations(self) -> None:
        """Test that low iterations is rejected."""
        salt = os.urandom(32)
        config = Argon2Config(
            memory_kib=64 * 1024,
            iterations=1,
            parallelism=4,
            salt=salt,
        )
        with pytest.raises(KdfError):
            config.validate_security()

    def test_validate_security_low_parallelism(self) -> None:
        """Test that zero parallelism is rejected."""
        salt = os.urandom(32)
        config = Argon2Config(
            memory_kib=64 * 1024,
            iterations=3,
            parallelism=0,
            salt=salt,
        )
        with pytest.raises(KdfError):
            config.validate_security()


class TestAesKdfConfig:
    """Tests for AesKdfConfig dataclass."""

    def test_valid_config(self) -> None:
        """Test creating valid configuration."""
        salt = os.urandom(32)
        config = AesKdfConfig(rounds=60000, salt=salt)
        assert config.rounds == 60000
        assert config.salt == salt

    def test_invalid_salt_length(self) -> None:
        """Test that wrong salt length is rejected."""
        with pytest.raises(KdfError):
            AesKdfConfig(rounds=60000, salt=b"short")

    def test_invalid_rounds(self) -> None:
        """Test that zero rounds is rejected."""
        salt = os.urandom(32)
        with pytest.raises(KdfError):
            AesKdfConfig(rounds=0, salt=salt)


class TestDeriveKeyArgon2:
    """Tests for derive_key_argon2 function."""

    def test_returns_securebytes(self) -> None:
        """Test that result is SecureBytes."""
        config = Argon2Config.default()
        result = derive_key_argon2(b"password", config)
        assert isinstance(result, SecureBytes)
        assert len(result.data) == 32

    def test_deterministic(self) -> None:
        """Test that same inputs produce same output."""
        salt = os.urandom(32)
        config = Argon2Config(
            memory_kib=16 * 1024,
            iterations=3,
            parallelism=2,
            salt=salt,
        )
        result1 = derive_key_argon2(b"password", config)
        result2 = derive_key_argon2(b"password", config)
        assert result1.data == result2.data

    def test_different_passwords(self) -> None:
        """Test that different passwords produce different keys."""
        config = Argon2Config.default()
        result1 = derive_key_argon2(b"password1", config)
        result2 = derive_key_argon2(b"password2", config)
        assert result1.data != result2.data

    def test_different_salts(self) -> None:
        """Test that different salts produce different keys."""
        config1 = Argon2Config.default(salt=os.urandom(32))
        config2 = Argon2Config.default(salt=os.urandom(32))
        result1 = derive_key_argon2(b"password", config1)
        result2 = derive_key_argon2(b"password", config2)
        assert result1.data != result2.data

    def test_argon2d_variant(self) -> None:
        """Test Argon2d variant works."""
        salt = os.urandom(32)
        config = Argon2Config(
            memory_kib=16 * 1024,
            iterations=3,
            parallelism=2,
            salt=salt,
            variant=KdfType.ARGON2D,
        )
        result = derive_key_argon2(b"password", config)
        assert len(result.data) == 32

    def test_enforce_minimums(self) -> None:
        """Test that weak parameters are rejected by default."""
        salt = os.urandom(32)
        config = Argon2Config(
            memory_kib=1024,  # Too low
            iterations=3,
            parallelism=2,
            salt=salt,
        )
        with pytest.raises(KdfError):
            derive_key_argon2(b"password", config)

    def test_disable_minimum_enforcement(self) -> None:
        """Test that minimum enforcement can be disabled."""
        salt = os.urandom(32)
        config = Argon2Config(
            memory_kib=1024,  # Low but valid
            iterations=3,
            parallelism=2,
            salt=salt,
        )
        # Should work when enforcement is disabled
        result = derive_key_argon2(b"password", config, enforce_minimums=False)
        assert len(result.data) == 32


class TestDeriveKeyAesKdf:
    """Tests for derive_key_aes_kdf function."""

    def test_returns_securebytes(self) -> None:
        """Test that result is SecureBytes."""
        salt = os.urandom(32)
        config = AesKdfConfig(rounds=100, salt=salt)
        password = os.urandom(32)
        result = derive_key_aes_kdf(password, config)
        assert isinstance(result, SecureBytes)
        assert len(result.data) == 32

    def test_deterministic(self) -> None:
        """Test that same inputs produce same output."""
        salt = os.urandom(32)
        config = AesKdfConfig(rounds=100, salt=salt)
        password = os.urandom(32)
        result1 = derive_key_aes_kdf(password, config)
        result2 = derive_key_aes_kdf(password, config)
        assert result1.data == result2.data

    def test_different_passwords(self) -> None:
        """Test that different passwords produce different keys."""
        salt = os.urandom(32)
        config = AesKdfConfig(rounds=100, salt=salt)
        result1 = derive_key_aes_kdf(os.urandom(32), config)
        result2 = derive_key_aes_kdf(os.urandom(32), config)
        assert result1.data != result2.data

    def test_different_rounds(self) -> None:
        """Test that different rounds produce different keys."""
        salt = os.urandom(32)
        password = os.urandom(32)
        result1 = derive_key_aes_kdf(password, AesKdfConfig(rounds=100, salt=salt))
        result2 = derive_key_aes_kdf(password, AesKdfConfig(rounds=200, salt=salt))
        assert result1.data != result2.data

    def test_invalid_password_length(self) -> None:
        """Test that wrong password length is rejected."""
        salt = os.urandom(32)
        config = AesKdfConfig(rounds=100, salt=salt)
        with pytest.raises(KdfError):
            derive_key_aes_kdf(b"short", config)


class TestDeriveCompositeKey:
    """Tests for derive_composite_key function."""

    def test_password_only(self) -> None:
        """Test composite key from password only."""
        result = derive_composite_key(password="mypassword")
        assert isinstance(result, SecureBytes)
        assert len(result.data) == 32

    def test_keyfile_only(self) -> None:
        """Test composite key from keyfile only."""
        keyfile_data = os.urandom(64)
        result = derive_composite_key(keyfile_data=keyfile_data)
        assert isinstance(result, SecureBytes)
        assert len(result.data) == 32

    def test_password_and_keyfile(self) -> None:
        """Test composite key from both credentials."""
        keyfile_data = os.urandom(64)
        result = derive_composite_key(
            password="mypassword",
            keyfile_data=keyfile_data,
        )
        assert isinstance(result, SecureBytes)
        assert len(result.data) == 32

    def test_no_credentials_raises(self) -> None:
        """Test that no credentials raises error."""
        with pytest.raises(MissingCredentialsError):
            derive_composite_key()

    def test_deterministic(self) -> None:
        """Test that same inputs produce same output."""
        result1 = derive_composite_key(password="password123")
        result2 = derive_composite_key(password="password123")
        assert result1.data == result2.data

    def test_different_passwords(self) -> None:
        """Test that different passwords produce different keys."""
        result1 = derive_composite_key(password="password1")
        result2 = derive_composite_key(password="password2")
        assert result1.data != result2.data

    def test_password_only_differs_from_combined(self) -> None:
        """Test that password-only differs from password+keyfile."""
        keyfile_data = os.urandom(64)
        result_pwd = derive_composite_key(password="password")
        result_combined = derive_composite_key(
            password="password",
            keyfile_data=keyfile_data,
        )
        assert result_pwd.data != result_combined.data

    def test_unicode_password(self) -> None:
        """Test that unicode passwords work correctly."""
        result = derive_composite_key(password="p\u00e4ssw\u00f6rd")
        assert len(result.data) == 32
