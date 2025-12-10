"""Tests for YubiKey HMAC-SHA1 challenge-response support."""

import os
from unittest.mock import MagicMock, patch

import pytest

from kdbxtool.exceptions import (
    YubiKeyError,
    YubiKeyNotAvailableError,
    YubiKeyNotFoundError,
    YubiKeySlotError,
    YubiKeyTimeoutError,
)
from kdbxtool.security.kdf import derive_composite_key
from kdbxtool.security.memory import SecureBytes
from kdbxtool.security.yubikey import (
    HMAC_SHA1_RESPONSE_SIZE,
    YUBIKEY_AVAILABLE,
    YubiKeyConfig,
)


class TestYubiKeyConfig:
    """Tests for YubiKeyConfig dataclass."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = YubiKeyConfig()
        assert config.slot == 2
        assert config.timeout_seconds == 15.0

    def test_custom_slot(self) -> None:
        """Test custom slot configuration."""
        config = YubiKeyConfig(slot=1)
        assert config.slot == 1

    def test_custom_timeout(self) -> None:
        """Test custom timeout configuration."""
        config = YubiKeyConfig(timeout_seconds=30.0)
        assert config.timeout_seconds == 30.0

    def test_custom_serial(self) -> None:
        """Test custom serial configuration."""
        config = YubiKeyConfig(serial=12345678)
        assert config.serial == 12345678

    def test_default_serial_is_none(self) -> None:
        """Test default serial is None (use first device)."""
        config = YubiKeyConfig()
        assert config.serial is None

    def test_invalid_slot_raises(self) -> None:
        """Test that invalid slot raises ValueError."""
        with pytest.raises(ValueError, match="slot must be 1 or 2"):
            YubiKeyConfig(slot=3)

    def test_invalid_slot_zero_raises(self) -> None:
        """Test that slot 0 raises ValueError."""
        with pytest.raises(ValueError, match="slot must be 1 or 2"):
            YubiKeyConfig(slot=0)

    def test_invalid_timeout_raises(self) -> None:
        """Test that non-positive timeout raises ValueError."""
        with pytest.raises(ValueError, match="Timeout must be positive"):
            YubiKeyConfig(timeout_seconds=0)

    def test_negative_timeout_raises(self) -> None:
        """Test that negative timeout raises ValueError."""
        with pytest.raises(ValueError, match="Timeout must be positive"):
            YubiKeyConfig(timeout_seconds=-1.0)


class TestHmacSha1ResponseSize:
    """Tests for HMAC-SHA1 response size constant."""

    def test_response_size(self) -> None:
        """Test that HMAC-SHA1 response size is 20 bytes."""
        assert HMAC_SHA1_RESPONSE_SIZE == 20


class TestDeriveCompositeKeyWithYubiKey:
    """Tests for derive_composite_key with YubiKey response."""

    def test_yubikey_response_only(self) -> None:
        """Test composite key from YubiKey response only."""
        # Simulate 20-byte HMAC-SHA1 response
        yubikey_response = os.urandom(20)
        result = derive_composite_key(yubikey_response=yubikey_response)
        assert isinstance(result, SecureBytes)
        assert len(result.data) == 32

    def test_password_and_yubikey(self) -> None:
        """Test composite key from password and YubiKey response."""
        yubikey_response = os.urandom(20)
        result = derive_composite_key(
            password="mypassword",
            yubikey_response=yubikey_response,
        )
        assert isinstance(result, SecureBytes)
        assert len(result.data) == 32

    def test_keyfile_and_yubikey(self) -> None:
        """Test composite key from keyfile and YubiKey response."""
        keyfile_data = os.urandom(64)
        yubikey_response = os.urandom(20)
        result = derive_composite_key(
            keyfile_data=keyfile_data,
            yubikey_response=yubikey_response,
        )
        assert isinstance(result, SecureBytes)
        assert len(result.data) == 32

    def test_all_credentials(self) -> None:
        """Test composite key from all credential types."""
        keyfile_data = os.urandom(64)
        yubikey_response = os.urandom(20)
        result = derive_composite_key(
            password="mypassword",
            keyfile_data=keyfile_data,
            yubikey_response=yubikey_response,
        )
        assert isinstance(result, SecureBytes)
        assert len(result.data) == 32

    def test_yubikey_changes_key(self) -> None:
        """Test that YubiKey response changes the composite key."""
        yubikey_response = os.urandom(20)
        result_pwd = derive_composite_key(password="password")
        result_with_yk = derive_composite_key(
            password="password",
            yubikey_response=yubikey_response,
        )
        assert result_pwd.data != result_with_yk.data

    def test_different_yubikey_responses(self) -> None:
        """Test that different YubiKey responses produce different keys."""
        result1 = derive_composite_key(yubikey_response=os.urandom(20))
        result2 = derive_composite_key(yubikey_response=os.urandom(20))
        assert result1.data != result2.data

    def test_deterministic_with_yubikey(self) -> None:
        """Test that same inputs produce same output."""
        yubikey_response = os.urandom(20)
        result1 = derive_composite_key(
            password="password",
            yubikey_response=yubikey_response,
        )
        result2 = derive_composite_key(
            password="password",
            yubikey_response=yubikey_response,
        )
        assert result1.data == result2.data

    def test_invalid_yubikey_response_size(self) -> None:
        """Test that wrong response size raises ValueError."""
        with pytest.raises(ValueError, match="must be 20 bytes"):
            derive_composite_key(yubikey_response=os.urandom(16))

    def test_invalid_yubikey_response_too_long(self) -> None:
        """Test that too-long response raises ValueError."""
        with pytest.raises(ValueError, match="must be 20 bytes"):
            derive_composite_key(yubikey_response=os.urandom(32))


class TestYubiKeyExceptions:
    """Tests for YubiKey exception classes."""

    def test_yubikey_error_base(self) -> None:
        """Test YubiKeyError is a valid exception."""
        with pytest.raises(YubiKeyError):
            raise YubiKeyError("test error")

    def test_yubikey_not_found_error(self) -> None:
        """Test YubiKeyNotFoundError message."""
        error = YubiKeyNotFoundError()
        assert "found" in str(error).lower()
        assert "connected" in str(error).lower()

    def test_yubikey_slot_error(self) -> None:
        """Test YubiKeySlotError stores slot number."""
        error = YubiKeySlotError(slot=2)
        assert error.slot == 2
        assert "slot 2" in str(error).lower()
        assert "hmac-sha1" in str(error).lower()

    def test_yubikey_timeout_error(self) -> None:
        """Test YubiKeyTimeoutError stores timeout."""
        error = YubiKeyTimeoutError(timeout_seconds=30.0)
        assert error.timeout_seconds == 30.0
        assert "30" in str(error)
        assert "touch" in str(error).lower()

    def test_yubikey_not_available_error(self) -> None:
        """Test YubiKeyNotAvailableError message."""
        error = YubiKeyNotAvailableError()
        assert "yubikey-manager" in str(error).lower()
        assert "pip install" in str(error).lower()


class TestYubiKeyMocked:
    """Tests for YubiKey functions with mocked hardware."""

    @patch("kdbxtool.security.yubikey.YUBIKEY_AVAILABLE", False)
    def test_list_yubikeys_not_available(self) -> None:
        """Test list_yubikeys raises when yubikey-manager not installed."""
        from kdbxtool.security.yubikey import list_yubikeys

        with pytest.raises(YubiKeyNotAvailableError):
            list_yubikeys()

    @patch("kdbxtool.security.yubikey.YUBIKEY_AVAILABLE", False)
    def test_compute_challenge_response_not_available(self) -> None:
        """Test compute_challenge_response raises when not installed."""
        from kdbxtool.security.yubikey import compute_challenge_response

        with pytest.raises(YubiKeyNotAvailableError):
            compute_challenge_response(os.urandom(32))

    @patch("kdbxtool.security.yubikey.YUBIKEY_AVAILABLE", False)
    def test_check_slot_configured_not_available(self) -> None:
        """Test check_slot_configured raises when not installed."""
        from kdbxtool.security.yubikey import check_slot_configured

        with pytest.raises(YubiKeyNotAvailableError):
            check_slot_configured(slot=2)

    def test_compute_challenge_response_empty_challenge(self) -> None:
        """Test compute_challenge_response rejects empty challenge."""
        from kdbxtool.security.yubikey import compute_challenge_response

        # This should fail regardless of whether yubikey-manager is installed
        # because we validate the challenge before checking availability
        try:
            with pytest.raises((ValueError, YubiKeyNotAvailableError)):
                compute_challenge_response(b"")
        except YubiKeyNotAvailableError:
            # If yubikey-manager isn't installed, that's also acceptable
            pass


# Tests that require yubikey-manager to be installed for proper mocking
# These are marked to skip if yubikey-manager is not available
@pytest.mark.skipif(
    not YUBIKEY_AVAILABLE,
    reason="yubikey-manager not installed - cannot mock internal functions",
)
class TestYubiKeyWithManagerInstalled:
    """Tests that require yubikey-manager for proper mocking."""

    def test_compute_challenge_response_no_device(self) -> None:
        """Test compute_challenge_response raises when no device found."""
        from kdbxtool.security.yubikey import compute_challenge_response

        with patch("kdbxtool.security.yubikey.list_all_devices") as mock_list:
            mock_list.return_value = []
            with pytest.raises(YubiKeyNotFoundError):
                compute_challenge_response(os.urandom(32))

    def test_list_yubikeys_no_device(self) -> None:
        """Test list_yubikeys returns empty list when no device."""
        from kdbxtool.security.yubikey import list_yubikeys

        with patch("kdbxtool.security.yubikey.list_all_devices") as mock_list:
            mock_list.return_value = []
            result = list_yubikeys()
            assert result == []

    def test_check_slot_configured_no_device(self) -> None:
        """Test check_slot_configured raises when no device found."""
        from kdbxtool.security.yubikey import check_slot_configured

        with patch("kdbxtool.security.yubikey.list_all_devices") as mock_list:
            mock_list.return_value = []
            with pytest.raises(YubiKeyNotFoundError):
                check_slot_configured(slot=2)


class TestDatabaseApiYubiKey:
    """Tests for Database API YubiKey integration."""

    def test_open_bytes_yubikey_not_available(self) -> None:
        """Test Database.open_bytes raises when yubikey-manager not installed."""
        import kdbxtool.security.yubikey as yk_module

        from kdbxtool.database import Database

        # Create a simple test database bytes
        db = Database.create(password="test")
        db_bytes = db.to_bytes()

        # Patch at the actual yubikey module where it's defined
        original = yk_module.YUBIKEY_AVAILABLE
        try:
            yk_module.YUBIKEY_AVAILABLE = False
            with pytest.raises(YubiKeyNotAvailableError):
                Database.open_bytes(db_bytes, password="test", yubikey_slot=2)
        finally:
            yk_module.YUBIKEY_AVAILABLE = original

    def test_to_bytes_yubikey_not_available(self) -> None:
        """Test Database.to_bytes raises when yubikey-manager not installed."""
        import kdbxtool.security.yubikey as yk_module

        from kdbxtool.database import Database

        db = Database.create(password="test")

        original = yk_module.YUBIKEY_AVAILABLE
        try:
            yk_module.YUBIKEY_AVAILABLE = False
            with pytest.raises(YubiKeyNotAvailableError):
                db.to_bytes(yubikey_slot=2)
        finally:
            yk_module.YUBIKEY_AVAILABLE = original

    def test_save_yubikey_not_available(self, tmp_path: "pytest.TempPathFactory") -> None:
        """Test Database.save raises when yubikey-manager not installed."""
        import kdbxtool.security.yubikey as yk_module
        from pathlib import Path

        from kdbxtool.database import Database

        db = Database.create(password="test")
        db_path = Path(str(tmp_path)) / "test.kdbx"

        original = yk_module.YUBIKEY_AVAILABLE
        try:
            yk_module.YUBIKEY_AVAILABLE = False
            with pytest.raises(YubiKeyNotAvailableError):
                db.save(db_path, yubikey_slot=2)
        finally:
            yk_module.YUBIKEY_AVAILABLE = original


@pytest.mark.skipif(
    not YUBIKEY_AVAILABLE,
    reason="yubikey-manager not installed - cannot mock internal functions",
)
class TestDatabaseApiYubiKeyMocked:
    """Tests for Database API YubiKey integration with mocked hardware."""

    def test_open_and_save_with_yubikey(self, tmp_path: "pytest.TempPathFactory") -> None:
        """Test Database open/save cycle with mocked YubiKey."""
        from pathlib import Path

        from kdbxtool.database import Database

        # Create a test database
        db = Database.create(password="test")

        # Mock YubiKey response for save
        mock_response = MagicMock()
        mock_response.data = os.urandom(20)

        with patch("kdbxtool.database.compute_challenge_response") as mock_cr:
            mock_cr.return_value = mock_response

            # Save with YubiKey
            db_path = Path(str(tmp_path)) / "yubikey_test.kdbx"
            db.save(db_path, yubikey_slot=2)

            # Verify compute_challenge_response was called with master_seed
            assert mock_cr.called
            call_args = mock_cr.call_args
            # First positional arg should be the 32-byte master_seed
            assert len(call_args[0][0]) == 32

    def test_to_bytes_with_yubikey(self) -> None:
        """Test Database.to_bytes with mocked YubiKey."""
        from kdbxtool.database import Database

        db = Database.create(password="test")

        mock_response = MagicMock()
        mock_response.data = os.urandom(20)

        with patch("kdbxtool.database.compute_challenge_response") as mock_cr:
            mock_cr.return_value = mock_response
            result = db.to_bytes(yubikey_slot=1)

            assert isinstance(result, bytes)
            assert mock_cr.called
            # Verify YubiKeyConfig was passed with correct slot
            config = mock_cr.call_args[0][1]
            assert config.slot == 1
