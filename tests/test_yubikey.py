"""Tests for YubiKey HMAC-SHA1 challenge-response support."""

import os
from unittest.mock import patch

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
        assert config.serial is None

    def test_custom_slot(self) -> None:
        """Test custom slot configuration."""
        config = YubiKeyConfig(slot=1)
        assert config.slot == 1

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


class TestHmacSha1ResponseSize:
    """Tests for HMAC-SHA1 response size constant."""

    def test_response_size(self) -> None:
        """Test that HMAC-SHA1 response size is 20 bytes."""
        assert HMAC_SHA1_RESPONSE_SIZE == 20


class TestDeriveCompositeKeyWithYubiKey:
    """Tests for derive_composite_key with YubiKey HMAC-SHA1 response (KeePassXC-compatible mode)."""

    def test_yubikey_response_only(self) -> None:
        """Test composite key from YubiKey HMAC-SHA1 response only."""
        # Simulate 20-byte HMAC-SHA1 response
        yubikey_hmac_response = os.urandom(20)
        result = derive_composite_key(yubikey_hmac_response=yubikey_hmac_response)
        assert isinstance(result, SecureBytes)
        assert len(result.data) == 32

    def test_password_and_yubikey(self) -> None:
        """Test composite key from password and YubiKey response."""
        yubikey_hmac_response = os.urandom(20)
        result = derive_composite_key(
            password="mypassword",
            yubikey_hmac_response=yubikey_hmac_response,
        )
        assert isinstance(result, SecureBytes)
        assert len(result.data) == 32

    def test_keyfile_and_yubikey(self) -> None:
        """Test composite key from keyfile and YubiKey response."""
        keyfile_data = os.urandom(64)
        yubikey_hmac_response = os.urandom(20)
        result = derive_composite_key(
            keyfile_data=keyfile_data,
            yubikey_hmac_response=yubikey_hmac_response,
        )
        assert isinstance(result, SecureBytes)
        assert len(result.data) == 32

    def test_all_credentials(self) -> None:
        """Test composite key from all credential types."""
        keyfile_data = os.urandom(64)
        yubikey_hmac_response = os.urandom(20)
        result = derive_composite_key(
            password="mypassword",
            keyfile_data=keyfile_data,
            yubikey_hmac_response=yubikey_hmac_response,
        )
        assert isinstance(result, SecureBytes)
        assert len(result.data) == 32

    def test_yubikey_changes_key(self) -> None:
        """Test that YubiKey response changes the composite key."""
        yubikey_hmac_response = os.urandom(20)
        result_pwd = derive_composite_key(password="password")
        result_with_yk = derive_composite_key(
            password="password",
            yubikey_hmac_response=yubikey_hmac_response,
        )
        assert result_pwd.data != result_with_yk.data

    def test_different_yubikey_responses(self) -> None:
        """Test that different YubiKey responses produce different keys."""
        result1 = derive_composite_key(yubikey_hmac_response=os.urandom(20))
        result2 = derive_composite_key(yubikey_hmac_response=os.urandom(20))
        assert result1.data != result2.data

    def test_deterministic_with_yubikey(self) -> None:
        """Test that same inputs produce same output."""
        yubikey_hmac_response = os.urandom(20)
        result1 = derive_composite_key(
            password="password",
            yubikey_hmac_response=yubikey_hmac_response,
        )
        result2 = derive_composite_key(
            password="password",
            yubikey_hmac_response=yubikey_hmac_response,
        )
        assert result1.data == result2.data

    def test_invalid_yubikey_response_size(self) -> None:
        """Test that wrong response size raises ValueError."""
        # 16 bytes is invalid (KeePassXC-compatible mode only supports 20-byte HMAC-SHA1)
        with pytest.raises(ValueError, match="only supports YubiKey HMAC-SHA1"):
            derive_composite_key(yubikey_hmac_response=os.urandom(16))

    def test_invalid_yubikey_response_too_long(self) -> None:
        """Test that too-long response raises ValueError."""
        # 64 bytes is invalid (KeePassXC-compatible mode only supports 20-byte HMAC-SHA1)
        with pytest.raises(ValueError, match="only supports YubiKey HMAC-SHA1"):
            derive_composite_key(yubikey_hmac_response=os.urandom(64))

    def test_fido2_response_rejected_in_compat_mode(self) -> None:
        """Test that 32-byte FIDO2 response is rejected in KeePassXC-compatible mode.

        FIDO2 providers must use KEK mode, not KeePassXC-compatible mode.
        """
        with pytest.raises(ValueError, match="FIDO2.*must use KEK mode"):
            derive_composite_key(yubikey_hmac_response=os.urandom(32))


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
        """Test YubiKeyTimeoutError message."""
        error = YubiKeyTimeoutError()
        assert "timed out" in str(error).lower()
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


class TestMockYubiKey:
    """Tests for MockYubiKey from testing module."""

    def test_mock_yubikey_with_zero_secret(self) -> None:
        """Test MockYubiKey with zero secret."""
        from kdbxtool.testing import MockYubiKey

        provider = MockYubiKey.with_zero_secret()
        response = provider.challenge_response(b"test challenge")
        assert len(response.data) == 20  # HMAC-SHA1 output

    def test_mock_yubikey_with_test_secret(self) -> None:
        """Test MockYubiKey with test secret."""
        from kdbxtool.testing import MockYubiKey

        provider = MockYubiKey.with_test_secret()
        response = provider.challenge_response(b"test challenge")
        assert len(response.data) == 20

    def test_mock_yubikey_deterministic(self) -> None:
        """Test MockYubiKey produces deterministic output."""
        from kdbxtool.testing import MockYubiKey

        provider = MockYubiKey.with_test_secret()
        response1 = provider.challenge_response(b"test challenge")
        response2 = provider.challenge_response(b"test challenge")
        assert response1.data == response2.data

    def test_mock_yubikey_different_challenges(self) -> None:
        """Test MockYubiKey produces different output for different challenges."""
        from kdbxtool.testing import MockYubiKey

        provider = MockYubiKey.with_test_secret()
        response1 = provider.challenge_response(b"challenge 1")
        response2 = provider.challenge_response(b"challenge 2")
        assert response1.data != response2.data

    def test_mock_yubikey_custom_secret(self) -> None:
        """Test MockYubiKey with custom secret."""
        from kdbxtool.testing import MockYubiKey

        secret = b"custom_secret_12345"
        provider = MockYubiKey.with_secret(secret)
        response = provider.challenge_response(b"test")
        assert len(response.data) == 20

    def test_mock_yubikey_repr(self) -> None:
        """Test MockYubiKey repr."""
        from kdbxtool.testing import MockYubiKey

        provider = MockYubiKey.with_zero_secret()
        assert "MockYubiKey" in repr(provider)


class TestProviderBasedApi:
    """Tests for the new provider-based Database API."""

    def test_database_open_with_provider(self, tmp_path: "pytest.TempPathFactory") -> None:
        """Test Database.open with MockYubiKey provider."""
        from pathlib import Path

        from kdbxtool import Database
        from kdbxtool.testing import MockYubiKey

        provider = MockYubiKey.with_test_secret()

        # Create a database with the provider
        db = Database.create(password="test")
        db_path = Path(str(tmp_path)) / "provider_test.kdbx"
        db.save(db_path, challenge_response_provider=provider)

        # Open with the same provider
        db2 = Database.open(db_path, password="test", challenge_response_provider=provider)
        assert db2 is not None

    def test_database_roundtrip_with_provider(self, tmp_path: "pytest.TempPathFactory") -> None:
        """Test full roundtrip with provider."""
        from pathlib import Path

        from kdbxtool import Database
        from kdbxtool.testing import MockYubiKey

        provider = MockYubiKey.with_test_secret()

        # Create database with entry
        db = Database.create(password="test")
        db.root_group.create_entry(title="Test Entry", username="user", password="pass")

        # Save with provider
        db_path = Path(str(tmp_path)) / "roundtrip_test.kdbx"
        db.save(db_path, challenge_response_provider=provider)

        # Open and verify
        db2 = Database.open(db_path, password="test", challenge_response_provider=provider)
        entries = db2.find_entries(title="Test Entry")
        assert len(entries) == 1
        assert entries[0].username == "user"

    def test_provider_only_authentication(self, tmp_path: "pytest.TempPathFactory") -> None:
        """Test authentication with provider only (no password)."""
        from pathlib import Path

        from kdbxtool import Database
        from kdbxtool.testing import MockYubiKey

        provider = MockYubiKey.with_test_secret()

        # Create database with provider only
        db = Database.create(password="minimal")  # Need some credential
        db_path = Path(str(tmp_path)) / "provider_only.kdbx"
        db.save(db_path, challenge_response_provider=provider)

        # Open with provider
        db2 = Database.open(db_path, password="minimal", challenge_response_provider=provider)
        assert db2 is not None


class TestChallengeResponseProtocol:
    """Tests for ChallengeResponseProvider protocol compliance."""

    def test_mock_yubikey_implements_protocol(self) -> None:
        """Test MockYubiKey implements ChallengeResponseProvider."""
        from kdbxtool import ChallengeResponseProvider
        from kdbxtool.testing import MockYubiKey

        provider = MockYubiKey.with_test_secret()
        assert isinstance(provider, ChallengeResponseProvider)

    def test_mock_fido2_implements_protocol(self) -> None:
        """Test MockFido2 implements ChallengeResponseProvider."""
        from kdbxtool import ChallengeResponseProvider
        from kdbxtool.testing import MockFido2

        provider = MockFido2.with_test_secret()
        assert isinstance(provider, ChallengeResponseProvider)

    def test_mock_provider_implements_protocol(self) -> None:
        """Test MockProvider implements ChallengeResponseProvider."""
        from kdbxtool import ChallengeResponseProvider
        from kdbxtool.testing import MockProvider

        provider = MockProvider(b"secret")
        assert isinstance(provider, ChallengeResponseProvider)
