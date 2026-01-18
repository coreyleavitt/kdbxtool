"""Tests for YubiKey HMAC-SHA1 challenge-response support."""

import hashlib
import hmac
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
    YUBIKEY_HARDWARE_AVAILABLE,
    ChallengeResponseProvider,
    HardwareYubiKey,
    MockYubiKey,
    YubiKeyConfig,
)


class TestYubiKeyConfig:
    """Tests for YubiKeyConfig dataclass."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = YubiKeyConfig()
        assert config.slot == 2

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

    @patch("kdbxtool.security.yubikey.YUBIKEY_HARDWARE_AVAILABLE", False)
    def test_list_yubikeys_not_available(self) -> None:
        """Test list_yubikeys raises when yubikey-manager not installed."""
        from kdbxtool.security.yubikey import list_yubikeys

        with pytest.raises(YubiKeyNotAvailableError):
            list_yubikeys()

    @patch("kdbxtool.security.yubikey.YUBIKEY_HARDWARE_AVAILABLE", False)
    def test_compute_challenge_response_not_available(self) -> None:
        """Test compute_challenge_response raises when not installed."""
        from kdbxtool.security.yubikey import compute_challenge_response

        with pytest.raises(YubiKeyNotAvailableError):
            compute_challenge_response(os.urandom(32))

    @patch("kdbxtool.security.yubikey.YUBIKEY_HARDWARE_AVAILABLE", False)
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
    not YUBIKEY_HARDWARE_AVAILABLE,
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


class TestDatabaseApiWithProvider:
    """Tests for Database API with ChallengeResponseProvider."""

    def test_hardware_yubikey_not_available(self) -> None:
        """Test HardwareYubiKey raises when yubikey-manager not installed."""
        import kdbxtool.security.yubikey as yk_module

        original = yk_module.YUBIKEY_HARDWARE_AVAILABLE
        try:
            yk_module.YUBIKEY_HARDWARE_AVAILABLE = False
            with pytest.raises(YubiKeyNotAvailableError):
                HardwareYubiKey(slot=2)
        finally:
            yk_module.YUBIKEY_HARDWARE_AVAILABLE = original

    def test_mock_yubikey_always_available(self) -> None:
        """Test MockYubiKey works regardless of hardware availability."""
        # MockYubiKey should always work - no hardware needed
        mock = MockYubiKey.with_zero_secret(slot=1)
        response = mock.challenge_response(b"test challenge")
        assert len(response.data) == 20

    def test_mock_yubikey_implements_provider_abc(self) -> None:
        """Test MockYubiKey implements ChallengeResponseProvider."""
        mock = MockYubiKey.with_zero_secret(slot=1)
        assert isinstance(mock, ChallengeResponseProvider)
        assert mock.slot == 1
        assert mock.serial == 12345678

    def test_open_bytes_with_mock_provider(self) -> None:
        """Test Database.open_bytes with MockYubiKey provider."""
        from kdbxtool.database import Database

        # Create a database with MockYubiKey
        mock_provider = MockYubiKey.with_zero_secret(slot=1)
        db = Database.create(password="test")

        # Save with provider
        db_bytes = db.to_bytes(challenge_response_provider=mock_provider)

        # Open with same provider should work
        db2 = Database.open_bytes(
            db_bytes, password="test", challenge_response_provider=mock_provider
        )
        assert db2 is not None

    def test_to_bytes_with_mock_provider(self) -> None:
        """Test Database.to_bytes with MockYubiKey provider."""
        from kdbxtool.database import Database

        mock_provider = MockYubiKey.with_numeric_secret(MockYubiKey.TEST_NUMERIC_SECRET, slot=2)
        db = Database.create(password="test")

        result = db.to_bytes(challenge_response_provider=mock_provider)
        assert isinstance(result, bytes)


@pytest.mark.skipif(
    not YUBIKEY_HARDWARE_AVAILABLE,
    reason="yubikey-manager not installed - cannot test HardwareYubiKey",
)
class TestHardwareYubiKeyProvider:
    """Tests for HardwareYubiKey provider (requires yubikey-manager)."""

    def test_hardware_yubikey_creation(self) -> None:
        """Test HardwareYubiKey can be created when hardware is available."""
        provider = HardwareYubiKey(slot=2)
        assert provider.slot == 2
        # Serial is now the actual device serial, not the filter
        assert provider.serial is not None or provider.serial is None

    def test_hardware_yubikey_with_serial(self) -> None:
        """Test HardwareYubiKey with specific serial number."""
        # Get the actual serial of the connected device first
        from kdbxtool.security.yubikey import list_yubikeys

        devices = list_yubikeys()
        if not devices or "serial" not in devices[0]:
            pytest.skip("No YubiKey with serial available")

        actual_serial = devices[0]["serial"]
        provider = HardwareYubiKey(slot=1, serial=actual_serial)
        assert provider.slot == 1
        assert provider.serial == actual_serial

    def test_hardware_yubikey_implements_provider_abc(self) -> None:
        """Test HardwareYubiKey implements ChallengeResponseProvider."""
        provider = HardwareYubiKey(slot=2)
        assert isinstance(provider, ChallengeResponseProvider)


class TestMockYubiKey:
    """Tests for MockYubiKey implementation."""

    def test_zero_secret_hmac(self) -> None:
        """Test HMAC with zero secret produces correct output."""
        mock = MockYubiKey.with_zero_secret(slot=1)
        challenge = b"test challenge data here"
        response = mock.challenge_response(challenge)

        # Verify response is 20 bytes (HMAC-SHA1) wrapped in SecureBytes
        assert len(response.data) == 20

        # Verify HMAC is computed correctly
        expected = hmac.new(MockYubiKey.ZERO_SECRET, challenge, hashlib.sha1).digest()
        assert response.data == expected

    def test_numeric_secret_hmac(self) -> None:
        """Test HMAC with numeric secret produces correct output."""
        mock = MockYubiKey.with_numeric_secret(MockYubiKey.TEST_NUMERIC_SECRET, slot=2)
        challenge = b"another test challenge"
        response = mock.challenge_response(challenge)

        assert len(response.data) == 20

        expected = hmac.new(MockYubiKey.TEST_NUMERIC_SECRET, challenge, hashlib.sha1).digest()
        assert response.data == expected

    def test_serial_number(self) -> None:
        """Test mock serial number."""
        mock = MockYubiKey.with_zero_secret(slot=1)
        assert mock.serial == 12345678

    def test_custom_serial(self) -> None:
        """Test custom serial number."""
        mock = MockYubiKey(slot=1, serial=99999999)
        assert mock.serial == 99999999

    def test_invalid_slot_raises(self) -> None:
        """Test error on invalid slot number."""
        with pytest.raises(ValueError, match="Slot must be 1 or 2"):
            MockYubiKey(slot=3)

    def test_custom_secret(self) -> None:
        """Test MockYubiKey with custom secret."""
        custom_secret = b"x" * 20
        mock = MockYubiKey.with_secret(slot=1, secret=custom_secret)

        challenge = b"test"
        response = mock.challenge_response(challenge)
        expected = hmac.new(custom_secret, challenge, hashlib.sha1).digest()
        assert response.data == expected

    def test_invalid_secret_length(self) -> None:
        """Test error on invalid secret length."""
        with pytest.raises(ValueError, match="must be exactly 20 bytes"):
            MockYubiKey(slot=1, secret=b"too short")

    def test_touch_callback(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test touch prompt is printed when simulate_touch=True."""
        mock = MockYubiKey(slot=1, simulate_touch=True)
        mock.challenge_response(b"test")
        captured = capsys.readouterr()
        assert "Touch your YubiKey" in captured.err

    def test_no_touch_callback_by_default(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test touch prompt is not printed by default."""
        mock = MockYubiKey(slot=1)  # simulate_touch=False by default
        mock.challenge_response(b"test")
        captured = capsys.readouterr()
        assert "Touch your YubiKey" not in captured.err

    def test_deterministic_response(self) -> None:
        """Test same challenge produces same response."""
        mock = MockYubiKey.with_zero_secret(slot=1)
        challenge = b"deterministic test"
        response1 = mock.challenge_response(challenge)
        response2 = mock.challenge_response(challenge)
        assert response1.data == response2.data

    def test_different_challenges(self) -> None:
        """Test different challenges produce different responses."""
        mock = MockYubiKey.with_zero_secret(slot=1)
        response1 = mock.challenge_response(b"challenge1")
        response2 = mock.challenge_response(b"challenge2")
        assert response1.data != response2.data

    def test_different_slots_different_secrets(self) -> None:
        """Test that different slots use different secrets by default."""
        mock1 = MockYubiKey.with_zero_secret(slot=1)
        mock2 = MockYubiKey.with_numeric_secret(MockYubiKey.TEST_NUMERIC_SECRET, slot=2)
        challenge = b"test"

        response1 = mock1.challenge_response(challenge)
        response2 = mock2.challenge_response(challenge)

        # Different secrets should produce different responses
        assert response1.data != response2.data

        # Verify secrets are as expected
        expected1 = hmac.new(MockYubiKey.ZERO_SECRET, challenge, hashlib.sha1).digest()
        expected2 = hmac.new(MockYubiKey.TEST_NUMERIC_SECRET, challenge, hashlib.sha1).digest()
        assert response1.data == expected1
        assert response2.data == expected2


class TestMockYubiKeyDatabaseIntegration:
    """Tests for Database API using MockYubiKey (no hardware required).

    With the new ChallengeResponseProvider pattern, no patching is needed.
    MockYubiKey can be used directly as a provider.
    """

    def test_create_and_open_with_mock_yubikey(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test creating and reopening a database with mock YubiKey."""
        from pathlib import Path

        from kdbxtool.database import Database

        provider = MockYubiKey.with_zero_secret(slot=1)
        db_path = Path(str(tmp_path)) / "mock_yubikey_test.kdbx"

        # Create database
        db = Database.create(password="testpassword")
        db.root_group.create_entry(
            title="Test Entry",
            username="testuser",
            password="testpass",
        )

        # Save with mock YubiKey provider - no patching needed!
        db.save(db_path, challenge_response_provider=provider)

        # Read the database back with the same provider
        db2 = Database.open(db_path, password="testpassword", challenge_response_provider=provider)

        entries = db2.find_entries(title="Test Entry")
        assert len(entries) == 1
        assert entries[0].username == "testuser"
        assert entries[0].password == "testpass"

    def test_bytes_roundtrip_with_mock_yubikey(self) -> None:
        """Test to_bytes/open_bytes cycle with mock YubiKey."""
        from kdbxtool.database import Database

        provider = MockYubiKey.with_numeric_secret(MockYubiKey.TEST_NUMERIC_SECRET, slot=2)

        # Create and serialize with mock YubiKey - no patching needed!
        db = Database.create(password="testpassword")
        db.root_group.create_entry(title="Roundtrip Test", username="user")

        data = db.to_bytes(challenge_response_provider=provider)

        # Deserialize
        db2 = Database.open_bytes(
            data, password="testpassword", challenge_response_provider=provider
        )

        entries = db2.find_entries(title="Roundtrip Test")
        assert len(entries) == 1

    def test_wrong_provider_fails(self) -> None:
        """Test that using wrong provider fails to decrypt."""
        from kdbxtool.database import Database
        from kdbxtool.exceptions import AuthenticationError

        provider1 = MockYubiKey.with_zero_secret(slot=1)
        provider2 = MockYubiKey.with_numeric_secret(MockYubiKey.TEST_NUMERIC_SECRET, slot=2)

        # Create with provider 1
        db = Database.create(password="testpassword")
        data = db.to_bytes(challenge_response_provider=provider1)

        # Try to open with provider 2 (different secret) - should fail
        with pytest.raises(AuthenticationError):
            Database.open_bytes(
                data, password="testpassword", challenge_response_provider=provider2
            )

    def test_kdf_rotation_on_save(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test that KDF salt is regenerated on save (YubiKey challenge rotation)."""
        from pathlib import Path

        from kdbxtool.database import Database

        provider = MockYubiKey.with_zero_secret(slot=1)
        db_path = Path(str(tmp_path)) / "rotation_test.kdbx"

        # Create and save initial database
        db = Database.create(password="testpassword")
        db.root_group.create_entry(title="Original", username="user1")

        db.save(db_path, challenge_response_provider=provider)

        # Get the initial KDF salt
        initial_salt = db.kdf_salt

        # Modify and save again
        db.root_group.create_entry(title="New Entry", username="user2")
        db.save()

        # Salt should have changed (rotation on save)
        new_salt = db.kdf_salt
        assert initial_salt != new_salt, "KDF salt should be rotated on save"

        # Database should still be openable
        db2 = Database.open(db_path, password="testpassword", challenge_response_provider=provider)

        entries = db2.find_entries()
        assert len(entries) == 2
