"""Tests for FIDO2 hmac-secret support."""

from unittest.mock import patch

import pytest

from kdbxtool import AuthenticationError, ChallengeResponseProvider, Database
from kdbxtool.exceptions import (
    Fido2CredentialNotFoundError,
    Fido2DeviceNotFoundError,
    Fido2Error,
    Fido2NotAvailableError,
    Fido2PinRequiredError,
)
from kdbxtool.security.fido2 import (
    DEFAULT_RP_ID,
    FIDO2_AVAILABLE,
    list_fido2_devices,
)
from kdbxtool.security.memory import SecureBytes
from kdbxtool.testing import MockFido2


class TestFido2Exceptions:
    """Tests for FIDO2 exception classes."""

    def test_fido2_error_base(self) -> None:
        """Test Fido2Error is a valid exception."""
        with pytest.raises(Fido2Error):
            raise Fido2Error("test error")

    def test_fido2_not_available_error(self) -> None:
        """Test Fido2NotAvailableError message."""
        error = Fido2NotAvailableError()
        assert "fido2" in str(error).lower()
        assert "pip install" in str(error).lower()

    def test_fido2_device_not_found_error(self) -> None:
        """Test Fido2DeviceNotFoundError message."""
        error = Fido2DeviceNotFoundError()
        assert "not found" in str(error).lower() or "connected" in str(error).lower()

    def test_fido2_credential_not_found_error(self) -> None:
        """Test Fido2CredentialNotFoundError message."""
        error = Fido2CredentialNotFoundError()
        assert "credential" in str(error).lower()

    def test_fido2_pin_required_error(self) -> None:
        """Test Fido2PinRequiredError message."""
        error = Fido2PinRequiredError()
        assert "pin" in str(error).lower()


class TestDefaultRpId:
    """Tests for FIDO2 default relying party ID."""

    def test_default_rp_id(self) -> None:
        """Test that default RP ID is 'kdbxtool'."""
        assert DEFAULT_RP_ID == "kdbxtool"


class TestMockFido2:
    """Tests for MockFido2 provider."""

    def test_mock_fido2_with_zero_secret(self) -> None:
        """Test MockFido2 with zero secret."""
        provider = MockFido2.with_zero_secret()
        response = provider.challenge_response(b"x" * 32)
        assert len(response.data) == 32  # FIDO2 hmac-secret output is 32 bytes

    def test_mock_fido2_with_test_secret(self) -> None:
        """Test MockFido2 with test secret."""
        provider = MockFido2.with_test_secret()
        response = provider.challenge_response(b"x" * 32)
        assert len(response.data) == 32

    def test_mock_fido2_deterministic(self) -> None:
        """Test MockFido2 produces deterministic output."""
        provider = MockFido2.with_test_secret()
        challenge = b"test challenge padded to 32 bytes"[:32].ljust(32, b"\x00")
        response1 = provider.challenge_response(challenge)
        response2 = provider.challenge_response(challenge)
        assert response1.data == response2.data

    def test_mock_fido2_different_challenges(self) -> None:
        """Test MockFido2 produces different output for different challenges."""
        provider = MockFido2.with_test_secret()
        response1 = provider.challenge_response(b"challenge 1".ljust(32, b"\x00"))
        response2 = provider.challenge_response(b"challenge 2".ljust(32, b"\x00"))
        assert response1.data != response2.data

    def test_mock_fido2_custom_secret(self) -> None:
        """Test MockFido2 with custom secret."""
        secret = b"custom_secret_for_testing_12345"
        provider = MockFido2.with_secret(secret)
        response = provider.challenge_response(b"x" * 32)
        assert len(response.data) == 32

    def test_mock_fido2_returns_secure_bytes(self) -> None:
        """Test MockFido2 returns SecureBytes."""
        provider = MockFido2.with_test_secret()
        response = provider.challenge_response(b"x" * 32)
        assert isinstance(response, SecureBytes)

    def test_mock_fido2_repr(self) -> None:
        """Test MockFido2 repr."""
        provider = MockFido2.with_zero_secret()
        assert "MockFido2" in repr(provider)


class TestFido2ProtocolCompliance:
    """Tests for ChallengeResponseProvider protocol compliance."""

    def test_mock_fido2_implements_protocol(self) -> None:
        """Test MockFido2 implements ChallengeResponseProvider."""
        provider = MockFido2.with_test_secret()
        assert isinstance(provider, ChallengeResponseProvider)

    def test_mock_fido2_has_challenge_response_method(self) -> None:
        """Test MockFido2 has challenge_response method."""
        provider = MockFido2.with_test_secret()
        assert hasattr(provider, "challenge_response")
        assert callable(provider.challenge_response)


@pytest.mark.xfail(reason="FIDO2 requires KEK mode which is not yet implemented in database.py")
class TestFido2WithDatabase:
    """Tests for using MockFido2 with Database API.

    NOTE: These tests are marked xfail because FIDO2 requires KEK mode,
    which is not yet fully implemented in database.py. FIDO2 responses
    (32 bytes) cannot be passed to derive_composite_key() in KeePassXC-compatible mode.
    """

    def test_database_create_with_fido2_provider(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test creating database with FIDO2 provider."""
        from pathlib import Path

        provider = MockFido2.with_test_secret()

        db = Database.create(password="test")
        db_path = Path(str(tmp_path)) / "fido2_test.kdbx"
        db.save(db_path, challenge_response_provider=provider)

        db2 = Database.open(db_path, password="test", challenge_response_provider=provider)
        assert db2 is not None

    def test_database_roundtrip_with_fido2(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test full roundtrip with FIDO2 provider."""
        from pathlib import Path

        provider = MockFido2.with_test_secret()

        db = Database.create(password="secret")
        db.root_group.create_entry(
            title="FIDO2 Test Entry",
            username="fido2user",
            password="fido2pass",
        )

        db_path = Path(str(tmp_path)) / "fido2_roundtrip.kdbx"
        db.save(db_path, challenge_response_provider=provider)

        db2 = Database.open(db_path, password="secret", challenge_response_provider=provider)
        entries = db2.find_entries(title="FIDO2 Test Entry")
        assert len(entries) == 1
        assert entries[0].username == "fido2user"
        assert entries[0].password == "fido2pass"

    def test_fido2_only_authentication(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test authentication with FIDO2 provider (password still required)."""
        from pathlib import Path

        provider = MockFido2.with_test_secret()

        # KDBX always requires at least a minimal password
        db = Database.create(password="minimal")
        db_path = Path(str(tmp_path)) / "fido2_only.kdbx"
        db.save(db_path, challenge_response_provider=provider)

        db2 = Database.open(db_path, password="minimal", challenge_response_provider=provider)
        assert db2 is not None

    def test_fido2_changes_derived_key(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test that FIDO2 provider affects derived key."""
        from pathlib import Path

        provider = MockFido2.with_test_secret()

        # Create and save with provider
        db = Database.create(password="same_password")
        db_path = Path(str(tmp_path)) / "fido2_key.kdbx"
        db.save(db_path, challenge_response_provider=provider)

        # Should fail to open without provider
        with pytest.raises(AuthenticationError):
            Database.open(db_path, password="same_password")

        # Should succeed with provider
        db2 = Database.open(db_path, password="same_password", challenge_response_provider=provider)
        assert db2 is not None


class TestFido2ListDevices:
    """Tests for list_fido2_devices function."""

    @patch("kdbxtool.security.fido2.FIDO2_AVAILABLE", False)
    def test_list_devices_not_available(self) -> None:
        """Test list_fido2_devices raises when python-fido2 not installed."""
        with pytest.raises(Fido2NotAvailableError):
            list_fido2_devices()


# Tests that require python-fido2 to be installed for proper mocking
@pytest.mark.skipif(
    not FIDO2_AVAILABLE,
    reason="python-fido2 not installed - cannot mock internal functions",
)
class TestFido2WithLibraryInstalled:
    """Tests that require python-fido2 for proper mocking."""

    def test_list_devices_no_device(self) -> None:
        """Test list_fido2_devices returns empty list when no device."""
        with patch("kdbxtool.security.fido2.CtapHidDevice") as mock_ctap:
            mock_ctap.list_devices.return_value = []
            result = list_fido2_devices()
            assert result == []

    def test_yubikey_fido2_no_device(self) -> None:
        """Test YubiKeyFido2 raises when no device found."""
        from kdbxtool.security.fido2 import YubiKeyFido2

        with patch("kdbxtool.security.fido2.CtapHidDevice") as mock_ctap:
            mock_ctap.list_devices.return_value = []
            with pytest.raises(Fido2DeviceNotFoundError):
                YubiKeyFido2(credential_id=b"test_credential_id")
