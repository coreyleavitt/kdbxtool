"""Hardware integration tests for YubiKey HMAC-SHA1 challenge-response.

These tests require a physical YubiKey with HMAC-SHA1 configured in slot 2.
They are marked with @pytest.mark.hardware and skipped in CI.

To run these tests locally:
    pytest -m hardware tests/test_yubikey_hardware.py -v

To configure your YubiKey for testing:
    ykman otp chalresp -g 2  # Generate random secret for slot 2

Environment variables:
    YUBIKEY_SERIAL: Serial number of YubiKey to use (optional, uses first device)
    YUBIKEY_SLOT: Slot to use (default: 2)
"""

import os

import pytest

from kdbxtool.security.yubikey import YUBIKEY_HARDWARE_AVAILABLE

# Skip entire module if yubikey-manager not installed
pytestmark = [
    pytest.mark.hardware,
    pytest.mark.skipif(
        not YUBIKEY_HARDWARE_AVAILABLE,
        reason="yubikey-manager not installed",
    ),
]


def get_test_yubikey_config() -> tuple[int, int | None]:
    """Get YubiKey configuration from environment."""
    slot = int(os.environ.get("YUBIKEY_SLOT", "2"))
    serial_str = os.environ.get("YUBIKEY_SERIAL")
    serial = int(serial_str) if serial_str else None
    return slot, serial


def yubikey_connected() -> bool:
    """Check if a YubiKey is actually connected."""
    if not YUBIKEY_HARDWARE_AVAILABLE:
        return False
    try:
        from kdbxtool.security.yubikey import list_yubikeys

        devices = list_yubikeys()
        return len(devices) > 0
    except Exception:
        return False


# Additional skip if no YubiKey is connected
requires_yubikey = pytest.mark.skipif(
    not yubikey_connected(),
    reason="No YubiKey connected",
)


@requires_yubikey
class TestYubiKeyHardware:
    """Integration tests requiring physical YubiKey."""

    def test_list_yubikeys(self) -> None:
        """Test listing connected YubiKeys."""
        from kdbxtool.security.yubikey import list_yubikeys

        devices = list_yubikeys()
        assert len(devices) >= 1

        device = devices[0]
        assert "name" in device
        # Serial may not be available on all YubiKeys
        if "serial" in device:
            assert isinstance(device["serial"], int)

    def test_hardware_yubikey_provider(self) -> None:
        """Test YubiKeyHmacSha1 provider with real YubiKey."""
        from kdbxtool import YubiKeyHmacSha1

        slot, serial = get_test_yubikey_config()
        provider = YubiKeyHmacSha1(slot=slot, serial=serial, on_touch_required=None)

        # Send a test challenge
        challenge = os.urandom(32)
        response = provider.challenge_response(challenge)

        # Response should be 20 bytes (HMAC-SHA1 output)
        assert len(response.data) == 20

    def test_hardware_yubikey_deterministic(self) -> None:
        """Test that same challenge produces same response."""
        from kdbxtool import YubiKeyHmacSha1

        slot, serial = get_test_yubikey_config()
        provider = YubiKeyHmacSha1(slot=slot, serial=serial, on_touch_required=None)

        challenge = os.urandom(32)
        response1 = provider.challenge_response(challenge)
        response2 = provider.challenge_response(challenge)

        assert response1.data == response2.data

    def test_hardware_yubikey_different_challenges(self) -> None:
        """Test that different challenges produce different responses."""
        from kdbxtool import YubiKeyHmacSha1

        slot, serial = get_test_yubikey_config()
        provider = YubiKeyHmacSha1(slot=slot, serial=serial, on_touch_required=None)

        challenge1 = os.urandom(32)
        challenge2 = os.urandom(32)

        response1 = provider.challenge_response(challenge1)
        response2 = provider.challenge_response(challenge2)

        assert response1.data != response2.data

    def test_hardware_yubikey_requires_touch_property(self) -> None:
        """Test YubiKeyHmacSha1 requires_touch property."""
        from kdbxtool import YubiKeyHmacSha1

        slot, serial = get_test_yubikey_config()
        provider = YubiKeyHmacSha1(slot=slot, serial=serial, on_touch_required=None)

        # Property should be queryable
        requires_touch = provider.requires_touch
        assert isinstance(requires_touch, bool)

    def test_check_slot_configured(self) -> None:
        """Test checking if slot is configured for HMAC-SHA1."""
        from kdbxtool.security.yubikey import check_slot_configured

        slot, serial = get_test_yubikey_config()
        result = check_slot_configured(slot=slot, serial=serial)

        # This test assumes the slot is configured - skip if not
        if not result:
            pytest.skip(f"YubiKey slot {slot} not configured for HMAC-SHA1")

        assert result is True


@requires_yubikey
class TestDatabaseYubiKeyHardware:
    """Integration tests for Database API with real YubiKey."""

    def test_create_and_open_database(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test creating and reopening a YubiKey-protected database."""
        from pathlib import Path

        from kdbxtool import Database, YubiKeyHmacSha1

        slot, serial = get_test_yubikey_config()
        provider = YubiKeyHmacSha1(slot=slot, serial=serial, on_touch_required=None)
        db_path = Path(str(tmp_path)) / "yubikey_test.kdbx"

        # Create database and save with YubiKey
        db = Database.create(password="testpassword")
        db.root_group.create_entry(
            title="Test Entry",
            username="testuser",
            password="testpass",
        )
        db.save(db_path, challenge_response_provider=provider)

        # Reopen with YubiKey
        db2 = Database.open(
            db_path,
            password="testpassword",
            challenge_response_provider=provider,
        )

        entries = db2.find_entries(title="Test Entry")
        assert len(entries) == 1
        assert entries[0].username == "testuser"
        assert entries[0].password == "testpass"

    def test_bytes_roundtrip(self) -> None:
        """Test to_bytes/open_bytes with YubiKey."""
        from kdbxtool import Database, YubiKeyHmacSha1

        slot, serial = get_test_yubikey_config()
        provider = YubiKeyHmacSha1(slot=slot, serial=serial, on_touch_required=None)

        # Create and serialize with YubiKey
        db = Database.create(password="testpassword")
        db.root_group.create_entry(title="Roundtrip Test", username="user")
        data = db.to_bytes(challenge_response_provider=provider)

        # Deserialize
        db2 = Database.open_bytes(
            data,
            password="testpassword",
            challenge_response_provider=provider,
        )

        entries = db2.find_entries(title="Roundtrip Test")
        assert len(entries) == 1

    def test_wrong_password_fails(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test that wrong password fails even with correct YubiKey."""
        from pathlib import Path

        from kdbxtool import Database, YubiKeyHmacSha1
        from kdbxtool.exceptions import AuthenticationError

        slot, serial = get_test_yubikey_config()
        provider = YubiKeyHmacSha1(slot=slot, serial=serial, on_touch_required=None)
        db_path = Path(str(tmp_path)) / "yubikey_test.kdbx"

        # Create database
        db = Database.create(password="correctpassword")
        db.save(db_path, challenge_response_provider=provider)

        # Try to open with wrong password
        with pytest.raises(AuthenticationError):
            Database.open(
                db_path,
                password="wrongpassword",
                challenge_response_provider=provider,
            )

    def test_missing_yubikey_fails(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test that opening without YubiKey fails."""
        from pathlib import Path

        from kdbxtool import Database, YubiKeyHmacSha1
        from kdbxtool.exceptions import AuthenticationError

        slot, serial = get_test_yubikey_config()
        provider = YubiKeyHmacSha1(slot=slot, serial=serial, on_touch_required=None)
        db_path = Path(str(tmp_path)) / "yubikey_test.kdbx"

        # Create database with YubiKey
        db = Database.create(password="testpassword")
        db.save(db_path, challenge_response_provider=provider)

        # Try to open without YubiKey (password only)
        with pytest.raises(AuthenticationError):
            Database.open(db_path, password="testpassword")

    def test_modify_and_resave(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test modifying and resaving a YubiKey-protected database."""
        from pathlib import Path

        from kdbxtool import Database, YubiKeyHmacSha1

        slot, serial = get_test_yubikey_config()
        provider = YubiKeyHmacSha1(slot=slot, serial=serial, on_touch_required=None)
        db_path = Path(str(tmp_path)) / "yubikey_modify.kdbx"

        # Create initial database
        db = Database.create(password="testpassword")
        db.root_group.create_entry(title="Original Entry", username="user1")
        db.save(db_path, challenge_response_provider=provider)

        # Reopen and modify
        db2 = Database.open(
            db_path,
            password="testpassword",
            challenge_response_provider=provider,
        )
        db2.root_group.create_entry(title="New Entry", username="user2")
        db2.save(challenge_response_provider=provider)

        # Reopen again to verify
        db3 = Database.open(
            db_path,
            password="testpassword",
            challenge_response_provider=provider,
        )
        entries = db3.find_entries()
        assert len(entries) == 2
        titles = {e.title for e in entries}
        assert titles == {"Original Entry", "New Entry"}
