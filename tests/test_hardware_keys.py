"""Hardware integration tests for YubiKey HMAC-SHA1 challenge-response.

These tests require a physical YubiKey with HMAC-SHA1 configured in slot 2.
They are marked with @pytest.mark.hardware and skipped in CI.

Test Classes:
    TestYubiKeyHardware: Low-level YubiKey provider tests
    TestDatabaseYubiKeyHardware: KeePassXC-compatible mode database tests
    TestKekModeHardware: KEK mode tests (multi-device support)
    TestKeePassXCCompatibility: Compat vs KEK mode format verification

To run these tests locally:
    pytest -m hardware tests/test_hardware_keys.py -v

To configure your YubiKey for testing:
    ykman otp chalresp -g 2  # Generate random secret for slot 2

Environment variables:
    YUBIKEY_SERIAL: Serial number of YubiKey to use (optional, uses first device)
    YUBIKEY_SLOT: Slot to use (default: 2)

KEK Mode vs KeePassXC-Compatible Mode:
    KeePassXC-compatible mode:
        Uses challenge_response_provider parameter in save/open.
        Creates KeePassXC/KeePassDX compatible databases.
        Single device only.

    KEK mode:
        Uses enroll_device() to add devices.
        Supports multiple backup devices.
        NOT compatible with KeePassXC/KeePassDX.
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


@requires_yubikey
class TestKekModeHardware:
    """Integration tests for KEK mode (multi-device support) with real YubiKey.

    These tests verify:
    - Device enrollment and database encryption
    - Opening with enrolled device
    - Adding backup devices
    - Device revocation
    - KEK rotation
    - Migration to password-only (disable_kek_mode)
    """

    def test_enroll_single_device(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test enrolling a single YubiKey in KEK mode."""
        from pathlib import Path

        from kdbxtool import Database, YubiKeyHmacSha1

        slot, serial = get_test_yubikey_config()
        provider = YubiKeyHmacSha1(slot=slot, serial=serial, on_touch_required=None)
        db_path = Path(str(tmp_path)) / "kek_single.kdbx"

        # Create database and enroll device
        db = Database.create(password="testpassword")
        db.root_group.create_entry(
            title="KEK Test Entry",
            username="kekuser",
            password="kekpass",
        )
        db.enroll_device(provider, label="Primary YubiKey")
        db.save(db_path)

        # Verify KEK mode enabled
        assert db.kek_mode is True
        assert db.enrolled_device_count == 1

        # Reopen with enrolled device
        db2 = Database.open(
            db_path,
            password="testpassword",
            challenge_response_provider=provider,
        )

        # Verify data preserved
        entries = db2.find_entries(title="KEK Test Entry")
        assert len(entries) == 1
        assert entries[0].username == "kekuser"
        assert entries[0].password == "kekpass"
        assert db2.kek_mode is True

    def test_enroll_device_bytes_roundtrip(self) -> None:
        """Test KEK mode with to_bytes/open_bytes."""
        from kdbxtool import Database, YubiKeyHmacSha1

        slot, serial = get_test_yubikey_config()
        provider = YubiKeyHmacSha1(slot=slot, serial=serial, on_touch_required=None)

        # Create and serialize
        db = Database.create(password="testpassword")
        db.root_group.create_entry(title="Bytes Test", username="user")
        db.enroll_device(provider, label="Test Device")
        data = db.to_bytes()

        # Deserialize
        db2 = Database.open_bytes(
            data,
            password="testpassword",
            challenge_response_provider=provider,
        )

        entries = db2.find_entries(title="Bytes Test")
        assert len(entries) == 1
        assert db2.kek_mode is True

    def test_modify_and_resave_kek_mode(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test modifying and resaving a KEK-mode database."""
        from pathlib import Path

        from kdbxtool import Database, YubiKeyHmacSha1

        slot, serial = get_test_yubikey_config()
        provider = YubiKeyHmacSha1(slot=slot, serial=serial, on_touch_required=None)
        db_path = Path(str(tmp_path)) / "kek_modify.kdbx"

        # Create initial database
        db = Database.create(password="testpassword")
        db.root_group.create_entry(title="Original", username="user1")
        db.enroll_device(provider, label="Primary")
        db.save(db_path)

        # Reopen and modify
        db2 = Database.open(
            db_path,
            password="testpassword",
            challenge_response_provider=provider,
        )
        db2.root_group.create_entry(title="New Entry", username="user2")
        db2.save()

        # Reopen and verify
        db3 = Database.open(
            db_path,
            password="testpassword",
            challenge_response_provider=provider,
        )
        entries = db3.find_entries()
        assert len(entries) == 2
        titles = {e.title for e in entries}
        assert titles == {"Original", "New Entry"}

    def test_wrong_password_kek_mode(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test that wrong password fails in KEK mode even with correct device."""
        from pathlib import Path

        from kdbxtool import Database, YubiKeyHmacSha1
        from kdbxtool.exceptions import AuthenticationError

        slot, serial = get_test_yubikey_config()
        provider = YubiKeyHmacSha1(slot=slot, serial=serial, on_touch_required=None)
        db_path = Path(str(tmp_path)) / "kek_wrong_pass.kdbx"

        # Create database
        db = Database.create(password="correctpassword")
        db.enroll_device(provider, label="Primary")
        db.save(db_path)

        # Try to open with wrong password
        with pytest.raises(AuthenticationError):
            Database.open(
                db_path,
                password="wrongpassword",
                challenge_response_provider=provider,
            )

    def test_missing_device_kek_mode(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test that opening KEK database without device fails."""
        from pathlib import Path

        from kdbxtool import Database, YubiKeyHmacSha1
        from kdbxtool.exceptions import AuthenticationError

        slot, serial = get_test_yubikey_config()
        provider = YubiKeyHmacSha1(slot=slot, serial=serial, on_touch_required=None)
        db_path = Path(str(tmp_path)) / "kek_missing.kdbx"

        # Create database with device
        db = Database.create(password="testpassword")
        db.enroll_device(provider, label="Primary")
        db.save(db_path)

        # Try to open without device
        with pytest.raises(AuthenticationError):
            Database.open(db_path, password="testpassword")

    def test_list_enrolled_devices(self) -> None:
        """Test listing enrolled devices."""
        from kdbxtool import Database, YubiKeyHmacSha1

        slot, serial = get_test_yubikey_config()
        provider = YubiKeyHmacSha1(slot=slot, serial=serial, on_touch_required=None)

        db = Database.create(password="testpassword")
        db.enroll_device(provider, label="My YubiKey")

        devices = db.list_enrolled_devices()
        assert len(devices) == 1
        assert devices[0]["label"] == "My YubiKey"
        assert devices[0]["type"] == "yubikey_hmac"

    def test_disable_kek_mode_migration(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test migrating from KEK mode back to password-only."""
        from pathlib import Path

        from kdbxtool import Database, YubiKeyHmacSha1

        slot, serial = get_test_yubikey_config()
        provider = YubiKeyHmacSha1(slot=slot, serial=serial, on_touch_required=None)
        db_path = Path(str(tmp_path)) / "kek_migrate.kdbx"
        backup_path = Path(str(tmp_path)) / "password_only.kdbx"

        # Create KEK database
        db = Database.create(password="testpassword")
        db.root_group.create_entry(title="Migrate Test", username="user")
        db.enroll_device(provider, label="Primary")
        db.save(db_path)
        assert db.kek_mode is True

        # Reopen and migrate to password-only
        db2 = Database.open(
            db_path,
            password="testpassword",
            challenge_response_provider=provider,
        )
        db2.disable_kek_mode()
        db2.save(backup_path)

        # Verify password-only access works
        db3 = Database.open(backup_path, password="testpassword")
        assert db3.kek_mode is False
        entries = db3.find_entries(title="Migrate Test")
        assert len(entries) == 1
        assert entries[0].username == "user"

    def test_rotate_kek(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test KEK rotation with enrolled device."""
        from pathlib import Path

        from kdbxtool import Database, YubiKeyHmacSha1

        slot, serial = get_test_yubikey_config()
        provider = YubiKeyHmacSha1(slot=slot, serial=serial, on_touch_required=None)
        db_path = Path(str(tmp_path)) / "kek_rotate.kdbx"

        # Create KEK database
        db = Database.create(password="testpassword")
        db.root_group.create_entry(title="Rotate Test", username="user")
        db.enroll_device(provider, label="Primary")
        db.save(db_path)

        # Rotate KEK
        db2 = Database.open(
            db_path,
            password="testpassword",
            challenge_response_provider=provider,
        )
        db2.rotate_kek({"Primary": provider})
        db2.save()

        # Verify database still accessible
        db3 = Database.open(
            db_path,
            password="testpassword",
            challenge_response_provider=provider,
        )
        entries = db3.find_entries(title="Rotate Test")
        assert len(entries) == 1

    def test_revoke_device_prevents_access(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test that revoking a device prevents unwrapping its KEK entry.

        Note: This test uses the same physical YubiKey enrolled twice with
        different labels to test the revocation logic. In real usage, you
        would have different physical devices.
        """
        from pathlib import Path

        from kdbxtool import Database, YubiKeyHmacSha1

        slot, serial = get_test_yubikey_config()
        provider = YubiKeyHmacSha1(slot=slot, serial=serial, on_touch_required=None)
        db_path = Path(str(tmp_path)) / "kek_revoke.kdbx"

        # Create database with two "devices" (same physical key, different labels)
        db = Database.create(password="testpassword")
        db.root_group.create_entry(title="Revoke Test", username="user")
        db.enroll_device(provider, label="Primary")
        db.enroll_device(provider, label="Backup")
        db.save(db_path)

        assert db.enrolled_device_count == 2

        # Revoke one device
        db2 = Database.open(
            db_path,
            password="testpassword",
            challenge_response_provider=provider,
        )
        db2.revoke_device(label="Primary")
        db2.save()

        # Verify only one device remains
        db3 = Database.open(
            db_path,
            password="testpassword",
            challenge_response_provider=provider,
        )
        assert db3.enrolled_device_count == 1
        devices = db3.list_enrolled_devices()
        assert devices[0]["label"] == "Backup"


@requires_yubikey
class TestKeePassXCCompatibility:
    """Tests for KeePassXC-compatible mode.

    KeePassXC-compatible mode saves using challenge_response_provider parameter
    (not enroll_device), which produces databases compatible with KeePassXC and KeePassDX.
    """

    def test_compat_mode_format(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test that KeePassXC-compatible mode creates correct format."""
        from pathlib import Path

        from kdbxtool import Database, YubiKeyHmacSha1

        slot, serial = get_test_yubikey_config()
        provider = YubiKeyHmacSha1(slot=slot, serial=serial, on_touch_required=None)
        db_path = Path(str(tmp_path)) / "compat.kdbx"

        # Create database in KeePassXC-compatible mode
        db = Database.create(password="testpassword")
        db.root_group.create_entry(title="Compat Test", username="user")
        db.save(db_path, challenge_response_provider=provider)

        # Verify not in KEK mode
        assert db.kek_mode is False

        # Reopen and verify
        db2 = Database.open(
            db_path,
            password="testpassword",
            challenge_response_provider=provider,
        )
        assert db2.kek_mode is False
        entries = db2.find_entries(title="Compat Test")
        assert len(entries) == 1

    def test_compat_vs_kek_mode_incompatible(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test that KEK mode databases cannot be opened without device."""
        from pathlib import Path

        from kdbxtool import Database, YubiKeyHmacSha1
        from kdbxtool.exceptions import AuthenticationError

        slot, serial = get_test_yubikey_config()
        provider = YubiKeyHmacSha1(slot=slot, serial=serial, on_touch_required=None)
        compat_path = Path(str(tmp_path)) / "compat.kdbx"
        kek_path = Path(str(tmp_path)) / "kek.kdbx"

        # Create KeePassXC-compatible mode database
        db_compat = Database.create(password="testpassword")
        db_compat.save(compat_path, challenge_response_provider=provider)

        # Create KEK mode database
        db_kek = Database.create(password="testpassword")
        db_kek.enroll_device(provider, label="Primary")
        db_kek.save(kek_path)

        # Compat mode cannot be opened without device
        with pytest.raises(AuthenticationError):
            Database.open(compat_path, password="testpassword")

        # KEK mode cannot be opened without device
        with pytest.raises(AuthenticationError):
            Database.open(kek_path, password="testpassword")
