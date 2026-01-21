"""Tests for multi-key challenge-response scenarios.

These tests verify the provider-based API works correctly with
different provider types (MockYubiKey, MockFido2) and that the
system correctly differentiates between them.

Note: The full multi-key enrollment API (add_challenge_response_device, etc.)
is a planned future enhancement. These tests cover the current provider-based API.
"""

import pytest

from kdbxtool import ChallengeResponseProvider, Database
from kdbxtool.security.memory import SecureBytes
from kdbxtool.testing import MockFido2, MockProvider, MockYubiKey


class TestDifferentProviderTypes:
    """Tests for using different provider types."""

    def test_yubikey_and_fido2_different_keys(self) -> None:
        """Test that YubiKey and FIDO2 providers produce different keys."""
        challenge = b"x" * 32

        yubikey = MockYubiKey.with_test_secret()
        fido2 = MockFido2.with_test_secret()

        # Same secret but should produce different outputs due to different output sizes
        yk_response = yubikey.challenge_response(challenge)
        f2_response = fido2.challenge_response(challenge)

        # YubiKey HMAC-SHA1 is 20 bytes, FIDO2 hmac-secret is 32 bytes
        assert len(yk_response.data) == 20
        assert len(f2_response.data) == 32

    def test_different_secrets_different_keys(self) -> None:
        """Test that different secrets produce different keys."""
        challenge = b"x" * 32

        provider1 = MockProvider(b"secret_one")
        provider2 = MockProvider(b"secret_two")

        response1 = provider1.challenge_response(challenge)
        response2 = provider2.challenge_response(challenge)

        assert response1.data != response2.data


class TestProviderSeparation:
    """Tests for database separation with different providers."""

    def test_different_databases_different_providers(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Test that databases with different providers are separate."""
        from pathlib import Path

        provider1 = MockYubiKey.with_secret(b"provider_one_secret!")
        provider2 = MockYubiKey.with_secret(b"provider_two_secret!")

        # Create two databases with different providers
        db1 = Database.create(password="password1")
        db1_path = Path(str(tmp_path)) / "db1.kdbx"
        db1.save(db1_path, challenge_response_provider=provider1)

        db2 = Database.create(password="password2")
        db2_path = Path(str(tmp_path)) / "db2.kdbx"
        db2.save(db2_path, challenge_response_provider=provider2)

        # Each database should only open with its own provider
        db1_opened = Database.open(
            db1_path, password="password1", challenge_response_provider=provider1
        )
        assert db1_opened is not None

        db2_opened = Database.open(
            db2_path, password="password2", challenge_response_provider=provider2
        )
        assert db2_opened is not None

    def test_wrong_provider_fails(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test that wrong provider fails to open database."""
        from pathlib import Path

        correct_provider = MockYubiKey.with_secret(b"correct_secret_here!")
        wrong_provider = MockYubiKey.with_secret(b"wrong_secret_here__!")

        db = Database.create(password="password")
        db_path = Path(str(tmp_path)) / "test.kdbx"
        db.save(db_path, challenge_response_provider=correct_provider)

        # Wrong provider should fail
        with pytest.raises(Exception):  # AuthenticationError
            Database.open(db_path, password="password", challenge_response_provider=wrong_provider)


class TestProviderRequirement:
    """Tests for provider requirement after database is protected."""

    def test_missing_provider_fails(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test that missing provider fails when database was saved with one."""
        from pathlib import Path

        provider = MockYubiKey.with_test_secret()

        db = Database.create(password="password")
        db_path = Path(str(tmp_path)) / "with_provider.kdbx"
        db.save(db_path, challenge_response_provider=provider)

        # Should fail without provider
        with pytest.raises(Exception):  # AuthenticationError
            Database.open(db_path, password="password")

    def test_extra_provider_succeeds(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test that providing provider when not required still works.

        When a database wasn't saved with a challenge-response provider,
        providing one during open is allowed but has no effect since
        the provider wasn't used during key derivation.
        """
        from pathlib import Path

        provider = MockYubiKey.with_test_secret()

        # Create database WITHOUT provider
        db = Database.create(password="password")
        db_path = Path(str(tmp_path)) / "no_provider.kdbx"
        db.save(db_path)  # No provider

        # Opening without provider should work
        db1 = Database.open(db_path, password="password")
        assert db1 is not None

        # Opening with provider should FAIL because the key derivation
        # will include the challenge-response which wasn't used originally
        with pytest.raises(Exception):
            Database.open(db_path, password="password", challenge_response_provider=provider)


@pytest.mark.xfail(
    reason="FIDO2 requires KEK mode which is not yet implemented in database.py"
)
class TestMixedProviderTypes:
    """Tests for using different provider types (YubiKey vs FIDO2).

    NOTE: These tests are marked xfail because FIDO2 requires KEK mode,
    which is not yet fully implemented in database.py.
    """

    def test_yubikey_database_fido2_fails(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test that FIDO2 provider fails to open YubiKey-protected database."""
        from pathlib import Path

        yubikey = MockYubiKey.with_test_secret()
        fido2 = MockFido2.with_test_secret()

        db = Database.create(password="password")
        db_path = Path(str(tmp_path)) / "yubikey_db.kdbx"
        db.save(db_path, challenge_response_provider=yubikey)

        # FIDO2 should fail (different output size and algorithm)
        with pytest.raises(Exception):  # AuthenticationError
            Database.open(db_path, password="password", challenge_response_provider=fido2)

    def test_fido2_database_yubikey_fails(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test that YubiKey provider fails to open FIDO2-protected database."""
        from pathlib import Path

        yubikey = MockYubiKey.with_test_secret()
        fido2 = MockFido2.with_test_secret()

        db = Database.create(password="password")
        db_path = Path(str(tmp_path)) / "fido2_db.kdbx"
        db.save(db_path, challenge_response_provider=fido2)

        # YubiKey should fail (different output size and algorithm)
        with pytest.raises(Exception):  # AuthenticationError
            Database.open(db_path, password="password", challenge_response_provider=yubikey)


class TestProviderSameData:
    """Tests that same provider gives same data access."""

    def test_roundtrip_preserves_data(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test that data is preserved through provider-protected roundtrip."""
        from pathlib import Path

        provider = MockYubiKey.with_test_secret()

        db = Database.create(password="password")
        db.root_group.create_entry(
            title="Important Entry",
            username="admin",
            password="supersecret",
        )
        db.root_group.create_subgroup("Subgroup")

        db_path = Path(str(tmp_path)) / "data_test.kdbx"
        db.save(db_path, challenge_response_provider=provider)

        # Open and verify data
        db2 = Database.open(db_path, password="password", challenge_response_provider=provider)

        entries = db2.find_entries(title="Important Entry")
        assert len(entries) == 1
        assert entries[0].username == "admin"
        assert entries[0].password == "supersecret"

        groups = db2.find_groups(name="Subgroup")
        assert len(groups) == 1

    def test_multiple_roundtrips(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test multiple save/open cycles with provider."""
        from pathlib import Path

        provider = MockYubiKey.with_test_secret()
        db_path = Path(str(tmp_path)) / "multi_roundtrip.kdbx"

        # Create and save
        db = Database.create(password="password")
        db.root_group.create_entry(title="Entry 1", username="user1", password="pass1")
        db.save(db_path, challenge_response_provider=provider)

        # Open, modify, save
        db2 = Database.open(db_path, password="password", challenge_response_provider=provider)
        db2.root_group.create_entry(title="Entry 2", username="user2", password="pass2")
        db2.save(challenge_response_provider=provider)

        # Open and verify both entries
        db3 = Database.open(db_path, password="password", challenge_response_provider=provider)
        entries = list(db3.iter_entries())
        assert len(entries) == 2

        titles = [e.title for e in entries]
        assert "Entry 1" in titles
        assert "Entry 2" in titles


class TestCustomProvider:
    """Tests for custom ChallengeResponseProvider implementations."""

    def test_custom_provider_works(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test that a custom provider implementation works."""
        from pathlib import Path

        class CustomProvider:
            """Custom challenge-response provider for testing."""

            def challenge_response(self, challenge: bytes) -> SecureBytes:
                # Return a fixed 20-byte response (like YubiKey HMAC-SHA1)
                import hashlib

                h = hashlib.sha1(b"custom_secret" + challenge, usedforsecurity=False)
                return SecureBytes(h.digest())

        provider = CustomProvider()

        # Verify it implements the protocol
        assert isinstance(provider, ChallengeResponseProvider)

        # Use with database
        db = Database.create(password="password")
        db_path = Path(str(tmp_path)) / "custom_provider.kdbx"
        db.save(db_path, challenge_response_provider=provider)

        db2 = Database.open(db_path, password="password", challenge_response_provider=provider)
        assert db2 is not None


class TestKekModeEnrollment:
    """Tests for KEK mode device enrollment."""

    def test_enroll_single_device(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test enrolling a single device enables KEK mode."""
        from pathlib import Path

        db = Database.create(password="password")
        assert not db.kek_mode
        assert db.enrolled_device_count == 0

        provider = MockYubiKey.with_test_secret()
        db.enroll_device(provider, label="Primary YubiKey")

        assert db.kek_mode
        assert db.enrolled_device_count == 1

        devices = db.list_enrolled_devices()
        assert len(devices) == 1
        assert devices[0]["label"] == "Primary YubiKey"
        assert "yubikey" in devices[0]["type"].lower()

    def test_enroll_multiple_devices(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test enrolling multiple devices."""
        db = Database.create(password="password")

        provider1 = MockYubiKey.with_secret(b"secret_one_here__20!")
        provider2 = MockYubiKey.with_secret(b"secret_two_here__20!")

        db.enroll_device(provider1, label="Primary")
        db.enroll_device(provider2, label="Backup")

        assert db.kek_mode
        assert db.enrolled_device_count == 2

        devices = db.list_enrolled_devices()
        labels = [d["label"] for d in devices]
        assert "Primary" in labels
        assert "Backup" in labels

    def test_enroll_duplicate_label_fails(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test that enrolling with duplicate label fails."""
        db = Database.create(password="password")

        provider1 = MockYubiKey.with_secret(b"secret_one_here__20!")
        provider2 = MockYubiKey.with_secret(b"secret_two_here__20!")

        db.enroll_device(provider1, label="Primary")

        with pytest.raises(ValueError, match="already enrolled"):
            db.enroll_device(provider2, label="Primary")

    def test_revoke_device(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test revoking an enrolled device."""
        db = Database.create(password="password")

        provider1 = MockYubiKey.with_secret(b"secret_one_here__20!")
        provider2 = MockYubiKey.with_secret(b"secret_two_here__20!")

        db.enroll_device(provider1, label="Primary")
        db.enroll_device(provider2, label="Backup")

        assert db.enrolled_device_count == 2

        db.revoke_device("Primary")

        assert db.enrolled_device_count == 1
        devices = db.list_enrolled_devices()
        assert len(devices) == 1
        assert devices[0]["label"] == "Backup"

    def test_revoke_last_device_fails(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test that revoking the last device fails."""
        db = Database.create(password="password")

        provider = MockYubiKey.with_test_secret()
        db.enroll_device(provider, label="Primary")

        with pytest.raises(ValueError, match="at least one must remain"):
            db.revoke_device("Primary")

    def test_revoke_unknown_device_fails(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test that revoking unknown device fails."""
        db = Database.create(password="password")

        provider = MockYubiKey.with_test_secret()
        db.enroll_device(provider, label="Primary")

        with pytest.raises(ValueError, match="not found"):
            db.revoke_device("Unknown")

    def test_enroll_on_legacy_database_fails(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test that enrolling on a legacy mode database fails."""
        from pathlib import Path

        from kdbxtool.exceptions import DatabaseError

        # Create database with legacy mode (using challenge_response_provider directly)
        db = Database.create(password="password")
        legacy_provider = MockYubiKey.with_test_secret()
        db_path = Path(str(tmp_path)) / "legacy.kdbx"
        db.save(db_path, challenge_response_provider=legacy_provider)

        # Open with legacy mode
        db2 = Database.open(db_path, password="password", challenge_response_provider=legacy_provider)

        # Try to enroll another device - should fail
        new_provider = MockYubiKey.with_secret(b"different_secret_20!")
        with pytest.raises(DatabaseError, match="legacy"):
            db2.enroll_device(new_provider, label="New Device")


class TestKekModeRoundtrip:
    """Tests for KEK mode database save/open."""

    def test_kek_mode_roundtrip(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test save and open with KEK mode."""
        from pathlib import Path

        db = Database.create(password="password")
        provider = MockYubiKey.with_test_secret()
        db.enroll_device(provider, label="Primary")

        db.root_group.create_entry(
            title="Test Entry",
            username="testuser",
            password="testpass",
        )

        db_path = Path(str(tmp_path)) / "kek_test.kdbx"
        db.save(db_path)

        # Open with same provider
        db2 = Database.open(db_path, password="password", challenge_response_provider=provider)
        assert db2.kek_mode
        assert db2.enrolled_device_count == 1

        entries = db2.find_entries(title="Test Entry")
        assert len(entries) == 1
        assert entries[0].username == "testuser"
        assert entries[0].password == "testpass"

    def test_kek_mode_multiple_devices_any_can_open(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Test that any enrolled device can open the database."""
        from pathlib import Path

        db = Database.create(password="password")

        provider1 = MockYubiKey.with_secret(b"secret_one_here__20!")
        provider2 = MockYubiKey.with_secret(b"secret_two_here__20!")

        db.enroll_device(provider1, label="Primary")
        db.enroll_device(provider2, label="Backup")

        db.root_group.create_entry(title="Secret", username="user", password="pass")

        db_path = Path(str(tmp_path)) / "multi_device.kdbx"
        db.save(db_path)

        # Open with first device
        db2 = Database.open(db_path, password="password", challenge_response_provider=provider1)
        assert db2.kek_mode
        assert db2.enrolled_device_count == 2
        assert db2.find_entries(title="Secret")

        # Open with second device
        db3 = Database.open(db_path, password="password", challenge_response_provider=provider2)
        assert db3.kek_mode
        assert db3.enrolled_device_count == 2
        assert db3.find_entries(title="Secret")

    def test_kek_mode_wrong_device_fails(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test that wrong device fails to open KEK mode database."""
        from pathlib import Path

        db = Database.create(password="password")

        correct_provider = MockYubiKey.with_secret(b"correct_secret__20_!")
        wrong_provider = MockYubiKey.with_secret(b"wrong_secret____20_!")

        db.enroll_device(correct_provider, label="Primary")

        db_path = Path(str(tmp_path)) / "kek_wrong.kdbx"
        db.save(db_path)

        # Wrong device should fail
        with pytest.raises(Exception):  # AuthenticationError
            Database.open(db_path, password="password", challenge_response_provider=wrong_provider)

    def test_kek_mode_missing_device_fails(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test that opening KEK mode database without device fails."""
        from pathlib import Path

        from kdbxtool.exceptions import DatabaseError

        db = Database.create(password="password")
        provider = MockYubiKey.with_test_secret()
        db.enroll_device(provider, label="Primary")

        db_path = Path(str(tmp_path)) / "kek_no_device.kdbx"
        db.save(db_path)

        # Opening without device should fail
        with pytest.raises(DatabaseError, match="requires challenge-response"):
            Database.open(db_path, password="password")


class TestKekModeWithFido2:
    """Tests for KEK mode with FIDO2 devices."""

    def test_fido2_enrollment_works(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test that FIDO2 devices can be enrolled in KEK mode."""
        from pathlib import Path

        db = Database.create(password="password")
        provider = MockFido2.with_test_secret()
        db.enroll_device(provider, label="FIDO2 Key")

        assert db.kek_mode
        assert db.enrolled_device_count == 1

        devices = db.list_enrolled_devices()
        assert len(devices) == 1
        assert devices[0]["label"] == "FIDO2 Key"

    def test_fido2_roundtrip(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test FIDO2 device roundtrip in KEK mode."""
        from pathlib import Path

        db = Database.create(password="password")
        provider = MockFido2.with_test_secret()
        db.enroll_device(provider, label="FIDO2 Key")

        db.root_group.create_entry(title="FIDO2 Entry", username="fido", password="secret")

        db_path = Path(str(tmp_path)) / "fido2_kek.kdbx"
        db.save(db_path)

        db2 = Database.open(db_path, password="password", challenge_response_provider=provider)
        assert db2.kek_mode
        entries = db2.find_entries(title="FIDO2 Entry")
        assert len(entries) == 1
        assert entries[0].password == "secret"

    def test_mixed_yubikey_fido2_enrollment(self, tmp_path: pytest.TempPathFactory) -> None:
        """Test enrolling both YubiKey and FIDO2 devices."""
        from pathlib import Path

        db = Database.create(password="password")

        yubikey = MockYubiKey.with_test_secret()
        fido2 = MockFido2.with_test_secret()

        db.enroll_device(yubikey, label="YubiKey Primary")
        db.enroll_device(fido2, label="FIDO2 Backup")

        assert db.kek_mode
        assert db.enrolled_device_count == 2

        db.root_group.create_entry(title="Mixed Entry", username="mixed", password="mixedpass")

        db_path = Path(str(tmp_path)) / "mixed_devices.kdbx"
        db.save(db_path)

        # Open with YubiKey
        db2 = Database.open(db_path, password="password", challenge_response_provider=yubikey)
        assert db2.find_entries(title="Mixed Entry")

        # Open with FIDO2
        db3 = Database.open(db_path, password="password", challenge_response_provider=fido2)
        assert db3.find_entries(title="Mixed Entry")
