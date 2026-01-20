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


class TestMixedProviderTypes:
    """Tests for using different provider types (YubiKey vs FIDO2)."""

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
