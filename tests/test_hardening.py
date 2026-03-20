"""Tests for challenge-response / KEK hardening plan.

Covers:
- Issue 1: _apply_encryption_config preserves header fields (mutation)
- Issue 2: kdf_salt regenerated on save in KEK mode
- Issue 3: HKDF-based derive_final_key (covered in test_kek.py)
- Issue 4: revoke_device requires rotation
- Issue 5: Unified enroll_device with mode selection
- Issue 6: ExperimentalWarning on KEK enrollment
- Issue 7: require_device_on_save
- Issue 8: Cross-application compatibility
"""

import warnings
from pathlib import Path

import pytest

from kdbxtool import AuthenticationError, Database, DatabaseError
from kdbxtool.exceptions import ExperimentalWarning
from kdbxtool.security import Argon2Config
from kdbxtool.security.kek import (
    CR_DEVICE_PREFIX,
    CR_SALT_KEY,
    CR_VERSION_KEY,
    VERSION_COMPAT,
)
from kdbxtool.testing import MockFido2, MockYubiKey

pytestmark = pytest.mark.filterwarnings("ignore::kdbxtool.exceptions.ExperimentalWarning")


# --- Issue 1: _apply_encryption_config preserves header fields ---


class TestHeaderMutationPreservesEnrollment:
    """Verify that KDF config changes mutate the header in place."""

    def test_kdf_change_preserves_enrolled_devices(self, tmp_path: Path) -> None:
        """Enroll device -> save with kdf_config change -> reload -> verify."""
        db = Database.create(password="password")
        provider = MockYubiKey.with_test_secret()
        db.enroll_device(provider, label="Primary", mode="kek")

        db.root_group.create_entry(title="Secret", password="value")

        db_path = tmp_path / "kdf_change.kdbx"
        # Save with a different KDF config
        db.save(db_path, kdf_config=Argon2Config.fast())

        # Reload and verify KEK mode + device count preserved
        db2 = Database.open(db_path, password="password", challenge_response_provider=provider)
        assert db2.kek_mode
        assert db2.enrolled_device_count == 1
        assert db2.find_entries(title="Secret")[0].password == "value"

    def test_kdf_change_preserves_multiple_devices(self, tmp_path: Path) -> None:
        """Multiple enrolled devices survive KDF config change."""
        db = Database.create(password="password")
        p1 = MockYubiKey.with_secret(b"secret_one_here__20!")
        p2 = MockYubiKey.with_secret(b"secret_two_here__20!")

        db.enroll_device(p1, label="Primary", mode="kek")
        db.enroll_device(p2, label="Backup", mode="kek")

        db_path = tmp_path / "multi_kdf.kdbx"
        db.save(db_path, kdf_config=Argon2Config.fast())

        # Both devices should still work
        db2 = Database.open(db_path, password="password", challenge_response_provider=p1)
        assert db2.enrolled_device_count == 2

        db3 = Database.open(db_path, password="password", challenge_response_provider=p2)
        assert db3.enrolled_device_count == 2

    def test_cipher_change_preserves_enrollment(self, tmp_path: Path) -> None:
        """Cipher-only change also preserves enrollment."""
        from kdbxtool import Cipher

        db = Database.create(password="password")
        provider = MockYubiKey.with_test_secret()
        db.enroll_device(provider, label="Primary", mode="kek")

        db_path = tmp_path / "cipher_change.kdbx"
        db.save(db_path, cipher=Cipher.CHACHA20)

        db2 = Database.open(db_path, password="password", challenge_response_provider=provider)
        assert db2.kek_mode
        assert db2.enrolled_device_count == 1


# --- Issue 2: kdf_salt regeneration in KEK mode ---


class TestKdfSaltRegenerationInKekMode:
    """Verify kdf_salt is regenerated on every save, even in KEK mode."""

    def test_kdf_salt_changes_on_save(self, tmp_path: Path) -> None:
        """Save KEK DB twice -> verify different kdf_salt."""
        db = Database.create(password="password")
        provider = MockYubiKey.with_test_secret()
        db.enroll_device(provider, label="Primary", mode="kek")

        db_path = tmp_path / "salt_test.kdbx"
        db.save(db_path)

        # Capture salt after first save
        db2 = Database.open(db_path, password="password", challenge_response_provider=provider)
        salt1 = db2._header.kdf_salt

        # Save again
        db2.save(db_path)

        # Reopen and check salt changed
        db3 = Database.open(db_path, password="password", challenge_response_provider=provider)
        salt2 = db3._header.kdf_salt

        assert salt1 != salt2, "kdf_salt should change on each save"

    def test_cr_salt_stable_across_saves(self, tmp_path: Path) -> None:
        """Verify cr_salt remains stable across saves (not kdf_salt)."""
        db = Database.create(password="password")
        provider = MockYubiKey.with_test_secret()
        db.enroll_device(provider, label="Primary", mode="kek")

        db_path = tmp_path / "cr_salt_test.kdbx"
        db.save(db_path)

        db2 = Database.open(db_path, password="password", challenge_response_provider=provider)
        cr_salt1 = db2._header.public_custom_data.get(CR_SALT_KEY)

        db2.save(db_path)

        db3 = Database.open(db_path, password="password", challenge_response_provider=provider)
        cr_salt2 = db3._header.public_custom_data.get(CR_SALT_KEY)

        assert cr_salt1 == cr_salt2, "cr_salt should be stable across saves"

    def test_kek_mode_roundtrip_after_kdf_salt_regen(self, tmp_path: Path) -> None:
        """Reopen with device + password after kdf_salt regen -> verify decryption."""
        db = Database.create(password="password")
        provider = MockYubiKey.with_test_secret()
        db.enroll_device(provider, label="Primary", mode="kek")
        db.root_group.create_entry(title="Secret", password="value")

        db_path = tmp_path / "regen_roundtrip.kdbx"
        db.save(db_path)
        db2 = Database.open(db_path, password="password", challenge_response_provider=provider)
        db2.save(db_path)  # kdf_salt regenerated
        db3 = Database.open(db_path, password="password", challenge_response_provider=provider)

        assert db3.find_entries(title="Secret")[0].password == "value"


# --- Issue 4: revoke_device requires rotation ---


class TestRevokeDeviceRequiresRotation:
    """Verify revoke_device performs KEK rotation."""

    def test_revoke_with_rotation(self, tmp_path: Path) -> None:
        """Revoke with remaining providers -> verify rotation occurred."""
        db = Database.create(password="password")
        p1 = MockYubiKey.with_secret(b"secret_one_here__20!")
        p2 = MockYubiKey.with_secret(b"secret_two_here__20!")

        db.enroll_device(p1, label="Primary", mode="kek")
        db.enroll_device(p2, label="Backup", mode="kek")

        old_kek = db._kek.data

        db.revoke_device("Primary", remaining_providers={"Backup": p2})

        # KEK should have changed (rotation occurred)
        assert db._kek.data != old_kek
        assert db.enrolled_device_count == 1

    def test_old_device_cannot_decrypt_after_revoke(self, tmp_path: Path) -> None:
        """Old device can't decrypt after revocation + rotation."""
        db = Database.create(password="password")
        revoked = MockYubiKey.with_secret(b"revoked_secret___20!")
        keeper = MockYubiKey.with_secret(b"keeper_secret____20!")

        db.enroll_device(revoked, label="Revoked", mode="kek")
        db.enroll_device(keeper, label="Keeper", mode="kek")
        db.root_group.create_entry(title="Secret", password="value")

        db_path = tmp_path / "revoke_test.kdbx"
        db.save(db_path)

        # Revoke and save
        db2 = Database.open(db_path, password="password", challenge_response_provider=keeper)
        db2.revoke_device("Revoked", remaining_providers={"Keeper": keeper})
        db2.save(db_path)

        # Old device cannot open
        with pytest.raises(AuthenticationError):
            Database.open(db_path, password="password", challenge_response_provider=revoked)

        # Keeper can still open
        db3 = Database.open(db_path, password="password", challenge_response_provider=keeper)
        assert db3.find_entries(title="Secret")[0].password == "value"

    def test_revoke_rejects_revoked_label_in_remaining(self) -> None:
        """Cannot include the revoked device in remaining_providers."""
        db = Database.create(password="password")
        p1 = MockYubiKey.with_secret(b"secret_one_here__20!")
        p2 = MockYubiKey.with_secret(b"secret_two_here__20!")

        db.enroll_device(p1, label="A", mode="kek")
        db.enroll_device(p2, label="B", mode="kek")

        with pytest.raises(ValueError, match="Cannot include revoked device"):
            db.revoke_device("A", remaining_providers={"A": p1})

    def test_revoke_empty_remaining_fails(self) -> None:
        """Revoke with no remaining providers fails."""
        db = Database.create(password="password")
        p1 = MockYubiKey.with_test_secret()
        db.enroll_device(p1, label="Primary", mode="kek")

        with pytest.raises(ValueError, match="At least one remaining provider"):
            db.revoke_device("Primary", remaining_providers={})


# --- Issue 5: Unified enroll_device with mode selection ---


class TestEnrollDeviceModeSelection:
    """Verify auto-detection and explicit mode selection."""

    def test_auto_mode_single_yubikey_selects_compat(self) -> None:
        """Auto mode with single YubiKey HMAC-SHA1 selects compat."""
        db = Database.create(password="password")
        provider = MockYubiKey.with_test_secret()
        db.enroll_device(provider, label="Primary")  # mode="auto" default

        assert not db.kek_mode
        # Should have VERSION_COMPAT in public_custom_data
        assert db._header.public_custom_data.get(CR_VERSION_KEY) == VERSION_COMPAT

    def test_auto_mode_fido2_selects_kek(self) -> None:
        """Auto mode with FIDO2 provider selects KEK."""
        db = Database.create(password="password")
        provider = MockFido2.with_test_secret()
        db.enroll_device(provider, label="FIDO2 Key")  # auto -> kek

        assert db.kek_mode

    def test_auto_mode_second_device_selects_kek(self) -> None:
        """Auto mode for second enrollment selects KEK."""
        db = Database.create(password="password")
        p1 = MockYubiKey.with_secret(b"secret_one_here__20!")
        p2 = MockYubiKey.with_secret(b"secret_two_here__20!")

        # First goes compat (auto, single YubiKey)
        # But we can't add a second device in compat mode via auto...
        # First device must be KEK to add second
        db.enroll_device(p1, label="Primary", mode="kek")
        db.enroll_device(p2, label="Backup")  # auto -> kek (already in KEK mode)

        assert db.kek_mode
        assert db.enrolled_device_count == 2

    def test_explicit_compat_mode(self, tmp_path: Path) -> None:
        """Explicit compat mode works for YubiKey."""
        db = Database.create(password="password")
        provider = MockYubiKey.with_test_secret()
        db.enroll_device(provider, label="Primary", mode="compat")

        assert not db.kek_mode
        assert db._header.public_custom_data.get(CR_VERSION_KEY) == VERSION_COMPAT

        # Should be openable with the provider
        db_path = tmp_path / "compat.kdbx"
        db.save(db_path)
        db2 = Database.open(db_path, password="password", challenge_response_provider=provider)
        assert not db2.kek_mode

    def test_explicit_kek_mode(self) -> None:
        """Explicit kek mode works even for single YubiKey."""
        db = Database.create(password="password")
        provider = MockYubiKey.with_test_secret()
        db.enroll_device(provider, label="Primary", mode="kek")

        assert db.kek_mode
        assert db.enrolled_device_count == 1

    def test_compat_mode_fido2_rejected(self) -> None:
        """Compat mode rejects FIDO2 providers."""
        db = Database.create(password="password")
        provider = MockFido2.with_test_secret()

        with pytest.raises(ValueError, match="FIDO2.*not supported in compat"):
            db.enroll_device(provider, label="FIDO2", mode="compat")

    def test_compat_mode_with_existing_kek_rejected(self) -> None:
        """Compat mode rejected when KEK devices already enrolled."""
        db = Database.create(password="password")
        p1 = MockYubiKey.with_test_secret()
        db.enroll_device(p1, label="Primary", mode="kek")

        p2 = MockYubiKey.with_secret(b"another_secret___20!")
        with pytest.raises(ValueError, match="Cannot use compat mode"):
            db.enroll_device(p2, label="Second", mode="compat")

    def test_compat_mode_second_device_rejected(self) -> None:
        """Compat mode rejects second device enrollment."""
        db = Database.create(password="password")
        p1 = MockYubiKey.with_test_secret()
        db.enroll_device(p1, label="Primary", mode="compat")

        p2 = MockYubiKey.with_secret(b"another_secret___20!")
        with pytest.raises(ValueError, match="Only one device.*compat"):
            db.enroll_device(p2, label="Second", mode="compat")

    def test_auto_mode_existing_compat_rejects_second(self) -> None:
        """Auto mode on existing compat DB rejects second enrollment."""
        db = Database.create(password="password")
        p1 = MockYubiKey.with_test_secret()
        db.enroll_device(p1, label="Primary", mode="compat")

        p2 = MockYubiKey.with_secret(b"another_secret___20!")
        with pytest.raises(ValueError, match="KeePassXC-compatible"):
            db.enroll_device(p2, label="Second")  # auto mode


# --- Issue 6: ExperimentalWarning ---


class TestExperimentalWarning:
    """Verify ExperimentalWarning emitted on first KEK enrollment."""

    @pytest.mark.filterwarnings("default::kdbxtool.exceptions.ExperimentalWarning")
    def test_warning_emitted_on_kek_enrollment(self) -> None:
        """ExperimentalWarning emitted when entering KEK mode."""
        db = Database.create(password="password")
        provider = MockYubiKey.with_test_secret()

        with pytest.warns(ExperimentalWarning, match="experimental"):
            db.enroll_device(provider, label="Primary", mode="kek")

    @pytest.mark.filterwarnings("default::kdbxtool.exceptions.ExperimentalWarning")
    def test_warning_not_emitted_on_compat(self) -> None:
        """No ExperimentalWarning for compat mode."""
        db = Database.create(password="password")
        provider = MockYubiKey.with_test_secret()

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            db.enroll_device(provider, label="Primary", mode="compat")
            experimental_warnings = [x for x in w if issubclass(x.category, ExperimentalWarning)]
            assert len(experimental_warnings) == 0

    def test_warning_filterable(self) -> None:
        """ExperimentalWarning can be filtered."""
        db = Database.create(password="password")
        provider = MockYubiKey.with_test_secret()

        with warnings.catch_warnings(record=True) as w:
            warnings.filterwarnings("ignore", category=ExperimentalWarning)
            db.enroll_device(provider, label="Primary", mode="kek")
            experimental_warnings = [x for x in w if issubclass(x.category, ExperimentalWarning)]
            assert len(experimental_warnings) == 0

    def test_is_user_warning_subclass(self) -> None:
        """ExperimentalWarning is a UserWarning subclass."""
        assert issubclass(ExperimentalWarning, UserWarning)


# --- Issue 7: require_device_on_save ---


class TestRequireDeviceOnSave:
    """Verify opt-in device verification on save."""

    def test_correct_device_passes(self, tmp_path: Path) -> None:
        """Correct device passes verification."""
        db = Database.create(password="password")
        provider = MockYubiKey.with_test_secret()
        db.enroll_device(provider, label="Primary", mode="kek")
        db.root_group.create_entry(title="Secret", password="value")

        db_path = tmp_path / "verify.kdbx"
        # Should not raise
        db.save(db_path, require_device_on_save=provider)

        # Verify data was saved
        db2 = Database.open(db_path, password="password", challenge_response_provider=provider)
        assert db2.find_entries(title="Secret")[0].password == "value"

    def test_wrong_device_fails(self, tmp_path: Path) -> None:
        """Wrong device fails verification."""
        db = Database.create(password="password")
        correct = MockYubiKey.with_test_secret()
        wrong = MockYubiKey.with_secret(b"wrong_secret_here!!!")

        db.enroll_device(correct, label="Primary", mode="kek")

        db_path = tmp_path / "verify_fail.kdbx"
        with pytest.raises(AuthenticationError, match="verification failed"):
            db.save(db_path, require_device_on_save=wrong)

    def test_no_verification_without_flag(self, tmp_path: Path) -> None:
        """Save works without require_device_on_save (default behavior)."""
        db = Database.create(password="password")
        provider = MockYubiKey.with_test_secret()
        db.enroll_device(provider, label="Primary", mode="kek")

        db_path = tmp_path / "no_verify.kdbx"
        # Should not raise
        db.save(db_path)

    def test_ignored_for_non_kek_mode(self, tmp_path: Path) -> None:
        """require_device_on_save is ignored for non-KEK mode databases."""
        db = Database.create(password="password")
        provider = MockYubiKey.with_test_secret()

        db_path = tmp_path / "not_kek.kdbx"
        # Should not raise even though provider is given -- not in KEK mode
        db.save(db_path, require_device_on_save=provider)

    def test_to_bytes_also_verifies(self) -> None:
        """to_bytes also supports require_device_on_save."""
        db = Database.create(password="password")
        correct = MockYubiKey.with_test_secret()
        wrong = MockYubiKey.with_secret(b"wrong_secret_here!!!")

        db.enroll_device(correct, label="Primary", mode="kek")

        # Correct device
        data = db.to_bytes(require_device_on_save=correct)
        assert len(data) > 0

        # Wrong device
        with pytest.raises(AuthenticationError, match="verification failed"):
            db.to_bytes(require_device_on_save=wrong)


# --- Issue 8: Cross-application compatibility ---


class TestCrossApplicationCompatibility:
    """Verify KDBX4 header integrity and mode interop."""

    def test_kdbxtool_custom_keys_dont_corrupt_header(self, tmp_path: Path) -> None:
        """KDBXTOOL_* custom data keys don't corrupt KDBX4 header."""
        db = Database.create(password="password")
        provider = MockYubiKey.with_test_secret()
        db.enroll_device(provider, label="Primary", mode="kek")

        db.root_group.create_entry(title="Test", password="value")

        db_path = tmp_path / "custom_keys.kdbx"
        db.save(db_path)

        # Read raw file and re-parse to verify header integrity
        data = db_path.read_bytes()
        from kdbxtool.parsing.header import KdbxHeader

        header, _ = KdbxHeader.parse(data)

        # Verify custom data keys are present
        assert CR_VERSION_KEY in header.public_custom_data
        assert CR_SALT_KEY in header.public_custom_data
        device_keys = [k for k in header.public_custom_data if k.startswith(CR_DEVICE_PREFIX)]
        assert len(device_keys) == 1

        # Verify standard header fields are intact
        assert header.master_seed is not None and len(header.master_seed) == 32
        assert header.kdf_salt is not None and len(header.kdf_salt) == 32
        assert header.encryption_iv is not None

        # Can re-serialize header without error
        header.to_bytes()

    def test_compat_mode_produces_kepassxc_compatible_structure(self, tmp_path: Path) -> None:
        """Compat mode stores VERSION_COMPAT and uses standard CR mixing."""
        db = Database.create(password="password")
        provider = MockYubiKey.with_test_secret()
        db.enroll_device(provider, label="Primary", mode="compat")

        db_path = tmp_path / "compat_structure.kdbx"
        db.save(db_path)

        # Parse header and verify structure
        data = db_path.read_bytes()
        from kdbxtool.parsing.header import KdbxHeader

        header, _ = KdbxHeader.parse(data)

        # Should have VERSION_COMPAT marker
        assert header.public_custom_data.get(CR_VERSION_KEY) == VERSION_COMPAT
        # Should NOT have KEK-specific keys
        assert CR_SALT_KEY not in header.public_custom_data
        device_keys = [k for k in header.public_custom_data if k.startswith(CR_DEVICE_PREFIX)]
        assert len(device_keys) == 0

    def test_kek_mode_fails_gracefully_without_device(self, tmp_path: Path) -> None:
        """KEK-mode DBs fail with clear error when opened without device."""
        db = Database.create(password="password")
        provider = MockYubiKey.with_test_secret()
        db.enroll_device(provider, label="Primary", mode="kek")
        db.root_group.create_entry(title="Secret", password="value")

        db_path = tmp_path / "kek_no_device.kdbx"
        db.save(db_path)

        # Should give clear error, not crash
        with pytest.raises(DatabaseError, match="requires challenge-response"):
            Database.open(db_path, password="password")

    def test_kek_mode_wrong_password_clear_error(self, tmp_path: Path) -> None:
        """KEK-mode DB with wrong password gives AuthenticationError, not crash."""
        db = Database.create(password="correct")
        provider = MockYubiKey.with_test_secret()
        db.enroll_device(provider, label="Primary", mode="kek")

        db_path = tmp_path / "kek_wrong_pw.kdbx"
        db.save(db_path)

        with pytest.raises(AuthenticationError):
            Database.open(db_path, password="wrong", challenge_response_provider=provider)

    def test_password_only_roundtrip_unaffected_by_kek_code(self, tmp_path: Path) -> None:
        """Password-only database is unaffected by KEK infrastructure."""
        db = Database.create(password="password")
        db.root_group.create_entry(title="Test", password="value")

        db_path = tmp_path / "pw_only.kdbx"
        db.save(db_path)

        db2 = Database.open(db_path, password="password")
        assert not db2.kek_mode
        assert db2.enrolled_device_count == 0
        assert db2.find_entries(title="Test")[0].password == "value"

        # No KDBXTOOL_* keys in header
        for key in db2._header.public_custom_data:
            assert not key.startswith("KDBXTOOL_"), f"Unexpected key: {key}"
