"""Tests for KEK (Key Encryption Key) wrapping module."""

import pytest

from kdbxtool.security.kek import (
    CR_DEVICE_PREFIX,
    CR_SALT_KEY,
    CR_VERSION_KEY,
    HKDF_INFO_KEK_WRAP,
    MIN_CR_RESPONSE_LENGTH,
    VERSION_KEK,
    VERSION_LEGACY,
    WRAPPED_KEK_SIZE,
    EnrolledDevice,
    _hkdf_sha256,
    derive_final_key,
    deserialize_device_entry,
    generate_kek,
    generate_salt,
    get_device_key_name,
    parse_device_key_name,
    serialize_device_entry,
    unwrap_kek,
    wrap_kek,
)
from kdbxtool.security.memory import SecureBytes


class TestHkdfSha256:
    """Tests for HKDF-SHA256 key derivation with domain separation."""

    def test_deterministic_output(self) -> None:
        """Test that HKDF produces consistent output for same inputs."""
        ikm = b"input_keying_material"
        info = b"domain_info"

        result1 = _hkdf_sha256(ikm, info)
        result2 = _hkdf_sha256(ikm, info)

        assert result1 == result2
        assert len(result1) == 32

    def test_different_info_produces_different_keys(self) -> None:
        """Test that different info values produce different keys (domain separation)."""
        ikm = b"same_input_keying_material"
        info1 = b"kdbxtool-kek-wrap-v1"
        info2 = b"some-other-purpose"

        key1 = _hkdf_sha256(ikm, info1)
        key2 = _hkdf_sha256(ikm, info2)

        assert key1 != key2

    def test_different_ikm_produces_different_keys(self) -> None:
        """Test that different IKM produces different keys."""
        info = b"same_info"
        ikm1 = b"input1"
        ikm2 = b"input2"

        key1 = _hkdf_sha256(ikm1, info)
        key2 = _hkdf_sha256(ikm2, info)

        assert key1 != key2

    def test_custom_length(self) -> None:
        """Test HKDF with custom output length."""
        ikm = b"input"
        info = b"info"

        key16 = _hkdf_sha256(ikm, info, length=16)
        key32 = _hkdf_sha256(ikm, info, length=32)

        assert len(key16) == 16
        assert len(key32) == 32
        # First 16 bytes should match
        assert key16 == key32[:16]

    def test_length_exceeds_max_raises(self) -> None:
        """Test that requesting more than 32 bytes raises ValueError."""
        with pytest.raises(ValueError, match="cannot exceed 32 bytes"):
            _hkdf_sha256(b"ikm", b"info", length=33)

    def test_salt_affects_output(self) -> None:
        """Test that different salts produce different keys."""
        ikm = b"input"
        info = b"info"

        key1 = _hkdf_sha256(ikm, info, salt=b"salt1" + b"\x00" * 27)
        key2 = _hkdf_sha256(ikm, info, salt=b"salt2" + b"\x00" * 27)

        assert key1 != key2

    def test_kek_wrap_info_constant(self) -> None:
        """Test that the KEK wrap info constant is set correctly."""
        assert HKDF_INFO_KEK_WRAP == b"kdbxtool-kek-wrap-v1"


class TestConstants:
    """Tests for KEK module constants."""

    def test_version_constants(self) -> None:
        """Test version constant values."""
        assert VERSION_LEGACY == b"\x01"
        assert VERSION_KEK == b"\x02"

    def test_custom_data_keys(self) -> None:
        """Test CustomData key constants."""
        assert CR_VERSION_KEY == "KDBXTOOL_CR_VERSION"
        assert CR_SALT_KEY == "KDBXTOOL_CR_SALT"
        assert CR_DEVICE_PREFIX == "KDBXTOOL_CR_DEVICE_"

    def test_wrapped_kek_size(self) -> None:
        """Test wrapped KEK size constant."""
        # nonce (16, PyCryptodome default) + tag (16) + ciphertext (32) = 64
        assert WRAPPED_KEK_SIZE == 64


class TestGenerateKek:
    """Tests for generate_kek function."""

    def test_returns_secure_bytes(self) -> None:
        """Test that generate_kek returns SecureBytes."""
        kek = generate_kek()
        assert isinstance(kek, SecureBytes)

    def test_returns_32_bytes(self) -> None:
        """Test that KEK is 32 bytes."""
        kek = generate_kek()
        assert len(kek.data) == 32

    def test_unique_keks(self) -> None:
        """Test that each call generates a unique KEK."""
        keks = [generate_kek().data for _ in range(10)]
        # All should be unique
        assert len(set(keks)) == 10


class TestGenerateSalt:
    """Tests for generate_salt function."""

    def test_returns_bytes(self) -> None:
        """Test that generate_salt returns bytes."""
        salt = generate_salt()
        assert isinstance(salt, bytes)

    def test_returns_32_bytes(self) -> None:
        """Test that salt is 32 bytes."""
        salt = generate_salt()
        assert len(salt) == 32

    def test_unique_salts(self) -> None:
        """Test that each call generates a unique salt."""
        salts = [generate_salt() for _ in range(10)]
        assert len(set(salts)) == 10


class TestWrapUnwrapKek:
    """Tests for wrap_kek and unwrap_kek functions."""

    def test_basic_wrap_unwrap(self) -> None:
        """Test basic wrap and unwrap cycle."""
        kek = b"x" * 32
        cr_response = b"y" * 20  # YubiKey HMAC-SHA1 size

        wrapped = wrap_kek(kek, cr_response)
        unwrapped = unwrap_kek(wrapped, cr_response)

        assert unwrapped.data == kek

    def test_wrap_returns_correct_size(self) -> None:
        """Test that wrap_kek returns 64 bytes (nonce 16 + tag 16 + ciphertext 32)."""
        kek = b"k" * 32
        cr_response = b"r" * 20

        wrapped = wrap_kek(kek, cr_response)
        assert len(wrapped) == WRAPPED_KEK_SIZE

    def test_unwrap_returns_secure_bytes(self) -> None:
        """Test that unwrap_kek returns SecureBytes."""
        kek = b"k" * 32
        cr_response = b"r" * 32  # FIDO2 size

        wrapped = wrap_kek(kek, cr_response)
        unwrapped = unwrap_kek(wrapped, cr_response)

        assert isinstance(unwrapped, SecureBytes)

    def test_wrap_with_yubikey_response(self) -> None:
        """Test wrap/unwrap with 20-byte YubiKey HMAC-SHA1 response."""
        kek = b"k" * 32
        cr_response = b"r" * 20

        wrapped = wrap_kek(kek, cr_response)
        unwrapped = unwrap_kek(wrapped, cr_response)

        assert unwrapped.data == kek

    def test_wrap_with_fido2_response(self) -> None:
        """Test wrap/unwrap with 32-byte FIDO2 response."""
        kek = b"k" * 32
        cr_response = b"r" * 32

        wrapped = wrap_kek(kek, cr_response)
        unwrapped = unwrap_kek(wrapped, cr_response)

        assert unwrapped.data == kek

    def test_different_responses_produce_different_wrappings(self) -> None:
        """Test that different CR responses produce different wrapped KEKs."""
        kek = b"k" * 32
        response1 = b"a" * 32
        response2 = b"b" * 32

        wrapped1 = wrap_kek(kek, response1)
        wrapped2 = wrap_kek(kek, response2)

        # Different responses = different wrappings
        assert wrapped1 != wrapped2

    def test_unwrap_with_wrong_response_fails(self) -> None:
        """Test that unwrap fails with wrong CR response."""
        kek = b"k" * 32
        correct_response = b"a" * 32
        wrong_response = b"b" * 32

        wrapped = wrap_kek(kek, correct_response)

        with pytest.raises(ValueError, match="KEK decryption failed"):
            unwrap_kek(wrapped, wrong_response)

    def test_unwrap_with_corrupted_data_fails(self) -> None:
        """Test that unwrap fails with corrupted wrapped data."""
        kek = b"k" * 32
        cr_response = b"r" * 32

        wrapped = wrap_kek(kek, cr_response)
        # Corrupt the ciphertext
        corrupted = wrapped[:30] + b"\xff" + wrapped[31:]

        with pytest.raises(ValueError, match="KEK decryption failed"):
            unwrap_kek(corrupted, cr_response)

    def test_wrap_kek_wrong_size_fails(self) -> None:
        """Test that wrap_kek rejects wrong KEK size."""
        with pytest.raises(ValueError, match="KEK must be 32 bytes"):
            wrap_kek(b"short", b"r" * 32)

    def test_unwrap_kek_wrong_size_fails(self) -> None:
        """Test that unwrap_kek rejects wrong wrapped size."""
        with pytest.raises(ValueError, match="Invalid wrapped KEK length"):
            unwrap_kek(b"short", b"r" * 32)

    def test_each_wrap_has_unique_nonce(self) -> None:
        """Test that each wrap operation uses a unique nonce."""
        kek = b"k" * 32
        cr_response = b"r" * 32

        # Wrap same KEK multiple times
        wrapped1 = wrap_kek(kek, cr_response)
        wrapped2 = wrap_kek(kek, cr_response)

        # Nonces (first 16 bytes, PyCryptodome default) should differ
        assert wrapped1[:16] != wrapped2[:16]

        # Both should unwrap to same KEK
        assert unwrap_kek(wrapped1, cr_response).data == kek
        assert unwrap_kek(wrapped2, cr_response).data == kek

    def test_wrap_rejects_short_cr_response(self) -> None:
        """Test that wrap_kek rejects CR responses shorter than minimum."""
        kek = b"k" * 32
        short_response = b"x" * (MIN_CR_RESPONSE_LENGTH - 1)

        with pytest.raises(ValueError, match="CR response too short"):
            wrap_kek(kek, short_response)

    def test_unwrap_rejects_short_cr_response(self) -> None:
        """Test that unwrap_kek rejects CR responses shorter than minimum."""
        # Create a valid wrapped KEK first
        kek = b"k" * 32
        valid_response = b"r" * 20
        wrapped = wrap_kek(kek, valid_response)

        # Try to unwrap with too-short response
        short_response = b"x" * (MIN_CR_RESPONSE_LENGTH - 1)
        with pytest.raises(ValueError, match="CR response too short"):
            unwrap_kek(wrapped, short_response)

    def test_wrap_accepts_minimum_length_response(self) -> None:
        """Test that wrap_kek accepts exactly minimum length CR response."""
        kek = b"k" * 32
        min_response = b"x" * MIN_CR_RESPONSE_LENGTH

        # Should not raise
        wrapped = wrap_kek(kek, min_response)
        assert len(wrapped) == WRAPPED_KEK_SIZE

        # Should be able to unwrap
        unwrapped = unwrap_kek(wrapped, min_response)
        assert unwrapped.data == kek

    def test_min_cr_response_length_constant(self) -> None:
        """Test that minimum CR response length is 16 bytes (128 bits)."""
        assert MIN_CR_RESPONSE_LENGTH == 16

    def test_unwrap_truncated_at_nonce_boundary(self) -> None:
        """Test that unwrap fails when truncated within nonce (first 16 bytes)."""
        with pytest.raises(ValueError, match="Invalid wrapped KEK length"):
            unwrap_kek(b"x" * 15, b"r" * 20)  # Truncated nonce

    def test_unwrap_truncated_at_tag_boundary(self) -> None:
        """Test that unwrap fails when truncated within tag (bytes 16-32)."""
        with pytest.raises(ValueError, match="Invalid wrapped KEK length"):
            unwrap_kek(b"x" * 20, b"r" * 20)  # Has nonce but truncated tag

    def test_unwrap_truncated_at_ciphertext_boundary(self) -> None:
        """Test that unwrap fails when truncated within ciphertext (bytes 32-64)."""
        with pytest.raises(ValueError, match="Invalid wrapped KEK length"):
            unwrap_kek(b"x" * 40, b"r" * 20)  # Has nonce+tag but truncated ciphertext

    def test_wrap_with_very_long_cr_response(self) -> None:
        """Test that wrap/unwrap works with very long CR responses."""
        kek = b"k" * 32
        # 1KB response - much longer than typical
        long_response = b"x" * 1024

        wrapped = wrap_kek(kek, long_response)
        unwrapped = unwrap_kek(wrapped, long_response)

        assert unwrapped.data == kek

    def test_wrap_with_empty_cr_response_fails(self) -> None:
        """Test that wrap_kek rejects empty CR response."""
        kek = b"k" * 32
        with pytest.raises(ValueError, match="CR response too short"):
            wrap_kek(kek, b"")


class TestDeriveFinalKey:
    """Tests for derive_final_key function."""

    def test_basic_derivation(self) -> None:
        """Test basic final key derivation."""
        base = b"b" * 32
        kek = b"k" * 32

        final = derive_final_key(base, kek)
        assert isinstance(final, SecureBytes)
        assert len(final.data) == 32

    def test_xor_operation(self) -> None:
        """Test that derivation is XOR."""
        base = bytes(range(32))
        kek = bytes([0x55] * 32)

        final = derive_final_key(base, kek)

        # Verify XOR
        expected = bytes(a ^ 0x55 for a in range(32))
        assert final.data == expected

    def test_wrong_base_size_fails(self) -> None:
        """Test that wrong base_master_key size fails."""
        with pytest.raises(ValueError, match="base_master_key must be 32 bytes"):
            derive_final_key(b"short", b"k" * 32)

    def test_wrong_kek_size_fails(self) -> None:
        """Test that wrong kek size fails."""
        with pytest.raises(ValueError, match="kek must be 32 bytes"):
            derive_final_key(b"b" * 32, b"short")

    def test_reversible_with_same_kek(self) -> None:
        """Test that XOR is reversible with same KEK."""
        base = b"b" * 32
        kek = b"k" * 32

        final = derive_final_key(base, kek)
        # XOR again to get back base
        recovered = derive_final_key(final.data, kek)

        assert recovered.data == base


class TestEnrolledDevice:
    """Tests for EnrolledDevice dataclass."""

    def test_create_device(self) -> None:
        """Test creating an EnrolledDevice."""
        device = EnrolledDevice(
            device_type="yubikey_hmac",
            label="Primary YubiKey",
            device_id="slot2_serial12345",
        )
        assert device.device_type == "yubikey_hmac"
        assert device.label == "Primary YubiKey"
        assert device.device_id == "slot2_serial12345"
        assert device.metadata == {}
        assert device.wrapped_kek == b""

    def test_create_device_with_metadata(self) -> None:
        """Test creating device with metadata."""
        device = EnrolledDevice(
            device_type="fido2",
            label="Backup FIDO2",
            device_id="cred_abc123",
            metadata={"rp_id": "kdbxtool", "credential_id": "abc123"},
            wrapped_kek=b"wrapped" * 9 + b"w",  # 64 bytes
        )
        assert device.metadata == {"rp_id": "kdbxtool", "credential_id": "abc123"}
        assert len(device.wrapped_kek) == 64

    def test_missing_device_type_fails(self) -> None:
        """Test that missing device_type raises error."""
        with pytest.raises(ValueError, match="device_type is required"):
            EnrolledDevice(device_type="", label="Test", device_id="123")

    def test_missing_label_fails(self) -> None:
        """Test that missing label raises error."""
        with pytest.raises(ValueError, match="label is required"):
            EnrolledDevice(device_type="test", label="", device_id="123")

    def test_missing_device_id_fails(self) -> None:
        """Test that missing device_id raises error."""
        with pytest.raises(ValueError, match="device_id is required"):
            EnrolledDevice(device_type="test", label="Test", device_id="")


class TestSerializeDeserialize:
    """Tests for serialize/deserialize device entry functions."""

    def test_basic_roundtrip(self) -> None:
        """Test basic serialize/deserialize roundtrip."""
        device = EnrolledDevice(
            device_type="yubikey_hmac",
            label="Primary YubiKey",
            device_id="slot2_serial12345",
            wrapped_kek=b"w" * 64,
        )

        serialized = serialize_device_entry(device)
        restored = deserialize_device_entry(serialized)

        assert restored.device_type == device.device_type
        assert restored.label == device.label
        assert restored.device_id == device.device_id
        assert restored.wrapped_kek == device.wrapped_kek

    def test_roundtrip_with_metadata(self) -> None:
        """Test serialize/deserialize with metadata."""
        device = EnrolledDevice(
            device_type="fido2",
            label="Backup FIDO2",
            device_id="cred_abc123",
            metadata={"rp_id": "kdbxtool", "version": 2},
            wrapped_kek=b"x" * 64,
        )

        serialized = serialize_device_entry(device)
        restored = deserialize_device_entry(serialized)

        assert restored.metadata == {"rp_id": "kdbxtool", "version": 2}

    def test_serialized_format(self) -> None:
        """Test serialized format structure."""
        device = EnrolledDevice(
            device_type="test",
            label="Test Device",
            device_id="test123",
            wrapped_kek=b"k" * 64,
        )

        serialized = serialize_device_entry(device)

        # Should have null separator
        assert b"\x00" in serialized

        # JSON should be before null
        null_idx = serialized.index(b"\x00")
        json_part = serialized[:null_idx]
        assert b'"type":"test"' in json_part
        assert b'"label":"Test Device"' in json_part

        # Wrapped KEK should be after null
        kek_part = serialized[null_idx + 1 :]
        assert kek_part == b"k" * 64

    def test_deserialize_missing_null_fails(self) -> None:
        """Test that deserialize fails without null separator."""
        with pytest.raises(ValueError, match="missing null separator"):
            deserialize_device_entry(b"no null here")

    def test_deserialize_bad_json_fails(self) -> None:
        """Test that deserialize fails with bad JSON."""
        # Use correctly-sized wrapped_kek (64 bytes) so we hit JSON parsing error
        with pytest.raises(ValueError, match="bad JSON"):
            deserialize_device_entry(b"not valid json\x00" + b"x" * 64)

    def test_deserialize_bad_wrapped_kek_size_fails(self) -> None:
        """Test that deserialize fails with wrong wrapped_kek size."""
        # Valid JSON but wrong wrapped_kek size
        valid_json = b'{"type":"test","label":"Test","id":"1"}'
        with pytest.raises(ValueError, match=r"Invalid wrapped_kek size: \d+, expected 64"):
            deserialize_device_entry(valid_json + b"\x00" + b"too_short")


class TestDeviceKeyNames:
    """Tests for device key name functions."""

    def test_get_device_key_name(self) -> None:
        """Test getting device key names."""
        assert get_device_key_name(0) == "KDBXTOOL_CR_DEVICE_0"
        assert get_device_key_name(1) == "KDBXTOOL_CR_DEVICE_1"
        assert get_device_key_name(99) == "KDBXTOOL_CR_DEVICE_99"

    def test_parse_device_key_name(self) -> None:
        """Test parsing device key names."""
        assert parse_device_key_name("KDBXTOOL_CR_DEVICE_0") == 0
        assert parse_device_key_name("KDBXTOOL_CR_DEVICE_1") == 1
        assert parse_device_key_name("KDBXTOOL_CR_DEVICE_99") == 99

    def test_parse_non_device_key_returns_none(self) -> None:
        """Test that non-device keys return None."""
        assert parse_device_key_name("OTHER_KEY") is None
        assert parse_device_key_name("KDBXTOOL_CR_VERSION") is None
        assert parse_device_key_name("KDBXTOOL_CR_SALT") is None

    def test_parse_invalid_index_returns_none(self) -> None:
        """Test that invalid indices return None."""
        assert parse_device_key_name("KDBXTOOL_CR_DEVICE_abc") is None
        assert parse_device_key_name("KDBXTOOL_CR_DEVICE_") is None

    def test_get_parse_roundtrip(self) -> None:
        """Test get/parse roundtrip."""
        for i in range(10):
            key_name = get_device_key_name(i)
            parsed = parse_device_key_name(key_name)
            assert parsed == i


class TestMultiDeviceScenario:
    """Integration tests for multi-device scenarios."""

    def test_multiple_devices_same_kek(self) -> None:
        """Test that multiple devices can wrap the same KEK."""
        kek = generate_kek()

        # Simulate two different devices with different CR responses
        response1 = b"device1_cr_response_pad" + b"\x00" * 12  # 32 bytes
        response2 = b"device2_cr_response_pad" + b"\x00" * 12  # 32 bytes

        wrapped1 = wrap_kek(kek.data, response1)
        wrapped2 = wrap_kek(kek.data, response2)

        # Both should unwrap to same KEK
        unwrapped1 = unwrap_kek(wrapped1, response1)
        unwrapped2 = unwrap_kek(wrapped2, response2)

        assert unwrapped1.data == kek.data
        assert unwrapped2.data == kek.data

    def test_add_device_to_existing(self) -> None:
        """Test adding a new device to existing enrollment."""
        # Initial setup with one device
        kek = generate_kek()
        response1 = b"r1" * 16

        wrapped1 = wrap_kek(kek.data, response1)

        # Later, add second device using unwrapped KEK
        unwrapped = unwrap_kek(wrapped1, response1)
        response2 = b"r2" * 16

        wrapped2 = wrap_kek(unwrapped.data, response2)

        # Both should work
        assert unwrap_kek(wrapped1, response1).data == kek.data
        assert unwrap_kek(wrapped2, response2).data == kek.data

    def test_full_encryption_flow(self) -> None:
        """Test complete encryption flow with KEK."""
        # Generate KEK and derive base master from password
        kek = generate_kek()
        base_master = b"x" * 32  # 32 bytes

        # Derive final key
        final = derive_final_key(base_master, kek.data)

        # Wrap KEK for device
        cr_response = b"device_cr_response_32_bytes____"  # 32 bytes
        wrapped = wrap_kek(kek.data, cr_response)

        # Later, unwrap and derive same final key
        unwrapped_kek = unwrap_kek(wrapped, cr_response)
        final2 = derive_final_key(base_master, unwrapped_kek.data)

        assert final.data == final2.data
