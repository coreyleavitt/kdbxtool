"""Tests for cryptographic primitives and utilities."""

import pytest

from kdbxtool import UnknownCipherError
from kdbxtool.security.crypto import (
    Cipher,
    CipherContext,
    compute_hmac_sha256,
    constant_time_compare,
    secure_random_bytes,
    verify_hmac_sha256,
)


class TestConstantTimeCompare:
    """Tests for constant_time_compare function."""

    def test_equal_bytes(self) -> None:
        """Test that equal byte sequences return True."""
        a = b"secret password"
        b = b"secret password"
        assert constant_time_compare(a, b) is True

    def test_unequal_bytes(self) -> None:
        """Test that different byte sequences return False."""
        a = b"secret password"
        b = b"secret passwort"
        assert constant_time_compare(a, b) is False

    def test_different_lengths(self) -> None:
        """Test that different lengths return False."""
        a = b"short"
        b = b"much longer string"
        assert constant_time_compare(a, b) is False

    def test_empty_sequences(self) -> None:
        """Test that empty sequences are equal."""
        assert constant_time_compare(b"", b"") is True

    def test_bytearray_input(self) -> None:
        """Test that bytearrays work correctly."""
        a = bytearray(b"secret")
        b = bytearray(b"secret")
        assert constant_time_compare(a, b) is True

    def test_mixed_types(self) -> None:
        """Test bytes compared to bytearray."""
        a = b"secret"
        b = bytearray(b"secret")
        assert constant_time_compare(a, b) is True


class TestSecureRandomBytes:
    """Tests for secure_random_bytes function."""

    def test_correct_length(self) -> None:
        """Test that correct number of bytes is returned."""
        for length in [0, 1, 16, 32, 64, 1000]:
            result = secure_random_bytes(length)
            assert len(result) == length

    def test_returns_bytes(self) -> None:
        """Test that bytes type is returned."""
        result = secure_random_bytes(16)
        assert isinstance(result, bytes)

    def test_randomness(self) -> None:
        """Test that different calls produce different values."""
        results = [secure_random_bytes(32) for _ in range(100)]
        # All should be unique (collision probability is negligible)
        assert len(set(results)) == 100


class TestHMAC:
    """Tests for HMAC functions."""

    def test_compute_hmac_sha256(self) -> None:
        """Test HMAC-SHA256 computation."""
        key = b"secret key"
        data = b"message to authenticate"
        mac = compute_hmac_sha256(key, data)
        assert len(mac) == 32  # SHA-256 output

    def test_hmac_deterministic(self) -> None:
        """Test that same inputs produce same output."""
        key = b"secret key"
        data = b"message"
        mac1 = compute_hmac_sha256(key, data)
        mac2 = compute_hmac_sha256(key, data)
        assert mac1 == mac2

    def test_hmac_different_keys(self) -> None:
        """Test that different keys produce different MACs."""
        data = b"message"
        mac1 = compute_hmac_sha256(b"key1", data)
        mac2 = compute_hmac_sha256(b"key2", data)
        assert mac1 != mac2

    def test_hmac_different_data(self) -> None:
        """Test that different data produces different MACs."""
        key = b"key"
        mac1 = compute_hmac_sha256(key, b"message1")
        mac2 = compute_hmac_sha256(key, b"message2")
        assert mac1 != mac2

    def test_verify_hmac_sha256_valid(self) -> None:
        """Test verification of valid HMAC."""
        key = b"secret key"
        data = b"message"
        mac = compute_hmac_sha256(key, data)
        assert verify_hmac_sha256(key, data, mac) is True

    def test_verify_hmac_sha256_invalid(self) -> None:
        """Test verification of invalid HMAC."""
        key = b"secret key"
        data = b"message"
        bad_mac = b"\x00" * 32
        assert verify_hmac_sha256(key, data, bad_mac) is False

    def test_verify_hmac_sha256_tampered_data(self) -> None:
        """Test that tampered data fails verification."""
        key = b"secret key"
        original_data = b"original message"
        mac = compute_hmac_sha256(key, original_data)
        tampered_data = b"tampered message"
        assert verify_hmac_sha256(key, tampered_data, mac) is False


class TestCipherEnum:
    """Tests for Cipher enum."""

    def test_aes256_cbc_properties(self) -> None:
        """Test AES-256-CBC cipher properties."""
        cipher = Cipher.AES256_CBC
        assert cipher.key_size == 32
        assert cipher.iv_size == 16
        assert cipher.display_name == "AES-256-CBC"

    def test_chacha20_properties(self) -> None:
        """Test ChaCha20 cipher properties."""
        cipher = Cipher.CHACHA20
        assert cipher.key_size == 32
        assert cipher.iv_size == 12
        assert cipher.display_name == "ChaCha20"

    def test_from_uuid_aes(self) -> None:
        """Test lookup of AES cipher by UUID."""
        uuid = bytes.fromhex("31c1f2e6bf714350be5805216afc5aff")
        cipher = Cipher.from_uuid(uuid)
        assert cipher == Cipher.AES256_CBC

    def test_from_uuid_chacha(self) -> None:
        """Test lookup of ChaCha20 cipher by UUID."""
        uuid = bytes.fromhex("d6038a2b8b6f4cb5a524339a31dbb59a")
        cipher = Cipher.from_uuid(uuid)
        assert cipher == Cipher.CHACHA20

    def test_from_uuid_unknown(self) -> None:
        """Test that unknown UUID raises UnknownCipherError."""
        unknown_uuid = b"\x00" * 16
        with pytest.raises(UnknownCipherError):
            Cipher.from_uuid(unknown_uuid)

    def test_uuid_is_16_bytes(self) -> None:
        """Test that all cipher UUIDs are 16 bytes."""
        for cipher in Cipher:
            assert len(cipher.value) == 16


class TestCipherContext:
    """Tests for CipherContext class."""

    @pytest.fixture
    def aes_key(self) -> bytes:
        """32-byte AES key."""
        return secure_random_bytes(32)

    @pytest.fixture
    def aes_iv(self) -> bytes:
        """16-byte AES IV."""
        return secure_random_bytes(16)

    @pytest.fixture
    def chacha_key(self) -> bytes:
        """32-byte ChaCha20 key."""
        return secure_random_bytes(32)

    @pytest.fixture
    def chacha_nonce(self) -> bytes:
        """12-byte ChaCha20 nonce."""
        return secure_random_bytes(12)

    def test_aes_encrypt_decrypt_roundtrip(self, aes_key: bytes, aes_iv: bytes) -> None:
        """Test AES encryption and decryption roundtrip."""
        # AES-CBC requires block-aligned plaintext (16 bytes)
        plaintext = b"0123456789abcdef" * 4  # 64 bytes
        ctx = CipherContext(Cipher.AES256_CBC, aes_key, aes_iv)
        ciphertext = ctx.encrypt(plaintext)
        # Need new context for decryption (cipher objects are stateful)
        ctx2 = CipherContext(Cipher.AES256_CBC, aes_key, aes_iv)
        decrypted = ctx2.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_chacha_encrypt_decrypt_roundtrip(self, chacha_key: bytes, chacha_nonce: bytes) -> None:
        """Test ChaCha20 encryption and decryption roundtrip."""
        plaintext = b"This is a test message of arbitrary length!"
        ctx = CipherContext(Cipher.CHACHA20, chacha_key, chacha_nonce)
        ciphertext = ctx.encrypt(plaintext)
        # ChaCha20 is a stream cipher - same length output
        assert len(ciphertext) == len(plaintext)
        ctx2 = CipherContext(Cipher.CHACHA20, chacha_key, chacha_nonce)
        decrypted = ctx2.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_chacha_stream_cipher_properties(self, chacha_key: bytes, chacha_nonce: bytes) -> None:
        """Test ChaCha20 stream cipher produces different output per nonce."""
        plaintext = b"Same plaintext for both"
        ctx1 = CipherContext(Cipher.CHACHA20, chacha_key, chacha_nonce)
        ctx2 = CipherContext(Cipher.CHACHA20, chacha_key, b"\x00" * 12)
        ciphertext1 = ctx1.encrypt(plaintext)
        ciphertext2 = ctx2.encrypt(plaintext)
        # Different nonces produce different ciphertext
        assert ciphertext1 != ciphertext2

    def test_invalid_key_size(self, aes_iv: bytes) -> None:
        """Test that wrong key size raises error."""
        bad_key = b"too short"
        with pytest.raises(ValueError, match="requires 32-byte key"):
            CipherContext(Cipher.AES256_CBC, bad_key, aes_iv)

    def test_invalid_iv_size(self, aes_key: bytes) -> None:
        """Test that wrong IV size raises error."""
        bad_iv = b"short"
        with pytest.raises(ValueError, match="requires 16-byte IV"):
            CipherContext(Cipher.AES256_CBC, aes_key, bad_iv)

    def test_invalid_chacha_nonce_size(self, chacha_key: bytes) -> None:
        """Test that wrong nonce size raises error for ChaCha20."""
        bad_nonce = b"too long nonce!!"  # 16 bytes, should be 12
        with pytest.raises(ValueError, match="requires 12-byte IV"):
            CipherContext(Cipher.CHACHA20, chacha_key, bad_nonce)

    def test_aes_ciphertext_different_from_plaintext(self, aes_key: bytes, aes_iv: bytes) -> None:
        """Test that AES ciphertext differs from plaintext."""
        plaintext = b"0123456789abcdef"
        ctx = CipherContext(Cipher.AES256_CBC, aes_key, aes_iv)
        ciphertext = ctx.encrypt(plaintext)
        assert ciphertext != plaintext

    def test_different_keys_produce_different_ciphertext(self, aes_iv: bytes) -> None:
        """Test that different keys produce different ciphertext."""
        plaintext = b"0123456789abcdef"
        key1 = secure_random_bytes(32)
        key2 = secure_random_bytes(32)
        ctx1 = CipherContext(Cipher.AES256_CBC, key1, aes_iv)
        ctx2 = CipherContext(Cipher.AES256_CBC, key2, aes_iv)
        assert ctx1.encrypt(plaintext) != ctx2.encrypt(plaintext)
