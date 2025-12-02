"""Tests for KDBX header parsing."""

import struct

import pytest

from kdbxtool import (
    CorruptedDataError,
    InvalidSignatureError,
    KdfError,
    UnsupportedVersionError,
)
from kdbxtool.parsing.header import (
    KDBX_MAGIC,
    CompressionType,
    HeaderFieldType,
    InnerHeaderFieldType,
    KdbxHeader,
    KdbxVersion,
)
from kdbxtool.security import Cipher, KdfType


class TestKdbxVersion:
    """Tests for KdbxVersion enum."""

    def test_kdbx3_value(self) -> None:
        """Test KDBX3 version value."""
        assert KdbxVersion.KDBX3 == 3

    def test_kdbx4_value(self) -> None:
        """Test KDBX4 version value."""
        assert KdbxVersion.KDBX4 == 4


class TestHeaderFieldType:
    """Tests for HeaderFieldType enum."""

    def test_end_field(self) -> None:
        """Test END field type."""
        assert HeaderFieldType.END == 0

    def test_cipher_id_field(self) -> None:
        """Test CIPHER_ID field type."""
        assert HeaderFieldType.CIPHER_ID == 2

    def test_kdf_parameters_field(self) -> None:
        """Test KDF_PARAMETERS field type."""
        assert HeaderFieldType.KDF_PARAMETERS == 11


class TestInnerHeaderFieldType:
    """Tests for InnerHeaderFieldType enum."""

    def test_end_field(self) -> None:
        """Test END field type."""
        assert InnerHeaderFieldType.END == 0

    def test_binary_field(self) -> None:
        """Test BINARY field type."""
        assert InnerHeaderFieldType.BINARY == 3


class TestCompressionType:
    """Tests for CompressionType enum."""

    def test_none_compression(self) -> None:
        """Test NONE compression value."""
        assert CompressionType.NONE == 0

    def test_gzip_compression(self) -> None:
        """Test GZIP compression value."""
        assert CompressionType.GZIP == 1


class TestKdbxHeaderParsing:
    """Tests for KdbxHeader.parse method."""

    def _build_kdbx4_header(
        self,
        cipher: Cipher = Cipher.AES256_CBC,
        compression: CompressionType = CompressionType.GZIP,
        master_seed: bytes | None = None,
        encryption_iv: bytes | None = None,
        kdf_type: KdfType = KdfType.ARGON2ID,
        kdf_salt: bytes | None = None,
        memory_kib: int = 65536,
        iterations: int = 3,
        parallelism: int = 4,
    ) -> bytes:
        """Build a minimal valid KDBX4 header for testing."""
        parts = []

        # Magic and version
        parts.append(KDBX_MAGIC)
        parts.append(struct.pack("<HH", 1, 4))  # Minor 1, Major 4

        def add_field(field_type: int, data: bytes) -> None:
            parts.append(struct.pack("<BI", field_type, len(data)))
            parts.append(data)

        # Cipher
        add_field(HeaderFieldType.CIPHER_ID, cipher.value)

        # Compression
        add_field(HeaderFieldType.COMPRESSION_FLAGS, struct.pack("<I", compression.value))

        # Master seed
        if master_seed is None:
            master_seed = b"\x00" * 32
        add_field(HeaderFieldType.MASTER_SEED, master_seed)

        # Encryption IV
        if encryption_iv is None:
            encryption_iv = b"\x00" * cipher.iv_size
        add_field(HeaderFieldType.ENCRYPTION_IV, encryption_iv)

        # KDF parameters
        kdf_dict = self._build_variant_dict(
            kdf_type, kdf_salt or b"\x00" * 32, memory_kib, iterations, parallelism
        )
        add_field(HeaderFieldType.KDF_PARAMETERS, kdf_dict)

        # End
        add_field(HeaderFieldType.END, b"\r\n\r\n")

        return b"".join(parts)

    def _build_variant_dict(
        self,
        kdf_type: KdfType,
        salt: bytes,
        memory_kib: int,
        iterations: int,
        parallelism: int,
    ) -> bytes:
        """Build a VariantDictionary for KDF parameters."""
        parts = []
        parts.append(struct.pack("<H", 0x0100))  # Version

        def add_entry(entry_type: int, key: str, value: bytes) -> None:
            key_bytes = key.encode("utf-8")
            parts.append(struct.pack("<B", entry_type))
            parts.append(struct.pack("<I", len(key_bytes)))
            parts.append(key_bytes)
            parts.append(struct.pack("<I", len(value)))
            parts.append(value)

        add_entry(0x42, "$UUID", kdf_type.value)
        add_entry(0x42, "S", salt)
        add_entry(0x05, "M", struct.pack("<Q", memory_kib * 1024))
        add_entry(0x05, "I", struct.pack("<Q", iterations))
        add_entry(0x04, "P", struct.pack("<I", parallelism))
        parts.append(struct.pack("<B", 0x00))  # End

        return b"".join(parts)

    def test_parse_valid_kdbx4_header(self) -> None:
        """Test parsing a valid KDBX4 header."""
        header_data = self._build_kdbx4_header()
        header, consumed = KdbxHeader.parse(header_data)

        assert header.version == KdbxVersion.KDBX4
        assert header.cipher == Cipher.AES256_CBC
        assert header.compression == CompressionType.GZIP
        assert len(header.master_seed) == 32
        assert len(header.encryption_iv) == 16
        assert header.kdf_type == KdfType.ARGON2ID
        assert header.argon2_memory_kib == 65536
        assert header.argon2_iterations == 3
        assert header.argon2_parallelism == 4
        assert consumed > 0

    def test_parse_chacha20_cipher(self) -> None:
        """Test parsing header with ChaCha20 cipher."""
        header_data = self._build_kdbx4_header(
            cipher=Cipher.CHACHA20,
            encryption_iv=b"\x00" * 12,  # 12-byte nonce
        )
        header, _ = KdbxHeader.parse(header_data)
        assert header.cipher == Cipher.CHACHA20
        assert len(header.encryption_iv) == 12

    def test_parse_no_compression(self) -> None:
        """Test parsing header with no compression."""
        header_data = self._build_kdbx4_header(compression=CompressionType.NONE)
        header, _ = KdbxHeader.parse(header_data)
        assert header.compression == CompressionType.NONE

    def test_parse_argon2d_variant(self) -> None:
        """Test parsing header with Argon2d KDF."""
        header_data = self._build_kdbx4_header(kdf_type=KdfType.ARGON2D)
        header, _ = KdbxHeader.parse(header_data)
        assert header.kdf_type == KdfType.ARGON2D

    def test_raw_header_preserved(self) -> None:
        """Test that raw header bytes are preserved."""
        header_data = self._build_kdbx4_header()
        header, consumed = KdbxHeader.parse(header_data)
        assert header.raw_header == header_data[:consumed]

    def test_invalid_magic(self) -> None:
        """Test that invalid magic raises error."""
        bad_data = b"\x00" * 100
        with pytest.raises(InvalidSignatureError):
            KdbxHeader.parse(bad_data)

    def test_data_too_short(self) -> None:
        """Test that short data raises error."""
        with pytest.raises(CorruptedDataError):
            KdbxHeader.parse(b"\x00" * 5)

    def test_missing_cipher_id(self) -> None:
        """Test that missing cipher ID raises error."""
        # Build header without cipher
        parts = []
        parts.append(KDBX_MAGIC)
        parts.append(struct.pack("<HH", 1, 4))
        # Add end without cipher
        parts.append(struct.pack("<BI", HeaderFieldType.END, 4))
        parts.append(b"\r\n\r\n")

        with pytest.raises(CorruptedDataError):
            KdbxHeader.parse(b"".join(parts))

    def test_invalid_master_seed_length(self) -> None:
        """Test that wrong master seed length raises error."""
        parts = []
        parts.append(KDBX_MAGIC)
        parts.append(struct.pack("<HH", 1, 4))
        # Cipher
        parts.append(struct.pack("<BI", HeaderFieldType.CIPHER_ID, 16))
        parts.append(Cipher.AES256_CBC.value)
        # Compression
        parts.append(struct.pack("<BI", HeaderFieldType.COMPRESSION_FLAGS, 4))
        parts.append(struct.pack("<I", CompressionType.GZIP.value))
        # Bad master seed (only 16 bytes)
        parts.append(struct.pack("<BI", HeaderFieldType.MASTER_SEED, 16))
        parts.append(b"\x00" * 16)
        # End
        parts.append(struct.pack("<BI", HeaderFieldType.END, 4))
        parts.append(b"\r\n\r\n")

        with pytest.raises(CorruptedDataError):
            KdbxHeader.parse(b"".join(parts))


class TestKdbxHeaderSerialization:
    """Tests for KdbxHeader.to_bytes method."""

    def test_roundtrip_kdbx4(self) -> None:
        """Test that serialized header can be parsed back."""
        import os

        original = KdbxHeader(
            version=KdbxVersion.KDBX4,
            cipher=Cipher.AES256_CBC,
            compression=CompressionType.GZIP,
            master_seed=os.urandom(32),
            encryption_iv=os.urandom(16),
            kdf_type=KdfType.ARGON2ID,
            kdf_salt=os.urandom(32),
            argon2_memory_kib=65536,
            argon2_iterations=3,
            argon2_parallelism=4,
        )

        serialized = original.to_bytes()
        parsed, _ = KdbxHeader.parse(serialized)

        assert parsed.version == original.version
        assert parsed.cipher == original.cipher
        assert parsed.compression == original.compression
        assert parsed.master_seed == original.master_seed
        assert parsed.encryption_iv == original.encryption_iv
        assert parsed.kdf_type == original.kdf_type
        assert parsed.kdf_salt == original.kdf_salt
        assert parsed.argon2_memory_kib == original.argon2_memory_kib
        assert parsed.argon2_iterations == original.argon2_iterations
        assert parsed.argon2_parallelism == original.argon2_parallelism

    def test_roundtrip_chacha20(self) -> None:
        """Test roundtrip with ChaCha20."""
        import os

        original = KdbxHeader(
            version=KdbxVersion.KDBX4,
            cipher=Cipher.CHACHA20,
            compression=CompressionType.NONE,
            master_seed=os.urandom(32),
            encryption_iv=os.urandom(12),
            kdf_type=KdfType.ARGON2D,
            kdf_salt=os.urandom(32),
            argon2_memory_kib=32768,
            argon2_iterations=5,
            argon2_parallelism=2,
        )

        serialized = original.to_bytes()
        parsed, _ = KdbxHeader.parse(serialized)

        assert parsed.cipher == Cipher.CHACHA20
        assert parsed.kdf_type == KdfType.ARGON2D
        assert parsed.argon2_memory_kib == 32768

    def test_kdbx3_serialization_raises(self) -> None:
        """Test that KDBX3 serialization raises error."""
        header = KdbxHeader(
            version=KdbxVersion.KDBX3,
            cipher=Cipher.AES256_CBC,
            compression=CompressionType.GZIP,
            master_seed=b"\x00" * 32,
            encryption_iv=b"\x00" * 16,
            kdf_type=KdfType.AES_KDF,
            kdf_salt=b"\x00" * 32,
            aes_kdf_rounds=60000,
        )

        with pytest.raises(UnsupportedVersionError):
            header.to_bytes()

    def test_missing_argon2_params_raises(self) -> None:
        """Test that missing Argon2 params raise error."""
        header = KdbxHeader(
            version=KdbxVersion.KDBX4,
            cipher=Cipher.AES256_CBC,
            compression=CompressionType.GZIP,
            master_seed=b"\x00" * 32,
            encryption_iv=b"\x00" * 16,
            kdf_type=KdfType.ARGON2ID,
            kdf_salt=b"\x00" * 32,
            # Missing argon2 parameters
        )

        with pytest.raises(KdfError):
            header.to_bytes()


class TestVariantDictParsing:
    """Tests for VariantDictionary parsing."""

    def test_parse_uint32(self) -> None:
        """Test parsing UInt32 value."""
        # Build a simple variant dict with one UInt32
        parts = []
        parts.append(struct.pack("<H", 0x0100))  # Version
        # Entry: UInt32, key "V", value 0x13
        key = b"V"
        parts.append(struct.pack("<B", 0x04))  # Type
        parts.append(struct.pack("<I", len(key)))  # Key length
        parts.append(key)
        parts.append(struct.pack("<I", 4))  # Value length
        parts.append(struct.pack("<I", 0x13))  # Value
        parts.append(struct.pack("<B", 0x00))  # End

        result = KdbxHeader._parse_variant_dict(b"".join(parts))
        assert result["V"] == 0x13

    def test_parse_uint64(self) -> None:
        """Test parsing UInt64 value."""
        parts = []
        parts.append(struct.pack("<H", 0x0100))
        key = b"M"
        parts.append(struct.pack("<B", 0x05))  # UInt64 type
        parts.append(struct.pack("<I", len(key)))
        parts.append(key)
        parts.append(struct.pack("<I", 8))
        parts.append(struct.pack("<Q", 67108864))  # 64 MiB
        parts.append(struct.pack("<B", 0x00))

        result = KdbxHeader._parse_variant_dict(b"".join(parts))
        assert result["M"] == 67108864

    def test_parse_bytearray(self) -> None:
        """Test parsing ByteArray value."""
        parts = []
        parts.append(struct.pack("<H", 0x0100))
        key = b"S"
        salt = b"\x01\x02\x03\x04" * 8  # 32 bytes
        parts.append(struct.pack("<B", 0x42))  # ByteArray type
        parts.append(struct.pack("<I", len(key)))
        parts.append(key)
        parts.append(struct.pack("<I", len(salt)))
        parts.append(salt)
        parts.append(struct.pack("<B", 0x00))

        result = KdbxHeader._parse_variant_dict(b"".join(parts))
        assert result["S"] == salt

    def test_invalid_version(self) -> None:
        """Test that invalid version raises error."""
        data = struct.pack("<H", 0x0200)  # Wrong version
        with pytest.raises(CorruptedDataError):
            KdbxHeader._parse_variant_dict(data)

    def test_too_short(self) -> None:
        """Test that too short data raises error."""
        with pytest.raises(CorruptedDataError):
            KdbxHeader._parse_variant_dict(b"\x00")
