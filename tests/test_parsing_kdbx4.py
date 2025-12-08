"""Tests for KDBX4 encryption and decryption."""

import os
from pathlib import Path

import pytest

from kdbxtool import AuthenticationError, DecryptionError, MissingCredentialsError
from kdbxtool.parsing import (
    CompressionType,
    KdbxHeader,
    KdbxVersion,
)
from kdbxtool.parsing.kdbx4 import (
    DecryptedPayload,
    InnerHeader,
    Kdbx4Reader,
    Kdbx4Writer,
    read_kdbx4,
    write_kdbx4,
)
from kdbxtool.security import Cipher, KdfType


FIXTURES_DIR = Path(__file__).parent / "fixtures"
TEST4_KDBX = FIXTURES_DIR / "test4.kdbx"
TEST4_KEY = FIXTURES_DIR / "test4.key"
TEST_PASSWORD = "password"


class TestKdbx4Reader:
    """Tests for Kdbx4Reader class."""

    @pytest.fixture
    def test4_data(self) -> bytes:
        """Load test4.kdbx file data."""
        if not TEST4_KDBX.exists():
            pytest.skip("Test fixture test4.kdbx not found")
        return TEST4_KDBX.read_bytes()

    @pytest.fixture
    def test4_keyfile(self) -> bytes:
        """Load test4.key file data."""
        if not TEST4_KEY.exists():
            pytest.skip("Test fixture test4.key not found")
        return TEST4_KEY.read_bytes()

    def test_decrypt_test4(self, test4_data: bytes, test4_keyfile: bytes) -> None:
        """Test decrypting test4.kdbx with password and keyfile."""
        result = read_kdbx4(test4_data, password=TEST_PASSWORD, keyfile_data=test4_keyfile)

        assert isinstance(result, DecryptedPayload)
        assert result.header.version == KdbxVersion.KDBX4
        assert len(result.xml_data) > 0
        # XML should start with XML declaration or root element
        assert result.xml_data.startswith(b"<?xml") or result.xml_data.startswith(b"<")

    def test_decrypt_wrong_password(self, test4_data: bytes, test4_keyfile: bytes) -> None:
        """Test that wrong password raises error."""
        with pytest.raises(AuthenticationError):
            read_kdbx4(test4_data, password="wrongpassword", keyfile_data=test4_keyfile)

    def test_decrypt_no_credentials(self, test4_data: bytes) -> None:
        """Test that no credentials raises error."""
        with pytest.raises(MissingCredentialsError):
            read_kdbx4(test4_data)

    def test_header_parsed_correctly(self, test4_data: bytes, test4_keyfile: bytes) -> None:
        """Test that header is parsed correctly."""
        result = read_kdbx4(test4_data, password=TEST_PASSWORD, keyfile_data=test4_keyfile)

        assert result.header.version == KdbxVersion.KDBX4
        assert result.header.cipher in (Cipher.AES256_CBC, Cipher.CHACHA20)
        assert len(result.header.master_seed) == 32
        assert len(result.header.kdf_salt) == 32

    def test_inner_header_parsed(self, test4_data: bytes, test4_keyfile: bytes) -> None:
        """Test that inner header is parsed."""
        result = read_kdbx4(test4_data, password=TEST_PASSWORD, keyfile_data=test4_keyfile)

        assert isinstance(result.inner_header, InnerHeader)
        assert result.inner_header.random_stream_id > 0
        assert len(result.inner_header.random_stream_key) > 0


class TestKdbx4Writer:
    """Tests for Kdbx4Writer class."""

    @pytest.fixture
    def sample_header(self) -> KdbxHeader:
        """Create a sample KDBX4 header."""
        return KdbxHeader(
            version=KdbxVersion.KDBX4,
            cipher=Cipher.AES256_CBC,
            compression=CompressionType.GZIP,
            master_seed=os.urandom(32),
            encryption_iv=os.urandom(16),
            kdf_type=KdfType.ARGON2ID,
            kdf_salt=os.urandom(32),
            argon2_memory_kib=16 * 1024,  # 16 MiB for faster tests
            argon2_iterations=3,
            argon2_parallelism=2,
        )

    @pytest.fixture
    def sample_inner_header(self) -> InnerHeader:
        """Create a sample inner header."""
        return InnerHeader(
            random_stream_id=3,  # ChaCha20
            random_stream_key=os.urandom(64),
            binaries={},
        )

    @pytest.fixture
    def sample_xml(self) -> bytes:
        """Create sample XML payload."""
        return b"""<?xml version="1.0" encoding="utf-8"?>
<KeePassFile>
    <Root>
        <Group>
            <Name>Root</Name>
            <Entry>
                <String>
                    <Key>Title</Key>
                    <Value>Test Entry</Value>
                </String>
                <String>
                    <Key>UserName</Key>
                    <Value>testuser</Value>
                </String>
            </Entry>
        </Group>
    </Root>
</KeePassFile>"""

    def test_write_read_roundtrip(
        self,
        sample_header: KdbxHeader,
        sample_inner_header: InnerHeader,
        sample_xml: bytes,
    ) -> None:
        """Test that written file can be read back."""
        password = "testpassword123"

        # Write
        encrypted = write_kdbx4(
            header=sample_header,
            inner_header=sample_inner_header,
            xml_data=sample_xml,
            password=password,
        )

        # Read back
        result = read_kdbx4(encrypted, password=password)

        assert result.xml_data == sample_xml
        assert result.header.cipher == sample_header.cipher
        assert result.header.compression == sample_header.compression

    def test_write_read_roundtrip_chacha20(
        self,
        sample_inner_header: InnerHeader,
        sample_xml: bytes,
    ) -> None:
        """Test roundtrip with ChaCha20 cipher."""
        header = KdbxHeader(
            version=KdbxVersion.KDBX4,
            cipher=Cipher.CHACHA20,
            compression=CompressionType.GZIP,
            master_seed=os.urandom(32),
            encryption_iv=os.urandom(12),  # 12-byte nonce for ChaCha20
            kdf_type=KdfType.ARGON2ID,
            kdf_salt=os.urandom(32),
            argon2_memory_kib=16 * 1024,
            argon2_iterations=3,
            argon2_parallelism=2,
        )
        password = "chacha20test"

        encrypted = write_kdbx4(
            header=header,
            inner_header=sample_inner_header,
            xml_data=sample_xml,
            password=password,
        )

        result = read_kdbx4(encrypted, password=password)
        assert result.xml_data == sample_xml
        assert result.header.cipher == Cipher.CHACHA20

    def test_write_read_roundtrip_no_compression(
        self,
        sample_inner_header: InnerHeader,
        sample_xml: bytes,
    ) -> None:
        """Test roundtrip without compression."""
        header = KdbxHeader(
            version=KdbxVersion.KDBX4,
            cipher=Cipher.AES256_CBC,
            compression=CompressionType.NONE,
            master_seed=os.urandom(32),
            encryption_iv=os.urandom(16),
            kdf_type=KdfType.ARGON2ID,
            kdf_salt=os.urandom(32),
            argon2_memory_kib=16 * 1024,
            argon2_iterations=3,
            argon2_parallelism=2,
        )
        password = "nocompression"

        encrypted = write_kdbx4(
            header=header,
            inner_header=sample_inner_header,
            xml_data=sample_xml,
            password=password,
        )

        result = read_kdbx4(encrypted, password=password)
        assert result.xml_data == sample_xml
        assert result.header.compression == CompressionType.NONE

    def test_write_read_roundtrip_argon2d(
        self,
        sample_inner_header: InnerHeader,
        sample_xml: bytes,
    ) -> None:
        """Test roundtrip with Argon2d variant."""
        header = KdbxHeader(
            version=KdbxVersion.KDBX4,
            cipher=Cipher.AES256_CBC,
            compression=CompressionType.GZIP,
            master_seed=os.urandom(32),
            encryption_iv=os.urandom(16),
            kdf_type=KdfType.ARGON2D,
            kdf_salt=os.urandom(32),
            argon2_memory_kib=16 * 1024,
            argon2_iterations=3,
            argon2_parallelism=2,
        )
        password = "argon2dtest"

        encrypted = write_kdbx4(
            header=header,
            inner_header=sample_inner_header,
            xml_data=sample_xml,
            password=password,
        )

        result = read_kdbx4(encrypted, password=password)
        assert result.xml_data == sample_xml
        assert result.header.kdf_type == KdfType.ARGON2D

    def test_write_read_roundtrip_with_binaries(
        self,
        sample_header: KdbxHeader,
        sample_xml: bytes,
    ) -> None:
        """Test roundtrip with binary attachments."""
        inner = InnerHeader(
            random_stream_id=3,
            random_stream_key=os.urandom(64),
            binaries={
                0: (True, b"protected binary content"),
                1: (False, b"unprotected binary content"),
            },
        )
        password = "binarytest"

        encrypted = write_kdbx4(
            header=sample_header,
            inner_header=inner,
            xml_data=sample_xml,
            password=password,
        )

        result = read_kdbx4(encrypted, password=password)
        assert len(result.inner_header.binaries) == 2
        assert result.inner_header.binaries[0] == (True, b"protected binary content")
        assert result.inner_header.binaries[1] == (False, b"unprotected binary content")

    def test_write_read_roundtrip_with_keyfile(
        self,
        sample_header: KdbxHeader,
        sample_inner_header: InnerHeader,
        sample_xml: bytes,
    ) -> None:
        """Test roundtrip with keyfile instead of password."""
        keyfile_data = os.urandom(64)

        encrypted = write_kdbx4(
            header=sample_header,
            inner_header=sample_inner_header,
            xml_data=sample_xml,
            keyfile_data=keyfile_data,
        )

        result = read_kdbx4(encrypted, keyfile_data=keyfile_data)
        assert result.xml_data == sample_xml

    def test_write_read_roundtrip_with_both_credentials(
        self,
        sample_header: KdbxHeader,
        sample_inner_header: InnerHeader,
        sample_xml: bytes,
    ) -> None:
        """Test roundtrip with both password and keyfile."""
        password = "combo"
        keyfile_data = os.urandom(64)

        encrypted = write_kdbx4(
            header=sample_header,
            inner_header=sample_inner_header,
            xml_data=sample_xml,
            password=password,
            keyfile_data=keyfile_data,
        )

        # Must have both to decrypt
        result = read_kdbx4(encrypted, password=password, keyfile_data=keyfile_data)
        assert result.xml_data == sample_xml

        # Password alone should fail
        with pytest.raises(AuthenticationError):
            read_kdbx4(encrypted, password=password)

        # Keyfile alone should fail
        with pytest.raises(AuthenticationError):
            read_kdbx4(encrypted, keyfile_data=keyfile_data)

    def test_large_payload(
        self,
        sample_header: KdbxHeader,
        sample_inner_header: InnerHeader,
    ) -> None:
        """Test with large XML payload (multiple blocks)."""
        # Create XML larger than block size (1 MiB)
        large_xml = b"<?xml version='1.0'?><root>" + b"x" * (2 * 1024 * 1024) + b"</root>"
        password = "largetest"

        encrypted = write_kdbx4(
            header=sample_header,
            inner_header=sample_inner_header,
            xml_data=large_xml,
            password=password,
        )

        result = read_kdbx4(encrypted, password=password)
        assert result.xml_data == large_xml


class TestPkcs7Padding:
    """Tests for PKCS7 padding functions."""

    def test_padding_roundtrip(self) -> None:
        """Test that padding and unpadding are inverses."""
        from kdbxtool.parsing.kdbx4 import Kdbx4Reader, Kdbx4Writer

        writer = Kdbx4Writer()
        reader = Kdbx4Reader(b"")

        for length in [0, 1, 15, 16, 17, 31, 32, 100]:
            data = b"x" * length
            padded = writer._add_pkcs7_padding(data)
            assert len(padded) % 16 == 0
            unpadded = reader._remove_pkcs7_padding(padded)
            assert unpadded == data

    def test_invalid_padding_length(self) -> None:
        """Test that invalid padding is rejected."""
        from kdbxtool.parsing.kdbx4 import Kdbx4Reader

        reader = Kdbx4Reader(b"")

        # Padding length 0
        with pytest.raises(DecryptionError):
            reader._remove_pkcs7_padding(b"0123456789abcde\x00")

        # Padding length > 16
        with pytest.raises(DecryptionError):
            reader._remove_pkcs7_padding(b"0123456789abcde\x11")

    def test_invalid_padding_bytes(self) -> None:
        """Test that inconsistent padding is rejected."""
        from kdbxtool.parsing.kdbx4 import Kdbx4Reader

        reader = Kdbx4Reader(b"")

        # Says 4 bytes padding but not all are 0x04
        with pytest.raises(DecryptionError):
            reader._remove_pkcs7_padding(b"0123456789ab\x04\x04\x04\x05")


class TestInnerHeader:
    """Tests for InnerHeader parsing and building."""

    def test_inner_header_roundtrip(self) -> None:
        """Test that inner header can be built and parsed back."""
        from kdbxtool.parsing.kdbx4 import Kdbx4Reader, Kdbx4Writer

        original = InnerHeader(
            random_stream_id=3,
            random_stream_key=b"k" * 64,
            binaries={
                0: (True, b"binary0"),
                1: (False, b"binary1"),
            },
        )

        writer = Kdbx4Writer()
        data = writer._build_inner_header(original)

        reader = Kdbx4Reader(b"")
        parsed, offset = reader._parse_inner_header(data)

        assert parsed.random_stream_id == original.random_stream_id
        assert parsed.random_stream_key == original.random_stream_key
        assert parsed.binaries == original.binaries
        assert offset == len(data)

    def test_empty_binaries(self) -> None:
        """Test inner header with no binaries."""
        from kdbxtool.parsing.kdbx4 import Kdbx4Reader, Kdbx4Writer

        original = InnerHeader(
            random_stream_id=2,
            random_stream_key=b"key" * 10,
            binaries={},
        )

        writer = Kdbx4Writer()
        data = writer._build_inner_header(original)

        reader = Kdbx4Reader(b"")
        parsed, _ = reader._parse_inner_header(data)

        assert len(parsed.binaries) == 0
