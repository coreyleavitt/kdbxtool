"""Tests for keyfile creation and parsing."""

import hashlib
import tempfile
from pathlib import Path

import pytest

from kdbxtool import (
    InvalidKeyFileError,
    KeyFileVersion,
    create_keyfile,
    create_keyfile_bytes,
    parse_keyfile,
)


class TestKeyFileVersion:
    """Tests for KeyFileVersion enum."""

    def test_enum_values(self) -> None:
        """Test that all expected versions are present."""
        assert KeyFileVersion.XML_V2 == "xml_v2"
        assert KeyFileVersion.XML_V1 == "xml_v1"
        assert KeyFileVersion.RAW_32 == "raw_32"
        assert KeyFileVersion.HEX_64 == "hex_64"


class TestCreateKeyfileBytes:
    """Tests for create_keyfile_bytes function."""

    def test_xml_v2_format(self) -> None:
        """Test XML v2.0 keyfile creation."""
        data = create_keyfile_bytes(KeyFileVersion.XML_V2)

        # Should be valid UTF-8 XML
        text = data.decode("utf-8")
        assert '<?xml version="1.0"' in text
        assert "<KeyFile>" in text
        assert "<Version>2.0</Version>" in text
        assert 'Hash="' in text  # Should have hash attribute

    def test_xml_v2_hash_verification(self) -> None:
        """Test that XML v2.0 keyfile has valid hash."""
        data = create_keyfile_bytes(KeyFileVersion.XML_V2)

        # Parse and verify
        key = parse_keyfile(data)
        assert len(key) == 32  # Should be 32 bytes

    def test_xml_v1_format(self) -> None:
        """Test XML v1.0 keyfile creation."""
        data = create_keyfile_bytes(KeyFileVersion.XML_V1)

        text = data.decode("utf-8")
        assert '<?xml version="1.0"' in text
        assert "<KeyFile>" in text
        assert "<Version>1.00</Version>" in text

    def test_xml_v1_base64_encoded(self) -> None:
        """Test that XML v1.0 key is base64 encoded."""
        import base64

        data = create_keyfile_bytes(KeyFileVersion.XML_V1)

        # Parse and verify
        key = parse_keyfile(data)
        assert len(key) == 32

    def test_raw_32_format(self) -> None:
        """Test raw 32-byte keyfile creation."""
        data = create_keyfile_bytes(KeyFileVersion.RAW_32)

        assert len(data) == 32
        # Should be raw bytes, not ASCII
        assert data == parse_keyfile(data)

    def test_hex_64_format(self) -> None:
        """Test hex-encoded keyfile creation."""
        data = create_keyfile_bytes(KeyFileVersion.HEX_64)

        assert len(data) == 64
        # Should be valid hex
        text = data.decode("ascii")
        bytes.fromhex(text)  # Should not raise

    def test_different_keys_each_time(self) -> None:
        """Test that each call generates a different key."""
        data1 = create_keyfile_bytes(KeyFileVersion.RAW_32)
        data2 = create_keyfile_bytes(KeyFileVersion.RAW_32)

        assert data1 != data2

    def test_default_is_xml_v2(self) -> None:
        """Test that default version is XML v2.0."""
        data = create_keyfile_bytes()

        text = data.decode("utf-8")
        assert "<Version>2.0</Version>" in text


class TestCreateKeyfile:
    """Tests for create_keyfile function."""

    def test_creates_file(self) -> None:
        """Test that keyfile is created at specified path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.keyx"

            create_keyfile(path)

            assert path.exists()
            assert path.stat().st_size > 0

    def test_file_content_is_valid(self) -> None:
        """Test that created file contains valid keyfile."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.keyx"

            create_keyfile(path, version=KeyFileVersion.XML_V2)

            data = path.read_bytes()
            key = parse_keyfile(data)
            assert len(key) == 32

    def test_accepts_string_path(self) -> None:
        """Test that string paths are accepted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = f"{tmpdir}/test.key"

            create_keyfile(path, version=KeyFileVersion.RAW_32)

            assert Path(path).exists()


class TestParseKeyfile:
    """Tests for parse_keyfile function."""

    def test_parse_xml_v2(self) -> None:
        """Test parsing XML v2.0 keyfile."""
        key_bytes = b"\x00" * 32
        key_hex = key_bytes.hex().upper()
        hash_hex = hashlib.sha256(key_bytes).digest()[:4].hex().upper()

        xml = f"""<?xml version="1.0" encoding="utf-8"?>
<KeyFile>
    <Meta>
        <Version>2.0</Version>
    </Meta>
    <Key>
        <Data Hash="{hash_hex}">{key_hex}</Data>
    </Key>
</KeyFile>
"""
        result = parse_keyfile(xml.encode("utf-8"))
        assert result == key_bytes

    def test_parse_xml_v2_invalid_hash(self) -> None:
        """Test that invalid hash raises error."""
        key_bytes = b"\x00" * 32
        key_hex = key_bytes.hex().upper()

        xml = f"""<?xml version="1.0" encoding="utf-8"?>
<KeyFile>
    <Meta>
        <Version>2.0</Version>
    </Meta>
    <Key>
        <Data Hash="DEADBEEF">{key_hex}</Data>
    </Key>
</KeyFile>
"""
        with pytest.raises(InvalidKeyFileError, match="hash verification failed"):
            parse_keyfile(xml.encode("utf-8"))

    def test_parse_xml_v1(self) -> None:
        """Test parsing XML v1.0 keyfile."""
        import base64

        key_bytes = b"\x01\x02\x03\x04" * 8  # 32 bytes
        key_b64 = base64.b64encode(key_bytes).decode("ascii")

        xml = f"""<?xml version="1.0" encoding="utf-8"?>
<KeyFile>
    <Meta>
        <Version>1.00</Version>
    </Meta>
    <Key>
        <Data>{key_b64}</Data>
    </Key>
</KeyFile>
"""
        result = parse_keyfile(xml.encode("utf-8"))
        assert result == key_bytes

    def test_parse_raw_32(self) -> None:
        """Test parsing raw 32-byte keyfile."""
        key_bytes = b"\xab" * 32

        result = parse_keyfile(key_bytes)
        assert result == key_bytes

    def test_parse_hex_64(self) -> None:
        """Test parsing hex-encoded keyfile."""
        key_bytes = b"\xcd" * 32
        hex_data = key_bytes.hex().encode("ascii")

        result = parse_keyfile(hex_data)
        assert result == key_bytes

    def test_parse_arbitrary_file(self) -> None:
        """Test that arbitrary files are hashed."""
        arbitrary_data = b"This is not a proper keyfile format!"

        result = parse_keyfile(arbitrary_data)

        # Should be SHA-256 hash of the data
        expected = hashlib.sha256(arbitrary_data).digest()
        assert result == expected
        assert len(result) == 32

    def test_parse_large_file(self) -> None:
        """Test that large files are hashed."""
        large_data = b"X" * 10000

        result = parse_keyfile(large_data)

        expected = hashlib.sha256(large_data).digest()
        assert result == expected


class TestRoundTrip:
    """Tests for creating and parsing keyfiles."""

    @pytest.mark.parametrize("version", list(KeyFileVersion))
    def test_roundtrip_all_versions(self, version: KeyFileVersion) -> None:
        """Test that created keyfiles can be parsed back."""
        data = create_keyfile_bytes(version)
        key = parse_keyfile(data)

        assert len(key) == 32

        # Create another with same version and verify different keys
        data2 = create_keyfile_bytes(version)
        key2 = parse_keyfile(data2)

        assert key != key2  # Different random keys
