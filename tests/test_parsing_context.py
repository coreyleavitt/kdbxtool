"""Tests for parsing context classes."""

import struct

import pytest

from kdbxtool.exceptions import CorruptedDataError
from kdbxtool.parsing.context import BuildContext, ParseContext


class TestParseContext:
    """Tests for ParseContext class."""

    def test_read_bytes(self) -> None:
        """Test basic byte reading."""
        ctx = ParseContext(b"\x01\x02\x03\x04")
        assert ctx.read(2, "test") == b"\x01\x02"
        assert ctx.offset == 2
        assert ctx.read(2, "test") == b"\x03\x04"
        assert ctx.offset == 4

    def test_read_past_end_raises(self) -> None:
        """Test reading past end raises CorruptedDataError."""
        ctx = ParseContext(b"\x01\x02")
        with pytest.raises(CorruptedDataError) as exc_info:
            ctx.read(4, "test_field")
        assert "test_field" in str(exc_info.value)
        assert "need 4 bytes" in str(exc_info.value)

    def test_read_u8(self) -> None:
        """Test reading unsigned 8-bit integer."""
        ctx = ParseContext(b"\xff\x00")
        assert ctx.read_u8("test") == 255
        assert ctx.read_u8("test") == 0

    def test_read_u16(self) -> None:
        """Test reading unsigned 16-bit little-endian integer."""
        ctx = ParseContext(b"\x01\x00\xff\xff")
        assert ctx.read_u16("test") == 1
        assert ctx.read_u16("test") == 65535

    def test_read_u32(self) -> None:
        """Test reading unsigned 32-bit little-endian integer."""
        ctx = ParseContext(b"\x01\x00\x00\x00\xff\xff\xff\xff")
        assert ctx.read_u32("test") == 1
        assert ctx.read_u32("test") == 0xFFFFFFFF

    def test_read_u64(self) -> None:
        """Test reading unsigned 64-bit little-endian integer."""
        ctx = ParseContext(b"\x01\x00\x00\x00\x00\x00\x00\x00")
        assert ctx.read_u64("test") == 1

    def test_read_bytes_prefixed(self) -> None:
        """Test reading length-prefixed bytes."""
        # 4-byte length prefix (3) followed by 3 bytes of data
        data = struct.pack("<I", 3) + b"abc"
        ctx = ParseContext(data)
        assert ctx.read_bytes_prefixed("test") == b"abc"
        assert ctx.offset == 7

    def test_peek_does_not_advance_offset(self) -> None:
        """Test that peek does not advance offset."""
        ctx = ParseContext(b"\x01\x02\x03")
        assert ctx.peek(2) == b"\x01\x02"
        assert ctx.offset == 0
        assert ctx.peek(3) == b"\x01\x02\x03"
        assert ctx.offset == 0

    def test_peek_near_end(self) -> None:
        """Test peek near end of data returns available bytes."""
        ctx = ParseContext(b"\x01\x02")
        assert ctx.peek(10) == b"\x01\x02"

    def test_skip(self) -> None:
        """Test skipping bytes."""
        ctx = ParseContext(b"\x01\x02\x03\x04")
        ctx.skip(2, "header")
        assert ctx.offset == 2
        assert ctx.read(1, "test") == b"\x03"

    def test_skip_past_end_raises(self) -> None:
        """Test skipping past end raises error."""
        ctx = ParseContext(b"\x01")
        with pytest.raises(CorruptedDataError):
            ctx.skip(5, "test")

    def test_scope_context_manager(self) -> None:
        """Test scope context manager for error paths."""
        ctx = ParseContext(b"\x01")
        with ctx.scope("outer"):
            with ctx.scope("inner"):
                with pytest.raises(CorruptedDataError) as exc_info:
                    ctx.read(10, "field")
        assert "outer/inner/field" in str(exc_info.value)

    def test_scope_cleanup_on_exception(self) -> None:
        """Test scope cleans up path on exception."""
        ctx = ParseContext(b"\x01\x02\x03\x04")
        try:
            with ctx.scope("test"):
                raise ValueError("test error")
        except ValueError:
            pass
        # Path should be cleaned up
        with pytest.raises(CorruptedDataError) as exc_info:
            ctx.read(100, "field")
        assert "test" not in str(exc_info.value)

    def test_remaining_property(self) -> None:
        """Test remaining bytes property."""
        ctx = ParseContext(b"\x01\x02\x03\x04")
        assert ctx.remaining == 4
        ctx.read(2, "test")
        assert ctx.remaining == 2

    def test_exhausted_property(self) -> None:
        """Test exhausted property."""
        ctx = ParseContext(b"\x01\x02")
        assert not ctx.exhausted
        ctx.read(2, "test")
        assert ctx.exhausted

    def test_position_property(self) -> None:
        """Test position property (alias for offset)."""
        ctx = ParseContext(b"\x01\x02\x03\x04")
        assert ctx.position == 0
        ctx.read(2, "test")
        assert ctx.position == 2

    def test_empty_data(self) -> None:
        """Test with empty data."""
        ctx = ParseContext(b"")
        assert ctx.exhausted
        assert ctx.remaining == 0
        with pytest.raises(CorruptedDataError):
            ctx.read(1, "test")


class TestBuildContext:
    """Tests for BuildContext class."""

    def test_write_bytes(self) -> None:
        """Test writing raw bytes."""
        ctx = BuildContext()
        ctx.write(b"\x01\x02")
        ctx.write(b"\x03\x04")
        assert ctx.build() == b"\x01\x02\x03\x04"

    def test_write_u8(self) -> None:
        """Test writing unsigned 8-bit integer."""
        ctx = BuildContext()
        ctx.write_u8(0xFF)
        ctx.write_u8(0x00)
        assert ctx.build() == b"\xff\x00"

    def test_write_u16(self) -> None:
        """Test writing unsigned 16-bit little-endian integer."""
        ctx = BuildContext()
        ctx.write_u16(1)
        ctx.write_u16(0xFFFF)
        assert ctx.build() == b"\x01\x00\xff\xff"

    def test_write_u32(self) -> None:
        """Test writing unsigned 32-bit little-endian integer."""
        ctx = BuildContext()
        ctx.write_u32(1)
        assert ctx.build() == b"\x01\x00\x00\x00"

    def test_write_u64(self) -> None:
        """Test writing unsigned 64-bit little-endian integer."""
        ctx = BuildContext()
        ctx.write_u64(1)
        assert ctx.build() == b"\x01\x00\x00\x00\x00\x00\x00\x00"

    def test_write_bytes_prefixed(self) -> None:
        """Test writing length-prefixed bytes."""
        ctx = BuildContext()
        ctx.write_bytes_prefixed(b"abc")
        result = ctx.build()
        # Should have 4-byte length prefix (3) + "abc"
        assert result == struct.pack("<I", 3) + b"abc"

    def test_write_tlv_type_size_1(self) -> None:
        """Test writing TLV with 1-byte type."""
        ctx = BuildContext()
        ctx.write_tlv(0x02, b"test", type_size=1)
        result = ctx.build()
        # 1-byte type + 4-byte length + data
        assert result == b"\x02" + struct.pack("<I", 4) + b"test"

    def test_write_tlv_type_size_2(self) -> None:
        """Test writing TLV with 2-byte type."""
        ctx = BuildContext()
        ctx.write_tlv(0x0102, b"ab", type_size=2)
        result = ctx.build()
        # 2-byte type + 4-byte length + data
        assert result == struct.pack("<H", 0x0102) + struct.pack("<I", 2) + b"ab"

    def test_write_tlv_invalid_type_size(self) -> None:
        """Test that invalid type_size raises error."""
        ctx = BuildContext()
        with pytest.raises(ValueError) as exc_info:
            ctx.write_tlv(0x01, b"test", type_size=4)
        assert "type_size" in str(exc_info.value)

    def test_build_returns_joined_bytes(self) -> None:
        """Test that build returns all written bytes joined."""
        ctx = BuildContext()
        ctx.write(b"a")
        ctx.write(b"b")
        ctx.write(b"c")
        assert ctx.build() == b"abc"

    def test_size_property(self) -> None:
        """Test size property returns total byte count."""
        ctx = BuildContext()
        assert ctx.size == 0
        ctx.write(b"abc")
        assert ctx.size == 3
        ctx.write(b"de")
        assert ctx.size == 5

    def test_empty_build(self) -> None:
        """Test building with no data written."""
        ctx = BuildContext()
        assert ctx.build() == b""

    def test_write_empty_bytes(self) -> None:
        """Test writing empty bytes."""
        ctx = BuildContext()
        ctx.write(b"")
        ctx.write(b"a")
        ctx.write(b"")
        assert ctx.build() == b"a"


class TestRoundTrip:
    """Tests for round-trip consistency between ParseContext and BuildContext."""

    def test_u8_roundtrip(self) -> None:
        """Test u8 write then read."""
        build = BuildContext()
        build.write_u8(42)
        build.write_u8(255)

        parse = ParseContext(build.build())
        assert parse.read_u8("val1") == 42
        assert parse.read_u8("val2") == 255
        assert parse.exhausted

    def test_u16_roundtrip(self) -> None:
        """Test u16 write then read."""
        build = BuildContext()
        build.write_u16(12345)

        parse = ParseContext(build.build())
        assert parse.read_u16("val") == 12345
        assert parse.exhausted

    def test_u32_roundtrip(self) -> None:
        """Test u32 write then read."""
        build = BuildContext()
        build.write_u32(0xDEADBEEF)

        parse = ParseContext(build.build())
        assert parse.read_u32("val") == 0xDEADBEEF
        assert parse.exhausted

    def test_u64_roundtrip(self) -> None:
        """Test u64 write then read."""
        build = BuildContext()
        build.write_u64(0xDEADBEEFCAFEBABE)

        parse = ParseContext(build.build())
        assert parse.read_u64("val") == 0xDEADBEEFCAFEBABE
        assert parse.exhausted

    def test_bytes_prefixed_roundtrip(self) -> None:
        """Test length-prefixed bytes write then read."""
        build = BuildContext()
        build.write_bytes_prefixed(b"hello world")

        parse = ParseContext(build.build())
        assert parse.read_bytes_prefixed("data") == b"hello world"
        assert parse.exhausted

    def test_tlv_roundtrip(self) -> None:
        """Test TLV write then manual read."""
        build = BuildContext()
        build.write_tlv(0x05, b"payload")

        parse = ParseContext(build.build())
        field_type = parse.read_u8("type")
        field_len = parse.read_u32("length")
        field_data = parse.read(field_len, "data")

        assert field_type == 0x05
        assert field_len == 7
        assert field_data == b"payload"
        assert parse.exhausted

    def test_complex_structure_roundtrip(self) -> None:
        """Test complex structure with mixed types."""
        build = BuildContext()
        build.write(b"MAGIC")
        build.write_u16(1)  # version
        build.write_u32(42)  # flags
        build.write_bytes_prefixed(b"content")
        build.write_tlv(0xFF, b"end")

        parse = ParseContext(build.build())
        assert parse.read(5, "magic") == b"MAGIC"
        assert parse.read_u16("version") == 1
        assert parse.read_u32("flags") == 42
        assert parse.read_bytes_prefixed("content") == b"content"
        assert parse.read_u8("type") == 0xFF
        assert parse.read_u32("len") == 3
        assert parse.read(3, "data") == b"end"
        assert parse.exhausted
