"""Parsing and building context classes for binary data.

This module provides structured helpers for reading and writing binary data
with good error messages and type safety.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import cast

from kdbxtool.exceptions import CorruptedDataError


@dataclass
class ParseContext:
    """Stateful reader for binary data with error context tracking.

    Tracks the current offset and a path of nested scopes for error messages.
    When parsing fails, error messages include the full path to the failure point.

    Example:
        ctx = ParseContext(data)
        with ctx.scope("header"):
            magic = ctx.read(8, "magic")
            with ctx.scope("version"):
                major = ctx.read_u16("major")
        # Error would show: "Unexpected EOF at header/version/major, offset 10"
    """

    data: bytes
    offset: int = 0
    _path: list[str] = field(default_factory=list)

    def read(self, n: int, name: str = "") -> bytes:
        """Read n bytes from current position.

        Args:
            n: Number of bytes to read
            name: Optional name for error messages

        Returns:
            The bytes read

        Raises:
            CorruptedDataError: If not enough bytes available
        """
        if self.offset + n > len(self.data):
            location = self._format_location(name)
            raise CorruptedDataError(
                f"Unexpected EOF at {location}, offset {self.offset}, "
                f"need {n} bytes, have {len(self.data) - self.offset}"
            )
        result = self.data[self.offset : self.offset + n]
        self.offset += n
        return result

    def read_u8(self, name: str = "") -> int:
        """Read unsigned 8-bit integer."""
        return self.read(1, name)[0]

    def read_u16(self, name: str = "") -> int:
        """Read unsigned 16-bit little-endian integer."""
        return cast(int, struct.unpack("<H", self.read(2, name))[0])

    def read_u32(self, name: str = "") -> int:
        """Read unsigned 32-bit little-endian integer."""
        return cast(int, struct.unpack("<I", self.read(4, name))[0])

    def read_u64(self, name: str = "") -> int:
        """Read unsigned 64-bit little-endian integer."""
        return cast(int, struct.unpack("<Q", self.read(8, name))[0])

    def read_bytes_prefixed(self, name: str = "") -> bytes:
        """Read length-prefixed bytes (4-byte little-endian length prefix).

        Args:
            name: Optional name for error messages

        Returns:
            The bytes read (not including the length prefix)
        """
        length = self.read_u32(f"{name}.length" if name else "length")
        return self.read(length, f"{name}.data" if name else "data")

    def peek(self, n: int) -> bytes:
        """Peek at next n bytes without advancing offset.

        Args:
            n: Number of bytes to peek

        Returns:
            The bytes (may be shorter if near end of data)
        """
        return self.data[self.offset : self.offset + n]

    def skip(self, n: int, name: str = "") -> None:
        """Skip n bytes.

        Args:
            n: Number of bytes to skip
            name: Optional name for error messages

        Raises:
            CorruptedDataError: If not enough bytes available
        """
        self.read(n, name)

    @contextmanager
    def scope(self, name: str) -> Iterator[None]:
        """Create a named scope for error context.

        Args:
            name: Scope name to add to error path

        Example:
            with ctx.scope("inner_header"):
                field_type = ctx.read_u8("type")
        """
        self._path.append(name)
        try:
            yield
        finally:
            self._path.pop()

    @property
    def remaining(self) -> int:
        """Number of bytes remaining to read."""
        return len(self.data) - self.offset

    @property
    def exhausted(self) -> bool:
        """True if all bytes have been read."""
        return self.offset >= len(self.data)

    @property
    def position(self) -> int:
        """Current read position (alias for offset)."""
        return self.offset

    def _format_location(self, name: str = "") -> str:
        """Format current location for error messages."""
        parts = self._path.copy()
        if name:
            parts.append(name)
        return "/".join(parts) if parts else "<root>"


@dataclass
class BuildContext:
    """Stateful writer for building binary data.

    Accumulates bytes in a list and joins them efficiently at the end.

    Example:
        ctx = BuildContext()
        ctx.write(MAGIC_BYTES)
        ctx.write_u32(version)
        ctx.write_tlv(FIELD_TYPE, field_data)
        result = ctx.build()
    """

    _parts: list[bytes] = field(default_factory=list)

    def write(self, data: bytes) -> None:
        """Write raw bytes."""
        self._parts.append(data)

    def write_u8(self, value: int) -> None:
        """Write unsigned 8-bit integer."""
        self._parts.append(bytes([value]))

    def write_u16(self, value: int) -> None:
        """Write unsigned 16-bit little-endian integer."""
        self._parts.append(struct.pack("<H", value))

    def write_u32(self, value: int) -> None:
        """Write unsigned 32-bit little-endian integer."""
        self._parts.append(struct.pack("<I", value))

    def write_u64(self, value: int) -> None:
        """Write unsigned 64-bit little-endian integer."""
        self._parts.append(struct.pack("<Q", value))

    def write_bytes_prefixed(self, data: bytes) -> None:
        """Write length-prefixed bytes (4-byte little-endian length prefix)."""
        self.write_u32(len(data))
        self.write(data)

    def write_tlv(self, type_id: int, data: bytes, type_size: int = 1) -> None:
        """Write Type-Length-Value field.

        Args:
            type_id: Field type identifier
            data: Field data
            type_size: Size of type field in bytes (1 for KDBX4, can vary)
        """
        if type_size == 1:
            self.write_u8(type_id)
        elif type_size == 2:
            self.write_u16(type_id)
        else:
            raise ValueError(f"Unsupported type_size: {type_size}")
        self.write_u32(len(data))
        self.write(data)

    def build(self) -> bytes:
        """Join all accumulated bytes and return result."""
        return b"".join(self._parts)

    @property
    def size(self) -> int:
        """Total size of accumulated bytes."""
        return sum(len(p) for p in self._parts)
