"""KDBX header parsing and structures.

This module provides typed structures for KDBX file headers:
- Magic bytes and version detection
- Outer header fields (cipher, compression, KDF parameters, etc.)
- Inner header fields (binary attachments, protected stream cipher)

KDBX format reference:
https://keepass.info/help/kb/kdbx_4.html
"""

from __future__ import annotations

import contextlib
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Self

from kdbxtool.exceptions import (
    CorruptedDataError,
    InvalidSignatureError,
    KdfError,
    UnsupportedVersionError,
)
from kdbxtool.security import Cipher, KdfType

from .context import BuildContext, ParseContext

# KDBX signature bytes
KDBX_MAGIC = bytes.fromhex("03d9a29a67fb4bb5")  # KeePass 2.x signature
KDBX4_MAGIC = bytes.fromhex("03d9a29a67fb4bb5")  # Same magic, version differs


class KdbxVersion(IntEnum):
    """KDBX file format versions."""

    KDBX3 = 3
    KDBX4 = 4


class HeaderFieldType(IntEnum):
    """Outer header field types for KDBX format.

    These are the TLV (Type-Length-Value) field identifiers
    in the outer (unencrypted) header.
    """

    END = 0
    COMMENT = 1  # Unused
    CIPHER_ID = 2
    COMPRESSION_FLAGS = 3
    MASTER_SEED = 4
    # KDBX3 only:
    TRANSFORM_SEED = 5  # AES-KDF seed
    TRANSFORM_ROUNDS = 6  # AES-KDF rounds
    # Both:
    ENCRYPTION_IV = 7
    # KDBX3 only:
    PROTECTED_STREAM_KEY = 8
    STREAM_START_BYTES = 9
    INNER_RANDOM_STREAM_ID = 10
    # KDBX4 only:
    KDF_PARAMETERS = 11
    PUBLIC_CUSTOM_DATA = 12


class InnerHeaderFieldType(IntEnum):
    """Inner header field types for KDBX4 format.

    These appear after decryption, before the XML payload.
    """

    END = 0
    INNER_RANDOM_STREAM_ID = 1
    INNER_RANDOM_STREAM_KEY = 2
    BINARY = 3  # Attachment data


class CompressionType(IntEnum):
    """Compression algorithms for KDBX payload."""

    NONE = 0
    GZIP = 1


@dataclass(slots=True)
class KdbxHeader:
    """Parsed KDBX header data.

    This class holds all fields from the outer header in a typed format.
    It supports both KDBX3 and KDBX4, with version-specific fields optional.
    """

    # Format version
    version: KdbxVersion

    # Cipher for payload encryption
    cipher: Cipher

    # Compression for XML payload
    compression: CompressionType

    # Random seed for master key derivation (32 bytes)
    master_seed: bytes

    # IV for payload encryption (16 bytes for AES, 12 for ChaCha20)
    encryption_iv: bytes

    # KDF parameters (KDBX4: Argon2 config, KDBX3: AES-KDF config)
    kdf_type: KdfType

    # Argon2/AES-KDF salt (32 bytes)
    kdf_salt: bytes

    # For Argon2 (KDBX4)
    argon2_memory_kib: int | None = None
    argon2_iterations: int | None = None
    argon2_parallelism: int | None = None

    # For AES-KDF (KDBX3)
    aes_kdf_rounds: int | None = None

    # KDBX4 inner header fields (populated after decryption)
    inner_random_stream_id: int | None = None
    inner_random_stream_key: bytes | None = None

    # KDBX3 fields
    stream_start_bytes: bytes | None = None
    protected_stream_key: bytes | None = None

    # Raw header bytes for HMAC verification
    raw_header: bytes = field(default=b"", repr=False)

    @classmethod
    def parse(cls, data: bytes) -> tuple[Self, int]:
        """Parse KDBX header from raw bytes.

        Args:
            data: Raw file data starting from beginning

        Returns:
            Tuple of (parsed header, number of bytes consumed)

        Raises:
            InvalidSignatureError: If magic bytes don't match
            UnsupportedVersionError: If KDBX version is not supported
            CorruptedDataError: If header is malformed or truncated
        """
        ctx = ParseContext(data)

        with ctx.scope("signature"):
            magic = ctx.read(8, "magic")
            if magic != KDBX_MAGIC:
                raise InvalidSignatureError(
                    f"Invalid KDBX signature: {magic.hex()} (expected {KDBX_MAGIC.hex()})"
                )

        with ctx.scope("version"):
            version_minor = ctx.read_u16("minor")
            version_major = ctx.read_u16("major")

            if version_major == 4:
                version = KdbxVersion.KDBX4
            elif version_major == 3:
                version = KdbxVersion.KDBX3
            else:
                raise UnsupportedVersionError(version_major, version_minor)

        # Parse header fields
        header_fields: dict[HeaderFieldType, bytes] = {}

        with ctx.scope("fields"):
            while not ctx.exhausted:
                field_type = ctx.read_u8("type")

                if version == KdbxVersion.KDBX4:
                    # KDBX4: 4-byte length
                    field_len = ctx.read_u32("length")
                else:
                    # KDBX3: 2-byte length
                    field_len = ctx.read_u16("length")

                field_data = ctx.read(field_len, "data")

                with contextlib.suppress(ValueError):
                    header_fields[HeaderFieldType(field_type)] = field_data

                if field_type == HeaderFieldType.END:
                    break

        # Extract required fields
        raw_header = data[: ctx.offset]

        # Cipher ID (required)
        if HeaderFieldType.CIPHER_ID not in header_fields:
            raise CorruptedDataError("Missing cipher ID in header")
        cipher = Cipher.from_uuid(header_fields[HeaderFieldType.CIPHER_ID])

        # Compression (required)
        if HeaderFieldType.COMPRESSION_FLAGS not in header_fields:
            raise CorruptedDataError("Missing compression flags in header")
        compression_val = struct.unpack("<I", header_fields[HeaderFieldType.COMPRESSION_FLAGS])[0]
        compression = CompressionType(compression_val)

        # Master seed (required, 32 bytes)
        if HeaderFieldType.MASTER_SEED not in header_fields:
            raise CorruptedDataError("Missing master seed in header")
        master_seed = header_fields[HeaderFieldType.MASTER_SEED]
        if len(master_seed) != 32:
            raise CorruptedDataError(f"Invalid master seed length: {len(master_seed)}")

        # Encryption IV (required)
        if HeaderFieldType.ENCRYPTION_IV not in header_fields:
            raise CorruptedDataError("Missing encryption IV in header")
        encryption_iv = header_fields[HeaderFieldType.ENCRYPTION_IV]

        # KDF parameters
        if version == KdbxVersion.KDBX4:
            return cls._parse_kdbx4_kdf(
                header_fields,
                version,
                cipher,
                compression,
                master_seed,
                encryption_iv,
                raw_header,
                ctx.offset,
            )
        else:
            return cls._parse_kdbx3_kdf(
                header_fields,
                version,
                cipher,
                compression,
                master_seed,
                encryption_iv,
                raw_header,
                ctx.offset,
            )

    @classmethod
    def _parse_kdbx4_kdf(
        cls,
        fields: dict[HeaderFieldType, bytes],
        version: KdbxVersion,
        cipher: Cipher,
        compression: CompressionType,
        master_seed: bytes,
        encryption_iv: bytes,
        raw_header: bytes,
        offset: int,
    ) -> tuple[Self, int]:
        """Parse KDBX4-specific KDF parameters."""
        if HeaderFieldType.KDF_PARAMETERS not in fields:
            raise CorruptedDataError("Missing KDF parameters in KDBX4 header")

        kdf_data = fields[HeaderFieldType.KDF_PARAMETERS]
        kdf_params = cls._parse_variant_dict(kdf_data)

        # Get KDF UUID (must be bytes)
        kdf_uuid = kdf_params.get("$UUID")
        if not isinstance(kdf_uuid, bytes):
            raise KdfError("Missing or invalid KDF UUID in parameters")
        kdf_type = KdfType.from_uuid(kdf_uuid)

        # Get salt (must be bytes)
        kdf_salt = kdf_params.get("S")
        if not isinstance(kdf_salt, bytes) or len(kdf_salt) != 32:
            raise KdfError("Invalid or missing KDF salt")

        argon2_memory: int | None = None
        argon2_iterations: int | None = None
        argon2_parallelism: int | None = None
        aes_kdf_rounds: int | None = None

        if kdf_type in (KdfType.ARGON2ID, KdfType.ARGON2D):
            # Argon2 parameters (must be ints)
            memory = kdf_params.get("M")
            iterations = kdf_params.get("I")
            parallelism = kdf_params.get("P")

            if (
                not isinstance(memory, int)
                or not isinstance(iterations, int)
                or not isinstance(parallelism, int)
            ):
                raise KdfError("Missing or invalid Argon2 parameters")

            argon2_memory = memory // 1024  # Convert bytes to KiB
            argon2_iterations = iterations
            argon2_parallelism = parallelism
        elif kdf_type == KdfType.AES_KDF:
            # AES-KDF parameters
            rounds = kdf_params.get("R")

            if not isinstance(rounds, int):
                raise KdfError("Missing or invalid AES-KDF rounds parameter")

            aes_kdf_rounds = rounds

        return (
            cls(
                version=version,
                cipher=cipher,
                compression=compression,
                master_seed=master_seed,
                encryption_iv=encryption_iv,
                kdf_type=kdf_type,
                kdf_salt=kdf_salt,
                argon2_memory_kib=argon2_memory,
                argon2_iterations=argon2_iterations,
                argon2_parallelism=argon2_parallelism,
                aes_kdf_rounds=aes_kdf_rounds,
                raw_header=raw_header,
            ),
            offset,
        )

    @classmethod
    def _parse_kdbx3_kdf(
        cls,
        fields: dict[HeaderFieldType, bytes],
        version: KdbxVersion,
        cipher: Cipher,
        compression: CompressionType,
        master_seed: bytes,
        encryption_iv: bytes,
        raw_header: bytes,
        offset: int,
    ) -> tuple[Self, int]:
        """Parse KDBX3-specific KDF parameters (AES-KDF)."""
        # Transform seed (AES-KDF key)
        if HeaderFieldType.TRANSFORM_SEED not in fields:
            raise CorruptedDataError("Missing transform seed in KDBX3 header")
        kdf_salt = fields[HeaderFieldType.TRANSFORM_SEED]
        if len(kdf_salt) != 32:
            raise CorruptedDataError(f"Invalid transform seed length: {len(kdf_salt)}")

        # Transform rounds
        if HeaderFieldType.TRANSFORM_ROUNDS not in fields:
            raise CorruptedDataError("Missing transform rounds in KDBX3 header")
        aes_kdf_rounds = struct.unpack("<Q", fields[HeaderFieldType.TRANSFORM_ROUNDS])[0]

        # Stream start bytes (for verification)
        stream_start = fields.get(HeaderFieldType.STREAM_START_BYTES)

        # Protected stream key (in outer header for KDBX3)
        protected_key = fields.get(HeaderFieldType.PROTECTED_STREAM_KEY)

        # Protected stream ID (in outer header for KDBX3)
        stream_id = None
        if HeaderFieldType.INNER_RANDOM_STREAM_ID in fields:
            stream_id = struct.unpack("<I", fields[HeaderFieldType.INNER_RANDOM_STREAM_ID])[0]

        return (
            cls(
                version=version,
                cipher=cipher,
                compression=compression,
                master_seed=master_seed,
                encryption_iv=encryption_iv,
                kdf_type=KdfType.AES_KDF,
                kdf_salt=kdf_salt,
                aes_kdf_rounds=aes_kdf_rounds,
                stream_start_bytes=stream_start,
                protected_stream_key=protected_key,
                inner_random_stream_id=stream_id,
                raw_header=raw_header,
            ),
            offset,
        )

    @staticmethod
    def _parse_variant_dict(data: bytes) -> dict[str, bytes | int | bool | str]:
        """Parse KDBX4 VariantDictionary format.

        VariantDictionary is a TLV format used for KDF parameters:
        - 2 bytes: version (0x0100)
        - Entries until type 0x00:
          - 1 byte: type
          - 4 bytes: key length
          - key bytes
          - 4 bytes: value length
          - value bytes

        Types:
        - 0x00: End
        - 0x04: UInt32
        - 0x05: UInt64
        - 0x08: Bool
        - 0x0C: Int32
        - 0x0D: Int64
        - 0x18: String
        - 0x42: ByteArray
        """
        ctx = ParseContext(data)

        with ctx.scope("variant_dict"):
            version = ctx.read_u16("version")
            if version != 0x0100:
                raise CorruptedDataError(f"Unsupported VariantDictionary version: {version:#x}")

            result: dict[str, bytes | int | bool | str] = {}

            while not ctx.exhausted:
                entry_type = ctx.read_u8("entry_type")

                if entry_type == 0x00:  # End
                    break

                with ctx.scope(f"entry[{entry_type:#x}]"):
                    # Read key
                    key_data = ctx.read_bytes_prefixed("key")
                    key = key_data.decode("utf-8")

                    # Read value
                    val_data = ctx.read_bytes_prefixed("value")

                    # Parse value based on type
                    if entry_type == 0x04:  # UInt32
                        result[key] = struct.unpack("<I", val_data)[0]
                    elif entry_type == 0x05:  # UInt64
                        result[key] = struct.unpack("<Q", val_data)[0]
                    elif entry_type == 0x08:  # Bool
                        result[key] = val_data[0] != 0
                    elif entry_type == 0x0C:  # Int32
                        result[key] = struct.unpack("<i", val_data)[0]
                    elif entry_type == 0x0D:  # Int64
                        result[key] = struct.unpack("<q", val_data)[0]
                    elif entry_type == 0x42:  # ByteArray
                        result[key] = val_data
                    elif entry_type == 0x18:  # String
                        result[key] = val_data.decode("utf-8")
                    else:
                        # Unknown type, store as bytes
                        result[key] = val_data

        return result

    def to_bytes(self) -> bytes:
        """Serialize header to KDBX4 binary format.

        Returns:
            Binary header data ready to be written to file

        Raises:
            UnsupportedVersionError: If not KDBX4 format
            KdfError: If Argon2 parameters are missing
        """
        if self.version != KdbxVersion.KDBX4:
            raise UnsupportedVersionError(self.version.value, 0)

        ctx = BuildContext()

        # Magic and version
        ctx.write(KDBX_MAGIC)
        ctx.write_u16(1)  # Minor version
        ctx.write_u16(4)  # Major version

        # Cipher ID
        ctx.write_tlv(HeaderFieldType.CIPHER_ID, self.cipher.value)

        # Compression
        ctx.write_tlv(
            HeaderFieldType.COMPRESSION_FLAGS,
            struct.pack("<I", self.compression.value),
        )

        # Master seed
        ctx.write_tlv(HeaderFieldType.MASTER_SEED, self.master_seed)

        # Encryption IV
        ctx.write_tlv(HeaderFieldType.ENCRYPTION_IV, self.encryption_iv)

        # KDF parameters as VariantDictionary
        kdf_dict = self._build_kdf_variant_dict()
        ctx.write_tlv(HeaderFieldType.KDF_PARAMETERS, kdf_dict)

        # End of header
        ctx.write_tlv(HeaderFieldType.END, b"\r\n\r\n")

        return ctx.build()

    def _build_kdf_variant_dict(self) -> bytes:
        """Build VariantDictionary for KDF parameters."""
        ctx = BuildContext()

        # Version
        ctx.write_u16(0x0100)

        def add_entry(entry_type: int, key: str, value: bytes) -> None:
            """Add an entry to the variant dictionary."""
            key_bytes = key.encode("utf-8")
            ctx.write_u8(entry_type)
            ctx.write_bytes_prefixed(key_bytes)
            ctx.write_bytes_prefixed(value)

        # KDF UUID
        add_entry(0x42, "$UUID", self.kdf_type.value)

        # Salt
        add_entry(0x42, "S", self.kdf_salt)

        if self.kdf_type in (KdfType.ARGON2ID, KdfType.ARGON2D):
            if (
                self.argon2_memory_kib is None
                or self.argon2_iterations is None
                or self.argon2_parallelism is None
            ):
                raise KdfError("Missing Argon2 parameters")

            # Memory in bytes (UInt64)
            add_entry(0x05, "M", struct.pack("<Q", self.argon2_memory_kib * 1024))
            # Iterations (UInt64)
            add_entry(0x05, "I", struct.pack("<Q", self.argon2_iterations))
            # Parallelism (UInt32)
            add_entry(0x04, "P", struct.pack("<I", self.argon2_parallelism))
            # Version (UInt32) - Argon2 version 0x13
            add_entry(0x04, "V", struct.pack("<I", 0x13))
        elif self.kdf_type == KdfType.AES_KDF:
            if self.aes_kdf_rounds is None:
                raise KdfError("Missing AES-KDF rounds")

            # Rounds (UInt64)
            add_entry(0x05, "R", struct.pack("<Q", self.aes_kdf_rounds))

        # End marker
        ctx.write_u8(0x00)

        return ctx.build()
