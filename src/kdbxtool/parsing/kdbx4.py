"""KDBX4 payload encryption and decryption.

This module handles the cryptographic operations for KDBX4 files:
- Master key derivation from credentials
- Header integrity verification (HMAC-SHA256)
- Payload decryption and encryption
- Block-based HMAC verification (HmacBlockStream)
- Inner header parsing

KDBX4 structure:
1. Outer header (plaintext)
2. SHA-256 hash of header
3. HMAC-SHA256 of header
4. Encrypted payload (HmacBlockStream format)
   - Inner header
   - XML database content
"""

from __future__ import annotations

import gzip
import hashlib
import struct
import warnings
from dataclasses import dataclass
from typing import TYPE_CHECKING

from kdbxtool.exceptions import (
    AuthenticationError,
    CorruptedDataError,
    DecryptionError,
    KdfError,
    UnsupportedVersionError,
)
from kdbxtool.security import (
    Argon2Config,
    CipherContext,
    SecureBytes,
    compute_hmac_sha256,
    constant_time_compare,
    derive_composite_key,
    derive_key_aes_kdf,
    derive_key_argon2,
)
from kdbxtool.security.kdf import AesKdfConfig, KdfType

from .context import BuildContext, ParseContext
from .header import (
    CompressionType,
    InnerHeaderFieldType,
    KdbxHeader,
    KdbxVersion,
)

if TYPE_CHECKING:
    pass

# Maximum size for a single binary attachment (512 MiB)
# Prevents memory exhaustion from malicious KDBX files
MAX_BINARY_SIZE = 512 * 1024 * 1024


@dataclass(slots=True)
class InnerHeader:
    """KDBX4 inner header data.

    The inner header appears after decryption, before the XML payload.
    It contains the protected stream cipher settings and binary attachments.
    """

    # Random stream for protected values (e.g., passwords in XML)
    random_stream_id: int
    random_stream_key: bytes

    # Binary attachments (id -> data with protection flag)
    binaries: dict[int, tuple[bool, bytes]]


@dataclass(slots=True)
class DecryptedPayload:
    """Result of decrypting a KDBX4 file.

    Contains all data needed to work with the database.
    """

    header: KdbxHeader
    inner_header: InnerHeader
    xml_data: bytes
    transformed_key: bytes | None = None  # For caching to speed up repeated opens


class Kdbx4Reader:
    """Reader for KDBX4 database files."""

    def __init__(self, data: bytes) -> None:
        """Initialize reader with file data.

        Args:
            data: Complete KDBX4 file contents
        """
        self._ctx = ParseContext(data)

    def decrypt(
        self,
        password: str | None = None,
        keyfile_data: bytes | None = None,
        transformed_key: bytes | None = None,
        yubikey_response: bytes | None = None,
    ) -> DecryptedPayload:
        """Decrypt the KDBX4 file.

        Args:
            password: Optional password
            keyfile_data: Optional keyfile contents
            transformed_key: Optional precomputed transformed key (skips KDF)
            yubikey_response: Optional 20-byte YubiKey HMAC-SHA1 response

        Returns:
            DecryptedPayload with header, inner header, XML, and transformed_key

        Raises:
            ValueError: If decryption fails (wrong credentials, corrupted file)
        """
        # Parse outer header
        header, header_end = KdbxHeader.parse(self._ctx.data)

        if header.version != KdbxVersion.KDBX4:
            raise UnsupportedVersionError(header.version.value, 0)

        self._ctx.offset = header_end

        # Read header hash and HMAC
        with self._ctx.scope("header_verification"):
            header_hash = self._ctx.read(32, "header_hash")
            header_hmac = self._ctx.read(32, "header_hmac")

        # Verify header hash
        computed_hash = hashlib.sha256(header.raw_header).digest()
        if not constant_time_compare(computed_hash, header_hash):
            raise CorruptedDataError("Header hash mismatch - file may be corrupted")

        # Get transformed key - either use provided one or derive via KDF
        if transformed_key is not None:
            # Use precomputed transformed key (skips expensive KDF)
            master_key_bytes = transformed_key
        else:
            # Derive composite key from credentials
            # KeePassXC: YubiKey response is incorporated into composite key
            composite_key = derive_composite_key(
                password=password,
                keyfile_data=keyfile_data,
                yubikey_response=yubikey_response,
            )
            # Derive master key using KDF (slow)
            master_key = self._derive_master_key(header, composite_key)
            master_key_bytes = master_key.data

        # Derive keys for HMAC and encryption
        hmac_key, cipher_key = self._derive_keys(master_key_bytes, header.master_seed)

        # Verify header HMAC
        block_key = self._compute_block_hmac_key(hmac_key, 0xFFFFFFFFFFFFFFFF)
        computed_hmac = compute_hmac_sha256(block_key, header.raw_header)
        if not constant_time_compare(computed_hmac, header_hmac):
            raise AuthenticationError()

        # Read and verify HMAC block stream
        encrypted_payload = self._read_hmac_block_stream(hmac_key)

        # Decrypt payload
        ctx = CipherContext(header.cipher, cipher_key, header.encryption_iv)
        decrypted = ctx.decrypt(encrypted_payload)

        # Remove PKCS7 padding for AES-CBC
        if header.cipher.iv_size == 16:  # AES-CBC
            decrypted = self._remove_pkcs7_padding(decrypted)

        # Decompress if needed
        if header.compression == CompressionType.GZIP:
            decrypted = gzip.decompress(decrypted)

        # Parse inner header
        inner_header, xml_start = self._parse_inner_header(decrypted)

        # Extract XML
        xml_data = decrypted[xml_start:]

        return DecryptedPayload(
            header=header,
            inner_header=inner_header,
            xml_data=xml_data,
            transformed_key=master_key_bytes,
        )

    def _derive_master_key(self, header: KdbxHeader, composite_key: SecureBytes) -> SecureBytes:
        """Derive master key using the KDF specified in header."""
        if header.kdf_type in (KdfType.ARGON2ID, KdfType.ARGON2D):
            if (
                header.argon2_memory_kib is None
                or header.argon2_iterations is None
                or header.argon2_parallelism is None
            ):
                raise KdfError("Missing Argon2 parameters in header")

            argon2_config = Argon2Config(
                memory_kib=header.argon2_memory_kib,
                iterations=header.argon2_iterations,
                parallelism=header.argon2_parallelism,
                salt=header.kdf_salt,
                variant=header.kdf_type,
            )
            # Warn if parameters are below security minimums
            try:
                argon2_config.validate_security()
            except KdfError as e:
                warnings.warn(
                    f"Database has weak KDF parameters: {e}. "
                    "Consider re-saving with stronger settings.",
                    UserWarning,
                    stacklevel=4,
                )
            # Don't enforce minimums when reading - accept what the file has
            return derive_key_argon2(composite_key.data, argon2_config, enforce_minimums=False)
        elif header.kdf_type == KdfType.AES_KDF:
            if header.aes_kdf_rounds is None:
                raise KdfError("Missing AES-KDF rounds in header")
            aes_config = AesKdfConfig(
                rounds=header.aes_kdf_rounds,
                salt=header.kdf_salt,
            )
            return derive_key_aes_kdf(composite_key.data, aes_config)
        else:
            raise KdfError(f"Unsupported KDF: {header.kdf_type}")

    def _derive_keys(self, transformed_key: bytes, master_seed: bytes) -> tuple[bytes, bytes]:
        """Derive HMAC key and cipher key from transformed key.

        KDBX4 key derivation:
        - cipher_key = SHA256(master_seed || transformed_key)
        - hmac_key = SHA512(master_seed || transformed_key || 0x01)
        """
        cipher_key = hashlib.sha256(master_seed + transformed_key).digest()
        hmac_key = hashlib.sha512(master_seed + transformed_key + b"\x01").digest()

        return hmac_key, cipher_key

    def _compute_block_hmac_key(self, hmac_key: bytes, block_index: int) -> bytes:
        """Compute HMAC key for a specific block.

        Each block uses a different key derived from the master HMAC key.
        key = SHA512(block_index_le64 || hmac_key)
        """
        index_bytes = struct.pack("<Q", block_index)
        return hashlib.sha512(index_bytes + hmac_key).digest()

    def _read_hmac_block_stream(self, hmac_key: bytes) -> bytes:
        """Read and verify HMAC block stream.

        KDBX4 uses a block-based format with per-block HMAC:
        - 32 bytes: HMAC of (block_index || length || data)
        - 4 bytes: block length (little-endian)
        - N bytes: block data

        Last block has length 0.
        """
        blocks = []
        block_index = 0

        with self._ctx.scope("hmac_blocks"):
            while True:
                with self._ctx.scope(f"block[{block_index}]"):
                    block_hmac = self._ctx.read(32, "hmac")
                    block_len = self._ctx.read_u32("length")

                    if block_len == 0:
                        # Verify final block HMAC
                        block_key = self._compute_block_hmac_key(hmac_key, block_index)
                        expected = compute_hmac_sha256(
                            block_key,
                            struct.pack("<Q", block_index) + struct.pack("<I", 0),
                        )
                        if not constant_time_compare(expected, block_hmac):
                            raise AuthenticationError("Block authentication failed")
                        break

                    block_data = self._ctx.read(block_len, "data")

                    # Verify block HMAC
                    block_key = self._compute_block_hmac_key(hmac_key, block_index)
                    hmac_data = (
                        struct.pack("<Q", block_index) + struct.pack("<I", block_len) + block_data
                    )
                    expected = compute_hmac_sha256(block_key, hmac_data)

                    if not constant_time_compare(expected, block_hmac):
                        raise AuthenticationError("Block authentication failed")

                    blocks.append(block_data)
                    block_index += 1

        return b"".join(blocks)

    def _remove_pkcs7_padding(self, data: bytes) -> bytes:
        """Remove PKCS7 padding from decrypted data.

        Note: Padding oracle attacks are not possible here because HMAC
        verification on the ciphertext occurs BEFORE decryption. Any
        ciphertext modification would fail HMAC verification first.
        We still use generic error messages for defense-in-depth.
        """
        if not data:
            raise DecryptionError()
        padding_len = data[-1]
        if padding_len == 0 or padding_len > 16:
            raise DecryptionError()
        # Verify all padding bytes are correct
        for i in range(1, padding_len + 1):
            if data[-i] != padding_len:
                raise DecryptionError()
        return data[:-padding_len]

    def _parse_inner_header(self, data: bytes) -> tuple[InnerHeader, int]:
        """Parse KDBX4 inner header.

        Returns inner header and offset where XML starts.
        """
        ctx = ParseContext(data)
        random_stream_id = 0
        random_stream_key = b""
        binaries: dict[int, tuple[bool, bytes]] = {}
        binary_index = 0

        with ctx.scope("inner_header"):
            while not ctx.exhausted:
                field_type = ctx.read_u8("type")
                field_len = ctx.read_u32("length")
                field_data = ctx.read(field_len, "data")

                if field_type == InnerHeaderFieldType.END:
                    break
                elif field_type == InnerHeaderFieldType.INNER_RANDOM_STREAM_ID:
                    random_stream_id = struct.unpack("<I", field_data)[0]
                elif field_type == InnerHeaderFieldType.INNER_RANDOM_STREAM_KEY:
                    random_stream_key = field_data
                elif field_type == InnerHeaderFieldType.BINARY:
                    # First byte is protection flag
                    binary_data = field_data[1:]
                    if len(binary_data) > MAX_BINARY_SIZE:
                        raise CorruptedDataError(
                            f"Binary attachment too large: {len(binary_data)} bytes "
                            f"(max {MAX_BINARY_SIZE} bytes)"
                        )
                    protected = field_data[0] != 0
                    binaries[binary_index] = (protected, binary_data)
                    binary_index += 1

        return (
            InnerHeader(
                random_stream_id=random_stream_id,
                random_stream_key=random_stream_key,
                binaries=binaries,
            ),
            ctx.offset,
        )


class Kdbx4Writer:
    """Writer for KDBX4 database files."""

    # Default block size for HMAC block stream (1 MiB)
    BLOCK_SIZE = 1024 * 1024

    def encrypt(
        self,
        header: KdbxHeader,
        inner_header: InnerHeader,
        xml_data: bytes,
        password: str | None = None,
        keyfile_data: bytes | None = None,
        transformed_key: bytes | None = None,
        yubikey_response: bytes | None = None,
    ) -> bytes:
        """Encrypt database to KDBX4 format.

        Args:
            header: Outer header configuration
            inner_header: Inner header with stream cipher and binaries
            xml_data: XML database content
            password: Optional password
            keyfile_data: Optional keyfile contents
            transformed_key: Optional precomputed transformed key (skips KDF)
            yubikey_response: Optional 20-byte YubiKey HMAC-SHA1 response

        Returns:
            Complete KDBX4 file as bytes
        """
        if header.version != KdbxVersion.KDBX4:
            raise UnsupportedVersionError(header.version.value, 0)

        # Get transformed key - either use provided one or derive via KDF
        if transformed_key is not None:
            # Use precomputed transformed key (skips expensive KDF)
            master_key_bytes = transformed_key
        else:
            # Derive composite key from credentials
            # KeePassXC: YubiKey response is incorporated into composite key
            composite_key = derive_composite_key(
                password=password,
                keyfile_data=keyfile_data,
                yubikey_response=yubikey_response,
            )
            # Derive master key using KDF (slow)
            master_key = self._derive_master_key(header, composite_key)
            master_key_bytes = master_key.data

        # Derive keys for HMAC and encryption
        hmac_key, cipher_key = self._derive_keys(master_key_bytes, header.master_seed)

        # Build inner header
        inner_header_bytes = self._build_inner_header(inner_header)

        # Combine inner header and XML
        payload = inner_header_bytes + xml_data

        # Compress if needed
        if header.compression == CompressionType.GZIP:
            payload = gzip.compress(payload, compresslevel=6)

        # Add PKCS7 padding for AES-CBC
        if header.cipher.iv_size == 16:  # AES-CBC
            payload = self._add_pkcs7_padding(payload)

        # Encrypt payload
        ctx = CipherContext(header.cipher, cipher_key, header.encryption_iv)
        encrypted_payload = ctx.encrypt(payload)

        # Build HMAC block stream
        hmac_blocks = self._build_hmac_block_stream(encrypted_payload, hmac_key)

        # Build outer header
        header_bytes = header.to_bytes()

        # Compute header hash and HMAC
        header_hash = hashlib.sha256(header_bytes).digest()
        block_key = self._compute_block_hmac_key(hmac_key, 0xFFFFFFFFFFFFFFFF)
        header_hmac = compute_hmac_sha256(block_key, header_bytes)

        # Assemble final file
        return header_bytes + header_hash + header_hmac + hmac_blocks

    def _derive_master_key(self, header: KdbxHeader, composite_key: SecureBytes) -> SecureBytes:
        """Derive master key using the KDF specified in header."""
        if header.kdf_type in (KdfType.ARGON2ID, KdfType.ARGON2D):
            if (
                header.argon2_memory_kib is None
                or header.argon2_iterations is None
                or header.argon2_parallelism is None
            ):
                raise KdfError("Missing Argon2 parameters in header")

            config = Argon2Config(
                memory_kib=header.argon2_memory_kib,
                iterations=header.argon2_iterations,
                parallelism=header.argon2_parallelism,
                salt=header.kdf_salt,
                variant=header.kdf_type,
            )
            return derive_key_argon2(composite_key.data, config)
        elif header.kdf_type == KdfType.AES_KDF:
            if header.aes_kdf_rounds is None:
                raise KdfError("Missing AES-KDF rounds in header")

            aes_config = AesKdfConfig(
                rounds=header.aes_kdf_rounds,
                salt=header.kdf_salt,
            )
            return derive_key_aes_kdf(composite_key.data, aes_config)
        else:
            raise KdfError(f"Unsupported KDF for writing: {header.kdf_type}")

    def _derive_keys(self, transformed_key: bytes, master_seed: bytes) -> tuple[bytes, bytes]:
        """Derive HMAC key and cipher key from transformed key."""
        cipher_key = hashlib.sha256(master_seed + transformed_key).digest()
        hmac_key = hashlib.sha512(master_seed + transformed_key + b"\x01").digest()
        return hmac_key, cipher_key

    def _compute_block_hmac_key(self, hmac_key: bytes, block_index: int) -> bytes:
        """Compute HMAC key for a specific block."""
        index_bytes = struct.pack("<Q", block_index)
        return hashlib.sha512(index_bytes + hmac_key).digest()

    def _build_inner_header(self, inner: InnerHeader) -> bytes:
        """Build inner header bytes."""
        ctx = BuildContext()

        # Random stream ID
        ctx.write_tlv(
            InnerHeaderFieldType.INNER_RANDOM_STREAM_ID,
            struct.pack("<I", inner.random_stream_id),
        )

        # Random stream key
        ctx.write_tlv(
            InnerHeaderFieldType.INNER_RANDOM_STREAM_KEY,
            inner.random_stream_key,
        )

        # Binary attachments
        for _idx, (protected, data) in sorted(inner.binaries.items()):
            binary_data = bytes([1 if protected else 0]) + data
            ctx.write_tlv(InnerHeaderFieldType.BINARY, binary_data)

        # End marker
        ctx.write_tlv(InnerHeaderFieldType.END, b"")

        return ctx.build()

    def _add_pkcs7_padding(self, data: bytes) -> bytes:
        """Add PKCS7 padding to make data a multiple of 16 bytes."""
        padding_len = 16 - (len(data) % 16)
        padding = bytes([padding_len] * padding_len)
        return data + padding

    def _build_hmac_block_stream(self, data: bytes, hmac_key: bytes) -> bytes:
        """Build HMAC block stream from data."""
        ctx = BuildContext()
        block_index = 0
        offset = 0

        while offset < len(data):
            block_data = data[offset : offset + self.BLOCK_SIZE]
            block_len = len(block_data)
            offset += block_len

            # Compute block HMAC
            block_key = self._compute_block_hmac_key(hmac_key, block_index)
            hmac_data = struct.pack("<Q", block_index) + struct.pack("<I", block_len) + block_data
            block_hmac = compute_hmac_sha256(block_key, hmac_data)

            ctx.write(block_hmac)
            ctx.write_u32(block_len)
            ctx.write(block_data)

            block_index += 1

        # Final empty block
        block_key = self._compute_block_hmac_key(hmac_key, block_index)
        final_hmac = compute_hmac_sha256(
            block_key,
            struct.pack("<Q", block_index) + struct.pack("<I", 0),
        )
        ctx.write(final_hmac)
        ctx.write_u32(0)

        return ctx.build()


def read_kdbx4(
    data: bytes,
    password: str | None = None,
    keyfile_data: bytes | None = None,
    transformed_key: bytes | None = None,
    yubikey_response: bytes | None = None,
) -> DecryptedPayload:
    """Convenience function to read a KDBX4 file.

    Args:
        data: Complete file contents
        password: Optional password
        keyfile_data: Optional keyfile contents
        transformed_key: Optional precomputed transformed key (skips KDF)
        yubikey_response: Optional 20-byte YubiKey HMAC-SHA1 response

    Returns:
        DecryptedPayload with header, inner header, XML, and transformed_key
    """
    reader = Kdbx4Reader(data)
    return reader.decrypt(
        password=password,
        keyfile_data=keyfile_data,
        transformed_key=transformed_key,
        yubikey_response=yubikey_response,
    )


def write_kdbx4(
    header: KdbxHeader,
    inner_header: InnerHeader,
    xml_data: bytes,
    password: str | None = None,
    keyfile_data: bytes | None = None,
    transformed_key: bytes | None = None,
    yubikey_response: bytes | None = None,
) -> bytes:
    """Convenience function to write a KDBX4 file.

    Args:
        header: Outer header configuration
        inner_header: Inner header with stream cipher and binaries
        xml_data: XML database content
        password: Optional password
        keyfile_data: Optional keyfile contents
        transformed_key: Optional precomputed transformed key (skips KDF)
        yubikey_response: Optional 20-byte YubiKey HMAC-SHA1 response

    Returns:
        Complete KDBX4 file as bytes
    """
    writer = Kdbx4Writer()
    return writer.encrypt(
        header=header,
        inner_header=inner_header,
        xml_data=xml_data,
        password=password,
        keyfile_data=keyfile_data,
        transformed_key=transformed_key,
        yubikey_response=yubikey_response,
    )
