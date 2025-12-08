"""KDBX3 payload encryption and decryption.

This module handles the cryptographic operations for KDBX3 files:
- Master key derivation from credentials (AES-KDF)
- Payload decryption and encryption
- Content hashed block verification
- Synthetic inner header creation from outer header

KDBX3 structure:
1. Outer header (plaintext, with 2-byte length fields)
2. Encrypted payload (content hashed blocks format)
   - Stream start bytes (32 bytes, for verification)
   - Compressed/uncompressed XML database content

Key differences from KDBX4:
- No header hash or HMAC verification
- Protected stream key is in outer header (not inner)
- Uses content hashed blocks instead of HMAC block stream
- No inner header inside the encrypted payload
"""

from __future__ import annotations

import gzip
import hashlib

from kdbxtool.exceptions import (
    AuthenticationError,
    CorruptedDataError,
    KdfError,
    UnsupportedVersionError,
)
from kdbxtool.security import (
    CipherContext,
    SecureBytes,
    constant_time_compare,
    derive_composite_key,
    derive_key_aes_kdf,
)
from kdbxtool.security.kdf import AesKdfConfig

from .context import ParseContext
from .header import CompressionType, KdbxHeader, KdbxVersion
from .kdbx4 import DecryptedPayload, InnerHeader


class Kdbx3Reader:
    """Reader for KDBX3 format databases.

    KDBX3 uses AES-KDF for key derivation and content hashed blocks
    for payload integrity verification.
    """

    def __init__(self, data: bytes) -> None:
        """Initialize reader with KDBX3 file data.

        Args:
            data: Complete KDBX3 file contents
        """
        self._data = data
        self._ctx = ParseContext(data)

    def decrypt(
        self,
        password: str | None = None,
        keyfile_data: bytes | None = None,
        transformed_key: bytes | None = None,
    ) -> DecryptedPayload:
        """Decrypt the KDBX3 file.

        Args:
            password: Optional password
            keyfile_data: Optional keyfile contents
            transformed_key: Optional pre-computed transformed key (skips KDF)

        Returns:
            DecryptedPayload with header, synthetic inner header, and XML

        Raises:
            AuthenticationError: If credentials are wrong
            CorruptedDataError: If file is corrupted
        """
        # Parse outer header
        header, header_end = KdbxHeader.parse(self._ctx.data)

        if header.version != KdbxVersion.KDBX3:
            raise UnsupportedVersionError(header.version.value, 0)

        self._ctx.offset = header_end

        # Use pre-computed transformed key if provided, otherwise derive it
        if transformed_key is not None:
            master_key = SecureBytes(transformed_key)
        else:
            # Derive composite key from credentials
            composite_key = derive_composite_key(
                password=password,
                keyfile_data=keyfile_data,
            )

            # Derive master key using AES-KDF
            master_key = self._derive_master_key(header, composite_key)

        # Derive cipher key
        cipher_key = self._derive_cipher_key(master_key.data, header.master_seed)

        # Read encrypted payload (everything after header)
        encrypted_payload = self._ctx.data[self._ctx.offset :]

        # Decrypt payload
        ctx = CipherContext(header.cipher, cipher_key, header.encryption_iv)
        decrypted = ctx.decrypt(encrypted_payload)

        # Remove PKCS7 padding for block ciphers
        if header.cipher.iv_size == 16:  # AES-CBC or Twofish-CBC
            decrypted = self._remove_pkcs7_padding(decrypted)

        # Verify stream start bytes (first 32 bytes)
        if len(decrypted) < 32:
            raise CorruptedDataError("Decrypted payload too short")

        stream_start = decrypted[:32]
        if header.stream_start_bytes is None:
            raise CorruptedDataError("Missing stream start bytes in header")

        if not constant_time_compare(stream_start, header.stream_start_bytes):
            raise AuthenticationError()

        # Read content hashed blocks (after stream start bytes)
        payload_data = self._read_hashed_blocks(decrypted[32:])

        # Decompress if needed
        if header.compression == CompressionType.GZIP:
            payload_data = gzip.decompress(payload_data)

        # Create synthetic inner header from outer header fields
        inner_header = self._create_synthetic_inner_header(header)

        return DecryptedPayload(
            header=header,
            inner_header=inner_header,
            xml_data=payload_data,
            transformed_key=master_key.data,
        )

    def _derive_master_key(self, header: KdbxHeader, composite_key: SecureBytes) -> SecureBytes:
        """Derive master key using AES-KDF."""
        if header.aes_kdf_rounds is None:
            raise KdfError("Missing AES-KDF rounds in header")

        aes_config = AesKdfConfig(
            salt=header.kdf_salt,
            rounds=header.aes_kdf_rounds,
        )

        return derive_key_aes_kdf(composite_key.data, aes_config)

    def _derive_cipher_key(self, master_key: bytes, master_seed: bytes) -> bytes:
        """Derive the cipher key from master key and seed.

        KDBX3 key derivation:
        - cipher_key = SHA256(master_seed || transformed_key)
        """
        return hashlib.sha256(master_seed + master_key).digest()

    def _read_hashed_blocks(self, data: bytes) -> bytes:
        """Read and verify content hashed blocks.

        KDBX3 uses content hashed blocks for integrity:
        - 4 bytes: block index (sequential, starting at 0)
        - 32 bytes: SHA-256 hash of block data
        - 4 bytes: block data length
        - N bytes: block data

        Blocks continue until block data length is 0.
        """
        result = bytearray()
        ctx = ParseContext(data)
        expected_index = 0

        with ctx.scope("hashed_blocks"):
            while not ctx.exhausted:
                with ctx.scope(f"block[{expected_index}]"):
                    # Read block index
                    block_index = ctx.read_u32("index")

                    if block_index != expected_index:
                        raise CorruptedDataError(
                            f"Block index mismatch: expected {expected_index}, got {block_index}"
                        )

                    # Read block hash
                    block_hash = ctx.read(32, "hash")

                    # Read block data length
                    block_len = ctx.read_u32("length")

                    # Check for end block
                    if block_len == 0:
                        # Verify empty block has zero hash
                        if block_hash != b"\x00" * 32:
                            raise CorruptedDataError("Invalid end block hash")
                        break

                    # Read block data
                    block_data = ctx.read(block_len, "data")

                    # Verify block hash
                    computed_hash = hashlib.sha256(block_data).digest()
                    if not constant_time_compare(computed_hash, block_hash):
                        raise CorruptedDataError(f"Block {block_index} hash mismatch")

                    result.extend(block_data)
                    expected_index += 1

        return bytes(result)

    def _create_synthetic_inner_header(self, header: KdbxHeader) -> InnerHeader:
        """Create a synthetic inner header from KDBX3 outer header fields.

        KDBX3 stores the protected stream configuration in the outer header,
        while KDBX4 has an inner header. We create a synthetic inner header
        so the rest of the code can work uniformly.
        """
        # Default to Salsa20 (stream_id=2) if not specified
        stream_id = header.inner_random_stream_id or 2

        # Protected stream key from outer header
        if header.protected_stream_key is None:
            raise CorruptedDataError("Missing protected stream key in KDBX3 header")

        return InnerHeader(
            random_stream_id=stream_id,
            random_stream_key=header.protected_stream_key,
            binaries={},  # KDBX3 stores binaries in XML, not inner header
        )

    @staticmethod
    def _remove_pkcs7_padding(data: bytes) -> bytes:
        """Remove PKCS7 padding from decrypted data."""
        if not data:
            raise CorruptedDataError("Empty decrypted data")

        pad_len = data[-1]
        if pad_len == 0 or pad_len > 16:
            raise CorruptedDataError(f"Invalid PKCS7 padding length: {pad_len}")

        # Verify all padding bytes are correct
        for i in range(1, pad_len + 1):
            if data[-i] != pad_len:
                raise CorruptedDataError("Invalid PKCS7 padding bytes")

        return data[:-pad_len]


def read_kdbx3(
    data: bytes,
    password: str | None = None,
    keyfile_data: bytes | None = None,
    transformed_key: bytes | None = None,
) -> DecryptedPayload:
    """Read and decrypt a KDBX3 database.

    Args:
        data: Complete KDBX3 file contents
        password: Optional password
        keyfile_data: Optional keyfile contents
        transformed_key: Optional pre-computed transformed key (skips KDF)

    Returns:
        DecryptedPayload containing header, inner header, and XML data

    Raises:
        AuthenticationError: If credentials are wrong
        CorruptedDataError: If file is corrupted
        UnsupportedVersionError: If file is not KDBX3
    """
    reader = Kdbx3Reader(data)
    return reader.decrypt(
        password=password,
        keyfile_data=keyfile_data,
        transformed_key=transformed_key,
    )
