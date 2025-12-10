"""KeePass keyfile creation and parsing.

This module provides support for all KeePass keyfile formats:
- XML v2.0: Recommended format with hex-encoded key and SHA-256 hash verification
- XML v1.0: Legacy format with base64-encoded key
- RAW_32: Raw 32-byte binary key
- HEX_64: 64-character hex string

Example:
    from kdbxtool import create_keyfile, KeyFileVersion

    # Create recommended XML v2.0 keyfile
    create_keyfile("my.keyx", version=KeyFileVersion.XML_V2)

    # Create raw 32-byte keyfile
    create_keyfile("my.key", version=KeyFileVersion.RAW_32)
"""

from __future__ import annotations

import hashlib
import os
from enum import StrEnum
from pathlib import Path

from kdbxtool.exceptions import InvalidKeyFileError

from .crypto import constant_time_compare


class KeyFileVersion(StrEnum):
    """Supported KeePass keyfile formats.

    Attributes:
        XML_V2: XML format v2.0 with hex-encoded key and SHA-256 hash verification.
            This is the recommended format for new keyfiles. Uses .keyx extension.
        XML_V1: Legacy XML format v1.0 with base64-encoded key.
            Supported for compatibility. Uses .key extension.
        RAW_32: Raw 32-byte binary key. Simple but no integrity verification.
        HEX_64: 64-character hex string (32 bytes encoded as hex).
    """

    XML_V2 = "xml_v2"
    XML_V1 = "xml_v1"
    RAW_32 = "raw_32"
    HEX_64 = "hex_64"


def create_keyfile_bytes(version: KeyFileVersion = KeyFileVersion.XML_V2) -> bytes:
    """Create a new keyfile and return its contents as bytes.

    Generates a cryptographically secure 32-byte random key and encodes it
    in the specified format.

    Args:
        version: Keyfile format to use. Defaults to XML_V2 (recommended).

    Returns:
        Keyfile contents as bytes, ready to write to a file.

    Example:
        keyfile_data = create_keyfile_bytes(KeyFileVersion.XML_V2)
        with open("my.keyx", "wb") as f:
            f.write(keyfile_data)
    """
    # Generate 32 bytes of cryptographically secure random data
    key_bytes = os.urandom(32)

    if version == KeyFileVersion.XML_V2:
        return _create_xml_v2(key_bytes)
    elif version == KeyFileVersion.XML_V1:
        return _create_xml_v1(key_bytes)
    elif version == KeyFileVersion.RAW_32:
        return key_bytes
    elif version == KeyFileVersion.HEX_64:
        return key_bytes.hex().encode("ascii")
    else:
        raise ValueError(f"Unknown keyfile version: {version}")


def create_keyfile(
    path: str | Path,
    version: KeyFileVersion = KeyFileVersion.XML_V2,
) -> None:
    """Create a new keyfile at the specified path.

    Generates a cryptographically secure 32-byte random key and saves it
    in the specified format.

    Args:
        path: Path where the keyfile will be created.
        version: Keyfile format to use. Defaults to XML_V2 (recommended).

    Raises:
        OSError: If the file cannot be written.

    Example:
        # Create XML v2.0 keyfile (recommended)
        create_keyfile("vault.keyx")

        # Create raw binary keyfile
        create_keyfile("vault.key", version=KeyFileVersion.RAW_32)
    """
    keyfile_data = create_keyfile_bytes(version)
    Path(path).write_bytes(keyfile_data)


def parse_keyfile(keyfile_data: bytes) -> bytes:
    """Parse keyfile data and extract the 32-byte key.

    KeePass supports several keyfile formats:
    1. XML keyfile (v1.0 or v2.0) - key is base64/hex encoded in XML
    2. 32-byte raw binary - used directly
    3. 64-byte hex string - decoded from hex
    4. Any other size - SHA-256 hashed

    Args:
        keyfile_data: Raw keyfile contents.

    Returns:
        32-byte key derived from keyfile.

    Raises:
        InvalidKeyFileError: If keyfile format is invalid or hash verification fails.
    """
    # Try parsing as XML keyfile
    try:
        import base64

        import defusedxml.ElementTree as ET

        tree = ET.fromstring(keyfile_data)
        version_elem = tree.find("Meta/Version")
        data_elem = tree.find("Key/Data")

        if version_elem is not None and data_elem is not None:
            version = version_elem.text or ""
            if version.startswith("1.0"):
                # Version 1.0: base64 encoded
                return base64.b64decode(data_elem.text or "")
            elif version.startswith("2.0"):
                # Version 2.0: hex encoded with hash verification
                key_hex = (data_elem.text or "").strip()
                key_bytes = bytes.fromhex(key_hex)
                # Verify hash if present (constant-time comparison)
                if "Hash" in data_elem.attrib:
                    expected_hash = bytes.fromhex(data_elem.attrib["Hash"])
                    computed_hash = hashlib.sha256(key_bytes).digest()[:4]
                    if not constant_time_compare(expected_hash, computed_hash):
                        raise InvalidKeyFileError("Keyfile hash verification failed")
                return key_bytes
    except (ET.ParseError, ValueError, AttributeError):
        pass  # Not an XML keyfile

    # Check for raw 32-byte key
    if len(keyfile_data) == 32:
        return keyfile_data

    # Check for 64-byte hex-encoded key
    if len(keyfile_data) == 64:
        try:
            # Verify it's valid hex
            int(keyfile_data, 16)
            return bytes.fromhex(keyfile_data.decode("ascii"))
        except (ValueError, UnicodeDecodeError):
            pass  # Not hex

    # Hash anything else
    return hashlib.sha256(keyfile_data).digest()


def _create_xml_v2(key_bytes: bytes) -> bytes:
    """Create XML v2.0 keyfile content.

    Format:
        <?xml version="1.0" encoding="utf-8"?>
        <KeyFile>
            <Meta>
                <Version>2.0</Version>
            </Meta>
            <Key>
                <Data Hash="XXXXXXXX">hex-encoded-key</Data>
            </Key>
        </KeyFile>

    The Hash attribute contains the first 4 bytes of SHA-256(key) as hex.
    """
    key_hex = key_bytes.hex().upper()
    hash_hex = hashlib.sha256(key_bytes).digest()[:4].hex().upper()

    xml = f"""<?xml version="1.0" encoding="utf-8"?>
<KeyFile>
\t<Meta>
\t\t<Version>2.0</Version>
\t</Meta>
\t<Key>
\t\t<Data Hash="{hash_hex}">{key_hex}</Data>
\t</Key>
</KeyFile>
"""
    return xml.encode("utf-8")


def _create_xml_v1(key_bytes: bytes) -> bytes:
    """Create XML v1.0 keyfile content.

    Format:
        <?xml version="1.0" encoding="utf-8"?>
        <KeyFile>
            <Meta>
                <Version>1.00</Version>
            </Meta>
            <Key>
                <Data>base64-encoded-key</Data>
            </Key>
        </KeyFile>
    """
    import base64

    key_b64 = base64.b64encode(key_bytes).decode("ascii")

    xml = f"""<?xml version="1.0" encoding="utf-8"?>
<KeyFile>
\t<Meta>
\t\t<Version>1.00</Version>
\t</Meta>
\t<Key>
\t\t<Data>{key_b64}</Data>
\t</Key>
</KeyFile>
"""
    return xml.encode("utf-8")
