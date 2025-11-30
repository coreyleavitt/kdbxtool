"""KDBX binary format parsing and building.

This module handles low-level binary format operations:
- Header parsing and validation
- KDBX4 payload encryption/decryption
- XML payload handling

All parsing uses Python's struct module for binary operations.
"""

from .header import (
    KDBX4_MAGIC,
    KDBX_MAGIC,
    CompressionType,
    HeaderFieldType,
    InnerHeaderFieldType,
    KdbxHeader,
    KdbxVersion,
)
from .kdbx4 import (
    DecryptedPayload,
    InnerHeader,
    Kdbx4Reader,
    Kdbx4Writer,
    read_kdbx4,
    write_kdbx4,
)

__all__ = [
    # Header
    "KDBX4_MAGIC",
    "KDBX_MAGIC",
    "CompressionType",
    "HeaderFieldType",
    "InnerHeaderFieldType",
    "KdbxHeader",
    "KdbxVersion",
    # KDBX4
    "DecryptedPayload",
    "InnerHeader",
    "Kdbx4Reader",
    "Kdbx4Writer",
    "read_kdbx4",
    "write_kdbx4",
]
