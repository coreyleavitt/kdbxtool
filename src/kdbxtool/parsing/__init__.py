"""KDBX binary format parsing and building.

This module handles low-level binary format operations:
- Header parsing and validation
- KDBX4 payload encryption/decryption
- XML payload handling

All parsing uses context classes for structured binary operations.
"""

from .context import BuildContext, ParseContext
from .header import (
    KDBX4_MAGIC,
    KDBX_MAGIC,
    CompressionType,
    HeaderFieldType,
    InnerHeaderFieldType,
    KdbxHeader,
    KdbxVersion,
)
from .kdbx3 import Kdbx3Reader, read_kdbx3
from .kdbx4 import (
    DecryptedPayload,
    InnerHeader,
    Kdbx4Reader,
    Kdbx4Writer,
    read_kdbx4,
    write_kdbx4,
)

__all__ = [
    # Context
    "BuildContext",
    "ParseContext",
    # Header
    "KDBX4_MAGIC",
    "KDBX_MAGIC",
    "CompressionType",
    "HeaderFieldType",
    "InnerHeaderFieldType",
    "KdbxHeader",
    "KdbxVersion",
    # KDBX3
    "Kdbx3Reader",
    "read_kdbx3",
    # KDBX4
    "DecryptedPayload",
    "InnerHeader",
    "Kdbx4Reader",
    "Kdbx4Writer",
    "read_kdbx4",
    "write_kdbx4",
]
