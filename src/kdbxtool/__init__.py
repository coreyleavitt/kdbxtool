"""kdbxtool - A modern, secure Python library for KeePass KDBX databases.

This library provides a clean, type-safe API for reading and writing KeePass
database files (KDBX format). It prioritizes security with:
- Secure memory handling (zeroization of sensitive data)
- Constant-time comparisons for authentication
- Modern cryptographic defaults (Argon2id, ChaCha20)

Example:
    from kdbxtool import Database

    db = Database.open("vault.kdbx", password="secret")
    entry = db.find_entries(title="Gmail")[0]
    print(entry.username)

    # Create new entry
    db.root_group.create_entry(
        title="New Site",
        username="user",
        password="pass123",
    )
    db.save()
"""

__version__ = "0.1.0"

from .database import Database, DatabaseSettings
from .models import Entry, Group, HistoryEntry, Times
from .security import Cipher, KdfType

__all__ = [
    "Database",
    "DatabaseSettings",
    "Entry",
    "Group",
    "HistoryEntry",
    "Times",
    "Cipher",
    "KdfType",
]
