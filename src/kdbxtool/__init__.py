"""kdbxtool - A modern, secure Python library for KeePass KDBX databases.

This library provides a clean, type-safe API for reading and writing KeePass
database files (KDBX format). It prioritizes security with:
- Secure memory handling (zeroization of sensitive data)
- Constant-time comparisons for authentication
- Modern cryptographic defaults (Argon2id, ChaCha20)

Example:
    from kdbxtool import Database, Credentials

    creds = Credentials(password="secret")
    with Database.open("vault.kdbx", creds) as db:
        entry = db.entries.find(title="Gmail").first()
        print(entry.username)
"""

__version__ = "0.1.0"

# Public API will be exported here as modules are implemented
__all__: list[str] = []
