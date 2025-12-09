# kdbxtool

A modern, secure Python library for reading and writing KeePass KDBX databases.

```{toctree}
:maxdepth: 2
:caption: Contents

getting-started
api
```

## Quick Start

```python
from kdbxtool import Database

with Database.open("vault.kdbx", password="secret") as db:
    entries = db.find_entries(title="Gmail")
    print(entries[0].username)
```

## Features

- **Secure by default**: Memory zeroization, constant-time comparisons
- **Type-safe**: Full type hints, Python 3.12+
- **KDBX4 focused**: Modern KeePass format with Argon2d KDF
- **Multiple ciphers**: AES-256-CBC, ChaCha20, Twofish (optional)
- **YubiKey support**: HMAC-SHA1 challenge-response authentication

## Installation

```bash
pip install kdbxtool
```

### Optional Dependencies

```bash
# Twofish cipher support (for legacy databases)
pip install kdbxtool[twofish]

# YubiKey support
pip install kdbxtool[yubikey]
```
