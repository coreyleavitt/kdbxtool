# kdbxtool

A modern, secure Python library for reading and writing KeePass KDBX databases.

## Features

- **Secure by default**: Memory zeroization, constant-time comparisons, hardened XML parsing
- **Type-safe**: Full type hints, Python 3.12+ features, mypy strict compatible
- **Modern API**: Clean, Pythonic interface with context manager support
- **KDBX4 focused**: First-class support for modern KeePass format with Argon2id

## Installation

```bash
pip install kdbxtool
```

## Quick Start

```python
from kdbxtool import Database, Credentials

# Open a database
creds = Credentials(password="my-password")
with Database.open("vault.kdbx", creds) as db:
    # Find entries
    entry = db.entries.find(title="Gmail").first()
    print(f"Username: {entry.username}")

    # Create new entries
    db.root_group.add_entry(
        title="New Account",
        username="user@example.com",
        password="secure-password"
    )

    db.save()
```

## Security

kdbxtool prioritizes security:

- **SecureBytes**: Sensitive data is stored in zeroizable buffers
- **Constant-time comparisons**: All authentication uses `hmac.compare_digest`
- **Hardened XML**: Uses defusedxml to prevent XXE attacks
- **Modern KDF**: Enforces minimum Argon2 parameters

## License

MIT
