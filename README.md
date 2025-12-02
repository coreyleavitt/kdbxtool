# kdbxtool

[![CI](https://github.com/coreyleavitt/kdbxtool/actions/workflows/ci.yml/badge.svg)](https://github.com/coreyleavitt/kdbxtool/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-report-blue.svg)](https://coreyleavitt.github.io/kdbxtool/coverage/htmlcov/)
[![Type Coverage](https://img.shields.io/badge/mypy-strict-blue.svg)](https://coreyleavitt.github.io/kdbxtool/mypy/)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

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
from kdbxtool import Database

# Open a database with context manager
with Database.open("vault.kdbx", password="my-password") as db:
    # Find entries
    entries = db.find_entries(title="Gmail")
    if entries:
        print(f"Username: {entries[0].username}")

    # Create new entries
    db.root_group.create_entry(
        title="New Account",
        username="user@example.com",
        password="secure-password",
    )

    db.save()

# Create a new database
db = Database.create(password="my-password", database_name="My Vault")
db.root_group.create_entry(title="First Entry", username="me", password="secret")
db.save("my-vault.kdbx")
```

## Security

kdbxtool prioritizes security:

- **SecureBytes**: Sensitive data is stored in zeroizable buffers
- **Constant-time comparisons**: All authentication uses `hmac.compare_digest`
- **Hardened XML**: Uses defusedxml to prevent XXE attacks
- **Modern KDF**: Enforces minimum Argon2 parameters

## License

MIT
