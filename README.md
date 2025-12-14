# kdbxtool

[![CI](https://github.com/coreyleavitt/kdbxtool/actions/workflows/ci.yml/badge.svg)](https://github.com/coreyleavitt/kdbxtool/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://coreyleavitt.github.io/kdbxtool/reports/coverage/coverage-badge.json)](https://coreyleavitt.github.io/kdbxtool/reports/coverage/htmlcov/)
[![mypy](https://img.shields.io/endpoint?url=https://coreyleavitt.github.io/kdbxtool/reports/mypy/mypy-badge.json)](https://coreyleavitt.github.io/kdbxtool/reports/mypy/)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://coreyleavitt.github.io/kdbxtool/latest/)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A modern, secure Python library for reading and writing KeePass KDBX databases.

## Features

- **Secure by default**: Memory zeroization, constant-time comparisons, hardened XML parsing
- **Type-safe**: Full type hints, Python 3.12+ features, mypy strict compatible
- **Modern API**: Clean, Pythonic interface with context manager support
- **KDBX4 focused**: First-class support for modern KeePass format with Argon2
- **Multiple ciphers**: AES-256-CBC, ChaCha20, and Twofish-256-CBC (optional)

## Installation

```bash
pip install kdbxtool
```

### Optional: Twofish Support

For legacy databases encrypted with Twofish-256-CBC:

```bash
pip install kdbxtool[twofish]
```

This installs [oxifish](https://github.com/coreyleavitt/oxifish), a Rust-based Twofish implementation.

### Optional: YubiKey Support

For hardware-backed authentication with YubiKey HMAC-SHA1 challenge-response:

```bash
pip install kdbxtool[yubikey]
```

This installs [yubikey-manager](https://github.com/Yubico/yubikey-manager) for YubiKey communication.

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

## Keyfile Support

kdbxtool supports all KeePass keyfile formats for two-factor authentication:

```python
from kdbxtool import Database, create_keyfile, KeyFileVersion

# Create a new keyfile (XML v2.0 recommended)
create_keyfile("vault.keyx")  # Default: XML v2.0 with hash verification

# Other formats available
create_keyfile("vault.key", version=KeyFileVersion.XML_V1)   # Legacy XML
create_keyfile("vault.key", version=KeyFileVersion.RAW_32)   # Raw 32 bytes
create_keyfile("vault.key", version=KeyFileVersion.HEX_64)   # Hex-encoded

# Open a database with password + keyfile
with Database.open("vault.kdbx", password="my-password", keyfile="vault.keyx") as db:
    print(f"Entries: {len(db.find_entries())}")

# Create a new database with keyfile protection
db = Database.create(password="my-password", keyfile="vault.keyx")
db.save("protected.kdbx")

# Keyfile-only authentication (no password)
db = Database.create(keyfile="vault.keyx")
db.save("keyfile-only.kdbx")
```

## YubiKey Support

kdbxtool supports YubiKey HMAC-SHA1 challenge-response authentication, compatible with KeePassXC:

```python
from kdbxtool import Database
from kdbxtool.security import list_yubikeys

# List connected YubiKeys (raises YubiKeyNotAvailableError if yubikey-manager not installed)
for device in list_yubikeys():
    print(f"Found: {device['name']} (serial: {device.get('serial', 'N/A')})")

# Open a YubiKey-protected database
with Database.open("vault.kdbx", password="my-password", yubikey_slot=2) as db:
    print(f"Entries: {len(db.find_entries())}")
    db.save()

# Create a new database with YubiKey protection
db = Database.create(
    password="my-password",
    yubikey_slot=2,           # Use slot 2 (recommended)
    yubikey_serial=12345678,  # Optional: specific YubiKey serial
)
db.save("protected.kdbx")

# Open with specific YubiKey when multiple are connected
with Database.open(
    "vault.kdbx",
    password="my-password",
    yubikey_slot=2,
    yubikey_serial=12345678,
) as db:
    pass
```

Requirements:
- YubiKey with HMAC-SHA1 configured in slot 1 or 2
- Configure with: `ykman otp chalresp -g 2` (generates random secret for slot 2)

## Security

kdbxtool prioritizes security:

- **SecureBytes**: Sensitive data is stored in zeroizable buffers
- **Constant-time comparisons**: All authentication uses `hmac.compare_digest`
- **Hardened XML**: Uses defusedxml to prevent XXE attacks
- **Modern KDF**: Enforces minimum Argon2 parameters

## License

Apache-2.0
