# Getting Started

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

## Opening a Database

```python
from kdbxtool import Database

# Using context manager (recommended)
with Database.open("vault.kdbx", password="secret") as db:
    for entry in db.find_entries():
        print(entry.title)

# Or without context manager
db = Database.open("vault.kdbx", password="secret")
# ... work with database ...
db.zeroize_credentials()  # Clean up when done
```

## Creating a Database

```python
from kdbxtool import Database

db = Database.create(password="secret", database_name="My Vault")
db.root_group.create_entry(
    title="Example",
    username="user",
    password="pass123",
)
db.save("vault.kdbx")
```

## Finding Entries

```python
# Find by title
entries = db.find_entries(title="Gmail")

# Find by username (regex supported)
entries = db.find_entries(username=".*@example.com")

# Find in specific group
group = db.find_groups(name="Email")[0]
entries = db.find_entries(group=group, title="Gmail")
```

## Working with Groups

```python
# Access root group
root = db.root_group

# Create subgroup
email_group = root.create_subgroup(name="Email Accounts")

# Create entry in group
email_group.create_entry(
    title="Gmail",
    username="user@gmail.com",
    password="secret",
)
```

## YubiKey Authentication

```python
from kdbxtool import Database, list_yubikeys

# List connected YubiKeys (raises YubiKeyNotAvailableError if yubikey-manager not installed)
for device in list_yubikeys():
    print(f"Found: {device['name']}")

# Open with YubiKey (slot 2 recommended)
with Database.open("vault.kdbx", password="secret", yubikey_slot=2) as db:
    # ... work with database ...
    pass

# Create with YubiKey protection
db = Database.create(
    password="secret",
    yubikey_slot=2,
    database_name="Protected Vault",
)
db.save("protected.kdbx")
```

## Saving Changes

```python
# Save to same file
db.save()

# Save to new file
db.save("backup.kdbx")

# KDBX3 databases upgrade to KDBX4 on save
# Use allow_upgrade=True to confirm
db.save(allow_upgrade=True)
```
