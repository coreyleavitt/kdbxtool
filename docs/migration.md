# Migration from pykeepass

This guide shows equivalent operations between pykeepass and kdbxtool.

## Opening a Database

```python
# pykeepass
from pykeepass import PyKeePass
kp = PyKeePass('db.kdbx', password='secret')

# kdbxtool
from kdbxtool import Database
db = Database.open('db.kdbx', password='secret')

# Or with context manager (recommended)
with Database.open('db.kdbx', password='secret') as db:
    # ... work with database ...
    pass
```

## Finding Entries

```python
# pykeepass
entry = kp.find_entries(title='Gmail', first=True)
entries = kp.find_entries(username='user@example.com')

# kdbxtool
entry = db.find_entries(title='Gmail', first=True)
entries = db.find_entries(username='user@example.com')
```

## Creating Entries

```python
# pykeepass
group = kp.find_groups(name='Email', first=True)
kp.add_entry(group, 'Gmail', 'user@gmail.com', 'password123')

# kdbxtool
group = db.find_groups(name='Email', first=True)
group.create_entry(title='Gmail', username='user@gmail.com', password='password123')
```

## Creating Groups

```python
# pykeepass
kp.add_group(kp.root_group, 'New Group')

# kdbxtool
db.root_group.create_subgroup(name='New Group')
```

## Accessing Entry Fields

```python
# pykeepass
entry.title
entry.username
entry.password
entry.url
entry.notes

# kdbxtool (identical)
entry.title
entry.username
entry.password
entry.url
entry.notes
```

## Custom Properties

```python
# pykeepass
entry.set_custom_property('api_key', 'secret123')
value = entry.get_custom_property('api_key')

# kdbxtool
entry.set_custom_property('api_key', 'secret123')
value = entry.get_custom_property('api_key')
```

## Attachments

```python
# pykeepass
kp.add_binary(b'file content', 'file.txt')
entry.add_attachment(kp.binaries[-1], 'file.txt')

# kdbxtool
entry.add_attachment('file.txt', b'file content')
```

## Saving

```python
# pykeepass
kp.save()
kp.save('newfile.kdbx')

# kdbxtool
db.save()
db.save('newfile.kdbx')
```

## Key Differences

| Feature | pykeepass | kdbxtool |
|---------|-----------|----------|
| Context manager | No | Yes (recommended) |
| Memory cleanup | Manual | Automatic with context manager |
| Type hints | Partial | Full strict typing |
| KDBX3 write | Yes | Upgrades to KDBX4 |
| Argon2 presets | No | Yes (standard, high_security, fast) |
| Field references | No | Yes (ref/deref) |
| Merge support | No | Yes |
