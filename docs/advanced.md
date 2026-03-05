# Advanced Examples

## Custom Fields

Entries can store arbitrary custom properties beyond the standard fields.

```python
# Set custom properties
entry.set_custom_property('api_key', 'sk-abc123')
entry.set_custom_property('secret_token', 'token123', protected=True)  # Encrypted

# Get custom properties
api_key = entry.get_custom_property('api_key')

# List all custom properties
for name, field in entry.custom_properties.items():
    print(f"{name}: {field.value} (protected: {field.protected})")

# Remove a custom property
entry.remove_custom_property('api_key')
```

## Attachments

Add, retrieve, and remove file attachments from entries.

```python
# Add attachment
entry.add_attachment('document.pdf', pdf_bytes)
entry.add_attachment('config.json', b'{"key": "value"}')

# List attachments
for attachment in entry.attachments:
    print(f"{attachment.filename} ({len(attachment.data)} bytes)")

# Get attachment data
attachment = entry.attachments[0]
with open(attachment.filename, 'wb') as f:
    f.write(attachment.data)

# Remove attachment
entry.remove_attachment('document.pdf')
```

## History Management

Entries automatically track history when modified. You can manage this history.

```python
# View history
for i, hist in enumerate(entry.history):
    print(f"{i}: {hist.title} (modified: {hist.times.last_modification_time})")

# Restore from history
old_version = entry.history[0]
entry.title = old_version.title
entry.password = old_version.password

# Clear all history
entry.clear_history()

# Delete specific history entry
entry.delete_history(entry.history[0])
```

## Custom Icons

Databases can store custom icons for entries and groups.

```python
import uuid

# Add custom icon to database
with open('icon.png', 'rb') as f:
    icon_data = f.read()

icon_uuid = db.add_custom_icon(icon_data, name='My Icon')

# Assign to entry or group
entry.custom_icon_uuid = icon_uuid
group.custom_icon_uuid = icon_uuid

# Find icon by name
icon = db.find_custom_icon(name='My Icon')

# List all custom icons
for icon in db.custom_icons:
    print(f"{icon.uuid}: {icon.name}")

# Remove custom icon
db.remove_custom_icon(icon_uuid)
```

## Field References

Reference fields from other entries to avoid duplication.

```python
# Create a reference to another entry's password
source_entry = db.find_entries(title='Master Account', first=True)
ref_string = source_entry.ref('password')  # Returns {REF:P@I:UUID}

# Use the reference in another entry
other_entry.password = ref_string

# Dereference to get actual value
actual_password = db.deref(other_entry.password)

# Or dereference from the entry directly
actual_password = other_entry.deref(other_entry.password)
```

## AutoType Configuration

Configure automatic typing sequences for entries.

```python
# Set default AutoType sequence
entry.autotype_sequence = '{USERNAME}{TAB}{PASSWORD}{ENTER}'

# Enable/disable AutoType
entry.autotype_enabled = True

# Add window associations
entry.add_autotype_association(
    window='*login*',
    sequence='{USERNAME}{TAB}{PASSWORD}{TAB}{TOTP}{ENTER}'
)

# List associations
for assoc in entry.autotype_associations:
    print(f"Window: {assoc.window}, Sequence: {assoc.sequence}")
```

## Database Settings

Modify database-level settings.

```python
# Access settings
settings = db.settings

# Modify settings
settings.database_name = 'My Vault'
settings.database_description = 'Personal passwords'
settings.default_username = 'myuser@example.com'

# Recycle bin settings
settings.recycle_bin_enabled = True

# History settings
settings.history_max_items = 10
settings.history_max_size = 6 * 1024 * 1024  # 6 MB
```

## Changing Credentials

Update the master password or keyfile.

```python
# Change password
db.set_credentials(password='new_password')

# Change to keyfile only
db.set_credentials(keyfile='path/to/keyfile.keyx')

# Use both password and keyfile
db.set_credentials(password='secret', keyfile='keyfile.keyx')

# Save with new credentials
db.save()
```

## Database Merge

Merge changes from another database (useful for sync conflicts).

```python
from kdbxtool import Database, MergeMode

# Open both databases
with Database.open('local.kdbx', password='secret') as local:
    with Database.open('remote.kdbx', password='secret') as remote:
        # Merge remote into local
        result = local.merge(remote, mode=MergeMode.SYNCHRONIZE)

        print(f"Added: {len(result.added_entries)} entries")
        print(f"Modified: {len(result.modified_entries)} entries")
        print(f"Deleted: {len(result.deleted_entries)} entries")

        # Save merged result
        local.save()
```

## TOTP/OTP Support

Generate one-time passwords for entries with OTP configured.

```python
# Get current TOTP
totp = entry.generate_otp()
print(f"Current code: {totp}")

# Set OTP secret (otpauth:// URI format)
entry.otp = 'otpauth://totp/Example:user?secret=JBSWY3DPEHPK3PXP&issuer=Example'

# Or set the secret directly
entry.set_custom_property('otp', 'otpauth://totp/...', protected=True)
```

## Iterating All Entries/Groups

```python
# Iterate all entries in database
for entry in db.iter_entries():
    print(entry.title)

# Iterate all groups
for group in db.iter_groups():
    print(group.name)

# Iterate entries in a specific group (non-recursive)
for entry in group.entries:
    print(entry.title)

# Iterate subgroups
for subgroup in group.subgroups:
    print(subgroup.name)
```
