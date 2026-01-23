# Hardware Key Support

kdbxtool supports hardware security keys (YubiKeys, FIDO2 devices) for additional database protection. This document covers compatibility, operating modes, and backup strategies.

## Compatibility Matrix

| Feature | kdbxtool | KeePassXC | KeePassDX | KeePass 2.x |
|---------|----------|-----------|-----------|-------------|
| Password only | Yes | Yes | Yes | Yes |
| Keyfile | Yes | Yes | Yes | Yes |
| YubiKey HMAC-SHA1 (Legacy) | Yes | Yes | Yes | Plugin |
| YubiKey HMAC-SHA1 (KEK) | Yes | No | No | No |
| FIDO2 hmac-secret | Yes | No | No | No |
| Multiple hardware keys | Yes | No* | No | No |

*KeePassXC requires manually programming the same HMAC secret onto multiple YubiKeys.

### Operating Modes

kdbxtool supports two challenge-response modes:

#### Legacy Mode (KeePassXC Compatible)

- Single YubiKey HMAC-SHA1 only
- Challenge-response mixed directly into key derivation
- Compatible with KeePassXC and KeePassDX
- Use when you need to open databases in other applications

```python
from kdbxtool import Database, YubiKeyHmacSha1

db = Database.create(password="secret")
yubikey = YubiKeyHmacSha1(slot=2)

# Legacy mode - compatible with KeePassXC
db.save("vault.kdbx", challenge_response_provider=yubikey)
```

#### KEK Mode (Multi-Device)

- Supports multiple enrolled devices
- Supports YubiKey HMAC-SHA1, FIDO2, and future device types
- NOT compatible with KeePassXC, KeePassDX, or other KeePass applications
- Use when you exclusively use kdbxtool

```python
from kdbxtool import Database, YubiKeyHmacSha1

db = Database.create(password="secret")
primary = YubiKeyHmacSha1(slot=2)
backup = YubiKeyHmacSha1(slot=2, serial=12345678)  # Different YubiKey

# KEK mode - enroll multiple devices
db.enroll_device(primary, label="Primary YubiKey")
db.enroll_device(backup, label="Backup YubiKey")
db.save("vault.kdbx")

# Either device can open the database
db2 = Database.open("vault.kdbx", password="secret",
                    challenge_response_provider=primary)
```

### Choosing a Mode

| Use Case | Recommended Mode |
|----------|------------------|
| Need KeePassXC/mobile access | Legacy |
| Single YubiKey, no backup needed | Legacy |
| Multiple backup keys | KEK |
| FIDO2 devices | KEK |
| Mixed device types (YubiKey + FIDO2) | KEK |
| Enterprise with device management | KEK |

## Backup Strategies

Hardware keys can fail, get lost, or be damaged. Plan your backup strategy before enabling hardware key protection.

### Strategy 1: Multiple Enrolled Devices (Recommended)

Enroll multiple hardware keys when first setting up the database:

```python
db = Database.create(password="strong_password")

# Enroll primary and backup devices
db.enroll_device(primary_yubikey, label="Primary - Daily Use")
db.enroll_device(backup_yubikey, label="Backup - Safe Deposit Box")
db.enroll_device(fido2_key, label="Emergency - Office Safe")

db.save("vault.kdbx")
```

Store backup devices in secure, separate locations (safe deposit box, office safe, trusted family member).

### Strategy 2: Add Backup Device Later

You can add backup devices to an existing KEK-mode database:

```python
# Open with any enrolled device
db = Database.open("vault.kdbx", password="secret",
                   challenge_response_provider=existing_device)

# Add new backup device
db.enroll_device(new_backup_device, label="New Backup Key")
db.save()
```

### Strategy 3: Password-Only Backup Copy

Keep a password-only copy for emergency recovery:

```python
# Open with hardware key
db = Database.open("vault.kdbx", password="secret",
                   challenge_response_provider=device)

# Disable KEK mode for backup copy
db.disable_kek_mode()
db.save("vault_emergency_backup.kdbx")
```

Store this backup securely - it's only protected by your password.

### Strategy 4: Disable KEK Mode (Migration)

If you need to switch to a KeePassXC-compatible format:

```python
db = Database.open("vault.kdbx", password="secret",
                   challenge_response_provider=device)

# Remove hardware key requirement
db.disable_kek_mode()
db.save("vault_no_hardware.kdbx")
```

## Device Management

### List Enrolled Devices

```python
db = Database.open("vault.kdbx", password="secret",
                   challenge_response_provider=device)

for device in db.list_enrolled_devices():
    print(f"{device['label']}: {device['type']}")
```

### Revoke a Device

Remove a lost or compromised device:

```python
db.revoke_device(label="Lost YubiKey")
db.save()
```

After revoking a device, consider rotating the KEK if the device may have been compromised:

```python
# Rotate KEK with remaining devices
db.rotate_kek({
    "Primary YubiKey": primary_device,
    "Backup YubiKey": backup_device,
})
db.save()
```

### Check KEK Mode Status

```python
db = Database.open("vault.kdbx", password="secret",
                   challenge_response_provider=device)

print(f"KEK mode: {db.kek_mode}")
print(f"Enrolled devices: {db.enrolled_device_count}")
```

## Security Considerations

1. **Password still required**: Hardware keys add protection but don't replace your password. Use a strong, unique password.

2. **Physical security**: Hardware keys can be stolen. Consider PIN protection on FIDO2 devices.

3. **Backup before changes**: Always backup your database before enrolling/revoking devices or rotating KEK.

4. **Test backups**: Periodically verify you can open your database with backup devices.

5. **KEK rotation**: After revoking a potentially compromised device, rotate the KEK to ensure old backups can't be decrypted with the revoked device.
