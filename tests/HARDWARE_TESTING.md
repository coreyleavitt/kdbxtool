# Hardware Key Testing Guide

This guide covers testing kdbxtool with physical hardware security keys.

## Prerequisites

### Hardware Requirements

- **YubiKey** with HMAC-SHA1 support (YubiKey 4, 5 series, or NEO)
  - One slot configured for HMAC-SHA1 challenge-response
  - Slot 2 is used by default (configurable)

- **FIDO2 device** (optional, for FIDO2 tests)
  - YubiKey 5 series with FIDO2 support
  - Any FIDO2 key supporting hmac-secret extension

### Software Requirements

```bash
# Install kdbxtool with YubiKey support
pip install kdbxtool[yubikey]

# Or install development dependencies
uv sync --group dev --all-extras
```

## YubiKey Setup

### Configure HMAC-SHA1 Slot

Use `ykman` (YubiKey Manager CLI) to configure a slot:

```bash
# Generate a random 20-byte secret for slot 2
ykman otp chalresp --generate 2

# Or set a specific secret (hex-encoded, 20 bytes)
ykman otp chalresp --key <40-hex-chars> 2

# Verify configuration
ykman otp info
```

**Important**: The secret is stored on the YubiKey and cannot be retrieved. For testing with multiple YubiKeys, you must either:
1. Use different YubiKeys with different secrets (KEK mode supports this)
2. Program the same secret onto multiple YubiKeys (KeePassXC-compatible mode requires this)

### Verify YubiKey is Detected

```python
from kdbxtool.security.yubikey import list_yubikeys

devices = list_yubikeys()
for d in devices:
    print(f"Found: {d['name']}, serial: {d.get('serial', 'N/A')}")
```

## Running Hardware Tests

### Basic Test Run

```bash
# Run all hardware tests
pytest -m hardware -v

# Run only hardware key tests
pytest -m hardware tests/test_hardware_keys.py -v

# Run with specific YubiKey serial number
YUBIKEY_SERIAL=12345678 pytest -m hardware -v

# Use a different slot
YUBIKEY_SLOT=1 pytest -m hardware -v
```

### Test Classes

| Class | Description | Mode |
|-------|-------------|------|
| `TestYubiKeyHardware` | Low-level provider tests | N/A |
| `TestDatabaseYubiKeyHardware` | Database integration | KeePassXC-compatible |
| `TestKekModeHardware` | Multi-device enrollment | KEK |
| `TestKeePassXCCompatibility` | Format compatibility | Both |

### Expected Output

```
tests/test_hardware_keys.py::TestYubiKeyHardware::test_list_yubikeys PASSED
tests/test_hardware_keys.py::TestYubiKeyHardware::test_hardware_yubikey_provider PASSED
tests/test_hardware_keys.py::TestYubiKeyHardware::test_hardware_yubikey_deterministic PASSED
tests/test_hardware_keys.py::TestYubiKeyHardware::test_hardware_yubikey_different_challenges PASSED
tests/test_hardware_keys.py::TestYubiKeyHardware::test_hardware_yubikey_requires_touch_property PASSED
tests/test_hardware_keys.py::TestYubiKeyHardware::test_check_slot_configured PASSED
tests/test_hardware_keys.py::TestDatabaseYubiKeyHardware::test_create_and_open_database PASSED
tests/test_hardware_keys.py::TestDatabaseYubiKeyHardware::test_bytes_roundtrip PASSED
tests/test_hardware_keys.py::TestDatabaseYubiKeyHardware::test_wrong_password_fails PASSED
tests/test_hardware_keys.py::TestDatabaseYubiKeyHardware::test_missing_yubikey_fails PASSED
tests/test_hardware_keys.py::TestDatabaseYubiKeyHardware::test_modify_and_resave PASSED
tests/test_hardware_keys.py::TestKekModeHardware::test_enroll_single_device PASSED
tests/test_hardware_keys.py::TestKekModeHardware::test_enroll_device_bytes_roundtrip PASSED
tests/test_hardware_keys.py::TestKekModeHardware::test_modify_and_resave_kek_mode PASSED
tests/test_hardware_keys.py::TestKekModeHardware::test_wrong_password_kek_mode PASSED
tests/test_hardware_keys.py::TestKekModeHardware::test_missing_device_kek_mode PASSED
tests/test_hardware_keys.py::TestKekModeHardware::test_list_enrolled_devices PASSED
tests/test_hardware_keys.py::TestKekModeHardware::test_disable_kek_mode_migration PASSED
tests/test_hardware_keys.py::TestKekModeHardware::test_rotate_kek PASSED
tests/test_hardware_keys.py::TestKekModeHardware::test_revoke_device_prevents_access PASSED
tests/test_hardware_keys.py::TestKeePassXCCompatibility::test_compat_mode_format PASSED
tests/test_hardware_keys.py::TestKeePassXCCompatibility::test_compat_vs_kek_mode_incompatible PASSED
```

## Understanding Test Modes

### KeePassXC-Compatible Mode Tests

KeePassXC-compatible mode tests use the `challenge_response_provider` parameter:

```python
# Save in KeePassXC-compatible mode
db.save(path, challenge_response_provider=yubikey)

# Open in KeePassXC-compatible mode
db = Database.open(path, password="secret", challenge_response_provider=yubikey)
```

**Characteristics:**
- Single device only
- Challenge-response mixed into key derivation
- Compatible with KeePassXC, KeePassDX, KeePass 2.x (with plugin)
- Same database cannot be opened with a different YubiKey (unless same secret)

### KEK Mode Tests

KEK mode tests use the `enroll_device()` method:

```python
# Create and enroll device (KEK mode)
db = Database.create(password="secret")
db.enroll_device(yubikey, label="Primary YubiKey")
db.save(path)

# Open with enrolled device
db = Database.open(path, password="secret", challenge_response_provider=yubikey)
```

**Characteristics:**
- Supports multiple enrolled devices
- KEK (Key Encryption Key) wrapped per-device
- NOT compatible with other KeePass applications
- Different physical devices can open the same database

## Troubleshooting

### "No YubiKey connected"

```
SKIPPED [1] tests/test_hardware_keys.py: No YubiKey connected
```

- Ensure YubiKey is inserted
- Check USB connection
- Try a different USB port
- Verify with `ykman list`

### "yubikey-manager not installed"

```
SKIPPED [1] tests/test_hardware_keys.py: yubikey-manager not installed
```

Install the yubikey extra:
```bash
pip install kdbxtool[yubikey]
```

### "Slot not configured for HMAC-SHA1"

```
SKIPPED [1] tests/test_hardware_keys.py: YubiKey slot 2 not configured for HMAC-SHA1
```

Configure the slot:
```bash
ykman otp chalresp --generate 2
```

### Permission Errors (Linux)

On Linux, you may need udev rules for YubiKey access:

```bash
# Add udev rules
sudo tee /etc/udev/rules.d/70-yubikey.rules << 'EOF'
# YubiKey
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", MODE="0660", GROUP="plugdev", ATTRS{idVendor}=="1050"
EOF

# Reload rules
sudo udevadm control --reload-rules
sudo udevadm trigger

# Add user to plugdev group
sudo usermod -aG plugdev $USER
# Log out and back in
```

### Touch Required

Some tests may require touching the YubiKey if touch is configured for the slot:

```bash
# Check if touch is required
ykman otp info
```

If touch is required, the test will wait for touch. Consider disabling touch for testing:

```bash
# Reconfigure without touch requirement
ykman otp chalresp --generate --no-touch 2
```

## Testing with Multiple YubiKeys

To fully test multi-device support, you need multiple physical YubiKeys. However, the current test suite can test the KEK wrapping logic with a single YubiKey by enrolling it multiple times with different labels.

For comprehensive testing with actual multiple devices:

```python
# Example: Testing with two YubiKeys
from kdbxtool import Database, YubiKeyHmacSha1

primary = YubiKeyHmacSha1(slot=2, serial=12345678)
backup = YubiKeyHmacSha1(slot=2, serial=87654321)

db = Database.create(password="secret")
db.enroll_device(primary, label="Primary")
db.enroll_device(backup, label="Backup")
db.save("vault.kdbx")

# Test opening with each device
db1 = Database.open("vault.kdbx", password="secret",
                    challenge_response_provider=primary)
db2 = Database.open("vault.kdbx", password="secret",
                    challenge_response_provider=backup)
```

## KeePassXC Compatibility Testing

To verify KeePassXC-compatible mode works with KeePassXC:

1. Create a database with kdbxtool in KeePassXC-compatible mode:
```python
from kdbxtool import Database, YubiKeyHmacSha1

db = Database.create(password="testpassword")
db.root_group.create_entry(title="Test", username="user", password="pass")
db.save("test.kdbx", challenge_response_provider=YubiKeyHmacSha1(slot=2))
```

2. Open in KeePassXC:
   - File > Open Database
   - Select the .kdbx file
   - Enter password
   - Select "Challenge-Response" as key file type
   - Choose your YubiKey slot
   - Verify the entry is accessible

3. Save in KeePassXC and reopen with kdbxtool:
```python
db = Database.open("test.kdbx", password="testpassword",
                   challenge_response_provider=YubiKeyHmacSha1(slot=2))
```

## CI Integration

Hardware tests are automatically skipped in CI environments where no YubiKey is present. The tests use these markers:

```python
@pytest.mark.hardware  # Marks test as requiring hardware
@pytest.mark.skipif(not YUBIKEY_HARDWARE_AVAILABLE, ...)  # Skip if no yubikey-manager
@pytest.mark.skipif(not yubikey_connected(), ...)  # Skip if no YubiKey connected
```

To run hardware tests in CI (e.g., with a hardware security module):

```yaml
# Example GitHub Actions workflow
jobs:
  hardware-tests:
    runs-on: self-hosted  # Use a runner with YubiKey access
    steps:
      - uses: actions/checkout@v4
      - name: Run hardware tests
        run: pytest -m hardware -v
```

## Security Considerations

- **Test secrets are ephemeral**: Use `ykman otp chalresp --generate` to create random secrets for testing
- **Don't use production YubiKeys**: Use dedicated test YubiKeys with test secrets
- **Test databases are temporary**: Tests use `tmp_path` fixtures, databases are deleted after tests
- **No secrets in code**: Serial numbers and slot configurations come from environment variables
