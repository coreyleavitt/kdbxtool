# Security Audit Report: KEK Multi-Device Challenge-Response Implementation

**Project:** kdbxtool
**Component:** KEK (Key Encryption Key) Wrapping for Multi-Device Support
**Audit Date:** 2026-01-21
**Auditors:** 6 specialized security agents

---

## Executive Summary

This comprehensive security audit examined the KEK wrapping implementation in kdbxtool, which enables multiple hardware devices (YubiKeys, FIDO2 keys) to unlock the same password database. The audit was conducted by six specialized agents covering cryptographic security, memory safety, API design, attack surface analysis, ecosystem compatibility, and test coverage.

### Overall Assessment: **GOOD with Notable Concerns**

The implementation demonstrates solid cryptographic engineering practices and security awareness. However, several issues require attention before production release:

| Severity | Count | Summary |
|----------|-------|---------|
| Critical | 0 | No critical vulnerabilities found |
| High | 5 | Memory exposure, enrollment manipulation, ecosystem compatibility |
| Medium | 12 | Information leakage, timing oracles, missing features |
| Low | 15+ | Documentation gaps, test coverage, best practice improvements |

### Top 5 Issues Requiring Immediate Attention

1. **KEK Memory Exposure** - KEK accessible in process memory to local attackers
2. **Silent Device Enrollment Attack** - Attacker with temporary access can add their own device
3. **KeePassXC Incompatibility** - KEK mode databases cannot be opened in KeePassXC/KeePassDX
4. **No KEK Rotation on Revocation** - Revoked devices can still decrypt old backups
5. **Missing Runtime Warnings** - Users not warned about compatibility implications

---

## Table of Contents

1. [Cryptographic Security Findings](#1-cryptographic-security-findings)
2. [Memory Safety Findings](#2-memory-safety-findings)
3. [API Design & Error Handling Findings](#3-api-design--error-handling-findings)
4. [Attack Surface & Threat Model Findings](#4-attack-surface--threat-model-findings)
5. [KeePass Ecosystem Compatibility Findings](#5-keepass-ecosystem-compatibility-findings)
6. [Test Coverage Findings](#6-test-coverage-findings)
7. [Consolidated Recommendations](#7-consolidated-recommendations)
8. [Positive Security Properties](#8-positive-security-properties)

---

## 1. Cryptographic Security Findings

### HIGH SEVERITY

#### H1.1: Lack of Domain Separation in Key Derivation
**Location:** `src/kdbxtool/security/kek.py` lines 113-114

The AES key derivation from CR response uses plain SHA-256 without domain separation:
```python
device_key = bytearray(hashlib.sha256(cr_response).digest())
```

**Risk:** If the same CR response is used in a different context, derived keys would be identical.

**Recommendation:** Use HKDF with domain separation:
```python
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
device_key = HKDF(algorithm=SHA256(), length=32, salt=b"",
                  info=b"kdbxtool-kek-wrap-v2").derive(cr_response)
```

#### H1.2: XOR Key Combination Security Model
**Location:** `src/kdbxtool/security/kek.py` lines 169-191

The final key uses `final_master_key = base_master_key XOR KEK`. While mathematically sound, a weak password undermines the entire security model - the KEK provides no additional protection against password compromise.

**Recommendation:** Document this clearly; consider HKDF for key combination.

### MEDIUM SEVERITY

#### M1.1: No AAD in AES-GCM Wrapping
**Location:** `src/kdbxtool/security/kek.py` lines 117-122

AES-GCM encryption doesn't use Associated Authenticated Data (AAD) to bind the wrapped KEK to device identity or database UUID.

#### M1.2: Device Metadata Exposed in Header
The number of enrolled devices, device types, labels, and IDs are stored in unencrypted `public_custom_data`. Attackers can learn organizational details from the database file.

#### M1.3: Timing Side Channel in Device Matching
**Location:** `src/kdbxtool/database.py` lines 910-954

The `_unwrap_kek_from_devices()` method returns immediately on successful match, creating timing differences based on device position.

#### M1.4: 16-Byte GCM Nonce (Non-Standard)
PyCryptodome uses 16-byte nonces by default; NIST recommends 12 bytes.

### POSITIVE FINDINGS

- Correct use of `os.urandom()` for all security-critical random values
- KEK is 256 bits of pure entropy
- AES-GCM tag verified before plaintext use via `decrypt_and_verify()`
- Generic error messages prevent oracle attacks
- `hmac.compare_digest()` used for constant-time comparison
- SecureBytes wrapper for key material lifecycle

---

## 2. Memory Safety Findings

### HIGH SEVERITY

#### H2.1: SecureBytes `.data` Property Creates Copies
**Location:** `src/kdbxtool/security/memory.py` line 62

```python
@property
def data(self) -> bytes:
    return bytes(self._buffer)  # Creates immutable copy
```

Every access creates a new `bytes` object that cannot be zeroized. These copies persist until garbage collection.

**Exploitability:** An attacker with memory access (core dump, memory forensics) could find multiple copies of sensitive material.

#### H2.2: Password String Immutability
**Location:** `src/kdbxtool/security/kdf.py` lines 416-498

Passwords arrive as Python `str` (immutable, potentially interned). The password cannot be zeroized and persists in memory.

### MEDIUM SEVERITY

#### M2.1: Temporary `bytes(device_key)` Copy for AES
**Location:** `src/kdbxtool/security/kek.py` lines 118, 155

`bytes(device_key)` creates an immutable copy passed to PyCryptodome that cannot be zeroized.

#### M2.2: XOR Intermediate Not Zeroized
**Location:** `src/kdbxtool/security/kek.py` lines 190

The `final = bytes(...)` intermediate in `derive_final_key()` cannot be zeroized.

#### M2.3: CipherContext Stores Key as Plain bytes
**Location:** `src/kdbxtool/security/crypto.py` lines 163-189

No zeroization on object destruction.

### POSITIVE FINDINGS

- Device key properly zeroized in `finally` blocks
- All `__repr__` methods hide sensitive content
- No logging of sensitive data even at DEBUG level
- Exception messages reference only lengths, not values
- KDF intermediate values properly zeroized in bytearray

---

## 3. API Design & Error Handling Findings

### HIGH SEVERITY

#### H3.1: Inconsistent KEK State on Provider Failure
**Location:** `src/kdbxtool/database.py` lines 491-604

If `challenge_response()` fails mid-enrollment, the database state may be partially modified (salt generated but KEK not set).

**Recommendation:** Make enrollment atomic - test provider before generating salt/KEK.

### MEDIUM SEVERITY

#### M3.1: Authentication Errors Reveal Device Count
**Location:** `src/kdbxtool/database.py` lines 940-954

```python
raise AuthenticationError(f"...tried {devices_tried} enrolled devices...")
```

**Recommendation:** Use generic message without count.

#### M3.2: No Provider Output Size Validation
Providers returning very short responses (e.g., 1 byte) result in weak key derivation.

#### M3.3: Missing KEK Version Forward Compatibility
No handling for unknown future KEK versions - could fall back to legacy mode unpredictably.

#### M3.4: Device Label Information Disclosure in Debug Logs
**Location:** `src/kdbxtool/database.py` lines 932, 936

Device labels logged at DEBUG level.

### LOW SEVERITY

#### L3.1: No KEK Rotation API
No method to rotate KEK while keeping enrolled devices.

#### L3.2: Device Type Auto-Detection is Fragile
String matching on class names for device type detection.

#### L3.3: `list_enrolled_devices()` Returns Device ID
Could contain sensitive information like YubiKey serial numbers.

---

## 4. Attack Surface & Threat Model Findings

### CRITICAL ATTACK VECTORS

#### Attack 4.1: KEK Memory Disclosure
**Attacker:** Local malware with user privileges
**Prerequisites:** Database currently open
**Impact:** CRITICAL - Full database decryption without hardware device
**Likelihood:** HIGH - Memory reading is trivial

The KEK is stored in `SecureBytes` but Python's memory model creates copies that cannot be zeroized. An attacker can read process memory to extract the KEK.

#### Attack 4.2: CR Response Capture
**Attacker:** Local malware
**Impact:** CRITICAL - Response + wrapped_kek = full decryption
**Likelihood:** HIGH - API hooking is straightforward

#### Attack 4.3: Silent Device Enrollment
**Attacker:** Local malware with temporary access while database is open
**Impact:** CRITICAL - Persistent unauthorized access
**Likelihood:** MEDIUM - Requires timing

Attacker extracts KEK from memory, creates their own device entry with controlled CR response, and gains permanent access even after password changes.

### HIGH SEVERITY ATTACKS

#### Attack 4.4: Rollback Attack (Un-Revoke Device)
**Attacker:** File access to backups
**Impact:** MEDIUM - Revoked device can decrypt old backups
**Likelihood:** MEDIUM - Backups are common

The KEK is NOT rotated on device revocation. Old backups remain vulnerable.

**Recommendation:** Rotate KEK on revocation and re-wrap for remaining devices.

### MITIGATED ATTACKS

#### Downgrade Attack: MITIGATED
Header is protected by HMAC-SHA256. Modifying `KDBXTOOL_CR_VERSION` causes authentication failure.

#### Error/Timing Oracle: LOW RISK
Generic error messages. Timing differences are minimal.

---

## 5. KeePass Ecosystem Compatibility Findings

### CRITICAL COMPATIBILITY ISSUES

#### C5.1: KEK Mode Incompatible with KeePassXC/KeePassDX
KEK-mode databases will **fail silently** in KeePassXC with an unhelpful "invalid credentials" error. Users may think their password is wrong.

**Risk Level:** HIGH - Users may lose access if they don't understand why KeePassXC cannot open their database.

#### C5.2: Legacy Mode Compatibility Unverified
The legacy mode uses `kdf_salt` as the challenge, but KeePassXC uses a dedicated `KDBXC_CHAL_RESPONSE_PUBLIC_DATA` CustomData entry. Compatibility is **not verified**.

#### C5.3: No Migration Path Out of KEK Mode
Once in KEK mode:
- `revoke_device()` prevents removing the last device
- There is NO `disable_kek_mode()` method
- Users are permanently locked into kdbxtool

### UX CONCERNS

#### U5.1: No Runtime Warning on First Enrollment
The docstring warns about KeePassXC incompatibility, but this is never displayed to users.

#### U5.2: Missing Device Metadata
`list_enrolled_devices()` doesn't return enrollment timestamp, last used time, or device serial.

#### U5.3: Unclear Error Messages
"Database requires challenge-response device but none provided" doesn't explain which devices are enrolled or recovery options.

### DOCUMENTATION GAPS

1. No compatibility matrix (KEK vs Legacy vs KeePassXC)
2. No backup strategy documentation
3. No migration guides (to or from kdbxtool)
4. No recovery procedures for lost devices

---

## 6. Test Coverage Findings

### MISSING CRITICAL TESTS

#### T6.1: `_unwrap_kek_from_devices()` Error Paths
- All devices corrupted scenario
- No enrolled devices found scenario

#### T6.2: Empty/Very Long CR Response Handling
No tests for edge case CR response sizes.

#### T6.3: Wrong Password + Right Device
No explicit test for this error path.

#### T6.4: Truncated Wrapped Value Boundaries
Tests don't cover truncation at nonce/tag/ciphertext boundaries.

### EXISTING TEST ISSUES

#### T6.5: FIDO2 Tests Incorrectly Marked xfail
Tests marked `@pytest.mark.xfail(reason="FIDO2 requires KEK mode which is not yet implemented")` but KEK mode IS implemented. These should be enabled.

#### T6.6: Docstring Typo
`test_wrap_returns_correct_size` says "60 bytes" but should be "64 bytes".

### MISSING EDGE CASE TESTS

- Special characters/Unicode in device labels
- Null bytes in metadata values
- Many enrolled devices (scalability)
- Large metadata dictionaries
- Revoke device from middle of list

---

## 7. Consolidated Recommendations

### Priority 1: Must Fix Before Release

| # | Issue | Effort | Files |
|---|-------|--------|-------|
| 1 | Add runtime warning when enrolling first device about KeePassXC incompatibility | Low | database.py |
| 2 | Verify legacy mode compatibility with actual KeePassXC testing | Medium | - |
| 3 | Add `disable_kek_mode()` method for migration out | Medium | database.py |
| 4 | Remove device count from error messages | Low | database.py |
| 5 | Add version forward-compatibility check | Low | database.py |

### Priority 2: Should Fix Before Production Use

| # | Issue | Effort | Files |
|---|-------|--------|-------|
| 6 | Implement HKDF with domain separation for key derivation | Medium | kek.py |
| 7 | Add KEK rotation on device revocation | High | database.py, kek.py |
| 8 | Make enrollment atomic (test provider before state changes) | Medium | database.py |
| 9 | Add minimum CR response length validation | Low | kek.py |
| 10 | Enable FIDO2 tests (remove incorrect xfail) | Low | test_multi_key.py |
| 11 | Add missing critical tests for error paths | Medium | test_kek.py |
| 12 | Create compatibility matrix documentation | Low | docs |
| 13 | Create backup strategy documentation | Low | docs |

### Priority 3: Future Hardening

| # | Issue | Effort |
|---|-------|--------|
| 14 | Use `mlock()` for KEK memory protection | High |
| 15 | Add AAD to AES-GCM wrapping | Medium |
| 16 | Encrypt device metadata in header | High |
| 17 | Add enrollment authentication (require existing device) | High |
| 18 | Add anti-rollback counter | Medium |
| 19 | Use 12-byte GCM nonces per NIST recommendation | Low |
| 20 | Add device enrollment metadata (timestamps) | Low |

---

## 8. Positive Security Properties

The implementation demonstrates strong security fundamentals:

1. **Cryptographic Primitives**
   - AES-256-GCM with proper authenticated encryption
   - SHA-256/Argon2 for key derivation
   - `os.urandom()` for all random values
   - 256-bit KEK with full entropy

2. **Key Material Handling**
   - `SecureBytes` wrapper with automatic zeroization
   - Device key zeroized in `finally` blocks
   - KDF intermediates properly zeroized

3. **Error Handling**
   - Generic error messages prevent oracle attacks
   - `hmac.compare_digest()` for constant-time comparison
   - Exception messages don't expose sensitive values

4. **Mode Separation**
   - Proper prevention of legacy/KEK mode mixing
   - HMAC integrity protection prevents downgrade attacks

5. **Code Quality**
   - Comprehensive type annotations
   - Good test coverage for happy paths
   - Clear separation of concerns

---

## Appendix: Agent IDs for Follow-up

If additional investigation is needed:
- Cryptographic Security: `a1527e7`
- Memory Safety: `acc0a86`
- API Design: `abc5d60`
- Attack Surface: `a6a7bfd`
- KeePass Ecosystem: `a0cdeb0`
- Test Coverage: `a362ef2`

---

## Conclusion

The KEK implementation in kdbxtool is **fundamentally sound** from a cryptographic perspective. The main concerns are:

1. **Ecosystem compatibility** - Users need clear warnings and migration paths
2. **Local attacker resistance** - Memory exposure is inherent to Python but should be documented
3. **Revocation security** - KEK should rotate when devices are revoked
4. **Test coverage** - Error paths need explicit testing

With the Priority 1 fixes implemented, the implementation would be suitable for technical users who understand the tradeoffs. Priority 2 fixes are recommended before broader production deployment.
