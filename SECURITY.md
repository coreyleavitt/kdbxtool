# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in kdbxtool, please report it through GitHub's private vulnerability reporting:

1. Go to the [Security tab](https://github.com/coreyleavitt/kdbxtool/security)
2. Click "Report a vulnerability"
3. Provide details about the vulnerability

Please include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

You will receive a response within 48 hours acknowledging your report. We will work with you to understand and address the issue, and will keep you informed of our progress.

## Security Considerations

kdbxtool is a cryptographic library handling sensitive password data. We prioritize:

- **Memory safety**: Sensitive data is stored in zeroizable buffers (SecureBytes)
- **Constant-time operations**: Authentication uses timing-safe comparisons
- **Secure defaults**: Modern KDF (Argon2d) with enforced minimum parameters
- **Hardened parsing**: XML parsing uses defusedxml to prevent XXE attacks

## Scope

The following are in scope for security reports:
- Cryptographic weaknesses
- Memory disclosure of sensitive data
- Authentication bypasses
- XML/parsing vulnerabilities
- Timing attacks

Out of scope:
- Denial of service through malformed files
- Issues requiring physical access to the machine
- Social engineering
