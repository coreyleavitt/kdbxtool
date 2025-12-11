"""TOTP (Time-based One-Time Password) implementation per RFC 6238.

This module provides TOTP code generation from otpauth:// URIs stored in
KeePass entry otp fields.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal
from urllib.parse import parse_qs, unquote, urlparse


@dataclass
class TotpCode:
    """A generated TOTP code with expiration info.

    Attributes:
        code: The TOTP code as a zero-padded string (e.g., "123456")
        period: Time step in seconds (typically 30)
        generated_at: Unix timestamp when code was generated
    """

    code: str
    period: int
    generated_at: float

    @property
    def remaining(self) -> int:
        """Seconds remaining until this code expires.

        Note: This is calculated fresh each call based on current time.
        """
        now = time.time()
        elapsed = now - (int(self.generated_at) // self.period * self.period)
        return max(0, self.period - int(elapsed))

    @property
    def expires_at(self) -> datetime:
        """Datetime when this code expires."""
        period_start = int(self.generated_at) // self.period * self.period
        return datetime.fromtimestamp(period_start + self.period, tz=UTC)

    @property
    def is_expired(self) -> bool:
        """Whether this code has expired."""
        return self.remaining <= 0

    def __str__(self) -> str:
        return self.code


@dataclass
class TotpConfig:
    """TOTP configuration parsed from an otpauth:// URI.

    Attributes:
        secret: Base32-encoded secret key (decoded to bytes internally)
        digits: Number of digits in the code (default: 6)
        period: Time step in seconds (default: 30)
        algorithm: Hash algorithm (SHA1, SHA256, or SHA512)
        issuer: Optional issuer name
        account: Optional account name/label
    """

    secret: bytes
    digits: int = 6
    period: int = 30
    algorithm: Literal["SHA1", "SHA256", "SHA512"] = "SHA1"
    issuer: str | None = None
    account: str | None = None


def parse_otpauth_uri(uri: str) -> TotpConfig:
    """Parse an otpauth:// URI into a TotpConfig.

    Supports the standard otpauth:// URI format:
        otpauth://totp/LABEL?secret=BASE32SECRET&issuer=ISSUER&...

    Args:
        uri: The otpauth:// URI string

    Returns:
        TotpConfig with parsed parameters

    Raises:
        ValueError: If the URI is invalid or missing required parameters
    """
    parsed = urlparse(uri)

    if parsed.scheme != "otpauth":
        raise ValueError(f"Invalid scheme: expected 'otpauth', got '{parsed.scheme}'")

    otp_type = parsed.netloc.lower()
    if otp_type not in ("totp", "hotp"):
        raise ValueError(f"Unsupported OTP type: {otp_type}")

    if otp_type == "hotp":
        raise ValueError("HOTP is not supported, only TOTP")

    # Parse query parameters
    params = parse_qs(parsed.query)

    # Secret is required
    if "secret" not in params:
        raise ValueError("Missing required 'secret' parameter")

    secret_b32 = params["secret"][0].upper()
    # Add padding if needed (base32 requires padding to multiple of 8)
    padding = (8 - len(secret_b32) % 8) % 8
    secret_b32 += "=" * padding

    try:
        secret = base64.b32decode(secret_b32)
    except Exception as e:
        raise ValueError(f"Invalid base32 secret: {e}") from e

    # Parse optional parameters with defaults
    digits = int(params.get("digits", ["6"])[0])
    if digits not in (6, 7, 8):
        raise ValueError(f"Invalid digits: {digits} (must be 6, 7, or 8)")

    period = int(params.get("period", ["30"])[0])
    if period <= 0:
        raise ValueError(f"Invalid period: {period} (must be positive)")

    algorithm = params.get("algorithm", ["SHA1"])[0].upper()
    if algorithm not in ("SHA1", "SHA256", "SHA512"):
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    issuer = params.get("issuer", [None])[0]

    # Parse label (path component) for account name
    label = unquote(parsed.path.lstrip("/"))
    account = None
    if label:
        # Label format: "Issuer:Account" or just "Account"
        if ":" in label:
            _, account = label.split(":", 1)
        else:
            account = label

    return TotpConfig(
        secret=secret,
        digits=digits,
        period=period,
        algorithm=algorithm,  # type: ignore[arg-type]
        issuer=issuer,
        account=account,
    )


def parse_keepassxc_legacy(seed: str, settings: str | None = None) -> TotpConfig:
    """Parse KeePassXC legacy TOTP fields.

    KeePassXC historically stored TOTP in separate custom fields:
    - "TOTP Seed": Base32 secret
    - "TOTP Settings": "period;digits" (e.g., "30;6")

    Args:
        seed: The TOTP seed (base32 encoded secret)
        settings: Optional settings string in "period;digits" format

    Returns:
        TotpConfig with parsed parameters
    """
    # Clean up seed
    secret_b32 = seed.strip().upper().replace(" ", "")
    padding = (8 - len(secret_b32) % 8) % 8
    secret_b32 += "=" * padding

    try:
        secret = base64.b32decode(secret_b32)
    except Exception as e:
        raise ValueError(f"Invalid base32 seed: {e}") from e

    period = 30
    digits = 6

    if settings:
        parts = settings.split(";")
        if len(parts) >= 1 and parts[0]:
            period = int(parts[0])
        if len(parts) >= 2 and parts[1]:
            digits = int(parts[1])

    return TotpConfig(secret=secret, digits=digits, period=period)


def generate_totp(config: TotpConfig, timestamp: float | None = None) -> TotpCode:
    """Generate a TOTP code.

    Args:
        config: TOTP configuration
        timestamp: Unix timestamp (defaults to current time)

    Returns:
        TotpCode with code string and expiration info
    """
    if timestamp is None:
        timestamp = time.time()

    # Calculate time counter
    counter = int(timestamp) // config.period

    # Select hash algorithm
    if config.algorithm == "SHA1":
        digest = hashlib.sha1
    elif config.algorithm == "SHA256":
        digest = hashlib.sha256
    else:  # SHA512
        digest = hashlib.sha512

    # Compute HMAC
    counter_bytes = struct.pack(">Q", counter)
    mac = hmac.new(config.secret, counter_bytes, digest).digest()

    # Dynamic truncation (RFC 4226)
    offset = mac[-1] & 0x0F
    binary = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF

    # Generate code with specified digits
    code_int = binary % (10**config.digits)
    code = str(code_int).zfill(config.digits)

    return TotpCode(code=code, period=config.period, generated_at=timestamp)
