"""Tests for TOTP code generation."""

import time

import pytest

from kdbxtool import Database
from kdbxtool.security.totp import (
    TotpCode,
    TotpConfig,
    generate_totp,
    parse_keepassxc_legacy,
    parse_otpauth_uri,
)


class TestParseOtpauthUri:
    """Tests for otpauth:// URI parsing."""

    def test_basic_uri(self) -> None:
        """Test parsing a basic otpauth URI."""
        uri = "otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        config = parse_otpauth_uri(uri)

        assert config.digits == 6
        assert config.period == 30
        assert config.algorithm == "SHA1"
        assert config.issuer == "Example"
        assert config.account == "user@example.com"

    def test_uri_with_all_params(self) -> None:
        """Test parsing URI with all parameters."""
        uri = "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&digits=8&period=60&algorithm=SHA256"
        config = parse_otpauth_uri(uri)

        assert config.digits == 8
        assert config.period == 60
        assert config.algorithm == "SHA256"

    def test_uri_minimal(self) -> None:
        """Test parsing minimal URI with just secret."""
        uri = "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP"
        config = parse_otpauth_uri(uri)

        # Should use defaults
        assert config.digits == 6
        assert config.period == 30
        assert config.algorithm == "SHA1"

    def test_invalid_scheme(self) -> None:
        """Test that invalid scheme raises error."""
        with pytest.raises(ValueError, match="Invalid scheme"):
            parse_otpauth_uri("http://example.com")

    def test_missing_secret(self) -> None:
        """Test that missing secret raises error."""
        with pytest.raises(ValueError, match="Missing required 'secret'"):
            parse_otpauth_uri("otpauth://totp/Test")

    def test_hotp_not_supported(self) -> None:
        """Test that HOTP raises error."""
        with pytest.raises(ValueError, match="HOTP is not supported"):
            parse_otpauth_uri("otpauth://hotp/Test?secret=JBSWY3DPEHPK3PXP")

    def test_invalid_digits(self) -> None:
        """Test that invalid digit count raises error."""
        with pytest.raises(ValueError, match="Invalid digits"):
            parse_otpauth_uri("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&digits=5")

    def test_secret_without_padding(self) -> None:
        """Test parsing secret without base32 padding."""
        # JBSWY3DPEHPK3PXP is valid without padding
        uri = "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP"
        config = parse_otpauth_uri(uri)
        assert len(config.secret) > 0


class TestParseKeepassxcLegacy:
    """Tests for KeePassXC legacy TOTP field parsing."""

    def test_seed_only(self) -> None:
        """Test parsing seed without settings."""
        config = parse_keepassxc_legacy("JBSWY3DPEHPK3PXP")

        assert config.digits == 6
        assert config.period == 30

    def test_seed_with_settings(self) -> None:
        """Test parsing seed with settings."""
        config = parse_keepassxc_legacy("JBSWY3DPEHPK3PXP", "60;8")

        assert config.digits == 8
        assert config.period == 60

    def test_seed_with_spaces(self) -> None:
        """Test that spaces in seed are handled."""
        config = parse_keepassxc_legacy("JBSW Y3DP EHPK 3PXP")
        assert len(config.secret) > 0


class TestTotpCode:
    """Tests for TotpCode dataclass."""

    def test_code_attribute(self) -> None:
        """Test code attribute."""
        totp_code = TotpCode(code="123456", period=30, generated_at=0.0)
        assert totp_code.code == "123456"

    def test_str_returns_code(self) -> None:
        """Test that str() returns the code."""
        totp_code = TotpCode(code="123456", period=30, generated_at=0.0)
        assert str(totp_code) == "123456"

    def test_remaining_at_period_start(self) -> None:
        """Test remaining time at period start."""
        # At t=0, should have 30s remaining
        totp_code = TotpCode(code="123456", period=30, generated_at=0.0)
        # Note: remaining is calculated from current time, so we test the logic
        # by checking that it's consistent within a period
        assert 0 <= totp_code.remaining <= 30

    def test_expires_at(self) -> None:
        """Test expires_at datetime."""
        from datetime import datetime, timezone

        totp_code = TotpCode(code="123456", period=30, generated_at=0.0)
        # Generated at t=0, period=30, should expire at t=30
        expected = datetime.fromtimestamp(30, tz=timezone.utc)
        assert totp_code.expires_at == expected

    def test_is_expired_false_when_fresh(self) -> None:
        """Test is_expired is False for fresh code."""
        # Generate at current time
        totp_code = TotpCode(code="123456", period=30, generated_at=time.time())
        assert not totp_code.is_expired

    def test_is_expired_true_when_old(self) -> None:
        """Test is_expired is True for old code."""
        # Generate at time far in the past
        totp_code = TotpCode(code="123456", period=30, generated_at=0.0)
        assert totp_code.is_expired


class TestGenerateTotp:
    """Tests for TOTP code generation."""

    def test_known_vector(self) -> None:
        """Test against known test vector from RFC 6238."""
        # RFC 6238 test vector: SHA1, secret "12345678901234567890"
        # At time 59, code should be 287082
        secret = b"12345678901234567890"
        config = TotpConfig(secret=secret, digits=8, period=30, algorithm="SHA1")

        result = generate_totp(config, timestamp=59.0)
        assert result.code == "94287082"

    def test_returns_totp_code(self) -> None:
        """Test that generate_totp returns TotpCode."""
        secret = b"12345678901234567890"
        config = TotpConfig(secret=secret, digits=6, period=30)

        result = generate_totp(config, timestamp=59.0)
        assert isinstance(result, TotpCode)
        assert len(result.code) == 6
        assert result.period == 30
        assert result.generated_at == 59.0

    def test_six_digits(self) -> None:
        """Test 6-digit code generation."""
        secret = b"12345678901234567890"
        config = TotpConfig(secret=secret, digits=6, period=30)

        result = generate_totp(config, timestamp=59.0)
        assert len(result.code) == 6
        assert result.code.isdigit()

    def test_zero_padding(self) -> None:
        """Test that codes are zero-padded."""
        # Find a timestamp that produces a low code
        secret = b"test_secret_key_here"
        config = TotpConfig(secret=secret, digits=6, period=30)

        # Generate many codes to verify format
        for ts in range(0, 1000, 30):
            result = generate_totp(config, timestamp=float(ts))
            assert len(result.code) == 6
            assert result.code.isdigit()

    def test_different_algorithms(self) -> None:
        """Test different hash algorithms produce different codes."""
        secret = b"12345678901234567890"
        timestamp = 59.0

        code_sha1 = generate_totp(TotpConfig(secret=secret, algorithm="SHA1"), timestamp).code
        code_sha256 = generate_totp(TotpConfig(secret=secret, algorithm="SHA256"), timestamp).code
        code_sha512 = generate_totp(TotpConfig(secret=secret, algorithm="SHA512"), timestamp).code

        # All should be different
        assert code_sha1 != code_sha256
        assert code_sha256 != code_sha512

    def test_same_period_same_code(self) -> None:
        """Test that times in same period produce same code."""
        secret = b"test_secret"
        config = TotpConfig(secret=secret, period=30)

        code1 = generate_totp(config, timestamp=0.0).code
        code2 = generate_totp(config, timestamp=15.0).code
        code3 = generate_totp(config, timestamp=29.0).code

        assert code1 == code2 == code3

    def test_different_period_different_code(self) -> None:
        """Test that different periods produce different codes."""
        secret = b"test_secret"
        config = TotpConfig(secret=secret, period=30)

        code1 = generate_totp(config, timestamp=0.0).code
        code2 = generate_totp(config, timestamp=30.0).code

        assert code1 != code2


class TestEntryTotp:
    """Tests for Entry.totp() method."""

    def test_totp_with_otpauth_uri(self) -> None:
        """Test TOTP generation from otpauth URI."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Test")
        entry.otp = "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP"

        result = entry.totp(at=0.0)
        assert result is not None
        assert isinstance(result, TotpCode)
        assert len(result.code) == 6
        assert result.code.isdigit()

    def test_totp_no_otp_returns_none(self) -> None:
        """Test that entry without OTP returns None."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Test")

        assert entry.totp() is None

    def test_totp_code_properties(self) -> None:
        """Test TotpCode properties from entry."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Test")
        entry.otp = "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&period=30"

        result = entry.totp(at=15.0)
        assert result is not None
        assert result.period == 30
        # expires_at should be at t=30
        assert result.expires_at.timestamp() == 30.0

    def test_totp_with_datetime(self) -> None:
        """Test TOTP with datetime timestamp."""
        from datetime import datetime, timezone

        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Test")
        entry.otp = "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP"

        dt = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        result = entry.totp(at=dt)
        assert result is not None

    def test_totp_deterministic(self) -> None:
        """Test that same timestamp produces same code."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Test")
        entry.otp = "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP"

        code1 = entry.totp(at=12345.0)
        code2 = entry.totp(at=12345.0)
        assert code1 is not None and code2 is not None
        assert code1.code == code2.code

    def test_totp_keepassxc_legacy(self) -> None:
        """Test TOTP with KeePassXC legacy fields."""
        from kdbxtool.models.entry import StringField

        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Test")

        # Set legacy KeePassXC fields
        entry.strings["TOTP Seed"] = StringField("TOTP Seed", "JBSWY3DPEHPK3PXP")
        entry.strings["TOTP Settings"] = StringField("TOTP Settings", "30;6")

        result = entry.totp(at=0.0)
        assert result is not None
        assert len(result.code) == 6

    def test_totp_prefers_otpauth_over_legacy(self) -> None:
        """Test that otpauth URI is preferred over legacy fields."""
        from kdbxtool.models.entry import StringField

        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Test")

        # Set both
        entry.otp = "otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQ"  # Different secret
        entry.strings["TOTP Seed"] = StringField("TOTP Seed", "JBSWY3DPEHPK3PXP")

        # Should use otpauth, not legacy
        result = entry.totp(at=0.0)
        assert result is not None

        # Manually check what otpauth would produce
        config = parse_otpauth_uri("otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQ")
        expected = generate_totp(config, 0.0)

        assert result.code == expected.code

    def test_totp_str_conversion(self) -> None:
        """Test that TotpCode works in string contexts."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Test")
        entry.otp = "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP"

        result = entry.totp(at=0.0)
        assert result is not None

        # Should work with str()
        assert str(result) == result.code

        # Should work in f-strings
        formatted = f"Code: {result}"
        assert result.code in formatted
