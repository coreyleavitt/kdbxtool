"""Tests for secure memory handling."""

import pytest

from kdbxtool.security.memory import SecureBytes


class TestSecureBytes:
    """Tests for SecureBytes class."""

    def test_init_from_bytes(self) -> None:
        """Test initialization from bytes."""
        data = b"secret password"
        sb = SecureBytes(data)
        assert sb.data == data
        assert len(sb) == len(data)

    def test_init_from_bytearray(self) -> None:
        """Test initialization from bytearray."""
        data = bytearray(b"secret password")
        sb = SecureBytes(data)
        assert sb.data == b"secret password"

    def test_from_str(self) -> None:
        """Test creation from string."""
        sb = SecureBytes.from_str("password123")
        assert sb.data == b"password123"

    def test_from_str_with_encoding(self) -> None:
        """Test creation from string with custom encoding."""
        sb = SecureBytes.from_str("password123", encoding="ascii")
        assert sb.data == b"password123"

    def test_zeroize(self) -> None:
        """Test that zeroize overwrites buffer with zeros."""
        sb = SecureBytes(b"secret")
        sb.zeroize()
        # After zeroize, accessing data should raise
        with pytest.raises(ValueError, match="zeroized"):
            _ = sb.data

    def test_zeroize_idempotent(self) -> None:
        """Test that zeroize can be called multiple times safely."""
        sb = SecureBytes(b"secret")
        sb.zeroize()
        sb.zeroize()  # Should not raise
        sb.zeroize()  # Should not raise

    def test_context_manager(self) -> None:
        """Test context manager zeroizes on exit."""
        with SecureBytes(b"secret") as sb:
            assert sb.data == b"secret"
        # After context exit, buffer should be zeroized
        with pytest.raises(ValueError, match="zeroized"):
            _ = sb.data

    def test_context_manager_on_exception(self) -> None:
        """Test context manager zeroizes even on exception."""
        try:
            with SecureBytes(b"secret") as sb:
                raise RuntimeError("test error")
        except RuntimeError:
            pass
        # Should still be zeroized
        with pytest.raises(ValueError, match="zeroized"):
            _ = sb.data

    def test_repr_does_not_expose_data(self) -> None:
        """Test that repr doesn't reveal sensitive data."""
        sb = SecureBytes(b"supersecretpassword")
        repr_str = repr(sb)
        assert "supersecretpassword" not in repr_str
        assert "19 bytes" in repr_str

    def test_repr_after_zeroize(self) -> None:
        """Test repr shows zeroized state."""
        sb = SecureBytes(b"secret")
        sb.zeroize()
        assert "zeroized" in repr(sb)

    def test_str_does_not_expose_data(self) -> None:
        """Test that str doesn't reveal sensitive data."""
        sb = SecureBytes(b"supersecretpassword")
        str_repr = str(sb)
        assert "supersecretpassword" not in str_repr

    def test_bool_true_when_has_data(self) -> None:
        """Test bool is True when buffer has data."""
        sb = SecureBytes(b"secret")
        assert bool(sb) is True

    def test_bool_false_when_empty(self) -> None:
        """Test bool is False when buffer is empty."""
        sb = SecureBytes(b"")
        assert bool(sb) is False

    def test_bool_false_after_zeroize(self) -> None:
        """Test bool is False after zeroize."""
        sb = SecureBytes(b"secret")
        sb.zeroize()
        assert bool(sb) is False

    def test_equality_constant_time(self) -> None:
        """Test that equal buffers compare equal."""
        sb1 = SecureBytes(b"password")
        sb2 = SecureBytes(b"password")
        assert sb1 == sb2

    def test_inequality(self) -> None:
        """Test that different buffers compare not equal."""
        sb1 = SecureBytes(b"password1")
        sb2 = SecureBytes(b"password2")
        assert sb1 != sb2

    def test_equality_after_zeroize(self) -> None:
        """Test that zeroized buffers are not equal."""
        sb1 = SecureBytes(b"password")
        sb2 = SecureBytes(b"password")
        sb1.zeroize()
        assert sb1 != sb2

    def test_equality_with_non_securebytes(self) -> None:
        """Test comparison with non-SecureBytes returns NotImplemented."""
        sb = SecureBytes(b"password")
        assert (sb == b"password") is False  # Falls through to NotImplemented

    def test_not_hashable(self) -> None:
        """Test that SecureBytes cannot be hashed (security measure)."""
        sb = SecureBytes(b"password")
        with pytest.raises(TypeError, match="not hashable"):
            hash(sb)


class TestSecureBytesDestructor:
    """Tests for destructor behavior."""

    def test_destructor_zeroizes(self) -> None:
        """Test that destructor zeroizes buffer."""
        # Create and let it go out of scope
        sb = SecureBytes(b"secret")
        # Get reference to internal buffer before deletion
        buffer_ref = sb._buffer

        # Delete the object
        del sb

        # Buffer should now be all zeros
        # Note: This test is somewhat fragile due to GC timing
        assert all(b == 0 for b in buffer_ref)
