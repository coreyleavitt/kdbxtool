"""Timestamp handling for KDBX elements."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now() -> datetime:
    """Get current UTC time."""
    return datetime.now(UTC)


@dataclass
class Times:
    """Timestamps associated with entries and groups.

    All times are stored as timezone-aware UTC datetimes.

    Attributes:
        creation_time: When the element was created
        last_modification_time: When the element was last modified
        last_access_time: When the element was last accessed
        expiry_time: When the element expires (if expires is True)
        expires: Whether the element can expire
        usage_count: Number of times the element has been used
        location_changed: When the element was moved to a different group
    """

    creation_time: datetime = field(default_factory=_now)
    last_modification_time: datetime = field(default_factory=_now)
    last_access_time: datetime = field(default_factory=_now)
    expiry_time: datetime | None = None
    expires: bool = False
    usage_count: int = 0
    location_changed: datetime | None = None

    def __post_init__(self) -> None:
        """Ensure location_changed has a default value."""
        if self.location_changed is None:
            self.location_changed = self.creation_time

    @property
    def expired(self) -> bool:
        """Check if the element has expired.

        Returns:
            True if expires is True and expiry_time is in the past
        """
        if not self.expires or self.expiry_time is None:
            return False
        return datetime.now(UTC) > self.expiry_time

    def touch(self, modify: bool = False) -> None:
        """Update access time, and optionally modification time.

        Args:
            modify: If True, also update modification time
        """
        now = _now()
        self.last_access_time = now
        if modify:
            self.last_modification_time = now

    def increment_usage(self) -> None:
        """Increment usage count and update access time."""
        self.usage_count += 1
        self.touch()

    def update_location(self) -> None:
        """Update location_changed timestamp when element is moved."""
        self.location_changed = _now()
        self.touch(modify=True)

    @classmethod
    def create_new(
        cls,
        expires: bool = False,
        expiry_time: datetime | None = None,
    ) -> Times:
        """Create timestamps for a new element.

        Args:
            expires: Whether the element can expire
            expiry_time: When the element expires

        Returns:
            New Times instance with current timestamps
        """
        now = _now()
        return cls(
            creation_time=now,
            last_modification_time=now,
            last_access_time=now,
            expiry_time=expiry_time,
            expires=expires,
            usage_count=0,
            location_changed=now,
        )
