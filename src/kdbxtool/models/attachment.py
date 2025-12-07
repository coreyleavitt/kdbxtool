"""Attachment model for KDBX binary attachments."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .entry import Entry


@dataclass
class Attachment:
    """An attachment (binary file) associated with an entry.

    Attachments represent files attached to entries in the database. The binary
    data is stored at the database level and referenced by ID.

    Attributes:
        filename: Name of the attached file
        id: Reference ID to the binary data in the database
        entry: The entry this attachment belongs to
    """

    filename: str
    id: int
    entry: Entry

    @property
    def data(self) -> bytes | None:
        """Get the binary data for this attachment.

        Returns:
            Binary data if available, None if not found or entry has no database
        """
        if self.entry.database is None:
            return None
        return self.entry.database.get_binary(self.id)

    def __str__(self) -> str:
        return f"Attachment: '{self.filename}' -> {self.id}"

    def __repr__(self) -> str:
        return f"Attachment(filename={self.filename!r}, id={self.id})"
