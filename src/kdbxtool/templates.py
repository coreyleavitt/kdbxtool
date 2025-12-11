"""Entry templates for common account types.

This module provides typed template classes for creating entries with predefined
fields and icons. Templates follow KeePass conventions for icon IDs and provide
full IDE autocompletion for field names.

Example:
    >>> from kdbxtool import Database, Templates
    >>> db = Database.create(password="secret")
    >>> entry = db.root_group.create_entry(
    ...     title="GitHub",
    ...     template=Templates.Login(),
    ...     username="user@example.com",
    ...     password="secret123",
    ...     url="https://github.com",
    ... )
    >>> entry = db.root_group.create_entry(
    ...     title="Visa Card",
    ...     template=Templates.CreditCard(
    ...         card_number="4111111111111111",
    ...         expiry_date="12/25",
    ...         cvv="123",
    ...     ),
    ... )

Custom templates can be created by subclassing EntryTemplate:
    >>> from dataclasses import dataclass
    >>> from typing import ClassVar
    >>> from kdbxtool import EntryTemplate, IconId
    >>>
    >>> @dataclass
    ... class VPNConnection(EntryTemplate):
    ...     _icon_id: ClassVar[int] = IconId.TERMINAL_ENCRYPTED
    ...     _protected_fields: ClassVar[frozenset[str]] = frozenset({"certificate"})
    ...
    ...     server: str | None = None
    ...     protocol: str = "OpenVPN"
    ...     certificate: str | None = None
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from enum import IntEnum
from typing import ClassVar


class IconId(IntEnum):
    """KeePass standard icon IDs.

    These correspond to the PwIcon enumeration in KeePass. There are 69
    standard icons (0-68) built into KeePass/KeePassXC.
    """

    KEY = 0
    WORLD = 1
    WARNING = 2
    NETWORK_SERVER = 3
    MARKED_DIRECTORY = 4
    USER_COMMUNICATION = 5
    PARTS = 6
    NOTEPAD = 7
    WORLD_SOCKET = 8
    IDENTITY = 9
    PAPER_READY = 10
    DIGICAM = 11
    IR_COMMUNICATION = 12
    MULTI_KEYS = 13
    ENERGY = 14
    SCANNER = 15
    WORLD_STAR = 16
    CDROM = 17
    MONITOR = 18
    EMAIL = 19
    CONFIGURATION = 20
    CLIPBOARD_READY = 21
    PAPER_NEW = 22
    SCREEN = 23
    ENERGY_CAREFUL = 24
    EMAIL_BOX = 25
    DISK = 26
    DRIVE = 27
    PAPER_Q = 28
    TERMINAL_ENCRYPTED = 29
    CONSOLE = 30
    PRINTER = 31
    PROGRAM_ICONS = 32
    RUN = 33
    SETTINGS = 34
    WORLD_COMPUTER = 35
    ARCHIVE = 36
    HOMEBANKING = 37
    DRIVE_WINDOWS = 38
    CLOCK = 39
    EMAIL_SEARCH = 40
    PAPER_FLAG = 41
    MEMORY = 42
    TRASH_BIN = 43
    NOTE = 44
    EXPIRED = 45
    INFO = 46
    PACKAGE = 47
    FOLDER = 48
    FOLDER_OPEN = 49
    FOLDER_PACKAGE = 50
    LOCK_OPEN = 51
    PAPER_LOCKED = 52
    CHECKED = 53
    PEN = 54
    THUMBNAIL = 55
    BOOK = 56
    LIST = 57
    USER_KEY = 58
    TOOL = 59
    HOME = 60
    STAR = 61
    TUX = 62
    FEATHER = 63
    APPLE = 64
    WIKI = 65
    MONEY = 66
    CERTIFICATE = 67
    BLACKBERRY = 68


@dataclass
class EntryTemplate:
    """Base class for entry templates. Subclass to create custom templates.

    Class variables to override:
        _icon_id: Icon for entries using this template (default: KEY)
        _include_standard: Whether to populate username/password/url (default: True)
        _protected_fields: Field names that should be memory-protected

    Example:
        >>> @dataclass
        ... class VPNConnection(EntryTemplate):
        ...     _icon_id: ClassVar[int] = IconId.TERMINAL_ENCRYPTED
        ...     _protected_fields: ClassVar[frozenset[str]] = frozenset({"certificate"})
        ...
        ...     server: str | None = None
        ...     protocol: str = "OpenVPN"
        ...     certificate: str | None = None
        ...
        >>> entry = group.create_entry(
        ...     title="Work VPN",
        ...     template=VPNConnection(server="vpn.company.com"),
        ... )
    """

    _icon_id: ClassVar[int] = IconId.KEY
    _include_standard: ClassVar[bool] = True
    _protected_fields: ClassVar[frozenset[str]] = frozenset()

    def _get_fields(self) -> dict[str, tuple[str | None, bool]]:
        """Return template field values with display names and protection status.

        Returns:
            Dict mapping display name to (value, is_protected) tuple.
            Display names are derived from field names by replacing underscores
            with spaces and title-casing.
        """
        result: dict[str, tuple[str | None, bool]] = {}
        for field in fields(self):
            if field.name.startswith("_"):
                continue  # Skip class variables
            value = getattr(self, field.name)
            display_name = field.name.replace("_", " ").title()
            is_protected = field.name in self._protected_fields
            result[display_name] = (value, is_protected)
        return result


# --- Built-in Templates ---


@dataclass
class Login(EntryTemplate):
    """Standard login entry template.

    Uses standard fields (title, username, password, url) without
    additional custom fields.
    """


@dataclass
class CreditCard(EntryTemplate):
    """Credit card entry template.

    Includes card number, expiry date, CVV, cardholder name, and PIN.
    Sensitive fields (card_number, cvv, pin) are memory-protected.
    Does not use standard username/password fields.
    """

    _icon_id: ClassVar[int] = IconId.MONEY
    _include_standard: ClassVar[bool] = False
    _protected_fields: ClassVar[frozenset[str]] = frozenset({"card_number", "cvv", "pin"})

    card_number: str | None = None
    expiry_date: str | None = None
    cvv: str | None = None
    cardholder_name: str | None = None
    pin: str | None = None


@dataclass
class SecureNote(EntryTemplate):
    """Secure note entry template.

    For storing text without standard credential fields.
    Use the notes parameter in create_entry() for content.
    """

    _icon_id: ClassVar[int] = IconId.NOTE
    _include_standard: ClassVar[bool] = False


@dataclass
class Identity(EntryTemplate):
    """Identity/personal information entry template.

    Includes name, contact, and address fields.
    Does not use standard username/password fields.
    """

    _icon_id: ClassVar[int] = IconId.IDENTITY
    _include_standard: ClassVar[bool] = False

    first_name: str | None = None
    last_name: str | None = None
    email: str | None = None
    phone: str | None = None
    address: str | None = None
    city: str | None = None
    state: str | None = None
    postal_code: str | None = None
    country: str | None = None


@dataclass
class BankAccount(EntryTemplate):
    """Bank account entry template.

    Includes account details and routing information.
    Sensitive fields (account_number, iban, pin) are memory-protected.
    Does not use standard username/password fields.
    """

    _icon_id: ClassVar[int] = IconId.HOMEBANKING
    _include_standard: ClassVar[bool] = False
    _protected_fields: ClassVar[frozenset[str]] = frozenset({"account_number", "iban", "pin"})

    bank_name: str | None = None
    account_type: str | None = None
    account_number: str | None = None
    routing_number: str | None = None
    swift_bic: str | None = None
    iban: str | None = None
    pin: str | None = None


@dataclass
class Server(EntryTemplate):
    """Server/SSH entry template.

    Includes hostname, port, and SSH key fields.
    Uses standard username/password fields for credentials.
    SSH key is memory-protected.
    """

    _icon_id: ClassVar[int] = IconId.CONSOLE
    _protected_fields: ClassVar[frozenset[str]] = frozenset({"ssh_key"})

    hostname: str | None = None
    port: str = "22"
    ssh_key: str | None = None


@dataclass
class WirelessRouter(EntryTemplate):
    """Wireless router entry template.

    Includes SSID, security type, and admin credentials.
    Admin password is memory-protected.
    """

    _icon_id: ClassVar[int] = IconId.IR_COMMUNICATION
    _protected_fields: ClassVar[frozenset[str]] = frozenset({"admin_password"})

    ssid: str | None = None
    security_type: str = "WPA2"
    admin_url: str | None = None
    admin_username: str | None = None
    admin_password: str | None = None


@dataclass
class Email(EntryTemplate):
    """Email account entry template.

    Includes email address and server settings.
    Uses standard username/password fields for credentials.
    """

    _icon_id: ClassVar[int] = IconId.EMAIL

    email_address: str | None = None
    imap_server: str | None = None
    imap_port: str = "993"
    smtp_server: str | None = None
    smtp_port: str = "587"


@dataclass
class SoftwareLicense(EntryTemplate):
    """Software license entry template.

    Includes license key and registration information.
    License key is memory-protected.
    Does not use standard username/password fields.
    """

    _icon_id: ClassVar[int] = IconId.PACKAGE
    _include_standard: ClassVar[bool] = False
    _protected_fields: ClassVar[frozenset[str]] = frozenset({"license_key"})

    license_key: str | None = None
    registered_email: str | None = None
    registered_name: str | None = None
    purchase_date: str | None = None
    download_url: str | None = None


@dataclass
class DatabaseConnection(EntryTemplate):
    """Database connection entry template.

    Includes database type, host, port, and connection details.
    Connection string is memory-protected.
    Uses standard username/password fields for credentials.
    """

    _icon_id: ClassVar[int] = IconId.DRIVE
    _protected_fields: ClassVar[frozenset[str]] = frozenset({"connection_string"})

    database_type: str = "PostgreSQL"
    host: str | None = None
    port: str = "5432"
    database_name: str | None = None
    connection_string: str | None = None


class Templates:
    """Namespace containing all built-in entry templates.

    Provides discoverability via IDE autocompletion.

    Usage:
        >>> from kdbxtool import Templates
        >>>
        >>> entry = group.create_entry(
        ...     title="My Card",
        ...     template=Templates.CreditCard(
        ...         card_number="4111111111111111",
        ...         cvv="123",
        ...     ),
        ... )

    Available templates:
        - Login: Standard login (username, password, url)
        - CreditCard: Card number, expiry, CVV, cardholder, PIN
        - SecureNote: Notes-only entry
        - Identity: Personal information (name, address, etc.)
        - BankAccount: Account and routing numbers
        - Server: Hostname, port, SSH key
        - WirelessRouter: SSID, security type, admin credentials
        - Email: Email address and server settings
        - SoftwareLicense: License key and registration info
        - Database: Database connection details
    """

    Login = Login
    CreditCard = CreditCard
    SecureNote = SecureNote
    Identity = Identity
    BankAccount = BankAccount
    Server = Server
    WirelessRouter = WirelessRouter
    Email = Email
    SoftwareLicense = SoftwareLicense
    Database = DatabaseConnection
