"""Tests for entry templates."""

from dataclasses import dataclass
from typing import ClassVar

import pytest

from kdbxtool import (
    Database,
    EntryTemplate,
    IconId,
    Templates,
)


class TestIconId:
    """Tests for IconId enum."""

    def test_icon_values(self) -> None:
        """Test that icon IDs have expected values."""
        assert int(IconId.KEY) == 0
        assert int(IconId.WORLD) == 1
        assert int(IconId.MONEY) == 66
        assert int(IconId.BLACKBERRY) == 68

    def test_icon_count(self) -> None:
        """Test that all 69 standard KeePass icons are defined."""
        # KeePass has icons 0-68 = 69 total
        assert len(IconId) == 69

    def test_icon_is_int(self) -> None:
        """Test that IconId values can be used as integers."""
        icon = IconId.EMAIL
        assert isinstance(icon, int)
        assert icon == 19


class TestEntryTemplateBase:
    """Tests for EntryTemplate base class."""

    def test_default_values(self) -> None:
        """Test base class default values."""
        template = EntryTemplate()
        assert template._icon_id == IconId.KEY
        assert template._include_standard is True
        assert template._protected_fields == frozenset()

    def test_get_fields_empty(self) -> None:
        """Test _get_fields on base class returns empty dict."""
        template = EntryTemplate()
        assert template._get_fields() == {}


class TestBuiltInTemplates:
    """Tests for built-in entry templates."""

    def test_login_template(self) -> None:
        """Test Login template attributes."""
        t = Templates.Login()
        assert t._icon_id == IconId.KEY
        assert t._include_standard is True
        assert t._get_fields() == {}

    def test_credit_card_template(self) -> None:
        """Test CreditCard template attributes."""
        t = Templates.CreditCard()
        assert t._icon_id == IconId.MONEY
        assert t._include_standard is False
        # Protected fields
        assert "card_number" in t._protected_fields
        assert "cvv" in t._protected_fields
        assert "pin" in t._protected_fields

    def test_credit_card_fields(self) -> None:
        """Test CreditCard field population."""
        t = Templates.CreditCard(
            card_number="4111111111111111",
            cvv="123",
        )
        fields = t._get_fields()
        assert fields["Card Number"] == ("4111111111111111", True)
        assert fields["Cvv"] == ("123", True)

    def test_secure_note_template(self) -> None:
        """Test SecureNote template attributes."""
        t = Templates.SecureNote()
        assert t._icon_id == IconId.NOTE
        assert t._include_standard is False
        assert t._get_fields() == {}

    def test_identity_template(self) -> None:
        """Test Identity template attributes."""
        t = Templates.Identity(first_name="John", email="john@example.com")
        assert t._icon_id == IconId.IDENTITY
        assert t._include_standard is False
        fields = t._get_fields()
        assert fields["First Name"] == ("John", False)
        assert fields["Email"] == ("john@example.com", False)

    def test_bank_account_template(self) -> None:
        """Test BankAccount template attributes."""
        t = Templates.BankAccount()
        assert t._icon_id == IconId.HOMEBANKING
        assert t._include_standard is False
        assert "account_number" in t._protected_fields
        assert "iban" in t._protected_fields

    def test_server_template(self) -> None:
        """Test Server template attributes."""
        t = Templates.Server(hostname="192.168.1.1")
        assert t._icon_id == IconId.CONSOLE
        assert t._include_standard is True
        assert "ssh_key" in t._protected_fields
        # Check default value
        assert t.port == "22"
        fields = t._get_fields()
        assert fields["Hostname"] == ("192.168.1.1", False)
        assert fields["Port"] == ("22", False)

    def test_wireless_router_template(self) -> None:
        """Test WirelessRouter template attributes."""
        t = Templates.WirelessRouter(ssid="MyNetwork")
        assert t._icon_id == IconId.IR_COMMUNICATION
        assert t.security_type == "WPA2"

    def test_email_template(self) -> None:
        """Test Email template attributes."""
        t = Templates.Email(email_address="user@example.com")
        assert t._icon_id == IconId.EMAIL
        assert t._include_standard is True
        assert t.imap_port == "993"
        assert t.smtp_port == "587"

    def test_software_license_template(self) -> None:
        """Test SoftwareLicense template attributes."""
        t = Templates.SoftwareLicense(license_key="XXXX-XXXX")
        assert t._icon_id == IconId.PACKAGE
        assert t._include_standard is False
        assert "license_key" in t._protected_fields

    def test_database_template(self) -> None:
        """Test Database template attributes."""
        t = Templates.Database(host="localhost")
        assert t._icon_id == IconId.DRIVE
        assert t._include_standard is True
        assert t.database_type == "PostgreSQL"
        assert t.port == "5432"


class TestCreateEntryWithTemplate:
    """Tests for creating entries using templates."""

    @pytest.fixture
    def db(self) -> Database:
        """Create a test database."""
        return Database.create(password="test")

    def test_create_entry_no_template(self, db: Database) -> None:
        """Test creating entry without template (standard behavior)."""
        entry = db.root_group.create_entry(
            title="GitHub",
            username="user@example.com",
            password="secret123",
            url="https://github.com",
        )
        assert entry.title == "GitHub"
        assert entry.username == "user@example.com"
        assert entry.password == "secret123"
        assert entry.url == "https://github.com"

    def test_create_entry_with_login_template(self, db: Database) -> None:
        """Test creating entry with Login template."""
        entry = db.root_group.create_entry(
            title="Gmail",
            username="user@gmail.com",
            password="pass123",
            url="https://gmail.com",
            template=Templates.Login(),
        )
        assert entry.title == "Gmail"
        assert entry.username == "user@gmail.com"
        assert entry.password == "pass123"
        assert entry.icon_id == str(IconId.KEY)

    def test_create_entry_with_credit_card_template(self, db: Database) -> None:
        """Test creating entry with CreditCard template."""
        entry = db.root_group.create_entry(
            title="My Visa",
            template=Templates.CreditCard(
                card_number="4111111111111111",
                expiry_date="12/25",
                cvv="123",
                cardholder_name="John Doe",
            ),
        )
        assert entry.title == "My Visa"
        assert entry.icon_id == str(IconId.MONEY)
        # Standard fields should not be set (include_standard=False)
        assert entry.username is None
        assert entry.password is None
        # Custom fields should be populated
        assert entry.strings["Card Number"].value == "4111111111111111"
        assert entry.strings["Expiry Date"].value == "12/25"
        assert entry.strings["Cvv"].value == "123"
        assert entry.strings["Cardholder Name"].value == "John Doe"
        # Protected fields should be marked as such
        assert entry.strings["Card Number"].protected is True
        assert entry.strings["Cvv"].protected is True

    def test_create_entry_with_server_template(self, db: Database) -> None:
        """Test creating entry with Server template (include_standard=True)."""
        entry = db.root_group.create_entry(
            title="prod-server",
            username="admin",
            password="secret",
            template=Templates.Server(
                hostname="192.168.1.1",
                port="2222",
                ssh_key="-----BEGIN RSA PRIVATE KEY-----",
            ),
        )
        assert entry.title == "prod-server"
        assert entry.username == "admin"
        assert entry.password == "secret"
        assert entry.icon_id == str(IconId.CONSOLE)
        assert entry.strings["Hostname"].value == "192.168.1.1"
        assert entry.strings["Port"].value == "2222"
        assert entry.strings["Ssh Key"].value == "-----BEGIN RSA PRIVATE KEY-----"
        assert entry.strings["Ssh Key"].protected is True

    def test_create_entry_template_defaults(self, db: Database) -> None:
        """Test that template field defaults are applied."""
        entry = db.root_group.create_entry(
            title="my-server",
            template=Templates.Server(hostname="10.0.0.1"),
        )
        # Port should have default value from template
        assert entry.strings["Port"].value == "22"

    def test_create_entry_secure_note(self, db: Database) -> None:
        """Test creating a secure note."""
        entry = db.root_group.create_entry(
            title="My Secret",
            notes="This is confidential information.",
            template=Templates.SecureNote(),
        )
        assert entry.title == "My Secret"
        assert entry.notes == "This is confidential information."
        assert entry.icon_id == str(IconId.NOTE)
        # No standard fields
        assert entry.username is None
        assert entry.password is None

    def test_create_entry_identity(self, db: Database) -> None:
        """Test creating an identity entry."""
        entry = db.root_group.create_entry(
            title="Personal",
            template=Templates.Identity(
                first_name="John",
                last_name="Doe",
                email="john@example.com",
                phone="555-1234",
            ),
        )
        assert entry.title == "Personal"
        assert entry.strings["First Name"].value == "John"
        assert entry.strings["Last Name"].value == "Doe"
        assert entry.strings["Email"].value == "john@example.com"
        assert entry.strings["Phone"].value == "555-1234"

    def test_none_fields_not_added(self, db: Database) -> None:
        """Test that None fields are not added to entry."""
        entry = db.root_group.create_entry(
            title="Partial Card",
            template=Templates.CreditCard(
                card_number="1234",
                # other fields left as None
            ),
        )
        assert "Card Number" in entry.strings
        assert "Expiry Date" not in entry.strings
        assert "Cvv" not in entry.strings


class TestCustomTemplate:
    """Tests for creating and using custom templates."""

    @pytest.fixture
    def db(self) -> Database:
        """Create a test database."""
        return Database.create(password="test")

    def test_custom_template(self, db: Database) -> None:
        """Test creating entry with a custom template."""

        @dataclass
        class VPNConnection(EntryTemplate):
            _icon_id: ClassVar[int] = IconId.TERMINAL_ENCRYPTED
            _protected_fields: ClassVar[frozenset[str]] = frozenset({"certificate"})

            server: str | None = None
            protocol: str = "OpenVPN"
            certificate: str | None = None

        entry = db.root_group.create_entry(
            title="Work VPN",
            username="johnd",
            password="vpnpass",
            template=VPNConnection(
                server="vpn.company.com",
                certificate="-----BEGIN CERTIFICATE-----",
            ),
        )

        assert entry.title == "Work VPN"
        assert entry.username == "johnd"  # include_standard=True by default
        assert entry.icon_id == str(IconId.TERMINAL_ENCRYPTED)
        assert entry.strings["Server"].value == "vpn.company.com"
        assert entry.strings["Protocol"].value == "OpenVPN"  # default
        assert entry.strings["Certificate"].value == "-----BEGIN CERTIFICATE-----"
        assert entry.strings["Certificate"].protected is True

    def test_custom_template_no_standard_fields(self, db: Database) -> None:
        """Test custom template that excludes standard fields."""

        @dataclass
        class ApiKey(EntryTemplate):
            _icon_id: ClassVar[int] = IconId.KEY
            _include_standard: ClassVar[bool] = False
            _protected_fields: ClassVar[frozenset[str]] = frozenset({"api_key"})

            api_key: str | None = None
            environment: str = "production"

        entry = db.root_group.create_entry(
            title="Stripe API",
            username="ignored",  # Should be ignored
            password="also_ignored",  # Should be ignored
            template=ApiKey(api_key="sk_live_xxxxx"),
        )

        assert entry.title == "Stripe API"
        assert entry.username is None  # Not set because include_standard=False
        assert entry.password is None
        assert entry.strings["Api Key"].value == "sk_live_xxxxx"
        assert entry.strings["Environment"].value == "production"
