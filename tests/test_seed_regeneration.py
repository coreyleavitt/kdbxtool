"""Tests for cryptographic seed regeneration on save."""

from kdbxtool import Database


class TestSeedRegeneration:
    """Tests for seed regeneration on save."""

    def test_seeds_regenerated_on_save(self) -> None:
        """Test that all cryptographic seeds are regenerated on save."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="Test")

        # Get initial seeds
        initial_master_seed = db._header.master_seed
        initial_encryption_iv = db._header.encryption_iv
        initial_kdf_salt = db._header.kdf_salt
        initial_stream_key = db._inner_header.random_stream_key

        # Save the database
        data1 = db.to_bytes()

        # All seeds should be different after save
        assert db._header.master_seed != initial_master_seed
        assert db._header.encryption_iv != initial_encryption_iv
        assert db._header.kdf_salt != initial_kdf_salt
        assert db._inner_header.random_stream_key != initial_stream_key

    def test_seeds_different_each_save(self) -> None:
        """Test that seeds are different on each save."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="Test")

        # First save
        data1 = db.to_bytes()
        seeds_after_first = (
            db._header.master_seed,
            db._header.encryption_iv,
            db._header.kdf_salt,
            db._inner_header.random_stream_key,
        )

        # Second save
        data2 = db.to_bytes()
        seeds_after_second = (
            db._header.master_seed,
            db._header.encryption_iv,
            db._header.kdf_salt,
            db._inner_header.random_stream_key,
        )

        # All seeds should be different between saves
        assert seeds_after_first[0] != seeds_after_second[0]  # master_seed
        assert seeds_after_first[1] != seeds_after_second[1]  # encryption_iv
        assert seeds_after_first[2] != seeds_after_second[2]  # kdf_salt
        assert seeds_after_first[3] != seeds_after_second[3]  # random_stream_key

    def test_regenerate_seeds_false_preserves_seeds(self) -> None:
        """Test that regenerate_seeds=False preserves existing seeds."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="Test")

        # Get initial seeds (after first to_bytes to initialize them)
        db.to_bytes(regenerate_seeds=True)
        master_seed = db._header.master_seed
        encryption_iv = db._header.encryption_iv
        kdf_salt = db._header.kdf_salt
        stream_key = db._inner_header.random_stream_key

        # Save with regenerate_seeds=False
        db.to_bytes(regenerate_seeds=False)

        # Seeds should remain the same
        assert db._header.master_seed == master_seed
        assert db._header.encryption_iv == encryption_iv
        assert db._header.kdf_salt == kdf_salt
        assert db._inner_header.random_stream_key == stream_key

    def test_file_still_readable_after_seed_regeneration(self) -> None:
        """Test that file is still readable after seed regeneration."""
        db = Database.create(password="test")
        entry = db.root_group.create_entry(title="Test Entry", password="secret")

        # Save and reload
        data = db.to_bytes()
        db2 = Database.open_bytes(data, password="test")

        # Verify data is intact
        found = db2.find_entries(title="Test Entry", first=True)
        assert found is not None
        assert found.password == "secret"

    def test_multiple_roundtrips_with_regeneration(self) -> None:
        """Test multiple save/load cycles with seed regeneration."""
        db = Database.create(password="test")
        db.root_group.create_entry(title="Test", password="pass1")

        for i in range(3):
            # Save and reload
            data = db.to_bytes()
            db = Database.open_bytes(data, password="test")

            # Verify data
            entry = db.find_entries(title="Test", first=True)
            assert entry is not None
            assert entry.password == "pass1"

    def test_seed_lengths(self) -> None:
        """Test that regenerated seeds have correct lengths."""
        db = Database.create(password="test")

        # Save to trigger regeneration
        db.to_bytes()

        # master_seed should be 32 bytes
        assert len(db._header.master_seed) == 32

        # encryption_iv depends on cipher (12 for ChaCha20, 16 for AES)
        assert len(db._header.encryption_iv) == db._header.cipher.iv_size

        # kdf_salt should be 32 bytes
        assert len(db._header.kdf_salt) == 32

        # random_stream_key should be 64 bytes
        assert len(db._inner_header.random_stream_key) == 64
