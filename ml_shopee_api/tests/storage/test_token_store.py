import os
import stat
import sys

import pytest
from cryptography.fernet import Fernet

from storage.token_store import SecureTokenStore, TokenStoreError


@pytest.fixture
def key():
    return Fernet.generate_key()


@pytest.fixture
def store_path(tmp_path):
    return tmp_path / "tokens.enc"


class TestSaveLoad:
    def test_load_missing_file_returns_none(self, store_path, key):
        store = SecureTokenStore(store_path, key)

        assert store.load("mercadolivre") is None

    def test_save_then_load_roundtrip(self, store_path, key):
        store = SecureTokenStore(store_path, key)

        store.save("mercadolivre", {"access_token": "a", "refresh_token": "r"})

        assert store.load("mercadolivre") == {"access_token": "a", "refresh_token": "r"}

    def test_multiple_namespaces_are_independent(self, store_path, key):
        store = SecureTokenStore(store_path, key)

        store.save("mercadolivre", {"access_token": "ml-a"})
        store.save("shopee", {"access_token": "shopee-a"})

        assert store.load("mercadolivre") == {"access_token": "ml-a"}
        assert store.load("shopee") == {"access_token": "shopee-a"}

    def test_save_overwrites_existing_namespace(self, store_path, key):
        store = SecureTokenStore(store_path, key)

        store.save("mercadolivre", {"access_token": "first"})
        store.save("mercadolivre", {"access_token": "second"})

        assert store.load("mercadolivre") == {"access_token": "second"}

    def test_file_content_is_encrypted_on_disk(self, store_path, key):
        store = SecureTokenStore(store_path, key)
        store.save("mercadolivre", {"access_token": "super-secret-value"})

        raw = store_path.read_bytes()

        assert b"super-secret-value" not in raw


class TestDelete:
    def test_delete_removes_only_target_namespace(self, store_path, key):
        store = SecureTokenStore(store_path, key)
        store.save("mercadolivre", {"access_token": "ml-a"})
        store.save("shopee", {"access_token": "shopee-a"})

        store.delete("mercadolivre")

        assert store.load("mercadolivre") is None
        assert store.load("shopee") == {"access_token": "shopee-a"}

    def test_delete_on_missing_namespace_is_noop(self, store_path, key):
        store = SecureTokenStore(store_path, key)

        store.delete("does-not-exist")

        assert store.load("does-not-exist") is None

    def test_delete_on_missing_file_is_noop(self, store_path, key):
        store = SecureTokenStore(store_path, key)

        store.delete("mercadolivre")


class TestSecurityProperties:
    def test_wrong_key_cannot_decrypt(self, store_path, key):
        store = SecureTokenStore(store_path, key)
        store.save("mercadolivre", {"access_token": "a"})

        other_store = SecureTokenStore(store_path, Fernet.generate_key())

        with pytest.raises(TokenStoreError):
            other_store.load("mercadolivre")

    def test_corrupted_file_raises_token_store_error(self, store_path, key):
        store = SecureTokenStore(store_path, key)
        store.save("mercadolivre", {"access_token": "a"})

        with open(store_path, "r+b") as f:
            content = bytearray(f.read())
            content[-1] ^= 0xFF
            f.seek(0)
            f.write(content)

        with pytest.raises(TokenStoreError):
            store.load("mercadolivre")

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX file permission bits aren't meaningful on NTFS")
    def test_file_written_with_owner_only_permissions(self, store_path, key):
        store = SecureTokenStore(store_path, key)

        store.save("mercadolivre", {"access_token": "a"})

        mode = stat.S_IMODE(os.stat(store_path).st_mode)
        assert mode == 0o600

    def test_no_leftover_tmp_file_after_save(self, store_path, key):
        store = SecureTokenStore(store_path, key)

        store.save("mercadolivre", {"access_token": "a"})

        tmp_path = store_path.with_suffix(store_path.suffix + ".tmp")
        assert not tmp_path.exists()
