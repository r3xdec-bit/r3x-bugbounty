"""
R3X Encrypted Keystore
Safely stores and manages multi-provider API keys using encrypted local storage.
"""
import base64
import hashlib
import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from r3x.core.config import settings
from r3x.core.exceptions import KeyStoreError
from r3x.core.logger import logger


class APIKeyEntry:
    def __init__(
        self,
        key_id: str,
        provider: str,
        key_value: str,
        label: str = "default",
        added_at: str | None = None,
        is_active: bool = True,
        usage_count: int = 0,
        failed_count: int = 0,
        last_used: str | None = None
    ):
        self.key_id = key_id
        self.provider = provider.lower()
        self.key_value = key_value
        self.label = label
        self.added_at = added_at or datetime.now(UTC).isoformat()
        self.is_active = is_active
        self.usage_count = usage_count
        self.failed_count = failed_count
        self.last_used = last_used

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "provider": self.provider,
            "key_value": self.key_value,
            "label": self.label,
            "added_at": self.added_at,
            "is_active": self.is_active,
            "usage_count": self.usage_count,
            "failed_count": self.failed_count,
            "last_used": self.last_used
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "APIKeyEntry":
        return cls(**data)

    def mask(self) -> str:
        """Return masked key for safe display in CLI."""
        val = self.key_value
        if len(val) <= 8:
            return "***"
        return f"{val[:4]}...{val[-4:]}"

class KeyStore:
    def __init__(self, vault_path: Path | None = None):
        self.vault_path = vault_path or settings.keystore_path
        self._key_cache: dict[str, list[APIKeyEntry]] = {}
        self._fernet: Fernet | None = None
        self._init_encryption()
        self._load()

    def _get_machine_seed(self) -> bytes:
        """Derive consistent machine-specific salt and entropy."""
        machine_id = "r3x-security-entropy"
        for candidate in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
            if os.path.exists(candidate):
                try:
                    with open(candidate, "r") as f:
                        machine_id = f.read().strip()
                        break
                except (OSError, UnicodeDecodeError) as e:
                    logger.debug("Cannot read machine-id candidate %s: %s", candidate, e)
        user = os.environ.get("USER", "r3xuser")
        home = str(Path.home())
        return f"{machine_id}:{user}:{home}".encode()

    def _init_encryption(self) -> None:
        """Derive encryption key via PBKDF2."""
        salt = hashlib.sha256(self._get_machine_seed()).digest()[:16]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        derived_key = base64.urlsafe_b64encode(kdf.derive(b"r3x-ai-mixer-master-key"))
        self._fernet = Fernet(derived_key)

    def _save(self) -> None:
        """Encrypt and persist vault to disk."""
        if not self._fernet:
            raise KeyStoreError("Keystore encryption not initialized")

        raw_data: list[dict[str, Any]] = []
        for entries in self._key_cache.values():
            for e in entries:
                raw_data.append(e.to_dict())

        json_bytes = json.dumps(raw_data).encode("utf-8")
        encrypted = self._fernet.encrypt(json_bytes)

        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.vault_path, "wb") as f:
            f.write(encrypted)
        os.chmod(self.vault_path, 0o600)  # Restricted user permissions

    def _load(self) -> None:
        """Read and decrypt vault from disk."""
        self._key_cache.clear()
        if not self.vault_path.exists():
            return

        try:
            with open(self.vault_path, "rb") as f:
                encrypted = f.read()
            if not encrypted:
                return

            decrypted = self._fernet.decrypt(encrypted)
            items = json.loads(decrypted.decode("utf-8"))
            for item in items:
                entry = APIKeyEntry.from_dict(item)
                if entry.provider not in self._key_cache:
                    self._key_cache[entry.provider] = []
                self._key_cache[entry.provider].append(entry)
        except Exception as e:
            raise KeyStoreError(f"Failed to decrypt keystore vault: {e}")

    def add_key(self, provider: str, key_value: str, label: str = "default") -> APIKeyEntry:
        """Add an API key to the secure store."""
        provider = provider.strip().lower()
        key_value = key_value.strip()

        if not key_value:
            raise KeyStoreError("API Key cannot be empty.")

        if provider not in self._key_cache:
            self._key_cache[provider] = []

        # Avoid duplicates
        for existing in self._key_cache[provider]:
            if existing.key_value == key_value:
                existing.label = label
                existing.is_active = True
                self._save()
                return existing

        entry = APIKeyEntry(
            key_id=str(uuid.uuid4())[:8],
            provider=provider,
            key_value=key_value,
            label=label
        )
        self._key_cache[provider].append(entry)
        self._save()
        return entry

    def remove_key(self, key_id: str) -> bool:
        """Remove a key by its ID."""
        for entries in self._key_cache.values():
            for i, entry in enumerate(entries):
                if entry.key_id == key_id:
                    entries.pop(i)
                    self._save()
                    return True
        return False

    def get_keys(self, provider: str, active_only: bool = True) -> list[APIKeyEntry]:
        """Get all keys for a specific provider."""
        provider = provider.strip().lower()
        entries = self._key_cache.get(provider, [])
        if active_only:
            return [e for e in entries if e.is_active]
        return entries

    def get_active_key(self, provider: str) -> APIKeyEntry | None:
        """Retrieve the best active key with load-balancing (least recently used)."""
        entries = self.get_keys(provider, active_only=True)
        if not entries:
            return None
        # Sort by usage count and failures to load-balance
        sorted_entries = sorted(entries, key=lambda x: (x.failed_count, x.usage_count))
        chosen = sorted_entries[0]
        chosen.usage_count += 1
        chosen.last_used = datetime.now(UTC).isoformat()
        self._save()
        return chosen

    def mark_key_failure(self, key_id: str) -> None:
        """Record a failure event for backoff/rotation."""
        for entries in self._key_cache.values():
            for entry in entries:
                if entry.key_id == key_id:
                    entry.failed_count += 1
                    if entry.failed_count >= 5:
                        entry.is_active = False  # Auto-disable after repeated failures
                    self._save()
                    return

    def mark_key_success(self, key_id: str) -> None:
        """Record success and reset fail counter."""
        for entries in self._key_cache.values():
            for entry in entries:
                if entry.key_id == key_id:
                    entry.failed_count = 0
                    self._save()
                    return

    def list_all(self) -> list[APIKeyEntry]:
        """List all keys across all providers."""
        all_keys = []
        for entries in self._key_cache.values():
            all_keys.extend(entries)
        return all_keys

    def get_status_summary(self) -> dict[str, Any]:
        """Get high-level summary of keystore contents."""
        total = sum(len(entries) for entries in self._key_cache.values())
        active = sum(sum(1 for e in entries if e.is_active) for entries in self._key_cache.values())
        providers = [p for p, entries in self._key_cache.items() if any(e.is_active for e in entries)]
        return {
            "total_keys": total,
            "active_keys": active,
            "active_providers": providers,
            "provider_breakdown": {p: len(entries) for p, entries in self._key_cache.items()}
        }

key_store = KeyStore()
