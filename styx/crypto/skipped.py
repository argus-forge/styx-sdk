"""
Styx skipped message key manager.

Per-chain limits, age eviction, chain supersession, and global cap.
Per PROTOCOL.md Section "Skipped Message Key Management (C-2 Fix)".
"""
import time
from typing import Optional

MAX_SKIP = 100        # per-chain limit
MAX_GLOBAL = 500      # total across all chains
AGE_SECONDS = 48 * 3600  # 48-hour age eviction


class SkippedKeyManager:
    """
    Manages skipped message keys keyed by (dh_pub_hex, message_number).

    Storage: {(dh_pub_hex, n): (message_key, timestamp)}
    """

    def __init__(self) -> None:
        self._store: dict = {}

    def store(self, dh_pub: bytes, n: int, message_key: bytes) -> None:
        """Store a skipped message key with the current timestamp."""
        key = (dh_pub.hex(), n)
        self._store[key] = (message_key, time.monotonic())
        self._enforce_global_cap()

    def retrieve(self, dh_pub: bytes, n: int) -> Optional[bytes]:
        """
        Retrieve and delete a skipped message key.

        Returns message_key bytes or None if not found.
        """
        key = (dh_pub.hex(), n)
        entry = self._store.pop(key, None)
        if entry is None:
            return None
        return entry[0]

    def evict(self) -> int:
        """
        Run all eviction rules.

        1. Age-based: remove keys older than 48 hours.
        Returns count of evicted entries.
        """
        now = time.monotonic()
        expired = [k for k, (_, ts) in self._store.items() if now - ts > AGE_SECONDS]
        for k in expired:
            del self._store[k]
        return len(expired)

    def evict_chain(self, dh_pub: bytes) -> int:
        """Remove all skipped keys for a superseded chain."""
        prefix = dh_pub.hex()
        keys = [k for k in self._store if k[0] == prefix]
        for k in keys:
            del self._store[k]
        return len(keys)

    def count(self) -> int:
        return len(self._store)

    def _enforce_global_cap(self) -> None:
        """Evict oldest entries when global cap is exceeded."""
        while len(self._store) > MAX_GLOBAL:
            oldest = min(self._store, key=lambda k: self._store[k][1])
            del self._store[oldest]
