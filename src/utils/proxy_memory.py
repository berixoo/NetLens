"""Proxy memory — persist verified proxy addresses for quick reuse."""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

_DEFAULT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "proxy_memory.json")


@dataclass
class ProxyRecord:
    ip: str
    port: int
    proxy_type: str = ""        # HTTP / SOCKS4 / SOCKS5
    latency_ms: float = 0.0
    requires_auth: bool = False
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    last_used: float = 0.0      # last time user chose to use this proxy
    use_count: int = 0           # how many times user applied it
    success_count: int = 0       # how many times connectivity test passed
    notes: str = ""

    @property
    def address(self) -> str:
        return f"{self.ip}:{self.port}"

    @property
    def label(self) -> str:
        auth = " [认证]" if self.requires_auth else ""
        latency = f" {self.latency_ms:.0f}ms" if self.latency_ms else ""
        return f"{self.address} ({self.proxy_type}{auth}{latency})"


class ProxyMemory:
    """Thread-safe persistent storage for verified proxy records."""

    def __init__(self, filepath: str | None = None):
        self._filepath = filepath or _DEFAULT_PATH
        self._lock = threading.Lock()
        self._records: dict[str, ProxyRecord] = {}   # key = "ip:port"
        self._load()

    # -- public API --------------------------------------------------

    @property
    def records(self) -> list[ProxyRecord]:
        with self._lock:
            # sorted by last_seen descending (most recent first)
            return sorted(self._records.values(), key=lambda r: r.last_seen, reverse=True)

    def add_or_update(self, ip: str, port: int, proxy_type: str = "",
                      latency_ms: float = 0.0, requires_auth: bool = False) -> ProxyRecord:
        """Add a new record or update an existing one. Returns the record."""
        key = f"{ip}:{port}"
        with self._lock:
            if key in self._records:
                rec = self._records[key]
                rec.last_seen = time.time()
                rec.success_count += 1
                if proxy_type:
                    rec.proxy_type = proxy_type
                if latency_ms > 0:
                    rec.latency_ms = latency_ms
                rec.requires_auth = requires_auth
            else:
                rec = ProxyRecord(
                    ip=ip, port=port, proxy_type=proxy_type,
                    latency_ms=latency_ms, requires_auth=requires_auth,
                )
                self._records[key] = rec
            self._save_unlocked()
            return rec

    def mark_used(self, ip: str, port: int) -> None:
        """Record that the user chose to apply this proxy."""
        key = f"{ip}:{port}"
        with self._lock:
            if key in self._records:
                rec = self._records[key]
                rec.last_used = time.time()
                rec.use_count += 1
                self._save_unlocked()

    def remove(self, ip: str, port: int) -> bool:
        """Remove a record. Returns True if it existed."""
        key = f"{ip}:{port}"
        with self._lock:
            if key in self._records:
                del self._records[key]
                self._save_unlocked()
                return True
            return False

    def clear(self) -> None:
        """Remove all records."""
        with self._lock:
            self._records.clear()
            self._save_unlocked()

    def get(self, ip: str, port: int) -> Optional[ProxyRecord]:
        key = f"{ip}:{port}"
        with self._lock:
            return self._records.get(key)

    def get_recent(self, limit: int = 20) -> list[ProxyRecord]:
        """Get the most recently seen records."""
        return self.records[:limit]

    def get_most_used(self, limit: int = 10) -> list[ProxyRecord]:
        """Get the most frequently used records."""
        with self._lock:
            return sorted(self._records.values(), key=lambda r: r.use_count, reverse=True)[:limit]

    # -- persistence -------------------------------------------------

    def _load(self) -> None:
        if not os.path.exists(self._filepath):
            return
        try:
            with open(self._filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to read proxy memory file: {e}")
            return

        # filter to only known fields to handle extra/corrupt keys gracefully
        import dataclasses as _dc
        valid_keys = {f.name for f in _dc.fields(ProxyRecord)}
        loaded = 0
        for item in data:
            try:
                filtered = {k: v for k, v in item.items() if k in valid_keys}
                rec = ProxyRecord(**filtered)
                self._records[f"{rec.ip}:{rec.port}"] = rec
                loaded += 1
            except (TypeError, KeyError, ValueError) as e:
                logger.debug(f"Skipping corrupt proxy record: {e}")
        logger.debug(f"Loaded {loaded} proxy records from {self._filepath}")

    def _save_unlocked(self) -> None:
        """Save to disk. Caller must hold self._lock."""
        try:
            data = [asdict(r) for r in self._records.values()]
            tmp = self._filepath + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            # atomic replace
            if os.path.exists(self._filepath):
                os.replace(tmp, self._filepath)
            else:
                os.rename(tmp, self._filepath)
        except OSError as e:
            logger.error(f"Failed to save proxy memory: {e}")
