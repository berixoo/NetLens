"""Thread-safe logging for scan operations."""
from __future__ import annotations

import logging
import os
import threading
from datetime import datetime
from typing import Optional


class ScanLogger:
    """Thread-safe logger that writes to both console and file."""

    def __init__(self, name: str = "NetLens", log_dir: str = "logs"):
        self._lock = threading.Lock()
        self._log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)

        # file handler
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._log_file = os.path.join(log_dir, f"scan_{timestamp}.log")

        self._logger = logging.getLogger(name)
        self._logger.setLevel(logging.DEBUG)

        # file handler — detailed
        self._fh = logging.FileHandler(self._log_file, encoding="utf-8")
        self._fh.setLevel(logging.DEBUG)
        self._fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"
        ))
        # avoid duplicate handlers if ScanLogger is instantiated multiple times
        if not any(isinstance(h, logging.FileHandler) for h in self._logger.handlers):
            self._logger.addHandler(self._fh)

        # in-memory buffer for UI display
        self._buffer: list[str] = []
        self._max_buffer = 5000

    @property
    def log_file(self) -> str:
        return self._log_file

    @property
    def buffer(self) -> list[str]:
        with self._lock:
            return list(self._buffer)

    def debug(self, msg: str):
        self._log(logging.DEBUG, msg)

    def info(self, msg: str):
        self._log(logging.INFO, msg)

    def warning(self, msg: str):
        self._log(logging.WARNING, msg)

    def error(self, msg: str):
        self._log(logging.ERROR, msg)

    def _log(self, level: int, msg: str):
        # logger has its own lock; call it outside our lock to avoid nesting
        self._logger.log(level, msg)
        with self._lock:
            self._buffer.append(msg)
            if len(self._buffer) > self._max_buffer:
                self._buffer = self._buffer[-self._max_buffer:]

    def clear_buffer(self):
        with self._lock:
            self._buffer.clear()

    def close(self):
        """Flush and close the file handler."""
        try:
            self._fh.close()
            self._logger.removeHandler(self._fh)
        except Exception:
            pass
