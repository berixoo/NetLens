"""Protocol detection for proxy services (HTTP/SOCKS4/SOCKS5)."""
from __future__ import annotations

import logging
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

logger = logging.getLogger(__name__)


class ProxyType(Enum):
    NONE = auto()
    HTTP = auto()
    SOCKS4 = auto()
    SOCKS5 = auto()
    UNKNOWN = auto()

    def display_name(self) -> str:
        return {ProxyType.HTTP: "HTTP", ProxyType.SOCKS4: "SOCKS4", ProxyType.SOCKS5: "SOCKS5"}.get(self, "N/A")


@dataclass
class ProxyResult:
    ip: str
    port: int
    is_open: bool = False
    proxy_type: ProxyType = ProxyType.NONE
    latency_ms: float = 0.0
    requires_auth: bool = False
    banner: str = ""
    error: str = ""
    timestamp: float = field(default_factory=time.time)


# cached SOCKS4 destination IP (avoid repeated DNS lookups)
_socks4_dest_cache: bytes | None = None
_socks4_dest_lock = threading.Lock()


def _resolve_socks4_dest(host: str = "httpbin.org") -> bytes | None:
    """Resolve and cache the destination IP for SOCKS4 probes. Thread-safe."""
    global _socks4_dest_cache
    if _socks4_dest_cache is not None:
        return _socks4_dest_cache
    with _socks4_dest_lock:
        # double-check after acquiring lock
        if _socks4_dest_cache is not None:
            return _socks4_dest_cache
        try:
            _socks4_dest_cache = socket.inet_aton(socket.gethostbyname(host))
        except OSError:
            # DNS failed — return None so caller can skip SOCKS4 probe
            logger.debug(f"DNS resolution failed for {host}, skipping SOCKS4 probe")
            return None
    return _socks4_dest_cache


def _parse_http_status(resp: str) -> int | None:
    """Extract HTTP status code from response. Returns None on parse failure."""
    try:
        status_line = resp.split("\r\n")[0]
        parts = status_line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            return int(parts[1])
    except (IndexError, ValueError):
        pass
    return None


class ProtocolDetector:
    """Detect proxy protocols on open TCP ports."""

    _TEST_HOST = "httpbin.org"
    _TEST_PORT = 80
    _TEST_PATH = "/ip"

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    # -- public API --------------------------------------------------

    def probe(self, ip: str, port: int) -> ProxyResult:
        """Run the full detection pipeline on an open port."""
        result = ProxyResult(ip=ip, port=port, is_open=True)

        # 1. grab banner + try HTTP in one connection
        self._grab_banner_and_http(ip, port, result)
        if result.proxy_type == ProxyType.HTTP:
            return result

        # 2. try SOCKS5
        if self._try_socks5(ip, port, result):
            return result

        # 3. try SOCKS4
        if self._try_socks4(ip, port, result):
            return result

        # 4. fallback: port is open but not a known proxy
        result.proxy_type = ProxyType.UNKNOWN
        return result

    def test_proxy_connectivity(self, ip: str, port: int, proxy_type: ProxyType) -> bool:
        """Actually route a request through the proxy to verify it works."""
        try:
            if proxy_type == ProxyType.HTTP:
                return self._http_get_through_proxy(ip, port)
            elif proxy_type == ProxyType.SOCKS5:
                return self._socks5_get_through_proxy(ip, port)
            elif proxy_type == ProxyType.SOCKS4:
                return self._socks4_get_through_proxy(ip, port)
        except (socket.timeout, OSError) as e:
            logger.debug(f"Proxy connectivity test failed {ip}:{port} ({proxy_type}): {e}")
        return False

    # -- internal: TCP connect --------------------------------------

    @staticmethod
    def check_port_open(ip: str, port: int, timeout: float = 2.0) -> tuple[bool, float]:
        """Returns (is_open, latency_ms)."""
        start = time.monotonic()
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                latency = (time.monotonic() - start) * 1000
                return True, round(latency, 2)
        except (socket.timeout, OSError):
            return False, 0.0

    # -- internal: combined banner + HTTP probe ---------------------

    def _grab_banner_and_http(self, ip: str, port: int, result: ProxyResult):
        """Grab banner only (for display). Proxy detection is done separately via CONNECT."""
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                sock.settimeout(min(self.timeout, 1.5))
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n")
                    data = sock.recv(1024)
                    banner = data.decode("utf-8", errors="replace")
                    result.banner = banner.split("\r\n")[0][:200]
                except OSError:
                    pass
        except OSError:
            return

        # try HTTP CONNECT — this is the real proxy detection
        self._try_http_connect(ip, port, result)

    # -- internal: HTTP CONNECT detection ---------------------------

    def _try_http_connect(self, ip: str, port: int, result: ProxyResult) -> bool:
        """Detect HTTP proxy via CONNECT method."""
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                start = time.monotonic()
                req = f"CONNECT {self._TEST_HOST}:{self._TEST_PORT} HTTP/1.1\r\nHost: {self._TEST_HOST}:{self._TEST_PORT}\r\n\r\n"
                sock.sendall(req.encode())
                sock.settimeout(self.timeout)
                resp = sock.recv(4096).decode("utf-8", errors="replace")
                latency = (time.monotonic() - start) * 1000

                status = _parse_http_status(resp)
                if status == 200:
                    result.proxy_type = ProxyType.HTTP
                    result.latency_ms = round(latency, 2)
                    return True
                if status == 407:
                    result.proxy_type = ProxyType.HTTP
                    result.requires_auth = True
                    result.latency_ms = round(latency, 2)
                    return True
        except OSError:
            pass

        # try plain HTTP GET (some proxies respond to GET)
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                start = time.monotonic()
                req = f"GET http://{self._TEST_HOST}/ HTTP/1.0\r\nHost: {self._TEST_HOST}\r\n\r\n"
                sock.sendall(req.encode())
                sock.settimeout(self.timeout)
                resp = sock.recv(4096).decode("utf-8", errors="replace")
                latency = (time.monotonic() - start) * 1000
                if resp.startswith("HTTP/"):
                    status = _parse_http_status(resp)
                    if status is not None:
                        result.proxy_type = ProxyType.HTTP
                        result.latency_ms = round(latency, 2)
                        return True
        except OSError:
            pass

        return False

    # keep _try_http as alias for backward compat
    _try_http = _try_http_connect

    # -- internal: SOCKS5 detection ---------------------------------

    def _try_socks5(self, ip: str, port: int, result: ProxyResult) -> bool:
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                start = time.monotonic()
                sock.sendall(b"\x05\x01\x00")
                sock.settimeout(self.timeout)
                resp = sock.recv(256)
                latency = (time.monotonic() - start) * 1000

                if len(resp) >= 2 and resp[0] == 0x05:
                    result.proxy_type = ProxyType.SOCKS5
                    result.latency_ms = round(latency, 2)
                    if resp[1] == 0x02:
                        result.requires_auth = True
                    return True
        except OSError:
            pass
        return False

    # -- internal: SOCKS4 detection ---------------------------------

    def _try_socks4(self, ip: str, port: int, result: ProxyResult) -> bool:
        dest_ip = _resolve_socks4_dest()
        if dest_ip is None:
            return False  # DNS failed, can't probe SOCKS4
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                start = time.monotonic()
                req = b"\x04\x01" + struct.pack("!H", 80) + dest_ip + b"\x00"
                sock.sendall(req)
                sock.settimeout(self.timeout)
                resp = sock.recv(8)
                latency = (time.monotonic() - start) * 1000

                if len(resp) >= 2 and resp[0] == 0x00 and resp[1] in (0x5A, 0x5B):
                    result.proxy_type = ProxyType.SOCKS4
                    result.latency_ms = round(latency, 2)
                    return True
        except OSError:
            pass
        return False

    # -- internal: live proxy test ----------------------------------

    def _http_get_through_proxy(self, proxy_ip: str, proxy_port: int) -> bool:
        target = f"{self._TEST_HOST}:{self._TEST_PORT}"
        with socket.create_connection((proxy_ip, proxy_port), timeout=self.timeout) as sock:
            req = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"
            sock.sendall(req.encode())
            sock.settimeout(self.timeout)
            resp = sock.recv(4096)
            # check status code properly
            try:
                status_line = resp.decode("utf-8", errors="replace").split("\r\n")[0]
                parts = status_line.split()
                if len(parts) < 2 or int(parts[1]) != 200:
                    return False
            except (ValueError, IndexError):
                return False
            get_req = f"GET {self._TEST_PATH} HTTP/1.1\r\nHost: {self._TEST_HOST}\r\nConnection: close\r\n\r\n"
            sock.sendall(get_req.encode())
            data = sock.recv(4096)
            return b"200 OK" in data or b"\"origin\"" in data

    def _socks5_get_through_proxy(self, proxy_ip: str, proxy_port: int) -> bool:
        dest = _resolve_socks4_dest()
        if dest is None:
            return False
        with socket.create_connection((proxy_ip, proxy_port), timeout=self.timeout) as sock:
            sock.sendall(b"\x05\x01\x00")
            sock.settimeout(self.timeout)
            resp = sock.recv(256)
            if len(resp) < 2 or resp[0] != 0x05:
                return False

            req = b"\x05\x01\x00\x01" + dest + struct.pack("!H", 80)
            sock.sendall(req)
            resp = sock.recv(256)
            if len(resp) < 2 or resp[1] != 0x00:
                return False

            get_req = f"GET {self._TEST_PATH} HTTP/1.1\r\nHost: {self._TEST_HOST}\r\nConnection: close\r\n\r\n"
            sock.sendall(get_req.encode())
            data = sock.recv(4096)
            return b"200 OK" in data or b"\"origin\"" in data

    def _socks4_get_through_proxy(self, proxy_ip: str, proxy_port: int) -> bool:
        dest_ip = _resolve_socks4_dest()
        if dest_ip is None:
            return False
        with socket.create_connection((proxy_ip, proxy_port), timeout=self.timeout) as sock:
            req = b"\x04\x01" + struct.pack("!H", 80) + dest_ip + b"\x00"
            sock.sendall(req)
            sock.settimeout(self.timeout)
            resp = sock.recv(8)
            if len(resp) < 2 or resp[1] != 0x5A:
                return False

            get_req = f"GET {self._TEST_PATH} HTTP/1.1\r\nHost: {self._TEST_HOST}\r\nConnection: close\r\n\r\n"
            sock.sendall(get_req.encode())
            data = sock.recv(4096)
            return b"200 OK" in data or b"\"origin\"" in data
