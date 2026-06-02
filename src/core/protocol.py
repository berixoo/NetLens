"""代理协议检测模块。

负责在已开放的 TCP 端口上识别代理服务类型，支持 HTTP CONNECT、SOCKS4、SOCKS5 三种协议。
同时提供代理连通性验证功能，通过代理实际转发流量以确认其可用性。
"""
from __future__ import annotations

import logging
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from enum import Enum, auto

logger = logging.getLogger(__name__)


class ProxyType(Enum):
    """代理类型枚举。"""
    NONE = auto()       # 非代理
    HTTP = auto()       # HTTP/HTTPS 代理（支持 CONNECT 隧道）
    SOCKS4 = auto()     # SOCKS4 代理（仅支持 TCP，不支持域名）
    SOCKS5 = auto()     # SOCKS5 代理（支持 TCP/UDP + 域名解析）
    UNKNOWN = auto()    # 端口开放但无法识别协议类型

    def display_name(self) -> str:
        """返回代理类型的中文显示名称。"""
        return {ProxyType.HTTP: "HTTP", ProxyType.SOCKS4: "SOCKS4", ProxyType.SOCKS5: "SOCKS5"}.get(self, "N/A")


@dataclass
class ProxyResult:
    """单个端口的代理探测结果。"""
    ip: str                     # 目标 IP 地址
    port: int                   # 目标端口号
    is_open: bool = False       # TCP 端口是否开放
    proxy_type: ProxyType = ProxyType.NONE  # 检测到的代理类型
    latency_ms: float = 0.0    # 协议握手延迟（毫秒）
    requires_auth: bool = False # 是否需要认证
    banner: str = ""            # 端口返回的 banner 信息（如 HTTP 响应头）
    error: str = ""             # 探测过程中的错误信息
    timestamp: float = field(default_factory=time.time)  # 探测时间戳


# SOCKS4 目标 IP 缓存（避免重复 DNS 查询）
# SOCKS4 协议仅支持 IP 地址，不支持域名，因此需要预先解析目标主机的 IP
_socks4_dest_cache: bytes | None = None
# 保护缓存的线程锁，防止多线程同时解析和写入
_socks4_dest_lock = threading.Lock()


def _resolve_socks4_dest(host: str = "httpbin.org") -> bytes | None:
    """解析并缓存 SOCKS4 探测目标的 IP 地址（线程安全）。

    SOCKS4 协议要求在 CONNECT 请求中直接使用 IP 地址，
    因此需要预先将目标主机名解析为 4 字节的 IPv4 地址。

    Args:
        host: 要解析的主机名，默认为 httpbin.org（用于验证代理是否能转发请求）

    Returns:
        4 字节的 IPv4 地址，DNS 解析失败时返回 None（调用方应跳过 SOCKS4 探测）
    """
    global _socks4_dest_cache
    # 快速路径：缓存已存在，直接返回（无需获取锁）
    if _socks4_dest_cache is not None:
        return _socks4_dest_cache
    with _socks4_dest_lock:
        # 双重检查：获取锁后再次确认缓存是否已被其他线程填充
        if _socks4_dest_cache is not None:
            return _socks4_dest_cache
        try:
            _socks4_dest_cache = socket.inet_aton(socket.gethostbyname(host))
        except OSError:
            # DNS 解析失败，记录日志并返回 None，调用方将跳过 SOCKS4 探测
            logger.debug(f"DNS 解析失败: {host}，跳过 SOCKS4 探测")
            return None
    return _socks4_dest_cache


def _parse_http_status(resp: str) -> int | None:
    """从 HTTP 响应中提取状态码。

    解析 HTTP 响应的第一行（状态行），提取数字状态码。
    例如 "HTTP/1.1 200 OK" -> 200，"HTTP/1.0 407 Proxy Auth" -> 407

    Args:
        resp: 完整的 HTTP 响应字符串

    Returns:
        状态码整数，解析失败返回 None
    """
    try:
        status_line = resp.split("\r\n")[0]
        parts = status_line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            return int(parts[1])
    except (IndexError, ValueError):
        pass
    return None


class ProtocolDetector:
    """代理协议检测器。

    在已开放的 TCP 端口上依次尝试识别以下协议：
    1. HTTP CONNECT — 发送 CONNECT 请求，200 响应表示 HTTP 代理
    2. SOCKS5 — 发送版本协商握手（0x05 0x01 0x00）
    3. SOCKS4 — 发送 CONNECT 请求到已知 IP 地址

    每种检测都在独立的 TCP 连接中进行，互不干扰。
    """

    # 用于代理连通性验证的目标主机
    # 通过代理向此主机发起请求，验证代理是否能正常转发流量
    _TEST_HOST = "httpbin.org"
    _TEST_PORT = 80
    _TEST_PATH = "/ip"

    def __init__(self, timeout: float = 3.0):
        """初始化检测器。

        Args:
            timeout: 所有网络操作的超时时间（秒）
        """
        self.timeout = timeout

    # ── 公开接口 ──────────────────────────────────────────────────

    def probe(self, ip: str, port: int) -> ProxyResult:
        """对一个开放端口执行完整的代理协议检测流水线。

        检测顺序：banner 抓取 → HTTP CONNECT → SOCKS5 → SOCKS4
        一旦识别出协议类型立即返回，不再尝试后续检测。

        Args:
            ip: 目标 IP 地址
            port: 目标端口号

        Returns:
            包含检测结果的 ProxyResult 对象
        """
        result = ProxyResult(ip=ip, port=port, is_open=True)

        # 第一步：抓取 banner 并尝试 HTTP CONNECT 检测
        self._grab_banner_and_http(ip, port, result)
        if result.proxy_type == ProxyType.HTTP:
            return result

        # 第二步：尝试 SOCKS5 协议握手
        if self._try_socks5(ip, port, result):
            return result

        # 第三步：尝试 SOCKS4 协议握手
        if self._try_socks4(ip, port, result):
            return result

        # 第四步：端口开放但未识别出任何代理协议
        result.proxy_type = ProxyType.UNKNOWN
        return result

    def test_proxy_connectivity(self, ip: str, port: int, proxy_type: ProxyType) -> bool:
        """通过代理实际转发 HTTP 请求，验证代理是否可用。

        向代理发送请求，让代理代为访问 httpbin.org/ip，如果收到正常响应则说明代理可用。

        Args:
            ip: 代理服务器 IP
            port: 代理服务器端口
            proxy_type: 代理类型（决定使用哪种协议连接代理）

        Returns:
            True 表示代理可用（成功获取到 httpbin.org 的响应）
        """
        try:
            if proxy_type == ProxyType.HTTP:
                return self._http_get_through_proxy(ip, port)
            elif proxy_type == ProxyType.SOCKS5:
                return self._socks5_get_through_proxy(ip, port)
            elif proxy_type == ProxyType.SOCKS4:
                return self._socks4_get_through_proxy(ip, port)
        except (socket.timeout, OSError) as e:
            logger.debug(f"代理连通性测试失败 {ip}:{port} ({proxy_type}): {e}")
        return False

    # ── 内部方法：TCP 连接检测 ────────────────────────────────────

    @staticmethod
    def check_port_open(ip: str, port: int, timeout: float = 2.0) -> tuple[bool, float]:
        """检测目标端口是否开放。

        尝试建立 TCP 连接，成功则端口开放，失败（超时/拒绝）则端口关闭。

        Args:
            ip: 目标 IP 地址
            port: 目标端口号
            timeout: 连接超时时间（秒）

        Returns:
            元组 (是否开放, 延迟毫秒数)，端口关闭时延迟为 0.0
        """
        start = time.monotonic()
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                latency = (time.monotonic() - start) * 1000
                return True, round(latency, 2)
        except (socket.timeout, OSError):
            return False, 0.0

    # ── 内部方法：Banner 抓取 + HTTP 探测 ─────────────────────────

    def _grab_banner_and_http(self, ip: str, port: int, result: ProxyResult):
        """抓取端口 banner（用于显示），然后尝试 HTTP CONNECT 代理检测。

        Banner 抓取通过发送 HEAD 请求获取服务端响应的第一行，
        仅用于信息展示，不作为代理类型的判断依据。
        代理类型判断仅依赖后续的 CONNECT 方法检测。
        """
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                sock.settimeout(min(self.timeout, 1.5))
                try:
                    # 发送 HEAD 请求获取 banner（响应第一行通常包含服务器信息）
                    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n")
                    data = sock.recv(1024)
                    banner = data.decode("utf-8", errors="replace")
                    result.banner = banner.split("\r\n")[0][:200]
                except OSError:
                    pass
        except OSError:
            return

        # 使用 HTTP CONNECT 方法进行真正的代理检测
        self._try_http_connect(ip, port, result)

    # ── 内部方法：HTTP CONNECT 检测 ──────────────────────────────

    def _try_http_connect(self, ip: str, port: int, result: ProxyResult) -> bool:
        """通过 HTTP CONNECT 方法检测 HTTP 代理。

        发送 CONNECT 请求尝试建立到目标主机的隧道。
        HTTP 代理对 CONNECT 请求返回 200 表示隧道建立成功，
        返回 407 表示需要代理认证。

        同时尝试使用绝对 URL 的 GET 请求（部分代理支持这种方式）。

        Args:
            ip: 目标 IP
            port: 目标端口
            result: 用于存储检测结果的对象

        Returns:
            True 表示检测到 HTTP 代理
        """
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                start = time.monotonic()
                # 发送 CONNECT 请求建立隧道
                req = f"CONNECT {self._TEST_HOST}:{self._TEST_PORT} HTTP/1.1\r\nHost: {self._TEST_HOST}:{self._TEST_PORT}\r\n\r\n"
                sock.sendall(req.encode())
                sock.settimeout(self.timeout)
                resp = sock.recv(4096).decode("utf-8", errors="replace")
                latency = (time.monotonic() - start) * 1000

                status = _parse_http_status(resp)
                if status == 200:
                    # 200 = 隧道建立成功，确认是 HTTP 代理
                    result.proxy_type = ProxyType.HTTP
                    result.latency_ms = round(latency, 2)
                    return True
                if status == 407:
                    # 407 = 需要代理认证，也是 HTTP 代理（只是需要密码）
                    result.proxy_type = ProxyType.HTTP
                    result.requires_auth = True
                    result.latency_ms = round(latency, 2)
                    return True
        except OSError:
            pass

        # 部分代理支持使用绝对 URL 的 GET 请求（非 CONNECT 方式）
        # 例如：GET http://example.com/ HTTP/1.0
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

    # 保留 _try_http 别名以兼容旧代码
    _try_http = _try_http_connect

    # ── 内部方法：SOCKS5 检测 ────────────────────────────────────

    def _try_socks5(self, ip: str, port: int, result: ProxyResult) -> bool:
        """通过 SOCKS5 握手协议检测 SOCKS5 代理。

        SOCKS5 握手流程：
        1. 客户端发送: [版本=0x05] [方法数=1] [方法=无认证=0x00]
        2. 服务端响应: [版本=0x05] [选中方法]
           - 0x00 = 无需认证
           - 0x02 = 需要用户名/密码认证

        如果服务端返回版本号为 0x05 的响应，则确认为 SOCKS5 代理。

        Args:
            ip: 目标 IP
            port: 目标端口
            result: 用于存储检测结果的对象

        Returns:
            True 表示检测到 SOCKS5 代理
        """
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                start = time.monotonic()
                # 发送 SOCKS5 握手请求：版本5，1种认证方式，无认证
                sock.sendall(b"\x05\x01\x00")
                sock.settimeout(self.timeout)
                resp = sock.recv(256)
                latency = (time.monotonic() - start) * 1000

                # 检查响应：至少 2 字节，且第一个字节为 0x05（SOCKS5 版本标识）
                if len(resp) >= 2 and resp[0] == 0x05:
                    result.proxy_type = ProxyType.SOCKS5
                    result.latency_ms = round(latency, 2)
                    # 第二个字节为认证方式：0x02 表示需要用户名/密码
                    if resp[1] == 0x02:
                        result.requires_auth = True
                    return True
        except OSError:
            pass
        return False

    # ── 内部方法：SOCKS4 检测 ────────────────────────────────────

    def _try_socks4(self, ip: str, port: int, result: ProxyResult) -> bool:
        """通过 SOCKS4 连接请求检测 SOCKS4 代理。

        SOCKS4 连接流程：
        1. 客户端发送: [版本=0x04] [命令=CONNECT=0x01] [端口=80] [目标IP] [用户ID=\x00]
        2. 服务端响应: [版本=0x00] [状态]
           - 0x5A = 连接成功/代理可用
           - 0x5B = 连接被拒/代理不可用

        注意：SOCKS4 仅支持 IP 地址作为目标，不支持域名。
        因此需要预先解析目标主机的 IP（通过 _resolve_socks4_dest）。

        Args:
            ip: 目标 IP
            port: 目标端口
            result: 用于存储检测结果的对象

        Returns:
            True 表示检测到 SOCKS4 代理
        """
        dest_ip = _resolve_socks4_dest()
        if dest_ip is None:
            return False  # DNS 解析失败，无法进行 SOCKS4 探测
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                start = time.monotonic()
                # 构造 SOCKS4 CONNECT 请求：版本4 + 命令1(连接) + 端口80 + 目标IP + 空用户ID
                req = b"\x04\x01" + struct.pack("!H", 80) + dest_ip + b"\x00"
                sock.sendall(req)
                sock.settimeout(self.timeout)
                resp = sock.recv(8)
                latency = (time.monotonic() - start) * 1000

                # 检查响应：第一个字节 0x00 表示 SOCKS4，第二个字节 0x5A/0x5B 表示状态
                if len(resp) >= 2 and resp[0] == 0x00 and resp[1] in (0x5A, 0x5B):
                    result.proxy_type = ProxyType.SOCKS4
                    result.latency_ms = round(latency, 2)
                    return True
        except OSError:
            pass
        return False

    # ── 内部方法：代理连通性验证 ─────────────────────────────────

    def _http_get_through_proxy(self, proxy_ip: str, proxy_port: int) -> bool:
        """通过 HTTP 代理发送请求验证连通性。

        流程：先通过 CONNECT 建立隧道，再在隧道中发送 HTTP GET 请求。
        如果能收到 httpbin.org 的正常响应，说明代理可以正常转发流量。

        Args:
            proxy_ip: 代理服务器 IP
            proxy_port: 代理服务器端口

        Returns:
            True 表示代理可用
        """
        target = f"{self._TEST_HOST}:{self._TEST_PORT}"
        with socket.create_connection((proxy_ip, proxy_port), timeout=self.timeout) as sock:
            # 第一步：通过 CONNECT 建立到目标的隧道
            req = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"
            sock.sendall(req.encode())
            sock.settimeout(self.timeout)
            resp = sock.recv(4096)
            # 验证 CONNECT 响应状态码是否为 200
            try:
                status_line = resp.decode("utf-8", errors="replace").split("\r\n")[0]
                parts = status_line.split()
                if len(parts) < 2 or int(parts[1]) != 200:
                    return False
            except (ValueError, IndexError):
                return False
            # 第二步：在隧道中发送实际的 HTTP GET 请求
            get_req = f"GET {self._TEST_PATH} HTTP/1.1\r\nHost: {self._TEST_HOST}\r\nConnection: close\r\n\r\n"
            sock.sendall(get_req.encode())
            data = sock.recv(4096)
            # 检查响应中是否包含 httpbin.org /ip 接口的特征内容
            return b"200 OK" in data or b"\"origin\"" in data

    def _socks5_get_through_proxy(self, proxy_ip: str, proxy_port: int) -> bool:
        """通过 SOCKS5 代理发送请求验证连通性。

        流程：SOCKS5 握手 → CONNECT 到目标 → 发送 HTTP GET → 检查响应。

        Args:
            proxy_ip: 代理服务器 IP
            proxy_port: 代理服务器端口

        Returns:
            True 表示代理可用
        """
        dest = _resolve_socks4_dest()
        if dest is None:
            return False
        with socket.create_connection((proxy_ip, proxy_port), timeout=self.timeout) as sock:
            # 第一步：SOCKS5 握手
            sock.sendall(b"\x05\x01\x00")
            sock.settimeout(self.timeout)
            resp = sock.recv(256)
            if len(resp) < 2 or resp[0] != 0x05:
                return False

            # 第二步：通过 SOCKS5 发起 CONNECT 到目标主机
            # 请求格式：[版本=5] [命令=CONNECT=1] [保留=0] [地址类型=IPv4=1] [IP] [端口]
            req = b"\x05\x01\x00\x01" + dest + struct.pack("!H", 80)
            sock.sendall(req)
            resp = sock.recv(256)
            if len(resp) < 2 or resp[1] != 0x00:
                return False

            # 第三步：在 SOCKS5 隧道中发送 HTTP GET 请求
            get_req = f"GET {self._TEST_PATH} HTTP/1.1\r\nHost: {self._TEST_HOST}\r\nConnection: close\r\n\r\n"
            sock.sendall(get_req.encode())
            data = sock.recv(4096)
            return b"200 OK" in data or b"\"origin\"" in data

    def _socks4_get_through_proxy(self, proxy_ip: str, proxy_port: int) -> bool:
        """通过 SOCKS4 代理发送请求验证连通性。

        流程：SOCKS4 CONNECT → 发送 HTTP GET → 检查响应。

        Args:
            proxy_ip: 代理服务器 IP
            proxy_port: 代理服务器端口

        Returns:
            True 表示代理可用
        """
        dest_ip = _resolve_socks4_dest()
        if dest_ip is None:
            return False
        with socket.create_connection((proxy_ip, proxy_port), timeout=self.timeout) as sock:
            # 第一步：SOCKS4 CONNECT 到目标主机
            req = b"\x04\x01" + struct.pack("!H", 80) + dest_ip + b"\x00"
            sock.sendall(req)
            sock.settimeout(self.timeout)
            resp = sock.recv(8)
            if len(resp) < 2 or resp[1] != 0x5A:
                return False

            # 第二步：在 SOCKS4 隧道中发送 HTTP GET 请求
            get_req = f"GET {self._TEST_PATH} HTTP/1.1\r\nHost: {self._TEST_HOST}\r\nConnection: close\r\n\r\n"
            sock.sendall(get_req.encode())
            data = sock.recv(4096)
            return b"200 OK" in data or b"\"origin\"" in data
