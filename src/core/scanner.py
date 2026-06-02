"""多线程端口扫描引擎，支持校园网级大规模两阶段扫描。

两阶段扫描流程：
  阶段一（主机发现）：对所有目标的少量常用端口进行快速 TCP 探测，找出存活主机
  阶段二（深度扫描）：仅对存活主机进行全端口扫描 + 协议识别 + 连通性验证

对于目标数超过 two_phase_threshold（默认 256）的情况，自动启用两阶段模式，
避免对大量不活跃主机浪费扫描时间。
"""
from __future__ import annotations

import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable, Optional

from .protocol import ProtocolDetector, ProxyType


class ScanState(Enum):
    """扫描引擎的运行状态。"""
    IDLE = auto()           # 空闲，未在扫描
    DISCOVERING = auto()    # 阶段一：主机发现中
    SCANNING = auto()       # 阶段二：深度端口扫描中
    PAUSED = auto()         # 已暂停（预留）
    STOPPED = auto()        # 已停止（用户手动停止或扫描完成）


@dataclass
class ScanConfig:
    """扫描配置参数。"""
    # 深度扫描的目标端口列表（常见的代理服务端口）
    ports: list[int] = field(default_factory=lambda: [7890, 7891, 1080, 10808, 10809, 8080, 8118, 3128])
    # 主机发现阶段使用的端口列表（应与 ports 不重叠，避免重复扫描）
    # 选择常见的 Web/远程端口，能在 1 秒超时内快速判断主机是否在线
    discovery_ports: list[int] = field(default_factory=lambda: [443, 80, 22, 445])
    # 深度扫描的 TCP 连接超时时间（秒）
    timeout: float = 3.0
    # 主机发现阶段的超时时间（秒），比深度扫描更短以加速发现过程
    discovery_timeout: float = 1.0
    # 线程池最大线程数，建议不超过 256 以避免耗尽系统临时端口
    max_threads: int = 64
    # 是否对开放端口进行代理协议检测（HTTP/SOCKS4/SOCKS5）
    detect_protocol: bool = True
    # 是否对检测到的代理进行连通性验证（通过代理转发实际请求）
    test_connectivity: bool = False
    # 是否启用两阶段扫描模式
    two_phase: bool = True
    # 自动启用两阶段扫描的目标数阈值
    two_phase_threshold: int = 256
    # 是否跳过发现阶段未响应的主机（不对其进行深度扫描）
    skip_dead_hosts: bool = True


@dataclass
class ScanResult:
    """单个 IP:端口 的扫描结果。"""
    ip: str                         # 目标 IP 地址
    port: int                       # 目标端口号
    is_open: bool = False           # TCP 端口是否开放
    proxy_type: ProxyType = ProxyType.NONE  # 检测到的代理类型
    latency_ms: float = 0.0        # TCP 连接或协议握手延迟（毫秒）
    requires_auth: bool = False     # 代理是否需要认证
    banner: str = ""                # 端口返回的 banner 信息
    connectivity_ok: bool = False   # 代理连通性验证是否通过
    connectivity_tested: bool = False  # 是否已执行过连通性验证（区分"未测试"和"测试失败"）
    timestamp: float = field(default_factory=time.time)  # 扫描时间戳
    error: str = ""                 # 扫描过程中的错误信息
    phase: str = ""                 # 所属扫描阶段："discovery"（发现）或 "scan"（深度扫描）


class ScannerEngine:
    """核心扫描引擎，支持两阶段校园网级大规模扫描。

    线程安全：所有状态修改通过 self._lock 保护，取消事件的 set/clear 操作均在锁内执行，
    避免 stop() 与扫描循环之间的竞态条件。

    回调机制：通过注册回调函数通知外部（UI 线程）扫描进度和结果。
    回调在扫描线程中被调用，UI 线程应通过 Qt 信号槽机制安全地接收通知。
    """

    def __init__(self, config: ScanConfig | None = None):
        """初始化扫描引擎。

        Args:
            config: 扫描配置，为 None 时使用默认配置
        """
        self.config = config or ScanConfig()
        self._state = ScanState.IDLE
        self._lock = threading.Lock()               # 保护所有可变状态的互斥锁
        self._results: list[ScanResult] = []         # 已完成的扫描结果列表
        self._alive_hosts: set[str] = set()          # 发现阶段找到的存活主机集合
        self._executor: Optional[ThreadPoolExecutor] = None  # 当前的线程池实例
        self._cancel_event = threading.Event()       # 取消信号，stop() 时置位

        # 回调函数列表（外部通过 on_xxx() 方法注册）
        self._on_result: Optional[Callable[[ScanResult], None]] = None       # 单个结果回调
        self._on_progress: Optional[Callable[[int, int], None]] = None       # 进度回调 (已完成, 总数)
        self._on_proxy_found: Optional[Callable[[ScanResult], None]] = None  # 发现代理回调
        self._on_complete: Optional[Callable[[], None]] = None               # 扫描完成回调
        self._on_phase_change: Optional[Callable[[str], None]] = None        # 阶段切换回调
        self._on_alive_found: Optional[Callable[[str], None]] = None         # 发现存活主机回调

    # ── 公开属性 ──────────────────────────────────────────────────

    @property
    def state(self) -> ScanState:
        """当前扫描状态（线程安全）。"""
        with self._lock:
            return self._state

    @property
    def results(self) -> list[ScanResult]:
        """所有已扫描的结果副本（线程安全）。"""
        with self._lock:
            return list(self._results)

    @property
    def open_ports(self) -> list[ScanResult]:
        """所有开放端口的结果（线程安全）。"""
        with self._lock:
            return [r for r in self._results if r.is_open]

    @property
    def proxy_results(self) -> list[ScanResult]:
        """所有检测到代理的端口结果（线程安全）。"""
        with self._lock:
            return [r for r in self._results if r.proxy_type not in (ProxyType.NONE, ProxyType.UNKNOWN)]

    @property
    def alive_hosts(self) -> set[str]:
        """发现阶段找到的存活主机集合副本（线程安全）。"""
        with self._lock:
            return set(self._alive_hosts)

    # ── 回调注册 ──────────────────────────────────────────────────

    def on_result(self, callback: Callable[[ScanResult], None]):
        """注册单个扫描结果的回调。每当一个 IP:端口 扫描完成时调用。"""
        self._on_result = callback

    def on_progress(self, callback: Callable[[int, int], None]):
        """注册进度回调。参数为 (已完成任务数, 总任务数)。"""
        self._on_progress = callback

    def on_proxy_found(self, callback: Callable[[ScanResult], None]):
        """注册发现代理的回调。当检测到开放端口为代理服务时调用。"""
        self._on_proxy_found = callback

    def on_complete(self, callback: Callable[[], None]):
        """注册扫描完成回调。扫描正常结束或被停止后调用。"""
        self._on_complete = callback

    def on_phase_change(self, callback: Callable[[str], None]):
        """注册阶段切换回调。参数为 "discovery"（发现阶段）或 "scan"（深度扫描阶段）。"""
        self._on_phase_change = callback

    def on_alive_found(self, callback: Callable[[str], None]):
        """注册发现存活主机的回调。参数为存活主机的 IP 地址。"""
        self._on_alive_found = callback

    # ── 控制接口 ──────────────────────────────────────────────────

    def stop(self):
        """停止扫描（线程安全）。

        设置取消信号，扫描循环会在下一个检查点退出。
        set 操作在锁内执行，避免与 _cancel_event.clear() 的竞态条件。
        """
        with self._lock:
            self._state = ScanState.STOPPED
            self._cancel_event.set()

    def reset(self):
        """重置引擎状态（线程安全）。清空所有结果和存活主机记录。"""
        with self._lock:
            self._results.clear()
            self._alive_hosts.clear()
            self._state = ScanState.IDLE
            self._cancel_event.clear()

    # ── 扫描入口 ──────────────────────────────────────────────────

    def scan_targets(self, targets: list[str], ports: list[int] | None = None) -> list[ScanResult]:
        """扫描一组 IP 地址。

        根据目标数量自动选择扫描模式：
        - 目标数 <= two_phase_threshold：直接扫描（每个目标 × 每个端口）
        - 目标数 > two_phase_threshold 且 two_phase=True：两阶段扫描

        Args:
            targets: 要扫描的 IP 地址列表
            ports: 要扫描的端口列表，为 None 时使用配置中的默认端口

        Returns:
            所有扫描结果列表
        """
        ports = ports or self.config.ports

        if self.config.two_phase and len(targets) > self.config.two_phase_threshold:
            return self._scan_two_phase(targets, ports)
        else:
            return self._scan_direct(targets, ports)

    def scan_subnet(self, cidr: str, ports: list[int] | None = None) -> list[ScanResult]:
        """扫描整个 CIDR 子网（无 /24 限制）。

        对于超大子网（> /16），最多生成 65536 个目标地址以防止内存溢出。

        Args:
            cidr: CIDR 格式的子网地址，如 "10.16.0.0/16"
            ports: 要扫描的端口列表

        Returns:
            所有扫描结果列表
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            if network.prefixlen <= 16:
                # /16 或更大子网，限制最多 65536 个目标
                targets = []
                for i, ip in enumerate(network.hosts()):
                    targets.append(str(ip))
                    if i >= 65535:
                        break
            else:
                targets = [str(ip) for ip in network.hosts()]
            return self.scan_targets(targets, ports)
        except ValueError as e:
            return [ScanResult(ip=cidr, port=0, error=f"无效的 CIDR: {e}")]

    def discover_hosts(self, targets: list[str], ports: list[int] | None = None) -> set[str]:
        """仅执行阶段一：主机发现。

        对所有目标的少量常用端口进行快速 TCP 探测，返回存活主机的 IP 集合。

        Args:
            targets: 要探测的 IP 地址列表
            ports: 发现阶段使用的端口列表，默认使用 discovery_ports

        Returns:
            存活主机的 IP 地址集合
        """
        ports = ports or self.config.discovery_ports
        alive: set[str] = set()

        with self._lock:
            self._state = ScanState.DISCOVERING
            self._cancel_event.clear()

        # 构建任务列表：每个目标 × 每个发现端口
        tasks = [(ip, port) for ip in targets for port in ports]
        total = len(tasks)
        completed = 0

        with ThreadPoolExecutor(max_workers=min(self.config.max_threads, total)) as executor:
            futures = {}
            for ip, port in tasks:
                if self._cancel_event.is_set():
                    break
                # 提交 TCP 连接检测任务，使用较短的超时时间
                future = executor.submit(
                    ProtocolDetector.check_port_open, ip, port, self.config.discovery_timeout
                )
                futures[future] = ip

            for future in as_completed(futures):
                if self._cancel_event.is_set():
                    break
                try:
                    is_open, _ = future.result()
                    ip = futures[future]
                    if is_open and ip not in alive:
                        alive.add(ip)
                        with self._lock:
                            self._alive_hosts.add(ip)
                        if self._on_alive_found:
                            self._on_alive_found(ip)
                except Exception:
                    ip = futures.get(future, "?")
                    # 发现阶段的网络错误（连接拒绝/超时）是预期行为，静默跳过
                completed += 1
                if self._on_progress:
                    self._on_progress(completed, total)

        return alive

    # ── 内部扫描逻辑 ─────────────────────────────────────────────

    def _scan_two_phase(self, targets: list[str], ports: list[int]) -> list[ScanResult]:
        """两阶段扫描：先发现存活主机，再深度扫描这些主机。

        阶段一（发现）：对所有目标的 discovery_ports 端口进行快速探测
        阶段二（深度扫描）：仅对存活主机的 ports 端口进行完整扫描 + 协议检测
        """
        # ── 阶段一：主机发现 ──
        if self._on_phase_change:
            self._on_phase_change("discovery")

        with self._lock:
            self._state = ScanState.DISCOVERING
            self._results.clear()
            self._alive_hosts.clear()
            self._cancel_event.clear()

        # 构建发现任务：每个目标 × 每个发现端口
        disc_ports = self.config.discovery_ports
        disc_tasks = [(ip, port) for ip in targets for port in disc_ports]
        disc_total = len(disc_tasks)
        disc_done = 0
        alive: set[str] = set()

        with ThreadPoolExecutor(max_workers=min(self.config.max_threads, disc_total)) as executor:
            futures = {}
            for ip, port in disc_tasks:
                if self._cancel_event.is_set():
                    break
                future = executor.submit(
                    ProtocolDetector.check_port_open, ip, port, self.config.discovery_timeout
                )
                futures[future] = ip

            for future in as_completed(futures):
                if self._cancel_event.is_set():
                    break
                try:
                    is_open, _ = future.result()
                    ip = futures[future]
                    if is_open and ip not in alive:
                        alive.add(ip)
                        with self._lock:
                            self._alive_hosts.add(ip)
                        if self._on_alive_found:
                            self._on_alive_found(ip)
                except Exception:
                    pass  # 连接拒绝/超时在发现阶段是预期行为
                disc_done += 1
                if self._on_progress:
                    self._on_progress(disc_done, disc_total)

        # 如果在发现阶段被用户停止，提前结束
        if self._cancel_event.is_set():
            self._finish()
            return self.results

        # ── 阶段二：深度扫描 ──
        if self._on_phase_change:
            self._on_phase_change("scan")

        with self._lock:
            self._state = ScanState.SCANNING

        # 如果没有发现存活主机，直接结束
        if not alive:
            self._finish()
            return self.results

        # 仅对存活主机执行深度扫描
        scan_targets = list(alive)
        return self._scan_direct(scan_targets, ports, phase="scan")

    def _scan_direct(self, targets: list[str], ports: list[int], phase: str = "scan") -> list[ScanResult]:
        """直接扫描模式：对每个目标的每个端口执行扫描。

        Args:
            targets: 目标 IP 列表
            ports: 端口列表
            phase: 当前扫描阶段标识（"discovery" 或 "scan"）

        Returns:
            所有扫描结果列表
        """
        # 构建所有任务：目标数 × 端口数
        tasks = [(ip, port) for ip in targets for port in ports]
        total = len(tasks)
        if total == 0:
            self._finish()
            return []

        with self._lock:
            # 在清除取消事件前，先检查是否已被用户停止
            if self._state == ScanState.STOPPED:
                self._finish()
                return self.results
            if self._state == ScanState.IDLE:
                self._state = ScanState.SCANNING
            if phase == "scan":
                self._results.clear()
            self._cancel_event.clear()

        completed = 0
        futures = {}

        with ThreadPoolExecutor(max_workers=min(self.config.max_threads, total)) as executor:
            self._executor = executor
            for ip, port in tasks:
                if self._cancel_event.is_set():
                    break
                # 提交单个端口扫描任务
                future = executor.submit(self._scan_single, ip, port)
                futures[future] = (ip, port)

            for future in as_completed(futures):
                if self._cancel_event.is_set():
                    break
                try:
                    result = future.result()
                    result.phase = phase
                    with self._lock:
                        self._results.append(result)

                    # 通知外部：单个结果完成
                    if self._on_result:
                        self._on_result(result)

                    # 如果检测到代理类型，通知外部
                    if result.is_open and result.proxy_type not in (ProxyType.NONE, ProxyType.UNKNOWN):
                        if self._on_proxy_found:
                            self._on_proxy_found(result)

                    completed += 1
                    if self._on_progress:
                        self._on_progress(completed, total)

                except Exception as e:
                    # 任务执行异常（非网络错误，如内部 bug），记录错误并继续
                    ip, port = futures[future]
                    err_result = ScanResult(ip=ip, port=port, error=str(e), phase=phase)
                    with self._lock:
                        self._results.append(err_result)
                    completed += 1
                    if self._on_progress:
                        self._on_progress(completed, total)

        self._executor = None
        self._finish()
        return self.results

    def _finish(self):
        """扫描结束处理。将状态恢复为空闲并触发完成回调。"""
        with self._lock:
            if self._state in (ScanState.SCANNING, ScanState.DISCOVERING):
                self._state = ScanState.IDLE
        if self._on_complete:
            self._on_complete()

    def _scan_single(self, ip: str, port: int) -> ScanResult:
        """扫描单个 IP:端口 组合（在工作线程中执行，线程安全）。

        扫描流程：
        1. TCP 连接检测 — 判断端口是否开放
        2. 代理协议检测 — 识别 HTTP/SOCKS4/SOCKS5 代理类型
        3. 连通性验证（可选）— 通过代理转发请求验证可用性

        每次调用创建独立的 ProtocolDetector 实例，避免多线程共享状态。

        Args:
            ip: 目标 IP 地址
            port: 目标端口号

        Returns:
            包含完整扫描结果的 ScanResult 对象
        """
        if self._cancel_event.is_set():
            return ScanResult(ip=ip, port=port, error="已取消")

        result = ScanResult(ip=ip, port=port)
        detector = ProtocolDetector(timeout=self.config.timeout)

        # 第一步：TCP 连接检测
        is_open, latency = ProtocolDetector.check_port_open(ip, port, self.config.timeout)
        result.is_open = is_open
        result.latency_ms = latency

        if not is_open:
            return result

        # 第二步：代理协议检测
        if self.config.detect_protocol:
            try:
                proxy_result = detector.probe(ip, port)
                result.proxy_type = proxy_result.proxy_type
                result.requires_auth = proxy_result.requires_auth
                result.banner = proxy_result.banner
                if proxy_result.latency_ms > 0:
                    result.latency_ms = proxy_result.latency_ms
            except Exception as e:
                result.error = f"协议检测异常: {e}"

        # 第三步：代理连通性验证（可选）
        if self.config.test_connectivity and result.proxy_type not in (ProxyType.NONE, ProxyType.UNKNOWN):
            try:
                result.connectivity_ok = detector.test_proxy_connectivity(
                    ip, port, result.proxy_type
                )
            except Exception:
                result.connectivity_ok = False
            result.connectivity_tested = True

        return result
