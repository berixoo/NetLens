"""Multi-threaded TCP port scanner engine with host discovery for campus-scale networks."""
from __future__ import annotations

import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable, Generator, Optional

from .protocol import ProtocolDetector, ProxyResult, ProxyType


class ScanState(Enum):
    IDLE = auto()
    DISCOVERING = auto()   # phase 1: fast host-alive check
    SCANNING = auto()      # phase 2: full port scan
    PAUSED = auto()
    STOPPED = auto()


@dataclass
class ScanConfig:
    ports: list[int] = field(default_factory=lambda: [7890, 7891, 1080, 10808, 10809, 8080, 8118, 3128])
    # ports used for the fast host-alive discovery phase (should NOT overlap with `ports`)
    discovery_ports: list[int] = field(default_factory=lambda: [443, 80, 22, 8080])
    timeout: float = 3.0
    discovery_timeout: float = 1.0          # shorter timeout for discovery
    max_threads: int = 64
    detect_protocol: bool = True
    test_connectivity: bool = False
    # two-phase scanning: discover alive hosts first, then deep scan
    two_phase: bool = True
    # target count threshold to auto-enable two-phase scanning
    two_phase_threshold: int = 256
    # skip hosts that didn't respond during discovery
    skip_dead_hosts: bool = True


@dataclass
class ScanResult:
    ip: str
    port: int
    is_open: bool = False
    proxy_type: ProxyType = ProxyType.NONE
    latency_ms: float = 0.0
    requires_auth: bool = False
    banner: str = ""
    connectivity_ok: bool = False
    timestamp: float = field(default_factory=time.time)
    error: str = ""
    phase: str = ""          # "discovery" or "scan"


class ScannerEngine:
    """Core scanning engine with two-phase campus-scale scanning.

    Phase 1 (Discovery): fast TCP probe on a few common ports to find alive hosts.
    Phase 2 (Deep Scan): full port scan + protocol detection on alive hosts only.
    """

    def __init__(self, config: ScanConfig | None = None):
        self.config = config or ScanConfig()
        self._state = ScanState.IDLE
        self._lock = threading.Lock()
        self._results: list[ScanResult] = []
        self._alive_hosts: set[str] = set()
        self._executor: Optional[ThreadPoolExecutor] = None
        self._cancel_event = threading.Event()

        # callbacks
        self._on_result: Optional[Callable[[ScanResult], None]] = None
        self._on_progress: Optional[Callable[[int, int], None]] = None
        self._on_proxy_found: Optional[Callable[[ScanResult], None]] = None
        self._on_complete: Optional[Callable[[], None]] = None
        self._on_phase_change: Optional[Callable[[str], None]] = None
        self._on_alive_found: Optional[Callable[[str], None]] = None

    # -- public properties ------------------------------------------

    @property
    def state(self) -> ScanState:
        with self._lock:
            return self._state

    @property
    def results(self) -> list[ScanResult]:
        with self._lock:
            return list(self._results)

    @property
    def open_ports(self) -> list[ScanResult]:
        with self._lock:
            return [r for r in self._results if r.is_open]

    @property
    def proxy_results(self) -> list[ScanResult]:
        with self._lock:
            return [r for r in self._results if r.proxy_type not in (ProxyType.NONE, ProxyType.UNKNOWN)]

    @property
    def alive_hosts(self) -> set[str]:
        with self._lock:
            return set(self._alive_hosts)

    # -- callbacks --------------------------------------------------

    def on_result(self, callback: Callable[[ScanResult], None]):
        self._on_result = callback

    def on_progress(self, callback: Callable[[int, int], None]):
        self._on_progress = callback

    def on_proxy_found(self, callback: Callable[[ScanResult], None]):
        self._on_proxy_found = callback

    def on_complete(self, callback: Callable[[], None]):
        self._on_complete = callback

    def on_phase_change(self, callback: Callable[[str], None]):
        self._on_phase_change = callback

    def on_alive_found(self, callback: Callable[[str], None]):
        self._on_alive_found = callback

    # -- control ----------------------------------------------------

    def stop(self):
        with self._lock:
            self._state = ScanState.STOPPED
        self._cancel_event.set()

    def reset(self):
        with self._lock:
            self._results.clear()
            self._alive_hosts.clear()
            self._state = ScanState.IDLE
        self._cancel_event.clear()

    # -- scanning: high level ---------------------------------------

    def scan_targets(self, targets: list[str], ports: list[int] | None = None) -> list[ScanResult]:
        """Scan a list of IPs. If two_phase is on and len(targets) > 100, runs discovery first."""
        ports = ports or self.config.ports

        if self.config.two_phase and len(targets) > self.config.two_phase_threshold:
            return self._scan_two_phase(targets, ports)
        else:
            return self._scan_direct(targets, ports)

    def scan_subnet(self, cidr: str, ports: list[int] | None = None) -> list[ScanResult]:
        """Scan an entire CIDR subnet — no /24 cap."""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            # for very large ranges (> /16), generate lazily
            if network.prefixlen <= 16:
                # /16 or larger — build list in chunks
                targets = []
                for i, ip in enumerate(network.hosts()):
                    targets.append(str(ip))
                    if i >= 65535:
                        break
            else:
                targets = [str(ip) for ip in network.hosts()]
            return self.scan_targets(targets, ports)
        except ValueError as e:
            return [ScanResult(ip=cidr, port=0, error=f"Invalid CIDR: {e}")]

    def discover_hosts(self, targets: list[str], ports: list[int] | None = None) -> set[str]:
        """Phase 1 only: find alive hosts by probing a few ports. Returns set of IPs."""
        ports = ports or self.config.discovery_ports
        alive: set[str] = set()

        with self._lock:
            self._state = ScanState.DISCOVERING
        self._cancel_event.clear()

        # build tasks: each target × discovery_ports
        tasks = [(ip, port) for ip in targets for port in ports]
        total = len(tasks)
        completed = 0

        with ThreadPoolExecutor(max_workers=min(self.config.max_threads, total)) as executor:
            futures = {}
            for ip, port in tasks:
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
                    ip = futures.get(future, "?")
                    # network errors during discovery are expected; silently skip
                completed += 1
                if self._on_progress:
                    self._on_progress(completed, total)

        return alive

    # -- scanning: internal -----------------------------------------

    def _scan_two_phase(self, targets: list[str], ports: list[int]) -> list[ScanResult]:
        """Two-phase scan: discover alive hosts, then deep scan only those."""
        # -- Phase 1: Discovery --
        if self._on_phase_change:
            self._on_phase_change("discovery")

        with self._lock:
            self._state = ScanState.DISCOVERING
            self._results.clear()
            self._alive_hosts.clear()
        self._cancel_event.clear()

        # discovery: probe all targets on a few ports
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
                    pass  # connection refused/timeout during discovery — expected
                disc_done += 1
                if self._on_progress:
                    self._on_progress(disc_done, disc_total)

        if self._cancel_event.is_set():
            self._finish()
            return self.results

        # -- Phase 2: Deep Scan on alive hosts --
        if self._on_phase_change:
            self._on_phase_change("scan")

        with self._lock:
            self._state = ScanState.SCANNING

        if not alive:
            self._finish()
            return self.results

        scan_targets = list(alive)
        return self._scan_direct(scan_targets, ports, phase="scan")

    def _scan_direct(self, targets: list[str], ports: list[int], phase: str = "scan") -> list[ScanResult]:
        """Direct scan: every target × every port."""
        tasks = [(ip, port) for ip in targets for port in ports]
        total = len(tasks)
        if total == 0:
            self._finish()
            return []

        with self._lock:
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

                    if self._on_result:
                        self._on_result(result)

                    if result.is_open and result.proxy_type not in (ProxyType.NONE, ProxyType.UNKNOWN):
                        if self._on_proxy_found:
                            self._on_proxy_found(result)

                    completed += 1
                    if self._on_progress:
                        self._on_progress(completed, total)

                except Exception as e:
                    ip, port = futures[future]
                    err_result = ScanResult(ip=ip, port=port, error=str(e), phase=phase)
                    with self._lock:
                        self._results.append(err_result)
                    completed += 1

        self._executor = None
        self._finish()
        return self.results

    def _finish(self):
        with self._lock:
            if self._state in (ScanState.SCANNING, ScanState.DISCOVERING):
                self._state = ScanState.IDLE
        if self._on_complete:
            self._on_complete()

    def _scan_single(self, ip: str, port: int) -> ScanResult:
        """Scan a single IP:port combination. Thread-safe: creates local detector."""
        if self._cancel_event.is_set():
            return ScanResult(ip=ip, port=port, error="cancelled")

        result = ScanResult(ip=ip, port=port)
        detector = ProtocolDetector(timeout=self.config.timeout)

        # step 1: TCP connect check
        is_open, latency = ProtocolDetector.check_port_open(ip, port, self.config.timeout)
        result.is_open = is_open
        result.latency_ms = latency

        if not is_open:
            return result

        # step 2: protocol detection
        if self.config.detect_protocol:
            try:
                proxy_result = detector.probe(ip, port)
                result.proxy_type = proxy_result.proxy_type
                result.requires_auth = proxy_result.requires_auth
                result.banner = proxy_result.banner
                if proxy_result.latency_ms > 0:
                    result.latency_ms = proxy_result.latency_ms
            except Exception as e:
                result.error = f"detect: {e}"

        # step 3: optional connectivity test
        if self.config.test_connectivity and result.proxy_type not in (ProxyType.NONE, ProxyType.UNKNOWN):
            try:
                result.connectivity_ok = detector.test_proxy_connectivity(
                    ip, port, result.proxy_type
                )
            except Exception:
                result.connectivity_ok = False

        return result
