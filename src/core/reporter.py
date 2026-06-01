"""Report generation: risk assessment, CSV export, summary statistics."""
from __future__ import annotations

import csv
import json
import os
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, auto
from typing import Sequence

from .protocol import ProxyType
from .scanner import ScanResult


class RiskLevel(Enum):
    CRITICAL = auto()   # open proxy, no auth, reachable
    HIGH = auto()       # open proxy, no auth
    MEDIUM = auto()     # proxy with auth, or unknown open port
    LOW = auto()        # open port, not a proxy
    INFO = auto()       # closed port

    @property
    def label(self) -> str:
        return self.name

    @property
    def color_hex(self) -> str:
        return {
            RiskLevel.CRITICAL: "#FF0000",
            RiskLevel.HIGH: "#FF6600",
            RiskLevel.MEDIUM: "#FFAA00",
            RiskLevel.LOW: "#00AA00",
            RiskLevel.INFO: "#888888",
        }[self]


@dataclass
class ReportSummary:
    total_targets: int = 0
    total_ports_scanned: int = 0
    open_ports: int = 0
    proxies_found: int = 0
    by_type: dict[str, int] = None
    by_risk: dict[str, int] = None
    scan_duration_s: float = 0.0

    def __post_init__(self):
        if self.by_type is None:
            self.by_type = {}
        if self.by_risk is None:
            self.by_risk = {}


class ReportGenerator:
    """Generate reports and assess risk for scan results."""

    # -- risk assessment -------------------------------------------

    @staticmethod
    def assess_risk(result: ScanResult) -> RiskLevel:
        """Classify a scan result into a risk level."""
        if not result.is_open:
            return RiskLevel.INFO

        if result.proxy_type in (ProxyType.HTTP, ProxyType.SOCKS4, ProxyType.SOCKS5):
            if not result.requires_auth:
                if result.connectivity_ok:
                    return RiskLevel.CRITICAL
                return RiskLevel.HIGH
            return RiskLevel.MEDIUM

        if result.proxy_type == ProxyType.UNKNOWN:
            return RiskLevel.MEDIUM

        # open port but not a proxy
        return RiskLevel.LOW

    @staticmethod
    def risk_description(level: RiskLevel) -> str:
        return {
            RiskLevel.CRITICAL: "Open unauthenticated proxy, verified reachable — immediate risk",
            RiskLevel.HIGH: "Open unauthenticated proxy detected — high risk of abuse",
            RiskLevel.MEDIUM: "Authenticated proxy or unidentifiable service — moderate risk",
            RiskLevel.LOW: "Open port, no proxy service detected — low risk",
            RiskLevel.INFO: "Port closed or unreachable — informational",
        }[level]

    # -- summary ---------------------------------------------------

    @staticmethod
    def summarize(results: Sequence[ScanResult], duration_s: float = 0.0) -> ReportSummary:
        summary = ReportSummary(
            total_ports_scanned=len(results),
            open_ports=sum(1 for r in results if r.is_open),
            scan_duration_s=duration_s,
        )

        ips = set()
        for r in results:
            ips.add(r.ip)
            if r.proxy_type not in (ProxyType.NONE, ProxyType.UNKNOWN):
                summary.proxies_found += 1
                type_name = r.proxy_type.display_name()
                summary.by_type[type_name] = summary.by_type.get(type_name, 0) + 1

            risk = ReportGenerator.assess_risk(r)
            summary.by_risk[risk.label] = summary.by_risk.get(risk.label, 0) + 1

        summary.total_targets = len(ips)
        return summary

    # -- CSV export ------------------------------------------------

    @staticmethod
    def export_csv(results: Sequence[ScanResult], filepath: str) -> str:
        """Export results to CSV. Returns the absolute path."""
        filepath = os.path.abspath(filepath)
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)

        fieldnames = [
            "ip", "port", "is_open", "proxy_type", "latency_ms",
            "requires_auth", "connectivity_ok", "risk_level",
            "banner", "error", "timestamp"
        ]

        with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                writer.writerow({
                    "ip": r.ip,
                    "port": r.port,
                    "is_open": r.is_open,
                    "proxy_type": r.proxy_type.display_name(),
                    "latency_ms": r.latency_ms,
                    "requires_auth": r.requires_auth,
                    "connectivity_ok": r.connectivity_ok,
                    "risk_level": ReportGenerator.assess_risk(r).label,
                    "banner": r.banner,
                    "error": r.error,
                    "timestamp": datetime.fromtimestamp(r.timestamp).isoformat() if r.timestamp else "",
                })

        return filepath

    # -- JSON export -----------------------------------------------

    @staticmethod
    def export_json(results: Sequence[ScanResult], filepath: str) -> str:
        filepath = os.path.abspath(filepath)
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)

        data = []
        for r in results:
            data.append({
                "ip": r.ip,
                "port": r.port,
                "is_open": r.is_open,
                "proxy_type": r.proxy_type.name,
                "latency_ms": r.latency_ms,
                "requires_auth": r.requires_auth,
                "connectivity_ok": r.connectivity_ok,
                "risk_level": ReportGenerator.assess_risk(r).label,
                "banner": r.banner,
                "error": r.error,
                "timestamp": r.timestamp,
            })

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        return filepath

    # -- log export ------------------------------------------------

    @staticmethod
    def export_log(results: Sequence[ScanResult], filepath: str) -> str:
        filepath = os.path.abspath(filepath)
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(f"# NetLens Scan Report — {datetime.now().isoformat()}\n")
            f.write(f"# Total results: {len(results)}\n\n")

            for r in results:
                risk = ReportGenerator.assess_risk(r)
                status = "OPEN" if r.is_open else "CLOSED"
                proxy = r.proxy_type.display_name()
                auth = " [AUTH]" if r.requires_auth else ""
                conn = " [VERIFIED]" if r.connectivity_ok else ""
                f.write(
                    f"[{risk.label:8s}] {r.ip}:{r.port}  {status:6s}  "
                    f"{proxy}{auth}{conn}  {r.latency_ms}ms"
                )
                if r.banner:
                    f.write(f"  banner={r.banner[:60]}")
                if r.error:
                    f.write(f"  error={r.error}")
                f.write("\n")

        return filepath
