"""报告生成模块：风险评估、汇总统计、多格式导出。

提供三种导出格式：
  - CSV（带 BOM 头，可直接用 Excel 打开）
  - JSON（结构化数据，便于程序处理）
  - 纯文本日志（人类可读的扫描报告）
"""
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
    """风险等级枚举，从高到低排列。"""
    CRITICAL = auto()   # 严重：开放无认证代理，已验证可达 — 面临即时风险，可能被用于匿名上网或攻击跳板
    HIGH = auto()       # 高危：开放无认证代理 — 存在被滥用的高风险
    MEDIUM = auto()     # 中危：需认证的代理或无法识别的服务 — 需要进一步确认
    LOW = auto()        # 低危：开放端口但非代理服务 — 普通 Web 服务等
    INFO = auto()       # 信息：端口关闭或不可达 — 仅供参考

    @property
    def label(self) -> str:
        """返回风险等级的英文标签（用于显示和导出）。"""
        return self.name

    @property
    def color_hex(self) -> str:
        """返回风险等级对应的显示颜色（十六进制）。"""
        return {
            RiskLevel.CRITICAL: "#FF0000",  # 红色
            RiskLevel.HIGH: "#FF6600",      # 橙色
            RiskLevel.MEDIUM: "#FFAA00",    # 黄色
            RiskLevel.LOW: "#00AA00",       # 绿色
            RiskLevel.INFO: "#888888",      # 灰色
        }[self]


@dataclass
class ReportSummary:
    """扫描结果汇总统计。"""
    total_targets: int = 0          # 扫描的目标 IP 数量（去重后）
    total_ports_scanned: int = 0    # 扫描的端口总数（IP 数 × 端口数）
    open_ports: int = 0             # 开放端口数量
    proxies_found: int = 0          # 检测到的代理数量
    by_type: dict[str, int] = None  # 按代理类型统计（如 {"HTTP": 5, "SOCKS5": 2}）
    by_risk: dict[str, int] = None  # 按风险等级统计（如 {"CRITICAL": 1, "HIGH": 3}）
    scan_duration_s: float = 0.0    # 扫描耗时（秒）

    def __post_init__(self):
        if self.by_type is None:
            self.by_type = {}
        if self.by_risk is None:
            self.by_risk = {}


class ReportGenerator:
    """报告生成器，提供风险评估、汇总统计和多格式导出功能。"""

    # ── 风险评估 ──────────────────────────────────────────────────

    @staticmethod
    def assess_risk(result: ScanResult) -> RiskLevel:
        """评估单个扫描结果的风险等级。

        评估逻辑（按优先级从高到低）：
        1. 端口关闭 → INFO
        2. 已知代理类型 + 无认证 + 已验证可达 → CRITICAL
        3. 已知代理类型 + 无认证 → HIGH
        4. 已知代理类型 + 需认证 → MEDIUM
        5. 端口开放但协议未知 → MEDIUM
        6. 端口开放但非代理 → LOW

        Args:
            result: 单个端口的扫描结果

        Returns:
            对应的风险等级
        """
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

        # 端口开放但不是代理服务
        return RiskLevel.LOW

    @staticmethod
    def risk_description(level: RiskLevel) -> str:
        """返回风险等级的中文描述。"""
        return {
            RiskLevel.CRITICAL: "开放无认证代理，已验证可达 — 面临即时风险",
            RiskLevel.HIGH: "检测到开放无认证代理 — 存在被滥用的高风险",
            RiskLevel.MEDIUM: "需认证的代理或无法识别的服务 — 中等风险",
            RiskLevel.LOW: "开放端口但未检测到代理服务 — 低风险",
            RiskLevel.INFO: "端口关闭或不可达 — 仅供参考",
        }[level]

    # ── 汇总统计 ──────────────────────────────────────────────────

    @staticmethod
    def summarize(results: Sequence[ScanResult], duration_s: float = 0.0) -> ReportSummary:
        """统计扫描结果的汇总信息。

        遍历所有结果，统计开放端口数、代理数、按类型和风险等级分组计数。

        Args:
            results: 扫描结果序列
            duration_s: 扫描总耗时（秒）

        Returns:
            汇总统计对象
        """
        summary = ReportSummary(
            total_ports_scanned=len(results),
            open_ports=sum(1 for r in results if r.is_open),
            scan_duration_s=duration_s,
        )

        ips = set()
        for r in results:
            ips.add(r.ip)
            # 统计代理数量（排除 NONE 和 UNKNOWN）
            if r.proxy_type not in (ProxyType.NONE, ProxyType.UNKNOWN):
                summary.proxies_found += 1
                type_name = r.proxy_type.display_name()
                summary.by_type[type_name] = summary.by_type.get(type_name, 0) + 1

            # 统计各风险等级数量
            risk = ReportGenerator.assess_risk(r)
            summary.by_risk[risk.label] = summary.by_risk.get(risk.label, 0) + 1

        summary.total_targets = len(ips)
        return summary

    # ── CSV 导出 ──────────────────────────────────────────────────

    @staticmethod
    def export_csv(results: Sequence[ScanResult], filepath: str) -> str:
        """将扫描结果导出为 CSV 文件。

        使用 UTF-8 with BOM 编码，确保 Excel 能正确识别中文。
        风险等级在导出时动态计算，不依赖存储的字段。

        Args:
            results: 扫描结果序列
            filepath: 输出文件路径

        Returns:
            导出文件的绝对路径
        """
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

    # ── JSON 导出 ─────────────────────────────────────────────────

    @staticmethod
    def export_json(results: Sequence[ScanResult], filepath: str) -> str:
        """将扫描结果导出为 JSON 文件。

        Args:
            results: 扫描结果序列
            filepath: 输出文件路径

        Returns:
            导出文件的绝对路径
        """
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

    # ── 日志导出 ──────────────────────────────────────────────────

    @staticmethod
    def export_log(results: Sequence[ScanResult], filepath: str) -> str:
        """将扫描结果导出为人类可读的纯文本日志。

        格式示例：
          [CRITICAL] 10.16.88.217:7890  OPEN    HTTP  [VERIFIED]  16ms

        Args:
            results: 扫描结果序列
            filepath: 输出文件路径

        Returns:
            导出文件的绝对路径
        """
        filepath = os.path.abspath(filepath)
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(f"# NetLens 扫描报告 — {datetime.now().isoformat()}\n")
            f.write(f"# 总结果数: {len(results)}\n\n")

            for r in results:
                risk = ReportGenerator.assess_risk(r)
                status = "OPEN" if r.is_open else "CLOSED"
                proxy = r.proxy_type.display_name()
                auth = " [需认证]" if r.requires_auth else ""
                conn = " [已验证]" if r.connectivity_ok else ""
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
