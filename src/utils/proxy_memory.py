"""代理记忆模块：持久化存储已验证的代理地址。

将扫描发现的可用代理记录保存到 JSON 文件中，下次启动时自动加载，
用户可以直接从历史记录中选择代理，无需重新扫描。

存储格式：proxy_memory.json（位于项目根目录，已加入 .gitignore）
每条记录包含：地址、类型、延迟、认证需求、发现时间、使用次数、验证次数等。

线程安全：所有读写操作通过 threading.Lock 保护。
原子写入：先写入临时文件再原子替换，防止写入过程中断导致文件损坏。
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# 默认存储路径：项目根目录下的 proxy_memory.json
_DEFAULT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "proxy_memory.json")


@dataclass
class ProxyRecord:
    """单条代理记录。

    Attributes:
        ip: 代理服务器 IP 地址
        port: 代理服务器端口号
        proxy_type: 代理类型字符串（"HTTP" / "SOCKS4" / "SOCKS5"）
        latency_ms: 协议握手延迟（毫秒）
        requires_auth: 是否需要认证
        first_seen: 首次发现时间（Unix 时间戳）
        last_seen: 最后一次发现时间（Unix 时间戳）
        last_used: 用户最后一次选择使用此代理的时间（Unix 时间戳）
        use_count: 用户选择使用此代理的累计次数
        success_count: 连通性验证成功的累计次数
        notes: 用户备注（预留字段）
    """
    ip: str
    port: int
    proxy_type: str = ""
    latency_ms: float = 0.0
    requires_auth: bool = False
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    last_used: float = 0.0
    use_count: int = 0
    success_count: int = 0
    notes: str = ""

    @property
    def address(self) -> str:
        """返回 "ip:port" 格式的地址字符串。"""
        return f"{self.ip}:{self.port}"

    @property
    def label(self) -> str:
        """返回带详情的显示标签，如 "192.168.1.1:7890 (HTTP 15ms)"。"""
        auth = " [认证]" if self.requires_auth else ""
        latency = f" {self.latency_ms:.0f}ms" if self.latency_ms else ""
        return f"{self.address} ({self.proxy_type}{auth}{latency})"


class ProxyMemory:
    """线程安全的代理记忆持久化存储。

    使用 JSON 文件作为后端存储，支持原子写入（先写临时文件再替换），
    防止写入过程中程序崩溃导致数据丢失。
    """

    def __init__(self, filepath: str | None = None):
        """初始化代理记忆存储。

        Args:
            filepath: JSON 存储文件路径，为 None 时使用默认路径
        """
        self._filepath = filepath or _DEFAULT_PATH
        self._lock = threading.Lock()
        self._records: dict[str, ProxyRecord] = {}  # key = "ip:port"
        self._load()

    # ── 公开接口 ──────────────────────────────────────────────────

    @property
    def records(self) -> list[ProxyRecord]:
        """返回所有记录的列表，按最后发现时间降序排列（最近的在前）。"""
        with self._lock:
            return sorted(self._records.values(), key=lambda r: r.last_seen, reverse=True)

    def add_or_update(self, ip: str, port: int, proxy_type: str = "",
                      latency_ms: float = 0.0, requires_auth: bool = False) -> ProxyRecord:
        """添加新记录或更新已有记录。

        如果该 IP:port 已存在记录，则更新其 last_seen、success_count 等字段；
        否则创建一条新记录。操作完成后自动保存到磁盘。

        Args:
            ip: 代理 IP 地址
            port: 代理端口号
            proxy_type: 代理类型
            latency_ms: 延迟
            requires_auth: 是否需认证

        Returns:
            被添加或更新的 ProxyRecord 对象
        """
        key = f"{ip}:{port}"
        with self._lock:
            if key in self._records:
                # 更新已有记录
                rec = self._records[key]
                rec.last_seen = time.time()
                rec.success_count += 1
                if proxy_type:
                    rec.proxy_type = proxy_type
                if latency_ms > 0:
                    rec.latency_ms = latency_ms
                rec.requires_auth = requires_auth
            else:
                # 创建新记录
                rec = ProxyRecord(
                    ip=ip, port=port, proxy_type=proxy_type,
                    latency_ms=latency_ms, requires_auth=requires_auth,
                )
                self._records[key] = rec
            self._save_unlocked()
            return rec

    def mark_used(self, ip: str, port: int) -> None:
        """记录用户选择使用了此代理。

        更新 last_used 时间戳和 use_count 计数器。

        Args:
            ip: 代理 IP 地址
            port: 代理端口号
        """
        key = f"{ip}:{port}"
        with self._lock:
            if key in self._records:
                rec = self._records[key]
                rec.last_used = time.time()
                rec.use_count += 1
                self._save_unlocked()

    def remove(self, ip: str, port: int) -> bool:
        """删除指定记录。

        Args:
            ip: 代理 IP 地址
            port: 代理端口号

        Returns:
            True 表示成功删除，False 表示记录不存在
        """
        key = f"{ip}:{port}"
        with self._lock:
            if key in self._records:
                del self._records[key]
                self._save_unlocked()
                return True
            return False

    def clear(self) -> None:
        """清空所有记录并保存到磁盘。"""
        with self._lock:
            self._records.clear()
            self._save_unlocked()

    def get(self, ip: str, port: int) -> Optional[ProxyRecord]:
        """获取指定地址的记录。"""
        key = f"{ip}:{port}"
        with self._lock:
            return self._records.get(key)

    def get_recent(self, limit: int = 20) -> list[ProxyRecord]:
        """获取最近发现的 N 条记录。"""
        return self.records[:limit]

    def get_most_used(self, limit: int = 10) -> list[ProxyRecord]:
        """获取使用次数最多的 N 条记录。"""
        with self._lock:
            return sorted(self._records.values(), key=lambda r: r.use_count, reverse=True)[:limit]

    # ── 持久化 ───────────────────────────────────────────────────

    def _load(self) -> None:
        """从 JSON 文件加载记录。

        加载时会过滤掉未知字段（防止手动编辑或版本升级导致的字段不匹配），
        单条记录解析失败不会影响其他记录。
        """
        if not os.path.exists(self._filepath):
            return
        try:
            with open(self._filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"读取代理记忆文件失败: {e}")
            return

        # 提取 ProxyRecord 的合法字段名，过滤掉未知字段
        import dataclasses as _dc
        valid_keys = {f.name for f in _dc.fields(ProxyRecord)}
        loaded = 0
        for item in data:
            try:
                # 只保留合法字段，忽略多余的键
                filtered = {k: v for k, v in item.items() if k in valid_keys}
                rec = ProxyRecord(**filtered)
                self._records[f"{rec.ip}:{rec.port}"] = rec
                loaded += 1
            except (TypeError, KeyError, ValueError) as e:
                logger.debug(f"跳过损坏的代理记录: {e}")
        logger.debug(f"从 {self._filepath} 加载了 {loaded} 条代理记录")

    def _save_unlocked(self) -> None:
        """将记录保存到磁盘（调用方必须持有 self._lock）。

        使用原子写入策略：
        1. 先写入临时文件（.tmp 后缀）
        2. 使用 os.replace() 原子替换目标文件

        这样即使写入过程中程序崩溃，也不会损坏已有的数据文件。
        """
        try:
            data = [asdict(r) for r in self._records.values()]
            tmp = self._filepath + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            # 原子替换：os.replace 在 Windows 上是原子操作
            if os.path.exists(self._filepath):
                os.replace(tmp, self._filepath)
            else:
                os.rename(tmp, self._filepath)
        except OSError as e:
            logger.error(f"保存代理记忆失败: {e}")
