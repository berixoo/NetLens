"""线程安全的日志模块。

提供双重输出：写入日志文件（DEBUG 级别）+ 内存缓冲区（供 UI 实时显示）。
日志文件以时间戳命名，存储在 logs/ 目录下。

线程安全：内存缓冲区的读写通过 threading.Lock 保护。
注意：logging 模块自身的 FileHandler 有内部锁，我们在锁外调用日志写入，
避免嵌套锁导致的死锁风险。
"""
from __future__ import annotations

import logging
import os
import threading
from datetime import datetime


class ScanLogger:
    """线程安全的扫描日志记录器。

    同时向日志文件和内存缓冲区写入日志消息。
    内存缓冲区有最大容量限制（默认 5000 条），超出后自动丢弃最早的记录。

    使用方式：
        logger = ScanLogger()
        logger.info("扫描开始")
        logger.error("连接失败")
        buffer = logger.buffer  # 获取内存中的所有日志
        logger.close()          # 程序退出时关闭文件句柄
    """

    def __init__(self, name: str = "NetLens", log_dir: str = "logs"):
        """初始化日志记录器。

        Args:
            name: 日志记录器名称，相同名称共享同一个底层 logger 实例
            log_dir: 日志文件存储目录，不存在时自动创建
        """
        self._lock = threading.Lock()  # 保护内存缓冲区的互斥锁
        self._log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)

        # 生成带时间戳的日志文件名，如 scan_20260601_172332.log
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._log_file = os.path.join(log_dir, f"scan_{timestamp}.log")

        self._logger = logging.getLogger(name)
        self._logger.setLevel(logging.DEBUG)

        # 创建文件处理器：记录所有级别的详细日志
        self._fh = logging.FileHandler(self._log_file, encoding="utf-8")
        self._fh.setLevel(logging.DEBUG)
        self._fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"
        ))
        # 防止重复添加 handler：如果 ScanLogger 被多次实例化（如测试场景），
        # 同名 logger 会共享，重复添加 handler 会导致日志重复输出
        if not any(isinstance(h, logging.FileHandler) for h in self._logger.handlers):
            self._logger.addHandler(self._fh)

        # 内存缓冲区：存储最近的日志消息，供 UI 实时显示
        self._buffer: list[str] = []
        self._max_buffer = 5000  # 最多保留 5000 条日志

    @property
    def log_file(self) -> str:
        """返回当前日志文件的完整路径。"""
        return self._log_file

    @property
    def buffer(self) -> list[str]:
        """返回内存缓冲区中的所有日志消息副本（线程安全）。"""
        with self._lock:
            return list(self._buffer)

    def debug(self, msg: str):
        """记录 DEBUG 级别日志。"""
        self._log(logging.DEBUG, msg)

    def info(self, msg: str):
        """记录 INFO 级别日志。"""
        self._log(logging.INFO, msg)

    def warning(self, msg: str):
        """记录 WARNING 级别日志。"""
        self._log(logging.WARNING, msg)

    def error(self, msg: str):
        """记录 ERROR 级别日志。"""
        self._log(logging.ERROR, msg)

    def _log(self, level: int, msg: str):
        """内部方法：同时写入文件和内存缓冲区。

        先调用 logging 模块写入文件（logging 自身有锁，不持有我们的锁），
        再获取我们的锁更新内存缓冲区，避免嵌套锁。
        """
        self._logger.log(level, msg)
        with self._lock:
            self._buffer.append(msg)
            # 缓冲区满时丢弃最早的一半记录，避免频繁截断
            if len(self._buffer) > self._max_buffer:
                self._buffer = self._buffer[-self._max_buffer:]

    def clear_buffer(self):
        """清空内存缓冲区（不影响日志文件）。"""
        with self._lock:
            self._buffer.clear()

    def close(self):
        """刷新并关闭文件处理器。

        程序退出时应调用此方法，确保所有日志写入磁盘，
        释放文件句柄，使日志文件可被其他程序读取。
        """
        try:
            self._fh.close()
            self._logger.removeHandler(self._fh)
        except Exception:
            pass
