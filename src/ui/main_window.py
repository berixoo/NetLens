"""Main application window for NetLens — campus-scale proxy scanner."""
from __future__ import annotations

import html
import os
import sys
import threading
from collections import deque
from datetime import datetime

from PySide6.QtCore import Qt, QThread, Signal, Slot, QTimer
from PySide6.QtGui import QColor, QFont, QIcon, QTextCursor
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QGroupBox, QLabel, QLineEdit, QTextEdit, QSpinBox,
    QDoubleSpinBox, QCheckBox, QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QProgressBar, QFileDialog, QMessageBox, QSplitter,
    QTabWidget, QComboBox, QDialog, QDialogButtonBox, QPlainTextEdit,
    QStatusBar, QToolButton, QSizePolicy
)

from ..core.scanner import ScannerEngine, ScanConfig, ScanResult, ScanState
from ..core.protocol import ProxyType, ProtocolDetector
from ..core.reporter import ReportGenerator, RiskLevel
from ..utils.network import (
    parse_ip_range, get_local_subnet, ip_range_count,
    get_local_network_info, get_campus_scan_targets, expand_cidr, cidr_host_count
)
from ..utils.logger import ScanLogger
from ..utils.proxy_switch import get_proxy_status, set_proxy, disable_proxy, ProxyStatus
from ..utils.proxy_memory import ProxyMemory, ProxyRecord


# ─── Worker thread ───────────────────────────────────────────────

class ScanWorker(QThread):
    """Background thread that runs the scanner engine with two-phase support."""
    result_ready = Signal(object)       # ScanResult
    progress = Signal(int, int)         # completed, total
    proxy_found = Signal(object)        # ScanResult
    finished_signal = Signal()
    log_message = Signal(str)
    phase_change = Signal(str)          # "discovery" or "scan"
    alive_found = Signal(str)           # IP of alive host

    def __init__(self, engine: ScannerEngine, targets: list[str], ports: list[int]):
        super().__init__()
        self.engine = engine
        self.targets = targets
        self.ports = ports

    def run(self):
        def on_result(r: ScanResult):
            self.result_ready.emit(r)
            status = "开放" if r.is_open else "关闭"
            proxy_name = r.proxy_type.display_name()
            self.log_message.emit(
                f"{r.ip}:{r.port}  {status}  {proxy_name}  {r.latency_ms}ms"
            )

        def on_progress(done: int, total: int):
            self.progress.emit(done, total)

        def on_proxy(r: ScanResult):
            self.proxy_found.emit(r)

        def on_complete():
            self.finished_signal.emit()

        def on_phase(phase: str):
            self.phase_change.emit(phase)

        def on_alive(ip: str):
            self.alive_found.emit(ip)

        self.engine.on_result(on_result)
        self.engine.on_progress(on_progress)
        self.engine.on_proxy_found(on_proxy)
        self.engine.on_complete(on_complete)
        self.engine.on_phase_change(on_phase)
        self.engine.on_alive_found(on_alive)

        self.engine.scan_targets(self.targets, self.ports)


class ProxyTestWorker(QThread):
    """Background thread for proxy connectivity testing — keeps UI responsive."""
    finished = Signal(object, bool)  # ScanResult, connectivity_ok

    def __init__(self, result: ScanResult, timeout: float):
        super().__init__()
        self.result = result
        self.timeout = timeout

    def run(self):
        try:
            detector = ProtocolDetector(timeout=self.timeout)
            ok = detector.test_proxy_connectivity(
                self.result.ip, self.result.port, self.result.proxy_type
            )
        except Exception:
            ok = False
        self.finished.emit(self.result, ok)


# ─── Proxy test dialog ──────────────────────────────────────────

class ProxyTestDialog(QDialog):
    """Shown when a working proxy is found; asks user whether to use it."""

    def __init__(self, result: ScanResult, parent=None):
        super().__init__(parent)
        self.setWindowTitle("发现代理!")
        self.setMinimumWidth(420)
        self.result = result
        self.use_proxy = False

        layout = QVBoxLayout(self)

        safe_ip = html.escape(result.ip)
        info = QLabel(
            f"<b style='color:#00AA00;font-size:14px'>发现可用代理</b><br><br>"
            f"<b>地址:</b> {safe_ip}:{result.port}<br>"
            f"<b>类型:</b> {result.proxy_type.display_name()}<br>"
            f"<b>延迟:</b> {result.latency_ms} ms<br>"
            f"<b>需要认证:</b> {'是' if result.requires_auth else '否'}<br>"
            f"<b>已验证:</b> {'是 — 流量转发成功' if result.connectivity_ok else '未测试'}"
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        layout.addWidget(QLabel("是否使用此代理?"))

        btn_box = QDialogButtonBox()
        btn_use = btn_box.addButton("使用此代理 (设为系统代理)", QDialogButtonBox.AcceptRole)
        btn_skip = btn_box.addButton("跳过并继续扫描", QDialogButtonBox.RejectRole)
        btn_copy = btn_box.addButton("复制到剪贴板", QDialogButtonBox.ActionRole)

        btn_use.clicked.connect(self._on_use)
        btn_skip.clicked.connect(self._on_skip)
        btn_copy.clicked.connect(self._on_copy)

        layout.addWidget(btn_box)

    def _on_use(self):
        self.use_proxy = True
        self.accept()

    def _on_skip(self):
        self.use_proxy = False
        self.accept()

    def _on_copy(self):
        addr = f"{self.result.ip}:{self.result.port}"
        QApplication.clipboard().setText(addr)
        QMessageBox.information(self, "已复制", f"已复制: {addr}")


# ─── Saved Proxies Dialog ────────────────────────────────────────

class SavedProxiesDialog(QDialog):
    """Show saved proxy records, allow quick apply, re-test, or delete."""

    def __init__(self, memory: ProxyMemory, timeout: float = 3.0, parent=None):
        super().__init__(parent)
        self.setWindowTitle("已保存代理")
        self.setMinimumSize(640, 400)
        self.memory = memory
        self._timeout = timeout
        self._test_workers: list[ProxyTestWorker] = []

        layout = QVBoxLayout(self)

        # info label
        self._info_label = QLabel(f"共 {len(memory.records)} 条记录")
        layout.addWidget(self._info_label)

        # table — 8 columns: address, type, latency, auth, use_count, last_seen, status, action
        self._table = QTableWidget()
        self._table.setColumnCount(8)
        self._table.setHorizontalHeaderLabels([
            "地址", "类型", "延迟", "需认证", "使用次数", "最后发现", "连通性", "操作"
        ])
        header = self._table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self._table)

        self._records = memory.records  # snapshot for stable indexing
        self._connectivity: dict[str, str] = {}  # "ip:port" -> status text
        self._populate_table()

        # bottom buttons
        btn_row = QHBoxLayout()

        btn_retest = QPushButton("重新测试连通性")
        btn_retest.clicked.connect(self._retest_selected)
        btn_row.addWidget(btn_retest)

        btn_retest_all = QPushButton("测试全部")
        btn_retest_all.clicked.connect(self._retest_all)
        btn_row.addWidget(btn_retest_all)

        btn_apply = QPushButton("应用选中代理到系统")
        btn_apply.setObjectName("proxyOnBtn")
        btn_apply.clicked.connect(self._apply_selected)
        btn_row.addWidget(btn_apply)

        btn_copy = QPushButton("复制地址")
        btn_copy.clicked.connect(self._copy_selected)
        btn_row.addWidget(btn_copy)

        btn_delete = QPushButton("删除选中")
        btn_delete.setObjectName("proxyOffBtn")
        btn_delete.clicked.connect(self._delete_selected)
        btn_row.addWidget(btn_delete)

        btn_close = QPushButton("关闭")
        btn_close.clicked.connect(self.accept)
        btn_row.addWidget(btn_close)

        layout.addLayout(btn_row)

    def _populate_table(self):
        self._records = self.memory.records
        self._table.setRowCount(len(self._records))
        for row, rec in enumerate(self._records):
            try:
                last = datetime.fromtimestamp(rec.last_seen).strftime("%m-%d %H:%M")
            except (ValueError, OSError):
                last = "-"

            status_text = self._connectivity.get(rec.address, "未测试")
            items = [
                rec.address,
                rec.proxy_type or "-",
                f"{rec.latency_ms:.0f}ms" if rec.latency_ms else "-",
                "是" if rec.requires_auth else "",
                str(rec.use_count),
                last,
                status_text,
                "",
            ]
            for col, text in enumerate(items):
                item = QTableWidgetItem(text)
                if col == 6:
                    if "可达" in text:
                        item.setForeground(QColor("#a6e3a1"))
                    elif "不可达" in text:
                        item.setForeground(QColor("#f38ba8"))
                self._table.setItem(row, col, item)

            btn = QPushButton("使用")
            btn.setFixedHeight(24)
            btn.clicked.connect(lambda checked, r=rec: self._quick_apply(r))
            self._table.setCellWidget(row, 7, btn)

    def _get_selected_record(self) -> ProxyRecord | None:
        row = self._table.currentRow()
        if row < 0 or row >= len(self._records):
            return None
        return self._records[row]

    def _retest_selected(self):
        rec = self._get_selected_record()
        if not rec:
            QMessageBox.information(self, "提示", "请先选中一条记录。")
            return
        self._start_test(rec)

    def _retest_all(self):
        for rec in self._records:
            self._start_test(rec)

    def _start_test(self, rec: ProxyRecord):
        self._connectivity[rec.address] = "测试中..."
        self._populate_table()
        # build a minimal ScanResult for the worker
        from src.core.protocol import ProxyType as PT
        ptype = {"HTTP": PT.HTTP, "SOCKS4": PT.SOCKS4, "SOCKS5": PT.SOCKS5}.get(rec.proxy_type, PT.NONE)
        result = ScanResult(ip=rec.ip, port=rec.port, is_open=True, proxy_type=ptype)
        worker = ProxyTestWorker(result, self._timeout)
        worker.finished.connect(self._on_test_done)
        self._test_workers.append(worker)
        worker.start()

    def _on_test_done(self, result: ScanResult, ok: bool):
        addr = f"{result.ip}:{result.port}"
        if ok:
            self._connectivity[addr] = "可达"
        else:
            self._connectivity[addr] = "不可达"
        self._populate_table()
        self._test_workers = [w for w in self._test_workers if w.isRunning()]

    def _apply_selected(self):
        rec = self._get_selected_record()
        if not rec:
            QMessageBox.information(self, "提示", "请先选中一条记录。")
            return
        self._quick_apply(rec)

    def _quick_apply(self, rec: ProxyRecord):
        addr = rec.address
        ok = set_proxy(addr)
        self.memory.mark_used(rec.ip, rec.port)
        if ok:
            QMessageBox.information(self, "已应用", f"系统代理已设置为:\n{addr} ({rec.proxy_type})")
        else:
            QMessageBox.warning(self, "失败", f"设置系统代理失败，请以管理员身份运行。")
        self.accept()

    def _copy_selected(self):
        rec = self._get_selected_record()
        if rec:
            QApplication.clipboard().setText(rec.address)
            QMessageBox.information(self, "已复制", f"已复制: {rec.address}")

    def _delete_selected(self):
        rec = self._get_selected_record()
        if not rec:
            return
        self.memory.remove(rec.ip, rec.port)
        self._populate_table()

    def closeEvent(self, event):
        for w in self._test_workers:
            w.wait(1000)
        event.accept()


# ─── Scan Summary Dialog ─────────────────────────────────────────

class ScanSummaryDialog(QDialog):
    """Shown after scan completes — lists all found proxies, user picks one to use."""

    def __init__(self, results: list[ScanResult], parent=None):
        super().__init__(parent)
        self.setWindowTitle("扫描完成 — 发现的代理")
        self.setMinimumSize(600, 380)
        self.results = results
        self.chosen: ScanResult | None = None

        layout = QVBoxLayout(self)

        count = len(results)
        verified = sum(1 for r in results if r.connectivity_ok)
        layout.addWidget(QLabel(
            f"共发现 {count} 个代理，其中 {verified} 个已验证可达。"
        ))

        # table
        self._table = QTableWidget()
        self._table.setColumnCount(7)
        self._table.setHorizontalHeaderLabels([
            "地址", "类型", "延迟", "需认证", "已验证", "连通性", "风险"
        ])
        header = self._table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self._table)

        for row, r in enumerate(results):
            self._table.insertRow(row)
            risk = ReportGenerator.assess_risk(r)
            items = [
                f"{r.ip}:{r.port}",
                r.proxy_type.display_name(),
                f"{r.latency_ms:.0f}ms" if r.latency_ms else "-",
                "是" if r.requires_auth else "",
                "是" if r.connectivity_ok else "",
                "可达" if r.connectivity_ok else "未验证" if not r.connectivity_ok else "不可达",
                risk.label,
            ]
            for col, text in enumerate(items):
                item = QTableWidgetItem(text)
                if col == 4:
                    item.setForeground(QColor("#a6e3a1") if r.connectivity_ok else QColor("#6c7086"))
                if col == 5:
                    if r.connectivity_ok:
                        item.setForeground(QColor("#a6e3a1"))
                if col == 6:
                    item.setForeground(QColor(risk.color_hex))
                    item.setFont(QFont("", -1, QFont.Bold))
                self._table.setItem(row, col, item)

        # buttons
        btn_row = QHBoxLayout()

        btn_use = QPushButton("使用选中代理")
        btn_use.setObjectName("proxyOnBtn")
        btn_use.clicked.connect(self._use_selected)
        btn_row.addWidget(btn_use)

        btn_copy = QPushButton("复制地址")
        btn_copy.clicked.connect(self._copy_selected)
        btn_row.addWidget(btn_copy)

        btn_skip = QPushButton("跳过")
        btn_skip.clicked.connect(self.accept)
        btn_row.addWidget(btn_skip)

        layout.addLayout(btn_row)

    def _use_selected(self):
        row = self._table.currentRow()
        if row < 0 or row >= len(self.results):
            QMessageBox.information(self, "提示", "请先选中一个代理。")
            return
        self.chosen = self.results[row]
        addr = f"{self.chosen.ip}:{self.chosen.port}"
        ok = set_proxy(addr)
        if ok:
            QMessageBox.information(self, "已应用", f"系统代理已设置为:\n{addr}")
        else:
            QMessageBox.warning(self, "失败", "设置系统代理失败，请以管理员身份运行。")
        self.accept()

    def _copy_selected(self):
        row = self._table.currentRow()
        if 0 <= row < len(self.results):
            r = self.results[row]
            QApplication.clipboard().setText(f"{r.ip}:{r.port}")
            QMessageBox.information(self, "已复制", f"已复制: {r.ip}:{r.port}")


# ─── Main Window ─────────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetLens - LAN 代理服务暴露检测工具")
        self.setMinimumSize(1100, 750)

        self._engine = ScannerEngine()
        self._logger = ScanLogger()
        self._reporter = ReportGenerator()
        self._memory = ProxyMemory()
        self._test_workers: list[ProxyTestWorker] = []
        self._found_proxies: list[ScanResult] = []  # proxies found during current scan
        self._worker: ScanWorker | None = None
        self._results: list[ScanResult] = []
        self._scan_start: float = 0.0
        self._alive_count: int = 0
        self._current_phase: str = ""

        self._build_ui()
        self._apply_style()
        self._refresh_proxy_status()
        self._log("NetLens 启动完成，准备就绪。")

    # ── UI construction ──────────────────────────────────────────

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setSpacing(6)

        # top area: config + target input side by side
        top = QHBoxLayout()

        # left: target input
        target_group = QGroupBox("扫描目标")
        tg_layout = QVBoxLayout(target_group)

        # scan mode selector
        mode_row = QHBoxLayout()
        mode_row.addWidget(QLabel("扫描模式:"))
        self._scan_mode = QComboBox()
        self._scan_mode.addItems([
            "本机子网 (/24)",
            "校园网段 (/16)",
            "自定义 (下方输入)",
        ])
        self._scan_mode.currentIndexChanged.connect(self._on_mode_changed)
        mode_row.addWidget(self._scan_mode, stretch=1)

        self._btn_campus_scan = QPushButton("校园扫描")
        self._btn_campus_scan.setObjectName("campusBtn")
        self._btn_campus_scan.setToolTip("扫描校园网段中的代理服务")
        self._btn_campus_scan.clicked.connect(self._campus_scan)
        mode_row.addWidget(self._btn_campus_scan)
        tg_layout.addLayout(mode_row)

        input_row = QHBoxLayout()
        self._target_input = QPlainTextEdit()
        self._target_input.setPlaceholderText(
            "输入 IP 地址，每行一个或逗号分隔。\n"
            "支持格式: 192.168.1.1 | 10.0.0.0/24 | 192.168.1.1-100\n"
            "或从文件导入..."
        )
        self._target_input.setMaximumHeight(100)
        input_row.addWidget(self._target_input)

        btn_col = QVBoxLayout()
        self._btn_import = QPushButton("导入\n文件")
        self._btn_import.setFixedWidth(80)
        self._btn_import.clicked.connect(self._import_file)
        btn_col.addWidget(self._btn_import)

        self._btn_localnet = QPushButton("本机\n子网")
        self._btn_localnet.setFixedWidth(80)
        self._btn_localnet.clicked.connect(self._use_local_subnet)
        btn_col.addWidget(self._btn_localnet)

        self._btn_clear_targets = QPushButton("清空")
        self._btn_clear_targets.setFixedWidth(80)
        self._btn_clear_targets.clicked.connect(lambda: self._target_input.clear())
        btn_col.addWidget(self._btn_clear_targets)

        btn_col.addStretch()
        input_row.addLayout(btn_col)
        tg_layout.addLayout(input_row)

        self._lbl_target_count = QLabel("0 个目标")
        tg_layout.addWidget(self._lbl_target_count)
        self._target_input.textChanged.connect(self._update_target_count)

        top.addWidget(target_group, stretch=3)

        # right: config
        config_group = QGroupBox("扫描配置")
        cg = QGridLayout(config_group)

        cg.addWidget(QLabel("端口:"), 0, 0)
        self._ports_input = QLineEdit("7890, 7891, 1080, 10808, 10809, 8080, 8118, 3128")
        self._ports_input.setPlaceholderText("逗号分隔的端口号")
        cg.addWidget(self._ports_input, 0, 1, 1, 3)

        cg.addWidget(QLabel("线程数:"), 1, 0)
        self._threads_spin = QSpinBox()
        self._threads_spin.setRange(1, 256)
        self._threads_spin.setValue(128)
        cg.addWidget(self._threads_spin, 1, 1)

        cg.addWidget(QLabel("超时 (秒):"), 1, 2)
        self._timeout_spin = QDoubleSpinBox()
        self._timeout_spin.setRange(0.5, 30.0)
        self._timeout_spin.setValue(3.0)
        self._timeout_spin.setSingleStep(0.5)
        cg.addWidget(self._timeout_spin, 1, 3)

        self._chk_detect = QCheckBox("协议检测")
        self._chk_detect.setChecked(True)
        cg.addWidget(self._chk_detect, 2, 0, 1, 2)

        self._chk_test = QCheckBox("测试代理连通性")
        self._chk_test.setChecked(False)
        cg.addWidget(self._chk_test, 2, 2, 1, 2)

        self._chk_two_phase = QCheckBox("两阶段扫描 (先发现存活主机，再深度扫描)")
        self._chk_two_phase.setChecked(True)
        self._chk_two_phase.setToolTip(
            "大型网络: 先快速发现存活主机，再仅深度扫描这些主机。\n"
            "超过 256 个目标时自动启用。"
        )
        cg.addWidget(self._chk_two_phase, 3, 0, 1, 4)

        top.addWidget(config_group, stretch=2)
        main_layout.addLayout(top)

        # proxy status bar
        proxy_bar = QHBoxLayout()
        proxy_bar.setContentsMargins(4, 2, 4, 2)

        self._proxy_indicator = QLabel("*")
        self._proxy_indicator.setFixedWidth(16)
        proxy_bar.addWidget(self._proxy_indicator)

        self._proxy_label = QLabel("系统代理: 检测中...")
        self._proxy_label.setStyleSheet("font-weight: bold;")
        proxy_bar.addWidget(self._proxy_label)

        proxy_bar.addStretch()

        self._btn_proxy_on = QPushButton("应用到系统")
        self._btn_proxy_on.setObjectName("proxyOnBtn")
        self._btn_proxy_on.setToolTip("将选中的代理设为 Windows 系统代理")
        self._btn_proxy_on.setEnabled(False)
        self._btn_proxy_on.clicked.connect(self._apply_selected_proxy)
        proxy_bar.addWidget(self._btn_proxy_on)

        self._btn_proxy_off = QPushButton("关闭系统代理")
        self._btn_proxy_off.setObjectName("proxyOffBtn")
        self._btn_proxy_off.setToolTip("关闭 Windows 系统代理")
        self._btn_proxy_off.clicked.connect(self._disable_system_proxy)
        proxy_bar.addWidget(self._btn_proxy_off)

        self._btn_proxy_refresh = QPushButton("刷新")
        self._btn_proxy_refresh.setFixedWidth(60)
        self._btn_proxy_refresh.setToolTip("刷新代理状态")
        self._btn_proxy_refresh.clicked.connect(self._refresh_proxy_status)
        proxy_bar.addWidget(self._btn_proxy_refresh)

        self._btn_saved = QPushButton("已保存代理")
        self._btn_saved.setObjectName("savedBtn")
        self._btn_saved.setToolTip("查看和使用已保存的代理记录")
        self._btn_saved.clicked.connect(self._show_saved_proxies)
        proxy_bar.addWidget(self._btn_saved)

        main_layout.addLayout(proxy_bar)

        # action buttons
        btn_row = QHBoxLayout()
        self._btn_start = QPushButton("开始扫描")
        self._btn_start.setObjectName("startBtn")
        self._btn_start.setFixedHeight(38)
        self._btn_start.clicked.connect(self._start_scan)
        btn_row.addWidget(self._btn_start)

        self._btn_stop = QPushButton("停止")
        self._btn_stop.setFixedHeight(38)
        self._btn_stop.setEnabled(False)
        self._btn_stop.clicked.connect(self._stop_scan)
        btn_row.addWidget(self._btn_stop)

        btn_row.addStretch()

        self._btn_export_csv = QPushButton("导出 CSV")
        self._btn_export_csv.clicked.connect(lambda: self._export("csv"))
        btn_row.addWidget(self._btn_export_csv)

        self._btn_export_json = QPushButton("导出 JSON")
        self._btn_export_json.clicked.connect(lambda: self._export("json"))
        btn_row.addWidget(self._btn_export_json)

        self._btn_export_log = QPushButton("导出日志")
        self._btn_export_log.clicked.connect(lambda: self._export("log"))
        btn_row.addWidget(self._btn_export_log)

        main_layout.addLayout(btn_row)

        # progress area
        progress_row = QHBoxLayout()
        self._progress = QProgressBar()
        self._progress.setTextVisible(True)
        self._progress.setValue(0)
        progress_row.addWidget(self._progress, stretch=1)

        self._lbl_phase = QLabel("")
        self._lbl_phase.setFixedWidth(180)
        self._lbl_phase.setStyleSheet("color: #89b4fa; font-weight: bold;")
        progress_row.addWidget(self._lbl_phase)

        self._lbl_alive = QLabel("")
        self._lbl_alive.setFixedWidth(140)
        self._lbl_alive.setStyleSheet("color: #a6e3a1;")
        progress_row.addWidget(self._lbl_alive)

        main_layout.addLayout(progress_row)

        # tabs: results + log
        tabs = QTabWidget()

        # results table
        self._table = QTableWidget()
        self._table.setColumnCount(10)
        self._table.setHorizontalHeaderLabels([
            "IP", "端口", "状态", "代理类型", "延迟",
            "需认证", "已验证", "风险", "Banner", "错误"
        ])
        header = self._table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(7, QHeaderView.ResizeToContents)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.setSortingEnabled(True)
        self._table.itemSelectionChanged.connect(self._on_table_selection_changed)
        tabs.addTab(self._table, "扫描结果")

        # log viewer
        self._log_view = QTextEdit()
        self._log_view.setReadOnly(True)
        self._log_view.setFont(QFont("Consolas", 9))
        tabs.addTab(self._log_view, "日志")

        # summary tab
        self._summary_view = QTextEdit()
        self._summary_view.setReadOnly(True)
        self._summary_view.setFont(QFont("Consolas", 10))
        tabs.addTab(self._summary_view, "汇总")

        main_layout.addWidget(tabs, stretch=1)

        # status bar
        self._status = QStatusBar()
        self.setStatusBar(self._status)
        self._status.showMessage("就绪")

    # ── Style ────────────────────────────────────────────────────

    def _apply_style(self):
        self.setStyleSheet("""
            QMainWindow { background: #1e1e2e; }
            QGroupBox {
                color: #cdd6f4; border: 1px solid #45475a;
                border-radius: 6px; margin-top: 8px; padding-top: 14px;
                font-weight: bold;
            }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; }
            QLabel { color: #cdd6f4; }
            QLineEdit, QSpinBox, QDoubleSpinBox, QPlainTextEdit, QTextEdit {
                background: #313244; color: #cdd6f4; border: 1px solid #45475a;
                border-radius: 4px; padding: 4px;
            }
            QComboBox {
                background: #313244; color: #cdd6f4; border: 1px solid #45475a;
                border-radius: 4px; padding: 4px 8px;
            }
            QComboBox::drop-down { border: none; }
            QComboBox QAbstractItemView {
                background: #313244; color: #cdd6f4; selection-background-color: #45475a;
            }
            QTableWidget {
                background: #181825; color: #cdd6f4; gridline-color: #313244;
                alternate-background-color: #1e1e2e;
                selection-background-color: #45475a;
            }
            QHeaderView::section {
                background: #313244; color: #cdd6f4; padding: 4px;
                border: 1px solid #45475a; font-weight: bold;
            }
            QPushButton {
                background: #45475a; color: #cdd6f4; border: none;
                border-radius: 4px; padding: 6px 14px;
            }
            QPushButton:hover { background: #585b70; }
            QPushButton:disabled { background: #313244; color: #6c7086; }
            QPushButton#startBtn { background: #a6e3a1; color: #1e1e2e; font-weight: bold; }
            QPushButton#startBtn:hover { background: #94e2d5; }
            QPushButton#campusBtn { background: #f9e2af; color: #1e1e2e; font-weight: bold; }
            QPushButton#campusBtn:hover { background: #f5c2e7; }
            QPushButton#proxyOnBtn { background: #89b4fa; color: #1e1e2e; font-weight: bold; }
            QPushButton#proxyOnBtn:hover { background: #74c7ec; }
            QPushButton#proxyOffBtn { background: #f38ba8; color: #1e1e2e; font-weight: bold; }
            QPushButton#proxyOffBtn:hover { background: #eba0ac; }
            QPushButton#savedBtn { background: #f9e2af; color: #1e1e2e; font-weight: bold; }
            QPushButton#savedBtn:hover { background: #f5c2e7; }
            QProgressBar {
                background: #313244; border: 1px solid #45475a;
                border-radius: 4px; text-align: center; color: #cdd6f4;
            }
            QProgressBar::chunk { background: #89b4fa; border-radius: 3px; }
            QTabWidget::pane { border: 1px solid #45475a; }
            QTabBar::tab {
                background: #313244; color: #cdd6f4; padding: 6px 16px;
                border: 1px solid #45475a; border-bottom: none;
            }
            QTabBar::tab:selected { background: #45475a; }
            QCheckBox { color: #cdd6f4; }
            QStatusBar { color: #a6adc8; background: #181825; }
        """)

    # ── Actions ──────────────────────────────────────────────────

    def _parse_ports(self) -> list[int]:
        text = self._ports_input.text()
        ports = []
        for part in text.split(","):
            part = part.strip()
            if part.isdigit():
                port = int(part)
                if 1 <= port <= 65535:
                    ports.append(port)
        return ports or [7890]

    def _parse_targets(self) -> list[str]:
        text = self._target_input.toPlainText().strip()
        if not text:
            return []
        return parse_ip_range(text)

    def _update_target_count(self):
        text = self._target_input.toPlainText().strip()
        if not text:
            self._lbl_target_count.setText("0 个目标")
            return
        count = ip_range_count(text)
        self._lbl_target_count.setText(f"{count} 个目标")

    def _on_mode_changed(self, index: int):
        """Update target input when scan mode changes."""
        if index == 0:  # local /24
            info = get_local_network_info()
            self._target_input.setPlainText(info["subnet_24"])
        elif index == 1:  # campus /16
            info = get_local_network_info()
            self._target_input.setPlainText(info["campus_hint"])

    def _import_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "导入 IP 列表", "",
            "文本文件 (*.txt *.csv *.lst);;所有文件 (*)"
        )
        if path:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                self._target_input.setPlainText(content)
                self._log(f"已导入 IP 列表: {path}")
            except Exception as e:
                QMessageBox.warning(self, "导入错误", str(e))

    def _use_local_subnet(self):
        subnet = get_local_subnet()
        self._target_input.setPlainText(subnet)
        self._log(f"使用本机子网: {subnet}")

    def _campus_scan(self):
        """Quick campus scan — use the /16 mode and start immediately."""
        self._scan_mode.setCurrentIndex(1)  # campus /16
        self._chk_two_phase.setChecked(True)
        self._start_scan()

    def _start_scan(self):
        targets = self._parse_targets()
        if not targets:
            QMessageBox.warning(self, "无目标", "请至少输入一个 IP 地址或子网。")
            return

        ports = self._parse_ports()
        if not ports:
            QMessageBox.warning(self, "无端口", "请至少输入一个端口号。")
            return

        # auto-enable two-phase for large networks
        two_phase = self._chk_two_phase.isChecked() or len(targets) > 256  # matches ScanConfig.two_phase_threshold

        # configure engine
        config = ScanConfig(
            ports=ports,
            timeout=self._timeout_spin.value(),
            max_threads=self._threads_spin.value(),
            detect_protocol=self._chk_detect.isChecked(),
            test_connectivity=self._chk_test.isChecked(),
            two_phase=two_phase,
        )
        self._engine = ScannerEngine(config)
        self._results.clear()
        self._found_proxies.clear()
        self._alive_count = 0
        self._current_phase = ""
        self._table.setRowCount(0)
        self._progress.setValue(0)
        self._lbl_alive.setText("")

        if two_phase:
            self._log(f"两阶段扫描: {len(targets)} 台主机, 发现端口={config.discovery_ports}")
            # discovery phase total = hosts * discovery_ports
            disc_total = len(targets) * len(config.discovery_ports)
            self._progress.setMaximum(disc_total)
        else:
            total_tasks = len(targets) * len(ports)
            self._progress.setMaximum(total_tasks)
            self._log(f"直接扫描: {len(targets)} 个目标 x {len(ports)} 个端口 = {total_tasks} 个任务")

        self._log(f"配置: 线程={config.max_threads}, 超时={config.timeout}秒")

        # start worker
        self._worker = ScanWorker(self._engine, targets, ports)
        self._worker.result_ready.connect(self._on_result)
        self._worker.progress.connect(self._on_progress)
        self._worker.proxy_found.connect(self._on_proxy_found)
        self._worker.finished_signal.connect(self._on_scan_finished)
        self._worker.log_message.connect(self._log)
        self._worker.phase_change.connect(self._on_phase_change)
        self._worker.alive_found.connect(self._on_alive_found)

        self._btn_start.setEnabled(False)
        self._btn_campus_scan.setEnabled(False)
        self._btn_stop.setEnabled(True)
        self._status.showMessage("扫描中...")
        self._reporter.start_timer()
        self._scan_start = datetime.now().timestamp()

        self._worker.start()

    def _stop_scan(self):
        if self._worker and self._worker.isRunning():
            self._engine.stop()
            self._log("用户停止扫描。")
            self._status.showMessage("已停止")

    def _on_phase_change(self, phase: str):
        self._current_phase = phase
        if phase == "discovery":
            self._lbl_phase.setText("阶段: 主机发现")
            self._log("--- 阶段一: 主机发现 ---")
        elif phase == "scan":
            self._lbl_phase.setText("阶段: 深度扫描")
            # reset progress for scan phase
            scan_total = self._alive_count * len(self._parse_ports())
            self._progress.setMaximum(max(scan_total, 1))
            self._progress.setValue(0)
            self._log(f"--- 阶段二: 深度扫描 ({self._alive_count} 台存活主机) ---")

    def _on_alive_found(self, ip: str):
        self._alive_count += 1
        self._lbl_alive.setText(f"存活: {self._alive_count}")

    def _on_result(self, result: ScanResult):
        self._results.append(result)
        self._add_table_row(result)

    def _on_progress(self, done: int, total: int):
        self._progress.setValue(done)
        if self._current_phase == "discovery":
            self._progress.setFormat(f"发现中: {done}/{total}")
        else:
            self._progress.setFormat(f"{done}/{total} ({100*done//max(total,1)}%)")

    def _on_proxy_found(self, result: ScanResult):
        self._log(f"*** 发现代理: {result.ip}:{result.port} ({result.proxy_type.display_name()}) ***")

        # save to memory immediately
        self._memory.add_or_update(
            result.ip, result.port,
            proxy_type=result.proxy_type.display_name(),
            latency_ms=result.latency_ms,
            requires_auth=result.requires_auth,
        )
        self._found_proxies.append(result)

        # run connectivity test in background thread to avoid blocking UI
        if not result.connectivity_ok and result.proxy_type not in (ProxyType.NONE, ProxyType.UNKNOWN):
            worker = ProxyTestWorker(result, self._timeout_spin.value())
            worker.finished.connect(self._on_connectivity_test_done)
            self._test_workers.append(worker)
            worker.start()
        else:
            self._log(f"    已保存到记忆")

    def _on_connectivity_test_done(self, result: ScanResult, ok: bool):
        """Called when background connectivity test finishes — just update, no popup."""
        result.connectivity_ok = ok
        if ok:
            self._log(f"    代理已验证: 流量转发成功 (已保存到记忆)")
        else:
            self._log(f"    代理未通过验证 (已保存到记忆)")
        self._test_workers = [w for w in self._test_workers if w.isRunning()]

    def _apply_selected_proxy(self):
        row = self._table.currentRow()
        if row < 0:
            return
        ip_item = self._table.item(row, 0)
        port_item = self._table.item(row, 1)
        if not ip_item or not port_item:
            return
        addr = f"{ip_item.text()}:{port_item.text()}"
        ok = set_proxy(addr)
        if ok:
            self._log(f"系统代理已设置为 {addr}")
            self._status.showMessage(f"系统代理 -> {addr}")
        else:
            self._log(f"设置系统代理失败: {addr}")
            QMessageBox.warning(self, "错误", "设置系统代理失败，请尝试以管理员身份运行。")
        self._refresh_proxy_status()

    def _disable_system_proxy(self):
        ok = disable_proxy()
        if ok:
            self._log("系统代理已关闭")
            self._status.showMessage("系统代理已关闭")
        else:
            self._log("关闭系统代理失败")
            QMessageBox.warning(self, "错误", "关闭系统代理失败，请尝试以管理员身份运行。")
        self._refresh_proxy_status()

    def _refresh_proxy_status(self):
        status = get_proxy_status()
        if status.enabled:
            self._proxy_indicator.setStyleSheet("color: #a6e3a1; font-size: 16px;")
            self._proxy_label.setText(f"系统代理: 已开启 -> {status.server}")
            self._btn_proxy_off.setEnabled(True)
        else:
            self._proxy_indicator.setStyleSheet("color: #6c7086; font-size: 16px;")
            self._proxy_label.setText("系统代理: 已关闭")
            self._btn_proxy_off.setEnabled(False)

    def _show_saved_proxies(self):
        """Open the saved proxies dialog."""
        if not self._memory.records:
            QMessageBox.information(self, "已保存代理", "暂无已保存的代理记录。\n扫描发现的代理会自动保存。")
            return
        dlg = SavedProxiesDialog(self._memory, timeout=self._timeout_spin.value(), parent=self)
        dlg.exec()
        self._refresh_proxy_status()

    def _on_scan_finished(self):
        self._btn_start.setEnabled(True)
        self._btn_campus_scan.setEnabled(True)
        self._btn_stop.setEnabled(False)
        self._lbl_phase.setText("")
        duration = datetime.now().timestamp() - self._scan_start
        self._status.showMessage(f"扫描完成 -- {len(self._results)} 条结果, {self._alive_count} 台存活主机, 耗时 {duration:.1f} 秒")
        self._log(f"扫描完成。{len(self._results)} 条结果, {self._alive_count} 台存活主机, 耗时 {duration:.1f} 秒")

        summary = self._reporter.summarize(self._results, duration)
        self._show_summary(summary)

        # show proxy summary dialog if any proxies were found
        if self._found_proxies:
            self._log(f"发现 {len(self._found_proxies)} 个代理，弹出汇总选择窗口")
            QTimer.singleShot(300, self._show_scan_summary_dialog)

    def _show_scan_summary_dialog(self):
        """Show summary dialog with all found proxies after scan completes."""
        # wait for any pending connectivity tests to finish
        for w in self._test_workers:
            w.wait(5000)
        dlg = ScanSummaryDialog(self._found_proxies, self)
        dlg.exec()
        if dlg.chosen:
            r = dlg.chosen
            self._memory.mark_used(r.ip, r.port)
            self._refresh_proxy_status()

    def _show_summary(self, summary):
        lines = [
            "=" * 50,
            "  扫描汇总",
            "=" * 50,
            f"  扫描目标数:    {summary.total_targets}",
            f"  存活主机数:    {self._alive_count}",
            f"  扫描端口数:    {summary.total_ports_scanned}",
            f"  开放端口数:    {summary.open_ports}",
            f"  发现代理数:    {summary.proxies_found}",
            f"  耗时:          {summary.scan_duration_s:.1f} 秒",
            "",
            "  按代理类型:",
        ]
        for ptype, count in summary.by_type.items():
            lines.append(f"    {ptype}: {count}")

        lines.append("")
        lines.append("  按风险等级:")
        risk_icons = {"CRITICAL": "[!]", "HIGH": "[H]", "MEDIUM": "[M]", "LOW": "[L]", "INFO": "[.]"}
        for risk, count in summary.by_risk.items():
            icon = risk_icons.get(risk, "")
            lines.append(f"    {icon} {risk}: {count}")

        lines.append("=" * 50)
        self._summary_view.setPlainText("\n".join(lines))

    # ── Table ────────────────────────────────────────────────────

    def _add_table_row(self, r: ScanResult):
        row = self._table.rowCount()
        self._table.insertRow(row)

        risk = ReportGenerator.assess_risk(r)
        risk_color = QColor(RiskLevel[risk.name].color_hex)

        items = [
            r.ip,
            str(r.port),
            "开放" if r.is_open else "关闭",
            r.proxy_type.display_name(),
            f"{r.latency_ms:.1f}" if r.latency_ms else "",
            "是" if r.requires_auth else "",
            "是" if r.connectivity_ok else "",
            risk.label,
            r.banner[:50],
            r.error[:50],
        ]

        for col, text in enumerate(items):
            item = QTableWidgetItem(text)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)

            if col == 7:
                item.setForeground(risk_color)
                item.setFont(QFont("", -1, QFont.Bold))

            if col == 2:
                if r.is_open:
                    item.setForeground(QColor("#a6e3a1"))
                else:
                    item.setForeground(QColor("#6c7086"))

            self._table.setItem(row, col, item)

    def _on_table_selection_changed(self):
        row = self._table.currentRow()
        if row < 0:
            self._btn_proxy_on.setEnabled(False)
            return
        type_item = self._table.item(row, 3)
        if type_item and type_item.text() not in ("N/A", ""):
            self._btn_proxy_on.setEnabled(True)
        else:
            self._btn_proxy_on.setEnabled(False)

    # ── Export ───────────────────────────────────────────────────

    def _export(self, fmt: str):
        if not self._results:
            QMessageBox.information(self, "无数据", "没有扫描结果可导出。")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"netlens_scan_{timestamp}.{fmt}"

        path, _ = QFileDialog.getSaveFileName(
            self, f"导出 {fmt.upper()}", default_name,
            f"{fmt.upper()} 文件 (*.{fmt});;所有文件 (*)"
        )
        if not path:
            return

        try:
            if fmt == "csv":
                ReportGenerator.export_csv(self._results, path)
            elif fmt == "json":
                ReportGenerator.export_json(self._results, path)
            elif fmt == "log":
                ReportGenerator.export_log(self._results, path)

            self._log(f"已导出到: {path}")
            self._status.showMessage(f"已导出: {path}")
        except Exception as e:
            QMessageBox.critical(self, "导出错误", str(e))

    # ── Logging ──────────────────────────────────────────────────

    def _log(self, msg: str):
        self._logger.info(msg)
        timestamp = datetime.now().strftime("%H:%M:%S")
        self._log_view.append(f"[{timestamp}] {msg}")
        cursor = self._log_view.textCursor()
        cursor.movePosition(QTextCursor.End)
        self._log_view.setTextCursor(cursor)

    # ── Close ────────────────────────────────────────────────────

    def closeEvent(self, event):
        if self._worker and self._worker.isRunning():
            self._engine.stop()
            self._worker.wait(8000)
            # don't use terminate() — it's unsafe; let thread finish naturally
        # stop any background test workers
        for w in self._test_workers:
            w.wait(1000)
        event.accept()
