"""NetLens — LAN 代理服务暴露检测工具。

使用方式：
    python app.py
"""
from __future__ import annotations

import sys
import os

# ensure src is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    from PySide6.QtWidgets import QApplication
    from PySide6.QtGui import QIcon
    from src.ui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("NetLens")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("NetLens")

    # 设置应用图标（同时影响任务栏和窗口标题栏）
    # PyInstaller 打包后 sys._MEIPASS 指向临时解压目录
    if hasattr(sys, "_MEIPASS"):
        icon_path = os.path.join(sys._MEIPASS, "media_1773652121.ico")
    else:
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "media_1773652121.ico")
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
