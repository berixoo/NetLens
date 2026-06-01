#!/usr/bin/env python3
"""NetLens — LAN Proxy Service Exposure Detection Tool.

Usage:
    python app.py              # Launch GUI
    python app.py --cli ...    # Run headless CLI scan (future)
"""
from __future__ import annotations

import sys
import os

# ensure src is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    from PySide6.QtWidgets import QApplication
    from src.ui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("NetLens")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("NetLens")

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
