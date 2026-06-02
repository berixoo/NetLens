"""NetLens 打包脚本 — 使用 PyInstaller 生成 Windows 可执行文件。"""
import PyInstaller.__main__
import os

# 获取项目根目录
ROOT = os.path.dirname(os.path.abspath(__file__))

PyInstaller.__main__.run([
    os.path.join(ROOT, "app.py"),
    "--name=NetLens",
    "--onefile",
    "--windowed",
    "--noconfirm",
    "--clean",
    f"--workpath={os.path.join(ROOT, 'build')}",
    f"--distpath={os.path.join(ROOT, 'dist')}",
    f"--specpath={ROOT}",
])
