"""Windows 系统代理切换模块。

通过修改 Windows 注册表中的代理设置来控制系统代理的开启/关闭，
并调用 wininet API 广播代理变更，使其他应用程序（如浏览器）立即生效。

注册表路径：HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings
  - ProxyEnable (DWORD): 1=开启代理, 0=关闭代理
  - ProxyServer (字符串): 代理地址，格式 "ip:port"
  - ProxyOverride (字符串): 代理绕过列表，分号分隔

跨平台兼容：非 Windows 平台使用 stub 实现，所有操作返回 False/空值。
"""
from __future__ import annotations

import logging
import platform
import re
from dataclasses import dataclass

# 检测当前是否为 Windows 平台
_IS_WINDOWS = platform.system() == "Windows"

if _IS_WINDOWS:
    import ctypes
    import winreg
else:
    # 非 Windows 平台的 stub 实现，所有操作返回失败或空值
    # 这样代码在 Linux/macOS 上也能正常导入，不会因缺少 winreg 而崩溃
    class _StubWinreg:
        HKEY_CURRENT_USER = 0
        KEY_READ = 0
        KEY_WRITE = 0
        REG_DWORD = 0
        REG_SZ = 0
        def OpenKey(self, *a, **kw): raise OSError("仅支持 Windows 平台")
        def QueryValueEx(self, *a, **kw): raise OSError("仅支持 Windows 平台")
        def SetValueEx(self, *a, **kw): raise OSError("仅支持 Windows 平台")
    winreg = _StubWinreg()

logger = logging.getLogger(__name__)

# 注册表路径：IE/系统代理设置
_REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

# wininet API 常量，用于通知系统代理设置已变更
_INTERNET_OPTION_SETTINGS_CHANGED = 39  # 通知系统设置已更改
_INTERNET_OPTION_REFRESH = 37           # 强制刷新设置


@dataclass
class ProxyStatus:
    """系统代理状态信息。"""
    enabled: bool = False   # 代理是否开启
    server: str = ""        # 代理服务器地址（如 "192.168.1.1:7890"）
    override: str = ""      # 代理绕过列表


def _notify_system() -> None:
    """广播代理设置变更，使其他应用程序立即生效。

    调用 wininet 的 InternetSetOptionW API 通知系统代理设置已更改，
    浏览器等应用会在下次请求时读取新的代理设置。
    """
    if not _IS_WINDOWS:
        return
    try:
        ctypes.windll.wininet.InternetSetOptionW(0, _INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        ctypes.windll.wininet.InternetSetOptionW(0, _INTERNET_OPTION_REFRESH, 0, 0)
    except Exception as e:
        logger.debug(f"广播代理变更失败: {e}")


def get_proxy_status() -> ProxyStatus:
    """读取当前系统代理设置。

    从注册表中读取 ProxyEnable、ProxyServer、ProxyOverride 的值。

    Returns:
        包含代理状态信息的 ProxyStatus 对象
    """
    status = ProxyStatus()
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_PATH, 0, winreg.KEY_READ) as key:
            status.enabled = bool(winreg.QueryValueEx(key, "ProxyEnable")[0])
            status.server = winreg.QueryValueEx(key, "ProxyServer")[0] if status.enabled else ""
            try:
                status.override = winreg.QueryValueEx(key, "ProxyOverride")[0]
            except FileNotFoundError:
                status.override = ""
    except FileNotFoundError:
        pass
    return status


# 代理地址格式校验正则：IPv4:端口，如 "192.168.1.1:7890"
_ADDR_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}:\d{1,5}$")


def set_proxy(address: str, bypass: str = "localhost;127.0.0.1;<local>") -> bool:
    """开启系统代理，指向指定的代理地址。

    将 ProxyEnable 设为 1，ProxyServer 设为指定地址，
    ProxyOverride 设为绕过列表（默认绕过本地地址）。

    Args:
        address: 代理服务器地址，格式 "ip:port"，如 "192.168.1.5:7890"
        bypass: 代理绕过列表，分号分隔的域名/IP 模式

    Returns:
        True 表示设置成功，False 表示失败（格式错误或权限不足）
    """
    # 校验地址格式，防止写入非法字符串到注册表
    if not _ADDR_RE.match(address):
        logger.warning(f"无效的代理地址格式: {address!r}")
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_PATH, 0, winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, address)
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, bypass)
        _notify_system()
        return True
    except OSError:
        return False


def disable_proxy() -> bool:
    """关闭系统代理。

    将 ProxyEnable 设为 0，系统将不再使用代理服务器。

    Returns:
        True 表示关闭成功，False 表示失败（权限不足）
    """
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_PATH, 0, winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        _notify_system()
        return True
    except OSError:
        return False


def toggle_proxy(address: str | None = None) -> ProxyStatus:
    """切换系统代理的开关状态。

    如果当前代理已开启则关闭，如果已关闭则开启。
    开启时使用指定地址，未指定则复用上次的代理地址。

    Args:
        address: 要开启的代理地址，为 None 时复用上次地址

    Returns:
        切换后的代理状态
    """
    current = get_proxy_status()
    if current.enabled:
        disable_proxy()
    else:
        target = address or current.server or "127.0.0.1:7890"
        set_proxy(target)
    return get_proxy_status()
