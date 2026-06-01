"""Windows system proxy switcher — enable/disable via registry + wininet notification."""
from __future__ import annotations

import logging
import platform
import re
from dataclasses import dataclass

_IS_WINDOWS = platform.system() == "Windows"

if _IS_WINDOWS:
    import ctypes
    import winreg
else:
    # stubs for non-Windows platforms — all operations return False/empty
    class _StubWinreg:
        HKEY_CURRENT_USER = 0
        KEY_READ = 0
        KEY_WRITE = 0
        REG_DWORD = 0
        REG_SZ = 0
        def OpenKey(self, *a, **kw): raise OSError("Windows only")
        def QueryValueEx(self, *a, **kw): raise OSError("Windows only")
        def SetValueEx(self, *a, **kw): raise OSError("Windows only")
    winreg = _StubWinreg()

logger = logging.getLogger(__name__)

# registry path for IE/system proxy settings
_REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

# wininet constants for InternetSetOption
_INTERNET_OPTION_SETTINGS_CHANGED = 39
_INTERNET_OPTION_REFRESH = 37


@dataclass
class ProxyStatus:
    enabled: bool = False
    server: str = ""
    override: str = ""


def _notify_system() -> None:
    """Broadcast proxy change so other apps pick it up immediately."""
    if not _IS_WINDOWS:
        return
    try:
        ctypes.windll.wininet.InternetSetOptionW(0, _INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        ctypes.windll.wininet.InternetSetOptionW(0, _INTERNET_OPTION_REFRESH, 0, 0)
    except Exception as e:
        logger.debug(f"Failed to notify system of proxy change: {e}")


def get_proxy_status() -> ProxyStatus:
    """Read current system proxy settings from registry."""
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


_ADDR_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}:\d{1,5}$")


def set_proxy(address: str, bypass: str = "localhost;127.0.0.1;<local>") -> bool:
    """Enable system proxy pointing to `address` (ip:port).

    Args:
        address: proxy address, e.g. "192.168.1.5:7890"
        bypass:  semicolon-separated bypass list

    Returns:
        True on success.
    """
    if not _ADDR_RE.match(address):
        logger.warning(f"Invalid proxy address format: {address!r}")
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
    """Disable system proxy.

    Returns:
        True on success.
    """
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_PATH, 0, winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        _notify_system()
        return True
    except OSError:
        return False


def toggle_proxy(address: str | None = None) -> ProxyStatus:
    """Toggle proxy on/off. If turning on, use `address`; if None, reuse last known server.

    Returns:
        Updated ProxyStatus.
    """
    current = get_proxy_status()
    if current.enabled:
        disable_proxy()
    else:
        target = address or current.server or "127.0.0.1:7890"
        set_proxy(target)
    return get_proxy_status()
