"""网络工具模块：IP 地址解析、CIDR 展开、子网检测、校园网发现。

支持的 IP 输入格式：
  - 单个 IP：        192.168.1.1
  - CIDR 子网：      192.168.1.0/24
  - 完整范围：       192.168.1.1-192.168.1.100
  - 短横线范围：     192.168.1.1-100（同一 /24 内）
  - 逗号分隔列表：   192.168.1.1, 192.168.1.2, 10.0.0.0/24
  - 混合格式：       以上任意组合，以逗号、换行或分号分隔
"""
from __future__ import annotations

import ipaddress
import re
import socket
from typing import Generator


def parse_ip_range(input_str: str) -> list[str]:
    """将各种格式的 IP 输入解析为扁平的 IP 地址列表。

    Args:
        input_str: 包含 IP 地址的输入字符串，支持多种格式（见模块文档）

    Returns:
        解析后的 IPv4 地址字符串列表

    注意：
        - 完整 IP 范围（start-end）最多展开 65536 个地址，防止内存溢出
        - 短横线短格式会验证左侧是否为合法 IPv4 地址
        - 无效的地址会被静默跳过，不会引发异常
    """
    results: list[str] = []
    # 按逗号、分号、换行符分割输入
    tokens = re.split(r"[,;\n\r]+", input_str.strip())

    for token in tokens:
        token = token.strip()
        if not token:
            continue

        # CIDR 格式：192.168.1.0/24
        if "/" in token:
            results.extend(expand_cidr(token))
            continue

        # 短横线范围格式
        if "-" in token:
            parts = token.split("-", 1)
            left = parts[0].strip()
            right = parts[1].strip()

            # 短横线短格式：192.168.1.1-100（同一子网内的连续地址）
            if right.isdigit():
                # 验证左侧是否为合法 IPv4 地址
                try:
                    ipaddress.IPv4Address(left)
                except (ValueError, ipaddress.AddressValueError):
                    continue
                # 提取前三段作为子网前缀，最后一段作为起始值
                base = ".".join(left.split(".")[:3])
                start = int(left.split(".")[-1])
                end = int(right)
                for i in range(start, min(end + 1, 256)):
                    results.append(f"{base}.{i}")
                continue

            # 完整 IP 范围格式：192.168.1.1-192.168.1.100
            try:
                start_ip = int(ipaddress.IPv4Address(left))
                end_ip = int(ipaddress.IPv4Address(right))
                # 限制最多展开 65536 个地址，防止用户输入超大范围导致内存溢出
                count = min(end_ip - start_ip + 1, 65536)
                for ip_int in range(start_ip, start_ip + count):
                    results.append(str(ipaddress.IPv4Address(ip_int)))
            except (ValueError, ipaddress.AddressValueError):
                pass
            continue

        # 单个 IP 地址：192.168.1.1
        try:
            ipaddress.IPv4Address(token)
            results.append(token)
        except (ValueError, ipaddress.AddressValueError):
            pass

    return results


def expand_cidr(cidr: str, limit: int = 65536) -> list[str]:
    """将 CIDR 子网展开为 IP 地址列表。

    Args:
        cidr: CIDR 格式的子网地址，如 "10.16.0.0/16"
        limit: 最多展开的地址数量，默认 65536

    Returns:
        子网内的所有主机 IP 地址列表（排除网络地址和广播地址）
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        hosts = network.hosts()
        return [str(ip) for _, ip in zip(range(limit), hosts)]
    except (ValueError, ipaddress.AddressValueError):
        return []


def cidr_host_count(cidr: str) -> int:
    """计算 CIDR 子网中的主机数量（不实际展开，节省内存）。

    Args:
        cidr: CIDR 格式的子网地址

    Returns:
        主机数量。/31 和 /32 子网中所有地址均视为主机地址。
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        if network.prefixlen >= 31:
            # /31（点对点链路）和 /32（主机路由）中没有网络/广播地址
            return network.num_addresses
        # 普通子网排除网络地址和广播地址
        return max(0, network.num_addresses - 2)
    except (ValueError, ipaddress.AddressValueError):
        return 0


def cidr_generator(cidr: str) -> Generator[str, None, None]:
    """惰性生成器：逐个产出 CIDR 子网中的 IP 地址。

    适用于超大子网（如 /8），避免一次性将所有地址加载到内存。

    Args:
        cidr: CIDR 格式的子网地址

    Yields:
        子网内的每个主机 IP 地址字符串
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        for ip in network.hosts():
            yield str(ip)
    except (ValueError, ipaddress.AddressValueError):
        return


def get_local_subnet() -> str:
    """检测本机所在的 /24 子网。

    通过 UDP socket 连接公共 DNS（8.8.8.8）来确定本机的出口 IP，
    然后取前三段构造 /24 子网地址。

    Returns:
        本机 /24 子网的 CIDR 地址，如 "192.168.1.0/24"
        检测失败时返回 "192.168.1.0/24" 作为默认值
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        parts = local_ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except OSError:
        return "192.168.1.0/24"


def get_local_ip() -> str:
    """获取本机的 IPv4 地址。

    Returns:
        本机 IP 地址字符串，检测失败返回 "127.0.0.1"
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def get_local_network_info() -> dict:
    """获取本机的网络信息，包括 /24 子网和推荐的校园网扫描范围。

    根据本机 IP 的首字节判断网络类型：
    - 10.x.x.x    → A 类私有地址，校园网段建议 10.x.0.0/16
    - 172.16-31.x  → B 类私有地址，校园网段建议 172.x.0.0/16
    - 192.168.x.x  → C 类私有地址，校园网段建议 192.168.0.0/16
    - 其他         → 仅返回 /24 子网

    Returns:
        包含以下键的字典：
        - local_ip: 本机 IP 地址
        - subnet_24: 本机 /24 子网
        - campus_range: 推荐的校园网起始 /24 子网
        - campus_hint: 推荐的校园网 /16 扫描范围
    """
    ip = get_local_ip()
    parts = ip.split(".")
    subnet_24 = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    first = int(parts[0])

    if first == 10:
        # A 类私有地址（10.0.0.0/8），校园网常用
        campus = f"10.{parts[1]}.{parts[2]}.0/24"
        campus_hint = f"10.{parts[1]}.0.0/16"
    elif first == 172 and 16 <= int(parts[1]) <= 31:
        # B 类私有地址（172.16.0.0/12），校园网常用
        campus = f"172.{parts[1]}.{parts[2]}.0/24"
        campus_hint = f"172.{parts[1]}.0.0/16"
    elif first == 192:
        # C 类私有地址（192.168.0.0/16），家庭/小型网络常用
        campus = f"192.168.{parts[2]}.0/24"
        campus_hint = f"192.168.0.0/16"
    else:
        # 公网地址或其他私有地址，仅返回 /24 子网
        campus = subnet_24
        campus_hint = subnet_24

    return {
        "local_ip": ip,
        "subnet_24": subnet_24,
        "campus_range": campus,
        "campus_hint": campus_hint,
    }


def get_campus_scan_targets(mode: str = "local_sub") -> list[str]:
    """根据扫描模式生成校园网扫描目标列表。

    Args:
        mode: 扫描模式
            - "local_sub": 仅本机 /24 子网（约 254 台主机）
            - "local_seg": 本机所在的 /16 网段（最多 65536 台主机）
            - "full_campus": 同 local_seg（完整 /8 太大不实用）

    Returns:
        目标 IP 地址列表
    """
    info = get_local_network_info()

    if mode == "local_sub":
        return expand_cidr(info["subnet_24"])
    elif mode == "local_seg":
        return expand_cidr(info["campus_hint"], limit=65536)
    elif mode == "full_campus":
        # 完整 /8 有 1600 万台主机，不切实际，使用 /16 代替
        return expand_cidr(info["campus_hint"], limit=65536)
    else:
        return expand_cidr(info["subnet_24"])


def ip_range_count(input_str: str) -> int:
    """计算输入字符串展开后的 IP 地址数量（不实际展开，节省内存）。

    对于 CIDR 格式使用 cidr_host_count() 直接计算，
    避免对大子网（如 /16）进行完整的内存展开。

    Args:
        input_str: 包含 IP 地址的输入字符串

    Returns:
        展开后的 IP 地址总数
    """
    tokens = re.split(r"[,;\n\r]+", input_str.strip())
    total = 0
    for token in tokens:
        token = token.strip()
        if not token:
            continue
        if "/" in token:
            total += cidr_host_count(token)
        elif "-" in token:
            parts = token.split("-", 1)
            right = parts[1].strip()
            if right.isdigit():
                left = parts[0].strip()
                try:
                    ipaddress.IPv4Address(left)
                except (ValueError, ipaddress.AddressValueError):
                    continue
                start = int(left.split(".")[-1])
                end = int(right)
                total += max(0, end - start + 1)
            else:
                try:
                    start_ip = int(ipaddress.IPv4Address(parts[0].strip()))
                    end_ip = int(ipaddress.IPv4Address(right))
                    total += max(0, end_ip - start_ip + 1)
                except (ValueError, ipaddress.AddressValueError):
                    pass
        else:
            try:
                ipaddress.IPv4Address(token)
                total += 1
            except (ValueError, ipaddress.AddressValueError):
                pass
    return total
