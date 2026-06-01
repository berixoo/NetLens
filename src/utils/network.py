"""Network utilities: IP parsing, CIDR expansion, local subnet detection, campus discovery."""
from __future__ import annotations

import ipaddress
import re
import socket
from typing import Generator


def parse_ip_range(input_str: str) -> list[str]:
    """Parse various IP input formats into a flat list of IP strings.

    Supported formats:
        - Single IP:  192.168.1.1
        - CIDR:       192.168.1.0/24
        - Dash range: 192.168.1.1-192.168.1.100
        - Dash short: 192.168.1.1-100
        - Comma list: 192.168.1.1, 192.168.1.2, 10.0.0.0/24
        - Mixed:      all of the above separated by commas or newlines
    """
    results: list[str] = []
    tokens = re.split(r"[,;\n\r]+", input_str.strip())

    for token in tokens:
        token = token.strip()
        if not token:
            continue

        # CIDR
        if "/" in token:
            results.extend(expand_cidr(token))
            continue

        # dash range: IP-IP or IP-last_octet
        if "-" in token:
            parts = token.split("-", 1)
            left = parts[0].strip()
            right = parts[1].strip()

            # short form: 192.168.1.1-100
            if right.isdigit():
                base = ".".join(left.split(".")[:3])
                start = int(left.split(".")[-1])
                end = int(right)
                for i in range(start, min(end + 1, 256)):
                    results.append(f"{base}.{i}")
                continue

            # full form: 192.168.1.1-192.168.1.100
            try:
                start_ip = int(ipaddress.IPv4Address(left))
                end_ip = int(ipaddress.IPv4Address(right))
                for ip_int in range(start_ip, end_ip + 1):
                    results.append(str(ipaddress.IPv4Address(ip_int)))
            except (ValueError, ipaddress.AddressValueError):
                pass
            continue

        # single IP
        try:
            ipaddress.IPv4Address(token)
            results.append(token)
        except (ValueError, ipaddress.AddressValueError):
            pass

    return results


def expand_cidr(cidr: str, limit: int = 65536) -> list[str]:
    """Expand a CIDR notation into a list of host IPs."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        hosts = network.hosts()
        return [str(ip) for _, ip in zip(range(limit), hosts)]
    except (ValueError, ipaddress.AddressValueError):
        return []


def cidr_host_count(cidr: str) -> int:
    """Return the number of hosts in a CIDR range without expanding."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        if network.prefixlen >= 31:
            return network.num_addresses  # /31 and /32: all addresses are hosts
        return max(0, network.num_addresses - 2)  # exclude network and broadcast
    except (ValueError, ipaddress.AddressValueError):
        return 0


def cidr_generator(cidr: str) -> Generator[str, None, None]:
    """Lazily yield IPs from a CIDR range — memory friendly for large subnets."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        for ip in network.hosts():
            yield str(ip)
    except (ValueError, ipaddress.AddressValueError):
        return


def get_local_subnet() -> str:
    """Detect the local machine's /24 subnet."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        parts = local_ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except OSError:
        return "192.168.1.0/24"


def get_local_ip() -> str:
    """Get the local machine's IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def get_local_network_info() -> dict:
    """Return local IP, /24 subnet, and the broader campus-worthy range."""
    ip = get_local_ip()
    parts = ip.split(".")
    subnet_24 = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    # guess the campus range based on first octet
    first = int(parts[0])
    if first == 10:
        campus = f"10.{parts[1]}.{parts[2]}.0/24"  # 10.x.x — use /24 as starting point
        campus_hint = f"10.{parts[1]}.0.0/16"
    elif first == 172 and 16 <= int(parts[1]) <= 31:
        campus = f"172.{parts[1]}.{parts[2]}.0/24"
        campus_hint = f"172.{parts[1]}.0.0/16"
    elif first == 192:
        campus = f"192.168.{parts[2]}.0/24"
        campus_hint = f"192.168.0.0/16"
    else:
        campus = subnet_24
        campus_hint = subnet_24

    return {
        "local_ip": ip,
        "subnet_24": subnet_24,
        "campus_range": campus,
        "campus_hint": campus_hint,
    }


def get_campus_scan_targets(mode: str = "local_sub") -> list[str]:
    """Generate IP list for campus scanning.

    Modes:
        - local_sub:  only the local /24 subnet
        - local_seg:  the local /16 segment (e.g. 10.x.0.0/16)
        - full_campus: all common private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    """
    info = get_local_network_info()

    if mode == "local_sub":
        return expand_cidr(info["subnet_24"])
    elif mode == "local_seg":
        return expand_cidr(info["campus_hint"], limit=65536)
    elif mode == "full_campus":
        # return just the local /16 — full 10/8 is 16M hosts, not practical
        return expand_cidr(info["campus_hint"], limit=65536)
    else:
        return expand_cidr(info["subnet_24"])


def ip_range_count(input_str: str) -> int:
    """Count how many IPs an input string would expand to."""
    # for large CIDRs, use the count method instead of expanding
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
