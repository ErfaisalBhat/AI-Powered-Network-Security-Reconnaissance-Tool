"""
tools/scanner.py — Port scanning & banner grabbing
"""

import socket
import concurrent.futures
from typing import List, Optional

# Common ports to prioritize in quick scans
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389,
    5900, 8080, 8443, 8888
]


def _check_port(ip: str, port: int, timeout: float = 0.5) -> Optional[int]:
    """Try to connect to a single port. Return port number if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            return port if result == 0 else None
    except Exception:
        return None


def scan_ports(ip: str, port_range: tuple = (20, 1025), timeout: float = 0.4) -> List[int]:
    """
    Threaded TCP port scanner.
    Scans port_range using a thread pool for speed.
    Returns sorted list of open ports.
    """
    ports = list(range(port_range[0], port_range[1]))
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(_check_port, ip, p, timeout): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)

    return sorted(open_ports)


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """
    Attempt to grab a service banner from an open port.
    Sends a generic HTTP-like probe and reads the response.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            # Send a probe (works for HTTP, FTP, SMTP, SSH, etc.)
            try:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            except Exception:
                pass
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner if banner else None
    except Exception:
        return None


def os_fingerprint(ip: str) -> str:
    """
    Basic OS fingerprinting based on open ports and TTL values.
    """
    import subprocess
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            capture_output=True, text=True, timeout=5
        )
        output = result.stdout
        if "ttl=64" in output.lower():
            os_guess = "Linux / Unix (TTL=64)"
        elif "ttl=128" in output.lower():
            os_guess = "Windows (TTL=128)"
        elif "ttl=255" in output.lower():
            os_guess = "Cisco / Network Device (TTL=255)"
        else:
            os_guess = "Unknown"
        return f"OS Fingerprint (TTL-based): {os_guess}"
    except Exception as e:
        return f"OS fingerprint failed: {str(e)}"
