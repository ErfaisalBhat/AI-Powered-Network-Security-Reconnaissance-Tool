"""
tools/network.py — Ping, traceroute, local network info
"""

import os
import socket
import subprocess
import platform


def ping_host(host: str, count: int = 4) -> str:
    """Ping a host and return formatted results."""
    try:
        flag = "-n" if platform.system().lower() == "windows" else "-c"
        result = subprocess.run(
            ["ping", flag, str(count), host],
            capture_output=True, text=True, timeout=15
        )
        output = result.stdout.strip()

        # Extract key stats
        lines = output.split("\n")
        summary = []
        for line in lines:
            l = line.lower()
            if any(k in l for k in ["packets", "loss", "min/avg/max", "round-trip", "rtt"]):
                summary.append(line.strip())

        if result.returncode == 0:
            status = "✅ Host is REACHABLE"
        else:
            status = "❌ Host is UNREACHABLE"

        details = "\n".join(summary) if summary else output[-300:]
        return f"{status}\n\n📊 Stats:\n{details}"
    except subprocess.TimeoutExpired:
        return "⏱️ Ping timed out."
    except Exception as e:
        return f"❌ Ping error: {str(e)}"


def traceroute(host: str) -> str:
    """Run traceroute / tracert and return results."""
    try:
        cmd = ["tracert", host] if platform.system().lower() == "windows" else ["traceroute", "-m", "15", host]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout.strip()
        return output if output else "No traceroute output."
    except FileNotFoundError:
        return "❌ traceroute not installed. Try: sudo apt install traceroute"
    except subprocess.TimeoutExpired:
        return "⏱️ Traceroute timed out (15 hops max)."
    except Exception as e:
        return f"❌ Traceroute error: {str(e)}"


def get_network_info() -> str:
    """Gather local network information."""
    info = []

    # Hostname
    hostname = socket.gethostname()
    info.append(f"🖥️  Hostname     : {hostname}")

    # Local IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        info.append(f"📍 Local IP     : {local_ip}")
    except Exception:
        info.append("📍 Local IP     : Unavailable")

    # Public IP
    try:
        import urllib.request
        pub_ip = urllib.request.urlopen("https://api.ipify.org", timeout=5).read().decode()
        info.append(f"🌐 Public IP    : {pub_ip}")
    except Exception:
        info.append("🌐 Public IP    : Unavailable (no internet)")

    # DNS resolution test
    try:
        dns_ip = socket.gethostbyname("google.com")
        info.append(f"✅ DNS          : Resolving (google.com → {dns_ip})")
    except Exception:
        info.append("❌ DNS          : Not resolving")

    # Platform info
    info.append(f"💻 Platform     : {platform.system()} {platform.release()}")
    info.append(f"🐍 Python       : {platform.python_version()}")

    # Interface info via ifconfig/ip
    try:
        if platform.system().lower() != "windows":
            result = subprocess.run(["ip", "-br", "addr"], capture_output=True, text=True)
            if result.returncode == 0:
                info.append("\n📡 Network Interfaces:\n" + result.stdout.strip())
    except Exception:
        pass

    return "\n".join(info)


def resolve_host(host: str) -> str:
    """Resolve hostname to IP(s)."""
    try:
        ips = socket.getaddrinfo(host, None)
        unique = list(set(i[4][0] for i in ips))
        return f"🔎 {host} resolves to: {', '.join(unique)}"
    except Exception as e:
        return f"❌ Could not resolve {host}: {str(e)}"
