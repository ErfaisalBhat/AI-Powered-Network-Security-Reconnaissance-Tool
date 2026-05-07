"""
tools/vuln.py — Vulnerability detection & SSL/TLS inspection
"""

import ssl
import socket
import datetime
import platform
import subprocess


# Known dangerous open port combinations
DANGEROUS_COMBOS = {
    (21, 23): "FTP + Telnet both open — unencrypted protocols, high risk!",
    (22, 3389): "SSH + RDP both exposed — review remote access policies.",
    (3306,): "MySQL port 3306 exposed — DB should not be publicly accessible!",
    (27017,): "MongoDB port 27017 open — often misconfigured without auth!",
    (6379,): "Redis port 6379 open — typically runs without auth by default!",
    (9200,): "Elasticsearch port 9200 open — may expose sensitive data!",
    (5900,): "VNC port 5900 open — remote desktop without encryption!",
    (445,): "SMB port 445 open — potential EternalBlue / ransomware vector!",
}


def detect_vulnerability(open_ports: list = None) -> str:
    """
    Run a basic vulnerability audit.
    - Checks OS for known weaknesses
    - Checks for dangerous open ports (if provided)
    - Checks for weak system configs
    """
    findings = []

    # ── 1. OS & kernel check ─────────────────────────
    sys_name = platform.system()
    release = platform.release()
    findings.append(f"🖥️  OS: {sys_name} {release}")

    if sys_name == "Linux":
        try:
            result = subprocess.run(["uname", "-r"], capture_output=True, text=True)
            kernel = result.stdout.strip()
            findings.append(f"🐧 Kernel: {kernel}")
            findings.append("✅ Kernel version retrieved. Check CVE databases for known issues.")
        except Exception:
            pass

    # ── 2. Dangerous port combos ──────────────────────
    if open_ports:
        port_set = set(open_ports)
        for combo, warning in DANGEROUS_COMBOS.items():
            if set(combo).issubset(port_set):
                findings.append(f"🔴 RISK: {warning}")

    # ── 3. World-writable /tmp check (Linux) ─────────
    if sys_name == "Linux":
        try:
            result = subprocess.run(
                ["find", "/tmp", "-perm", "-o+w", "-type", "f"],
                capture_output=True, text=True, timeout=5
            )
            if result.stdout.strip():
                findings.append("⚠️  World-writable files found in /tmp — check for malicious scripts.")
            else:
                findings.append("✅ /tmp: No world-writable files detected.")
        except Exception:
            pass

    # ── 4. Listening services ─────────────────────────
    try:
        if sys_name == "Linux":
            result = subprocess.run(
                ["ss", "-tlnp"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                services = result.stdout.strip()
                findings.append(f"\n📡 Listening Services (ss -tlnp):\n{services}")
    except Exception:
        pass

    # ── 5. Sudo version check ─────────────────────────
    try:
        result = subprocess.run(["sudo", "--version"], capture_output=True, text=True)
        sudo_ver = result.stdout.split("\n")[0].strip()
        findings.append(f"🔐 {sudo_ver}")
    except Exception:
        pass

    if not findings:
        return "⚠️ Could not gather vulnerability data."

    return "\n".join(findings)


def check_ssl(domain: str, port: int = 443) -> str:
    """
    Inspect an SSL/TLS certificate for a domain.
    Returns expiry, issuer, subject, and security warnings.
    """
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, port))
            cert = s.getpeercert()

        # Parse expiry
        not_after = cert.get("notAfter", "")
        expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry - datetime.datetime.utcnow()).days

        # Issuer
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))

        status_icon = "✅" if days_left > 30 else ("⚠️" if days_left > 0 else "🔴")

        lines = [
            f"🔒 SSL/TLS Certificate — {domain}:{port}",
            f"  Subject      : {subject.get('commonName', 'N/A')}",
            f"  Issuer       : {issuer.get('organizationName', 'N/A')}",
            f"  Valid Until  : {expiry.strftime('%Y-%m-%d')}",
            f"  Days Left    : {status_icon} {days_left} days",
            f"  TLS Version  : {s.version() if hasattr(s, 'version') else 'N/A'}",
        ]

        # SANs (Subject Alternative Names)
        sans = cert.get("subjectAltName", [])
        if sans:
            san_list = [v for t, v in sans if t == "DNS"]
            lines.append(f"  Alt Names    : {', '.join(san_list[:5])}")

        # Warnings
        if days_left < 0:
            lines.append("\n🔴 CRITICAL: Certificate is EXPIRED!")
        elif days_left < 7:
            lines.append(f"\n🔴 CRITICAL: Certificate expires in {days_left} days!")
        elif days_left < 30:
            lines.append(f"\n⚠️  WARNING: Certificate expires soon ({days_left} days).")

        return "\n".join(lines)

    except ssl.SSLCertVerificationError as e:
        return f"🔴 SSL VERIFICATION FAILED: {str(e)}"
    except ConnectionRefusedError:
        return f"❌ Connection refused on {domain}:{port}"
    except socket.timeout:
        return f"⏱️ Connection timed out for {domain}"
    except Exception as e:
        return f"❌ SSL check error: {str(e)}"
