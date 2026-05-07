"""
tools/logs.py — Rule-based log analysis + threat classification
"""

import re
from datetime import datetime


# ── Threat signatures ──────────────────────────────────────────
THREAT_RULES = {
    "CRITICAL": [
        r"sql.?inject",
        r"union.*select",
        r"exec\(",
        r"<script",
        r"root.*login.*fail",
        r"privilege.?escal",
        r"buffer.?overflow",
        r"command.?injection",
        r"/etc/passwd",
        r"\.\.\/",  # path traversal
    ],
    "HIGH": [
        r"failed.*password",
        r"authentication.*fail",
        r"unauthorized.*access",
        r"brute.?force",
        r"invalid user",
        r"permission denied",
        r"connection refused.*(\d{1,3}\.){3}\d{1,3}",
        r"port.*scan",
    ],
    "MEDIUM": [
        r"error",
        r"warning",
        r"timeout",
        r"deprecated",
        r"connection.*reset",
        r"ssl.*error",
        r"certificate.*invalid",
    ],
    "INFO": [
        r"logged in",
        r"session.*start",
        r"connection.*established",
        r"service.*start",
    ],
}


def analyze_logs(log_text: str) -> str:
    """
    Analyze a log entry or block against known threat signatures.
    Returns a threat level + matched patterns.
    """
    log_lower = log_text.lower()
    findings = []

    for level, patterns in THREAT_RULES.items():
        for pattern in patterns:
            if re.search(pattern, log_lower):
                findings.append((level, pattern))

    if not findings:
        return "✅ [INFO] No known threat signatures detected in logs."

    # Determine highest severity
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "INFO"]
    top_level = min(findings, key=lambda x: severity_order.index(x[0]))[0]

    colors = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "INFO": "🔵",
    }

    result_lines = [
        f"{colors[top_level]} Threat Level: {top_level}",
        f"Matched {len(findings)} signature(s):",
    ]
    for level, pattern in findings:
        result_lines.append(f"  [{level}] Pattern: `{pattern}`")

    # Recommendations
    recommendations = {
        "CRITICAL": "⚡ IMMEDIATE ACTION REQUIRED: Isolate system, check for compromise, review access logs.",
        "HIGH":     "🔥 Investigate ASAP: Check for unauthorized access, verify user accounts.",
        "MEDIUM":   "⚠️  Monitor closely: Check system health and review configurations.",
        "INFO":     "ℹ️  No action needed, routine activity.",
    }
    result_lines.append(f"\n💡 Recommendation: {recommendations[top_level]}")

    return "\n".join(result_lines)


def parse_auth_log(filepath: str) -> dict:
    """
    Parse /var/log/auth.log for failed login attempts.
    Returns stats: total failures, IPs, usernames.
    """
    stats = {"total_failures": 0, "ips": {}, "users": {}}
    try:
        with open(filepath, "r") as f:
            for line in f:
                if "Failed password" in line:
                    stats["total_failures"] += 1
                    ip_match = re.search(r"from (\d{1,3}(?:\.\d{1,3}){3})", line)
                    user_match = re.search(r"for (?:invalid user )?(\w+)", line)
                    if ip_match:
                        ip = ip_match.group(1)
                        stats["ips"][ip] = stats["ips"].get(ip, 0) + 1
                    if user_match:
                        user = user_match.group(1)
                        stats["users"][user] = stats["users"].get(user, 0) + 1
    except FileNotFoundError:
        return {"error": f"Log file not found: {filepath}"}
    except PermissionError:
        return {"error": "Permission denied. Run as root."}
    return stats
