"""
tools/report.py — JSON + text report generation
"""

import json
import os
import datetime
import platform
import socket


def generate_report(session_log: list) -> str:
    """
    Generate a structured JSON report from the session log.
    Saves to reports/ directory with timestamped filename.
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"netsentinel_report_{timestamp}.json"
    report_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
    os.makedirs(report_dir, exist_ok=True)
    filepath = os.path.join(report_dir, filename)

    report = {
        "metadata": {
            "tool": "NetSentinel v2.0",
            "generated_at": datetime.datetime.now().isoformat(),
            "hostname": socket.gethostname(),
            "platform": f"{platform.system()} {platform.release()}",
            "python_version": platform.python_version(),
        },
        "summary": {
            "total_commands": len(session_log),
            "session_start": session_log[0]["timestamp"] if session_log else None,
            "session_end": session_log[-1]["timestamp"] if session_log else None,
        },
        "session_log": session_log,
    }

    with open(filepath, "w") as f:
        json.dump(report, f, indent=2, default=str)

    # Also write a human-readable .txt summary
    txt_path = filepath.replace(".json", ".txt")
    with open(txt_path, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("  NetSentinel v2.0 — Security Scan Report\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Generated  : {report['metadata']['generated_at']}\n")
        f.write(f"Hostname   : {report['metadata']['hostname']}\n")
        f.write(f"Platform   : {report['metadata']['platform']}\n")
        f.write(f"Commands   : {report['summary']['total_commands']}\n\n")
        f.write("-" * 60 + "\n")
        f.write("SESSION LOG\n")
        f.write("-" * 60 + "\n\n")
        for i, entry in enumerate(session_log, 1):
            f.write(f"[{i}] {entry['timestamp']}\n")
            f.write(f"    Query  : {entry.get('query', '')}\n")
            result = entry.get("result", "")
            if result:
                # Clean up rich markup for plain text
                import re
                clean = re.sub(r"\[/?[^\]]*\]", "", str(result))
                f.write(f"    Result : {clean[:300]}\n")
            f.write("\n")

    return filepath
