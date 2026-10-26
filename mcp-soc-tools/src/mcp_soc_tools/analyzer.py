from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_RESULTS = 5000


def _read_lines(file_path: str) -> tuple[list[str], str | None]:
    """Read a caller-selected local file with size and path validation."""
    path = Path(file_path).expanduser().resolve(strict=True)
    if not path.is_file():
        raise ValueError("The supplied path is not a regular file.")
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"File exceeds the {MAX_FILE_BYTES // (1024 * 1024)} MiB limit.")
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as exc:
        raise ValueError(f"Could not read file: {exc}") from exc
    return text.splitlines(), path.name


def _parse_line(line: str) -> dict[str, Any] | None:
    stripped = line.strip()
    if not stripped:
        return None
    try:
        obj = json.loads(stripped)
        if isinstance(obj, dict):
            message = str(obj.get("message") or obj.get("msg") or obj.get("event") or stripped)
            merged = " ".join([message, str(obj.get("action", "")), str(obj.get("status", "")), str(obj.get("result", ""))])
            return {"raw": stripped, "text": merged, "timestamp": obj.get("timestamp") or obj.get("@timestamp"), "source_ip": obj.get("source_ip") or obj.get("src_ip") or obj.get("client_ip")}
    except json.JSONDecodeError:
        pass
    return {"raw": stripped, "text": stripped, "timestamp": None, "source_ip": None}


def analyze_log_text(text: str) -> dict[str, Any]:
    """Analyze supplied log text for a small set of transparent heuristics."""
    parsed = [event for line in text.splitlines() if (event := _parse_line(line)) is not None]
    findings: list[dict[str, Any]] = []
    patterns = [
        ("failed_auth", re.compile(r"failed password|authentication failure|login failed|invalid user|401 unauthorized", re.I), "Repeated or unsuccessful authentication indicator", "medium"),
        ("successful_auth", re.compile(r"accepted password|login successful|authentication success|user logged in", re.I), "Successful authentication indicator; review source and timing", "low"),
        ("privilege_change", re.compile(r"sudo:|privilege escalation|user .* became root|euid=0", re.I), "Privileged command or account transition indicator", "medium"),
        ("port_scan", re.compile(r"port scan|syn scan|nmap|connection refused", re.I), "Possible network probing indicator", "low"),
        ("malware_alert", re.compile(r"malware|ransomware|trojan|virus detected|quarantined", re.I), "Malware-related alert indicator", "high"),
        ("web_attack", re.compile(r"<script|union\s+select|\.\./\.\./|sql injection|command injection", re.I), "Possible web attack payload indicator", "high"),
    ]
    for idx, event in enumerate(parsed, start=1):
        for key, pattern, description, severity in patterns:
            if pattern.search(event["text"]):
                findings.append({"line": idx, "type": key, "severity": severity, "description": description, "timestamp": event["timestamp"], "source_ip": event["source_ip"], "excerpt": event["raw"][:500]})
                if len(findings) >= MAX_RESULTS:
                    break
        if len(findings) >= MAX_RESULTS:
            break
    ips = Counter(str(f["source_ip"]) for f in findings if f["source_ip"])
    repeated = [{"source_ip": ip, "finding_count": count} for ip, count in ips.most_common() if count >= 5]
    severity_counts = Counter(f["severity"] for f in findings)
    return {
        "line_count": len(parsed),
        "findings_count": len(findings),
        "severity_counts": dict(severity_counts),
        "repeated_source_ips": repeated,
        "findings": findings,
        "limitations": ["Heuristic triage only; findings are not proof of compromise.", "No log data is sent to external services.", "Only the supplied file contents are analyzed."],
    }


def analyze_file(file_path: str) -> dict[str, Any]:
    lines, file_name = _read_lines(file_path)
    result = analyze_log_text("\n".join(lines))
    result["file_name"] = file_name
    return result

