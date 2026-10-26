import json
from pathlib import Path

from mcp_soc_tools.analyzer import analyze_file, analyze_log_text


def test_detects_failed_auth_and_retains_limitations():
    result = analyze_log_text("Jan 1 sshd: Failed password for invalid user admin from 203.0.113.4 port 22")
    assert result["findings_count"] == 1
    assert result["findings"][0]["type"] == "failed_auth"
    assert "not proof of compromise" in result["limitations"][0]


def test_detects_json_fields_and_repeated_ip(tmp_path: Path):
    events = [
        {"timestamp": "2026-01-01T00:00:00Z", "action": "login failed", "source_ip": "198.51.100.9"}
        for _ in range(5)
    ]
    log = tmp_path / "events.jsonl"
    log.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    result = analyze_file(str(log))
    assert result["line_count"] == 5
    assert result["repeated_source_ips"] == [{"source_ip": "198.51.100.9", "finding_count": 5}]
    assert result["file_name"] == "events.jsonl"


def test_empty_file_is_valid():
    assert analyze_log_text("")["findings_count"] == 0

