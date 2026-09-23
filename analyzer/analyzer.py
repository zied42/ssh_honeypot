"""Structured JSON Lines Log Analyzer for SSH Honeypot Analytics"""

import argparse
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


class HoneypotLogAnalyzer:
    """Analyze honeypot JSON Lines logs and generate detailed security reports"""

    def __init__(self, log_dir="data/logs"):
        self.log_dir = Path(log_dir)
        if not self.log_dir.exists():
            # Fallback check for relative data/logs
            alt = Path(__file__).parent.parent / "data" / "logs"
            if alt.exists():
                self.log_dir = alt

    def read_jsonl_files(self, prefix, time_range_hours=720):
        """Read and parse all JSON Lines log files with given prefix within time range"""
        if not self.log_dir.exists():
            return []

        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=time_range_hours)
        records = []

        for log_file in self.log_dir.glob(f"{prefix}*"):
            if not log_file.is_file():
                continue
            try:
                with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            record = json.loads(line)
                            ts_str = record.get("timestamp")
                            if ts_str:
                                # Parse ISO timestamp
                                try:
                                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                                    if ts.tzinfo is None:
                                        ts = ts.replace(tzinfo=timezone.utc)
                                    if ts >= cutoff_time:
                                        records.append(record)
                                except Exception:
                                    records.append(record)
                            else:
                                records.append(record)
                        except Exception:
                            continue
            except Exception:
                continue

        return records

    def generate_full_report(self, time_range_hours=720):
        """Generate comprehensive analytics over the time range"""
        audit_records = self.read_jsonl_files("audits", time_range_hours)
        cmd_records = self.read_jsonl_files("cmd_audits", time_range_hours)
        alert_records = self.read_jsonl_files("alerts", time_range_hours)

        # Overview counters
        unique_ips = set()
        total_connections = 0
        total_sessions = 0
        session_durations = []
        sessions_per_day = Counter()

        # Version & IP counters
        client_versions = Counter()
        ip_conn_counts = Counter()
        ip_session_counts = Counter()
        ip_alert_counts = Counter()

        # Credential counters
        usernames = Counter()
        passwords = Counter()
        combos = Counter()

        # Command & Attack counters
        top_commands = Counter()
        severities = Counter()
        categories = Counter()
        mitre_counts = Counter()

        # IOC counters
        extracted_urls = Counter()
        extracted_ips = Counter()
        extracted_hashes = Counter()

        # Process Audit Records
        for rec in audit_records:
            event = rec.get("event")
            ip = rec.get("src_ip")
            if ip:
                unique_ips.add(ip)

            if event == "connection":
                total_connections += 1
                if ip:
                    ip_conn_counts[ip] += 1

            elif event == "session_start":
                total_sessions += 1
                if ip:
                    ip_session_counts[ip] += 1
                version = rec.get("remote_version")
                if version:
                    client_versions[version] += 1
                ts_str = rec.get("timestamp")
                if ts_str:
                    day_str = ts_str[:10]
                    sessions_per_day[day_str] += 1

            elif event == "session_end":
                dur = rec.get("duration")
                if isinstance(dur, (int, float)):
                    session_durations.append(dur)

            elif event == "auth":
                u = rec.get("username")
                p = rec.get("password")
                if u:
                    usernames[u] += 1
                if p:
                    passwords[p] += 1
                if u and p:
                    combos[f"{u}:{p}"] += 1

        # Process Command Records
        for rec in cmd_records:
            cmd = rec.get("command")
            if cmd:
                top_commands[cmd] += 1

        # Process Alert Records
        for rec in alert_records:
            ip = rec.get("src_ip")
            if ip:
                ip_alert_counts[ip] += 1
            sev = rec.get("severity")
            if sev:
                severities[sev] += 1
            cat = rec.get("category")
            if cat:
                categories[cat] += 1
            mitre_list = rec.get("mitre_attack") or []
            for tid in mitre_list:
                mitre_counts[tid] += 1

            iocs = rec.get("iocs") or {}
            for url in iocs.get("urls", []):
                extracted_urls[url] += 1
            for i_ip in iocs.get("ips", []):
                extracted_ips[i_ip] += 1
            for h in iocs.get("md5", []) + iocs.get("sha256", []):
                extracted_hashes[h] += 1

        avg_session_length = (
            sum(session_durations) / len(session_durations) if session_durations else 0.0
        )

        top_ips_list = []
        for ip in sorted(unique_ips, key=lambda x: ip_conn_counts[x], reverse=True)[:20]:
            top_ips_list.append({
                "ip": ip,
                "connections": ip_conn_counts[ip],
                "sessions": ip_session_counts[ip],
                "alerts": ip_alert_counts[ip]
            })

        return {
            "overview": {
                "total_connections": total_connections,
                "unique_ips": len(unique_ips),
                "total_sessions": total_sessions,
                "avg_session_length_seconds": round(avg_session_length, 2),
                "total_commands": len(cmd_records),
                "alerts_triggered": len(alert_records),
                "time_range_hours": time_range_hours
            },
            "credentials": {
                "top_usernames": [{"username": u, "count": c} for u, c in usernames.most_common(10)],
                "top_passwords": [{"password": p, "count": c} for p, c in passwords.most_common(10)],
                "top_combos": [{"combo": combo, "count": c} for combo, c in combos.most_common(10)]
            },
            "traffic_analysis": {
                "sessions_per_day": [{"date": d, "sessions": c} for d, c in sorted(sessions_per_day.items())],
                "top_source_ips": top_ips_list,
                "client_versions": [{"version": v, "count": c} for v, c in client_versions.most_common(10)]
            },
            "attacks": {
                "top_commands": [{"command": cmd, "count": c} for cmd, c in top_commands.most_common(15)],
                "severity_distribution": [{"severity": s, "count": c} for s, c in severities.items()],
                "categories": [{"category": cat, "count": c} for cat, c in categories.items()],
                "mitre_attack_counts": [{"technique": t, "count": c} for t, c in mitre_counts.most_common(10)]
            },
            "iocs": {
                "urls": [{"url": url, "count": c} for url, c in extracted_urls.most_common(20)],
                "ips": [{"ip": ip, "count": c} for ip, c in extracted_ips.most_common(20)],
                "hashes": [{"hash": h, "count": c} for h, c in extracted_hashes.most_common(20)]
            },
            "generated_at": datetime.now(timezone.utc).isoformat()
        }

    def export_to_json(self, output_file="analytics_report.json", time_range_hours=720):
        """Export analytics to JSON file"""
        report = self.generate_full_report(time_range_hours)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        return report

    def export_to_markdown(self, markdown_file="analytics_report.md", time_range_hours=720):
        """Export analytics to Markdown file"""
        report = self.generate_full_report(time_range_hours)
        ov = report["overview"]
        creds = report["credentials"]
        traffic = report["traffic_analysis"]
        attacks = report["attacks"]
        iocs = report["iocs"]

        md = []
        md.append("# 🛡️ SSH Honeypot Threat Intelligence & Analytics Report")
        md.append(f"**Generated At**: {report['generated_at']}")
        md.append(f"**Time Range**: Last {ov['time_range_hours']} hours\n")

        md.append("## 📊 Overview Metrics")
        md.append(f"- **Total Connections**: {ov['total_connections']}")
        md.append(f"- **Unique Attacker IPs**: {ov['unique_ips']}")
        md.append(f"- **Total SSH Sessions**: {ov['total_sessions']}")
        md.append(f"- **Avg Session Length**: {ov['avg_session_length_seconds']} seconds")
        md.append(f"- **Commands Executed**: {ov['total_commands']}")
        md.append(f"- **Alerts Triggered**: {ov['alerts_triggered']}\n")

        md.append("## 🔑 Top Credential Attempts")
        md.append("### Usernames")
        md.append("| Username | Attempts |")
        md.append("|---|---|")
        for item in creds["top_usernames"]:
            md.append(f"| `{item['username']}` | {item['count']} |")

        md.append("\n### Passwords")
        md.append("| Password | Attempts |")
        md.append("|---|---|")
        for item in creds["top_passwords"]:
            md.append(f"| `{item['password']}` | {item['count']} |")

        md.append("\n## 🎯 ATT&CK Techniques & Threat Categories")
        md.append("| Technique / Category | Count |")
        md.append("|---|---|")
        for item in attacks["mitre_attack_counts"]:
            md.append(f"| **{item['technique']}** | {item['count']} |")
        for item in attacks["categories"]:
            md.append(f"| {item['category']} | {item['count']} |")

        md.append("\n## 🌐 Extracted IOCs (Indicators of Compromise)")
        md.append("### URLs")
        if iocs["urls"]:
            md.append("| URL | Frequency |")
            md.append("|---|---|")
            for item in iocs["urls"]:
                md.append(f"| `{item['url']}` | {item['count']} |")
        else:
            md.append("_No URLs extracted yet._")

        with open(markdown_file, "w", encoding="utf-8") as f:
            f.write("\n".join(md) + "\n")


def main():
    parser = argparse.ArgumentParser(description="SSH Honeypot Structured JSON Log Analyzer")
    parser.add_argument("--hours", type=int, default=720, help="Time range in hours (default: 720 / 30 days)")
    parser.add_argument("--log-dir", type=str, default="data/logs", help="Path to log directory")
    parser.add_argument("--output", type=str, default="analytics_report.json", help="JSON output file path")
    parser.add_argument("--markdown", type=str, default="analytics_report.md", help="Markdown output file path")
    args = parser.parse_args()

    analyzer = HoneypotLogAnalyzer(log_dir=args.log_dir)
    report = analyzer.export_to_json(output_file=args.output, time_range_hours=args.hours)
    analyzer.export_to_markdown(markdown_file=args.markdown, time_range_hours=args.hours)

    print("=" * 60)
    print("SSH Honeypot Log Analyzer Complete")
    print(f"Time Range        : {args.hours} hours")
    print(f"Total Connections : {report['overview']['total_connections']}")
    print(f"Unique IPs        : {report['overview']['unique_ips']}")
    print(f"Total Commands    : {report['overview']['total_commands']}")
    print(f"Alerts Triggered  : {report['overview']['alerts_triggered']}")
    print(f"JSON Report       : {args.output}")
    print(f"Markdown Report   : {args.markdown}")
    print("=" * 60)


if __name__ == "__main__":
    main()