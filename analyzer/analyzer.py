"""Log analyzer for SSH honeypot analytics"""

import re
import json
import os
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from pathlib import Path
class HoneypotLogAnalyzer:
    """Analyze honeypot logs and generate comprehensive statistics"""

    def __init__(self, log_dir="logs"):
        self.log_dir = Path(log_dir)

        # Debug: Print current working directory and log directory
        print(f"Current working directory: {os.getcwd()}")
        print(f"Looking for logs in: {self.log_dir.absolute()}")

        # Check if log directory exists
        if not self.log_dir.exists():
            print(f"ERROR: Log directory does not exist: {self.log_dir.absolute()}")
            print(f"Please create the directory or specify the correct path.")
            # Try to find logs directory
            possible_paths = [
                Path("logs"),
                Path("../logs"),
                Path("./PythonProject/logs"),
                Path.cwd() / "logs"
            ]
            for path in possible_paths:
                if path.exists():
                    print(f"Found logs directory at: {path.absolute()}")
                    self.log_dir = path
                    break
        else:
            print(f"✓ Log directory exists")
            # List files in log directory
            files = list(self.log_dir.iterdir())
            print(f"Files in log directory: {[f.name for f in files]}")

        self.audit_log = self.log_dir / "audits.log"
        self.cmd_log = self.log_dir / "cmd_audits.log"
        self.alert_log = self.log_dir / "alerts.log"

        # Check each log file
        for log_name, log_path in [
            ("Audit log", self.audit_log),
            ("Command log", self.cmd_log),
            ("Alert log", self.alert_log)
        ]:
            if log_path.exists():
                size = log_path.stat().st_size
                print(f"✓ {log_name} found: {log_path.name} ({size} bytes)")
            else:
                print(f"✗ {log_name} NOT found: {log_path.absolute()}")

    def parse_log_line(self, line, log_type):
        """Parse a log line and extract structured data"""
        try:
            # Extract timestamp (at beginning of line)
            timestamp_match = re.search(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
            timestamp = timestamp_match.group(1) if timestamp_match else None

            if log_type == "audit":
                # Parse audit logs (connections, sessions, auth)
                session_id = re.search(r'\[([a-f0-9]{8})\]', line)
                # Try to match IP from both formats: "IP=x.x.x.x" and "CONNECTION FROM x.x.x.x"
                ip_match = re.search(r'IP=([0-9.]+)', line)
                if not ip_match:
                    ip_match = re.search(r'CONNECTION FROM ([0-9.]+)', line)
                user_match = re.search(r'USER=(\w+)', line)
                duration_match = re.search(r'DURATION=([\d.]+)s', line)

                # Detect AUTH attempts (format: AUTH username:password)
                auth_match = re.search(r'AUTH (\w+):(.+)$', line)

                event_type = None
                if 'CONNECTION FROM' in line:
                    event_type = 'connection'
                elif 'SESSION START' in line:
                    event_type = 'session_start'
                elif 'SESSION END' in line:
                    event_type = 'session_end'
                elif 'AUTH' in line:
                    event_type = 'auth'

                return {
                    'timestamp': timestamp,
                    'session_id': session_id.group(1) if session_id else None,
                    'ip': ip_match.group(1) if ip_match else None,
                    'user': user_match.group(1) if user_match else None,
                    'duration': float(duration_match.group(1)) if duration_match else None,
                    'event_type': event_type,
                    'auth_username': auth_match.group(1) if auth_match else None,
                    'auth_password': auth_match.group(2) if auth_match else None,
                    'raw': line
                }

            elif log_type == "command":
                # Parse command logs
                # Format: [session_id] IP=x.x.x.x USER=username TIME=iso8601 CMD=command
                session_id = re.search(r'\[([a-f0-9]{8})\]', line)
                ip_match = re.search(r'IP=([0-9.]+)', line)
                user_match = re.search(r'USER=(\w+)', line)
                time_match = re.search(r'TIME=([\d\-:T+.]+)', line)
                cmd_match = re.search(r'CMD=(.+?)(?:\s+SUDO|$)', line)
                sudo_pwd = re.search(r'SUDO_PASSWORD_ATTEMPT=(\S+)', line)
                sudo_cmd = re.search(r'SUDO_CMD=(.+)$', line)

                return {
                    'timestamp': timestamp,
                    'session_id': session_id.group(1) if session_id else None,
                    'ip': ip_match.group(1) if ip_match else None,
                    'user': user_match.group(1) if user_match else None,
                    'command': cmd_match.group(1).strip() if cmd_match else None,
                    'sudo_password': sudo_pwd.group(1) if sudo_pwd else None,
                    'sudo_command': sudo_cmd.group(1) if sudo_cmd else None,
                    'raw': line
                }

            elif log_type == "alert":
                # Parse alert logs
                # Two formats:
                # 1. CANARY_ACCESSED format
                # 2. SEVERITY format with HITS
                session_id = re.search(r'\[([a-f0-9]{8})\]', line)
                ip_match = re.search(r'IP=([0-9.]+)', line)
                user_match = re.search(r'USER=(\w+)', line)
                severity_match = re.search(r'SEVERITY=(\w+)', line)
                hits_match = re.search(r"HITS=\[(.*?)\]", line)
                cmd_match = re.search(r'CMD=(.+)$', line)
                canary_match = re.search(r'CANARY_ACCESSED=(.+)$', line)

                # Parse hits array
                hits = []
                if hits_match:
                    hits_str = hits_match.group(1)
                    # Remove quotes and split by comma
                    hits = [h.strip().strip("'\"") for h in hits_str.split(',') if h.strip()]

                return {
                    'timestamp': timestamp,
                    'session_id': session_id.group(1) if session_id else None,
                    'ip': ip_match.group(1) if ip_match else None,
                    'user': user_match.group(1) if user_match else None,
                    'severity': severity_match.group(1) if severity_match else 'HIGH',  # Canary is HIGH
                    'hits': hits,
                    'command': cmd_match.group(1).strip() if cmd_match else None,
                    'canary': canary_match.group(1) if canary_match else None,
                    'raw': line
                }

        except Exception as e:
            print(f"Error parsing line: {e}")
            print(f"Line: {line}")
            return None

    def read_logs(self, log_file, log_type, time_range_hours=24):
        """Read and parse log files within time range"""
        if not log_file.exists():
            print(f"Warning: Log file not found: {log_file}")
            return []

        cutoff_time = datetime.now() - timedelta(hours=time_range_hours)
        parsed_logs = []

        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    parsed = self.parse_log_line(line, log_type)
                    if parsed and parsed['timestamp']:
                        try:
                            # Parse timestamp format: 2026-01-11 12:41:19
                            log_time = datetime.strptime(parsed['timestamp'], '%Y-%m-%d %H:%M:%S')
                            if log_time >= cutoff_time:
                                parsed_logs.append(parsed)
                        except ValueError as e:
                            # Try alternative format
                            try:
                                log_time = datetime.strptime(parsed['timestamp'][:19], '%Y-%m-%d %H:%M:%S')
                                if log_time >= cutoff_time:
                                    parsed_logs.append(parsed)
                            except:
                                pass
        except Exception as e:
            print(f"Error reading log file {log_file}: {e}")

        return parsed_logs

    def analyze_credentials(self, audit_logs, cmd_logs):
        """Analyze credential usage patterns"""
        usernames = Counter()
        passwords = Counter()
        combos = Counter()
        sudo_attempts = []

        # From audit logs (AUTH attempts)
        for log in audit_logs:
            if log.get('event_type') == 'auth':
                username = log.get('auth_username')
                password = log.get('auth_password')
                if username and password:
                    usernames[username] += 1
                    passwords[password] += 1
                    combos[f"{username}:{password}"] += 1

        # From command logs (SUDO attempts)
        for log in cmd_logs:
            if log.get('sudo_password'):
                sudo_attempts.append({
                    'ip': log['ip'],
                    'user': log['user'],
                    'password': log['sudo_password'],
                    'command': log.get('sudo_command', 'N/A'),
                    'timestamp': log['timestamp']
                })
                passwords[log['sudo_password']] += 1

        return {
            'top_usernames': [{'username': u, 'attempts': c} for u, c in usernames.most_common(10)],
            'top_passwords': [{'password': p, 'attempts': c} for p, c in passwords.most_common(10)],
            'top_combos': [{'combo': combo, 'attempts': c} for combo, c in combos.most_common(10)],
            'sudo_attempts': sudo_attempts
        }

    def analyze_attacks(self, alert_logs, cmd_logs):
        """Analyze attack patterns and commands"""
        severity_distribution = Counter()
        top_commands = Counter()
        attack_patterns = Counter()
        targeted_files = Counter()
        malicious_ips = Counter()

        for alert in alert_logs:
            if alert.get('severity'):
                severity_distribution[alert['severity']] += 1

            if alert.get('command'):
                top_commands[alert['command']] += 1

            if alert.get('ip'):
                malicious_ips[alert['ip']] += 1

            # Classify attack patterns from hits
            if alert.get('hits'):
                for hit in alert['hits']:
                    hit_lower = hit.lower()
                    if 'wget' in hit_lower or 'curl' in hit_lower:
                        attack_patterns['Malware Download'] += 1
                    elif 'bash -i' in hit_lower or 'nc' in hit_lower or '/dev/tcp' in hit_lower:
                        attack_patterns['Reverse Shell'] += 1
                    elif 'chmod +x' in hit_lower or 'rm -rf' in hit_lower:
                        attack_patterns['System Manipulation'] += 1
                    elif 'base64' in hit_lower or 'python -c' in hit_lower or 'perl -e' in hit_lower:
                        attack_patterns['Code Execution'] += 1

            # Track canary file access
            if alert.get('canary'):
                targeted_files[alert['canary']] += 1
                attack_patterns['Data Exfiltration'] += 1

        # Analyze all commands for file access patterns
        file_pattern = re.compile(r'(/etc/\w+|/root/\S+|/home/\S+|~/.ssh/\S+|\.txt|\.sql|\.key)')
        for cmd in cmd_logs:
            if cmd.get('command'):
                matches = file_pattern.findall(cmd['command'])
                for match in matches:
                    targeted_files[match] += 1

        return {
            'severity_distribution': [
                {'severity': sev, 'count': count}
                for sev, count in severity_distribution.items()
            ],
            'top_commands': [
                {'command': cmd, 'count': count}
                for cmd, count in top_commands.most_common(10)
            ],
            'attack_patterns': dict(attack_patterns),
            'targeted_files': [
                {'file': file, 'count': count}
                for file, count in targeted_files.most_common(10)
            ],
            'malicious_ips': dict(malicious_ips)
        }

    def analyze_ip_intelligence(self, audit_logs, alert_logs):
        """Analyze IP-based intelligence"""
        ip_stats = defaultdict(lambda: {
            'attempts': 0,
            'sessions': set(),
            'alerts': 0,
            'last_seen': None,
            'usernames': set(),
            'severity': 'LOW'
        })

        # Count connections
        for log in audit_logs:
            if log.get('ip'):
                ip = log['ip']

                if log.get('event_type') == 'connection':
                    ip_stats[ip]['attempts'] += 1

                if log.get('session_id'):
                    ip_stats[ip]['sessions'].add(log['session_id'])

                if log.get('timestamp'):
                    if ip_stats[ip]['last_seen'] is None or log['timestamp'] > ip_stats[ip]['last_seen']:
                        ip_stats[ip]['last_seen'] = log['timestamp']

                if log.get('user'):
                    ip_stats[ip]['usernames'].add(log['user'])

        # Count alerts per IP
        for alert in alert_logs:
            if alert.get('ip'):
                ip_stats[alert['ip']]['alerts'] += 1
                if alert.get('severity'):
                    # Upgrade severity if higher
                    current = ip_stats[alert['ip']]['severity']
                    new = alert['severity']
                    if new == 'HIGH' or (new == 'MEDIUM' and current == 'LOW'):
                        ip_stats[alert['ip']]['severity'] = new

        # Convert to list format
        top_ips = []
        for ip, stats in sorted(ip_stats.items(), key=lambda x: x[1]['attempts'], reverse=True)[:20]:
            top_ips.append({
                'ip': ip,
                'attempts': stats['attempts'],
                'sessions': len(stats['sessions']),
                'alerts': stats['alerts'],
                'last_seen': stats['last_seen'],
                'usernames': list(stats['usernames']),
                'severity': stats['severity']
            })

        return {'top_attackers': top_ips}

    def analyze_sessions(self, audit_logs, cmd_logs, alert_logs):
        """Analyze individual sessions"""
        sessions = defaultdict(lambda: {
            'id': None,
            'ip': None,
            'user': None,
            'start_time': None,
            'end_time': None,
            'duration': 0,
            'commands': [],
            'alerts': 0
        })

        # Build session data from audit logs
        for log in audit_logs:
            sid = log.get('session_id')
            if sid:
                if log.get('event_type') == 'session_start':
                    sessions[sid]['id'] = sid
                    sessions[sid]['ip'] = log.get('ip')
                    sessions[sid]['user'] = log.get('user')
                    sessions[sid]['start_time'] = log.get('timestamp')
                elif log.get('event_type') == 'session_end':
                    sessions[sid]['end_time'] = log.get('timestamp')
                    sessions[sid]['duration'] = log.get('duration', 0)

        # Add commands
        for cmd in cmd_logs:
            sid = cmd.get('session_id')
            if sid and cmd.get('command'):
                sessions[sid]['commands'].append(cmd['command'])

        # Add alerts
        for alert in alert_logs:
            sid = alert.get('session_id')
            if sid:
                sessions[sid]['alerts'] += 1

        # Convert to list and sort by start time
        session_list = []
        for sid, data in sessions.items():
            if data['id']:  # Only include sessions that actually started
                session_list.append({
                    'id': data['id'],
                    'ip': data['ip'],
                    'user': data['user'],
                    'start_time': data['start_time'],
                    'duration': f"{int(data['duration'] // 60)}m {int(data['duration'] % 60)}s" if data[
                        'duration'] else 'N/A',
                    'command_count': len(data['commands']),
                    'alerts': data['alerts'],
                    'status': 'closed' if data['end_time'] else 'active'
                })

        return sorted(session_list, key=lambda x: x['start_time'] or '', reverse=True)[:50]

    def analyze_timeline(self, alert_logs, hours=24):
        """Create attack timeline"""
        timeline = defaultdict(int)

        for alert in alert_logs:
            if alert.get('timestamp'):
                try:
                    dt = datetime.strptime(alert['timestamp'], '%Y-%m-%d %H:%M:%S')
                    hour_bucket = dt.strftime('%H:00')
                    timeline[hour_bucket] += 1
                except:
                    pass

        # Fill in missing hours with 0
        result = []
        for i in range(24):
            hour = f"{i:02d}:00"
            result.append({'time': hour, 'attacks': timeline.get(hour, 0)})

        return result

    def generate_full_report(self, time_range_hours=24):
        """Generate comprehensive analytics report"""
        print(f"\nGenerating report for last {time_range_hours} hours...")

        # Read all logs
        audit_logs = self.read_logs(self.audit_log, "audit", time_range_hours)
        cmd_logs = self.read_logs(self.cmd_log, "command", time_range_hours)
        alert_logs = self.read_logs(self.alert_log, "alert", time_range_hours)

        print(f"Found {len(audit_logs)} audit logs, {len(cmd_logs)} command logs, {len(alert_logs)} alert logs")

        # Get unique IPs from connections
        unique_ips = set()
        total_connections = 0
        for log in audit_logs:
            if log.get('event_type') == 'connection' and log.get('ip'):
                unique_ips.add(log['ip'])
                total_connections += 1

        # Generate all analytics
        credentials = self.analyze_credentials(audit_logs, cmd_logs)
        attacks = self.analyze_attacks(alert_logs, cmd_logs)
        ip_intel = self.analyze_ip_intelligence(audit_logs, alert_logs)
        sessions = self.analyze_sessions(audit_logs, cmd_logs, alert_logs)
        timeline = self.analyze_timeline(alert_logs, time_range_hours)

        return {
            'overview': {
                'total_connections': total_connections,
                'unique_ips': len(unique_ips),
                'total_commands': len(cmd_logs),
                'alerts_triggered': len(alert_logs),
                'time_range_hours': time_range_hours
            },
            'credentials': credentials,
            'attacks': attacks,
            'ip_intelligence': ip_intel,
            'sessions': sessions,
            'timeline': timeline,
            'generated_at': datetime.now().isoformat()
        }

    def export_to_json(self, output_file="analytics_report.json", time_range_hours=24):
        """Export analytics to JSON file"""
        report = self.generate_full_report(time_range_hours)

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n✓ Analytics report exported to {output_file}")
        return report


if __name__ == "__main__":
    # Example usage
    print("=" * 70)
    print("SSH Honeypot Log Analyzer - Starting...")
    print("=" * 70)

    analyzer = HoneypotLogAnalyzer()

    # Generate report for last 24 hours
    report = analyzer.generate_full_report(time_range_hours=24)

    # Print summary
    print("\n" + "=" * 70)
    print("SSH Honeypot Analytics Report")
    print("=" * 70)
    print(f"Total Connections: {report['overview']['total_connections']}")
    print(f"Unique IPs: {report['overview']['unique_ips']}")
    print(f"Commands Executed: {report['overview']['total_commands']}")
    print(f"Alerts Triggered: {report['overview']['alerts_triggered']}")
    print("=" * 70)

    # Show top credentials
    if report['credentials']['top_usernames']:
        print("\n📊 Top Usernames:")
        for cred in report['credentials']['top_usernames'][:5]:
            print(f"  • {cred['username']}: {cred['attempts']} attempts")

    if report['credentials']['top_passwords']:
        print("\n🔑 Top Passwords:")
        for cred in report['credentials']['top_passwords'][:5]:
            print(f"  • {cred['password']}: {cred['attempts']} attempts")

    if report['attacks']['attack_patterns']:
        print("\n⚠️  Attack Patterns:")
        for pattern, count in report['attacks']['attack_patterns'].items():
            print(f"  • {pattern}: {count}")

    if report['attacks']['severity_distribution']:
        print("\n🚨 Severity Distribution:")
        for item in report['attacks']['severity_distribution']:
            print(f"  • {item['severity']}: {item['count']}")

    # Export to JSON
    analyzer.export_to_json("analytics_report.json", time_range_hours=24)

    print("\n" + "=" * 70)
    print("Analysis complete!")
    print("=" * 70)