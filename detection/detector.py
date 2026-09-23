"""Attack detection patterns"""

SUSPICIOUS = {
    # Existing patterns
    "wget": 2,
    "curl": 2,
    "chmod +x": 3,
    "nc": 3,
    "bash -i": 3,
    "rm -rf": 3,
    "/dev/tcp": 4,
    "base64": 2,
    "python -c": 3,
    "perl -e": 3,
    "nohup": 2,

    # Additional malicious patterns
    "sh -i": 3,
    "/bin/sh": 2,
    "/bin/bash": 2,
    "mkfifo": 3,
    "telnet": 2,
    "exec": 2,
    "eval": 3,
    ">& /dev/tcp": 4,
    "0>&1": 3,
    "awk 'BEGIN": 3,
    "socat": 3,
    "openssl": 2,
    "cryptcat": 4,
    "/tmp/": 2,
    "&&": 1,
    ";": 1,
    "|": 1,
    "$(": 2,
    "`": 2,
    "http://": 2,
    "https://": 2,
    "ftp://": 2,
    ".sh": 2,
    "whoami": 1,
    "uname -a": 1,
    "/etc/passwd": 3,
    "/etc/shadow": 4,
    "crontab": 2,
    "systemctl": 2,
    "service": 2,
}

def detect_attack(cmd):
    """Detect suspicious commands and return severity"""
    score = 0
    hits = []
    cmd_lower = cmd.lower()

    for pattern, value in SUSPICIOUS.items():
        if pattern.lower() in cmd_lower:
            score += value
            hits.append(pattern)

    # Determine severity
    severity = "LOW"
    if score >= 5:
        severity = "HIGH"
    elif score >= 3:
        severity = "MEDIUM"

    return severity, hits