"""Detection module for analyzing shell commands with Regex, MITRE ATT&CK mapping, and IOC extraction"""

import re

# Threat Rules Definition
RULES = [
    {
        "name": "wget_download",
        "pattern": re.compile(r"\bwget\b", re.IGNORECASE),
        "severity": "HIGH",
        "category": "download_execute",
        "mitre": ["T1105"]
    },
    {
        "name": "curl_download",
        "pattern": re.compile(r"\bcurl\b", re.IGNORECASE),
        "severity": "HIGH",
        "category": "download_execute",
        "mitre": ["T1105"]
    },
    {
        "name": "tftp_download",
        "pattern": re.compile(r"\btftp\b", re.IGNORECASE),
        "severity": "HIGH",
        "category": "download_execute",
        "mitre": ["T1105"]
    },
    {
        "name": "chmod_execution",
        "pattern": re.compile(r"\bchmod\s+(\+x|[0-7]{3,4})\b", re.IGNORECASE),
        "severity": "MEDIUM",
        "category": "download_execute",
        "mitre": ["T1222.002"]
    },
    {
        "name": "netcat_reverse_shell",
        "pattern": re.compile(r"\b(nc|netcat|ncat|cryptcat|socat)\b", re.IGNORECASE),
        "severity": "HIGH",
        "category": "download_execute",
        "mitre": ["T1095", "T1059.004"]
    },
    {
        "name": "interactive_shell",
        "pattern": re.compile(r"\b(bash|sh|zsh|dash)\s+-i\b", re.IGNORECASE),
        "severity": "HIGH",
        "category": "download_execute",
        "mitre": ["T1059.004"]
    },
    {
        "name": "dev_tcp_redirection",
        "pattern": re.compile(r"/dev/(tcp|udp)/", re.IGNORECASE),
        "severity": "HIGH",
        "category": "download_execute",
        "mitre": ["T1059.004"]
    },
    {
        "name": "destructive_deletion",
        "pattern": re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\b", re.IGNORECASE),
        "severity": "HIGH",
        "category": "destructive",
        "mitre": ["T1070.004"]
    },
    {
        "name": "base64_decode",
        "pattern": re.compile(r"\bbase64\b", re.IGNORECASE),
        "severity": "MEDIUM",
        "category": "download_execute",
        "mitre": ["T1140"]
    },
    {
        "name": "script_inline_exec",
        "pattern": re.compile(r"\b(python[23]?|perl|ruby|php|awk)\s+(-c|-e|'BEGIN)\b", re.IGNORECASE),
        "severity": "HIGH",
        "category": "download_execute",
        "mitre": ["T1059"]
    },
    {
        "name": "cron_persistence",
        "pattern": re.compile(r"\bcrontab\b|/etc/cron", re.IGNORECASE),
        "severity": "HIGH",
        "category": "persistence",
        "mitre": ["T1053.003"]
    },
    {
        "name": "service_persistence",
        "pattern": re.compile(r"\b(systemctl|service)\b", re.IGNORECASE),
        "severity": "MEDIUM",
        "category": "persistence",
        "mitre": ["T1543.002"]
    },
    {
        "name": "credential_access_passwd",
        "pattern": re.compile(r"/etc/(passwd|shadow)", re.IGNORECASE),
        "severity": "MEDIUM",
        "category": "credential_access",
        "mitre": ["T1003.008"]
    },
    {
        "name": "authorized_keys_persistence",
        "pattern": re.compile(r"authorized_keys", re.IGNORECASE),
        "severity": "HIGH",
        "category": "persistence",
        "mitre": ["T1098.004"]
    },
    {
        "name": "ssh_lateral_movement",
        "pattern": re.compile(r"\b(ssh|scp|sftp)\b", re.IGNORECASE),
        "severity": "MEDIUM",
        "category": "lateral_movement",
        "mitre": ["T1021.004"]
    },
    {
        "name": "system_recon",
        "pattern": re.compile(r"\b(whoami|id|uname|lscpu|nproc|free|df|ifconfig|ip\s+a|uptime|w)\b", re.IGNORECASE),
        "severity": "LOW",
        "category": "recon",
        "mitre": ["T1082"]
    }
]

# Regex patterns for IOC extraction
URL_PATTERN = re.compile(r"https?://[^\s'\"<>]+|ftp://[^\s'\"<>]+", re.IGNORECASE)
IP_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")


def extract_iocs(command):
    """Extract URLs, IPs, MD5 and SHA256 hashes from a command string"""
    if not command:
        return {}

    urls = URL_PATTERN.findall(command)
    raw_ips = IP_PATTERN.findall(command)
    valid_ips = []
    for ip in raw_ips:
        octets = ip.split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            # Exclude loopback or local subnet if needed, or keep all
            if ip not in ("127.0.0.1", "0.0.0.0"):
                valid_ips.append(ip)

    md5_hashes = MD5_PATTERN.findall(command)
    sha256_hashes = SHA256_PATTERN.findall(command)

    iocs = {}
    if urls:
        iocs["urls"] = list(set(urls))
    if valid_ips:
        iocs["ips"] = list(set(valid_ips))
    if md5_hashes:
        iocs["md5"] = list(set(md5_hashes))
    if sha256_hashes:
        iocs["sha256"] = list(set(sha256_hashes))

    return iocs


def detect_attack(cmd):
    """
    Analyze command with regex rules and word boundaries.
    Returns: (severity, matched_rules, category, mitre_attack, iocs)
    """
    if not cmd:
        return "LOW", [], "recon", [], {}

    matched_rules = []
    categories = set()
    mitre_ids = set()
    highest_severity_val = 0
    sev_map = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

    for rule in RULES:
        if rule["pattern"].search(cmd):
            matched_rules.append(rule["name"])
            categories.add(rule["category"])
            mitre_ids.update(rule["mitre"])
            val = sev_map.get(rule["severity"], 1)
            if val > highest_severity_val:
                highest_severity_val = val

    inv_sev_map = {0: "LOW", 1: "LOW", 2: "MEDIUM", 3: "HIGH"}
    severity = inv_sev_map[highest_severity_val]

    primary_category = list(categories)[0] if categories else "recon"
    iocs = extract_iocs(cmd)

    return severity, matched_rules, primary_category, list(mitre_ids), iocs