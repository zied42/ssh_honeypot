"""Configuration module for SSH Honeypot"""

import os

# Base Directories
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
LOG_DIR = os.path.join(DATA_DIR, "logs")

# Ensure directories exist
os.makedirs(LOG_DIR, exist_ok=True)

# Authentication settings
COMMON_CREDENTIALS = [
    ("root", "root"),
    ("root", "123456"),
    ("root", "password"),
    ("root", "admin"),
    ("root", "toor"),
    ("admin", "admin"),
    ("admin", "admin123"),
    ("admin", "password"),
    ("ubuntu", "ubuntu"),
    ("pi", "raspberry"),
    ("user", "user"),
    ("test", "test"),
    ("oracle", "oracle"),
    ("postgres", "postgres"),
]
ALLOW_ANY_AFTER_N_FAILS = 3

# Server settings
HOSTNAME = "srv01"
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 2222
WEB_HOST = "127.0.0.1"
WEB_PORT = 5000

# Resource & Rate Limits
MAX_GLOBAL_CONNECTIONS = 50
MAX_PER_IP_CONNECTIONS = 5
IDLE_TIMEOUT = 120  # seconds of inactivity
MAX_SESSION_DURATION = 1800  # 30 minutes max session
MAX_COMMAND_LEN = 4096
CHANNEL_TIMEOUT = 30  # seconds for channel handshake/recv

# Logging settings
AUDIT_LOG = "audits.jsonl"
CMD_LOG = "cmd_audits.jsonl"
ALERT_LOG = "alerts.jsonl"
LOG_MAX_BYTES = 50 * 1024 * 1024  # 50 MB
LOG_BACKUP_COUNT = 20

# SSH settings
HOST_KEY_FILE = os.path.join(DATA_DIR, "host.key")
HOST_KEY_SIZE = 2048
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"

# System emulation settings
SYSTEM_INFO = {
    "kernel": "Linux srv01 5.15.0-101-generic #111-Ubuntu SMP Mon Mar 11 11:00:00 UTC 2024 x86_64 GNU/Linux",
    "os": "Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)",
    "banner": """Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
""",
}