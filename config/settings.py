"""Configuration module for SSH Honeypot"""

# Authentication settings
VALID_USERNAME = "admin"
VALID_PASSWORD = "admin123"

# Server settings
HOSTNAME = "zied-ubuntu"
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 2222

# Logging settings
LOG_DIR = "logs"
AUDIT_LOG = "audits.log"
CMD_LOG = "cmd_audits.log"
ALERT_LOG = "alerts.log"
LOG_MAX_BYTES = 5000
LOG_BACKUP_COUNT = 5

# SSH settings
HOST_KEY_FILE = "host.key"
HOST_KEY_SIZE = 2048
SSH_BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"

# System emulation
SYSTEM_INFO = {
    "kernel": "Linux zied-ubuntu 5.15.0-91-generic x86_64 GNU/Linux",
    "os": "Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-91-generic x86_64)",
    "banner": """Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
""",
}