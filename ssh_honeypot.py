import logging
from logging.handlers import RotatingFileHandler
import socket
import threading
import paramiko
import os
import uuid
from datetime import datetime, timezone

# =======================
# CONFIG
# =======================
VALID_USERNAME = "admin"
VALID_PASSWORD = "admin123"
HOSTNAME = "zied-ubuntu"

# =======================
# LOGGING
# =======================
logging_format = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

funnel_logger = logging.getLogger("FunnelLogger")
funnel_logger.setLevel(logging.INFO)
if not funnel_logger.handlers:
    fh = RotatingFileHandler("audits.log", maxBytes=5000, backupCount=5)
    fh.setFormatter(logging_format)
    funnel_logger.addHandler(fh)

cmd_logger = logging.getLogger("CmdLogger")
cmd_logger.setLevel(logging.INFO)
if not cmd_logger.handlers:
    ch = RotatingFileHandler("cmd_audits.log", maxBytes=5000, backupCount=5)
    ch.setFormatter(logging_format)
    cmd_logger.addHandler(ch)

alert_logger = logging.getLogger("AlertLogger")
alert_logger.setLevel(logging.WARNING)
if not alert_logger.handlers:
    ah = RotatingFileHandler("alerts.log", maxBytes=5000, backupCount=5)
    ah.setFormatter(logging_format)
    alert_logger.addHandler(ah)

# =======================
# HOST KEY (stable)
# =======================
if os.path.exists("host.key"):
    host_key = paramiko.RSAKey(filename="host.key")
else:
    host_key = paramiko.RSAKey.generate(2048)
    host_key.write_private_key_file("host.key")

# =======================
# FAKE FILESYSTEM
# =======================
FAKE_FS = {
    "/home/admin": {
        "type": "dir",
        "children": {
            "Documents": {"type": "dir", "children": {}},
            "Downloads": {
                "type": "dir",
                "children": {
                    "tools": {"type": "dir", "children": {}},
                    "payloads": {"type": "dir", "children": {}},
                },
            },
            ".bashrc": {"type": "file", "content": "# bashrc"},
            ".profile": {"type": "file", "content": "# profile"},
            "passwords.txt": {
                "type": "file",
                "content": "root:toor\nadmin:admin123\n",
                "canary": True,  # trap
            },
            "id_rsa": {
                "type": "file",
                "content": "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEKEY\n-----END-----",
                "canary": True,  # trap
            },
        },
    }
}


def fs_resolve(path, cwd, home):
    """Resolve a path relative to cwd or as absolute"""
    if not path or path == "~":
        return home
    if path.startswith("/"):
        return path
    if path == ".":
        return cwd
    if path == "..":
        # Fixed: properly handle parent directory
        if cwd == home or cwd.count("/") <= 2:
            return home
        parent = "/".join(cwd.rstrip("/").split("/")[:-1])
        return parent if parent else "/"
    # Fixed: handle relative paths properly
    return cwd.rstrip("/") + "/" + path


def fs_get_node(path):
    """Get filesystem node at path"""
    if not path or path == "/":
        return None

    # Fixed: handle path resolution properly
    path = path.rstrip("/")
    parts = [p for p in path.split("/") if p]

    # Check if exact path exists in FAKE_FS
    if path in FAKE_FS:
        return FAKE_FS[path]

    # Navigate through filesystem tree
    current = None
    current_path = ""

    for i, part in enumerate(parts):
        current_path = "/" + "/".join(parts[:i + 1])

        # Check if this path exists as a key
        if current_path in FAKE_FS:
            current = FAKE_FS[current_path]
        # Or check if it's a child of current node
        elif current and current.get("children") and part in current["children"]:
            current = current["children"][part]
        else:
            return None

    return current


# =======================
# ATTACK DETECTION
# =======================
SUSPICIOUS = {
    "wget": 2,
    "curl": 2,
    "chmod +x": 3,
    "nc": 3,
    "bash -i": 3,
    "rm -rf": 3,
    "/dev/tcp": 4,  # reverse shell
    "base64": 2,
    "python -c": 3,
    "perl -e": 3,
    "nohup": 2,
}


def detect_attack(cmd):
    """Detect suspicious commands"""
    score = 0
    hits = []
    cmd_lower = cmd.lower()

    for pattern, value in SUSPICIOUS.items():
        if pattern.lower() in cmd_lower:
            score += value
            hits.append(pattern)

    severity = "LOW"
    if score >= 5:
        severity = "HIGH"
    elif score >= 3:
        severity = "MEDIUM"

    return severity, hits


# =======================
# SSH SERVER
# =======================
class HoneypotServer(paramiko.ServerInterface):
    def __init__(self):
        self.username = None

    def check_auth_password(self, username, password):
        self.username = username
        funnel_logger.info(f"AUTH ATTEMPT {username}:{password}")
        if username == VALID_USERNAME and password == VALID_PASSWORD:
            funnel_logger.info("AUTH SUCCESS")
            return paramiko.AUTH_SUCCESSFUL
        funnel_logger.info("AUTH FAILED")
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, *args):
        return True


# =======================
# SHELL
# =======================
def emulated_shell(channel, ip, username, session_id):
    home = f"/home/{username}"
    cwd = home

    def prompt():
        # Fixed: show proper relative path
        display_path = cwd.replace(home, "~") if cwd.startswith(home) else cwd
        return f"{username}@{HOSTNAME}:{display_path}$ ".encode()

    channel.send(prompt())
    command = b""

    while True:
        char = channel.recv(1)
        if not char:
            channel.send(b"\r\nlogout\r\n")
            break

        if char in (b"\n",):
            continue

        if char == b"\x7f":
            if command:
                command = command[:-1]
                channel.send(b"\b \b")
            continue

        channel.send(char)

        if char == b"\r":
            channel.send(b"\r\n")
            cmd = command.decode(errors="ignore").strip()

            # ---- log command
            now = datetime.now(timezone.utc).isoformat()
            cmd_logger.info(
                f"[{session_id}] IP={ip} USER={username} TIME={now} CMD={cmd}"
            )

            # ---- detection
            severity, hits = detect_attack(cmd)
            if hits:
                alert_logger.warning(
                    f"[{session_id}] IP={ip} USER={username} SEVERITY={severity} HITS={hits} CMD={cmd}"
                )

            # ---- commands
            if cmd in ("exit", "logout"):
                channel.send(b"logout\r\n")
                break

            elif cmd == "pwd":
                channel.send(cwd.encode() + b"\r\n")

            elif cmd == "whoami":
                channel.send(username.encode() + b"\r\n")

            elif cmd == "uname -a":
                channel.send(b"Linux zied-ubuntu 5.15.0 x86_64 GNU/Linux\r\n")

            elif cmd.startswith("ls"):
                # Fixed: handle ls with arguments
                parts = cmd.split(maxsplit=1)
                target_path = cwd

                if len(parts) == 2:
                    # ls with path argument
                    target_path = fs_resolve(parts[1], cwd, home)

                node = fs_get_node(target_path)
                if node and node.get("type") == "dir" and node.get("children"):
                    items = list(node["children"].keys())
                    channel.send(("  ".join(items) + "\r\n").encode())
                elif node and node.get("type") == "file":
                    # ls on a file shows the filename
                    filename = target_path.split("/")[-1]
                    channel.send((filename + "\r\n").encode())
                else:
                    channel.send(b"ls: cannot access: No such file or directory\r\n")

            elif cmd.startswith("cd"):
                parts = cmd.split(maxsplit=1)
                target = parts[1] if len(parts) == 2 else "~"
                newp = fs_resolve(target, cwd, home)
                node = fs_get_node(newp)

                # Fixed: check if node is a directory
                if node and node.get("type") == "dir":
                    cwd = newp
                elif node and node.get("type") == "file":
                    channel.send(b"bash: cd: Not a directory\r\n")
                else:
                    channel.send(b"bash: cd: No such file or directory\r\n")

            elif cmd.startswith("cat"):
                parts = cmd.split(maxsplit=1)
                if len(parts) != 2:
                    channel.send(b"cat: missing operand\r\n")
                else:
                    path = fs_resolve(parts[1], cwd, home)
                    node = fs_get_node(path)
                    if node and node.get("type") == "file":
                        channel.send((node.get("content", "") + "\r\n").encode())
                        if node.get("canary"):
                            alert_logger.warning(
                                f"[{session_id}] IP={ip} USER={username} CANARY_ACCESSED={path}"
                            )
                    elif node and node.get("type") == "dir":
                        channel.send(b"cat: Is a directory\r\n")
                    else:
                        channel.send(b"cat: No such file or directory\r\n")

            elif cmd.startswith("sudo"):
                # Fixed: log sudo attempts as suspicious
                alert_logger.warning(
                    f"[{session_id}] IP={ip} USER={username} SUDO_ATTEMPT CMD={cmd}"
                )
                channel.send(b"[sudo] password for admin: \r\n")
                channel.send(b"Sorry, try again.\r\n")

            elif cmd == "":
                pass

            else:
                channel.send(b"bash: command not found\r\n")

            command = b""
            channel.send(prompt())
        else:
            command += char

    channel.close()


# =======================
# CONNECTION HANDLER
# =======================
def handle_connection(client, addr):
    session_id = str(uuid.uuid4())[:8]
    start = datetime.now(timezone.utc)

    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(host_key)
        server = HoneypotServer()
        transport.start_server(server=server)

        channel = transport.accept(20)
        if channel:
            funnel_logger.info(
                f"[{session_id}] SESSION START IP={addr[0]} USER={server.username}"
            )
            emulated_shell(channel, addr[0], server.username, session_id)
            end = datetime.now(timezone.utc)
            duration = (end - start).total_seconds()
            funnel_logger.info(
                f"[{session_id}] SESSION END IP={addr[0]} USER={server.username} DURATION={duration}s"
            )

        transport.close()
        client.close()

    except Exception as e:
        funnel_logger.error(f"[{session_id}] ERROR {addr[0]} {e}")
        try:
            client.close()
        except:
            pass


# =======================
# START
# =======================
def start_honeypot(host="0.0.0.0", port=2222):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(100)
    funnel_logger.info(f"Honeypot listening on {host}:{port}")

    while True:
        client, addr = sock.accept()
        funnel_logger.info(f"CONNECTION FROM {addr[0]}")
        threading.Thread(
            target=handle_connection,
            args=(client, addr),
            daemon=True
        ).start()


start_honeypot()