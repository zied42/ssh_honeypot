"""Interactive and Non-Interactive Shell Emulation Engine for SSH Honeypot"""

import re
import socket
from datetime import datetime, timezone
from config.settings import HOSTNAME, SYSTEM_INFO, MAX_COMMAND_LEN
from detection.detector import detect_attack, extract_iocs
from fs.fake_fs import (
    fs_get_node,
    fs_resolve,
    fs_mkdir,
    fs_touch,
    fs_rm,
    fs_write_file,
    ensure_user_home,
    normalize_path,
)
from honeylog.logger import cmd_logger, alert_logger, log_event, log_alert


def split_command_line(full_cmd):
    """Split complex command lines on ';', '&&', '||', and '|'"""
    if not full_cmd:
        return []
    # Tokenize operators preserving strings
    tokens = re.split(r"(&&|\|\||;|\|)", full_cmd)
    subcommands = []
    current = ""
    for token in tokens:
        if token in ("&&", "||", ";", "|"):
            if current.strip():
                subcommands.append(current.strip())
            current = ""
        else:
            current += token
    if current.strip():
        subcommands.append(current.strip())
    return subcommands if subcommands else [full_cmd.strip()]


def execute_emulated_command(raw_cmd, cwd, username, session_id, ip, history):
    """
    Execute a single emulated command in memory.
    Returns: (output_text, new_cwd, should_exit)
    """
    if len(raw_cmd) > MAX_COMMAND_LEN:
        raw_cmd = raw_cmd[:MAX_COMMAND_LEN]

    history.append(raw_cmd)
    home = f"/root" if username == "root" else f"/home/{username}"

    # Handle file output redirection ('>' or '>>')
    redirect_target = None
    append_mode = False

    if " >> " in raw_cmd or " >>" in raw_cmd:
        parts = raw_cmd.split(">>", 1)
        raw_cmd = parts[0].strip()
        redirect_target = parts[1].strip()
        append_mode = True
    elif " > " in raw_cmd or " >" in raw_cmd:
        parts = raw_cmd.split(">", 1)
        raw_cmd = parts[0].strip()
        redirect_target = parts[1].strip()
        append_mode = False

    parts = raw_cmd.split(None, 1)
    cmd_name = parts[0] if parts else ""
    cmd_args = parts[1] if len(parts) > 1 else ""

    output = ""
    new_cwd = cwd
    should_exit = False

    if cmd_name in ("exit", "logout"):
        should_exit = True
        return output, new_cwd, should_exit

    elif cmd_name == "pwd":
        output = cwd + "\n"

    elif cmd_name == "whoami":
        output = username + "\n"

    elif cmd_name == "hostname":
        output = HOSTNAME + "\n"

    elif cmd_name == "id":
        if username == "root":
            output = "uid=0(root) gid=0(root) groups=0(root)\n"
        else:
            output = f"uid=1000({username}) gid=1000({username}) groups=1000({username})\n"

    elif cmd_name == "uname":
        if "-a" in cmd_args or "--all" in cmd_args:
            output = SYSTEM_INFO["kernel"] + "\n"
        elif "-r" in cmd_args:
            output = "5.15.0-101-generic\n"
        elif "-n" in cmd_args:
            output = f"{HOSTNAME}\n"
        elif "-m" in cmd_args:
            output = "x86_64\n"
        elif "-s" in cmd_args:
            output = "Linux\n"
        elif "-v" in cmd_args:
            output = "#111-Ubuntu SMP Mon Mar 11 11:00:00 UTC 2024\n"
        elif "-o" in cmd_args:
            output = "GNU/Linux\n"
        else:
            output = "Linux\n"

    elif cmd_name == "ps":
        output = (
            "  PID TTY          TIME CMD\n"
            " 1201 pts/0    00:00:00 bash\n"
            " 1245 pts/0    00:00:00 ps\n"
        )

    elif cmd_name in ("free", "free -m"):
        output = (
            "               total        used        free      shared  buff/cache   available\n"
            "Mem:            3924         845        2095          12         983        2815\n"
            "Swap:           2047           0        2047\n"
        )

    elif cmd_name in ("df", "df -h"):
        output = (
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/sda1        49G  8.2G   39G  18% /\n"
            "none            4.0M     0  4.0M   0% /sys/fs/cgroup\n"
            "udev             1.9G     0  1.9G   0% /dev\n"
            "tmpfs            393M  1.2M  392M   1% /run\n"
        )

    elif cmd_name in ("w", "uptime"):
        output = " 14:22:01 up 12 days,  4:18,  1 user,  load average: 0.04, 0.03, 0.00\n"

    elif cmd_name == "lscpu":
        output = (
            "Architecture:            x86_64\n"
            "CPU op-mode(s):          32-bit, 64-bit\n"
            "Address sizes:           46 bits physical, 48 bits virtual\n"
            "Byte Order:              Little Endian\n"
            "CPU(s):                  2\n"
            "On-line CPU(s) list:     0,1\n"
            "Vendor ID:               GenuineIntel\n"
            "Model name:              Intel(R) Xeon(R) CPU @ 2.20GHz\n"
        )

    elif cmd_name == "nproc":
        output = "2\n"

    elif cmd_name in ("ifconfig", "ip"):
        output = (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
            "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
            "    inet 127.0.0.1/8 scope host lo\n"
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n"
            "    link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff\n"
            "    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0\n"
        )

    elif cmd_name == "history":
        lines = [f"  {idx+1}  {item}" for idx, item in enumerate(history)]
        output = "\n".join(lines) + "\n"

    elif cmd_name == "env":
        output = (
            f"USER={username}\n"
            f"HOME={home}\n"
            f"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
            "SHELL=/bin/bash\n"
            "TERM=xterm-256color\n"
            f"HOSTNAME={HOSTNAME}\n"
        )

    elif cmd_name == "which":
        if cmd_args in ("bash", "sh", "ls", "cat", "pwd", "whoami", "id", "uname", "wget", "curl", "python"):
            output = f"/usr/bin/{cmd_args}\n"
        else:
            output = ""

    elif cmd_name == "echo":
        output = cmd_args + "\n"

    elif cmd_name == "ls":
        target = cwd
        show_all = "-a" in cmd_args or "-la" in cmd_args or "-al" in cmd_args
        show_long = "-l" in cmd_args or "-la" in cmd_args or "-al" in cmd_args

        # Strip flags to find target path
        clean_args = [a for a in cmd_args.split() if not a.startswith("-")]
        if clean_args:
            target = fs_resolve(clean_args[0], cwd, home)

        node = fs_get_node(target)
        if node and node.get("type") == "dir":
            children = node.get("children", {})
            items = list(children.keys())
            if show_all:
                items = [".", ".."] + items
            if show_long:
                lines = []
                for item in items:
                    if item in (".", ".."):
                        lines.append(f"drwxr-xr-x 2 {username} {username} 4096 Mar 23 12:00 {item}")
                    else:
                        child = children.get(item, {})
                        c_type = "d" if child.get("type") == "dir" else "-"
                        mode = child.get("mode", f"{c_type}rwxr-xr-x" if c_type == "d" else "-rw-r--r--")
                        owner = child.get("owner", username)
                        group = child.get("group", username)
                        size = len(child.get("content", "")) if c_type == "-" else 4096
                        lines.append(f"{mode} 1 {owner} {group} {size:4d} Mar 23 12:00 {item}")
                output = "\n".join(lines) + "\n"
            else:
                output = "  ".join(items) + "\n" if items else "\n"
        elif node and node.get("type") == "file":
            filename = target.split("/")[-1]
            output = filename + "\n"
        else:
            output = "ls: cannot access: No such file or directory\n"

    elif cmd_name == "cd":
        if not cmd_args or cmd_args == "~":
            target = home
        else:
            target = fs_resolve(cmd_args.split()[0], cwd, home)

        node = fs_get_node(target)
        if node and node.get("type") == "dir":
            new_cwd = target
        elif node and node.get("type") == "file":
            output = "bash: cd: Not a directory\n"
        else:
            output = "bash: cd: No such file or directory\n"

    elif cmd_name == "cat":
        if not cmd_args:
            output = "cat: missing operand\n"
        else:
            filepath = fs_resolve(cmd_args.split()[0], cwd, home)
            node = fs_get_node(filepath)
            if node and node.get("type") == "file":
                output = node.get("content", "")
                if not output.endswith("\n") and output:
                    output += "\n"
                if node.get("canary"):
                    log_alert(
                        session_id=session_id,
                        src_ip=ip,
                        username=username,
                        severity="HIGH",
                        hits=["canary_access"],
                        category="credential_access",
                        mitre_attack=["T1003.008"],
                        command=f"cat {filepath}",
                        iocs={}
                    )
            elif node and node.get("type") == "dir":
                output = "cat: Is a directory\n"
            else:
                output = "cat: No such file or directory\n"

    elif cmd_name == "mkdir":
        if not cmd_args:
            output = "mkdir: missing operand\n"
        else:
            target = fs_resolve(cmd_args.split()[0], cwd, home)
            ok, err = fs_mkdir(target, owner=username)
            if not ok:
                output = f"mkdir: cannot create directory '{cmd_args}': {err}\n"

    elif cmd_name == "touch":
        if not cmd_args:
            output = "touch: missing operand\n"
        else:
            target = fs_resolve(cmd_args.split()[0], cwd, home)
            ok, err = fs_touch(target, owner=username)
            if not ok:
                output = f"touch: cannot touch '{cmd_args}': {err}\n"

    elif cmd_name == "rm":
        if not cmd_args:
            output = "rm: missing operand\n"
        else:
            recursive = "-r" in cmd_args or "-rf" in cmd_args or "-fr" in cmd_args
            clean_args = [a for a in cmd_args.split() if not a.startswith("-")]
            if clean_args:
                target = fs_resolve(clean_args[0], cwd, home)
                ok, err = fs_rm(target, recursive=recursive)
                if not ok:
                    output = f"rm: cannot remove '{clean_args[0]}': {err}\n"

    elif cmd_name == "chmod":
        output = ""

    elif cmd_name in ("wget", "curl", "tftp"):
        urls = extract_iocs(raw_cmd).get("urls", [])
        url_str = urls[0] if urls else "http://example.com/file"
        filename = url_str.split("/")[-1] or "payload"

        # Touch file in fake fs so subsequent chmod/execution succeeds
        file_path = fs_resolve(filename, cwd, home)
        fs_touch(file_path, owner=username)

        if cmd_name == "wget":
            output = (
                f"--{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}--  {url_str}\n"
                f"Resolving server... connected.\n"
                f"HTTP request sent, awaiting response... 200 OK\n"
                f"Length: 1048576 (1.0M) [application/octet-stream]\n"
                f"Saving to: '{filename}'\n\n"
                f"{filename:20s} 100%[===================>]   1.00M  --.-KB/s    in 0.1s\n\n"
                f"'{filename}' saved [1048576/1048576]\n"
            )
        else:
            output = (
                f"  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
                f"                                 Dload  Upload   Total   Spent    Left  Speed\n"
                f"100 1024k  100 1024k    0     0  2048k      0 --:--:-- --:--:-- --:--:-- 2048k\n"
            )

    else:
        output = f"bash: {cmd_name}: command not found\n"

    # Handle output redirection if specified
    if redirect_target:
        target_path = fs_resolve(redirect_target, cwd, home)
        fs_write_file(
            target_path,
            output,
            append=append_mode,
            owner=username,
            session_id=session_id,
            src_ip=ip,
            username=username
        )
        output = ""

    return output, new_cwd, should_exit


def process_command_line(full_cmd, cwd, username, session_id, ip, history):
    """
    Log full command line, split into subcommands, detect threats, and execute.
    Returns: (output_str, new_cwd, should_exit)
    """
    if not full_cmd:
        return "", cwd, False

    # Log full raw command line
    log_event(
        cmd_logger,
        event_type="command",
        session_id=session_id,
        src_ip=ip,
        username=username,
        command=full_cmd
    )

    # Detect threats on full command line
    severity, matched_rules, category, mitre_attack, iocs = detect_attack(full_cmd)

    # Only log alerts at WARNING for MEDIUM and HIGH severity!
    if severity in ("MEDIUM", "HIGH"):
        log_alert(
            session_id=session_id,
            src_ip=ip,
            username=username,
            severity=severity,
            hits=matched_rules,
            category=category,
            mitre_attack=mitre_attack,
            command=full_cmd,
            iocs=iocs
        )

    # Split and process subcommands
    subcommands = split_command_line(full_cmd)
    combined_output = []
    current_cwd = cwd
    exit_requested = False

    for sub_cmd in subcommands:
        out, current_cwd, should_exit = execute_emulated_command(
            sub_cmd, current_cwd, username, session_id, ip, history
        )
        if out:
            combined_output.append(out)
        if should_exit:
            exit_requested = True
            break

    final_output = "".join(combined_output)
    return final_output, current_cwd, exit_requested


def handle_exec_mode(channel, exec_command, ip, username, session_id):
    """Process non-interactive SSH exec mode commands (ssh user@host 'cmd')"""
    home = ensure_user_home(username)
    history = []
    output, _, _ = process_command_line(exec_command, home, username, session_id, ip, history)
    if output:
        # Convert \n to \r\n for terminal formatting
        formatted_output = output.replace("\n", "\r\n")
        channel.send(formatted_output.encode("utf-8"))
    try:
        channel.send_exit_status(0)
    except Exception:
        pass


def emulated_shell(channel, ip, username, session_id):
    """Run an emulated interactive SSH shell session"""
    home = ensure_user_home(username)
    cwd = home
    history = []

    def make_prompt(current_cwd):
        disp = current_cwd.replace(home, "~") if current_cwd.startswith(home) else current_cwd
        symbol = "#" if username == "root" else "$"
        return f"{username}@{HOSTNAME}:{disp}{symbol} ".encode("utf-8")

    # Send SSH banner
    banner = (
        f"{SYSTEM_INFO['banner']}\r\n"
        f"Last login: {datetime.now(timezone.utc).strftime('%a %b %d %H:%M:%S %Y')} from {ip}\r\n"
    )
    channel.send(banner.encode("utf-8"))
    channel.send(make_prompt(cwd))

    cmd_buffer = b""

    while True:
        try:
            char = channel.recv(1)
            if not char:
                break

            # Handle ANSI escape sequences (e.g. arrow keys \x1b[A)
            if char == b"\x1b":
                # Drain trailing sequence characters
                channel.settimeout(0.05)
                try:
                    while True:
                        seq = channel.recv(1)
                        if not seq or seq in (b"A", b"B", b"C", b"D", b"~"):
                            break
                except Exception:
                    pass
                channel.settimeout(None)
                continue

            # Handle Ctrl-C (\x03)
            if char == b"\x03":
                cmd_buffer = b""
                channel.send(b"^C\r\n")
                channel.send(make_prompt(cwd))
                continue

            # Handle Ctrl-D (\x04)
            if char == b"\x04":
                if not cmd_buffer:
                    channel.send(b"logout\r\n")
                    break
                continue

            # Handle line feed
            if char == b"\n":
                continue

            # Handle backspace (\x08, \x7f)
            if char in (b"\x08", b"\x7f"):
                if cmd_buffer:
                    cmd_buffer = cmd_buffer[:-1]
                    channel.send(b"\b \b")
                continue

            # Handle carriage return (Execute command)
            if char == b"\r":
                channel.send(b"\r\n")
                raw_line = cmd_buffer.decode("utf-8", errors="ignore").strip()
                cmd_buffer = b""

                if not raw_line:
                    channel.send(make_prompt(cwd))
                    continue

                output, cwd, should_exit = process_command_line(
                    raw_line, cwd, username, session_id, ip, history
                )

                if output:
                    formatted = output.replace("\n", "\r\n")
                    channel.send(formatted.encode("utf-8"))

                if should_exit:
                    channel.send(b"logout\r\n")
                    break

                channel.send(make_prompt(cwd))
            else:
                cmd_buffer += char
                channel.send(char)

        except socket.timeout:
            continue
        except Exception as e:
            break

    try:
        channel.close()
    except Exception:
        pass