"""Shell emulation module"""

from datetime import datetime, timezone
from fs.fake_fs import fs_get_node, fs_resolve, FAKE_FS
from detection.detector import detect_attack
from logs.logger import cmd_logger, alert_logger
from config.settings import HOSTNAME


def emulated_shell(channel, ip, username, session_id):
    """Run an emulated shell session"""
    home = f"/home/{username}"
    cwd = home

    def prompt():
        display_path = cwd.replace(home, "~") if cwd.startswith(home) else cwd
        return f"{username}@{HOSTNAME}:{display_path}$ ".encode()

    # Send banner
    banner = (
        "Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n"
        "\r\n"
        " * Documentation:  https://help.ubuntu.com\r\n"
        " * Management:     https://landscape.canonical.com\r\n"
        " * Support:        https://ubuntu.com/advantage\r\n"
        "\r\n"
        f"Last login: {datetime.now(timezone.utc).strftime('%a %b %d %H:%M:%S %Y')} from {ip}\r\n"
    )
    channel.send(banner.encode())
    channel.send(prompt())

    command = b""

    while True:
        try:
            char = channel.recv(1)
            if not char:
                break

            # Skip line feed
            if char == b"\n":
                continue

            # Handle backspace
            if char == b"\x7f":
                if command:
                    command = command[:-1]
                    channel.send(b"\b \b")
                continue

            # Echo character
            channel.send(char)

            # Handle carriage return (execute command)
            if char == b"\r":
                channel.send(b"\r\n")
                cmd = command.decode(errors="ignore").strip()
                command = b""

                # Skip empty commands
                if not cmd:
                    channel.send(prompt())
                    continue

                # Log command
                now = datetime.now(timezone.utc).isoformat()
                cmd_logger.info(f"[{session_id}] IP={ip} USER={username} TIME={now} CMD={cmd}")

                # Detect attacks
                severity, hits = detect_attack(cmd)
                if hits:
                    alert_logger.warning(
                        f"[{session_id}] IP={ip} USER={username} SEVERITY={severity} HITS={hits} CMD={cmd}"
                    )

                # Parse command (split only on first space to handle arguments)
                parts = cmd.split(None, 1)
                cmd_name = parts[0] if parts else ""
                cmd_args = parts[1] if len(parts) > 1 else ""

                # Execute commands
                if cmd_name in ("exit", "logout"):
                    channel.send(b"logout\r\n")
                    break

                elif cmd_name == "pwd":
                    channel.send(cwd.encode() + b"\r\n")

                elif cmd_name == "whoami":
                    channel.send(username.encode() + b"\r\n")

                elif cmd_name == "hostname":
                    channel.send(HOSTNAME.encode() + b"\r\n")

                elif cmd_name == "id":
                    channel.send(f"uid=1000({username}) gid=1000({username}) groups=1000({username})\r\n".encode())

                elif cmd_name == "uname":
                    if cmd_args == "-a":
                        channel.send(b"Linux zied-ubuntu 5.15.0-91-generic x86_64 GNU/Linux\r\n")
                    else:
                        channel.send(b"Linux\r\n")

                elif cmd_name == "echo":
                    channel.send((cmd_args + "\r\n").encode())

                elif cmd_name == "ls":
                    # Determine target path
                    target_path = cwd
                    if cmd_args:
                        target_path = fs_resolve(cmd_args, cwd, home)

                    # Get node
                    node = fs_get_node(target_path)

                    if node and node.get("type") == "dir":
                        children = node.get("children", {})
                        if children:
                            items = list(children.keys())
                            channel.send(("  ".join(items) + "\r\n").encode())
                        else:
                            channel.send(b"\r\n")
                    elif node and node.get("type") == "file":
                        # If target is a file, just show the filename
                        filename = target_path.split("/")[-1]
                        channel.send((filename + "\r\n").encode())
                    else:
                        channel.send(b"ls: cannot access: No such file or directory\r\n")

                elif cmd_name == "cd":
                    # Determine target
                    if not cmd_args or cmd_args == "~":
                        target = home
                    else:
                        target = fs_resolve(cmd_args, cwd, home)

                    # Check if target exists and is a directory
                    node = fs_get_node(target)

                    if node and node.get("type") == "dir":
                        cwd = target
                    elif node and node.get("type") == "file":
                        channel.send(b"bash: cd: Not a directory\r\n")
                    else:
                        channel.send(b"bash: cd: No such file or directory\r\n")

                elif cmd_name == "cat":
                    if not cmd_args:
                        channel.send(b"cat: missing operand\r\n")
                    else:
                        # Resolve path
                        path = fs_resolve(cmd_args, cwd, home)
                        node = fs_get_node(path)

                        if node and node.get("type") == "file":
                            content = node.get("content", "")
                            channel.send((content + "\r\n").encode())

                            # Check for canary
                            if node.get("canary"):
                                alert_logger.warning(
                                    f"[{session_id}] IP={ip} USER={username} CANARY_ACCESSED={path}"
                                )
                        elif node and node.get("type") == "dir":
                            channel.send(b"cat: Is a directory\r\n")
                        else:
                            channel.send(b"cat: No such file or directory\r\n")

                elif cmd_name == "sudo":
                    if not cmd_args:
                        channel.send(b"usage: sudo -h | -K | -k | -V\r\n")
                        channel.send(b"usage: sudo -v [-AknS] [-g group] [-h host] [-p prompt] [-u user]\r\n")
                        channel.send(
                            b"usage: sudo -l [-AknS] [-g group] [-h host] [-p prompt] [-U user] [-u user] [command]\r\n")
                        channel.send(
                            b"usage: sudo [-AbEHknPS] [-r role] [-t type] [-C num] [-g group] [-h host] [-p prompt] [-T timeout] [-u user] [VAR=value] [-i|-s] [<command>]\r\n")
                    else:
                        # Simulate password prompt
                        channel.send(b"[sudo] password for " + username.encode() + b": ")

                        # Collect password without echo
                        password = b""
                        while True:
                            try:
                                pwd_char = channel.recv(1)
                                if not pwd_char or pwd_char == b"\r" or pwd_char == b"\n":
                                    channel.send(b"\r\n")
                                    break
                                # Don't echo the character (silent input)
                                password += pwd_char
                            except:
                                break

                        # Log sudo attempt with password
                        pwd_str = password.decode(errors="ignore")
                        cmd_logger.info(
                            f"[{session_id}] IP={ip} USER={username} TIME={datetime.now(timezone.utc).isoformat()} "
                            f"SUDO_PASSWORD_ATTEMPT={pwd_str} SUDO_CMD={cmd_args}"
                        )
                        alert_logger.warning(
                            f"[{session_id}] IP={ip} USER={username} SUDO_ATTEMPT CMD={cmd_args} PASSWORD={pwd_str}"
                        )

                        # Always deny (honeypot behavior - capture credentials)
                        channel.send(b"Sorry, try again.\r\n")
                        channel.send(b"[sudo] password for " + username.encode() + b": ")

                        # Second attempt
                        password2 = b""
                        while True:
                            try:
                                pwd_char = channel.recv(1)
                                if not pwd_char or pwd_char == b"\r" or pwd_char == b"\n":
                                    channel.send(b"\r\n")
                                    break
                                password2 += pwd_char
                            except:
                                break

                        # Log second attempt
                        pwd_str2 = password2.decode(errors="ignore")
                        if pwd_str2:
                            cmd_logger.info(
                                f"[{session_id}] IP={ip} USER={username} "
                                f"SUDO_PASSWORD_ATTEMPT_2={pwd_str2}"
                            )

                        # Final denial
                        channel.send(b"Sorry, try again.\r\n")
                        channel.send(b"sudo: 3 incorrect password attempts\r\n")


                else:
                    channel.send(f"bash: {cmd_name}: command not found\r\n".encode())

                channel.send(prompt())
            else:
                command += char

        except Exception as e:
            print(f"Error in shell: {e}")
            import traceback
            traceback.print_exc()
            break

    channel.close()