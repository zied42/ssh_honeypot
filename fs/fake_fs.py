"""In-memory Fake Linux Filesystem for SSH Honeypot"""

import copy
from config.settings import HOSTNAME
from honeylog.logger import alert_logger, log_alert

# Initial Filesystem Graph
DEFAULT_TREE = {
    "/": {
        "type": "dir",
        "owner": "root",
        "group": "root",
        "mode": "drwxr-xr-x",
        "children": {
            "bin": {"type": "dir", "owner": "root", "group": "root", "mode": "drwxr-xr-x", "children": {}},
            "boot": {"type": "dir", "owner": "root", "group": "root", "mode": "drwxr-xr-x", "children": {}},
            "dev": {"type": "dir", "owner": "root", "group": "root", "mode": "drwxr-xr-x", "children": {}},
            "etc": {
                "type": "dir",
                "owner": "root",
                "group": "root",
                "mode": "drwxr-xr-x",
                "children": {
                    "passwd": {
                        "type": "file",
                        "owner": "root",
                        "group": "root",
                        "mode": "-rw-r--r--",
                        "content": (
                            "root:x:0:0:root:/root:/bin/bash\n"
                            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                            "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
                            "sync:x:4:65534:sync:/bin:/bin/sync\n"
                            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                            "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
                            "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
                        )
                    },
                    "shadow": {
                        "type": "file",
                        "owner": "root",
                        "group": "shadow",
                        "mode": "-rw-r-----",
                        "content": "root:$6$v.xY8T9L$7sP1g...:19500:0:99999:7:::\nubuntu:$6$k3M1...:19500:0:99999:7:::\n"
                    },
                    "hostname": {
                        "type": "file",
                        "owner": "root",
                        "group": "root",
                        "mode": "-rw-r--r--",
                        "content": f"{HOSTNAME}\n"
                    },
                    "os-release": {
                        "type": "file",
                        "owner": "root",
                        "group": "root",
                        "mode": "-rw-r--r--",
                        "content": (
                            'NAME="Ubuntu"\n'
                            'VERSION="22.04.4 LTS (Jammy Jellyfish)"\n'
                            'ID=ubuntu\n'
                            'ID_LIKE=debian\n'
                            'PRETTY_NAME="Ubuntu 22.04.4 LTS"\n'
                            'VERSION_ID="22.04"\n'
                        )
                    },
                    "issue": {
                        "type": "file",
                        "owner": "root",
                        "group": "root",
                        "mode": "-rw-r--r--",
                        "content": "Ubuntu 22.04.4 LTS \\n \\l\n\n"
                    }
                }
            },
            "home": {"type": "dir", "owner": "root", "group": "root", "mode": "drwxr-xr-x", "children": {}},
            "lib": {"type": "dir", "owner": "root", "group": "root", "mode": "drwxr-xr-x", "children": {}},
            "proc": {
                "type": "dir",
                "owner": "root",
                "group": "root",
                "mode": "dr-xr-xr-x",
                "children": {
                    "cpuinfo": {
                        "type": "file",
                        "owner": "root",
                        "group": "root",
                        "mode": "-r--r--r--",
                        "content": (
                            "processor\t: 0\n"
                            "vendor_id\t: GenuineIntel\n"
                            "cpu family\t: 6\n"
                            "model name\t: Intel(R) Xeon(R) CPU @ 2.20GHz\n"
                            "cpu MHz\t\t: 2199.998\n"
                            "cache size\t: 16384 KB\n"
                            "cpu cores\t: 2\n\n"
                            "processor\t: 1\n"
                            "vendor_id\t: GenuineIntel\n"
                            "cpu family\t: 6\n"
                            "model name\t: Intel(R) Xeon(R) CPU @ 2.20GHz\n"
                            "cpu MHz\t\t: 2199.998\n"
                            "cache size\t: 16384 KB\n"
                            "cpu cores\t: 2\n"
                        )
                    },
                    "meminfo": {
                        "type": "file",
                        "owner": "root",
                        "group": "root",
                        "mode": "-r--r--r--",
                        "content": (
                            "MemTotal:        4018264 kB\n"
                            "MemFree:         2145892 kB\n"
                            "MemAvailable:    3104520 kB\n"
                            "Buffers:          124580 kB\n"
                            "Cached:           985412 kB\n"
                            "SwapTotal:       2097148 kB\n"
                            "SwapFree:        2097148 kB\n"
                        )
                    },
                    "version": {
                        "type": "file",
                        "owner": "root",
                        "group": "root",
                        "mode": "-r--r--r--",
                        "content": "Linux version 5.15.0-101-generic (buildd@lcy02-amd64-046) (gcc 11.4.0) #111-Ubuntu SMP\n"
                    }
                }
            },
            "root": {
                "type": "dir",
                "owner": "root",
                "group": "root",
                "mode": "drwx------",
                "children": {
                    ".bashrc": {"type": "file", "owner": "root", "group": "root", "mode": "-rw-r--r--", "content": "# root bashrc\n"},
                    ".profile": {"type": "file", "owner": "root", "group": "root", "mode": "-rw-r--r--", "content": "# root profile\n"},
                    ".ssh": {"type": "dir", "owner": "root", "group": "root", "mode": "drwx------", "children": {}}
                }
            },
            "tmp": {"type": "dir", "owner": "root", "group": "root", "mode": "drwxrwxrwt", "children": {}},
            "usr": {"type": "dir", "owner": "root", "group": "root", "mode": "drwxr-xr-x", "children": {}},
            "var": {
                "type": "dir",
                "owner": "root",
                "group": "root",
                "mode": "drwxr-xr-x",
                "children": {
                    "log": {
                        "type": "dir",
                        "owner": "root",
                        "group": "root",
                        "mode": "drwxr-xr-x",
                        "children": {
                            "auth.log": {"type": "file", "owner": "root", "group": "adm", "mode": "-rw-r-----", "content": "Mar 23 12:00:01 srv01 sshd[1234]: Server listening on 0.0.0.0 port 22.\n"},
                            "syslog": {"type": "file", "owner": "syslog", "group": "adm", "mode": "-rw-r-----", "content": "Mar 23 12:00:00 srv01 systemd[1]: Started System Logging Service.\n"}
                        }
                    }
                }
            }
        }
    }
}

# Active working memory filesystem tree
FAKE_FS = copy.deepcopy(DEFAULT_TREE)


def normalize_path(path):
    """Normalize a path eliminating duplicate slashes and relative components"""
    if not path:
        return "/"
    parts = []
    for p in path.split("/"):
        if p == "" or p == ".":
            continue
        elif p == "..":
            if parts:
                parts.pop()
        else:
            parts.append(p)
    return "/" + "/".join(parts)


def fs_resolve(path, cwd="/root", home="/root"):
    """Resolve relative, absolute, or tilde paths"""
    if not path or path == "~":
        return home
    if path.startswith("~/"):
        return home.rstrip("/") + "/" + path[2:]
    if path.startswith("/"):
        return normalize_path(path)
    return normalize_path(cwd.rstrip("/") + "/" + path)


def fs_get_node(path):
    """Retrieve node dict at given absolute path, returns None if not found"""
    norm = normalize_path(path)
    if norm == "/":
        return FAKE_FS["/"]

    parts = [p for p in norm.split("/") if p]
    current = FAKE_FS["/"]

    for part in parts:
        if current.get("type") != "dir" or "children" not in current:
            return None
        children = current["children"]
        if part not in children:
            return None
        current = children[part]

    return current


def ensure_user_home(username):
    """Ensure /home/<username> (or /root) exists for authenticated user"""
    if username == "root":
        return "/root"

    home_dir = f"/home/{username}"
    home_node = fs_get_node(home_dir)
    if not home_node:
        home_parts = fs_get_node("/home")
        if home_parts and home_parts.get("type") == "dir":
            home_parts["children"][username] = {
                "type": "dir",
                "owner": username,
                "group": username,
                "mode": "drwxr-xr-x",
                "children": {
                    ".bashrc": {"type": "file", "owner": username, "group": username, "mode": "-rw-r--r--", "content": "# user bashrc\n"},
                    ".profile": {"type": "file", "owner": username, "group": username, "mode": "-rw-r--r--", "content": "# user profile\n"},
                    ".ssh": {"type": "dir", "owner": username, "group": username, "mode": "drwx------", "children": {}},
                    "passwords.txt": {
                        "type": "file",
                        "owner": username,
                        "group": username,
                        "mode": "-rw-r--r--",
                        "content": "root:toor\nadmin:admin123\n",
                        "canary": True
                    }
                }
            }
    return home_dir


def fs_mkdir(path, owner="root"):
    """Create directory at given absolute path"""
    norm = normalize_path(path)
    if norm == "/":
        return True, "File exists"

    parts = [p for p in norm.split("/") if p]
    parent_path = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
    dir_name = parts[-1]

    parent_node = fs_get_node(parent_path)
    if not parent_node or parent_node.get("type") != "dir":
        return False, "No such file or directory"

    if dir_name in parent_node.get("children", {}):
        return False, "File exists"

    parent_node["children"][dir_name] = {
        "type": "dir",
        "owner": owner,
        "group": owner,
        "mode": "drwxr-xr-x",
        "children": {}
    }
    return True, ""


def fs_touch(path, owner="root"):
    """Touch/create empty file at given path"""
    norm = normalize_path(path)
    parts = [p for p in norm.split("/") if p]
    parent_path = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
    file_name = parts[-1]

    parent_node = fs_get_node(parent_path)
    if not parent_node or parent_node.get("type") != "dir":
        return False, "No such file or directory"

    children = parent_node.get("children", {})
    if file_name in children:
        return True, ""  # update timestamp in real system

    children[file_name] = {
        "type": "file",
        "owner": owner,
        "group": owner,
        "mode": "-rw-r--r--",
        "content": ""
    }
    return True, ""


def fs_rm(path, recursive=False):
    """Remove file or directory at path"""
    norm = normalize_path(path)
    if norm == "/":
        return False, "Cannot remove root directory"

    parts = [p for p in norm.split("/") if p]
    parent_path = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
    target_name = parts[-1]

    parent_node = fs_get_node(parent_path)
    if not parent_node or parent_node.get("type") != "dir":
        return False, "No such file or directory"

    children = parent_node.get("children", {})
    if target_name not in children:
        return False, "No such file or directory"

    target_node = children[target_name]
    if target_node.get("type") == "dir" and not recursive:
        return False, "Is a directory"

    del children[target_name]
    return True, ""


def fs_write_file(path, content, append=False, owner="root", session_id=None, src_ip=None, username=None):
    """Write or append text content to file, logging authorized_keys writes explicitly"""
    norm = normalize_path(path)
    if "authorized_keys" in norm:
        log_alert(
            session_id=session_id,
            src_ip=src_ip,
            username=username,
            severity="HIGH",
            hits=["authorized_keys_write"],
            category="persistence",
            mitre_attack=["T1098.004"],
            command=f"write to {norm}: {content[:100]}",
            iocs={}
        )

    node = fs_get_node(norm)
    if node:
        if node.get("type") == "dir":
            return False, "Is a directory"
        if append:
            node["content"] = node.get("content", "") + content
        else:
            node["content"] = content
        return True, ""
    else:
        # Create file
        ok, err = fs_touch(norm, owner=owner)
        if not ok:
            return False, err
        node = fs_get_node(norm)
        if node:
            node["content"] = content
            return True, ""
        return False, "Write failed"