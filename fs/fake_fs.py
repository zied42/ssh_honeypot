"""Fake filesystem implementation"""

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
                "canary": True,
            },
            "id_rsa": {
                "type": "file",
                "content": "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEKEY\n-----END-----",
                "canary": True,
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
        if cwd == home:
            return home
        parts = cwd.rstrip("/").split("/")
        if len(parts) > 1:
            parent = "/".join(parts[:-1])
            return parent if parent else "/"
        return home

    # Relative path - join with cwd
    if cwd.endswith("/"):
        resolved = cwd + path
    else:
        resolved = cwd + "/" + path

    return resolved


def fs_get_node(path):
    """Get filesystem node at path"""
    if not path or path == "/":
        return None

    path = path.rstrip("/")

    # Direct match in FAKE_FS
    if path in FAKE_FS:
        return FAKE_FS[path]

    # Navigate from root keys
    parts = [p for p in path.split("/") if p]

    # Find the root node (e.g., /home/admin)
    current = None
    start_idx = 0

    # Try to find a matching root path
    for i in range(len(parts), 0, -1):
        test_path = "/" + "/".join(parts[:i])
        if test_path in FAKE_FS:
            current = FAKE_FS[test_path]
            start_idx = i
            break

    if current is None:
        return None

    # Navigate remaining parts
    for idx, part in enumerate(parts[start_idx:], start=start_idx):
        if current.get("type") != "dir":
            return None

        children = current.get("children", {})

        if part not in children:
            return None

        current = children[part]

    return current