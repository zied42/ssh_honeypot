"""Unit tests for in-memory fake filesystem"""

import pytest
from fs.fake_fs import (
    fs_get_node,
    fs_resolve,
    fs_mkdir,
    fs_touch,
    fs_rm,
    fs_write_file,
    normalize_path,
)


def test_fs_root_node():
    root = fs_get_node("/")
    assert root is not None
    assert root["type"] == "dir"


def test_fs_proc_and_etc():
    passwd = fs_get_node("/etc/passwd")
    assert passwd is not None
    assert passwd["type"] == "file"
    assert "root:x:0:0" in passwd["content"]

    cpuinfo = fs_get_node("/proc/cpuinfo")
    assert cpuinfo is not None
    assert "GenuineIntel" in cpuinfo["content"]


def test_fs_mkdir_touch_rm():
    ok, err = fs_mkdir("/tmp/testdir")
    assert ok
    node = fs_get_node("/tmp/testdir")
    assert node is not None
    assert node["type"] == "dir"

    ok, err = fs_touch("/tmp/testdir/file.txt")
    assert ok
    file_node = fs_get_node("/tmp/testdir/file.txt")
    assert file_node is not None
    assert file_node["type"] == "file"

    ok, err = fs_rm("/tmp/testdir/file.txt")
    assert ok
    assert fs_get_node("/tmp/testdir/file.txt") is None


def test_echo_redirection_and_authorized_keys():
    ok, err = fs_write_file("/tmp/out.txt", "hello world\n", append=False)
    assert ok
    file_node = fs_get_node("/tmp/out.txt")
    assert file_node["content"] == "hello world\n"

    # Authorized keys append test
    ok, err = fs_write_file("/root/.ssh/authorized_keys", "ssh-rsa AAAA...", append=True)
    assert ok
    auth_node = fs_get_node("/root/.ssh/authorized_keys")
    assert "ssh-rsa" in auth_node["content"]
