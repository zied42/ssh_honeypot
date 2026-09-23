"""Authentication and channel request handler for Paramiko SSH honeypot"""

import binascii
import paramiko
from honeylog.logger import funnel_logger, log_event
from config.settings import COMMON_CREDENTIALS, ALLOW_ANY_AFTER_N_FAILS

# Track failed attempts per IP globally across connections
IP_FAIL_COUNTS = {}


def _safe_str(val):
    if val is None:
        return ""
    if isinstance(val, bytes):
        return val.decode("utf-8", errors="ignore")
    return str(val)


class HoneypotServer(paramiko.ServerInterface):
    """Paramiko ServerInterface implementation for SSH honeypot"""
    def __init__(self, client_ip="127.0.0.1", client_port=0, session_id=None):
        self.client_ip = client_ip
        self.client_port = client_port
        self.session_id = session_id
        self.username = None
        self.exec_command = None
        self.pty_info = None
        self.auth_successful = False

    def check_auth_password(self, username, password):
        u_str = _safe_str(username)
        p_str = _safe_str(password)
        self.username = u_str

        fail_count = IP_FAIL_COUNTS.get(self.client_ip, 0)
        is_common = (u_str, p_str) in COMMON_CREDENTIALS
        is_n_failed = fail_count >= ALLOW_ANY_AFTER_N_FAILS

        success = is_common or is_n_failed

        if success:
            self.auth_successful = True
            log_event(
                funnel_logger,
                event_type="auth",
                session_id=self.session_id,
                src_ip=self.client_ip,
                src_port=self.client_port,
                username=u_str,
                password=p_str,
                auth_success=True,
                fail_count=fail_count
            )
            return paramiko.AUTH_SUCCESSFUL
        else:
            IP_FAIL_COUNTS[self.client_ip] = fail_count + 1
            log_event(
                funnel_logger,
                event_type="auth",
                session_id=self.session_id,
                src_ip=self.client_ip,
                src_port=self.client_port,
                username=u_str,
                password=p_str,
                auth_success=False,
                fail_count=fail_count + 1
            )
            return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        u_str = _safe_str(username)
        self.username = u_str
        key_type = key.get_name()
        fingerprint = ""
        try:
            fingerprint = binascii.hexlify(key.get_fingerprint()).decode('ascii')
        except Exception:
            fingerprint = "unknown"

        log_event(
            funnel_logger,
            event_type="publickey",
            session_id=self.session_id,
            src_ip=self.client_ip,
            src_port=self.client_port,
            username=u_str,
            key_type=key_type,
            key_fingerprint=fingerprint,
            auth_success=False
        )
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        log_event(
            funnel_logger,
            event_type="shell_request",
            session_id=self.session_id,
            src_ip=self.client_ip,
            src_port=self.client_port,
            username=self.username
        )
        return True

    def check_channel_exec_request(self, channel, command):
        self.exec_command = _safe_str(command)
        log_event(
            funnel_logger,
            event_type="exec_request",
            session_id=self.session_id,
            src_ip=self.client_ip,
            src_port=self.client_port,
            username=self.username,
            command=self.exec_command
        )
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        term_str = _safe_str(term)
        self.pty_info = {
            "term": term_str,
            "width": width,
            "height": height,
            "pixelwidth": pixelwidth,
            "pixelheight": pixelheight
        }
        log_event(
            funnel_logger,
            event_type="pty_request",
            session_id=self.session_id,
            src_ip=self.client_ip,
            src_port=self.client_port,
            username=self.username,
            term=term_str,
            width=width,
            height=height
        )
        return True

    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        log_event(
            funnel_logger,
            event_type="window_change",
            session_id=self.session_id,
            src_ip=self.client_ip,
            src_port=self.client_port,
            username=self.username,
            width=width,
            height=height
        )
        return True

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        log_event(
            funnel_logger,
            event_type="direct_tcpip",
            session_id=self.session_id,
            src_ip=self.client_ip,
            src_port=self.client_port,
            origin=f"{origin[0]}:{origin[1]}",
            destination=f"{destination[0]}:{destination[1]}"
        )
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
