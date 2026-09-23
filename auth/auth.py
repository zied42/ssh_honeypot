import paramiko
from logs.logger import funnel_logger
from config.settings import VALID_USERNAME, VALID_PASSWORD

class HoneypotServer(paramiko.ServerInterface):
    def __init__(self):
        self.username = None

    def check_auth_password(self, username, password):
        self.username = username
        funnel_logger.info(f"AUTH {username}:{password}")

        if username == VALID_USERNAME and password == VALID_PASSWORD:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, *args):
        return True
