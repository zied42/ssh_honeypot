"""Connection handler module"""

import uuid
from datetime import datetime, timezone
import paramiko
from auth.auth import HoneypotServer
from shell.shell import emulated_shell
from logs.logger import funnel_logger


def handle_connection(client, addr, host_key):
    """Handle an individual SSH connection"""
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