"""SSH Connection Handler module"""

import uuid
from datetime import datetime, timezone
import paramiko
from auth.auth import HoneypotServer
from shell.shell import emulated_shell, handle_exec_mode
from honeylog.logger import funnel_logger, log_event
from config.settings import CHANNEL_TIMEOUT, SSH_BANNER


def handle_connection(client, addr, host_key):
    """Handle individual SSH client connection with proper resource teardown"""
    session_id = str(uuid.uuid4())[:8]
    start_time = datetime.now(timezone.utc)
    ip = addr[0]
    src_port = addr[1]

    transport = None
    channel = None

    try:
        client.settimeout(CHANNEL_TIMEOUT)
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        transport.banner_timeout = CHANNEL_TIMEOUT
        transport.auth_timeout = CHANNEL_TIMEOUT
        transport.add_server_key(host_key)

        server = HoneypotServer(client_ip=ip, client_port=src_port, session_id=session_id)
        transport.start_server(server=server)

        channel = transport.accept(CHANNEL_TIMEOUT)

        remote_version = getattr(transport, "remote_version", "unknown")
        kex_info = None
        try:
            kex = transport.get_kex_info()
            if kex:
                kex_info = str(kex)
        except Exception:
            kex_info = None

        if channel:
            channel.settimeout(CHANNEL_TIMEOUT)
            log_event(
                funnel_logger,
                event_type="session_start",
                session_id=session_id,
                src_ip=ip,
                src_port=src_port,
                username=server.username,
                remote_version=remote_version,
                kex_info=kex_info
            )

            # Check if this was an exec request or an interactive shell
            if server.exec_command:
                handle_exec_mode(channel, server.exec_command, ip, server.username or "root", session_id)
            else:
                emulated_shell(channel, ip, server.username or "root", session_id)

            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            log_event(
                funnel_logger,
                event_type="session_end",
                session_id=session_id,
                src_ip=ip,
                src_port=src_port,
                username=server.username,
                duration=duration
            )

    except paramiko.SSHException as e:
        log_event(
            funnel_logger,
            event_type="ssh_error",
            session_id=session_id,
            src_ip=ip,
            src_port=src_port,
            error=str(e)
        )
    except Exception as e:
        log_event(
            funnel_logger,
            event_type="connection_error",
            session_id=session_id,
            src_ip=ip,
            src_port=src_port,
            error=str(e)
        )
    finally:
        if channel is not None:
            try:
                channel.close()
            except Exception:
                pass
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
        if client is not None:
            try:
                client.close()
            except Exception:
                pass