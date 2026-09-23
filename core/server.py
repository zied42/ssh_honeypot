"""Main SSH Honeypot Server module with resource management and rate limits"""

import os
import socket
import threading
from collections import defaultdict
import paramiko

from core.connection import handle_connection
from config.settings import (
    HOST_KEY_FILE,
    HOST_KEY_SIZE,
    MAX_GLOBAL_CONNECTIONS,
    MAX_PER_IP_CONNECTIONS,
    DATA_DIR
)
from honeylog.logger import funnel_logger, log_event

ACTIVE_CONNECTIONS = 0
CONNECTIONS_PER_IP = defaultdict(int)
CONN_LOCK = threading.Lock()


def load_host_key():
    """Load or generate SSH host key"""
    os.makedirs(DATA_DIR, exist_ok=True)
    if os.path.exists(HOST_KEY_FILE):
        return paramiko.RSAKey(filename=HOST_KEY_FILE)

    key = paramiko.RSAKey.generate(HOST_KEY_SIZE)
    key.write_private_key_file(HOST_KEY_FILE)
    return key


def _connection_wrapper(client, addr, host_key):
    """Wrapper around handle_connection to manage active connection counters"""
    global ACTIVE_CONNECTIONS
    ip = addr[0]
    try:
        handle_connection(client, addr, host_key)
    finally:
        with CONN_LOCK:
            global ACTIVE_CONNECTIONS
            ACTIVE_CONNECTIONS = max(0, ACTIVE_CONNECTIONS - 1)
            if ip in CONNECTIONS_PER_IP:
                CONNECTIONS_PER_IP[ip] -= 1
                if CONNECTIONS_PER_IP[ip] <= 0:
                    del CONNECTIONS_PER_IP[ip]


def start_server(host, port):
    """Start the honeypot server"""
    global ACTIVE_CONNECTIONS
    host_key = load_host_key()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(100)

    log_event(funnel_logger, event_type="server_start", host=host, port=port)
    print(f"[*] Honeypot listening on {host}:{port}")

    while True:
        try:
            client, addr = sock.accept()
            ip = addr[0]
            src_port = addr[1]

            with CONN_LOCK:
                if ACTIVE_CONNECTIONS >= MAX_GLOBAL_CONNECTIONS:
                    log_event(
                        funnel_logger,
                        event_type="connection_rejected",
                        reason="max_global_connections",
                        src_ip=ip,
                        src_port=src_port
                    )
                    client.close()
                    continue

                if CONNECTIONS_PER_IP[ip] >= MAX_PER_IP_CONNECTIONS:
                    log_event(
                        funnel_logger,
                        event_type="connection_rejected",
                        reason="max_per_ip_connections",
                        src_ip=ip,
                        src_port=src_port
                    )
                    client.close()
                    continue

                ACTIVE_CONNECTIONS += 1
                CONNECTIONS_PER_IP[ip] += 1

            log_event(
                funnel_logger,
                event_type="connection",
                src_ip=ip,
                src_port=src_port
            )

            t = threading.Thread(
                target=_connection_wrapper,
                args=(client, addr, host_key),
                daemon=True
            )
            t.start()

        except KeyboardInterrupt:
            print("\n[*] Shutting down honeypot server...")
            try:
                sock.close()
            except Exception:
                pass
            break
        except Exception as e:
            log_event(funnel_logger, event_type="error", error=str(e))