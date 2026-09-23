"""Main server module"""

import socket
import threading
import paramiko
import os
from core.connection import handle_connection
from config.settings import HOST_KEY_FILE
from logs.logger import funnel_logger


def load_host_key():
    """Load or generate SSH host key"""
    if os.path.exists(HOST_KEY_FILE):
        return paramiko.RSAKey(filename=HOST_KEY_FILE)

    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_FILE)
    return key


def start_server(host, port):
    """Start the honeypot server"""
    host_key = load_host_key()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(100)

    funnel_logger.info(f"Honeypot listening on {host}:{port}")
    print(f"[*] Honeypot listening on {host}:{port}")

    while True:
        try:
            client, addr = sock.accept()
            funnel_logger.info(f"CONNECTION FROM {addr[0]}")

            threading.Thread(
                target=handle_connection,
                args=(client, addr, host_key),
                daemon=True
            ).start()

        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
            break
        except Exception as e:
            funnel_logger.error(f"Server error: {e}")