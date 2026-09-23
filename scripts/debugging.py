"""Debugging utility script for testing honeypot connections"""

import paramiko
import socket

def test_connection(host="127.0.0.1", port=2222, user="root", password="root"):
    """Test connection helper"""
    print(f"Connecting to {host}:{port} with {user}:{password}")
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=port, username=user, password=password, timeout=5)
        stdin, stdout, stderr = client.exec_command("uname -a")
        print("Output:", stdout.read().decode())
        client.close()
    except Exception as e:
        print("Test error:", e)

if __name__ == "__main__":
    test_connection()
