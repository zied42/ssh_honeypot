#!/usr/bin/env python3
"""SSH Honeypot - Main Entry Point"""

from core.server import start_server
from config.settings import LISTEN_HOST, LISTEN_PORT


def main():
    """Main entry point"""
    print("=" * 60)
    print("SSH Honeypot Server")
    print("=" * 60)
    print(f"Starting honeypot on {LISTEN_HOST}:{LISTEN_PORT}")
    print("Press Ctrl+C to stop")
    print("=" * 60)

    try:
        start_server(LISTEN_HOST, LISTEN_PORT)
    except KeyboardInterrupt:
        print("\n[*] Honeypot stopped")
    except Exception as e:
        print(f"[!] Fatal error: {e}")


if __name__ == "__main__":
    main()