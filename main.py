"""
main.py — Honeypot Entry Point
Starts SSH (port 22) and HTTP (port 80) honeypots in parallel threads.

Usage:
    python3 main.py

Note:
    Ports 22 and 80 require root on Linux.
    For local testing, ssh_honeypot uses 2222 and http_honeypot uses 8080.
    Change PORT in each file before deploying to the VM.
"""

import threading
import ssh_honeypot
import http_honeypot


def main():
    print("=" * 45)
    print("   Honeypot System Starting")
    print("=" * 45)

    ssh_thread = threading.Thread(target=ssh_honeypot.start_server, daemon=True)
    http_thread = threading.Thread(target=http_honeypot.start_server, daemon=True)

    ssh_thread.start()
    http_thread.start()

    print("[*] Both services running. Press Ctrl+C to stop.\n")

    try:
        ssh_thread.join()
        http_thread.join()
    except KeyboardInterrupt:
        print("\n[*] Shutting down all honeypot services.")


if __name__ == "__main__":
    main()
