"""
ssh_honeypot.py — SSH Honeypot Server
Simulates an SSH service using Paramiko to attract and log attacker behaviour.
All events are recorded via logger.py in structured JSON format.

Usage:
    python3 ssh_honeypot.py

Requirements:
    pip install paramiko
"""

import os
import socket
import threading
import time
import uuid

import paramiko

import logger

# ── Configuration ─────────────────────────────────────────────────────────────

HOST = "0.0.0.0"       # Listen on all interfaces
PORT = 2222            # Use 22 on the actual VM (requires root). 2222 for local testing.
HOST_KEY_FILE = os.path.join(os.path.dirname(__file__), "server.key")
BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"  # Realistic SSH banner

# ── RSA Host Key ──────────────────────────────────────────────────────────────

def get_host_key():
    """Load existing host key or generate a new one."""
    if os.path.exists(HOST_KEY_FILE):
        return paramiko.RSAKey(filename=HOST_KEY_FILE)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_FILE)
    print(f"[*] New host key generated: {HOST_KEY_FILE}")
    return key


HOST_KEY = get_host_key()


# ── SSH Server Interface ──────────────────────────────────────────────────────

class HoneypotServer(paramiko.ServerInterface):
    """
    Paramiko server interface that handles SSH negotiation.
    Always rejects authentication but logs every attempt.
    """

    def __init__(self, client_ip: str, session_id: str):
        self.client_ip = client_ip
        self.session_id = session_id
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        """Log every password attempt and always reject it."""
        logger.log_login_attempt(
            source_ip=self.client_ip,
            service="SSH",
            username=username,
            password=password,
            success=False,
        )
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        """Reject public key auth (we only care about password attempts)."""
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


# ── Client Handler ────────────────────────────────────────────────────────────

def handle_client(client_socket: socket.socket, client_address: tuple):
    """Handle a single attacker connection in its own thread."""
    client_ip, client_port = client_address
    session_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    logger.log_connection(
        source_ip=client_ip,
        source_port=client_port,
        service="SSH",
    )

    transport = None
    try:
        transport = paramiko.Transport(client_socket)
        transport.local_version = BANNER
        transport.add_server_key(HOST_KEY)

        server = HoneypotServer(client_ip, session_id)

        try:
            transport.start_server(server=server)
        except paramiko.SSHException:
            return

        # Wait for a channel to be opened (up to 20 seconds)
        channel = transport.accept(20)
        if channel is None:
            return

        # Wait for shell request
        server.event.wait(10)

        # Send a fake shell prompt
        channel.send(b"\r\nWelcome to Ubuntu 22.04.3 LTS\r\n\r\n$ ")

        # Read and log commands
        command_buffer = b""
        while True:
            try:
                data = channel.recv(1024)
                if not data:
                    break

                command_buffer += data

                # Echo back input so it looks real
                channel.send(data)

                # Process on Enter
                if b"\r" in command_buffer or b"\n" in command_buffer:
                    command = command_buffer.strip().decode("utf-8", errors="replace")
                    if command:
                        logger.log_command(
                            source_ip=client_ip,
                            service="SSH",
                            session_id=session_id,
                            command=command,
                        )
                        # Fake response for common commands
                        channel.send(_fake_response(command).encode())
                    channel.send(b"$ ")
                    command_buffer = b""

            except (socket.timeout, EOFError, OSError):
                break

    except Exception as e:
        print(f"[!] Error handling {client_ip}: {e}")

    finally:
        duration = time.time() - start_time
        logger.log_disconnection(
            source_ip=client_ip,
            service="SSH",
            session_id=session_id,
            duration_seconds=duration,
        )
        if transport:
            transport.close()
        client_socket.close()


def _fake_response(command: str) -> str:
    """Return a convincing fake response for common commands."""
    command = command.lower().strip()
    responses = {
        "whoami":       "root\r\n",
        "id":           "uid=0(root) gid=0(root) groups=0(root)\r\n",
        "uname -a":     "Linux ubuntu 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\r\n",
        "ls":           "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  srv  sys  tmp  usr  var\r\n",
        "pwd":          "/root\r\n",
        "hostname":     "ubuntu-server\r\n",
        "ifconfig":     "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST> inet 10.0.0.5\r\n",
        "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\r\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n",
    }
    return responses.get(command, f"-bash: {command}: command not found\r\n")


# ── Main Server Loop ──────────────────────────────────────────────────────────

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)

    print(f"[*] SSH Honeypot listening on {HOST}:{PORT}")
    print(f"[*] Logs → honeypot.log")
    print(f"[*] Press Ctrl+C to stop\n")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            print(f"[+] Connection from {client_address[0]}:{client_address[1]}")
            thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address),
                daemon=True,
            )
            thread.start()

    except KeyboardInterrupt:
        print("\n[*] Shutting down honeypot.")
    finally:
        server_socket.close()


if __name__ == "__main__":
    start_server()
