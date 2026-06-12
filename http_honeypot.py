"""
http_honeypot.py — HTTP Honeypot Server
Simulates a basic web service to attract and log attacker probing behaviour.
All events are recorded via logger.py in structured JSON format.

Usage:
    python3 http_honeypot.py

No extra dependencies required — uses Python's built-in socket library.
"""

import socket
import threading

import logger

# ── Configuration ─────────────────────────────────────────────────────────────

HOST = "0.0.0.0"   # Listen on all interfaces
PORT = 8080        # Use 80 on the actual VM (requires root). 8080 for local testing.
SERVER_HEADER = "Apache/2.4.57 (Ubuntu)"  # Realistic-looking server banner

# ── Fake HTML Pages ───────────────────────────────────────────────────────────

FAKE_INDEX = b"""\
<!DOCTYPE html>
<html>
<head><title>Company Intranet Portal</title></head>
<body>
  <h1>Welcome to the Company Portal</h1>
  <p>Please log in to access internal resources.</p>
  <form method="POST" action="/login">
    <label>Username: <input type="text" name="username"></label><br>
    <label>Password: <input type="password" name="password"></label><br>
    <input type="submit" value="Login">
  </form>
</body>
</html>"""

FAKE_404 = b"""\
<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
  <h1>Not Found</h1>
  <p>The requested URL was not found on this server.</p>
  <hr><address>Apache/2.4.57 (Ubuntu) Server</address>
</body>
</html>"""

FAKE_LOGIN_RESPONSE = b"""\
<!DOCTYPE html>
<html>
<head><title>Login Failed</title></head>
<body>
  <h1>Invalid credentials. Please try again.</h1>
</body>
</html>"""


# ── HTTP Parser ───────────────────────────────────────────────────────────────

def parse_request(raw: str) -> dict:
    """Parse a raw HTTP request into method, path, headers, and body."""
    result = {"method": "", "path": "", "headers": {}, "body": ""}
    try:
        lines = raw.split("\r\n")
        if not lines:
            return result

        # Request line: GET /path HTTP/1.1
        parts = lines[0].split(" ")
        if len(parts) >= 2:
            result["method"] = parts[0]
            result["path"] = parts[1]

        # Headers
        i = 1
        while i < len(lines) and lines[i] != "":
            if ":" in lines[i]:
                key, _, value = lines[i].partition(":")
                result["headers"][key.strip()] = value.strip()
            i += 1

        # Body (after blank line)
        result["body"] = "\r\n".join(lines[i + 1:]).strip()

    except Exception:
        pass

    return result


def build_response(status: str, body: bytes, content_type: str = "text/html") -> bytes:
    """Build a minimal HTTP/1.1 response."""
    headers = (
        f"HTTP/1.1 {status}\r\n"
        f"Server: {SERVER_HEADER}\r\n"
        f"Content-Type: {content_type}; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    return headers + body


# ── Client Handler ────────────────────────────────────────────────────────────

def handle_client(client_socket: socket.socket, client_address: tuple):
    """Handle a single HTTP request."""
    client_ip, client_port = client_address

    try:
        raw = client_socket.recv(4096).decode("utf-8", errors="replace")
        if not raw:
            return

        req = parse_request(raw)
        method = req["method"]
        path = req["path"]
        body = req["body"]

        # Log every request
        logger.log_connection(
            source_ip=client_ip,
            source_port=client_port,
            service="HTTP",
        )

        # Log commands/input for POST requests (credential harvesting)
        if method == "POST":
            logger.log_command(
                source_ip=client_ip,
                service="HTTP",
                session_id=f"{client_ip}:{client_port}",
                command=f"POST {path} — body: {body}",
            )

        # Log GET requests as commands too (path probing / scanning)
        else:
            logger.log_command(
                source_ip=client_ip,
                service="HTTP",
                session_id=f"{client_ip}:{client_port}",
                command=f"{method} {path}",
            )

        # Route responses
        if path in ("/", "/index.html"):
            response = build_response("200 OK", FAKE_INDEX)
        elif path == "/login" and method == "POST":
            response = build_response("200 OK", FAKE_LOGIN_RESPONSE)
        else:
            response = build_response("404 Not Found", FAKE_404)

        client_socket.sendall(response)

    except Exception as e:
        print(f"[!] HTTP error from {client_ip}: {e}")

    finally:
        logger.log_disconnection(
            source_ip=client_ip,
            service="HTTP",
            session_id=f"{client_ip}:{client_port}",
            duration_seconds=0,
        )
        client_socket.close()


# ── Main Server Loop ──────────────────────────────────────────────────────────

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(10)

    print(f"[*] HTTP Honeypot listening on {HOST}:{PORT}")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            print(f"[+] HTTP connection from {client_address[0]}:{client_address[1]}")
            thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address),
                daemon=True,
            )
            thread.start()

    except KeyboardInterrupt:
        print("\n[*] HTTP Honeypot shutting down.")
    finally:
        server_socket.close()


if __name__ == "__main__":
    start_server()
