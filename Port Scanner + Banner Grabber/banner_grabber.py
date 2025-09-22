
import socket
import sys
import time

# Target from CLI or localhost
TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"

# Host ports exposed by docker-compose (adjust if you change compose)
DEFAULT_PORTS = [8080, 2222, 2121]

# Optional: also scan some common local ports (uncomment if you want)
# DEFAULT_PORTS += [80, 22, 21]

TIMEOUT = 3.0

def grab_banner(ip: str, port: int) -> str:
    """Connect to ip:port, optionally send a tiny probe, return first bytes as text."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    try:
        s.connect((ip, port))

        # Small nudges for specific services to elicit a banner/headers
        if port in (80, 8080):  # HTTP
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        elif port in (21, 2121):  # FTP greets on connect; no probe needed
            pass
        elif port in (22, 2222):  # SSH greets on connect; no probe needed
            pass

        try:
            data = s.recv(1024)
        except socket.timeout:
            data = b""

        return data.decode(errors="ignore").strip()
    except Exception:
        return ""
    finally:
        s.close()

if __name__ == "__main__":
    # Allow custom port list via CLI: python banner_grabber.py 127.0.0.1 80,443,8080
    if len(sys.argv) >= 3:
        try:
            DEFAULT_PORTS = [int(p.strip()) for p in sys.argv[2].split(",") if p.strip()]
        except ValueError:
            print("Invalid port list; using defaults.")

    print(f"Scanning {TARGET} for banners...")
    for p in DEFAULT_PORTS:
        b = grab_banner(TARGET, p)
        if b:
            print(f"Port {p}: {b}")
        else:
            print(f"Port {p}: (no banner or closed)")
        time.sleep(0.15)
