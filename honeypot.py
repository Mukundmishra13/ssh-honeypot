"""
honeypot.py — the SSH listener.

WHAT THIS IS
------------
A fake SSH server. It speaks real SSH (real handshake, real encryption, real
key exchange) so that any normal SSH client connects happily, but behind the
protocol there is no actual system — only the scripted illusion in fake_shell.py.

Run it, point an SSH client at it, and every credential tried and every command
typed lands in logs/honeypot.jsonl.

    python3 honeypot.py
    ssh -p 2222 root@localhost      # password: anything

HOW THE PIECES FIT
------------------
    TCP socket  accepts a connection
        |
    paramiko.Transport  performs the SSH handshake and encryption
        |
    HoneypotServer  decides what the server permits (this is where we say "yes"
        |           to every password instead of checking one)
    Channel  the encrypted byte pipe to the attacker's terminal
        |
    shell_session()  reads keystrokes, echoes them, logs each submitted line
        |
    fake_shell.respond()  returns canned output. Never executes anything.

WHY PARAMIKO AND NOT A RAW SOCKET
---------------------------------
SSH is not a text protocol you can fake with print statements. Before a single
keystroke flows, the client and server negotiate algorithms, run a Diffie-Hellman
key exchange, verify a host key signature, and switch to an encrypted transport.
Implementing that correctly is months of work and one mistake makes every client
refuse to connect. paramiko gives us a correct SSH stack and lets us override
only the decisions we care about: whether to accept a password, and what to do
with the resulting shell.
"""

import argparse
import os
import socket
import sys
import threading
import time
import uuid

import paramiko

import fake_shell
from event_log import EventLogger

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# 2222, not 22. Ports below 1024 need root, and running a program that handles
# hostile input as root is exactly the mistake a honeypot should not make. In a
# real deployment you leave this unprivileged and redirect port 22 to it at the
# firewall:  iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to 2222
DEFAULT_PORT = 2222
DEFAULT_HOST = "0.0.0.0"

HOST_KEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "host_key")

# The SSH version string we advertise. paramiko's default banner literally
# contains the word "paramiko", which flags the box as a honeypot to anyone
# looking. We impersonate a stock Ubuntu OpenSSH instead.
SERVER_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"

# Accept every password. See HoneypotServer.check_auth_password for the reasoning.
ACCEPT_ANY_CREDENTIALS = True

# Drop a session after this long with no input. Without it, a bot that connects
# and goes quiet holds a thread open forever and the honeypot slowly dies.
SESSION_IDLE_TIMEOUT = 180  # seconds
HANDSHAKE_TIMEOUT = 20      # seconds to complete SSH negotiation

MAX_COMMAND_LENGTH = 4096   # refuse absurd input lines; cheap anti-DoS


# ---------------------------------------------------------------------------
# Host key
# ---------------------------------------------------------------------------

def load_or_create_host_key() -> paramiko.RSAKey:
    """
    Every SSH server must present a host key. Generate one once and reuse it.

    Reuse matters for the data, not just for speed: a client that reconnects to
    a *different* key sees a loud MITM warning. A stable key makes the honeypot
    look like one consistent machine across days of scanning, which is what you
    want when you are trying to spot the same botnet returning.
    """
    if os.path.exists(HOST_KEY_PATH):
        return paramiko.RSAKey(filename=HOST_KEY_PATH)

    print("[*] No host key found. Generating a 2048-bit RSA key (one-time)...")
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_PATH)
    os.chmod(HOST_KEY_PATH, 0o600)
    print(f"[*] Host key written to {HOST_KEY_PATH}")
    return key


# ---------------------------------------------------------------------------
# The server policy
# ---------------------------------------------------------------------------

class HoneypotServer(paramiko.ServerInterface):
    """
    Tells paramiko what this 'server' allows.

    paramiko calls these methods during the handshake. Each one is a policy
    decision, and for a honeypot every decision points the same way: say yes,
    and write down what was asked.
    """

    def __init__(self, logger: EventLogger, session_id: str, src_ip: str):
        self.logger = logger
        self.session_id = session_id
        self.src_ip = src_ip
        self.auth_attempts = 0
        self.credentials = []          # every (user, pass) pair tried
        self.exec_command = None       # set if the client ran `ssh host "cmd"`
        # Used to make the main thread wait until a shell is actually requested.
        self.shell_requested = threading.Event()

    def get_allowed_auths(self, username: str) -> str:
        """
        Advertise password auth only.

        If we also offered publickey, scanners would try keys they do not have,
        fail, and leave — and we would capture no passwords. Narrowing the
        options funnels them into the one path that produces intelligence.
        """
        return "password"

    def check_auth_password(self, username: str, password: str) -> int:
        """
        Called for every credential guess. We log it and accept it.

        WHY ACCEPT EVERYTHING: the credential list is interesting, but the
        commands are the real prize. Rejecting a guess ends the session before
        anyone types anything. Accepting converts a password-spray — which
        thousands of boxes already record — into a full behavioural capture.

        The cost is realism: a bot that tries one deliberately absurd password
        to detect honeypots (and some do) sees it accepted and knows. A more
        advanced version would reject the first N attempts and only then accept,
        so the login looks earned. That is the first thing I would add next.
        """
        self.auth_attempts += 1
        self.credentials.append((username, password))
        self.logger.auth_attempt(
            session_id=self.session_id,
            src_ip=self.src_ip,
            username=username,
            password=password,
            accepted=ACCEPT_ANY_CREDENTIALS,
        )
        return paramiko.AUTH_SUCCESSFUL if ACCEPT_ANY_CREDENTIALS else paramiko.AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        """Only allow 'session' channels. Refuse port forwarding outright."""
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        # Refusing this is a safety requirement, not a detail: an open
        # direct-tcpip channel would let an attacker tunnel traffic *through*
        # this machine to a third party, turning the honeypot into a relay.
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height,
                                  pixelwidth, pixelheight, modes) -> bool:
        """A PTY is what an interactive terminal asks for. Grant it."""
        return True

    def check_channel_shell_request(self, channel) -> bool:
        """The client wants an interactive shell. Grant it and wake the main thread."""
        self.shell_requested.set()
        return True

    def check_channel_exec_request(self, channel, command) -> bool:
        """
        Handles `ssh host "command"` — a single command, no interactive shell.

        Worth supporting explicitly: a large share of automated SSH attacks never
        open a shell at all. They connect, fire one long chained command, and
        disconnect. A honeypot that only handles interactive shells misses them
        entirely and under-reports bot traffic.
        """
        self.exec_command = command.decode("utf-8", errors="replace")
        self.shell_requested.set()
        return True


# ---------------------------------------------------------------------------
# The fake shell session
# ---------------------------------------------------------------------------

def shell_session(channel, logger: EventLogger, session_id: str, src_ip: str) -> int:
    """
    Read keystrokes, echo them, log each submitted line. Returns command count.

    WHY WE ECHO MANUALLY
    --------------------
    When the client asks for a PTY, the terminal is in raw mode: every keystroke
    is sent to us immediately and the client does *not* display it. If the
    server does not send the character back, the attacker types and sees a blank
    line, which no real shell does. So we assemble the line ourselves and echo
    each character — which is also why we can count backspaces, a signal a
    normal shell would never expose to us.
    """
    channel.settimeout(SESSION_IDLE_TIMEOUT)
    channel.send(fake_shell.banner())
    channel.send(fake_shell.prompt())

    buffer = ""            # the line being typed
    backspaces = 0         # corrections within the current line
    command_count = 0
    last_command_time = time.monotonic()  # monotonic: immune to clock changes

    while True:
        try:
            data = channel.recv(1024)
        except socket.timeout:
            channel.send("\r\ntimed out waiting for input\r\n")
            break
        except Exception:
            break

        if not data:
            break  # client closed the connection

        for byte in data:
            char = chr(byte)

            # Enter — submit the line.
            if char in ("\r", "\n"):
                channel.send("\r\n")
                command = buffer.strip()
                now = time.monotonic()

                if command:
                    command_count += 1
                    logger.command(
                        session_id=session_id,
                        src_ip=src_ip,
                        command=command,
                        seconds_since_prev=now - last_command_time,
                        backspaces=backspaces,
                    )
                    last_command_time = now

                    if command in ("exit", "logout", "quit"):
                        channel.send("logout\r\n")
                        return command_count

                    output = fake_shell.respond(command)
                    if output:
                        # Terminals in raw mode need \r\n, not bare \n, or the
                        # output walks diagonally down the screen.
                        channel.send(output.replace("\n", "\r\n") + "\r\n")

                buffer = ""
                backspaces = 0
                channel.send(fake_shell.prompt())

            # Backspace (0x7f DEL or 0x08 BS, depending on the client).
            elif byte in (0x7F, 0x08):
                if buffer:
                    buffer = buffer[:-1]
                    backspaces += 1
                    # Erase on screen: step back, overwrite with a space, step back.
                    channel.send("\b \b")

            # Ctrl-C — abandon the line, like a real shell.
            elif byte == 0x03:
                channel.send("^C\r\n")
                buffer = ""
                backspaces = 0
                channel.send(fake_shell.prompt())

            # Ctrl-D on an empty line — logout.
            elif byte == 0x04:
                channel.send("logout\r\n")
                return command_count

            # Printable characters. Control bytes (arrow keys, escape sequences)
            # fall through and are ignored, which is fine: we are capturing
            # commands, not reimplementing readline.
            elif 32 <= byte < 127:
                if len(buffer) < MAX_COMMAND_LENGTH:
                    buffer += char
                    channel.send(char)

    return command_count


def handle_connection(client_sock: socket.socket, addr, host_key, logger: EventLogger) -> None:
    """
    Handle one attacker connection, start to finish. Runs on its own thread.

    Wrapped in a broad try/except on purpose. This function touches raw network
    input from someone actively trying to break things; any exception here must
    kill this one session and nothing else. A honeypot that crashes on the first
    malformed packet is a honeypot that captures one attack.
    """
    src_ip, src_port = addr[0], addr[1]
    session_id = str(uuid.uuid4())[:8]
    started = time.monotonic()
    command_count = 0
    server = None
    transport = None
    reason = "closed"

    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = SERVER_BANNER
        transport.add_server_key(host_key)

        server = HoneypotServer(logger, session_id, src_ip)
        transport.start_server(server=server)

        client_banner = transport.remote_version or "unknown"
        logger.session_start(session_id, src_ip, src_port, client_banner)
        print(f"[+] {src_ip}:{src_port} connected  (session {session_id}, client: {client_banner})")

        # Wait for the client to open a channel. None arriving means it was a
        # bare port scan: connect, note the banner, leave.
        channel = transport.accept(HANDSHAKE_TIMEOUT)
        if channel is None:
            reason = "no_channel"
            return

        # Wait for a shell or exec request.
        if not server.shell_requested.wait(HANDSHAKE_TIMEOUT):
            reason = "no_shell_request"
            channel.close()
            return

        if server.exec_command is not None:
            # Non-interactive: one command, log it, answer, hang up.
            command_count = 1
            logger.command(
                session_id=session_id,
                src_ip=src_ip,
                command=server.exec_command,
                seconds_since_prev=0.0,
                backspaces=0,
            )
            output = fake_shell.respond(server.exec_command)
            if output:
                channel.send(output + "\n")
            channel.send_exit_status(0)
            reason = "exec"
            channel.close()
        else:
            command_count = shell_session(channel, logger, session_id, src_ip)
            channel.close()

    except paramiko.SSHException as e:
        reason = f"ssh_error: {type(e).__name__}"
    except Exception as e:
        reason = f"error: {type(e).__name__}"
    finally:
        duration = time.monotonic() - started
        logger.session_end(
            session_id=session_id,
            src_ip=src_ip,
            duration_s=duration,
            command_count=command_count,
            auth_attempts=server.auth_attempts if server else 0,
            reason=reason,
        )
        print(f"[-] {src_ip}:{src_port} disconnected  "
              f"({command_count} commands, {duration:.1f}s, {reason})")
        try:
            if transport:
                transport.close()
            client_sock.close()
        except Exception:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Low-interaction SSH honeypot")
    parser.add_argument("--host", default=DEFAULT_HOST, help="bind address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="bind port")
    args = parser.parse_args()

    host_key = load_or_create_host_key()
    logger = EventLogger()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Without SO_REUSEADDR, restarting the honeypot fails for ~60s while the
    # old socket sits in TIME_WAIT. You hit this the first time you Ctrl-C.
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_sock.bind((args.host, args.port))
    except OSError as e:
        print(f"[!] Could not bind {args.host}:{args.port} — {e}", file=sys.stderr)
        return 1

    server_sock.listen(100)  # backlog: pending connections queued by the kernel
    print(f"[*] Honeypot listening on {args.host}:{args.port}")
    print(f"[*] Logging to {logger.log_path}")
    print("[*] Try it:  ssh -p %d root@localhost   (any password)" % args.port)
    print("[*] Ctrl-C to stop\n")

    try:
        while True:
            client_sock, addr = server_sock.accept()
            # One thread per connection. Threads, not asyncio, because sessions
            # are few and mostly idle — the simplicity is worth more than the
            # concurrency ceiling here. daemon=True so Ctrl-C actually exits.
            t = threading.Thread(
                target=handle_connection,
                args=(client_sock, addr, host_key, logger),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")
        return 0
    finally:
        server_sock.close()


if __name__ == "__main__":
    sys.exit(main())
