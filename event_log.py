"""
event_log.py — the honeypot's recording layer.

WHY THIS FILE EXISTS
--------------------
A honeypot is only as useful as its evidence. Everything an attacker does gets
written here, and *nothing* else in the project writes to disk. Keeping all I/O
in one place means:
  - one place to reason about thread safety (many attackers connect at once)
  - one place that defines the log schema, so the analyzer can trust it

LOG FORMAT: JSON Lines (.jsonl)
-------------------------------
One JSON object per line. Chosen over plain text or CSV because:
  - append-only: a crash mid-write loses at most one line, not the file
  - streamable: you can analyze a 2 GB log without loading it into RAM
  - schema-flexible: an auth event and a command event have different fields,
    and that is fine. A CSV would force one rigid column set.

EVENT TYPES
-----------
  session_start  — a TCP connection completed an SSH handshake
  auth_attempt   — a username/password pair was tried
  command        — the attacker submitted a line in the fake shell
  session_end    — the connection closed; carries the session summary
"""

import json
import os
import threading
from datetime import datetime, timezone

# Default log location. The analyzer reads the same path.
DEFAULT_LOG_PATH = os.path.join(os.path.dirname(__file__), "logs", "honeypot.jsonl")

# Many attacker connections are handled on separate threads at the same time.
# Without this lock two threads can interleave their writes mid-line and
# produce a corrupted, unparseable JSON line. The lock makes each write atomic.
_write_lock = threading.Lock()


def utc_now() -> str:
    """
    Current time as an ISO-8601 string in UTC, e.g. '2026-10-22T13:45:02.123456+00:00'.

    UTC, not local time, on purpose: attackers come from every timezone, and
    "which hour of the day do bots scan in?" is only a meaningful question if
    every timestamp is on the same clock.
    """
    return datetime.now(timezone.utc).isoformat()


class EventLogger:
    """Appends structured events to a JSONL file. Safe to share across threads."""

    def __init__(self, log_path: str = DEFAULT_LOG_PATH):
        self.log_path = log_path
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

    def _write(self, event: dict) -> None:
        """Serialize one event to one line. The only function that touches the file."""
        line = json.dumps(event, ensure_ascii=False)
        with _write_lock:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                # flush + fsync so evidence survives a kill -9. A honeypot that
                # loses its buffer when it crashes has lost the attack it just saw.
                f.flush()
                os.fsync(f.fileno())

    # ---- one method per event type, so callers cannot invent a schema ----

    def session_start(self, session_id: str, src_ip: str, src_port: int,
                      client_banner: str) -> None:
        """
        Logged once per successful SSH handshake.

        client_banner is the SSH version string the client sends before any
        encryption (e.g. 'SSH-2.0-libssh2_1.9.0'). It is a strong fingerprint:
        real humans show 'OpenSSH_9.x'; mass scanners show libssh2, Go, or
        paramiko. This costs nothing to record and is one of the most
        discriminating fields in the whole log.
        """
        self._write({
            "event": "session_start",
            "ts": utc_now(),
            "session_id": session_id,
            "src_ip": src_ip,
            "src_port": src_port,
            "client_banner": client_banner,
        })

    def auth_attempt(self, session_id: str, src_ip: str, username: str,
                     password: str, accepted: bool) -> None:
        """
        Logged for every credential pair tried.

        We record the password in cleartext. That is correct here and nowhere
        else: these are not our users' passwords, they are the attacker's
        *guesses*, and the guess list is the intelligence. It tells you which
        credential dictionary the botnet is running.
        """
        self._write({
            "event": "auth_attempt",
            "ts": utc_now(),
            "session_id": session_id,
            "src_ip": src_ip,
            "username": username,
            "password": password,
            "accepted": accepted,
        })

    def command(self, session_id: str, src_ip: str, command: str,
                seconds_since_prev: float, backspaces: int) -> None:
        """
        Logged for every line the attacker submits in the fake shell.

        Two fields here are not obvious and carry most of the bot-detection signal:

        seconds_since_prev — gap between this command and the previous one.
            A script pipes its payload instantly; the gaps are milliseconds. A
            human reads output and thinks; the gaps are seconds. This single
            number separates the two populations better than anything else.

        backspaces — how many times the attacker pressed backspace while typing
            this line. A script never makes typos. A human corrects themselves.
            A non-zero count is near-proof of a live operator at the keyboard.
        """
        self._write({
            "event": "command",
            "ts": utc_now(),
            "session_id": session_id,
            "src_ip": src_ip,
            "command": command,
            "seconds_since_prev": round(seconds_since_prev, 4),
            "backspaces": backspaces,
        })

    def session_end(self, session_id: str, src_ip: str, duration_s: float,
                    command_count: int, auth_attempts: int,
                    reason: str = "closed") -> None:
        """Logged once per session, when the connection drops. The session summary."""
        self._write({
            "event": "session_end",
            "ts": utc_now(),
            "session_id": session_id,
            "src_ip": src_ip,
            "duration_s": round(duration_s, 3),
            "command_count": command_count,
            "auth_attempts": auth_attempts,
            "reason": reason,
        })


def read_events(log_path: str = DEFAULT_LOG_PATH):
    """
    Yield one event dict per line. Used by analyze.py.

    This is a generator, not a list: it holds one line in memory at a time, so
    the analyzer works the same on a 1 MB log and a 1 GB log.

    Malformed lines are skipped rather than raising. A honeypot is exposed to
    hostile input by definition; one bad line must not stop the analysis.
    """
    if not os.path.exists(log_path):
        return
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue
