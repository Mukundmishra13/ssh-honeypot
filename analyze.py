"""
analyze.py — turns raw honeypot logs into telemetry.

WHAT THIS DOES
--------------
Reads logs/honeypot.jsonl and answers the three questions the project asks:

  1. Who attacked, when, and what did they type?        -> IP and command stats
  2. What were they trying to download or run?           -> payload extraction
  3. Which sessions were bots and which were humans?     -> behavioural scoring

Run it:
    python3 analyze.py                       # analyze the live honeypot log
    python3 analyze.py --log logs/sample_attacks.jsonl
    python3 analyze.py --json output/telemetry.json      # machine-readable too

THE SHAPE OF THE DATA
---------------------
The log is a flat event stream. Almost every question here is really a question
about a *session*, so the first thing we do is group events by session_id and
rebuild each session as an object. Everything after that is counting.
"""

import argparse
import json
import os
import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime

from event_log import read_events, DEFAULT_LOG_PATH


# ---------------------------------------------------------------------------
# Payload extraction (base requirement 2)
# ---------------------------------------------------------------------------

# A URL inside a command. Deliberately broad: attackers write http://, https://,
# bare IPs with paths, and tftp://. Anchoring too tightly misses real payloads.
URL_PATTERN = re.compile(
    r"""(?:(?:https?|ftp|tftp)://|www\.)[^\s'"<>|;&)]+""",
    re.IGNORECASE,
)

# Bare IPv4 addresses, which show up in commands like `wget 1.2.3.4/bin.sh`
# where the scheme is omitted. \b prevents matching inside a longer number.
BARE_IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}(?:[:/][^\s'\"<>|;&)]*)?"
)

# Commands that signal intent rather than reconnaissance. Each key is a label we
# report; each value is the list of substrings that trigger it.
#
# These are the stages of a standard compromise: fetch a file, make it runnable,
# run it, clean up, survive a reboot. Tagging commands by stage turns a flat
# command list into a kill-chain narrative, which is what a defender actually
# wants out of a honeypot.
MALICIOUS_INDICATORS = {
    "download":     ["wget ", "curl ", "tftp ", "fetch ", "ftpget"],
    "execute":      ["chmod +x", "chmod 777", "./", "sh -c", "bash -c", "perl ", "python -c"],
    "persistence":  ["crontab", "rc.local", "systemctl enable", "authorized_keys", "/etc/init.d"],
    "cleanup":      ["history -c", "rm -rf", "unset HISTFILE", "shred "],
    "recon":        ["uname", "whoami", "cat /proc/cpuinfo", "nproc", "free -m", "lscpu", "id"],
    "credential":   ["/etc/shadow", "/etc/passwd", ".ssh/id_rsa", ".bash_history"],
    "mining":       ["xmrig", "minerd", "stratum+tcp", "cpuminer", "monero"],
    "ddos_malware": ["busybox", "/bins/", "mirai", "mozi", "gafgyt", "tsunami"],
}


def extract_urls(command: str) -> list:
    """Pull every URL or bare-IP target out of one command string."""
    found = list(URL_PATTERN.findall(command))
    # Only look for bare IPs if no full URL matched, otherwise the IP inside
    # 'http://1.2.3.4/x' gets reported twice.
    if not found:
        found.extend(BARE_IP_PATTERN.findall(command))
    # dict.fromkeys dedupes while keeping original order; set() would scramble it.
    return list(dict.fromkeys(found))


def classify_command(command: str) -> list:
    """Return every intent tag that applies to this command (may be several)."""
    lowered = command.lower()
    return [tag for tag, needles in MALICIOUS_INDICATORS.items()
            if any(n in lowered for n in needles)]


# ---------------------------------------------------------------------------
# Session reconstruction
# ---------------------------------------------------------------------------

class Session:
    """One attacker visit, rebuilt from its scattered log events."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.src_ip = None
        self.client_banner = None
        self.start_ts = None
        self.duration_s = 0.0
        self.credentials = []    # (username, password) tried
        self.commands = []       # command strings in order
        self.gaps = []           # seconds between consecutive commands
        self.backspaces = 0      # total typing corrections across the session
        self.end_reason = None

    def ingest(self, event: dict) -> None:
        """Fold one log event into this session."""
        kind = event.get("event")

        if kind == "session_start":
            self.src_ip = event.get("src_ip")
            self.client_banner = event.get("client_banner", "")
            self.start_ts = event.get("ts")

        elif kind == "auth_attempt":
            self.credentials.append((event.get("username", ""), event.get("password", "")))
            self.src_ip = self.src_ip or event.get("src_ip")

        elif kind == "command":
            self.commands.append(event.get("command", ""))
            self.backspaces += event.get("backspaces", 0)
            self.src_ip = self.src_ip or event.get("src_ip")
            # Skip the first gap: it measures how long they took to type their
            # first command after login, which is dominated by client startup
            # rather than by the attacker, and it skews the median.
            if len(self.commands) > 1:
                self.gaps.append(event.get("seconds_since_prev", 0.0))

        elif kind == "session_end":
            self.duration_s = event.get("duration_s", 0.0)
            self.end_reason = event.get("reason")

    # ---- derived properties ----

    @property
    def median_gap(self) -> float:
        """Typical pause between commands. Median, not mean, because one long
        pause (an attacker alt-tabbing away) would drag a mean far off."""
        return statistics.median(self.gaps) if self.gaps else 0.0

    @property
    def urls(self) -> list:
        out = []
        for c in self.commands:
            out.extend(extract_urls(c))
        return list(dict.fromkeys(out))

    @property
    def tags(self) -> set:
        t = set()
        for c in self.commands:
            t.update(classify_command(c))
        return t


def build_sessions(log_path: str) -> dict:
    """Group the flat event stream into {session_id: Session}."""
    sessions = defaultdict(lambda: None)
    for event in read_events(log_path):
        sid = event.get("session_id")
        if not sid:
            continue
        if sessions[sid] is None:
            sessions[sid] = Session(sid)
        sessions[sid].ingest(event)
    return {k: v for k, v in sessions.items() if v is not None}


# ---------------------------------------------------------------------------
# Bot vs human classification (base requirement 3)
# ---------------------------------------------------------------------------

# Tuning constants, named so the thresholds are visible instead of buried as
# magic numbers inside the scoring function.
FAST_TYPING_THRESHOLD = 0.5    # seconds between commands; below this is inhuman
SLOW_TYPING_THRESHOLD = 2.0    # above this looks like reading and thinking
BOT_SCORE_THRESHOLD = 2        # net score at or above this is called a bot

# SSH client strings that essentially never belong to a person at a keyboard.
# A human uses OpenSSH or PuTTY; these are libraries you only see inside tools.
AUTOMATED_CLIENT_HINTS = ["libssh", "paramiko", "go", "python", "nmap", "zgrab", "masscan"]


def classify_session(session: Session) -> dict:
    """
    Decide whether a session was driven by a script or a person.

    APPROACH: a small set of independent signals, each voting with a weight,
    summed into a score. Deliberately not machine learning — with no labelled
    ground truth (nobody tells us who was really a bot) a trained model would be
    unverifiable. A transparent rule set can be inspected, argued with, and
    tuned, and every verdict comes with the reasons attached.

    Positive weight = evidence of automation. Negative = evidence of a human.
    """
    score = 0
    reasons = []

    # --- Signal 1: inter-command timing. The strongest single indicator. ---
    if session.gaps:
        gap = session.median_gap
        if gap < FAST_TYPING_THRESHOLD:
            score += 2
            reasons.append(f"commands {gap:.2f}s apart — too fast to type")
        elif gap > SLOW_TYPING_THRESHOLD:
            score -= 2
            reasons.append(f"commands {gap:.1f}s apart — consistent with reading output")

    # --- Signal 2: typing corrections. Scripts do not make typos. ---
    if session.backspaces > 0:
        score -= 2
        reasons.append(f"{session.backspaces} backspaces — someone corrected their typing")

    # --- Signal 3: client fingerprint from the SSH banner. ---
    banner = (session.client_banner or "").lower()
    if any(h in banner for h in AUTOMATED_CLIENT_HINTS):
        score += 2
        reasons.append(f"client '{session.client_banner}' is a library, not a terminal")
    elif "openssh" in banner or "putty" in banner:
        score -= 1
        reasons.append("client is a normal interactive SSH client")

    # --- Signal 4: timing variance. Humans are erratic; loops are metronomic. ---
    if len(session.gaps) >= 3:
        spread = statistics.pstdev(session.gaps)
        if spread < 0.15:
            score += 1
            reasons.append(f"gaps vary by only {spread:.3f}s — machine-regular rhythm")
        elif spread > 1.5:
            score -= 1
            reasons.append(f"gaps vary by {spread:.1f}s — irregular, human-like")

    # --- Signal 5: no exploration. Bots fire a fixed payload and leave. ---
    if session.commands and not session.gaps and session.duration_s < 2:
        score += 1
        reasons.append("single command then immediate disconnect")

    # --- Signal 6: zero commands. A scanner checking the port exists. ---
    if not session.commands:
        score += 1
        reasons.append("authenticated but never ran a command — port scan or banner grab")

    verdict = "bot" if score >= BOT_SCORE_THRESHOLD else ("human" if score <= -2 else "uncertain")
    return {"verdict": verdict, "score": score, "reasons": reasons}


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def analyze(log_path: str) -> dict:
    """Build the full telemetry picture. Returns a plain dict so it can be
    printed, written to JSON, or handed to visualize.py without rework."""
    sessions = build_sessions(log_path)

    ip_sessions = Counter()
    ip_commands = Counter()
    command_counter = Counter()
    username_counter = Counter()
    password_counter = Counter()
    credential_pairs = Counter()
    url_counter = Counter()
    tag_counter = Counter()
    hour_counter = Counter()
    banner_counter = Counter()
    verdicts = Counter()

    session_rows = []

    for session in sessions.values():
        ip = session.src_ip or "unknown"
        ip_sessions[ip] += 1
        ip_commands[ip] += len(session.commands)
        banner_counter[session.client_banner or "unknown"] += 1

        for cmd in session.commands:
            command_counter[cmd] += 1
        for user, pwd in session.credentials:
            username_counter[user] += 1
            password_counter[pwd] += 1
            credential_pairs[f"{user}:{pwd}"] += 1
        for url in session.urls:
            url_counter[url] += 1
        for tag in session.tags:
            tag_counter[tag] += 1

        # Hour-of-day in UTC, for the attack-timing chart.
        if session.start_ts:
            try:
                hour_counter[datetime.fromisoformat(session.start_ts).hour] += 1
            except ValueError:
                pass

        classification = classify_session(session)
        verdicts[classification["verdict"]] += 1

        session_rows.append({
            "session_id": session.session_id,
            "src_ip": ip,
            "start": session.start_ts,
            "duration_s": round(session.duration_s, 2),
            "client_banner": session.client_banner,
            "credentials": [f"{u}:{p}" for u, p in session.credentials],
            "commands": session.commands,
            "command_count": len(session.commands),
            "median_gap_s": round(session.median_gap, 3),
            "backspaces": session.backspaces,
            "urls": session.urls,
            "tags": sorted(session.tags),
            "classification": classification,
        })

    # Sessions carrying a download or execute tag are the ones worth reading by
    # hand — they are where an actual payload was attempted.
    high_interest = [s for s in session_rows
                     if {"download", "execute", "mining", "ddos_malware"} & set(s["tags"])]

    return {
        "log_path": log_path,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "totals": {
            "sessions": len(sessions),
            "unique_ips": len(ip_sessions),
            "commands": sum(command_counter.values()),
            "auth_attempts": sum(credential_pairs.values()),
            "unique_urls": len(url_counter),
        },
        "verdicts": dict(verdicts),
        "top_ips": ip_sessions.most_common(15),
        "ip_command_counts": ip_commands.most_common(15),
        "top_commands": command_counter.most_common(20),
        "top_usernames": username_counter.most_common(15),
        "top_passwords": password_counter.most_common(15),
        "top_credential_pairs": credential_pairs.most_common(15),
        "captured_urls": url_counter.most_common(30),
        "intent_tags": tag_counter.most_common(),
        "hour_histogram": dict(sorted(hour_counter.items())),
        "client_banners": banner_counter.most_common(10),
        "sessions": session_rows,
        "high_interest_sessions": high_interest,
    }


# ---------------------------------------------------------------------------
# Terminal report
# ---------------------------------------------------------------------------

def _bar(n: int, peak: int, width: int = 28) -> str:
    """A tiny text bar. Makes the terminal output scannable with no dependencies."""
    return "#" * max(1, int(width * n / peak)) if peak else ""


def _section(title: str) -> None:
    print(f"\n{title}\n{'-' * len(title)}")


def print_report(data: dict) -> None:
    t = data["totals"]
    print("=" * 62)
    print("  SSH HONEYPOT — TELEMETRY REPORT")
    print("=" * 62)
    print(f"  Log:       {data['log_path']}")
    print(f"  Generated: {data['generated_at']}")
    print(f"\n  {t['sessions']} sessions from {t['unique_ips']} unique IPs")
    print(f"  {t['commands']} commands, {t['auth_attempts']} credential attempts")
    print(f"  {t['unique_urls']} distinct payload URLs captured")

    _section("Bot vs human")
    v = data["verdicts"]
    total = sum(v.values()) or 1
    for label in ("bot", "uncertain", "human"):
        count = v.get(label, 0)
        print(f"  {label:<10} {count:>4}  ({100*count/total:>5.1f}%)  {_bar(count, total)}")

    _section("Most active source IPs")
    peak = data["top_ips"][0][1] if data["top_ips"] else 0
    for ip, count in data["top_ips"][:10]:
        print(f"  {ip:<18} {count:>4} sessions  {_bar(count, peak)}")

    _section("Most common commands")
    peak = data["top_commands"][0][1] if data["top_commands"] else 0
    for cmd, count in data["top_commands"][:12]:
        shown = cmd if len(cmd) <= 52 else cmd[:49] + "..."
        print(f"  {count:>4}x  {shown}")

    _section("Most tried credentials")
    for pair, count in data["top_credential_pairs"][:12]:
        print(f"  {count:>4}x  {pair}")

    _section("Captured payload URLs")
    if data["captured_urls"]:
        for url, count in data["captured_urls"][:15]:
            print(f"  {count:>4}x  {url}")
    else:
        print("  (none seen yet)")

    _section("Attacker intent (tagged commands)")
    peak = data["intent_tags"][0][1] if data["intent_tags"] else 0
    for tag, count in data["intent_tags"]:
        print(f"  {tag:<14} {count:>4}  {_bar(count, peak)}")

    _section("Sessions worth reading by hand")
    if data["high_interest_sessions"]:
        for s in data["high_interest_sessions"][:6]:
            c = s["classification"]
            print(f"\n  [{s['session_id']}] {s['src_ip']}  "
                  f"{s['command_count']} cmds, {s['duration_s']}s  "
                  f"-> {c['verdict'].upper()} (score {c['score']})")
            for reason in c["reasons"]:
                print(f"      · {reason}")
            for cmd in s["commands"][:6]:
                shown = cmd if len(cmd) <= 64 else cmd[:61] + "..."
                print(f"      $ {shown}")
            if s["urls"]:
                print(f"      payloads: {', '.join(s['urls'][:3])}")
    else:
        print("  (none)")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze SSH honeypot logs")
    parser.add_argument("--log", default=DEFAULT_LOG_PATH, help="path to the .jsonl log")
    parser.add_argument("--json", metavar="PATH", help="also write full telemetry as JSON")
    args = parser.parse_args()

    if not os.path.exists(args.log):
        print(f"[!] No log at {args.log}")
        print("    Run the honeypot first, or generate sample data:")
        print("    python3 simulate_attacks.py")
        return 1

    data = analyze(args.log)
    if data["totals"]["sessions"] == 0:
        print(f"[!] {args.log} has no sessions in it yet.")
        return 1

    print_report(data)

    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"[*] Full telemetry written to {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
