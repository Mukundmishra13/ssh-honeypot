"""
fake_shell.py — the illusion the attacker interacts with.

WHY THIS FILE EXISTS
--------------------
Once an attacker "logs in", they expect a Linux shell. If they type `ls` and get
nothing, they disconnect in two seconds and we learn nothing. Every extra second
they stay is another command we capture, so the responses need to be plausible.

THE CRITICAL DESIGN RULE
------------------------
Nothing in this file executes anything. There is no subprocess, no os.system,
no eval. Every response is a hardcoded string looked up from a dictionary.

That is the whole safety model of the honeypot, and it is the first thing an
interviewer should ask about. An "interactive" honeypot that actually ran the
attacker's commands would not be a honeypot — it would be a remote shell you
handed to a stranger. This design makes that class of mistake impossible: there
is no code path from attacker input to execution.

This is what makes it a LOW-INTERACTION honeypot. The trade-off:
  + cannot be used to attack anyone; safe to run
  + trivial to deploy, no containers or VMs to isolate
  - a careful attacker spots the fake within a few commands
  - we never see what their downloaded malware actually does
A high-interaction honeypot (a real, sacrificial, isolated VM) flips that
trade-off: far richer intelligence, far more dangerous to operate. For capturing
scanner behaviour — which is what this project is about — low-interaction is the
right call, because scanners are automated and never check carefully.
"""

# A fake machine identity. Consistency matters: if `hostname` and the shell
# prompt disagree, an attentive attacker notices immediately.
FAKE_HOSTNAME = "web-prod-03"
FAKE_KERNEL = "Linux web-prod-03 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"

# A fake /etc/passwd. Deliberately mundane and entirely invented — no real
# system's data appears anywhere in this project.
FAKE_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
deploy:x:1000:1000:deploy,,,:/home/deploy:/bin/bash"""

# Fake directory listings, keyed by directory.
FAKE_FILESYSTEM = {
    "/root": ["backup.sh", "notes.txt"],
    "/home/deploy": ["app", "deploy.log", "releases"],
    "/tmp": [],
    "/var/www": ["html", "logs"],
    "/etc": ["passwd", "shadow", "hosts", "ssh", "cron.d", "nginx"],
}

# Exact-match command responses. Checked before the prefix handlers below.
STATIC_RESPONSES = {
    "whoami": "root",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "pwd": "/root",
    "hostname": FAKE_HOSTNAME,
    "uname -a": FAKE_KERNEL,
    "uname": "Linux",
    "uptime": " 04:21:17 up 97 days,  3:02,  1 user,  load average: 0.08, 0.04, 0.01",
    "ps": "    PID TTY          TIME CMD\n   1842 pts/0    00:00:00 bash\n   1901 pts/0    00:00:00 ps",
    "ls": "backup.sh  notes.txt",
    "ls -la": (
        "total 24\n"
        "drwx------  3 root root 4096 Oct 18 04:02 .\n"
        "drwxr-xr-x 19 root root 4096 Jul 11 09:33 ..\n"
        "-rw-------  1 root root 1204 Oct 18 04:02 .bash_history\n"
        "-rwxr-xr-x  1 root root  412 Mar 02 11:20 backup.sh\n"
        "-rw-r--r--  1 root root  180 Mar 02 11:21 notes.txt"
    ),
    "cat /etc/passwd": FAKE_PASSWD,
    # Permission denied is more believable than fake hashes, and it avoids
    # putting anything password-shaped in the project at all.
    "cat /etc/shadow": "cat: /etc/shadow: Permission denied",
    "free -m": (
        "               total        used        free      shared  buff/cache   available\n"
        "Mem:            3936        1204         412          22        2319        2458\n"
        "Swap:              0           0           0"
    ),
    "df -h": (
        "Filesystem      Size  Used Avail Use% Mounted on\n"
        "/dev/vda1        40G   12G   26G  32% /\n"
        "tmpfs           1.9G     0  1.9G   0% /dev/shm"
    ),
    # Scanners frequently run this to size up the machine for cryptomining:
    # more cores means more hashrate, so the answer decides whether they bother.
    "nproc": "4",
    "": "",  # bare Enter: real shells just show a new prompt
}


def respond(command: str) -> str:
    """
    Map an attacker's command to fake output.

    Returns the text to send back. Never executes anything — see the module
    docstring. The ordering below is deliberate: exact matches first (cheap and
    unambiguous), then prefix rules for commands that carry arguments.
    """
    cmd = command.strip()

    # 1. Exact match — covers most reconnaissance commands.
    if cmd in STATIC_RESPONSES:
        return STATIC_RESPONSES[cmd]

    # 2. Prefix rules for commands with arguments.

    # Download attempts. This is the single most valuable command class to fake
    # convincingly, because the URL is the payload — it points at the malware
    # the botnet is spreading. We claim success so the attacker proceeds to the
    # next stage (chmod, execute) and reveals the rest of the kill chain.
    if cmd.startswith(("wget ", "curl ")):
        return ""  # silent success, exactly like a real quiet download

    if cmd.startswith("ls "):
        path = cmd[3:].strip().split()[0] if len(cmd.split()) > 1 else "/root"
        if path in FAKE_FILESYSTEM:
            return "  ".join(FAKE_FILESYSTEM[path])
        return f"ls: cannot access '{path}': No such file or directory"

    if cmd.startswith("cd "):
        return ""  # real cd is silent on success

    if cmd.startswith("cat "):
        target = cmd[4:].strip()
        return f"cat: {target}: No such file or directory"

    # chmod/chown after a download = preparing to execute. Silent success keeps
    # the chain going so we see the execution attempt too.
    if cmd.startswith(("chmod ", "chown ")):
        return ""

    if cmd.startswith("echo "):
        return cmd[5:].strip().strip('"').strip("'")

    if cmd.startswith("which "):
        target = cmd[6:].strip()
        if target in ("wget", "curl", "python3", "perl"):
            return f"/usr/bin/{target}"
        return ""  # `which` prints nothing when it finds nothing

    if cmd.startswith(("apt", "apt-get", "yum")):
        return "Reading package lists... Done"

    if cmd.startswith("crontab"):
        return "no crontab for root"

    # 3. Unknown command — mimic bash's real error text exactly. Getting this
    # wrong (wrong wording, wrong format) is a common way honeypots get
    # fingerprinted and skipped by better tooling.
    program = cmd.split()[0] if cmd.split() else cmd
    return f"-bash: {program}: command not found"


def prompt() -> str:
    """The shell prompt. Must agree with FAKE_HOSTNAME and the fake `pwd`."""
    return f"root@{FAKE_HOSTNAME}:~# "


def banner() -> str:
    """
    The message-of-the-day shown right after login.

    Real Ubuntu servers print something like this, and its absence is a tell.
    """
    return (
        "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n"
        "\r\n"
        " * Documentation:  https://help.ubuntu.com\r\n"
        " * Management:     https://landscape.canonical.com\r\n"
        "\r\n"
        "Last login: Mon Oct 20 04:02:11 2026 from 10.0.0.14\r\n"
        "\r\n"
    )
