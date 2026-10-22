"""
visualize.py — charts for the bonus deliverable.

Run it:
    python3 visualize.py --log logs/sample_attacks.jsonl

Writes PNGs into output/.

WHAT EACH CHART IS FOR
----------------------
Each one answers a question a defender would actually ask, rather than
decorating the report:

  attack_timeline.png   When does this traffic arrive? (bots run overnight)
  top_sources.png       Which IPs should go on a blocklist first?
  bot_detection.png     Does the bot/human split hold up? (the key chart)
  command_frequency.png What are they trying to do?
  attack_intent.png     How far along the kill chain do they get?

bot_detection.png is the one to defend in a viva. It plots every session's
median inter-command gap on a log axis. If the classifier is measuring something
real, the points separate into two clusters with a gap between them. If they
smeared into one blob, the threshold would be arbitrary and the whole
classification would be guesswork. The chart is the evidence, not the decoration.
"""

import argparse
import os

import matplotlib
matplotlib.use("Agg")  # no display needed; required on a headless server
import matplotlib.pyplot as plt

from analyze import analyze, build_sessions, classify_session
from event_log import DEFAULT_LOG_PATH

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")

# One palette used everywhere, so a colour means the same thing in every chart.
# Chosen to stay distinguishable in the most common forms of colour blindness
# and to survive being printed in greyscale (the three differ in lightness).
C_BOT = "#C1442E"        # red — automated
C_HUMAN = "#2A6F97"      # blue — human
C_UNCERTAIN = "#B0A48F"  # grey-tan — undecided
C_ACCENT = "#3F6B52"     # green — neutral counts
C_GRID = "#D8D4CC"

plt.rcParams.update({
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "axes.edgecolor": "#55504A",
    "axes.labelcolor": "#2B2824",
    "axes.titlesize": 13,
    "axes.titleweight": "bold",
    "axes.grid": True,
    "grid.color": C_GRID,
    "grid.linewidth": 0.7,
    "font.size": 10,
    "text.color": "#2B2824",
    "xtick.color": "#55504A",
    "ytick.color": "#55504A",
    "figure.dpi": 130,
})


def _finish(fig, ax_or_axes, path):
    """Strip chartjunk and save. Called at the end of every chart function."""
    axes = ax_or_axes if isinstance(ax_or_axes, (list, tuple)) else [ax_or_axes]
    for ax in axes:
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
    fig.tight_layout()
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote {path}")


# ---------------------------------------------------------------------------

def chart_timeline(data, path):
    """Sessions by hour of day (UTC). Reveals the overnight scanning rhythm."""
    hours = list(range(24))
    counts = [data["hour_histogram"].get(h, 0) for h in hours]

    fig, ax = plt.subplots(figsize=(9, 4))
    ax.bar(hours, counts, color=C_ACCENT, width=0.72)
    ax.set_xlabel("Hour of day (UTC)")
    ax.set_ylabel("Sessions")
    ax.set_title("When attacks arrive")
    ax.set_xticks(range(0, 24, 2))
    ax.set_axisbelow(True)
    ax.grid(axis="x", visible=False)

    if any(counts):
        peak = max(range(24), key=lambda h: counts[h])
        ax.annotate(f"peak {peak:02d}:00 UTC",
                    xy=(peak, counts[peak]),
                    xytext=(0, 12), textcoords="offset points",
                    ha="center", fontsize=9, color="#55504A")
    _finish(fig, ax, path)


def chart_top_sources(data, path):
    """Busiest source IPs — the candidate blocklist, longest bar first."""
    rows = data["top_ips"][:10][::-1]  # reversed: barh builds bottom-up
    if not rows:
        return
    labels = [ip for ip, _ in rows]
    values = [n for _, n in rows]

    fig, ax = plt.subplots(figsize=(8, 4.6))
    ax.barh(labels, values, color=C_ACCENT, height=0.68)
    ax.set_xlabel("Sessions")
    ax.set_title("Most active source IPs")
    ax.set_axisbelow(True)
    ax.grid(axis="y", visible=False)
    for y, v in enumerate(values):
        ax.text(v + max(values) * 0.012, y, str(v), va="center", fontsize=9)
    _finish(fig, ax, path)


def chart_bot_detection(sessions, data, path):
    """
    The evidence chart for the classifier.

    Left:  every session's median inter-command gap, log scale, coloured by
           verdict, with the decision threshold drawn in. Two separated clusters
           means the signal is real.
    Right: how many sessions landed in each verdict.
    """
    points = []  # (median_gap, verdict)
    for s in sessions.values():
        if s.gaps:
            points.append((s.median_gap, classify_session(s)["verdict"]))

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.4),
                                   gridspec_kw={"width_ratios": [2.1, 1]})

    colors = {"bot": C_BOT, "human": C_HUMAN, "uncertain": C_UNCERTAIN}
    for verdict in ("bot", "uncertain", "human"):
        xs = [i for i, (_, v) in enumerate(points) if v == verdict]
        ys = [g for (g, v) in points if v == verdict]
        if xs:
            ax1.scatter(xs, ys, c=colors[verdict], label=verdict,
                        s=46, alpha=0.82, edgecolors="white", linewidths=0.6)

    ax1.axhline(0.5, color="#55504A", linestyle="--", linewidth=1.1)
    ax1.text(0.012, 0.52, "0.5s threshold", transform=ax1.get_yaxis_transform(),
             fontsize=8.5, va="bottom", color="#55504A")
    ax1.set_yscale("log")
    ax1.set_xlabel("Session (in log order)")
    ax1.set_ylabel("Median gap between commands (s, log scale)")
    ax1.set_title("Typing speed separates scripts from people")
    ax1.legend(frameon=False, fontsize=9)
    ax1.set_axisbelow(True)
    ax1.grid(axis="x", visible=False)

    v = data["verdicts"]
    names = ["bot", "uncertain", "human"]
    vals = [v.get(n, 0) for n in names]
    ax2.bar(names, vals, color=[C_BOT, C_UNCERTAIN, C_HUMAN], width=0.6)
    ax2.set_ylabel("Sessions")
    ax2.set_title("Verdicts")
    ax2.set_axisbelow(True)
    ax2.grid(axis="x", visible=False)
    for i, val in enumerate(vals):
        if val:
            ax2.text(i, val + max(vals) * 0.02, str(val), ha="center", fontsize=9)

    _finish(fig, [ax1, ax2], path)


def chart_commands(data, path):
    """Most frequently executed commands."""
    rows = data["top_commands"][:12][::-1]
    if not rows:
        return
    labels = [c if len(c) <= 38 else c[:35] + "..." for c, _ in rows]
    values = [n for _, n in rows]

    fig, ax = plt.subplots(figsize=(9, 5.2))
    ax.barh(labels, values, color=C_ACCENT, height=0.68)
    ax.set_xlabel("Times executed")
    ax.set_title("Most common attacker commands")
    ax.tick_params(axis="y", labelsize=8.5)
    ax.set_axisbelow(True)
    ax.grid(axis="y", visible=False)
    _finish(fig, ax, path)


def chart_intent(data, path):
    """Kill-chain stages reached, ordered by how far along the chain they are."""
    order = ["recon", "credential", "download", "execute",
             "mining", "ddos_malware", "persistence", "cleanup"]
    counts = dict(data["intent_tags"])
    labels = [t for t in order if counts.get(t)]
    values = [counts[t] for t in labels]
    if not labels:
        return

    fig, ax = plt.subplots(figsize=(8.5, 4.2))
    ax.bar(labels, values, color=C_BOT, width=0.62, alpha=0.88)
    ax.set_ylabel("Sessions containing this behaviour")
    ax.set_title("How far attackers get along the kill chain")
    ax.tick_params(axis="x", rotation=25)
    ax.set_axisbelow(True)
    ax.grid(axis="x", visible=False)
    for i, val in enumerate(values):
        ax.text(i, val + max(values) * 0.02, str(val), ha="center", fontsize=9)
    _finish(fig, ax, path)


def main():
    parser = argparse.ArgumentParser(description="Charts for honeypot telemetry")
    parser.add_argument("--log", default=DEFAULT_LOG_PATH)
    parser.add_argument("--out", default=OUT_DIR)
    args = parser.parse_args()

    if not os.path.exists(args.log):
        print(f"[!] No log at {args.log} — run simulate_attacks.py first.")
        return 1

    os.makedirs(args.out, exist_ok=True)
    data = analyze(args.log)
    if data["totals"]["sessions"] == 0:
        print("[!] No sessions in the log.")
        return 1

    sessions = build_sessions(args.log)
    print(f"[*] Charting {data['totals']['sessions']} sessions...")

    chart_timeline(data, os.path.join(args.out, "attack_timeline.png"))
    chart_top_sources(data, os.path.join(args.out, "top_sources.png"))
    chart_bot_detection(sessions, data, os.path.join(args.out, "bot_detection.png"))
    chart_commands(data, os.path.join(args.out, "command_frequency.png"))
    chart_intent(data, os.path.join(args.out, "attack_intent.png"))

    print(f"[*] Done — 5 charts in {args.out}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
