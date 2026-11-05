"""Stage 2: command-line controller that routes commands to the other modules."""

from __future__ import annotations

import argparse
import sys

import pandas as pd
from tabulate import tabulate

from . import __version__
from . import alerts as A
from .dashboard import generate_html_report, verify_report
from .parser import load_logs

# command name -> (detector, heading)
DETECTORS = {
    "loginfail": (A.detect_login_failures, "Login failures"),
    "bruteforce": (A.detect_bruteforce, "Brute-force suspects"),
    "alerts": (A.detect_sudo_usage, "Sudo usage"),
    "ips": (A.extract_ip_addresses, "IP addresses seen"),
    "hibernate": (A.detect_hibernation, "Hibernation / sleep events"),
    "battery": (A.detect_battery_alerts, "Battery / ACPI events"),
    "updates": (A.detect_patch_updates, "Package installs, upgrades, removals"),
    "tools": (A.detect_tool_installation, "Suspicious tool installations"),
}


def _show(df: pd.DataFrame, title: str, limit: int | None = None) -> None:
    print(f"\n=== {title} ({len(df)}) ===")
    if df.empty:
        print("None found.")
        return
    view = df.head(limit) if limit else df
    cols = [c for c in view.columns if c not in ("ts", "source")]
    print(tabulate(view[cols], headers="keys", tablefmt="github", showindex=False, maxcolwidths=90))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="main.py", description="Linux Log Sentinel: log viewer and SOC dashboard")
    p.add_argument("--log-dir", default="/var/log", help="directory holding the logs (default /var/log)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command")
    sub.add_parser("view", help="show the first 30 parsed log rows (default)")
    s = sub.add_parser("search", help="keyword search across log messages")
    s.add_argument("keyword")
    for name, (_, heading) in DETECTORS.items():
        sub.add_parser(name, help=heading.lower())
    r = sub.add_parser("report", help="generate the offline HTML SOC dashboard")
    r.add_argument("-o", "--output", default="security_report.html")
    v = sub.add_parser("verify", help="verify the SHA256 seal of a saved report")
    v.add_argument("file", nargs="?", default="security_report.html")
    sub.add_parser("monitor", help="live monitoring of the log directory")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cmd = args.command or "view"

    if cmd == "verify":
        ok = verify_report(args.file)
        print(f"{args.file}: {'INTEGRITY VERIFIED' if ok else 'TAMPERED OR NOT A SENTINEL REPORT'}")
        return 0 if ok else 1
    if cmd == "monitor":
        from .monitor import start_monitoring
        start_monitoring(args.log_dir)
        return 0

    df = load_logs(args.log_dir)
    if df.empty:
        print(f"No log data found in {args.log_dir}. Try --log-dir samples, or run with sudo.", file=sys.stderr)
        return 1

    if cmd == "view":
        _show(df, f"Log viewer: first 30 of {len(df)} events", limit=30)
    elif cmd == "search":
        hits = df[df["message"].str.contains(args.keyword, case=False, regex=False)]
        _show(hits, f"Search results for '{args.keyword}'", limit=50)
    elif cmd == "report":
        digest = generate_html_report(df, args.output)
        print(f"Report written to {args.output}\nSHA256: {digest}")
    else:
        fn, heading = DETECTORS[cmd]
        _show(fn(df), heading)
    return 0
