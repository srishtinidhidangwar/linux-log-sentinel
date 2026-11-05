"""Stage 1: turn raw Linux log files into a structured pandas DataFrame."""

from __future__ import annotations

import os
import re
import sys
from datetime import datetime

import pandas as pd

LOG_FILES = ["auth.log", "syslog", "kern.log", "dpkg.log"]
COLUMNS = ["timestamp", "host", "service", "message", "source", "ts"]

# Modern Debian/Kali rsyslog: 2026-04-11T10:22:01.123456+05:30 kali sshd[9823]: message
_ISO = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T[\d:.]+(?:[+-]\d{2}:?\d{2}|Z)?)\s+(\S+)\s+([^\s:\[]+)(?:\[\d+\])?:\s*(.*)$"
)
# Traditional syslog: Apr 11 10:22:01 kali sshd[9823]: message
_TRAD = re.compile(
    r"^([A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\s:\[]+)(?:\[\d+\])?:\s*(.*)$"
)
# dpkg.log: 2026-04-11 10:22:01 install steghide:amd64 <none> 0.5.1-15
_DPKG = re.compile(r"^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$")

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def _to_datetime(raw: str, year: int):
    """Best-effort timestamp parse. Returns a naive datetime (wall-clock) or None."""
    try:
        if raw[:4].isdigit():
            dt = datetime.fromisoformat(raw.replace(" ", "T"))
            return dt.replace(tzinfo=None)
        parts = raw.split()
        h, m, s = (int(x) for x in parts[2].split(":"))
        return datetime(year, _MONTHS[parts[0]], int(parts[1]), h, m, s)
    except (ValueError, KeyError, IndexError):
        return None


def parse_line(line: str, source: str = "", year: int | None = None) -> dict | None:
    """Parse one log line into a record dict, or None if it is malformed."""
    line = line.strip()
    if not line:
        return None
    year = year or datetime.now().year

    m = _DPKG.match(line) if source == "dpkg.log" else None
    if m:
        date, time_, action, rest = m.groups()
        raw = f"{date} {time_}"
        return {"timestamp": raw, "host": "-", "service": action, "message": rest,
                "source": source, "ts": _to_datetime(raw, year)}

    m = _ISO.match(line) or _TRAD.match(line)
    if m:
        raw, host, service, message = m.groups()
        return {"timestamp": raw, "host": host, "service": service, "message": message,
                "source": source, "ts": _to_datetime(raw, year)}
    return None


def parse_log_file(path: str, year: int | None = None) -> pd.DataFrame:
    """Parse a log file into a DataFrame (timestamp, host, service, message, ...).

    Unreadable bytes are ignored and malformed lines are skipped. Process IDs are
    stripped from service names (sshd[9823] -> sshd) so one service is one label.
    """
    source = os.path.basename(path)
    rows = []
    with open(path, "r", errors="ignore") as fh:
        for line in fh:
            rec = parse_line(line, source, year)
            if rec:
                rows.append(rec)
    df = pd.DataFrame(rows, columns=COLUMNS)
    df["ts"] = pd.to_datetime(df["ts"])
    return df


def load_logs(log_dir: str = "/var/log") -> pd.DataFrame:
    """Parse every known log file in log_dir and concatenate into one DataFrame."""
    frames = []
    for name in LOG_FILES:
        path = os.path.join(log_dir, name)
        try:
            frames.append(parse_log_file(path))
        except (FileNotFoundError, PermissionError) as exc:
            print(f"[!] Skipping {path}: {exc.__class__.__name__}", file=sys.stderr)
    if not frames:
        return pd.DataFrame(columns=COLUMNS)
    return pd.concat(frames, ignore_index=True)
