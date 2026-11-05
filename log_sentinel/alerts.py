"""Stage 3: security detection rules. Every detector takes the unified DataFrame
and returns a DataFrame of findings (printing is left to the caller)."""

from __future__ import annotations

import re
from collections import Counter

import pandas as pd

BRUTE_FORCE_THRESHOLD = 3
BATTERY_MAX_LEN = 200

AUTH_FAIL_RE = r"authentication failure|Failed password|password check failed"
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SLEEP_RE = r"\b(?:sleep|suspend|resume)\b"
BATTERY_RE = r"ACPI: battery|ACAD|BAT0|BAT1"

SUSPICIOUS_TOOLS = {
    "nmap", "hydra", "metasploit-framework", "sqlmap", "wireshark", "steghide",
    "foremost", "netcat", "netcat-traditional", "ncat", "hashcat", "john", "aircrack-ng",
    "nikto", "burpsuite", "ettercap-text-only", "ettercap-graphical", "autopsy", "sleuthkit",
    "binwalk", "volatility", "volatility3", "bulk-extractor", "scalpel", "exiftool",
    "tcpdump", "wfuzz", "gobuster", "dirb", "medusa", "responder", "crackmapexec",
    "ophcrack", "maltego", "zaproxy", "radare2", "ghidra", "chntpw", "dc3dd", "dcfldd",
}

_COLS = ["timestamp", "service", "message", "source"]


def _pick(df: pd.DataFrame, mask) -> pd.DataFrame:
    return df.loc[mask, _COLS].reset_index(drop=True)


def detect_login_failures(df: pd.DataFrame) -> pd.DataFrame:
    return _pick(df, df["message"].str.contains(AUTH_FAIL_RE, case=False, regex=True))


def detect_bruteforce(df: pd.DataFrame, threshold: int = BRUTE_FORCE_THRESHOLD) -> pd.DataFrame:
    """IPs that appear in `threshold` or more failed-authentication messages."""
    counts: Counter = Counter()
    for msg in detect_login_failures(df)["message"]:
        counts.update(IP_RE.findall(msg))
    rows = [{"ip": ip, "failed_attempts": n} for ip, n in counts.most_common() if n >= threshold]
    return pd.DataFrame(rows, columns=["ip", "failed_attempts"])


def detect_sudo_usage(df: pd.DataFrame) -> pd.DataFrame:
    return _pick(df, (df["service"] == "sudo") & df["message"].str.contains("COMMAND=", regex=False))


def detect_ssh_events(df: pd.DataFrame) -> pd.DataFrame:
    return _pick(df, df["service"] == "sshd")


def detect_hibernation(df: pd.DataFrame) -> pd.DataFrame:
    in_scope = df["source"].isin(["syslog", "kern.log"])
    return _pick(df, in_scope & df["message"].str.contains(SLEEP_RE, case=False, regex=True))


def detect_battery_alerts(df: pd.DataFrame) -> pd.DataFrame:
    """ACPI/battery events. The length filter drops long kernel-module lists that
    merely mention the word 'battery' (the main false-positive source)."""
    hit = df["message"].str.contains(BATTERY_RE, regex=True) & (df["message"].str.len() < BATTERY_MAX_LEN)
    return _pick(df, hit)


def _package_mask(df: pd.DataFrame, actions: set[str]):
    return ((df["source"] == "dpkg.log") & df["service"].isin(actions)
            & df["message"].str.contains(r":(?:amd64|arm64|i386|all)\b", regex=True))


def detect_patch_updates(df: pd.DataFrame) -> pd.DataFrame:
    return _pick(df, _package_mask(df, {"install", "upgrade", "remove"}))


def detect_tool_installation(df: pd.DataFrame) -> pd.DataFrame:
    rows = df[_package_mask(df, {"install"})]
    pkg = rows["message"].str.split(r"[:\s]", n=1, regex=True).str[0]
    mask = pkg.isin(SUSPICIOUS_TOOLS)
    out = rows.loc[mask, _COLS].reset_index(drop=True)
    out["tool"] = pkg[mask].reset_index(drop=True)
    return out


def extract_ip_addresses(df: pd.DataFrame) -> pd.DataFrame:
    counts: Counter = Counter()
    for msg in df["message"]:
        counts.update(IP_RE.findall(msg))
    return pd.DataFrame(counts.most_common(), columns=["ip", "occurrences"])


# ---- combined view used by the dashboard and the live monitor -------------------

SEVERITY = {
    "Brute force": "Critical",
    "Login failure": "High",
    "Suspicious tool": "High",
    "Sudo command": "Medium",
    "Battery event": "Medium",
    "Package change": "Medium",
    "Hibernation": "Low",
}


def collect_alerts(df: pd.DataFrame) -> list[dict]:
    """Run every detector and return one flat, ordered list of alert dicts."""
    alerts: list[dict] = []

    def add(kind: str, frame: pd.DataFrame, detail=lambda r: r["message"]):
        for _, r in frame.iterrows():
            alerts.append({"type": kind, "severity": SEVERITY[kind],
                           "time": r["timestamp"], "detail": detail(r)})

    for _, r in detect_bruteforce(df).iterrows():
        alerts.append({"type": "Brute force", "severity": "Critical", "time": "-",
                       "detail": f"{r['ip']} failed authentication {r['failed_attempts']} times"})
    add("Login failure", detect_login_failures(df))
    tools = detect_tool_installation(df)
    add("Suspicious tool", tools, lambda r: f"{r['tool']} installed ({r['message']})")
    add("Sudo command", detect_sudo_usage(df))
    add("Battery event", detect_battery_alerts(df))
    add("Hibernation", detect_hibernation(df))
    pkgs = detect_patch_updates(df)
    other = pkgs[~pkgs["message"].isin(set(tools["message"]))]  # tools already reported above
    add("Package change", other, lambda r: f"{r['service']} {r['message']}")
    return alerts
