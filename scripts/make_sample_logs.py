#!/usr/bin/env python3
"""Generate small, fully synthetic Kali-style logs in ./samples for demos and tests."""
import os
import random
from datetime import datetime, timedelta

random.seed(7)
out = os.path.join(os.path.dirname(__file__), "..", "samples")
os.makedirs(out, exist_ok=True)
base = datetime(2026, 4, 11, 0, 5, 0)


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.%f") + "+05:30"


def clock(i):
    return base + timedelta(minutes=i * 7 + random.randint(0, 5))


auth, syslog, kern, dpkg = [], [], [], []
for i in range(120):
    t = clock(i)
    syslog.append(f"{iso(t)} kali systemd[1]: Started Session {i} of User kali.")
    if i % 9 == 0:
        syslog.append(f"{iso(t)} kali CRON[{2000 + i}]: (root) CMD (command -v debian-sa1)")
for i, ip in enumerate(["203.0.113.50"] * 5 + ["198.51.100.7"] * 2):
    t = base + timedelta(hours=3, seconds=i * 4)
    auth.append(f"{iso(t)} kali sshd[{9800 + i}]: Failed password for root from {ip} port {40000 + i} ssh2")
t = base + timedelta(hours=9)
auth += [
    f"{iso(t)} kali sshd[9900]: Accepted password for kali from 192.168.1.20 port 51234 ssh2",
    f"{iso(t)} kali login[1100]: pam_unix(login:auth): authentication failure; logname=LOGIN uid=0 rhost= user=kali",
    f"{iso(t)} kali sudo:     kali : TTY=pts/0 ; PWD=/home/kali ; USER=root ; COMMAND=/usr/bin/apt update",
    f"{iso(t)} kali sudo:     kali : TTY=pts/0 ; PWD=/home/kali ; USER=root ; COMMAND=/usr/bin/nmap -sV 10.0.0.5",
    f"{iso(t)} kali sudo: pam_unix(sudo:session): session opened for user root(uid=0) by kali(uid=1000)",
]
syslog.append(f"{iso(base + timedelta(hours=14))} kali systemd-sleep[3100]: System is suspending (PM: suspend entry).")
kern.append(f"{iso(base + timedelta(hours=14))} kali kernel: ACPI: battery: Slot [BAT0] (battery present)")
kern.append(f"{iso(base + timedelta(hours=15))} kali kernel: ACPI: AC Adapter ACAD state changed")
kern.append(f"{iso(base)} kali kernel: Loaded modules: " + " ".join(f"battery_mod{i}" for i in range(60)))
for pkg, ver in [("steghide", "0.5.1-15"), ("foremost", "1.5.7-11"), ("curl", "8.5.0-2"), ("htop", "3.3.0-1")]:
    dpkg.append(f"2026-04-11 10:22:{random.randint(10, 59)} install {pkg}:amd64 <none> {ver}")
    dpkg.append(f"2026-04-11 10:22:59 status installed {pkg}:amd64 {ver}")
dpkg.append("2026-04-11 11:05:01 upgrade openssl:amd64 3.0.13-1 3.0.14-1")
dpkg.append("2026-04-11 11:05:09 remove libfoo1:all 1.0-1 <none>")

for name, lines in {"auth.log": auth, "syslog": syslog, "kern.log": kern, "dpkg.log": dpkg}.items():
    with open(os.path.join(out, name), "w") as fh:
        fh.write("\n".join(lines) + "\n")
print("Sample logs written to", os.path.abspath(out))
