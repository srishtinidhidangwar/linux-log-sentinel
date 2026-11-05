# Linux Log Sentinel

A Python host-based intrusion detection tool that parses Linux system logs, detects security events, and produces a **fully offline SOC dashboard** sealed with a SHA256 hash. Built as an M.Sc. Digital Forensics & Information Security minor project at the National Forensic Sciences University (NFSU), Gandhinagar.

![CI](https://github.com/<your-username>/linux-log-sentinel/actions/workflows/ci.yml/badge.svg)

## Features

- **Parser** for `auth.log`, `syslog`, `kern.log`, `dpkg.log` (ISO and traditional syslog timestamps) into a pandas DataFrame
- **Detections:** login failures, SSH brute force, sudo commands, sleep/hibernation, battery/ACPI events, package changes, and installs of 40 known hacking/forensics tools
- **Offline HTML dashboard:** KPI cards, 24h event timeline, alert donut, top-services bars. All charts are pure SVG, no CDN, no internet
- **Forensic integrity:** report body is SHA256-sealed; `verify` detects tampering
- **Live monitor:** watchdog-based, re-scans about 1 second after a log changes and prints only new alerts
- No server, agent, or licence needed

## Quick start

```bash
git clone https://github.com/<your-username>/linux-log-sentinel.git
cd linux-log-sentinel
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# try it on synthetic demo logs (safe, no root needed)
python scripts/make_sample_logs.py
python main.py --log-dir samples report
python main.py verify

# on a real Debian/Kali machine
sudo .venv/bin/python main.py report
```

## Commands

| Command | What it does |
|---|---|
| `python3 main.py` / `view` | First 30 parsed log rows |
| `search <keyword>` | Keyword search across messages |
| `loginfail` | Failed authentication attempts |
| `bruteforce` | IPs with 3+ failed attempts |
| `alerts` | `sudo` commands executed |
| `ips` | All IP addresses seen, by frequency |
| `hibernate` | Suspend / resume events |
| `battery` | ACPI battery events (long-line false positives filtered) |
| `updates` | Package installs, upgrades, removals |
| `tools` | Known hacking/forensics tool installs |
| `report [-o FILE]` | Generate the HTML dashboard |
| `verify [FILE]` | Check the report's SHA256 seal |
| `monitor` | Live monitoring |

Global option: `--log-dir DIR` (default `/var/log`).

## Architecture

```
/var/log/*.log --> parser.py --> DataFrame --> cli.py (router)
                                     |-> alerts.py   (detectors)
                                     |-> dashboard.py (HTML + SVG + SHA256)
                                     '-> monitor.py  (watchdog, live alerts)
```

## Detection rules

| Detector | Pattern | Severity |
|---|---|---|
| Login failure | `authentication failure`, `Failed password`, `password check failed` | High |
| Brute force | same IP in 3 or more failures | Critical |
| Sudo | `COMMAND=` in sudo entries | Medium |
| Hibernation | sleep / suspend / resume in syslog and kern.log | Low |
| Battery | `ACPI: battery`, `ACAD`, `BAT0/1` in lines under 200 chars | Medium |
| Package change | dpkg install/upgrade/remove with architecture suffix | Medium |
| Suspicious tool | dpkg install of a known tool (nmap, hydra, steghide, foremost, ...) | High |

Thresholds and the tool list live at the top of `log_sentinel/alerts.py`.

## Security notes

- Log text is attacker-controlled, so every value is HTML-escaped before it reaches the report (covered by a test).
- The SHA256 seal proves the report was not altered after generation. It is not a signature: anyone can regenerate a report with a fresh hash. Store the hash separately for evidence use.

## Development

```bash
pip install -r requirements-dev.txt
pytest
```

CI runs the tests on Python 3.11 and 3.12 and builds a sample report as a downloadable artifact.

## Limitations

Single host, Debian-family log formats only (RHEL/Arch and systemd-journal JSON need parser changes), no network or file-integrity analysis.

## Roadmap

Flask web UI, e-mail/SMS alerts, remote syslog forwarding, multi-host correlation, configurable thresholds via YAML.

## Author

Srishti Nidhi Dangwar, M.Sc. Digital Forensics & Information Security, NFSU Gandhinagar.
Supervisor: Mr. Sarang Rajvansh, Assistant Professor.

## License

MIT, see [LICENSE](LICENSE).
