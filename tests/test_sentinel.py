import pandas as pd
import pytest

from log_sentinel import alerts as A
from log_sentinel.dashboard import generate_html_report, verify_report
from log_sentinel.parser import parse_line, parse_log_file

ISO = "2026-04-11T10:22:01.123456+05:30 kali sshd[9823]: Failed password for root from 203.0.113.50 port 22 ssh2"


def frame(rows):
    cols = ["timestamp", "host", "service", "message", "source", "ts"]
    df = pd.DataFrame(rows, columns=cols)
    df["ts"] = pd.to_datetime(df["ts"])
    return df


def row(service, message, source="auth.log", ts="2026-04-11 10:00:00"):
    return [ts, "kali", service, message, source, ts]


def test_pid_is_stripped_from_service():
    rec = parse_line(ISO, "auth.log")
    assert rec["service"] == "sshd" and rec["host"] == "kali"
    assert rec["message"].startswith("Failed password")


def test_traditional_syslog_and_dpkg_formats():
    assert parse_line("Apr 11 10:22:01 kali sudo: kali : COMMAND=/bin/ls", "auth.log", 2026)["service"] == "sudo"
    d = parse_line("2026-04-11 10:22:01 install steghide:amd64 <none> 0.5.1-15", "dpkg.log")
    assert d["service"] == "install" and d["message"].startswith("steghide:amd64")


def test_malformed_lines_are_skipped(tmp_path):
    p = tmp_path / "auth.log"
    p.write_text("garbage\n\n" + ISO + "\n")
    assert len(parse_log_file(str(p))) == 1


def test_bruteforce_threshold():
    msgs = ["Failed password for root from 1.2.3.4 port 1"] * 3 + ["Failed password for x from 5.6.7.8 port 1"]
    df = frame([row("sshd", m) for m in msgs])
    out = A.detect_bruteforce(df)
    assert list(out["ip"]) == ["1.2.3.4"] and out.iloc[0]["failed_attempts"] == 3


def test_sudo_requires_command():
    df = frame([row("sudo", "kali : COMMAND=/bin/ls"), row("sudo", "pam_unix(sudo:session): opened")])
    assert len(A.detect_sudo_usage(df)) == 1


def test_battery_length_filter_removes_false_positive():
    df = frame([row("kernel", "ACPI: battery: Slot [BAT0]", "kern.log"),
                row("kernel", "modules: " + "BAT0 " * 100, "kern.log")])
    assert len(A.detect_battery_alerts(df)) == 1


def test_tool_detection_only_flags_installs_of_known_tools():
    df = frame([row("install", "steghide:amd64 <none> 0.5.1-15", "dpkg.log"),
                row("install", "curl:amd64 <none> 8.5", "dpkg.log"),
                row("status", "installed steghide:amd64 0.5.1-15", "dpkg.log")])
    out = A.detect_tool_installation(df)
    assert list(out["tool"]) == ["steghide"]


def test_empty_frame_does_not_crash(tmp_path):
    df = frame([])
    assert A.collect_alerts(df) == []
    out = tmp_path / "r.html"
    generate_html_report(df, str(out))
    assert verify_report(str(out))


def test_report_escapes_log_content_and_seal_detects_tampering(tmp_path):
    evil = "Failed password for <script>alert(1)</script> from 9.9.9.9"
    df = frame([row("sshd", evil)])
    out = tmp_path / "r.html"
    digest = generate_html_report(df, str(out))
    page = out.read_text()
    assert "<script>alert(1)" not in page and "&lt;script&gt;" in page
    assert len(digest) == 64 and verify_report(str(out))
    out.write_text(page.replace("Critical", "Low").replace("Login failure", "Nothing to see"))
    assert not verify_report(str(out))
