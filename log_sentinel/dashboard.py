"""Stage 4: standalone offline SOC dashboard (pure SVG, no CDN) with a SHA256 seal."""

from __future__ import annotations

import hashlib
import html
import re
from collections import Counter
from datetime import datetime

import pandas as pd

from . import alerts as A

START, END = "<!--SENTINEL-BODY-START-->", "<!--SENTINEL-BODY-END-->"
PALETTE = {"Brute force": "#ff4d4f", "Login failure": "#ff7a45", "Suspicious tool": "#ffa940",
           "Sudo command": "#36cfc9", "Battery event": "#597ef7", "Package change": "#9254de",
           "Hibernation": "#8c8c8c"}
SEV_COLOR = {"Critical": "#ff4d4f", "High": "#ff7a45", "Medium": "#faad14", "Low": "#8c8c8c"}

CSS = """
body{margin:0;background:#0d1117;color:#e6edf3;font-family:system-ui,Segoe UI,Roboto,sans-serif}
header{padding:18px 28px;border-bottom:1px solid #30363d}h1{margin:0;font-size:22px}
.sub{color:#8b949e;font-size:13px;margin-top:4px}main{padding:24px 28px;max-width:1100px;margin:auto}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.kpi{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px}
.kpi b{display:block;font-size:26px}.kpi span{color:#8b949e;font-size:12px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin-top:16px}
.card h2{margin:0 0 10px;font-size:15px;color:#c9d1d9}.row{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:800px){.row{grid-template-columns:1fr}}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #21262d;vertical-align:top}
th{color:#8b949e;font-weight:600}td.d{word-break:break-all;font-family:ui-monospace,Consolas,monospace;font-size:12px}
.pill{padding:2px 8px;border-radius:10px;font-size:11px;color:#0d1117;font-weight:700}
.ok{color:#3fb950}footer{padding:18px 28px;color:#8b949e;font-size:12px;border-top:1px solid #30363d;word-break:break-all}
svg{max-width:100%;height:auto}
"""


def _esc(x) -> str:
    return html.escape(str(x), quote=True)  # log text is attacker-controlled: always escape


def _line_chart(counts: list[int]) -> str:
    W, H, pl, pr, pt, pb = 660, 210, 40, 15, 15, 30
    pw, ph = W - pl - pr, H - pt - pb
    mx = max(max(counts), 1)
    pts = [(pl + i * pw / 23, pt + ph - c / mx * ph) for i, c in enumerate(counts)]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
    area = f"{pl},{pt + ph} {line} {pl + pw},{pt + ph}"
    grid = "".join(
        f'<line x1="{pl}" x2="{W - pr}" y1="{pt + ph - f * ph:.1f}" y2="{pt + ph - f * ph:.1f}" stroke="#21262d"/>'
        f'<text x="{pl - 6}" y="{pt + ph - f * ph + 4:.1f}" fill="#8b949e" font-size="10" text-anchor="end">{round(mx * f)}</text>'
        for f in (0, 0.5, 1))
    ticks = "".join(
        f'<text x="{pl + h * pw / 23:.1f}" y="{H - 8}" fill="#8b949e" font-size="10" text-anchor="middle">{h:02d}</text>'
        for h in range(0, 24, 3))
    return (f'<svg viewBox="0 0 {W} {H}" role="img" aria-label="Events per hour">{grid}{ticks}'
            f'<polygon points="{area}" fill="#58a6ff" fill-opacity="0.15"/>'
            f'<polyline points="{line}" fill="none" stroke="#58a6ff" stroke-width="2"/></svg>')


def _donut(counts: Counter) -> str:
    total = sum(counts.values())
    r, c = 70, 2 * 3.14159265 * 70
    segs, offset = "", 0.0
    for kind, n in counts.items():
        length = n / total * c
        segs += (f'<circle cx="100" cy="100" r="{r}" fill="none" stroke="{PALETTE[kind]}" stroke-width="28" '
                 f'stroke-dasharray="{length:.2f} {c - length:.2f}" stroke-dashoffset="{-offset:.2f}" '
                 f'transform="rotate(-90 100 100)"/>')
        offset += length
    if not total:
        segs = f'<circle cx="100" cy="100" r="{r}" fill="none" stroke="#21262d" stroke-width="28"/>'
    legend = "".join(
        f'<rect x="215" y="{22 + i * 22}" width="12" height="12" fill="{PALETTE[k]}"/>'
        f'<text x="234" y="{32 + i * 22}" fill="#c9d1d9" font-size="12">{_esc(k)} ({n})</text>'
        for i, (k, n) in enumerate(counts.items()))
    return (f'<svg viewBox="0 0 400 200" role="img" aria-label="Alert distribution">{segs}'
            f'<text x="100" y="106" fill="#e6edf3" font-size="22" text-anchor="middle">{total}</text>{legend}</svg>')


def _bars(df: pd.DataFrame) -> str:
    top = df["service"].value_counts().head(7)
    mx = max(top.max() if len(top) else 1, 1)
    out = ""
    for i, (svc, n) in enumerate(top.items()):
        y, w = 10 + i * 28, n / mx * 230
        out += (f'<text x="110" y="{y + 14}" fill="#c9d1d9" font-size="12" text-anchor="end">{_esc(svc[:16])}</text>'
                f'<rect x="120" y="{y}" width="{w:.1f}" height="18" rx="3" fill="#3fb950"/>'
                f'<text x="{126 + w:.1f}" y="{y + 14}" fill="#8b949e" font-size="11">{n}</text>')
    return f'<svg viewBox="0 0 400 210" role="img" aria-label="Top services">{out}</svg>'


def _alert_rows(alerts: list[dict], limit: int = 100) -> str:
    rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    rows = ""
    for a in sorted(alerts, key=lambda a: rank[a["severity"]])[:limit]:
        rows += (f'<tr><td><span class="pill" style="background:{SEV_COLOR[a["severity"]]}">{a["severity"]}</span></td>'
                 f'<td>{_esc(a["type"])}</td><td>{_esc(a["time"])}</td><td class="d">{_esc(a["detail"])}</td></tr>')
    return rows or '<tr><td colspan="4" class="ok">No alerts raised.</td></tr>'


def _build_body(df: pd.DataFrame, generated: str) -> str:
    alerts = A.collect_alerts(df)
    dist = Counter(a["type"] for a in alerts)
    hours = df["ts"].dropna().dt.hour.value_counts() if len(df) else pd.Series(dtype=int)
    per_hour = [int(hours.get(h, 0)) for h in range(24)]
    kpis = [("Log events", len(df)), ("Alerts", len(alerts)), ("Login failures", len(A.detect_login_failures(df))),
            ("Sudo commands", len(A.detect_sudo_usage(df))), ("SSH events", len(A.detect_ssh_events(df))),
            ("Suspicious tools", len(A.detect_tool_installation(df)))]
    kpi_html = "".join(f'<div class="kpi"><b>{v:,}</b><span>{k}</span></div>' for k, v in kpis)
    features = ["Log parser", "Search", "Login failures", "Brute force", "Sudo monitor", "SSH monitor",
                "Hibernation", "Battery", "Patch updates", "Tool detection", "SVG charts", "SHA256 seal", "Live monitor"]
    feat_html = "".join(f'<span class="ok">&#10003; {f}</span> &nbsp; ' for f in features)
    return f"""{START}
<header><h1>Linux Log Sentinel &mdash; SOC Dashboard</h1><div class="sub">Generated {_esc(generated)}</div></header>
<main>
<div class="kpis">{kpi_html}</div>
<div class="card"><h2>Events per hour (24h)</h2>{_line_chart(per_hour)}</div>
<div class="row"><div class="card"><h2>Alert distribution</h2>{_donut(dist)}</div>
<div class="card"><h2>Top services</h2>{_bars(df)}</div></div>
<div class="card"><h2>Security alert log</h2><table><tr><th>Severity</th><th>Type</th><th>Time</th><th>Detail</th></tr>{_alert_rows(alerts)}</table></div>
<div class="card"><h2>Feature status</h2>{feat_html}</div>
</main>
{END}"""


def generate_html_report(df: pd.DataFrame, output: str = "security_report.html") -> str:
    """Write the offline report and return its SHA256 seal (hash of the report body)."""
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    body = _build_body(df, generated)
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    page = (f'<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>Linux Log Sentinel Report</title><style>{CSS}</style></head><body>{body}'
            f'<footer>SHA256 INTEGRITY SEAL: <code data-sha256="{digest}">{digest}</code></footer></body></html>')
    with open(output, "w", encoding="utf-8") as fh:
        fh.write(page)
    return digest


def verify_report(path: str) -> bool:
    """Recompute the body hash of a saved report and compare with its embedded seal."""
    with open(path, "r", encoding="utf-8") as fh:
        page = fh.read()
    seal = re.search(r'data-sha256="([0-9a-f]{64})"', page)
    s, e = page.find(START), page.find(END)
    if not seal or s < 0 or e < 0:
        return False
    body = page[s:e + len(END)]
    return hashlib.sha256(body.encode("utf-8")).hexdigest() == seal.group(1)
