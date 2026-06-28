"""
Report Generator
Produces a full session report in:
  - reports/ids_report_<date>.txt  (detailed human-readable)
  - reports/ids_report_<date>.html (browser-viewable with basic styling)
"""

import os
from datetime import datetime
from collections import Counter
from typing import List
from src.models import ThreatAlert, Packet


REPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")


class ReportGenerator:

    def __init__(self, packets: List[Packet], alerts: List[ThreatAlert], session_start: datetime):
        self.packets       = packets
        self.alerts        = alerts
        self.session_start = session_start
        self.session_end   = datetime.now()
        os.makedirs(REPORT_DIR, exist_ok=True)

    def generate(self) -> str:
        """Generate both TXT and HTML reports. Return path of TXT report."""
        date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        txt_path  = os.path.join(REPORT_DIR, f"ids_report_{date_str}.txt")
        html_path = os.path.join(REPORT_DIR, f"ids_report_{date_str}.html")

        txt_content  = self._build_txt_report()
        html_content = self._build_html_report()

        with open(txt_path, "w")  as f: f.write(txt_content)
        with open(html_path, "w") as f: f.write(html_content)

        print(f"\n\033[92m[*] Report saved:\033[0m")
        print(f"    TXT  -> {txt_path}")
        print(f"    HTML -> {html_path}")
        return txt_path

    # ── Statistics helpers ────────────────────────────────────────────────────

    def _stats(self):
        threat_counts = Counter(a.threat_type for a in self.alerts)
        sev_counts    = Counter(a.severity    for a in self.alerts)
        src_counts    = Counter(a.src_ip      for a in self.alerts)
        proto_counts  = Counter(p.protocol    for p in self.packets)
        blocked_ips   = {a.src_ip for a in self.alerts if a.action_taken == "BLOCKED"}
        duration      = (self.session_end - self.session_start).total_seconds()
        return dict(
            total_packets=len(self.packets),
            total_alerts=len(self.alerts),
            threat_counts=threat_counts,
            sev_counts=sev_counts,
            top_attackers=src_counts.most_common(5),
            proto_counts=proto_counts,
            blocked_ips=blocked_ips,
            duration=duration,
        )

    # ── Plain-text report ─────────────────────────────────────────────────────

    def _build_txt_report(self) -> str:
        s = self._stats()
        sep = "=" * 65
        lines = [
            sep,
            "       NETWORK INTRUSION DETECTION SYSTEM REPORT",
            sep,
            f"  Generated   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"  Session     : {self.session_start.strftime('%H:%M:%S')} → "
                             f"{self.session_end.strftime('%H:%M:%S')} "
                             f"({s['duration']:.1f}s)",
            sep,
            "",
            "  EXECUTIVE SUMMARY",
            "  " + "-" * 40,
            f"  Total Packets Analysed : {s['total_packets']}",
            f"  Total Threats Detected : {s['total_alerts']}",
            f"  HIGH severity alerts   : {s['sev_counts'].get('HIGH', 0)}",
            f"  MEDIUM severity alerts : {s['sev_counts'].get('MEDIUM', 0)}",
            f"  LOW severity alerts    : {s['sev_counts'].get('LOW', 0)}",
            f"  Blocked IPs            : {len(s['blocked_ips'])}",
            "",
            "  THREAT BREAKDOWN",
            "  " + "-" * 40,
        ]
        for ttype, cnt in s['threat_counts'].most_common():
            lines.append(f"  {ttype:<30} {cnt} alert(s)")

        lines += [
            "",
            "  PROTOCOL DISTRIBUTION",
            "  " + "-" * 40,
        ]
        for proto, cnt in s['proto_counts'].most_common():
            pct = (cnt / max(s['total_packets'], 1)) * 100
            lines.append(f"  {proto:<10} {cnt:>6} packets  ({pct:.1f}%)")

        lines += [
            "",
            "  TOP ATTACKING IPs",
            "  " + "-" * 40,
        ]
        for ip, cnt in s['top_attackers']:
            blocked = " [BLOCKED]" if ip in s['blocked_ips'] else ""
            lines.append(f"  {ip:<22} {cnt} alerts{blocked}")

        lines += [
            "",
            "  BLOCKED IPs",
            "  " + "-" * 40,
        ]
        if s['blocked_ips']:
            for ip in s['blocked_ips']:
                lines.append(f"  {ip}")
        else:
            lines.append("  None")

        lines += [
            "",
            "  DETAILED ALERT LOG",
            "  " + "-" * 40,
        ]
        for alert in self.alerts:
            lines.append(f"\n  [{alert.timestamp.strftime('%H:%M:%S')}] "
                         f"{alert.threat_type} | {alert.severity}")
            lines.append(f"  Source  : {alert.src_ip}")
            lines.append(f"  Target  : {alert.dst_ip}:{alert.dst_port}")
            lines.append(f"  Detail  : {alert.description}")
            lines.append(f"  Action  : {alert.action_taken}")
            lines.append("  " + "-" * 40)

        lines += ["", sep, "  END OF REPORT", sep, ""]
        return "\n".join(lines)

    # ── HTML report ───────────────────────────────────────────────────────────

    def _build_html_report(self) -> str:
        s = self._stats()
        sev_color = {"HIGH": "#e74c3c", "MEDIUM": "#f39c12", "LOW": "#27ae60"}

        alert_rows = ""
        for a in self.alerts:
            color = sev_color.get(a.severity, "#888")
            alert_rows += f"""
            <tr>
              <td>{a.timestamp.strftime('%H:%M:%S')}</td>
              <td>{a.threat_type}</td>
              <td style="color:{color};font-weight:bold">{a.severity}</td>
              <td>{a.src_ip}</td>
              <td>{a.dst_ip}:{a.dst_port}</td>
              <td>{a.description[:70]}...</td>
              <td>{a.action_taken}</td>
            </tr>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Mini IDS Report</title>
<style>
  body {{font-family:Arial,sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:20px}}
  h1 {{color:#58a6ff;border-bottom:1px solid #30363d;padding-bottom:10px}}
  h2 {{color:#79c0ff;margin-top:30px}}
  .cards {{display:flex;gap:16px;flex-wrap:wrap;margin:20px 0}}
  .card {{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 24px;min-width:150px}}
  .card .num {{font-size:2em;font-weight:bold}}
  .card .lbl {{font-size:0.8em;color:#8b949e;margin-top:4px}}
  .high   {{color:#f85149}} .medium {{color:#d29922}} .low {{color:#3fb950}}
  table {{border-collapse:collapse;width:100%;margin-top:10px}}
  th {{background:#21262d;padding:8px 12px;text-align:left;border-bottom:1px solid #30363d}}
  td {{padding:7px 12px;border-bottom:1px solid #21262d;font-size:13px}}
  tr:hover td {{background:#161b22}}
  .blocked {{background:#3d1111;padding:4px 8px;border-radius:4px;font-family:monospace}}
  footer {{margin-top:40px;color:#8b949e;font-size:12px;border-top:1px solid #30363d;padding-top:12px}}
</style>
</head>
<body>
<h1>🛡️ Network Intrusion Detection Report</h1>
<p style="color:#8b949e">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
Session: {self.session_start.strftime('%H:%M:%S')} → {self.session_end.strftime('%H:%M:%S')}
({s['duration']:.1f}s)</p>

<h2>Summary</h2>
<div class="cards">
  <div class="card"><div class="num" style="color:#58a6ff">{s['total_packets']}</div><div class="lbl">Packets Captured</div></div>
  <div class="card"><div class="num high">{s['total_alerts']}</div><div class="lbl">Threats Detected</div></div>
  <div class="card"><div class="num high">{s['sev_counts'].get('HIGH',0)}</div><div class="lbl">HIGH Severity</div></div>
  <div class="card"><div class="num medium">{s['sev_counts'].get('MEDIUM',0)}</div><div class="lbl">MEDIUM Severity</div></div>
  <div class="card"><div class="num low">{s['sev_counts'].get('LOW',0)}</div><div class="lbl">LOW Severity</div></div>
  <div class="card"><div class="num" style="color:#f85149">{len(s['blocked_ips'])}</div><div class="lbl">IPs Blocked</div></div>
</div>

<h2>Alert Details</h2>
<table>
  <tr><th>Time</th><th>Threat</th><th>Severity</th><th>Source IP</th><th>Target</th><th>Description</th><th>Action</th></tr>
  {alert_rows}
</table>

<h2>Blocked IPs</h2>
{''.join(f'<span class="blocked">{ip}</span> ' for ip in s['blocked_ips']) or '<p>None</p>'}


</body></html>"""
