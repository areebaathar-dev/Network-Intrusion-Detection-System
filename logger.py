"""
Security Logger
Writes alerts and events to:
  - Console (colored output)
  - logs/ids_log_<date>.txt  (plain text)
  - logs/ids_log_<date>.csv  (machine readable)
"""

import os
import csv
import logging
from datetime import datetime
from typing import List
from src.models import ThreatAlert, Packet


LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")

# ANSI color codes
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"
RESET   = "\033[0m"
BOLD    = "\033[1m"


class IDSLogger:

    def __init__(self):
        os.makedirs(LOG_DIR, exist_ok=True)
        date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_txt  = os.path.join(LOG_DIR, f"ids_log_{date_str}.txt")
        self.log_csv  = os.path.join(LOG_DIR, f"ids_log_{date_str}.csv")
        self._init_csv()
        self._session_alerts: List[ThreatAlert] = []
        self._session_packets: List[Packet]     = []

    # ── CSV setup ─────────────────────────────────────────────────────────────

    def _init_csv(self):
        with open(self.log_csv, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp", "threat_type", "severity",
                "src_ip", "dst_ip", "dst_port",
                "description", "packet_count", "action_taken"
            ])

    # ── Logging methods ───────────────────────────────────────────────────────

    def log_packet(self, pkt: Packet):
        self._session_packets.append(pkt)

    def log_alert(self, alert: ThreatAlert):
        self._session_alerts.append(alert)
        self._print_alert(alert)
        self._write_txt(alert)
        self._write_csv(alert)

    def log_info(self, msg: str):
        print(f"{CYAN}[INFO]{RESET}  {msg}")
        self._append_txt(f"[INFO] {msg}")

    def log_start(self, mode: str):
        msg = f"IDS Session started | Mode: {mode} | Time: {datetime.now()}"
        print(f"\n{GREEN}{BOLD}[*] {msg}{RESET}\n")
        self._append_txt(f"\n{'='*60}\n{msg}\n{'='*60}")

    def log_end(self, stats: dict):
        lines = [
            "",
            f"{BOLD}{'='*50}",
            f"  SESSION SUMMARY",
            f"{'='*50}{RESET}",
            f"  Packets Analysed : {stats.get('packets', 0)}",
            f"  Total Alerts     : {stats.get('alerts', 0)}",
            f"  HIGH severity    : {stats.get('HIGH', 0)}",
            f"  MEDIUM severity  : {stats.get('MEDIUM', 0)}",
            f"  LOW severity     : {stats.get('LOW', 0)}",
            f"  Blocked IPs      : {stats.get('blocked', 0)}",
            f"  Log saved to     : {self.log_txt}",
            f"  CSV saved to     : {self.log_csv}",
            f"{'='*50}\n",
        ]
        print("\n".join(lines))
        self._append_txt("\n".join(lines))

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _print_alert(self, alert: ThreatAlert):
        color = RED if alert.severity == "HIGH" else (YELLOW if alert.severity == "MEDIUM" else WHITE)
        icon  = "!!!" if alert.severity == "HIGH" else ("!!" if alert.severity == "MEDIUM" else "!")
        print(f"{color}{BOLD}[{icon}] {alert.threat_type}{RESET}  "
              f"{alert.src_ip} -> {alert.dst_ip}:{alert.dst_port}  "
              f"| {alert.severity}  "
              f"| {alert.description[:80]}...")

    def _write_txt(self, alert: ThreatAlert):
        self._append_txt(str(alert))

    def _write_csv(self, alert: ThreatAlert):
        with open(self.log_csv, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                alert.timestamp.isoformat(),
                alert.threat_type,
                alert.severity,
                alert.src_ip,
                alert.dst_ip,
                alert.dst_port,
                alert.description,
                alert.packet_count,
                alert.action_taken,
            ])

    def _append_txt(self, text: str):
        with open(self.log_txt, "a") as f:
            f.write(text + "\n")

    # ── Getters ───────────────────────────────────────────────────────────────

    @property
    def alerts(self) -> List[ThreatAlert]:
        return self._session_alerts

    @property
    def packets(self) -> List[Packet]:
        return self._session_packets
