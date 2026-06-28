"""
Display helpers — banner, progress bar, live stats table.
"""

import os
import time


RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
RESET  = "\033[0m"
BOLD   = "\033[1m"
MAGENTA = "\033[95m"


def print_banner():
    banner = f"""
{CYAN}{BOLD}
  ╔══════════════════════════════════════════════════╗
  ║         Mini IDS — Intrusion Detection           ║
  ║         Network Security Monitoring Tool         ║
  ╠══════════════════════════════════════════════════╣
  ║  Detects: Port Scan | SYN Flood | Brute Force   ║
  ║           Suspicious IP | Payload Anomaly        ║
  ╚══════════════════════════════════════════════════╝
{RESET}"""
    print(banner)


def print_progress(current: int, total: int, alerts: int, label: str = "Packets"):
    bar_len = 30
    filled  = int(bar_len * current / max(total, 1))
    bar     = "█" * filled + "░" * (bar_len - filled)
    pct     = (current / max(total, 1)) * 100
    alert_color = RED if alerts > 0 else GREEN
    print(f"\r  {CYAN}[{bar}]{RESET} {pct:5.1f}%  "
          f"{label}: {current}/{total}  "
          f"Alerts: {alert_color}{alerts}{RESET}  ",
          end="", flush=True)


def print_live_stats(pkt_count: int, alerts: dict):
    """Print a compact live stats line."""
    print(f"\r  {BLUE}Pkts:{RESET}{pkt_count:>6}  "
          f"{RED}HIGH:{alerts.get('HIGH',0):>3}{RESET}  "
          f"{YELLOW}MED:{alerts.get('MEDIUM',0):>3}{RESET}  "
          f"{GREEN}LOW:{alerts.get('LOW',0):>3}{RESET}",
          end="", flush=True)


def clear_line():
    print("\r" + " " * 80 + "\r", end="", flush=True)
