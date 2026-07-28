"""
IDS Engine
Orchestrates: Simulator / Live Capture / PCAP Analysis
              → Detection Rules → Logger → Report
"""

import os
import sys
import time
from datetime import datetime
from collections import Counter

from src.models import Packet, ThreatAlert
from src.detection import DetectionEngine
from src.logger import IDSLogger
from src.report import ReportGenerator
from src.simulator import PacketSimulator
from src.display import print_progress, print_live_stats, clear_line

RED   = "\033[91m"
GREEN = "\033[92m"
CYAN  = "\033[96m"
RESET = "\033[0m"
BOLD  = "\033[1m"


class IDSEngine:

    def __init__(self):
        self.detector     = DetectionEngine()
        self.logger       = IDSLogger()
        self.session_start = datetime.now()

    # ── Mode 1: Live Capture ──────────────────────────────────────────────────

    def start_live_capture(self, iface: str):
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
        except ImportError:
            print(f"\n{RED}[!] scapy not installed. Run: pip install scapy{RESET}")
            print(f"{CYAN}[*] Falling back to simulation mode...{RESET}\n")
            self.start_simulation(300)
            return

        self.logger.log_start(f"LIVE CAPTURE on {iface}")
        sev_counts = Counter()

        def handle_packet(raw_pkt):
            pkt = self._scapy_to_model(raw_pkt)
            if pkt is None:
                return
            self.logger.log_packet(pkt)
            alerts = self.detector.inspect(pkt)
            for alert in alerts:
                self.logger.log_alert(alert)
                sev_counts[alert.severity] += 1
            n = len(self.logger.packets)
            print_live_stats(n, sev_counts)

        print(f"\n{GREEN}[*] Sniffing on {iface}. Press Ctrl+C to stop.{RESET}\n")
        try:
            sniff(iface=iface, prn=handle_packet, store=False)
        except KeyboardInterrupt:
            pass
        finally:
            clear_line()
            self._finish()

    # ── Mode 2: Simulation ────────────────────────────────────────────────────

    def start_simulation(self, total_packets: int = 500):
        self.logger.log_start("SIMULATION")
        sim = PacketSimulator(total_packets)
        sev_counts = Counter()

        print(f"\n{CYAN}[*] Simulating {total_packets} packets with embedded attack scenarios...{RESET}")
        print(f"    Attack types: PORT_SCAN | SYN_FLOOD | BRUTE_FORCE | SUSPICIOUS_IP | PAYLOAD_ANOMALY\n")

        for pkt in sim.stream():
            self.logger.log_packet(pkt)
            alerts = self.detector.inspect(pkt)
            for alert in alerts:
                self.logger.log_alert(alert)
                sev_counts[alert.severity] += 1
            n = len(self.logger.packets)
            print_progress(n, total_packets, len(self.logger.alerts))

        clear_line()
        self._finish()

    # ── Mode 3: PCAP Analysis ─────────────────────────────────────────────────

    def analyze_pcap(self, path: str):
        try:
            from scapy.all import rdpcap, IP, TCP, UDP, ICMP
        except ImportError:
            print(f"\n{RED}[!] scapy not installed. Run: pip install scapy{RESET}")
            return

        if not os.path.exists(path):
            print(f"\n{RED}[!] File not found: {path}{RESET}")
            return

        self.logger.log_start(f"PCAP ANALYSIS: {path}")
        print(f"\n{CYAN}[*] Reading {path}...{RESET}")

        raw_pkts = rdpcap(path)
        total    = len(raw_pkts)
        print(f"[*] {total} packets found. Analysing...\n")

        for i, raw in enumerate(raw_pkts):
            pkt = self._scapy_to_model(raw)
            if pkt is None:
                continue
            self.logger.log_packet(pkt)
            alerts = self.detector.inspect(pkt)
            for alert in alerts:
                self.logger.log_alert(alert)
            print_progress(i + 1, total, len(self.logger.alerts))

        clear_line()
        self._finish()

    # ── Mode 4: View Logs ─────────────────────────────────────────────────────

    def view_logs(self):
        log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
        if not os.path.exists(log_dir) or not os.listdir(log_dir):
            print(f"\n{CYAN}[*] No logs found. Run a capture first.{RESET}\n")
            return
        files = sorted(os.listdir(log_dir))
        print(f"\n{BOLD}Saved logs:{RESET}")
        for i, f in enumerate(files):
            size = os.path.getsize(os.path.join(log_dir, f))
            print(f"  [{i+1}] {f}  ({size} bytes)")
        choice = input("\nEnter number to view (or Enter to skip): ").strip()
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(files):
                path = os.path.join(log_dir, files[idx])
                with open(path) as f:
                    print("\n" + f.read())

    # ── Finish session ────────────────────────────────────────────────────────

    def _finish(self):
        alerts = self.logger.alerts
        sev_counts = Counter(a.severity for a in alerts)
        blocked    = {a.src_ip for a in alerts if a.action_taken == "BLOCKED"}

        stats = {
            "packets": len(self.logger.packets),
            "alerts":  len(alerts),
            "HIGH":    sev_counts.get("HIGH",   0),
            "MEDIUM":  sev_counts.get("MEDIUM", 0),
            "LOW":     sev_counts.get("LOW",    0),
            "blocked": len(blocked),
        }
        self.logger.log_end(stats)

        gen = input("Generate full report? (y/n): ").strip().lower()
        if gen == "y":
            rep = ReportGenerator(self.logger.packets, alerts, self.session_start)
            rep.generate()

    # ── Scapy packet → model ──────────────────────────────────────────────────

    def _scapy_to_model(self, raw) -> Packet:
        """Convert a scapy packet to our Packet dataclass."""
        try:
            from scapy.all import IP, TCP, UDP, ICMP, Raw
            if not raw.haslayer(IP):
                return None

            ip    = raw[IP]
            proto = "OTHER"
            flags = ""
            sport = 0
            dport = 0
            size  = len(raw)
            payload = ""

            if raw.haslayer(TCP):
                tcp   = raw[TCP]
                proto = "TCP"
                sport = tcp.sport
                dport = tcp.dport
                f_val = tcp.flags
                flags = self._decode_flags(int(f_val))
            elif raw.haslayer(UDP):
                udp   = raw[UDP]
                proto = "UDP"
                sport = udp.sport
                dport = udp.dport
            elif raw.haslayer(ICMP):
                proto = "ICMP"

            if raw.haslayer(Raw):
                try:
                    payload = raw[Raw].load[:40].decode(errors="replace")
                except Exception:
                    payload = ""

            return Packet(
                timestamp=datetime.now(),
                src_ip=ip.src,
                dst_ip=ip.dst,
                src_port=sport,
                dst_port=dport,
                protocol=proto,
                flags=flags,
                size=size,
                payload_snippet=payload,
            )
        except Exception:
            return None

    @staticmethod
    def _decode_flags(flag_int: int) -> str:
        names = ["FIN", "SYN", "RST", "PSH", "ACK", "URG"]
        active = [names[i] for i in range(6) if flag_int & (1 << i)]
        return "-".join(active) if active else "NONE"
