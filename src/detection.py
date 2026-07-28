"""
Detection Rules Engine
Implements:
  - Port Scan Detection
  - SYN Flood Detection
  - Suspicious IP Detection
  - Brute Force (SSH/RDP/FTP) Detection
  - Payload Anomaly Detection
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Optional
from src.models import Packet, ThreatAlert


# ── Thresholds (tunable) ──────────────────────────────────────────────────────
PORT_SCAN_THRESHOLD      = 10    # unique ports from same IP within window
SYN_FLOOD_THRESHOLD      = 20    # SYN packets from same IP within window
BRUTE_FORCE_THRESHOLD    = 8     # repeated attempts on SSH/RDP/FTP
PAYLOAD_SIZE_THRESHOLD   = 1400  # bytes — oversized payload flag
TIME_WINDOW_SECONDS      = 10    # sliding window for rate-based checks

# Known malicious / suspicious IP list (demo — real IDS uses threat feeds)
SUSPICIOUS_IPS = {
    "185.220.101.47": "Known Tor exit node",
    "91.108.4.1":     "Telegram C2 range",
    "5.188.206.1":    "Bulletproof hosting",
    "45.142.212.100": "Known scanner",
    "192.241.218.1":  "VPN exit node flagged",
    "31.13.72.36":    "Flagged datacenter IP",
    "198.199.71.1":   "Repeated abuse reports",
    "203.0.113.99":   "Reserved/test range abuse",
}

# Ports that indicate brute-force if hit repeatedly
BRUTE_FORCE_PORTS = {22: "SSH", 3389: "RDP", 21: "FTP", 23: "Telnet", 5900: "VNC"}


class DetectionEngine:

    def __init__(self):
        # ip -> list of (timestamp, dst_port)
        self._port_map: dict  = defaultdict(list)
        # ip -> list of timestamps of SYN packets
        self._syn_map: dict   = defaultdict(list)
        # ip -> list of timestamps per brute-force port
        self._brute_map: dict = defaultdict(lambda: defaultdict(list))
        # already alerted combinations to avoid duplicates
        self._alerted: set    = set()

    # ── Public API ─────────────────────────────────────────────────────────────

    def inspect(self, pkt: Packet) -> List[ThreatAlert]:
        """Run all rules against one packet. Returns list of alerts (may be empty)."""
        alerts = []
        now = pkt.timestamp

        self._expire_old_entries(now)
        self._register_packet(pkt, now)

        alerts += self._check_port_scan(pkt, now)
        alerts += self._check_syn_flood(pkt, now)
        alerts += self._check_suspicious_ip(pkt, now)
        alerts += self._check_brute_force(pkt, now)
        alerts += self._check_payload_anomaly(pkt, now)

        return alerts

    # ── Registration ──────────────────────────────────────────────────────────

    def _register_packet(self, pkt: Packet, now: datetime):
        self._port_map[pkt.src_ip].append((now, pkt.dst_port))
        if "SYN" in pkt.flags and "ACK" not in pkt.flags:
            self._syn_map[pkt.src_ip].append(now)
        if pkt.dst_port in BRUTE_FORCE_PORTS:
            self._brute_map[pkt.src_ip][pkt.dst_port].append(now)

    # ── Expiry ────────────────────────────────────────────────────────────────

    def _expire_old_entries(self, now: datetime):
        cutoff = now - timedelta(seconds=TIME_WINDOW_SECONDS)

        for ip in list(self._port_map):
            self._port_map[ip] = [(t, p) for t, p in self._port_map[ip] if t > cutoff]

        for ip in list(self._syn_map):
            self._syn_map[ip] = [t for t in self._syn_map[ip] if t > cutoff]

        for ip in list(self._brute_map):
            for port in list(self._brute_map[ip]):
                self._brute_map[ip][port] = [t for t in self._brute_map[ip][port] if t > cutoff]

    # ── Rule 1: Port Scan ─────────────────────────────────────────────────────

    def _check_port_scan(self, pkt: Packet, now: datetime) -> List[ThreatAlert]:
        unique_ports = set(p for _, p in self._port_map[pkt.src_ip])
        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            key = ("scan", pkt.src_ip)
            if key not in self._alerted:
                self._alerted.add(key)
                return [ThreatAlert(
                    timestamp=now,
                    threat_type="PORT_SCAN",
                    severity="MEDIUM",
                    src_ip=pkt.src_ip,
                    dst_ip=pkt.dst_ip,
                    dst_port=pkt.dst_port,
                    description=(f"Port scan detected: {len(unique_ports)} unique ports "
                                 f"probed in {TIME_WINDOW_SECONDS}s window. "
                                 f"Ports: {sorted(unique_ports)[:10]}..."),
                    packet_count=len(self._port_map[pkt.src_ip]),
                    action_taken="BLOCKED"
                )]
        return []

    # ── Rule 2: SYN Flood ─────────────────────────────────────────────────────

    def _check_syn_flood(self, pkt: Packet, now: datetime) -> List[ThreatAlert]:
        syn_count = len(self._syn_map[pkt.src_ip])
        if syn_count >= SYN_FLOOD_THRESHOLD:
            key = ("syn", pkt.src_ip)
            if key not in self._alerted:
                self._alerted.add(key)
                return [ThreatAlert(
                    timestamp=now,
                    threat_type="SYN_FLOOD",
                    severity="HIGH",
                    src_ip=pkt.src_ip,
                    dst_ip=pkt.dst_ip,
                    dst_port=pkt.dst_port,
                    description=(f"SYN flood detected: {syn_count} SYN packets "
                                 f"from {pkt.src_ip} in {TIME_WINDOW_SECONDS}s. "
                                 f"Possible DoS/DDoS attack."),
                    packet_count=syn_count,
                    action_taken="BLOCKED"
                )]
        return []

    # ── Rule 3: Suspicious IP ─────────────────────────────────────────────────

    def _check_suspicious_ip(self, pkt: Packet, now: datetime) -> List[ThreatAlert]:
        reason = SUSPICIOUS_IPS.get(pkt.src_ip)
        if reason:
            key = ("susip", pkt.src_ip)
            if key not in self._alerted:
                self._alerted.add(key)
                return [ThreatAlert(
                    timestamp=now,
                    threat_type="SUSPICIOUS_IP",
                    severity="MEDIUM",
                    src_ip=pkt.src_ip,
                    dst_ip=pkt.dst_ip,
                    dst_port=pkt.dst_port,
                    description=f"Traffic from blacklisted IP {pkt.src_ip}: {reason}",
                    action_taken="ALERTED"
                )]
        return []

    # ── Rule 4: Brute Force ───────────────────────────────────────────────────

    def _check_brute_force(self, pkt: Packet, now: datetime) -> List[ThreatAlert]:
        if pkt.dst_port not in BRUTE_FORCE_PORTS:
            return []
        attempts = len(self._brute_map[pkt.src_ip][pkt.dst_port])
        service = BRUTE_FORCE_PORTS[pkt.dst_port]
        if attempts >= BRUTE_FORCE_THRESHOLD:
            key = ("brute", pkt.src_ip, pkt.dst_port)
            if key not in self._alerted:
                self._alerted.add(key)
                return [ThreatAlert(
                    timestamp=now,
                    threat_type="BRUTE_FORCE",
                    severity="HIGH",
                    src_ip=pkt.src_ip,
                    dst_ip=pkt.dst_ip,
                    dst_port=pkt.dst_port,
                    description=(f"Brute force attack on {service} (port {pkt.dst_port}): "
                                 f"{attempts} attempts from {pkt.src_ip} in {TIME_WINDOW_SECONDS}s."),
                    packet_count=attempts,
                    action_taken="BLOCKED"
                )]
        return []

    # ── Rule 5: Payload Anomaly ───────────────────────────────────────────────

    def _check_payload_anomaly(self, pkt: Packet, now: datetime) -> List[ThreatAlert]:
        if pkt.size > PAYLOAD_SIZE_THRESHOLD and pkt.protocol == "TCP":
            key = ("payload", pkt.src_ip, round(now.timestamp()))
            if key not in self._alerted:
                self._alerted.add(key)
                return [ThreatAlert(
                    timestamp=now,
                    threat_type="PAYLOAD_ANOMALY",
                    severity="LOW",
                    src_ip=pkt.src_ip,
                    dst_ip=pkt.dst_ip,
                    dst_port=pkt.dst_port,
                    description=(f"Oversized TCP payload: {pkt.size} bytes "
                                 f"(threshold: {PAYLOAD_SIZE_THRESHOLD}B). "
                                 f"Possible data exfiltration or buffer overflow attempt."),
                    action_taken="LOGGED"
                )]
        return []
