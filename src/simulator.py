"""
Packet Simulator
Generates realistic fake network traffic including attack patterns.
Used when real capture is not available (no root/scapy).
"""

import random
import time
from datetime import datetime, timedelta
from typing import List, Generator
from src.models import Packet


# ── IP pools ──────────────────────────────────────────────────────────────────
NORMAL_IPS = [
    "192.168.1.10", "192.168.1.20", "192.168.1.30",
    "10.0.0.5",     "10.0.0.15",    "172.16.0.5",
    "8.8.8.8",      "1.1.1.1",      "142.250.74.46",
    "104.18.2.1",   "151.101.1.57",
]
ATTACKER_IPS = [
    "185.220.101.47",   # tor exit — port scanner
    "91.108.4.1",       # SYN flooder
    "203.0.113.55",     # brute forcer
    "198.199.71.1",     # payload anomaly sender
    "45.142.212.100",   # multi-technique attacker
]
COMMON_PORTS   = [80, 443, 53, 8080, 22, 3306, 5432, 6379, 27017]
SCAN_PORTS     = list(range(1, 1025))
PROTOCOLS      = ["TCP", "UDP", "ICMP"]
FLAGS_NORMAL   = ["SYN-ACK", "ACK", "PSH-ACK", "FIN-ACK"]
FLAGS_ATTACK   = ["SYN"]


def _rand_ip(pool): return random.choice(pool)
def _rand_port(pool): return random.choice(pool)
def _rand_size(lo, hi): return random.randint(lo, hi)
def _rand_proto(): return random.choices(PROTOCOLS, weights=[70, 20, 10])[0]


def _make_packet(src_ip, dst_ip, src_port, dst_port, protocol, flags, size, ts) -> Packet:
    snippets = ["GET /index.html", "POST /api/login", "SSH-2.0-OpenSSH", "\x00"*20, "DATA", ""]
    return Packet(
        timestamp=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        flags=flags,
        size=size,
        payload_snippet=random.choice(snippets),
    )


class PacketSimulator:
    """
    Generates a mix of normal traffic + embedded attack scenarios.
    Attack scenarios are injected at random intervals.
    """

    def __init__(self, total_packets: int = 500):
        self.total = total_packets
        self._start_ts = datetime.now()
        self._counter  = 0

    def stream(self) -> Generator[Packet, None, None]:
        """Yield packets one at a time with small sleep for realism."""
        attack_schedule = self._build_attack_schedule()

        for i in range(self.total):
            ts = self._start_ts + timedelta(milliseconds=i * 80)

            # Normal background traffic
            pkt = self._normal_packet(ts)
            yield pkt

            # Inject attack packets at scheduled indices
            for attack_pkts in attack_schedule.get(i, []):
                yield attack_pkts

            time.sleep(0.01)   # 10ms between packets (adjustable)
            self._counter = i

    def batch(self) -> List[Packet]:
        """Return all packets at once (for PCAP-style analysis)."""
        all_pkts = []
        attack_schedule = self._build_attack_schedule()
        for i in range(self.total):
            ts = self._start_ts + timedelta(milliseconds=i * 80)
            all_pkts.append(self._normal_packet(ts))
            for apkt in attack_schedule.get(i, []):
                all_pkts.append(apkt)
        return sorted(all_pkts, key=lambda p: p.timestamp)

    # ── Normal traffic factory ────────────────────────────────────────────────

    def _normal_packet(self, ts: datetime) -> Packet:
        src = _rand_ip(NORMAL_IPS)
        dst = _rand_ip(NORMAL_IPS)
        while dst == src:
            dst = _rand_ip(NORMAL_IPS)
        proto = _rand_proto()
        flags = random.choice(FLAGS_NORMAL) if proto == "TCP" else ""
        return _make_packet(
            src_ip=src, dst_ip=dst,
            src_port=_rand_size(1024, 65535),
            dst_port=_rand_port(COMMON_PORTS),
            protocol=proto, flags=flags,
            size=_rand_size(64, 900),
            ts=ts,
        )

    # ── Attack schedule ───────────────────────────────────────────────────────

    def _build_attack_schedule(self) -> dict:
        """
        Returns {packet_index: [list of attack packets to inject at that index]}.
        Spreads 5 attack types across the simulation.
        """
        schedule = {}
        quarter = self.total // 5

        # 1. Port Scan at index ~quarter*0
        start = max(0, quarter * 0 + 10)
        attacker = ATTACKER_IPS[0]
        victim   = "192.168.1.100"
        for j, port in enumerate(random.sample(SCAN_PORTS, 25)):
            idx = start + j
            if idx < self.total:
                ts = self._start_ts + timedelta(milliseconds=(idx * 80 + j * 30))
                schedule.setdefault(idx, []).append(
                    _make_packet(attacker, victim, _rand_size(1024,65535), port,
                                 "TCP", "SYN", _rand_size(40,60), ts)
                )

        # 2. SYN Flood at index ~quarter*1
        start = quarter * 1
        attacker = ATTACKER_IPS[1]
        for j in range(30):
            idx = start + j
            if idx < self.total:
                ts = self._start_ts + timedelta(milliseconds=(idx * 80 + j * 15))
                schedule.setdefault(idx, []).append(
                    _make_packet(attacker, "192.168.1.100", _rand_size(1024,65535),
                                 80, "TCP", "SYN", 60, ts)
                )

        # 3. SSH Brute Force at index ~quarter*2
        start = quarter * 2
        attacker = ATTACKER_IPS[2]
        for j in range(15):
            idx = start + j
            if idx < self.total:
                ts = self._start_ts + timedelta(milliseconds=(idx * 80 + j * 50))
                schedule.setdefault(idx, []).append(
                    _make_packet(attacker, "192.168.1.5", _rand_size(1024,65535),
                                 22, "TCP", "SYN", 80, ts)
                )

        # 4. Suspicious IP (blacklisted) at index ~quarter*3
        start = quarter * 3
        attacker = ATTACKER_IPS[3]
        for j in range(5):
            idx = start + j
            if idx < self.total:
                ts = self._start_ts + timedelta(milliseconds=(idx * 80 + j * 100))
                schedule.setdefault(idx, []).append(
                    _make_packet("185.220.101.47", "192.168.1.20",
                                 _rand_size(1024,65535), 443, "TCP", "SYN-ACK",
                                 _rand_size(200,800), ts)
                )

        # 5. Payload Anomaly at index ~quarter*4
        start = quarter * 4
        attacker = ATTACKER_IPS[4]
        for j in range(8):
            idx = start + j
            if idx < self.total:
                ts = self._start_ts + timedelta(milliseconds=(idx * 80 + j * 60))
                schedule.setdefault(idx, []).append(
                    _make_packet(attacker, "192.168.1.50",
                                 _rand_size(1024,65535), 8080, "TCP", "PSH-ACK",
                                 _rand_size(1450, 9000), ts)
                )

        return schedule
