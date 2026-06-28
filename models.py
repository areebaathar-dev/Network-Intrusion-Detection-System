"""
Data models for packets and threats.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Packet:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str       # TCP / UDP / ICMP / OTHER
    flags: str          # SYN, ACK, SYN-ACK, RST, FIN, etc.
    size: int           # bytes
    payload_snippet: str = ""

    def __str__(self):
        return (f"[{self.timestamp.strftime('%H:%M:%S')}] "
                f"{self.src_ip}:{self.src_port} -> "
                f"{self.dst_ip}:{self.dst_port} "
                f"[{self.protocol}/{self.flags}] {self.size}B")


@dataclass
class ThreatAlert:
    timestamp: datetime
    threat_type: str          # PORT_SCAN / SYN_FLOOD / SUSPICIOUS_IP / BRUTE_FORCE / PAYLOAD_ANOMALY
    severity: str             # HIGH / MEDIUM / LOW
    src_ip: str
    dst_ip: str
    dst_port: int
    description: str
    packet_count: int = 1
    action_taken: str = "LOGGED"   # LOGGED / BLOCKED / ALERTED

    def __str__(self):
        return (f"[{self.timestamp.strftime('%H:%M:%S')}] "
                f"{'!'*3 if self.severity=='HIGH' else '!'*2 if self.severity=='MEDIUM' else '!'} "
                f"{self.threat_type} | {self.severity} | "
                f"{self.src_ip} -> {self.dst_ip}:{self.dst_port} | "
                f"{self.description}")
