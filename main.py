"""
Mini IDS - Network Intrusion Detection System
Author: Areeba
Run: python main.py
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.ids_engine import IDSEngine
from src.display import print_banner


def main():
    print_banner()

    print("\nSelect mode:")
    print("  [1] Live Capture (requires root/admin + scapy)")
    print("  [2] Simulation Mode (no root needed - great for demo)")
    print("  [3] Analyze PCAP file")
    print("  [4] View previous logs/reports")
    print("  [5] Exit")

    choice = input("\nEnter choice (1-5): ").strip()

    engine = IDSEngine()

    if choice == "1":
        print("\n[!] Live mode requires: pip install scapy  and  run as admin/root")
        iface = input("Enter network interface (e.g. eth0, Wi-Fi): ").strip()
        engine.start_live_capture(iface)

    elif choice == "2":
        print("\n[*] Starting Simulation Mode...")
        packets = int(input("How many packets to simulate? (e.g. 500): ").strip() or "500")
        engine.start_simulation(packets)

    elif choice == "3":
        path = input("Enter path to .pcap file: ").strip()
        engine.analyze_pcap(path)

    elif choice == "4":
        engine.view_logs()

    elif choice == "5":
        print("\n[*] Exiting Mini IDS. Stay secure!\n")
        sys.exit(0)

    else:
        print("\n[!] Invalid choice. Launching simulation mode by default...")
        engine.start_simulation(300)


if __name__ == "__main__":
    main()
