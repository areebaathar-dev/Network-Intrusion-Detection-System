# Mini IDS — Network Intrusion Detection System
**CS Information Security Project**

---

## ▶ How to Run (GUI — Recommended)

Double-click `run.bat` on Windows, or:

```bash
cd mini_ids
python gui.py
```

## ▶ How to Run (Terminal)

```bash
cd mini_ids
python main.py
```

---

## Project Structure

```
mini_ids/
├── gui.py                   ← DOUBLE-CLICK THIS (GUI version)
├── main.py                  ← Terminal version
├── run.bat                  ← Windows launcher (double-click)
├── run.sh                   ← Mac/Linux launcher
├── requirements.txt
├── src/
│   ├── ids_engine.py        # Main orchestrator
│   ├── detection.py         # 5 detection rules
│   ├── simulator.py         # Packet simulator
│   ├── logger.py            # TXT + CSV logging
│   ├── report.py            # HTML + TXT reports
│   ├── display.py           # Terminal display
│   └── models.py            # Data models
├── logs/                    # Auto-created
└── reports/                 # Auto-created
```

---

## Detection Rules

| Rule | Trigger | Severity | Action |
|---|---|---|---|
| Port Scan | 10+ unique ports in 10s | MEDIUM | BLOCK |
| SYN Flood | 20+ SYN packets in 10s | HIGH | BLOCK |
| SSH Brute Force | 8+ attempts on SSH/RDP | HIGH | BLOCK |
| Suspicious IP | Matches blacklist | MEDIUM | ALERT |
| Payload Anomaly | TCP packet > 1400B | LOW | LOG |

---

## Requirements

- Python 3.8+ (tkinter is built-in — no install needed for GUI)
- Optional: `pip install scapy` for live capture mode
