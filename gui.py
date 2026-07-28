"""
Mini IDS — Graphical User Interface
Run: python gui.py
No extra install needed — uses built-in tkinter
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
import time
import sys
import os
from datetime import datetime
from collections import Counter

sys.path.insert(0, os.path.dirname(__file__))

from src.simulator import PacketSimulator
from src.detection import DetectionEngine
from src.logger import IDSLogger
from src.report import ReportGenerator
from src.models import Packet, ThreatAlert


# ── Color theme ───────────────────────────────────────────────────────────────
BG_DARK    = "#0d1117"
BG_PANEL   = "#161b22"
BG_ROW     = "#1c2128"
BG_INPUT   = "#21262d"
BORDER     = "#30363d"
TEXT_WHITE = "#e6edf3"
TEXT_GRAY  = "#8b949e"
BLUE       = "#58a6ff"
GREEN      = "#3fb950"
RED        = "#f85149"
YELLOW     = "#d29922"
PURPLE     = "#bc8cff"
CYAN       = "#76e3ea"
ACCENT     = "#1f6feb"


class MiniIDSApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("Mini IDS — Network Intrusion Detection System")
        self.geometry("1200x780")
        self.minsize(1000, 680)
        self.configure(bg=BG_DARK)

        # State
        self._running    = False
        self._thread     = None
        self._queue      = queue.Queue()
        self._pkt_count  = 0
        self._alert_count = 0
        self._sev        = Counter()
        self._blocked    = set()
        self._engine     = DetectionEngine()
        self._logger     = IDSLogger()
        self._session_start = datetime.now()
        self._all_alerts = []
        self._all_packets = []

        self._build_ui()
        self._poll_queue()

    # ═══════════════════════════════════════════════════════════════════════════
    # UI BUILD
    # ═══════════════════════════════════════════════════════════════════════════

    def _build_ui(self):
        self._build_titlebar()
        self._build_controls()       # ← moved to TOP so always visible
        self._build_metrics()
        self._build_main_area()
        self._build_statusbar()

    # ── Title bar ─────────────────────────────────────────────────────────────
    def _build_titlebar(self):
        bar = tk.Frame(self, bg=BG_PANEL, height=54)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        tk.Label(bar, text="🛡", font=("Segoe UI", 22),
                 bg=BG_PANEL, fg=BLUE).pack(side="left", padx=(16, 6), pady=8)
        tk.Label(bar, text="Mini IDS", font=("Segoe UI", 16, "bold"),
                 bg=BG_PANEL, fg=TEXT_WHITE).pack(side="left")
        tk.Label(bar, text="Network Intrusion Detection System",
                 font=("Segoe UI", 10), bg=BG_PANEL, fg=TEXT_GRAY).pack(side="left", padx=12, pady=14)

        # Status indicator
        self._status_dot = tk.Label(bar, text="●", font=("Segoe UI", 14),
                                    bg=BG_PANEL, fg=TEXT_GRAY)
        self._status_dot.pack(side="right", padx=(0, 6))
        self._status_lbl = tk.Label(bar, text="Idle", font=("Segoe UI", 10),
                                    bg=BG_PANEL, fg=TEXT_GRAY)
        self._status_lbl.pack(side="right")

        # Separator
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

    # ── Metric cards ──────────────────────────────────────────────────────────
    def _build_metrics(self):
        frame = tk.Frame(self, bg=BG_DARK, pady=10)
        frame.pack(fill="x", padx=14)

        metrics = [
            ("Packets Captured", "0", BLUE,   "_m_packets"),
            ("Threats Detected", "0", RED,    "_m_threats"),
            ("HIGH Severity",    "0", RED,    "_m_high"),
            ("MEDIUM Severity",  "0", YELLOW, "_m_medium"),
            ("LOW Severity",     "0", GREEN,  "_m_low"),
            ("IPs Blocked",      "0", PURPLE, "_m_blocked"),
        ]

        for i, (label, val, color, attr) in enumerate(metrics):
            card = tk.Frame(frame, bg=BG_PANEL, relief="flat",
                            highlightbackground=BORDER, highlightthickness=1)
            card.grid(row=0, column=i, padx=5, sticky="ew")
            frame.columnconfigure(i, weight=1)

            num_lbl = tk.Label(card, text=val, font=("Segoe UI", 22, "bold"),
                               bg=BG_PANEL, fg=color)
            num_lbl.pack(pady=(10, 2), padx=16)
            tk.Label(card, text=label, font=("Segoe UI", 9),
                     bg=BG_PANEL, fg=TEXT_GRAY).pack(pady=(0, 10), padx=16)

            setattr(self, attr, num_lbl)

    # ── Main content area ─────────────────────────────────────────────────────
    def _build_main_area(self):
        paned = tk.PanedWindow(self, orient="horizontal",
                               bg=BG_DARK, sashwidth=4, sashrelief="flat")
        paned.pack(fill="both", expand=True, padx=14, pady=(0, 8))

        left  = tk.Frame(paned, bg=BG_DARK)
        right = tk.Frame(paned, bg=BG_DARK)
        paned.add(left,  minsize=440)
        paned.add(right, minsize=320)

        # LEFT: packet stream + alerts (stacked)
        left_top = self._panel(left, "📡  Live Packet Stream")
        left_top.pack(fill="both", expand=True, pady=(0, 6))
        self._pkt_tree = self._make_tree(left_top, [
            ("Time",     70),
            ("Src IP",  130),
            ("Dst IP",  130),
            ("Proto",    60),
            ("Port",     55),
            ("Size",     60),
            ("Status",   80),
        ])

        left_bot = self._panel(left, "⚠️  Threat Alerts")
        left_bot.pack(fill="both", expand=True)
        self._alert_tree = self._make_tree(left_bot, [
            ("Time",      70),
            ("Type",     130),
            ("Severity",  75),
            ("Src IP",   130),
            ("Port",      55),
            ("Action",    75),
        ])

        # RIGHT: top IPs + log
        right_top = self._panel(right, "🌐  Top Source IPs")
        right_top.pack(fill="both", expand=True, pady=(0, 6))
        self._ip_tree = self._make_tree(right_top, [
            ("IP Address",  140),
            ("Packets",      70),
            ("Alerts",       60),
            ("Status",       80),
        ])

        right_bot = self._panel(right, "📋  Security Log")
        right_bot.pack(fill="both", expand=True)
        self._log_box = scrolledtext.ScrolledText(
            right_bot, bg=BG_ROW, fg=TEXT_GRAY,
            font=("Consolas", 9), relief="flat",
            insertbackground=TEXT_WHITE, wrap="word",
            state="disabled", height=10,
        )
        self._log_box.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        # Tag colors for log
        self._log_box.tag_config("CRIT",  foreground=RED)
        self._log_box.tag_config("WARN",  foreground=YELLOW)
        self._log_box.tag_config("INFO",  foreground=BLUE)
        self._log_box.tag_config("OK",    foreground=GREEN)
        self._log_box.tag_config("TIME",  foreground=TEXT_GRAY)

    # ── Controls bar ──────────────────────────────────────────────────────────
    def _build_controls(self):
        bar = tk.Frame(self, bg=BG_PANEL, height=56)
        bar.pack(fill="x")
        bar.pack_propagate(False)
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")  # top border

        # LEFT: mode + packet count
        lf = tk.Frame(bar, bg=BG_PANEL)
        lf.pack(side="left", padx=14, pady=10)

        tk.Label(lf, text="Mode:", font=("Segoe UI", 10),
                 bg=BG_PANEL, fg=TEXT_GRAY).pack(side="left")
        self._mode_var = tk.StringVar(value="Simulation")
        mode_menu = ttk.Combobox(lf, textvariable=self._mode_var, width=14,
                                 values=["Simulation", "Live Capture (root)"],
                                 state="readonly", font=("Segoe UI", 10))
        mode_menu.pack(side="left", padx=(6, 16))

        tk.Label(lf, text="Packets:", font=("Segoe UI", 10),
                 bg=BG_PANEL, fg=TEXT_GRAY).pack(side="left")
        self._pkt_var = tk.StringVar(value="500")
        pkt_entry = tk.Entry(lf, textvariable=self._pkt_var, width=6,
                             bg=BG_INPUT, fg=TEXT_WHITE, insertbackground=TEXT_WHITE,
                             relief="flat", font=("Segoe UI", 10),
                             highlightbackground=BORDER, highlightthickness=1)
        pkt_entry.pack(side="left", padx=(6, 0))

        # Speed slider
        tk.Label(lf, text="  Speed:", font=("Segoe UI", 10),
                 bg=BG_PANEL, fg=TEXT_GRAY).pack(side="left")
        self._speed_var = tk.IntVar(value=3)
        tk.Scale(lf, variable=self._speed_var, from_=1, to=10,
                 orient="horizontal", length=80, bg=BG_PANEL, fg=TEXT_WHITE,
                 troughcolor=BG_INPUT, highlightthickness=0,
                 activebackground=BLUE, sliderlength=14).pack(side="left", padx=(4, 0))

        # RIGHT: buttons
        rf = tk.Frame(bar, bg=BG_PANEL)
        rf.pack(side="right", padx=14, pady=10)

        self._start_btn = self._btn(rf, "▶  Start", ACCENT, TEXT_WHITE, self._start)
        self._start_btn.pack(side="left", padx=4)
        self._stop_btn  = self._btn(rf, "■  Stop", BG_INPUT, RED, self._stop, state="disabled")
        self._stop_btn.pack(side="left", padx=4)
        self._btn(rf, "⬇  Export Log",    BG_INPUT, TEXT_WHITE, self._export_log).pack(side="left", padx=4)
        self._btn(rf, "📄  Generate Report", BG_INPUT, TEXT_WHITE, self._gen_report).pack(side="left", padx=4)
        self._btn(rf, "🗑  Clear",          BG_INPUT, TEXT_GRAY,  self._clear).pack(side="left", padx=4)

    # ── Status bar ────────────────────────────────────────────────────────────
    def _build_statusbar(self):
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")
        sb = tk.Frame(self, bg=BG_PANEL, height=24)
        sb.pack(fill="x")
        sb.pack_propagate(False)
        self._sb_lbl = tk.Label(sb, text="Ready — select mode and press Start",
                                font=("Segoe UI", 9), bg=BG_PANEL, fg=TEXT_GRAY)
        self._sb_lbl.pack(side="left", padx=12)

        self._progress = ttk.Progressbar(sb, mode="determinate", length=180)
        self._progress.pack(side="right", padx=12, pady=4)

    # ═══════════════════════════════════════════════════════════════════════════
    # HELPERS
    # ═══════════════════════════════════════════════════════════════════════════

    def _panel(self, parent, title: str) -> tk.Frame:
        outer = tk.Frame(parent, bg=BG_PANEL,
                         highlightbackground=BORDER, highlightthickness=1)
        hdr = tk.Frame(outer, bg=BG_PANEL, height=32)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text=title, font=("Segoe UI", 10, "bold"),
                 bg=BG_PANEL, fg=TEXT_WHITE).pack(side="left", padx=10, pady=6)
        tk.Frame(outer, bg=BORDER, height=1).pack(fill="x")
        return outer

    def _make_tree(self, parent, columns) -> ttk.Treeview:
        style = ttk.Style()
        style.theme_use("default")
        style.configure("IDS.Treeview",
                        background=BG_ROW, foreground=TEXT_WHITE,
                        fieldbackground=BG_ROW, rowheight=22,
                        font=("Consolas", 9))
        style.configure("IDS.Treeview.Heading",
                        background=BG_INPUT, foreground=TEXT_GRAY,
                        font=("Segoe UI", 9), relief="flat")
        style.map("IDS.Treeview", background=[("selected", ACCENT)])

        frame = tk.Frame(parent, bg=BG_ROW)
        frame.pack(fill="both", expand=True, padx=6, pady=(4, 6))

        cols = [c[0] for c in columns]
        tree = ttk.Treeview(frame, columns=cols, show="headings",
                            style="IDS.Treeview")
        for col, width in columns:
            tree.heading(col, text=col)
            tree.column(col, width=width, minwidth=40, anchor="w")

        vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        tree.pack(side="left", fill="both", expand=True)

        # Tag colors
        tree.tag_configure("threat", background="#2d1515", foreground=RED)
        tree.tag_configure("high",   background="#2d1515", foreground=RED)
        tree.tag_configure("med",    background="#2d1a00", foreground=YELLOW)
        tree.tag_configure("low",    background="#0d1f0d", foreground=GREEN)
        tree.tag_configure("normal", foreground=TEXT_WHITE)
        tree.tag_configure("blocked",foreground=PURPLE)
        return tree

    def _btn(self, parent, text, bg, fg, cmd, state="normal") -> tk.Button:
        return tk.Button(parent, text=text, command=cmd,
                         bg=bg, fg=fg, activebackground=BORDER,
                         activeforeground=TEXT_WHITE,
                         font=("Segoe UI", 9), relief="flat",
                         padx=10, pady=4, cursor="hand2", state=state,
                         highlightthickness=0)

    def _set_status(self, msg: str, color=TEXT_GRAY):
        self._sb_lbl.config(text=msg, fg=color)

    def _log(self, msg: str, tag="INFO"):
        self._log_box.config(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self._log_box.insert("end", f"[{ts}] ", "TIME")
        self._log_box.insert("end", f"{msg}\n", tag)
        self._log_box.see("end")
        self._log_box.config(state="disabled")

    # ═══════════════════════════════════════════════════════════════════════════
    # ACTIONS
    # ═══════════════════════════════════════════════════════════════════════════

    def _start(self):
        if self._running:
            return
        self._running = True
        self._engine  = DetectionEngine()
        self._logger  = IDSLogger()
        self._session_start = datetime.now()

        self._start_btn.config(state="disabled")
        self._stop_btn.config(state="normal")
        self._status_dot.config(fg=GREEN)
        self._status_lbl.config(text="Running", fg=GREEN)

        mode = self._mode_var.get()
        if "Simulation" in mode:
            try:
                n = int(self._pkt_var.get())
            except ValueError:
                n = 500
            self._log(f"Starting simulation — {n} packets", "OK")
            self._progress["maximum"] = n
            self._thread = threading.Thread(target=self._sim_worker,
                                            args=(n,), daemon=True)
        else:
            self._log("Live capture requires root/admin + scapy", "WARN")
            self._thread = threading.Thread(target=self._live_worker, daemon=True)

        self._thread.start()

    def _stop(self):
        self._running = False
        self._start_btn.config(state="normal")
        self._stop_btn.config(state="disabled")
        self._status_dot.config(fg=YELLOW)
        self._status_lbl.config(text="Stopped", fg=YELLOW)
        self._log("Capture stopped by user", "WARN")
        self._set_status("Stopped — click Generate Report to save results", YELLOW)

    def _clear(self):
        if self._running:
            messagebox.showwarning("Warning", "Stop capture before clearing.")
            return
        for tree in (self._pkt_tree, self._alert_tree, self._ip_tree):
            tree.delete(*tree.get_children())
        self._log_box.config(state="normal")
        self._log_box.delete("1.0", "end")
        self._log_box.config(state="disabled")
        for attr, val in [("_m_packets","0"),("_m_threats","0"),("_m_high","0"),
                          ("_m_medium","0"),("_m_low","0"),("_m_blocked","0")]:
            getattr(self, attr).config(text=val)
        self._pkt_count  = 0
        self._alert_count = 0
        self._sev.clear()
        self._blocked.clear()
        self._all_alerts.clear()
        self._all_packets.clear()
        self._progress["value"] = 0
        self._engine  = DetectionEngine()
        self._logger  = IDSLogger()
        self._status_dot.config(fg=TEXT_GRAY)
        self._status_lbl.config(text="Idle", fg=TEXT_GRAY)
        self._set_status("Cleared — ready for new session")

    def _export_log(self):
        if not self._all_alerts:
            messagebox.showinfo("No Data", "Run a capture first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files","*.txt"),("CSV files","*.csv"),("All","*.*")],
            initialfile=f"ids_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        if not path:
            return
        with open(path, "w") as f:
            f.write(f"Mini IDS Security Log\nExported: {datetime.now()}\n{'='*60}\n\n")
            for a in self._all_alerts:
                f.write(str(a) + "\n")
            f.write(f"\n{'='*60}\nSummary\nTotal Packets : {self._pkt_count}\n"
                    f"Total Alerts  : {self._alert_count}\n"
                    f"Blocked IPs   : {', '.join(self._blocked)}\n")
        self._log(f"Log exported → {path}", "OK")
        messagebox.showinfo("Exported", f"Log saved to:\n{path}")

    def _gen_report(self):
        if not self._all_packets:
            messagebox.showinfo("No Data", "Run a capture first.")
            return
        rep = ReportGenerator(self._all_packets, self._all_alerts, self._session_start)
        html_content = rep._build_html_report()
        txt_content  = rep._build_txt_report()
        fname = "ids_report_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".html"
        save_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML Report","*.html"),("All","*.*")],
            initialdir=os.path.dirname(os.path.abspath(__file__)),
            initialfile=fname
        )
        if not save_path:
            return
        with open(save_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        txt_path = save_path.replace(".html", ".txt")
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(txt_content)
        self._log("Report saved: " + save_path, "OK")
        messagebox.showinfo("Report Saved!", "Saved to: " + save_path)


    # ═══════════════════════════════════════════════════════════════════════════
    # BACKGROUND WORKERS
    # ═══════════════════════════════════════════════════════════════════════════

    def _sim_worker(self, total: int):
        sim = PacketSimulator(total)
        speed = self._speed_var.get()

        for pkt in sim.stream():
            if not self._running:
                break
            alerts = self._engine.inspect(pkt)
            self._logger.log_packet(pkt)
            self._all_packets.append(pkt)
            for a in alerts:
                self._logger.log_alert(a)
                self._all_alerts.append(a)
            self._queue.put(("packet", pkt, alerts))
            delay = max(0.001, 0.05 / speed)
            time.sleep(delay)

        self._queue.put(("done", None, None))

    def _live_worker(self):
        """Live capture using scapy — needs root."""
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP
        except ImportError:
            self._queue.put(("error", "scapy not installed. Run: pip install scapy", None))
            return

        def handle(raw):
            if not self._running:
                return
            pkt = self._scapy_to_model(raw)
            if pkt is None:
                return
            alerts = self._engine.inspect(pkt)
            self._logger.log_packet(pkt)
            self._all_packets.append(pkt)
            for a in alerts:
                self._all_alerts.append(a)
            self._queue.put(("packet", pkt, alerts))

        try:
            sniff(prn=handle, store=False,
                  stop_filter=lambda _: not self._running)
        except Exception as e:
            self._queue.put(("error", str(e), None))

        self._queue.put(("done", None, None))

    # ═══════════════════════════════════════════════════════════════════════════
    # QUEUE POLLING (runs on main thread)
    # ═══════════════════════════════════════════════════════════════════════════

    def _poll_queue(self):
        try:
            while True:
                kind, pkt, alerts = self._queue.get_nowait()

                if kind == "packet":
                    self._pkt_count += 1
                    self._update_packet_tree(pkt, bool(alerts))
                    for alert in alerts:
                        self._alert_count += 1
                        self._sev[alert.severity] += 1
                        if alert.action_taken == "BLOCKED":
                            self._blocked.add(alert.src_ip)
                        self._update_alert_tree(alert)
                        self._log_alert(alert)
                    self._update_metrics()
                    self._update_ip_tree(pkt)
                    self._progress["value"] = self._pkt_count

                elif kind == "done":
                    self._running = False
                    self._start_btn.config(state="normal")
                    self._stop_btn.config(state="disabled")
                    self._status_dot.config(fg=BLUE)
                    self._status_lbl.config(text="Complete", fg=BLUE)
                    self._log(f"Session complete — {self._pkt_count} packets, "
                              f"{self._alert_count} threats", "OK")
                    self._set_status(
                        f"Done: {self._pkt_count} packets · {self._alert_count} threats · "
                        f"{len(self._blocked)} IPs blocked", GREEN)

                elif kind == "error":
                    self._running = False
                    self._log(f"ERROR: {pkt}", "CRIT")
                    messagebox.showerror("Error", str(pkt))

        except queue.Empty:
            pass

        self.after(30, self._poll_queue)

    # ═══════════════════════════════════════════════════════════════════════════
    # TREE UPDATES
    # ═══════════════════════════════════════════════════════════════════════════

    MAX_ROWS = 200

    def _update_packet_tree(self, pkt: Packet, has_threat: bool):
        tag = "threat" if has_threat else "normal"
        status = "⚠ THREAT" if has_threat else "✓ OK"
        self._pkt_tree.insert("", 0, values=(
            pkt.timestamp.strftime("%H:%M:%S"),
            pkt.src_ip,
            pkt.dst_ip,
            pkt.protocol,
            pkt.dst_port,
            f"{pkt.size}B",
            status,
        ), tags=(tag,))
        # Keep list short
        children = self._pkt_tree.get_children()
        if len(children) > self.MAX_ROWS:
            self._pkt_tree.delete(children[-1])

    def _update_alert_tree(self, alert: ThreatAlert):
        tag = {"HIGH": "high", "MEDIUM": "med", "LOW": "low"}.get(alert.severity, "normal")
        sev_icon = {"HIGH": "🔴 HIGH", "MEDIUM": "🟡 MED", "LOW": "🟢 LOW"}.get(alert.severity, alert.severity)
        self._alert_tree.insert("", 0, values=(
            alert.timestamp.strftime("%H:%M:%S"),
            alert.threat_type,
            sev_icon,
            alert.src_ip,
            alert.dst_port,
            alert.action_taken,
        ), tags=(tag,))
        children = self._alert_tree.get_children()
        if len(children) > 100:
            self._alert_tree.delete(children[-1])

    _ip_counts  = {}   # ip -> packet count
    _ip_alerts  = {}   # ip -> alert count

    def _update_ip_tree(self, pkt: Packet):
        ip = pkt.src_ip
        self._ip_counts[ip]  = self._ip_counts.get(ip, 0) + 1
        self._ip_alerts[ip]  = self._ip_alerts.get(ip, 0)

        # Check if IP is in alerts
        is_blocked = ip in self._blocked

        # Rebuild top-10
        self._ip_tree.delete(*self._ip_tree.get_children())
        top = sorted(self._ip_counts.items(), key=lambda x: -x[1])[:10]
        for src_ip, cnt in top:
            blk = src_ip in self._blocked
            alts = self._ip_alerts.get(src_ip, 0)
            status = "🚫 BLOCKED" if blk else ("⚠ SUSPECT" if alts > 0 else "✓ Normal")
            tag = "blocked" if blk else ("high" if alts > 0 else "normal")
            self._ip_tree.insert("", "end", values=(src_ip, cnt, alts, status), tags=(tag,))

    def _update_metrics(self):
        self._m_packets.config(text=str(self._pkt_count))
        self._m_threats.config(text=str(self._alert_count))
        self._m_high.config(text=str(self._sev.get("HIGH", 0)))
        self._m_medium.config(text=str(self._sev.get("MEDIUM", 0)))
        self._m_low.config(text=str(self._sev.get("LOW", 0)))
        self._m_blocked.config(text=str(len(self._blocked)))

    def _log_alert(self, alert: ThreatAlert):
        tag = {"HIGH": "CRIT", "MEDIUM": "WARN", "LOW": "INFO"}.get(alert.severity, "INFO")
        msg = f"[{alert.severity}] {alert.threat_type} — {alert.src_ip} → {alert.dst_ip}:{alert.dst_port} | {alert.action_taken}"
        self._log(msg, tag)
        self._ip_alerts[alert.src_ip] = self._ip_alerts.get(alert.src_ip, 0) + 1
        self._set_status(f"Alert: {alert.threat_type} from {alert.src_ip}", RED if alert.severity == "HIGH" else YELLOW)

    # ═══════════════════════════════════════════════════════════════════════════
    # SCAPY HELPER
    # ═══════════════════════════════════════════════════════════════════════════

    def _scapy_to_model(self, raw):
        try:
            from scapy.all import IP, TCP, UDP, ICMP, Raw
            from src.ids_engine import IDSEngine
            return IDSEngine()._scapy_to_model(raw)
        except Exception:
            return None


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = MiniIDSApp()
    app.mainloop()