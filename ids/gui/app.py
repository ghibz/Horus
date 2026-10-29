"""
Horus IDS dashboard (Tkinter)

Threading model:
  * scapy sniffs in a background thread and the detectors run there.
  * Detectors call alerts.emit(); our callback only puts the Alert on a queue.
  * The GUI thread drains that queue every POLL_MS and is the only code that
    touches widgets (Tkinter is not thread-safe).
"""
import queue
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from ids import alerts
from ids import config
from ids.capture import sniffer as capture
from ids.storage import export
from ids.storage.db import AlertStore

AUTO = "Auto (default)"
POLL_MS = 200        # how often the GUI checks for new alerts
MAX_PER_TICK = 100   # cap per poll so an alert storm can't freeze the window
MAX_ROWS = 2000      # cap on rows kept in the table
STALL_SECONDS = 30   # no packets for this long -> warn that capture may be dead
FONT = "Segoe UI"

# lapis and gold
C = {
    "bg": "#0d1826",
    "panel": "#142236",
    "panel_alt": "#1b2e47",
    "border": "#27405f",
    "text": "#e8edf3",
    "muted": "#8fa3bd",
    "accent": "#d1a23a",
    "accent_hover": "#e3b658",
    "on_accent": "#0d1826",
    "ok": "#3fb37f",
    "bad": "#e05260",
}
# Row tint per severity (text stays readable); LOW has no tint
SEVERITY_TINT = {"HIGH": "#3a2230", "MEDIUM": "#33301f", "LOW": "#1b3a5c"}


class HorusApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Horus IDS")
        self.geometry("1080x700")
        self.minsize(880, 540)
        self.configure(bg=C["bg"])

        self.alert_queue = queue.Queue()
        alerts.subscribe(self.alert_queue.put)
        alerts.subscribe(self._store_alert)   # saves to the database
        self.store = None
        self._db_warned = set()      # which database problems were already reported

        self.sniffer = None
        self.started_at = None
        self._last_packets = 0       # capture watchdog state
        self._last_packet_time = 0.0
        self._stalled = False
        self.alert_count = 0
        self.high_count = 0
        # table row id -> the full Alert, so the CSV export can include the
        # fields the table doesn't show (target, port, details)
        self._alert_by_row = {}

        self.logo = self._load_logo()
        if self.logo:
            self.iconphoto(True, self.logo)

        self._setup_style()
        self._build_header()
        self._build_controls()
        self._build_stats()
        self._build_statusbar()
        self._build_table()
        self._set_running(False)
        self.status_var.set("Ready. Choose an interface and press Start.")

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(POLL_MS, self._poll)

    # ------------------------------------------------------------ styling
    def _load_logo(self):
        path = Path(__file__).resolve().parents[2] / "misc/Horus.png"
        try:
            img = tk.PhotoImage(file=str(path))
            return img.subsample(max(1, img.height() // 44))
        except Exception:
            return None

    def _setup_style(self):
        s = ttk.Style(self)
        s.theme_use("clam")

        s.configure(".", background=C["bg"], foreground=C["text"],
                    font=(FONT, 10), borderwidth=0, focuscolor=C["bg"])
        s.configure("Card.TFrame", background=C["panel"])

        s.configure("Title.TLabel", font=(FONT, 22, "bold"), foreground=C["accent"])
        s.configure("Sub.TLabel", foreground=C["muted"])
        s.configure("Section.TLabel", font=(FONT, 11, "bold"))
        s.configure("Status.TLabel", background=C["panel"], foreground=C["muted"])
        s.configure("Empty.TLabel", background=C["panel"], foreground=C["muted"],
                    font=(FONT, 11))
        s.configure("Card.TLabel", background=C["panel"], foreground=C["muted"],
                    font=(FONT, 9))
        s.configure("CardValue.TLabel", background=C["panel"], foreground=C["text"],
                    font=(FONT, 24, "bold"))

        s.configure("TButton", background=C["panel_alt"], foreground=C["text"],
                    padding=(16, 7), bordercolor=C["border"], borderwidth=1,
                    lightcolor=C["panel_alt"], darkcolor=C["panel_alt"])
        s.map("TButton",
              background=[("disabled", C["panel"]), ("active", C["border"])],
              foreground=[("disabled", C["muted"])])
        s.configure("Accent.TButton", background=C["accent"],
                    foreground=C["on_accent"], font=(FONT, 10, "bold"),
                    bordercolor=C["accent"], lightcolor=C["accent"],
                    darkcolor=C["accent"])
        s.map("Accent.TButton",
              background=[("disabled", C["panel_alt"]), ("active", C["accent_hover"])],
              foreground=[("disabled", C["muted"])],
              bordercolor=[("disabled", C["border"])])

        s.configure("TCombobox", fieldbackground=C["panel_alt"],
                    background=C["panel_alt"], foreground=C["text"],
                    arrowcolor=C["muted"], bordercolor=C["border"],
                    lightcolor=C["panel_alt"], darkcolor=C["panel_alt"],
                    padding=6)
        s.map("TCombobox",
              fieldbackground=[("readonly", C["panel_alt"]), ("disabled", C["panel"])],
              foreground=[("readonly", C["text"]), ("disabled", C["muted"])],
              selectbackground=[("readonly", C["panel_alt"])],
              selectforeground=[("readonly", C["text"])])
        self.option_add("*TCombobox*Listbox.background", C["panel_alt"])
        self.option_add("*TCombobox*Listbox.foreground", C["text"])
        self.option_add("*TCombobox*Listbox.selectBackground", C["accent"])
        self.option_add("*TCombobox*Listbox.selectForeground", C["on_accent"])

        s.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        s.configure("Treeview", background=C["panel"], fieldbackground=C["panel"],
                    foreground=C["text"], rowheight=30, font=(FONT, 10))
        s.map("Treeview",
              background=[("selected", C["panel_alt"])],
              foreground=[("selected", C["text"])])
        # workaround for a Tk 8.6.9 bug that ignores Treeview tag colours
        def fixed_map(option):
            return [e for e in s.map("Treeview", query_opt=option)
                    if e[:2] != ("!disabled", "!selected")]
        s.map("Treeview", foreground=fixed_map("foreground"),
              background=fixed_map("background"))
        s.configure("Treeview.Heading", background=C["panel_alt"],
                    foreground=C["muted"], font=(FONT, 9, "bold"),
                    relief="flat", padding=(10, 7))
        s.map("Treeview.Heading", background=[("active", C["panel_alt"])])

        s.configure("Vertical.TScrollbar", background=C["panel_alt"],
                    troughcolor=C["panel"], bordercolor=C["panel"],
                    lightcolor=C["panel_alt"], darkcolor=C["panel_alt"],
                    arrowcolor=C["muted"])
        s.map("Vertical.TScrollbar", background=[("active", C["border"])])

    # ------------------------------------------------------------- layout
    def _build_header(self):
        bar = ttk.Frame(self, padding=(24, 18, 24, 6))
        bar.pack(fill="x")

        if self.logo:
            ttk.Label(bar, image=self.logo).pack(side="left", padx=(0, 14))

        titles = ttk.Frame(bar)
        titles.pack(side="left")
        ttk.Label(titles, text="Horus", style="Title.TLabel").pack(anchor="w")
        ttk.Label(titles, text="Network intrusion detection",
                  style="Sub.TLabel").pack(anchor="w")

        self.status_lbl = tk.Label(bar, text="● Stopped", bg=C["bg"], fg=C["muted"],
                                   font=(FONT, 11, "bold"))
        self.status_lbl.pack(side="right")

    def _build_controls(self):
        row = ttk.Frame(self, padding=(24, 10, 24, 6))
        row.pack(fill="x")

        ttk.Label(row, text="Interface", style="Sub.TLabel").pack(side="left", padx=(0, 8))
        self.iface_var = tk.StringVar(value=AUTO)
        self.iface_box = ttk.Combobox(row, textvariable=self.iface_var, width=34,
                                      state="readonly",
                                      values=[AUTO] + capture.list_interfaces())
        self.iface_box.pack(side="left", padx=(0, 14))

        self.start_btn = ttk.Button(row, text="Start monitoring",
                                    style="Accent.TButton", command=self.start)
        self.start_btn.pack(side="left", padx=(0, 8))
        self.stop_btn = ttk.Button(row, text="Stop", command=self.stop)
        self.stop_btn.pack(side="left")

        ttk.Button(row, text="Export CSV", command=self.export_csv).pack(side="right")
        ttk.Button(row, text="Clear", command=self.clear).pack(side="right", padx=(0, 8))

    def _build_stats(self):
        row = ttk.Frame(self, padding=(24, 10, 24, 6))
        row.pack(fill="x")
        self.val_packets = self._card(row, 0, "Packets captured")
        self.val_alerts = self._card(row, 1, "Alerts")
        self.val_high = self._card(row, 2, "High severity")
        self.val_uptime = self._card(row, 3, "Uptime")

    def _card(self, parent, col, title):
        parent.columnconfigure(col, weight=1, uniform="cards")
        card = ttk.Frame(parent, style="Card.TFrame", padding=(18, 14))
        card.grid(row=0, column=col, sticky="ew", padx=(0 if col == 0 else 10, 0))
        ttk.Label(card, text=title, style="Card.TLabel").pack(anchor="w")
        value = ttk.Label(card, text="0", style="CardValue.TLabel")
        value.pack(anchor="w")
        return value

    def _build_statusbar(self):
        # packed before the table so it always keeps its space at the bottom
        self.status_var = tk.StringVar()
        ttk.Label(self, textvariable=self.status_var, style="Status.TLabel",
                  padding=(24, 8)).pack(fill="x", side="bottom")

    def _build_table(self):
        wrap = ttk.Frame(self, padding=(24, 10, 24, 14))
        wrap.pack(fill="both", expand=True)
        ttk.Label(wrap, text="Alerts", style="Section.TLabel").pack(anchor="w", pady=(0, 8))

        holder = ttk.Frame(wrap, style="Card.TFrame")
        holder.pack(fill="both", expand=True)

        columns = [("time", "Time", 170), ("severity", "Severity", 90),
                   ("type", "Type", 130), ("source", "Source", 150),
                   ("details", "Details", 480)]
        self.tree = ttk.Treeview(holder, columns=[c[0] for c in columns],
                                 show="headings", selectmode="browse")
        for key, title, width in columns:
            self.tree.heading(key, text=title, anchor="w")
            self.tree.column(key, width=width, anchor="w", stretch=(key == "details"))
        for severity, tint in SEVERITY_TINT.items():
            self.tree.tag_configure(severity, background=tint)

        scroll = ttk.Scrollbar(holder, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        # created after the tree so it sits on top of it
        self.empty_lbl = ttk.Label(holder, style="Empty.TLabel",
                                   text="No alerts yet. Press Start monitoring to begin.")
        self.empty_lbl.place(relx=0.5, rely=0.5, anchor="center")

    # ------------------------------------------------------------ actions
    def start(self):
        if self.sniffer is not None:
            return
        choice = self.iface_var.get()
        iface = None if choice == AUTO else choice

        # fresh start: packet counter at zero, nothing learned in an earlier
        # session (the old sniffer was deactivated by stop(), so a late packet
        # from it can't leak into this one)
        capture.begin_session()
        self._db_warned = set()
        self.title("Horus IDS")
        self.store = AlertStore()
        self.store.start(interface=iface, config={
            name: config.get(name) for name in config.DEFAULTS})
        try:
            self.sniffer = capture.create_sniffer(iface)
            self.sniffer.start()
        except Exception as exc:
            capture.deactivate_sniffer()
            self._close_store()
            self.sniffer = None
            messagebox.showerror("Horus", f"Capture could not start.\n\n{exc}")
            return

        self.started_at = time.time()
        self._last_packets = 0
        self._last_packet_time = self.started_at
        self._stalled = False
        self._set_running(True)

    # ---------------------------------------------------- capture watchdog
    def _capture_failure(self):
        """Reason string if the sniffer thread has died, else None."""
        # scapy leaves .running True after a failed start, so check the thread
        reason = getattr(self.sniffer, "exception", None)
        thread = getattr(self.sniffer, "thread", None)
        if reason is not None:
            return repr(reason)
        if thread is not None and not thread.is_alive():
            return "the capture thread ended"
        return None

    def _check_capture(self):
        # called every poll: an IDS that silently stops capturing is worse than a crash
        if self.sniffer is None:
            return
        reason = self._capture_failure()
        if reason:
            self._capture_lost(reason)
            return

        packets, now = capture.stats["packets"], time.time()
        if packets != self._last_packets:
            self._last_packets, self._last_packet_time = packets, now
            if self._stalled:
                self._stalled = False
                self._show_listening()
        elif not self._stalled and now - self._last_packet_time > STALL_SECONDS:
            # a quiet network is possible, so only warn; don't stop
            self._stalled = True
            self.status_lbl.configure(text="● No traffic", fg=C["accent"])
            self.status_var.set(
                f"No packets seen for {STALL_SECONDS}s on {self.iface_var.get()}. "
                "Wrong interface, or did the adapter go down?")

    def _capture_lost(self, reason):
        early = self.started_at is not None and time.time() - self.started_at < 5
        msg = f"Capture stopped unexpectedly: {reason}"
        # emitted before stop() so it reaches the table and the database
        alerts.emit("Capture lost", "HIGH", "Horus", msg)
        self.stop()
        self.status_lbl.configure(text="● Capture lost", fg=C["bad"])
        self.status_var.set(msg)
        hint = ("Run Horus as Administrator (Windows, with Npcap installed) "
                "or with sudo (Linux), then try again."
                if early else
                "The interface may have gone down. Check the adapter, then press Start.")
        messagebox.showerror("Horus", f"{msg}\n\n{hint}")

    def stop(self):
        # first cut the sniffer off from the detectors: its thread may need a
        # moment to die, but nothing it still delivers is processed any more
        capture.deactivate_sniffer()
        if self.sniffer is not None:
            try:
                if self.sniffer.running:
                    self.sniffer.stop(join=False)
            except Exception:
                pass
        self.sniffer = None
        self._close_store()
        self.started_at = None
        self._set_running(False)

    def _store_alert(self, alert):
        # runs on the sniffing thread: just queues the alert for the DB writer
        store = self.store
        if store is not None:
            store.submit(alert)

    def _close_store(self):
        store, self.store = self.store, None
        if store is not None:
            store.stop()

    def clear(self):
        self.tree.delete(*self.tree.get_children())
        self._alert_by_row.clear()
        self.alert_count = 0
        self.high_count = 0
        self._update_empty_state()

    def export_csv(self):
        if not self.tree.get_children():
            messagebox.showinfo("Horus", "There are no alerts to export yet.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV files", "*.csv")],
            initialfile=f"horus_alerts_{time.strftime('%Y%m%d_%H%M%S')}.csv")
        if not path:
            return
        rows = reversed(self.tree.get_children())               # oldest first
        to_export = [self._alert_by_row[r] for r in rows if r in self._alert_by_row]
        try:
            export.write_csv(path, to_export)
        except Exception as exc:    # a button must never fail silently
            self.status_var.set("Export failed")
            messagebox.showerror(
                "Horus - export failed",
                f"The alerts could not be saved to:\n{path}\n\n{exc}\n\n"
                "If the file is open in Excel, close it. Otherwise pick another "
                "folder or file name.")
            return
        self.status_var.set(f"Exported {len(to_export)} alerts to {path}")

    # ------------------------------------------------------------ updates
    def _poll(self):
        for _ in range(MAX_PER_TICK):
            try:
                self._add_alert(self.alert_queue.get_nowait())
            except queue.Empty:
                break
        self._check_capture()
        self._check_store()
        self._refresh_stats()
        self.after(POLL_MS, self._poll)

    def _add_alert(self, alert):
        values = (alert.timestamp.strftime("%Y-%m-%d %H:%M:%S"), alert.severity,
                  alert.kind, alert.source, alert.message)
        row_id = self.tree.insert("", 0, values=values, tags=(alert.severity,))  # newest on top
        self._alert_by_row[row_id] = alert

        rows = self.tree.get_children()
        if len(rows) > MAX_ROWS:
            self.tree.delete(rows[-1])
            self._alert_by_row.pop(rows[-1], None)

        self.alert_count += 1
        if alert.severity == "HIGH":
            self.high_count += 1
        self._update_empty_state()

    def _check_store(self):
        # the table keeps filling even if the database is dead, so say it out loud
        store = self.store
        if store is None:
            return
        problems = []
        if store.failed:
            problems.append(("died", f"The alert database stopped ({store.error}). "
                                     "New alerts are NOT being saved."))
        if store.dropped:
            problems.append(("dropped", f"The alert database can't keep up: "
                                        f"{store.dropped} alerts were not saved."))
        if store.rejected:
            problems.append(("rejected", f"{store.rejected} alerts were refused by the "
                                         "database and not saved."))
        for key, msg in problems:
            if key in self._db_warned:
                continue
            self._db_warned.add(key)
            alerts.emit("Database error", "HIGH", "Horus", msg)
            self.status_var.set(msg)
            self.title("Horus IDS - DATABASE PROBLEM")

    def _update_empty_state(self):
        if self.tree.get_children():
            self.empty_lbl.place_forget()
        else:
            self.empty_lbl.place(relx=0.5, rely=0.5, anchor="center")

    def _refresh_stats(self):
        self.val_packets.configure(text=f"{capture.stats['packets']:,}")
        self.val_alerts.configure(text=f"{self.alert_count:,}")
        self.val_high.configure(text=f"{self.high_count:,}")
        if self.started_at:
            hours, rest = divmod(int(time.time() - self.started_at), 3600)
            minutes, seconds = divmod(rest, 60)
            self.val_uptime.configure(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        else:
            self.val_uptime.configure(text="--:--:--")

    def _set_running(self, running):
        self.start_btn.state(["disabled"] if running else ["!disabled"])
        self.stop_btn.state(["!disabled"] if running else ["disabled"])
        self.iface_box.configure(state="disabled" if running else "readonly")
        if running:
            self._show_listening()
        else:
            self.status_lbl.configure(text="● Stopped", fg=C["muted"])
            self.status_var.set("Stopped.")

    def _show_listening(self):
        self.status_lbl.configure(text="● Listening", fg=C["ok"])
        self.status_var.set(f"Listening on {self.iface_var.get()}.")

    def _on_close(self):
        self.stop()
        self.destroy()


def run():
    # sharp text on high-DPI Windows displays
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    HorusApp().mainloop()