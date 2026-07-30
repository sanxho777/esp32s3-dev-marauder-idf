#!/usr/bin/env python3
"""
Desktop control panel for the ESP32-S3 Marauder firmware, talking to the
device over USB serial instead of WiFi (see main/serial_control.cpp on the
firmware side for the protocol this speaks).
"""
import json
import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox

import serial
import serial.tools.list_ports

TAG_PREFIX = "#MRDR#"
BAUD_RATE = 115200


class SerialLink:
    def __init__(self, on_message):
        self.ser = None
        self.on_message = on_message
        self.running = False

    def connect(self, port):
        self.ser = serial.Serial(port, BAUD_RATE, timeout=1)
        self.running = True
        threading.Thread(target=self._read_loop, daemon=True).start()

    def disconnect(self):
        self.running = False
        if self.ser:
            try:
                self.ser.close()
            except Exception:
                pass
        self.ser = None

    def _read_loop(self):
        while self.running and self.ser:
            try:
                raw = self.ser.readline()
            except Exception:
                break
            if not raw:
                continue
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if not line.startswith(TAG_PREFIX):
                continue  # ignore ESP_LOG boot/debug noise sharing the same port
            try:
                msg = json.loads(line[len(TAG_PREFIX):])
            except json.JSONDecodeError:
                continue
            self.on_message(msg)

    def send(self, obj):
        if not self.ser:
            return
        try:
            self.ser.write((json.dumps(obj) + "\n").encode("utf-8"))
            self.ser.flush()
        except Exception:
            pass


class DashboardTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        status = ttk.LabelFrame(self, text="Status")
        status.pack(fill="x", padx=8, pady=8)
        self.status_vars = {}
        fields = [
            ("mode", "Mode"), ("channel", "Channel"), ("sdCard", "SD card"),
            ("pcapFile", "PCAP file"), ("pcapPackets", "PCAP packets"),
            ("deauthSent", "Deauth sent"), ("widsSeen", "WIDS deauth seen"),
        ]
        for i, (key, label) in enumerate(fields):
            ttk.Label(status, text=label + ":").grid(row=i // 4, column=(i % 4) * 2, sticky="e", padx=4, pady=2)
            var = tk.StringVar(value="-")
            self.status_vars[key] = var
            ttk.Label(status, textvariable=var).grid(row=i // 4, column=(i % 4) * 2 + 1, sticky="w", padx=4, pady=2)

        log_frame = ttk.LabelFrame(self, text="Live log")
        log_frame.pack(fill="both", expand=True, padx=8, pady=8)
        self.log_text = tk.Text(log_frame, height=20, state="disabled", bg="#0a0c10", fg="#9fd0ff")
        self.log_text.pack(fill="both", expand=True, padx=4, pady=4)

    def append_log(self, msg):
        self.log_text.config(state="normal")
        self.log_text.insert("end", msg + "\n")
        self.log_text.see("end")
        # keep the log from growing unbounded
        if float(self.log_text.index("end-1c").split(".")[0]) > 1000:
            self.log_text.delete("1.0", "500.0")
        self.log_text.config(state="disabled")

    def update_status(self, s):
        self.status_vars["mode"].set(s.get("mode", "-"))
        self.status_vars["channel"].set(s.get("channel", "-"))
        self.status_vars["sdCard"].set("yes" if s.get("sdCard") else "no")
        self.status_vars["pcapFile"].set(s.get("pcapFile") or "-")
        self.status_vars["pcapPackets"].set(s.get("pcapPackets", 0))
        self.status_vars["deauthSent"].set(s.get("deauthSent", 0))
        self.status_vars["widsSeen"].set(s.get("widsSeen", 0))


def make_table(parent, columns):
    tree = ttk.Treeview(parent, columns=columns, show="headings", height=10)
    for c in columns:
        tree.heading(c, text=c)
        tree.column(c, width=120, anchor="w")
    tree.pack(fill="both", expand=True, padx=4, pady=4)
    return tree


def refill_table(tree, rows, columns):
    tree.delete(*tree.get_children())
    for row in rows:
        tree.insert("", "end", values=[row.get(c, "") for c in columns])


class WifiTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.aps = []

        ap_frame = ttk.LabelFrame(self, text="Access Point Scan")
        ap_frame.pack(fill="both", expand=True, padx=8, pady=8)
        ttk.Button(ap_frame, text="Scan APs", command=lambda: app.send("wifi_scan_start")).pack(anchor="w", padx=4, pady=4)
        self.ap_columns = ("ssid", "bssid", "channel", "rssi", "secure")
        self.ap_table = make_table(ap_frame, self.ap_columns)

        st_frame = ttk.LabelFrame(self, text="Passive Station Discovery (channel hopping)")
        st_frame.pack(fill="both", expand=True, padx=8, pady=8)
        btns = ttk.Frame(st_frame)
        btns.pack(anchor="w", padx=4, pady=4)
        ttk.Button(btns, text="Start", command=lambda: app.send("wifi_stations_start")).pack(side="left", padx=2)
        ttk.Button(btns, text="Stop", command=lambda: app.send("wifi_stations_stop")).pack(side="left", padx=2)
        self.st_columns = ("mac", "ap", "rssi")
        self.st_table = make_table(st_frame, self.st_columns)

    def update_aps(self, aps):
        self.aps = aps
        refill_table(self.ap_table, aps, self.ap_columns)

    def update_stations(self, stations):
        refill_table(self.st_table, stations, self.st_columns)


class WidsTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        ttk.Label(self, text="Passive, receive-only. Flags bursts of deauth/disassoc frames as possible attacks.",
                  wraplength=700).pack(anchor="w", padx=8, pady=4)
        btns = ttk.Frame(self)
        btns.pack(anchor="w", padx=8, pady=4)
        ttk.Button(btns, text="Start Monitor", command=lambda: app.send("wids_start")).pack(side="left", padx=2)
        ttk.Button(btns, text="Stop", command=lambda: app.send("wids_stop")).pack(side="left", padx=2)
        self.columns = ("attacker", "victim", "count", "t")
        self.table = make_table(self, self.columns)

    def update_alerts(self, alerts):
        refill_table(self.table, alerts, self.columns)


BROADCAST_LABEL = "(broadcast -- all clients)"


class DeauthTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.aps = []
        self.stations = []

        warn = ttk.Label(
            self,
            text=("Only use against networks/devices you own or are authorized to test. Deauth frames are "
                  "broadcast on the shared 2.4GHz band -- anything else on the target channel is affected too."),
            wraplength=700, foreground="#b34700",
        )
        warn.pack(anchor="w", padx=8, pady=8)

        ttk.Label(self, text="Target AP:").pack(anchor="w", padx=8)
        self.ap_var = tk.StringVar()
        self.ap_combo = ttk.Combobox(self, textvariable=self.ap_var, state="readonly", width=60)
        self.ap_combo.pack(anchor="w", padx=8, pady=4)

        ttk.Label(self, text="Client (blank/broadcast = all clients on this AP):").pack(anchor="w", padx=8)
        self.client_var = tk.StringVar()
        self.client_combo = ttk.Combobox(self, textvariable=self.client_var, width=60)
        self.client_combo.pack(anchor="w", padx=8, pady=4)
        self.client_combo.bind("<<ComboboxSelected>>", self._on_client_selected)

        row = ttk.Frame(self)
        row.pack(anchor="w", padx=8, pady=4)
        ttk.Label(row, text="Burst:").pack(side="left")
        self.burst_var = tk.StringVar(value="5")
        ttk.Entry(row, textvariable=self.burst_var, width=6).pack(side="left", padx=4)

        btns = ttk.Frame(self)
        btns.pack(anchor="w", padx=8, pady=8)
        ttk.Button(btns, text="Start", command=self._start).pack(side="left", padx=2)
        ttk.Button(btns, text="Stop", command=lambda: app.send("deauth_stop")).pack(side="left", padx=2)

    def _on_client_selected(self, _event=None):
        # The dropdown's displayed text is a human-readable label, not a bare
        # MAC -- swap the entry back to just the MAC (or "" for broadcast)
        # once a real selection is made, since that's what actually gets sent.
        idx = self.client_combo.current()
        if idx <= 0:  # index 0 is always the broadcast entry
            self.client_var.set("")
        else:
            self.client_var.set(self.stations[idx - 1].get("mac", ""))

    def _start(self):
        idx = self.ap_combo.current()
        if idx < 0:
            messagebox.showinfo("No AP selected", "Run a WiFi scan and pick a target AP first.")
            return
        try:
            burst = int(self.burst_var.get())
        except ValueError:
            burst = 5
        client = self.client_var.get().strip()
        if client == BROADCAST_LABEL:
            client = ""
        self.app.send("deauth_start", apIndex=idx, client=client, burst=burst)

    def update_aps(self, aps):
        self.aps = aps
        self.ap_combo["values"] = [f"{a.get('ssid')} ({a.get('bssid')}) ch{a.get('channel')}" for a in aps]

    def update_stations(self, stations):
        self.stations = stations
        labels = [BROADCAST_LABEL]
        for s in stations:
            ap = s.get("ap") or "unassociated"
            labels.append(f"{s.get('mac')} (seen on {ap}, rssi {s.get('rssi')})")
        self.client_combo["values"] = labels


class BeaconTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        ttk.Label(self, text="Fake AP SSIDs (one per line):").pack(anchor="w", padx=8, pady=4)
        self.ssid_text = tk.Text(self, height=8)
        self.ssid_text.pack(fill="both", expand=True, padx=8)
        ttk.Button(self, text="Save SSID list", command=self._save_ssids).pack(anchor="w", padx=8, pady=4)

        row = ttk.Frame(self)
        row.pack(anchor="w", padx=8, pady=4)
        self.random_mac = tk.BooleanVar(value=True)
        ttk.Checkbutton(row, text="Random MACs", variable=self.random_mac).pack(side="left")
        ttk.Label(row, text="Channel:").pack(side="left", padx=(12, 0))
        self.channel_var = tk.StringVar(value="1")
        ttk.Entry(row, textvariable=self.channel_var, width=6).pack(side="left", padx=4)

        btns = ttk.Frame(self)
        btns.pack(anchor="w", padx=8, pady=8)
        ttk.Button(btns, text="Start", command=self._start).pack(side="left", padx=2)
        ttk.Button(btns, text="Stop", command=lambda: app.send("beacon_stop")).pack(side="left", padx=2)

    def _save_ssids(self):
        ssids = [l.strip() for l in self.ssid_text.get("1.0", "end").splitlines() if l.strip()]
        self.app.send("beacon_ssids", ssids=ssids)

    def _start(self):
        try:
            channel = int(self.channel_var.get())
        except ValueError:
            channel = 1
        self.app.send("beacon_start", randomMac=self.random_mac.get(), channel=channel)


class SnifferTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        row = ttk.Frame(self)
        row.pack(anchor="w", padx=8, pady=8)
        ttk.Label(row, text="Channel (0 = hop 1-13):").pack(side="left")
        self.channel_var = tk.StringVar(value="0")
        ttk.Entry(row, textvariable=self.channel_var, width=6).pack(side="left", padx=4)
        ttk.Button(row, text="Start Capture", command=self._start).pack(side="left", padx=8)
        ttk.Button(row, text="Stop", command=lambda: app.send("sniffer_stop")).pack(side="left", padx=2)

        self.status_var = tk.StringVar(value="-")
        ttk.Label(self, textvariable=self.status_var).pack(anchor="w", padx=8, pady=4)
        ttk.Label(
            self,
            text=("Captures are radiotap-wrapped .pcap files on the SD card (/pcaps). "
                  "There's no serial file transfer here -- pull the physical microSD card "
                  "to grab them with a card reader."),
            wraplength=700, foreground="#555",
        ).pack(anchor="w", padx=8, pady=8)

    def _start(self):
        try:
            channel = int(self.channel_var.get())
        except ValueError:
            channel = 0
        self.app.send("sniffer_start", channel=channel)

    def update_status(self, s):
        f = s.get("pcapFile") or "-"
        n = s.get("pcapPackets", 0)
        self.status_var.set(f"Current file: {f}    packets: {n}")


class BleTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        scan_frame = ttk.LabelFrame(self, text="BLE Scan")
        scan_frame.pack(fill="both", expand=True, padx=8, pady=8)
        btns = ttk.Frame(scan_frame)
        btns.pack(anchor="w", padx=4, pady=4)
        ttk.Button(btns, text="Start Scan", command=lambda: app.send("ble_scan_start")).pack(side="left", padx=2)
        ttk.Button(btns, text="Stop", command=lambda: app.send("ble_scan_stop")).pack(side="left", padx=2)
        self.columns = ("address", "name", "rssi")
        self.table = make_table(scan_frame, self.columns)

        spam_frame = ttk.LabelFrame(self, text="BLE Advertisement Spam")
        spam_frame.pack(fill="x", padx=8, pady=8)
        ttk.Label(spam_frame, text="Cycles novelty pairing-popup style advertisements (no exploit payload).",
                  wraplength=700).pack(anchor="w", padx=4, pady=4)
        btns2 = ttk.Frame(spam_frame)
        btns2.pack(anchor="w", padx=4, pady=4)
        ttk.Button(btns2, text="Start", command=lambda: app.send("ble_spam_start")).pack(side="left", padx=2)
        ttk.Button(btns2, text="Stop", command=lambda: app.send("ble_spam_stop")).pack(side="left", padx=2)

    def update_devices(self, devices):
        refill_table(self.table, devices, self.columns)


class PortalTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        ttk.Label(
            self,
            text=("Only use on networks/audiences you're authorized to run a phishing-awareness test against. "
                  "Starting this reconfigures the device's own AP to the SSID below."),
            wraplength=700, foreground="#b34700",
        ).pack(anchor="w", padx=8, pady=8)

        row = ttk.Frame(self)
        row.pack(anchor="w", padx=8, pady=4, fill="x")
        ttk.Label(row, text="SSID to broadcast:").pack(side="left")
        self.ssid_var = tk.StringVar(value="Free WiFi")
        ttk.Entry(row, textvariable=self.ssid_var, width=30).pack(side="left", padx=4)

        ttk.Label(self, text="Optional custom HTML template (blank = default login page):").pack(anchor="w", padx=8, pady=(8, 0))
        self.html_text = tk.Text(self, height=8)
        self.html_text.pack(fill="both", expand=True, padx=8, pady=4)

        btns = ttk.Frame(self)
        btns.pack(anchor="w", padx=8, pady=8)
        ttk.Button(btns, text="Start Portal", command=self._start).pack(side="left", padx=2)
        ttk.Button(btns, text="Stop", command=lambda: app.send("portal_stop")).pack(side="left", padx=2)

        ttk.Label(
            self,
            text="Captured credentials are logged to /portal_log.txt on the SD card -- pull the card to review them.",
            wraplength=700, foreground="#555",
        ).pack(anchor="w", padx=8, pady=8)

    def _start(self):
        ssid = self.ssid_var.get().strip() or "Free WiFi"
        if not messagebox.askyesno("Start portal?", f'Start portal as SSID "{ssid}"?'):
            return
        html = self.html_text.get("1.0", "end").strip()
        self.app.send("portal_start", ssid=ssid, html=html)


class MarauderApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ESP32-S3 Marauder")
        self.geometry("900x650")

        self.msg_queue = queue.Queue()
        self.link = SerialLink(on_message=self.msg_queue.put)

        self._build_connection_bar()
        self._build_tabs()

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, self._poll_queue)

    def _build_connection_bar(self):
        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=8, pady=6)

        ttk.Label(bar, text="Port:").pack(side="left")
        self.port_var = tk.StringVar()
        self.port_combo = ttk.Combobox(bar, textvariable=self.port_var, width=30, state="readonly")
        self.port_combo.pack(side="left", padx=4)
        self._refresh_ports()

        ttk.Button(bar, text="Refresh", command=self._refresh_ports).pack(side="left", padx=4)
        self.connect_btn = ttk.Button(bar, text="Connect", command=self._toggle_connect)
        self.connect_btn.pack(side="left", padx=4)

        self.status_label = ttk.Label(bar, text="disconnected", foreground="red")
        self.status_label.pack(side="left", padx=12)

        self.mode_label = ttk.Label(bar, text="mode: -")
        self.mode_label.pack(side="right", padx=8)

    def _refresh_ports(self):
        devices = [p.device for p in serial.tools.list_ports.comports()]
        # On macOS every USB-serial adapter shows up twice: /dev/cu.* and
        # /dev/tty.*. Opening the tty.* node blocks forever waiting for a
        # carrier-detect signal a plain USB-CDC device never raises -- which
        # is exactly what "just freezes" on connect looks like. Drop tty.*
        # whenever the matching cu.* device is also present.
        cu_devices = {d for d in devices if "/cu." in d}
        ports = [d for d in devices if "/tty." not in d or d.replace("/tty.", "/cu.") not in cu_devices]
        self.port_combo["values"] = ports
        if ports and self.port_var.get() not in ports:
            self.port_var.set(ports[0])

    def _toggle_connect(self):
        if self.link.ser:
            self.link.disconnect()
            self.connect_btn.config(text="Connect")
            self.status_label.config(text="disconnected", foreground="red")
            return
        port = self.port_var.get()
        if not port:
            messagebox.showerror("No port", "Select a serial port first.")
            return
        self.connect_btn.config(state="disabled")
        self.status_label.config(text=f"connecting to {port}...", foreground="orange")
        # Open the port off the GUI thread -- serial.Serial() can block for
        # platform-specific reasons (see the tty.* note above), and doing
        # this on the main thread is what froze the whole window.
        threading.Thread(target=self._connect_worker, args=(port,), daemon=True).start()

    def _connect_worker(self, port):
        try:
            self.link.connect(port)
            self.msg_queue.put({"type": "_connect_result", "ok": True, "port": port})
        except Exception as e:
            self.msg_queue.put({"type": "_connect_result", "ok": False, "port": port, "error": str(e)})

    def _build_tabs(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=4)

        self.dash = DashboardTab(nb, self)
        self.wifi = WifiTab(nb, self)
        self.wids = WidsTab(nb, self)
        self.deauth = DeauthTab(nb, self)
        self.beacon = BeaconTab(nb, self)
        self.sniffer = SnifferTab(nb, self)
        self.ble = BleTab(nb, self)
        self.portal = PortalTab(nb, self)

        for tab, label in [
            (self.dash, "Dashboard"), (self.wifi, "WiFi Recon"), (self.wids, "WIDS"),
            (self.deauth, "Deauth"), (self.beacon, "Beacon Spam"), (self.sniffer, "Sniffer"),
            (self.ble, "BLE"), (self.portal, "Evil Portal"),
        ]:
            nb.add(tab, text=label)

    def send(self, cmd, **kwargs):
        obj = {"cmd": cmd}
        obj.update(kwargs)
        self.link.send(obj)

    def _poll_queue(self):
        # Bounded per tick, and only the newest "status" message is kept
        # (older ones are stale full snapshots anyway) -- otherwise a burst
        # of messages queued up while this was busy elsewhere turns into one
        # long unbroken run of Treeview rebuilds with no chance to hand
        # control back to Tkinter's event loop, which looks like a freeze.
        drained = []
        try:
            for _ in range(200):
                drained.append(self.msg_queue.get_nowait())
        except queue.Empty:
            pass

        latest_status = None
        for msg in drained:
            if msg.get("type") == "status":
                latest_status = msg
            else:
                self._handle_message(msg)
        if latest_status is not None:
            self._handle_message(latest_status)

        self.after(100, self._poll_queue)

    def _handle_message(self, msg):
        t = msg.get("type")
        if t == "_connect_result":
            self.connect_btn.config(state="normal")
            if msg["ok"]:
                self.connect_btn.config(text="Disconnect")
                self.status_label.config(text=f"connected ({msg['port']})", foreground="green")
                self.link.send({"cmd": "status"})
            else:
                self.status_label.config(text="disconnected", foreground="red")
                messagebox.showerror("Connect failed", msg.get("error", "unknown error"))
        elif t == "log":
            self.dash.append_log(msg.get("msg", ""))
        elif t == "status":
            self.mode_label.config(text=f"mode: {msg.get('mode', '-')}  ch:{msg.get('channel', '-')}")
            self.dash.update_status(msg)
            self.wifi.update_aps(msg.get("aps", []))
            self.wifi.update_stations(msg.get("stations", []))
            self.wids.update_alerts(msg.get("alerts", []))
            self.deauth.update_aps(msg.get("aps", []))
            self.deauth.update_stations(msg.get("stations", []))
            self.sniffer.update_status(msg)
            self.ble.update_devices(msg.get("ble", []))

    def _on_close(self):
        self.link.disconnect()
        self.destroy()


if __name__ == "__main__":
    MarauderApp().mainloop()
